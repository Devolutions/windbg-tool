use crate::service::ReplayService;
use crate::tools::ToolCall;
use anyhow::{bail, Context};
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::{Hash, Hasher};
use std::time::Duration;

pub const PIPE_ENV: &str = "WINDBG_TOOL_PIPE";
const LEGACY_PIPE_ENV: &str = "TTD_MCP_PIPE";

pub fn default_pipe_name() -> String {
    if let Some(pipe) = env::var_os(PIPE_ENV).and_then(non_empty_os_string) {
        return pipe;
    }
    if let Some(pipe) = env::var_os(LEGACY_PIPE_ENV).and_then(non_empty_os_string) {
        return pipe;
    }

    let mut hasher = DefaultHasher::new();
    env::var("USERNAME")
        .unwrap_or_else(|_| "user".to_string())
        .hash(&mut hasher);
    if let Ok(current_dir) = env::current_dir() {
        current_dir.hash(&mut hasher);
    }
    format!(r"\\.\pipe\windbg-tool-{:016x}", hasher.finish())
}

fn non_empty_os_string(value: std::ffi::OsString) -> Option<String> {
    let value = value.to_string_lossy().trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(windows)]
pub async fn run_daemon(pipe_name: String) -> anyhow::Result<()> {
    windows::run_daemon(pipe_name).await
}

#[cfg(not(windows))]
pub async fn run_daemon(_pipe_name: String) -> anyhow::Result<()> {
    bail!("the TTD daemon named-pipe transport is only supported on Windows")
}

#[cfg(windows)]
pub struct DaemonClient {
    pipe_name: String,
}

#[cfg(windows)]
impl DaemonClient {
    pub fn new(pipe_name: String) -> Self {
        Self { pipe_name }
    }

    pub async fn health(&self) -> anyhow::Result<Value> {
        self.request_json("GET", "/health", None).await
    }

    pub async fn tools(&self) -> anyhow::Result<Value> {
        self.request_json("GET", "/tools", None).await
    }

    pub async fn sessions(&self) -> anyhow::Result<Value> {
        self.request_json("GET", "/sessions", None).await
    }

    pub async fn targets(&self) -> anyhow::Result<Value> {
        self.request_json("GET", "/targets", None).await
    }

    pub async fn shutdown(&self) -> anyhow::Result<Value> {
        self.request_json("POST", "/shutdown", Some(Value::Null))
            .await
    }

    pub async fn call_tool(&self, call: ToolCall) -> anyhow::Result<Value> {
        let response = self
            .request_json("POST", "/tools/call", Some(serde_json::to_value(call)?))
            .await?;
        if response["ok"].as_bool() == Some(true) {
            Ok(response["result"].clone())
        } else {
            let message = response["error"]
                .as_str()
                .unwrap_or("daemon returned an unknown tool error");
            bail!("{message}")
        }
    }

    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        windows::request_json(&self.pipe_name, method, path, body).await
    }
}

#[cfg(not(windows))]
pub struct DaemonClient {
    pipe_name: String,
}

#[cfg(not(windows))]
impl DaemonClient {
    pub fn new(pipe_name: String) -> Self {
        Self { pipe_name }
    }

    pub async fn health(&self) -> anyhow::Result<Value> {
        bail!(
            "the TTD daemon named-pipe transport is only supported on Windows: {}",
            self.pipe_name
        )
    }

    pub async fn tools(&self) -> anyhow::Result<Value> {
        self.health().await
    }

    pub async fn sessions(&self) -> anyhow::Result<Value> {
        self.health().await
    }

    pub async fn targets(&self) -> anyhow::Result<Value> {
        self.health().await
    }

    pub async fn shutdown(&self) -> anyhow::Result<Value> {
        self.health().await
    }

    pub async fn call_tool(&self, _call: ToolCall) -> anyhow::Result<Value> {
        self.health().await
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperBuilder;
    use std::convert::Infallible;
    use std::io::{ErrorKind, Result as IoResult};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeServer, PipeMode, ServerOptions,
    };
    use tokio::sync::{oneshot, Mutex};

    const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
    const CONNECT_ATTEMPTS: usize = 40;
    const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

    type ResponseBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;
    type ShutdownSender = Arc<Mutex<Option<oneshot::Sender<()>>>>;

    pub async fn run_daemon(pipe_name: String) -> anyhow::Result<()> {
        let service = ReplayService::default();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
        let mut server = create_server(&pipe_name, true)
            .with_context(|| format!("creating named pipe server {pipe_name}"))?;

        tracing::info!(pipe = %pipe_name, "TTD daemon listening");

        loop {
            tokio::select! {
                result = server.connect() => {
                    result.with_context(|| format!("accepting named pipe client on {pipe_name}"))?;
                    let connected = server;
                    server = create_server(&pipe_name, false)
                        .with_context(|| format!("creating next named pipe server instance {pipe_name}"))?;
                    spawn_connection(connected, service.clone(), shutdown_tx.clone());
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("TTD daemon shutdown requested");
                    break;
                }
            }
        }

        Ok(())
    }

    fn create_server(pipe_name: &str, first_instance: bool) -> IoResult<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first_instance);
        options.pipe_mode(PipeMode::Byte);
        options.reject_remote_clients(true);
        options.create(pipe_name)
    }

    fn spawn_connection(
        pipe: NamedPipeServer,
        service: ReplayService,
        shutdown_tx: ShutdownSender,
    ) {
        tokio::spawn(async move {
            let io = TokioIo::new(pipe);
            let hyper = HyperBuilder::new(TokioExecutor::new());
            let handler = service_fn(move |request| {
                handle_request(request, service.clone(), shutdown_tx.clone())
            });

            if let Err(error) = hyper.serve_connection(io, handler).await {
                tracing::debug!(%error, "named-pipe HTTP connection failed");
            }
        });
    }

    async fn handle_request(
        request: Request<Incoming>,
        service: ReplayService,
        shutdown_tx: ShutdownSender,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let response = match route_request(request, service, shutdown_tx).await {
            Ok(response) => response,
            Err(error) => json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "ok": false,
                    "error": error.to_string(),
                }),
            ),
        };
        Ok(response)
    }

    async fn route_request(
        request: Request<Incoming>,
        service: ReplayService,
        shutdown_tx: ShutdownSender,
    ) -> anyhow::Result<Response<ResponseBody>> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/health") => Ok(json_response(StatusCode::OK, service.health().await)),
            (&Method::GET, "/tools") => Ok(json_response(
                StatusCode::OK,
                json!({
                    "tools": service.list_tools(),
                }),
            )),
            (&Method::GET, "/sessions") => Ok(json_response(
                StatusCode::OK,
                json!({
                    "sessions": service.sessions().await,
                }),
            )),
            (&Method::GET, "/targets") => Ok(json_response(
                StatusCode::OK,
                json!({
                    "targets": service.targets().await?,
                }),
            )),
            (&Method::POST, "/tools/call") => {
                let body = read_body(request).await?;
                let call: ToolCall =
                    serde_json::from_slice(&body).context("parsing tool call request")?;
                let response = match service.call_tool(call).await {
                    Ok(result) => json!({
                        "ok": true,
                        "result": result,
                    }),
                    Err(error) => json!({
                        "ok": false,
                        "error": error.to_string(),
                    }),
                };
                Ok(json_response(StatusCode::OK, response))
            }
            (&Method::POST, "/shutdown") => {
                if let Some(sender) = shutdown_tx.lock().await.take() {
                    let _ = sender.send(());
                }
                Ok(json_response(
                    StatusCode::OK,
                    json!({
                        "ok": true,
                        "shutdown": true,
                    }),
                ))
            }
            _ => Ok(json_response(
                StatusCode::NOT_FOUND,
                json!({
                    "ok": false,
                    "error": "unknown daemon endpoint",
                }),
            )),
        }
    }

    async fn read_body(request: Request<Incoming>) -> anyhow::Result<Bytes> {
        let body = request
            .into_body()
            .collect()
            .await
            .context("reading HTTP request body")?
            .to_bytes();
        if body.len() > MAX_REQUEST_BYTES {
            bail!("request body exceeds {} bytes", MAX_REQUEST_BYTES);
        }
        Ok(body)
    }

    fn json_response(status: StatusCode, value: impl serde::Serialize) -> Response<ResponseBody> {
        let body = serde_json::to_vec(&value).unwrap_or_else(|error| {
            format!(r#"{{"ok":false,"error":"failed to serialize response: {error}"}}"#)
                .into_bytes()
        });
        let length = body.len().to_string();
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, length)
            .header(CONNECTION, "close")
            .body(Full::new(Bytes::from(body)).boxed())
            .expect("daemon response builder should accept static headers")
    }

    pub async fn request_json(
        pipe_name: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut pipe = open_client(pipe_name).await?;
        let body = body
            .map(|value| serde_json::to_vec(&value))
            .transpose()
            .context("serializing daemon request body")?
            .unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: windbg-tool\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        pipe.write_all(request.as_bytes())
            .await
            .context("writing daemon request headers")?;
        if !body.is_empty() {
            pipe.write_all(&body)
                .await
                .context("writing daemon request body")?;
        }
        pipe.flush().await.context("flushing daemon request")?;

        let response = read_response(&mut pipe).await?;
        parse_http_response(&response)
    }

    async fn read_response(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeClient,
    ) -> anyhow::Result<Vec<u8>> {
        let mut response = Vec::new();
        let mut buffer = vec![0_u8; 4096];

        loop {
            let bytes_read = pipe
                .read(&mut buffer)
                .await
                .context("reading daemon response")?;
            if bytes_read == 0 {
                return Ok(response);
            }

            response.extend_from_slice(&buffer[..bytes_read]);
            if response.len() > MAX_RESPONSE_BYTES {
                bail!("daemon response exceeds {MAX_RESPONSE_BYTES} bytes");
            }

            if let Some(response_end) = response_body_end(&response)? {
                if response_end > MAX_RESPONSE_BYTES {
                    bail!("daemon response exceeds {MAX_RESPONSE_BYTES} bytes");
                }
                if response.len() >= response_end {
                    response.truncate(response_end);
                    return Ok(response);
                }
            }
        }
    }

    async fn open_client(
        pipe_name: &str,
    ) -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        for attempt in 0..CONNECT_ATTEMPTS {
            match ClientOptions::new().open(pipe_name) {
                Ok(client) => return Ok(client),
                Err(error)
                    if (matches!(error.kind(), ErrorKind::NotFound | ErrorKind::WouldBlock)
                        || error.raw_os_error() == Some(231))
                        && attempt + 1 < CONNECT_ATTEMPTS =>
                {
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("connecting to daemon pipe {pipe_name}"))
                }
            }
        }
        bail!("daemon pipe {pipe_name} is not available")
    }

    fn parse_http_response(bytes: &[u8]) -> anyhow::Result<Value> {
        let header_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .context("daemon response did not contain HTTP headers")?;
        let headers = std::str::from_utf8(&bytes[..header_end])
            .context("daemon response headers were not UTF-8")?;
        let mut lines = headers.split("\r\n");
        let status_line = lines.next().context("daemon response was empty")?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .context("daemon response did not include a status code")?
            .parse::<u16>()
            .context("daemon response status code was invalid")?;

        let body_end = response_body_end(bytes)?.unwrap_or(bytes.len());
        if body_end > bytes.len() {
            bail!("daemon response ended before the declared content-length");
        }
        let body = &bytes[header_end..body_end];
        let value: Value = serde_json::from_slice(body).context("parsing daemon JSON response")?;
        if status >= 400 {
            let message = value["error"]
                .as_str()
                .unwrap_or("daemon returned an HTTP error");
            bail!("daemon HTTP {status}: {message}")
        }
        Ok(value)
    }

    fn response_body_end(bytes: &[u8]) -> anyhow::Result<Option<usize>> {
        let Some(header_end) = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        else {
            return Ok(None);
        };

        let headers = std::str::from_utf8(&bytes[..header_end])
            .context("daemon response headers were not UTF-8")?;
        let content_length = headers
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
            })
            .map(|value| {
                value
                    .parse::<usize>()
                    .context("daemon response content-length was invalid")
            })
            .transpose()?;

        content_length
            .map(|length| {
                header_end
                    .checked_add(length)
                    .context("daemon response content-length overflowed")
            })
            .transpose()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn response_body_end_waits_for_complete_headers() {
            assert_eq!(response_body_end(b"HTTP/1.1 200 OK\r\n").unwrap(), None);
        }

        #[test]
        fn response_body_end_uses_content_length() {
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}ignored";
            assert_eq!(response_body_end(response).unwrap(), Some(40));
        }

        #[test]
        fn parse_http_response_ignores_bytes_after_content_length() {
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}ignored";
            assert_eq!(parse_http_response(response).unwrap(), json!({}));
        }
    }
}
