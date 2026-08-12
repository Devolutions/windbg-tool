//! Remote debugging planning helpers shared by MCP and CLI.

use anyhow::{bail, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteKind {
    Dbgsrv,
    Ntsd,
}

impl RemoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dbgsrv => "dbgsrv",
            Self::Ntsd => "ntsd",
        }
    }
}

fn default_transport() -> String {
    "tcp:port=5005".into()
}

fn default_timeout_ms() -> u64 {
    1000
}

fn default_kind() -> RemoteKind {
    RemoteKind::Dbgsrv
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoteExplainRequest {
    #[serde(default)]
    pub kind: Option<RemoteKind>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoteServerCommandRequest {
    #[serde(default = "default_kind")]
    pub kind: RemoteKind,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub executable: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoteConnectCommandRequest {
    #[serde(default = "default_kind")]
    pub kind: RemoteKind,
    pub server: String,
    #[serde(default = "default_transport")]
    pub transport: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoteDoctorRequest {
    #[serde(default = "default_kind")]
    pub kind: RemoteKind,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub probe_connect: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoteStatusRequest {
    #[serde(default = "default_kind")]
    pub kind: RemoteKind,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub probe_connect: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemotePlanRequest {
    #[serde(default = "default_kind")]
    pub kind: RemoteKind,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub executable: Option<String>,
}

fn fix_item(description: impl Into<String>, command: Option<impl Into<String>>) -> Value {
    json!({
        "description": description.into(),
        "command": command.map(Into::into)
    })
}

fn diagnostic_item(
    id: impl Into<String>,
    severity: impl Into<String>,
    summary: impl Into<String>,
    detail: impl Into<String>,
    confidence: impl Into<String>,
    fix: Option<Value>,
) -> Value {
    json!({
        "id": id.into(),
        "severity": severity.into(),
        "summary": summary.into(),
        "detail": detail.into(),
        "confidence": confidence.into(),
        "fix": fix
    })
}

pub fn remote_explain(request: RemoteExplainRequest) -> anyhow::Result<Value> {
    let workflows = remote_workflows();
    let Some(kind) = request.kind else {
        return Ok(json!({
            "workflows": workflows,
            "default": "dbgsrv",
            "recipes": ["windbg-tool recipes remote-debugging"],
        }));
    };
    Ok(json!({
        "workflow": remote_workflow(kind),
        "recipes": ["windbg-tool recipes remote-debugging"],
    }))
}

pub fn remote_server_command(request: RemoteServerCommandRequest) -> anyhow::Result<Value> {
    ensure_exclusive_ntsd_target(request.kind, request.pid, request.executable.as_deref())?;
    Ok(json!({
        "side": "target",
        "workflow": remote_workflow(request.kind),
        "command": build_server_command(&request),
        "notes": server_notes(request.kind),
    }))
}

pub fn remote_connect_command(request: RemoteConnectCommandRequest) -> anyhow::Result<Value> {
    Ok(json!({
        "side": "host",
        "workflow": remote_workflow(request.kind),
        "command": build_connect_command(&request),
        "notes": connect_notes(request.kind),
    }))
}

pub fn remote_doctor(request: RemoteDoctorRequest) -> anyhow::Result<Value> {
    ensure_exclusive_ntsd_target(request.kind, request.pid, request.executable.as_deref())?;
    let status = remote_status(RemoteStatusRequest {
        kind: request.kind,
        server: request.server.clone(),
        transport: request.transport.clone(),
        probe_connect: request.probe_connect,
        timeout_ms: request.timeout_ms,
    })?;
    let plan = remote_plan(RemotePlanRequest {
        kind: request.kind,
        server: request.server,
        transport: request.transport,
        pid: request.pid,
        executable: request.executable,
    })?;
    Ok(json!({
        "schema_version": 1,
        "kind": request.kind.as_str(),
        "status": status,
        "plan": plan,
        "diagnostics": status["diagnostics"],
        "next_safe_commands": [
            "windbg-tool remote plan",
            "windbg-tool remote status --probe-connect"
        ]
    }))
}

pub fn remote_status(request: RemoteStatusRequest) -> anyhow::Result<Value> {
    let mut diagnostics = Vec::new();
    let parsed_transport = parse_tcp_transport(&request.transport);
    if parsed_transport.is_none() {
        diagnostics.push(diagnostic_item(
            "remote.transport.unsupported",
            "blocker",
            "Only tcp:port=<port> transports can be locally diagnosed today.",
            format!(
                "Transport '{}' can still be emitted in generated commands, but port checks and connect probes are unavailable.",
                request.transport
            ),
            "high",
            Some(fix_item(
                "Use a TCP transport for agent-diagnosable remote workflows.",
                Some("windbg-tool remote doctor --transport tcp:port=5005"),
            )),
        ));
    }

    if let Some(port) = parsed_transport {
        diagnostics.push(match TcpListener::bind(("127.0.0.1", port)) {
            Ok(_) => diagnostic_item(
                "remote.local_port.available",
                "info",
                format!("Local TCP port {port} is available."),
                "This only checks the current machine; remote target availability still depends on firewall, account, and server state.",
                "medium",
                None,
            ),
            Err(error) => diagnostic_item(
                "remote.local_port.unavailable",
                "warning",
                format!("Local TCP port {port} is not available."),
                error.to_string(),
                "medium",
                Some(fix_item(
                    "Choose a different transport port or stop the process currently using it.",
                    Some("windbg-tool remote doctor --transport tcp:port=5006"),
                )),
            ),
        });
    }

    let probe = if request.probe_connect {
        if let (Some(server), Some(port)) = (request.server.as_deref(), parsed_transport) {
            Some(connect_probe(server, port, request.timeout_ms)?)
        } else {
            diagnostics.push(diagnostic_item(
                "remote.probe.skipped",
                "warning",
                "Connect probe skipped.",
                "A TCP probe requires both --server and a tcp:port=<port> transport.",
                "high",
                None,
            ));
            None
        }
    } else {
        diagnostics.push(diagnostic_item(
            "remote.probe.opt_in",
            "info",
            "Remote reachability was not probed.",
            "Use --probe-connect for a bounded TCP connect check; this may be visible to remote network monitoring.",
            "high",
            None,
        ));
        None
    };

    diagnostics.push(diagnostic_item(
        "remote.long_running.server",
        "info",
        "Target-side remote server commands are long-running.",
        "Run them in a terminal or supervised process; this command only generates and diagnoses command lines.",
        "high",
        None,
    ));

    Ok(json!({
        "schema_version": 1,
        "kind": request.kind.as_str(),
        "transport": request.transport,
        "server": request.server,
        "parsed_tcp_port": parsed_transport,
        "probe": probe,
        "diagnostics": diagnostics
    }))
}

pub fn remote_plan(request: RemotePlanRequest) -> anyhow::Result<Value> {
    ensure_exclusive_ntsd_target(request.kind, request.pid, request.executable.as_deref())?;
    let server_args = RemoteServerCommandRequest {
        kind: request.kind,
        transport: request.transport.clone(),
        pid: request.pid,
        executable: request.executable.clone(),
    };
    let connect = request.server.as_ref().map(|server| {
        build_connect_command(&RemoteConnectCommandRequest {
            kind: request.kind,
            server: server.clone(),
            transport: request.transport.clone(),
        })
    });
    Ok(json!({
        "schema_version": 1,
        "kind": request.kind.as_str(),
        "workflow": remote_workflow(request.kind),
        "steps": [
            {
                "id": "target_start_server",
                "side": "target",
                "long_running": true,
                "command": build_server_command(&server_args),
                "notes": server_notes(request.kind)
            },
            {
                "id": "host_connect",
                "side": "host",
                "requires": ["target_start_server"],
                "command": connect,
                "notes": if request.server.is_some() {
                    connect_notes(request.kind)
                } else {
                    json!(["Pass server to emit the exact host-side command."])
                }
            },
            {
                "id": "verify",
                "side": "host",
                "command": ["windbg-tool", "remote", "status", "--probe-connect"],
                "notes": ["Run after the target-side server is listening."]
            }
        ],
        "cleanup": [
            "Close the host debugger connection.",
            "Stop the target-side server process or terminal."
        ]
    }))
}

fn ensure_exclusive_ntsd_target(
    kind: RemoteKind,
    pid: Option<u32>,
    executable: Option<&str>,
) -> anyhow::Result<()> {
    if matches!(kind, RemoteKind::Ntsd) && pid.is_some() && executable.is_some() {
        bail!("remote ntsd accepts either pid or executable, not both");
    }
    Ok(())
}

fn remote_workflows() -> Value {
    json!([
        remote_workflow(RemoteKind::Dbgsrv),
        remote_workflow(RemoteKind::Ntsd)
    ])
}

fn remote_workflow(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!({
            "kind": "dbgsrv",
            "summary": "DbgEng process server: debugger brains, symbols, and extensions stay on the host.",
            "use_when": [
                "target should stay lightweight",
                "host owns symbol/source paths and extensions",
                "host should launch or attach through -premote"
            ],
            "target_side": "windbg-tool dbgeng server --transport tcp:port=5005",
            "host_side": "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>"
        }),
        RemoteKind::Ntsd => json!({
            "kind": "ntsd",
            "summary": "NTSD/CDB remote session: debugger brains, symbols, and extensions run on the target.",
            "use_when": [
                "latency is high and command execution should be target-local",
                "target has the necessary symbols/extensions",
                "a preexisting debugger session should be exposed remotely"
            ],
            "target_side": "ntsd -server tcp:port=5005 -p <pid>",
            "host_side": "windbg-tool windbg run -- -remote tcp:port=5005,server=<target>"
        }),
    }
}

fn parse_tcp_transport(transport: &str) -> Option<u16> {
    let rest = transport.strip_prefix("tcp:")?;
    rest.split(',')
        .find_map(|part| part.strip_prefix("port="))
        .and_then(|port| port.parse::<u16>().ok())
}

fn connect_probe(server: &str, port: u16, timeout_ms: u64) -> anyhow::Result<Value> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut addrs = (server, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {server}:{port}"))?;
    let Some(addr) = addrs.next() else {
        return Ok(json!({
            "status": "error",
            "summary": "No socket addresses resolved.",
            "server": server,
            "port": port,
            "timeout_ms": timeout_ms
        }));
    };
    Ok(match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => json!({
            "status": "ok",
            "summary": "TCP connect probe succeeded.",
            "server": server,
            "port": port,
            "address": addr.to_string(),
            "timeout_ms": timeout_ms
        }),
        Err(error) => json!({
            "status": "error",
            "summary": "TCP connect probe failed.",
            "server": server,
            "port": port,
            "address": addr.to_string(),
            "timeout_ms": timeout_ms,
            "error": error.to_string()
        }),
    })
}

fn build_server_command(args: &RemoteServerCommandRequest) -> Vec<String> {
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".into(),
            "dbgeng".into(),
            "server".into(),
            "--transport".into(),
            args.transport.clone(),
        ],
        RemoteKind::Ntsd => {
            let mut command = vec!["ntsd".into(), "-server".into(), args.transport.clone()];
            if let Some(pid) = args.pid {
                command.push("-p".into());
                command.push(pid.to_string());
            } else if let Some(executable) = &args.executable {
                command.push(executable.clone());
            } else {
                command.push("-p".into());
                command.push("<pid>".into());
            }
            command
        }
    }
}

fn server_notes(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the target machine.",
            "The command blocks until the DbgEng process server exits.",
            "Use remote connect-command --kind dbgsrv on the host to generate the WinDbg -premote command."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the target machine with NTSD or CDB available.",
            "Symbols and extensions are resolved by the target-side debugger process.",
            "Use remote connect-command --kind ntsd on the host to generate the WinDbg -remote command."
        ]),
    }
}

fn build_connect_command(args: &RemoteConnectCommandRequest) -> Vec<String> {
    let remote = format!("{},server={}", args.transport, args.server);
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".into(),
            "windbg".into(),
            "run".into(),
            "--".into(),
            "-premote".into(),
            remote,
        ],
        RemoteKind::Ntsd => vec![
            "windbg-tool".into(),
            "windbg".into(),
            "run".into(),
            "--".into(),
            "-remote".into(),
            remote,
        ],
    }
}

fn connect_notes(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the host machine.",
            "This connects WinDbg to a DbgSrv process server; launch/attach decisions happen from the host.",
            "Append additional WinDbg launch/attach arguments after the generated -premote transport if needed."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the host machine.",
            "This connects WinDbg to an existing target-side NTSD/CDB -server session.",
            "Do not use -premote for NTSD/CDB -server sessions."
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_lists_workflows_without_kind() {
        let value = remote_explain(RemoteExplainRequest { kind: None }).unwrap();
        assert_eq!(value["default"], "dbgsrv");
        assert!(value["workflows"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn plan_emits_dbgsrv_server_command() {
        let value = remote_plan(RemotePlanRequest {
            kind: RemoteKind::Dbgsrv,
            server: Some("target.example".into()),
            transport: "tcp:port=5005".into(),
            pid: None,
            executable: None,
        })
        .unwrap();
        assert_eq!(value["kind"], "dbgsrv");
        assert!(value["steps"].as_array().unwrap().len() >= 2);
    }
}
