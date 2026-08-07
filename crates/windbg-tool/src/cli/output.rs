use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::error::Error;
use std::fmt;

const SCHEMA_VERSION: u32 = 1;
const ENVELOPE_ENV: &str = "WINDBG_TOOL_ENVELOPE";

#[derive(Debug, Clone)]
pub(super) struct OutputOptions {
    pub(super) compact: bool,
    pub(super) field: Option<String>,
    pub(super) raw: bool,
    pub(super) envelope: bool,
}

impl OutputOptions {
    pub(super) fn new(compact: bool, field: Option<String>, raw: bool, envelope: bool) -> Self {
        Self {
            compact,
            field,
            raw,
            envelope: envelope || env_envelope_enabled(),
        }
    }

    pub(super) fn from_env_and_args() -> Self {
        let mut compact = false;
        let mut envelope = env_envelope_enabled();
        for arg in std::env::args_os().skip(1) {
            if arg == "--compact" {
                compact = true;
            } else if arg == "--envelope" {
                envelope = true;
            }
        }
        Self {
            compact,
            field: None,
            raw: false,
            envelope,
        }
    }
}

pub(super) fn print_value(mut value: Value, output: &OutputOptions) -> anyhow::Result<()> {
    if let Some(path) = output.field.as_deref() {
        value = select_field(&value, path)?;
    }

    if output.envelope && !(output.raw && output.field.is_some()) {
        print_json(
            json!({
                "schema_version": SCHEMA_VERSION,
                "ok": true,
                "data": value,
            }),
            output.compact,
        )
    } else if output.raw {
        print_raw(value)
    } else {
        print_json(value, output.compact)
    }
}

pub(super) fn print_failure(error: &CliFailure, output: &OutputOptions) -> anyhow::Result<()> {
    if output.envelope {
        print_json(
            json!({
                "schema_version": SCHEMA_VERSION,
                "ok": false,
                "error": error,
            }),
            output.compact,
        )
    } else {
        eprintln!("Error: {}", error.message);
        for cause in &error.causes {
            eprintln!("Caused by: {cause}");
        }
        if let Some(hint) = &error.hint {
            eprintln!("Hint: {hint}");
        }
        Ok(())
    }
}

pub(super) fn classify_error(error: anyhow::Error) -> CliFailure {
    if let Some(failure) = error.downcast_ref::<CliFailure>() {
        return failure.clone();
    }

    let causes = error
        .chain()
        .skip(1)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let message = error.to_string();
    let joined = std::iter::once(message.as_str())
        .chain(causes.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    let combined = joined.to_ascii_lowercase();

    if combined.contains("connecting to daemon pipe")
        || combined.contains("daemon pipe")
            && (combined.contains("os error 2")
                || combined.contains("os error 3")
                || combined.contains("os error 231")
                || combined.contains("not found")
                || combined.contains("busy"))
    {
        let mut failure = CliFailure::new(
            CliErrorCode::DaemonUnavailable,
            message,
            "daemon_unavailable",
            true,
        )
        .with_hint("Start or repair the local daemon with `windbg-tool daemon ensure`.");
        if let Some(pipe) = extract_pipe_hint(&joined) {
            failure = failure.with_detail("pipe", pipe);
        }
        failure.causes = causes;
        return failure;
    }

    if combined.contains("session") && combined.contains("not found") {
        return CliFailure::with_causes(
            CliErrorCode::SessionNotFound,
            message,
            "session_not_found",
            false,
            causes,
        );
    }
    if combined.contains("cursor") && combined.contains("not found") {
        return CliFailure::with_causes(
            CliErrorCode::CursorNotFound,
            message,
            "cursor_not_found",
            false,
            causes,
        );
    }
    if combined.contains("timed out") || combined.contains("timeout") {
        return CliFailure::with_causes(CliErrorCode::Timeout, message, "timeout", true, causes);
    }
    if combined.contains("daemon http") || combined.contains("daemon response") {
        return CliFailure::with_causes(
            CliErrorCode::DaemonError,
            message,
            "daemon_error",
            false,
            causes,
        );
    }
    if combined.contains("unknown tool") || combined.contains("invalid tool arguments") {
        return CliFailure::with_causes(
            CliErrorCode::ToolError,
            message,
            "tool_error",
            false,
            causes,
        );
    }

    CliFailure::with_causes(CliErrorCode::Internal, message, "internal", false, causes)
}

pub(super) fn invalid_argument(message: impl Into<String>) -> CliFailure {
    CliFailure::new(
        CliErrorCode::InvalidArgument,
        message,
        "invalid_argument",
        false,
    )
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CliFailure {
    pub(super) code: CliErrorCode,
    pub(super) kind: Cow<'static, str>,
    pub(super) message: String,
    pub(super) retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) causes: Vec<String>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub(super) details: serde_json::Map<String, Value>,
}

impl CliFailure {
    fn new(
        code: CliErrorCode,
        message: impl Into<String>,
        kind: &'static str,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            kind: Cow::Borrowed(kind),
            message: message.into(),
            retryable,
            hint: None,
            causes: Vec::new(),
            details: serde_json::Map::new(),
        }
    }

    fn with_causes(
        code: CliErrorCode,
        message: impl Into<String>,
        kind: &'static str,
        retryable: bool,
        causes: Vec<String>,
    ) -> Self {
        Self {
            causes,
            ..Self::new(code, message, kind, retryable)
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    fn with_detail(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    pub(super) fn exit_code(&self) -> i32 {
        match self.code {
            CliErrorCode::InvalidArgument => 2,
            CliErrorCode::DaemonUnavailable => 3,
            CliErrorCode::DaemonError => 4,
            CliErrorCode::SessionNotFound => 5,
            CliErrorCode::CursorNotFound => 6,
            CliErrorCode::Timeout => 7,
            CliErrorCode::ToolError => 8,
            CliErrorCode::Internal => 1,
        }
    }
}

impl fmt::Display for CliFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CliFailure {}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CliErrorCode {
    InvalidArgument,
    DaemonUnavailable,
    DaemonError,
    SessionNotFound,
    CursorNotFound,
    Timeout,
    ToolError,
    Internal,
}

fn select_field(value: &Value, path: &str) -> anyhow::Result<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return Err(invalid_argument("field path contains an empty segment").into());
        }
        current = match current {
            Value::Object(object) => object
                .get(segment)
                .ok_or_else(|| invalid_argument(format!("field '{segment}' was not found")))?,
            Value::Array(items) => {
                let index = segment.parse::<usize>().map_err(|_| {
                    invalid_argument(format!("array field segment '{segment}' is not an index"))
                })?;
                items.get(index).ok_or_else(|| {
                    invalid_argument(format!("array index {index} is out of range"))
                })?
            }
            _ => {
                return Err(invalid_argument(format!(
                    "field '{segment}' cannot be selected from a scalar value"
                ))
                .into())
            }
        };
    }
    Ok(current.clone())
}

fn print_json(value: Value, compact: bool) -> anyhow::Result<()> {
    if compact {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

fn print_raw(value: Value) -> anyhow::Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(value) => {
            println!("{value}");
            Ok(())
        }
        Value::Number(value) => {
            println!("{value}");
            Ok(())
        }
        Value::String(value) => {
            println!("{value}");
            Ok(())
        }
        other => {
            println!("{}", serde_json::to_string(&other)?);
            Ok(())
        }
    }
}

fn env_envelope_enabled() -> bool {
    std::env::var_os(ENVELOPE_ENV).is_some_and(|value| {
        let value = value.to_string_lossy();
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

fn extract_pipe_hint(message: &str) -> Option<String> {
    let marker = "daemon pipe ";
    let start = message.find(marker)? + marker.len();
    let rest = message[start..].trim_start();
    let pipe = rest
        .trim_start_matches('`')
        .trim_start_matches('\'')
        .trim_start_matches('"');
    let end = pipe
        .find(|ch: char| ch == '`' || ch == '\'' || ch == '"' || ch.is_whitespace())
        .unwrap_or(pipe.len());
    (!pipe[..end].is_empty()).then(|| pipe[..end].to_string())
}
