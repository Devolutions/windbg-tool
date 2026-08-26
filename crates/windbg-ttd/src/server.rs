use crate::daemon::DaemonClient;
use crate::service::ReplayService;
use crate::tools::{self, ToolCall};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};

/// Backend used by the stdio MCP server.
///
/// Production defaults to the long-lived named-pipe daemon so MCP and CLI share
/// sessions, targets, and jobs. Local in-process mode remains available for tests
/// and `WINDBG_TOOL_MCP_IN_PROCESS=1`.
#[derive(Clone)]
pub enum McpToolBackend {
    Local(ReplayService),
    Daemon(DaemonClient),
}

#[derive(Clone)]
pub struct TtdMcpServer {
    backend: McpToolBackend,
}

impl Default for TtdMcpServer {
    fn default() -> Self {
        Self::local()
    }
}

impl TtdMcpServer {
    pub fn local() -> Self {
        Self {
            backend: McpToolBackend::Local(ReplayService::default()),
        }
    }

    pub fn daemon(client: DaemonClient) -> Self {
        Self {
            backend: McpToolBackend::Daemon(client),
        }
    }

    pub fn backend_kind(&self) -> &'static str {
        match self.backend {
            McpToolBackend::Local(_) => "in_process",
            McpToolBackend::Daemon(_) => "daemon",
        }
    }

    async fn call_backend(&self, call: ToolCall) -> anyhow::Result<Value> {
        match &self.backend {
            McpToolBackend::Local(service) => service.call_tool(call).await,
            McpToolBackend::Daemon(client) => client.call_tool(call).await,
        }
    }
}

impl ServerHandler for TtdMcpServer {
    fn get_info(&self) -> ServerInfo {
        let backend = self.backend_kind();
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "windbg-ttd".to_string(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some(format!(
                    "WinDbg TTD/live/dump automation MCP server (backend={backend})"
                )),
                icons: None,
                website_url: None,
            },
            instructions: Some(format!(
                "WinDbg Time Travel Debugging and DbgEng automation. \
Default backend is the long-lived windbg-tool daemon ({backend}), so sessions/targets/jobs \
survive MCP reconnects and are visible to the CLI. \
Prefer composites when available (ttd_open, session_list, daemon_health). \
Core flow: daemon_health/session_list → ttd_load_trace or ttd_open → ttd_cursor_create → \
inspect with ttd_trace_info, ttd_registers, ttd_read_memory, ttd_memory_watchpoint, and live/target tools."
            )),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: tools::definitions(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools::definitions()
            .into_iter()
            .find(|tool| tool.name.as_ref() == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = ToolCall {
            name: request.name.into_owned(),
            arguments: request.arguments.map(Value::Object).unwrap_or(Value::Null),
        };
        let result = self.call_backend(call).await;

        match result {
            Ok(value) => Ok(tool_text(value)),
            Err(error) => Ok(tool_error(json!({ "error": error.to_string() }))),
        }
    }
}

fn tool_text(value: Value) -> CallToolResult {
    CallToolResult {
        content: vec![Content::text(pretty_json(value))],
        structured_content: None,
        is_error: Some(false),
        meta: None,
    }
}

fn tool_error(value: Value) -> CallToolResult {
    CallToolResult {
        content: vec![Content::text(pretty_json(value))],
        structured_content: None,
        is_error: Some(true),
        meta: None,
    }
}

fn pretty_json(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_results_use_text_content_without_structured_content() {
        let result = tool_text(json!({"address": 140_728_946_327_552_u64}));

        assert!(result.structured_content.is_none());
        assert_eq!(
            result.content,
            vec![Content::text("{\n  \"address\": 140728946327552\n}")]
        );

        let error = tool_error(json!({"error": "failed"}));

        assert!(error.structured_content.is_none());
        assert_eq!(error.is_error, Some(true));
        assert_eq!(
            error.content,
            vec![Content::text("{\n  \"error\": \"failed\"\n}")]
        );
    }
}
