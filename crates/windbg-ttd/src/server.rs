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

#[derive(Clone, Default)]
pub struct TtdMcpServer {
    service: ReplayService,
}

impl ServerHandler for TtdMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "windbg-ttd".to_string(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: None,
                icons: None,
                website_url: None,
            },
            instructions: Some("Offline WinDbg Time Travel Debugging trace inspection. Load .run/.idx/.ttd traces, create cursors, seek positions, inspect metadata, and query replay state.".to_string()),
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
        let result = self.service.call_tool(call).await;

        match result {
            Ok(value) => Ok(tool_text(value)),
            Err(error) => Ok(tool_error(json!({ "error": error.to_string() }))),
        }
    }
}

fn tool_text(value: Value) -> CallToolResult {
    CallToolResult {
        content: vec![Content::text(pretty_json(value.clone()))],
        structured_content: Some(value),
        is_error: Some(false),
        meta: None,
    }
}

fn tool_error(value: Value) -> CallToolResult {
    CallToolResult {
        content: vec![Content::text(pretty_json(value.clone()))],
        structured_content: Some(value),
        is_error: Some(true),
        meta: None,
    }
}

fn pretty_json(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}
