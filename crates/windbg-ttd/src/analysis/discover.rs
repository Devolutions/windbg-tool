use super::recipes::recipes_manifest;
use crate::backend::capability_catalog;
use serde_json::{json, Value};

/// MCP-oriented discovery catalog. Tool names are injected by the tools layer
/// to avoid an analysis <-> tools dependency cycle.
pub fn discover_manifest(tool_names: &[String]) -> Value {
    json!({
        "name": "windbg-tool",
        "purpose": "Single executable for WinDbg Time Travel Debugging MCP stdio, daemon mode, and CLI commands",
        "session_model": "daemon-backed",
        "daemon": {
            "transport": "HTTP over Windows named pipes",
            "start": "windbg-tool daemon ensure",
            "status": "windbg-tool daemon status / MCP daemon_health",
            "shutdown": "windbg-tool daemon shutdown",
            "pipe_override": "--pipe \\\\.\\pipe\\windbg-tool-custom, WINDBG_TOOL_PIPE, or legacy TTD_MCP_PIPE"
        },
        "recommended_mcp_flow": [
            "discover",
            "daemon_health",
            "ttd_open { trace_path, optional position }",
            "session_list",
            "debug_snapshot { session_id, cursor_id }",
            "triage_run { kind: crash|hang|... }",
            "analysis primitives / recipes_get as needed"
        ],
        "preferred_entrypoints": [
            "discover",
            "recipes_list",
            "recipes_get",
            "debug_capabilities",
            "daemon_health",
            "session_list",
            "ttd_open",
            "debug_snapshot",
            "ttd_context_snapshot",
            "triage_run",
            "ttd_disassemble",
            "ttd_stack_recover",
            "ttd_memory_strings",
            "ttd_timeline_events",
            "ttd_watch_memory_sweep",
            "dump_triage",
            "remote_doctor",
            "target_memory_classify"
        ],
        "tool_count": tool_names.len(),
        "tools": tool_names,
        "backend_matrix": capability_catalog(),
        "recipes": recipes_manifest(),
        "notes": [
            "Prefer composite entrypoints over long primitive chains.",
            "TTD sessions and live/dump targets live in the shared daemon and survive MCP reconnects.",
            "Host-only workflows (WinDbg install, elevated TTD record, long-running process servers) remain CLI-first."
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_includes_injected_tools_and_recipes() {
        let manifest = discover_manifest(&[
            "discover".into(),
            "ttd_open".into(),
            "debug_snapshot".into(),
        ]);
        assert_eq!(manifest["tool_count"], 3);
        assert!(manifest["recipes"].as_array().unwrap().len() >= 5);
        assert!(manifest["preferred_entrypoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "ttd_open"));
    }
}
