use serde_json::{json, Value};

/// Returns the canonical capability contract for one debugger backend.
///
/// Dynamic availability, such as whether the native TTD bridge loaded, is
/// reported by the owning session. This contract describes the supported
/// operation shape and mutation policy independently of one session.
pub fn capability_contract(kind: &str) -> Value {
    match kind {
        "ttd_cursor" => json!({
            "backend": "ttd_cursor",
            "target_kind": "offline_replay",
            "persistence": "daemon_cursor",
            "architectures": {
                "x64": "implemented",
                "x86": "not_yet_exposed",
                "arm64": "not_yet_exposed"
            },
            "operations": {
                "read_memory": "supported",
                "disassemble": "supported_x64",
                "stack": "supported_x64_partial",
                "query_symbols": "supported_via_local_images_and_exports",
                "query_source": "supported_via_local_path_resolution",
                "step": "supported_forward_and_backward",
                "continue": "unsupported",
                "set_breakpoint": "unsupported",
                "set_data_breakpoint": "supported_as_replay_memory_watchpoint",
                "write_dump": "unsupported",
                "time_travel": "supported",
                "jobs": "supported",
                "timeline": "supported"
            },
            "mutability": {
                "read_only": ["memory", "registers", "modules", "threads", "timeline"],
                "cursor_state": ["position_set", "step"],
                "destructive": ["close_trace"]
            },
            "required_identifiers": ["session_id", "cursor_id"],
            "limitations": [
                "TTD cursors replay recorded state and cannot continue a live process.",
                "Native bridge availability and trace contents determine per-session feature availability."
            ]
        }),
        "dbgeng_live" | "dbgeng_target" => json!({
            "backend": "dbgeng_live",
            "target_kind": "live_user_mode",
            "persistence": "daemon_target",
            "engine_execution_model": "serialized_worker",
            "architectures": {
                "target_architecture": "reported_by_dbgeng",
                "host_architecture": "must_match_the_loaded_dbgeng_runtime"
            },
            "operations": {
                "read_memory": "supported",
                "disassemble": "supported",
                "stack": "supported",
                "query_symbols": "supported",
                "query_source": "supported",
                "query_virtual_memory_map": "supported_live_user_mode_only",
                "step": "supported_step_into_and_over",
                "continue": "supported",
                "continue_and_wait": "supported_with_opt_in_bounded_debuggee_output",
                "set_breakpoint": "supported_code_data_and_deferred_symbol",
                "set_data_breakpoint": "supported",
                "set_breakpoint_enabled": "supported",
                "write_dump": "supported",
                "time_travel": "unsupported",
                "jobs": "unsupported",
                "timeline": "unsupported"
            },
            "mutability": {
                "read_only": ["status", "event", "memory", "modules", "threads", "stack", "symbols", "source", "disassembly"],
                "target_execution": ["continue", "continue_and_wait", "step", "breakpoint_set", "breakpoint_enablement", "breakpoint_remove", "write_dump"],
                "destructive": ["terminate", "close"]
            },
            "required_identifiers": ["target_id"],
            "limitations": [
                "Event streaming and step-out are not exposed yet. Debuggee output capture is opt-in, bounded, and available only for one continue-and-wait operation.",
                "Live targets are not TTD replay cursors."
            ]
        }),
        "dbgeng_dump" => json!({
            "backend": "dbgeng_dump",
            "target_kind": "offline_dump",
            "persistence": "daemon_target",
            "engine_execution_model": "serialized_worker",
            "architectures": {
                "target_architecture": "reported_by_dbgeng",
                "host_architecture": "must_match_the_loaded_dbgeng_runtime"
            },
            "operations": {
                "read_memory": "supported_when_present_in_dump",
                "disassemble": "supported",
                "stack": "supported",
                "query_symbols": "supported",
                "query_source": "supported",
                "step": "unsupported",
                "continue": "unsupported",
                "set_breakpoint": "unsupported",
                "set_data_breakpoint": "unsupported",
                "write_dump": "unsupported",
                "time_travel": "unsupported",
                "jobs": "unsupported",
                "timeline": "unsupported"
            },
            "mutability": {
                "read_only": ["memory", "modules", "threads", "stack", "symbols", "source", "disassembly"],
                "target_execution": [],
                "destructive": ["close"]
            },
            "required_identifiers": ["target_id"],
            "limitations": [
                "Dump targets are immutable snapshots and do not have a live event stream."
            ]
        }),
        "dbgeng_remote_plan" => json!({
            "backend": "dbgeng_remote_plan",
            "target_kind": "remote_preflight",
            "persistence": "none",
            "architectures": {},
            "operations": {
                "read_memory": "unsupported",
                "disassemble": "unsupported",
                "stack": "unsupported",
                "query_symbols": "unsupported",
                "query_source": "unsupported",
                "step": "unsupported",
                "continue": "unsupported",
                "set_breakpoint": "unsupported",
                "set_data_breakpoint": "unsupported",
                "write_dump": "unsupported",
                "time_travel": "unsupported",
                "jobs": "unsupported",
                "timeline": "unsupported"
            },
            "mutability": {
                "read_only": ["remote_doctor", "remote_status", "remote_plan"],
                "target_execution": [],
                "destructive": []
            },
            "required_identifiers": ["transport"],
            "limitations": [
                "Remote planning generates preflight and connection instructions; it does not acquire a debugger target."
            ]
        }),
        _ => json!({
            "backend": kind,
            "status": "unknown"
        }),
    }
}

pub fn capability_catalog() -> Vec<Value> {
    [
        "ttd_cursor",
        "dbgeng_live",
        "dbgeng_dump",
        "dbgeng_remote_plan",
    ]
    .into_iter()
    .map(capability_contract)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_contract_reports_p1_control_support() {
        let contract = capability_contract("dbgeng_live");
        assert_eq!(contract["operations"]["set_data_breakpoint"], "supported");
        assert_eq!(
            contract["operations"]["step"],
            "supported_step_into_and_over"
        );
        assert_eq!(
            contract["operations"]["continue_and_wait"],
            "supported_with_opt_in_bounded_debuggee_output"
        );
        assert_eq!(
            contract["operations"]["set_breakpoint"],
            "supported_code_data_and_deferred_symbol"
        );
        assert_eq!(
            contract["operations"]["set_breakpoint_enabled"],
            "supported"
        );
        assert_eq!(contract["engine_execution_model"], "serialized_worker");
    }

    #[test]
    fn catalog_contains_each_public_backend() {
        let catalog = capability_catalog();
        assert_eq!(catalog.len(), 4);
        assert!(catalog
            .iter()
            .any(|contract| contract["backend"] == "ttd_cursor"));
        assert!(catalog
            .iter()
            .any(|contract| contract["backend"] == "dbgeng_dump"));
    }
}
