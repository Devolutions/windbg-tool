use anyhow::bail;
use serde_json::{json, Value};

pub fn recipes_manifest() -> Value {
    json!([
        {
            "id": "diagnostic-technique",
            "title": "Choose the lightest diagnostic technique that can answer the question",
            "source_posts": ["why-you-should-printf", "first-post"],
            "tags": ["advisor", "logs", "tracing", "dump", "ttd", "live-debugging"],
            "problem": "The user has a symptom but has not chosen whether to use logs, dumps, live debugging, TTD, or remote debugging.",
            "guidance": [
                "Use logs or tracing first when they already contain enough temporal context.",
                "Use dumps when there is a crash/hang anchor point and state-at-time matters most.",
                "Use TTD when the important question is what changed before the anchor point.",
                "Use live or remote debugging when the process must be controlled interactively."
            ],
            "commands": ["windbg-tool discover", "windbg-tool context snapshot", "windbg-tool recipes crash-triage"],
            "mcp_tools": ["discover", "ttd_context_snapshot", "recipes_get", "triage_run"]
        },
        {
            "id": "remote-debugging",
            "title": "Pick NTSD/CDB remote debugging vs DbgSrv process server",
            "source_posts": ["remote-debugging"],
            "tags": ["remote", "dbgeng", "dbgsrv", "ntsd", "cdb", "windbg"],
            "problem": "An agent needs to debug a target on another machine or in a sensitive desktop/session.",
            "guidance": [
                "Use NTSD/CDB -server when debugger brains, symbols, and extensions should live on the target and latency matters.",
                "Use DbgSrv when the target should stay minimal and symbols/extensions should stay on the host.",
                "Use WinDbg -remote for an existing NTSD/CDB remote session.",
                "Use WinDbg -premote for a DbgSrv process server that will launch or attach from the host side."
            ],
            "commands": [
                "windbg-tool dbgeng server --transport tcp:port=5005",
                "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>",
                "windbg-tool recipes remote-debugging"
            ],
            "mcp_tools": [
                "discover",
                "recipes_get",
                "remote_explain",
                "remote_doctor",
                "remote_plan",
                "remote_status",
                "remote_server_command",
                "remote_connect_command"
            ]
        },
        {
            "id": "crash-triage",
            "title": "Summarize a crash or end-of-trace state",
            "source_posts": ["writing-a-debugger-from-scratch-part-1", "writing-a-debugger-from-scratch-part-2", "debugger-lies-part-1"],
            "tags": ["crash", "triage", "exception", "stack", "registers"],
            "problem": "A trace/session is loaded and the agent needs the first actionable summary.",
            "guidance": [
                "Capture trace info, capabilities, current position, active thread state, registers, stack info, modules, and exceptions.",
                "Treat stack output as evidence, not truth; corrupted stacks can hide callers.",
                "If native replay is unavailable, stop before requesting native-only register/memory commands."
            ],
            "commands": [
                "windbg-tool context snapshot --session <id> --cursor <id>",
                "windbg-tool exceptions --session <id>",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool stack info --session <id> --cursor <id>"
            ],
            "mcp_tools": ["ttd_open", "debug_snapshot", "triage_run", "ttd_list_exceptions", "ttd_registers", "ttd_stack_info"]
        },
        {
            "id": "stack-corruption",
            "title": "Find what overwrote a return address in TTD",
            "source_posts": ["debugger-lies-part-1", "writing-a-debugger-from-scratch-part-5", "writing-a-debugger-from-scratch-part-6"],
            "tags": ["ttd", "stack", "corruption", "watchpoint", "memory"],
            "problem": "The stack looks truncated, impossible, or corrupted near a crash.",
            "guidance": [
                "At the crashing position, identify the suspicious frame and return-address slot.",
                "Seek backward to the function entry if possible.",
                "Use a write watchpoint on the return-address slot to find the overwrite.",
                "Record stop position, thread, instruction, and stack bytes around the write."
            ],
            "commands": [
                "windbg-tool stack recover --session <id> --cursor <id> --target-info",
                "windbg-tool stack backtrace --session <id> --cursor <id> --target-info",
                "windbg-tool stack read --session <id> --cursor <id> --decode-pointers",
                "windbg-tool memory watchpoint --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next",
                "windbg-tool sweep watch-memory --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next --max-hits 8"
            ],
            "mcp_tools": [
                "ttd_stack_info",
                "ttd_stack_read",
                "ttd_stack_recover",
                "ttd_stack_backtrace",
                "ttd_memory_watchpoint",
                "ttd_watch_memory_sweep",
                "job_start_watch_memory_sweep"
            ]
        },
        {
            "id": "symbol-health",
            "title": "Diagnose symbol and binary availability",
            "source_posts": ["symbol-indexing", "writing-a-debugger-from-scratch-part-4", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["symbols", "pdb", "source", "binary", "modules"],
            "problem": "Names, stacks, source, or disassembly are missing or low fidelity.",
            "guidance": [
                "Check module timestamp/checksum/size and CodeView RSDS PDB identity when available.",
                "Remember symbol servers can serve binaries as well as PDBs; missing binaries can break stack walking.",
                "Use source path search and source hashes to avoid opening the wrong file."
            ],
            "commands": [
                "windbg-tool symbols diagnose --session <id>",
                "windbg-tool symbols inspect <path-to-exe-or-dll>",
                "windbg-tool symbols exports <path-to-exe-or-dll> --filter <name>",
                "windbg-tool symbols nearest --session <id> --cursor <id> --address <addr>",
                "windbg-tool source resolve <recorded-path> --search-path <checkout-root>",
                "windbg-tool modules --session <id>",
                "windbg-tool module info --session <id> --address <addr>",
                "windbg-tool schema ttd_module_info"
            ],
            "mcp_tools": ["ttd_list_modules", "ttd_module_info", "triage_run"]
        },
        {
            "id": "memory-provenance",
            "title": "Classify unknown memory and find where it came from",
            "source_posts": ["writing-a-debugger-from-scratch-part-3", "recognizing-patterns", "useless-x86-trivia"],
            "tags": ["memory", "pointers", "strings", "code", "patterns"],
            "problem": "A byte range is suspicious and needs interpretation.",
            "guidance": [
                "Check whether values look like aligned integers, pointers, UTF-16/ASCII strings, code bytes, or high-entropy data.",
                "Use address classification before assuming a 64-bit value is a pointer, or use memory chase for bounded pointer-chain inspection.",
                "Use TTD memory provenance and watchpoints to connect a suspicious range to writes over time."
            ],
            "commands": [
                "windbg-tool address --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory read --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory dump --session <id> --cursor <id> --address <addr> --size 128 --format dq",
                "windbg-tool memory classify --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory chase --session <id> --cursor <id> --address <addr> --depth 8 --target-info",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory buffer --session <id> --cursor <id> --address <addr> --size <n>"
            ],
            "mcp_tools": [
                "ttd_address_info",
                "ttd_read_memory",
                "ttd_memory_dump",
                "ttd_memory_classify",
                "ttd_memory_strings",
                "ttd_memory_dps",
                "ttd_memory_chase",
                "ttd_memory_range",
                "ttd_memory_buffer",
                "ttd_memory_watchpoint",
                "ttd_watch_memory_sweep"
            ]
        },
        {
            "id": "assembly-or-source",
            "title": "Move between instruction bytes, symbols, and source",
            "source_posts": ["fakers-guide-to-assembly", "writing-a-debugger-from-scratch-part-7", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["assembly", "disassembly", "source", "instructions"],
            "problem": "Source is unavailable, misleading, or insufficient and the agent needs instruction-level truth.",
            "guidance": [
                "Prefer Intel syntax for Windows debugger workflows.",
                "Show instruction bytes, current address, decoded instruction, and nearest symbol together.",
                "When source exists, map both address-to-source and source-to-address; line mappings are not one-to-one."
            ],
            "commands": [
                "windbg-tool disasm --session <id> --cursor <id>",
                "windbg-tool u --session <id> --cursor <id> --address <rip> --count 16",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool memory read --session <id> --cursor <id> --address <rip> --size 64"
            ],
            "mcp_tools": [
                "ttd_disassemble",
                "ttd_registers",
                "ttd_register_context",
                "ttd_read_memory",
                "ttd_symbols_nearest",
                "source_resolve"
            ]
        },
        {
            "id": "com-vtable",
            "title": "Investigate impossible calls through vtables or COM interfaces",
            "source_posts": ["vtables"],
            "tags": ["com", "vtable", "object", "dynamic-type"],
            "problem": "A call stack or source line appears to call the wrong method.",
            "guidance": [
                "Read the object pointer, then read the first pointer-sized field as the vtable pointer.",
                "Resolve vtable entries to symbols and confirm they live in an expected loaded image.",
                "Suspect interface layout mismatches when method ordinals point to unrelated symbols."
            ],
            "commands": [
                "windbg-tool object vtable --session <id> --cursor <id> --address <object>",
                "windbg-tool memory read --session <id> --cursor <id> --address <object> --size 8",
                "windbg-tool address --session <id> --cursor <id> --address <vtable>",
                "windbg-tool memory read --session <id> --cursor <id> --address <vtable> --size 64"
            ],
            "mcp_tools": ["ttd_object_vtable", "ttd_read_memory", "ttd_address_info", "ttd_symbols_nearest"]
        },
        {
            "id": "injection-analysis",
            "title": "Analyze injection-like symptoms without automating injection",
            "source_posts": ["run-my-code"],
            "tags": ["injection", "modules", "memory-protection", "safety"],
            "problem": "A process may have unexpected code, DLLs, hooks, or executable memory.",
            "guidance": [
                "Do not use windbg-tool to inject arbitrary code.",
                "Inventory modules, DLL search-order clues, and executable memory regions.",
                "Classify unbacked executable memory and unexpected loaded modules as evidence for further review."
            ],
            "commands": [
                "windbg-tool modules --session <id>",
                "windbg-tool module audit --session <id>",
                "windbg-tool module search-order suspicious.dll --app-dir <app-dir>",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool address --session <id> --cursor <id> --address <addr>"
            ],
            "mcp_tools": [
                "ttd_list_modules",
                "ttd_module_audit",
                "module_search_order",
                "ttd_module_info",
                "ttd_memory_range",
                "ttd_address_info"
            ]
        },
        {
            "id": "dump-triage",
            "title": "Offline dump inspect and pool-corruption triage",
            "source_posts": ["why-you-should-printf"],
            "tags": ["dump", "triage", "pool", "offline"],
            "problem": "A crash dump needs offline summary or bounded pool-corruption context without a full interactive session.",
            "guidance": [
                "Start with dump_inspect for metadata and crash context.",
                "Use dump_triage for bugcheck-oriented packs.",
                "Use dump_pool_triage when pool tracker / free-list corruption is suspected."
            ],
            "commands": [
                "windbg-tool dump inspect --path <dump>",
                "windbg-tool dump triage --path <dump>",
                "windbg-tool dump pool-triage --path <dump>"
            ],
            "mcp_tools": ["dump_inspect", "dump_triage", "dump_pool_triage", "dump_open_session", "target_stack_recover"]
        }
    ])
}

pub fn recipe_matches_topic(recipe: &Value, topic: &str) -> bool {
    recipe["id"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(topic))
        || recipe["tags"].as_array().is_some_and(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .any(|tag| tag.eq_ignore_ascii_case(topic))
        })
}

pub fn recipes_value(topic: Option<&str>) -> anyhow::Result<Value> {
    let recipes = recipes_manifest();
    let Some(topic) = topic else {
        return Ok(json!({
            "recipes": recipes,
            "usage": "recipes_get with topic/id/tag, or recipes_list for the full catalog",
        }));
    };
    let topic = topic.to_ascii_lowercase();
    let matches = recipes
        .as_array()
        .into_iter()
        .flatten()
        .filter(|recipe| recipe_matches_topic(recipe, &topic))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        bail!("unknown recipe topic: {topic}");
    }
    Ok(json!({ "recipes": matches }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_recipes_by_tag_and_id() {
        let by_id = recipes_value(Some("crash-triage")).unwrap();
        assert_eq!(by_id["recipes"].as_array().unwrap().len(), 1);
        let by_tag = recipes_value(Some("ttd")).unwrap();
        assert!(by_tag["recipes"].as_array().unwrap().len() >= 2);
    }
}
