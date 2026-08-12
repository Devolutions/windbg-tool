use serde_json::{json, Value};

pub fn triage_value(kind: &str, snapshot: Value) -> Value {
    let mut hypotheses = Vec::new();
    let diagnostics = snapshot["diagnostics"].clone();
    match kind {
        "symbol_health" => hypotheses.push(json!({
            "id": "symbol_health.requires_review",
            "confidence": "medium",
            "summary": "Review symbol_source and nearest_symbol evidence before trusting names or source paths.",
            "supporting_sections": ["symbol_source", "nearest_symbol"]
        })),
        "loader" => hypotheses.push(json!({
            "id": "loader.module_review",
            "confidence": "medium",
            "summary": "Review module paths, duplicate module names, and recently loaded modules for loader anomalies.",
            "supporting_sections": ["modules", "timeline_summary"]
        })),
        "deadlock" | "hang" => hypotheses.push(json!({
            "id": "hang.stack_threads_review",
            "confidence": "low",
            "summary": "Thread and stack evidence can identify waits, but this command does not yet prove lock ownership.",
            "supporting_sections": ["threads", "stack"]
        })),
        "access_violation" | "crash" => hypotheses.push(json!({
            "id": "crash.exception_stack_review",
            "confidence": "medium",
            "summary": "Inspect exception/timeline, current disassembly, stack, and symbol quality before assigning root cause.",
            "supporting_sections": ["timeline_summary", "current_disassembly", "stack", "symbol_source"]
        })),
        "memory_corruption" => hypotheses.push(json!({
            "id": "memory_corruption.needs_watchpoint",
            "confidence": "low",
            "summary": "Snapshot evidence can identify suspicious pointers or stacks; use watchpoint planning before replaying or mutating.",
            "supporting_sections": ["stack", "modules", "disassembly"]
        })),
        _ => {}
    }
    json!({
        "schema_version": 1,
        "kind": kind,
        "evidence": {
            "snapshot": snapshot
        },
        "hypotheses": hypotheses,
        "diagnostics": diagnostics,
        "next_actions": [
            { "safety": "safe", "command": "windbg-tool debug snapshot", "reason": "Refresh bounded evidence." },
            { "safety": "safe", "command": "windbg-tool symbols doctor", "reason": "Validate symbol/source quality." },
            { "safety": "safe", "command": "windbg-tool breakpoint plan", "reason": "Plan breakpoints/watchpoints before mutating the target." }
        ],
        "limitations": [
            "Triage commands report evidence and hypotheses, not final root-cause verdicts.",
            "Backend support varies; inspect debug capabilities for unsupported operations."
        ]
    })
}
