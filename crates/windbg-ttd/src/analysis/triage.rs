use serde_json::{json, Value};

/// Keep only the candidate section names that the snapshot actually produced.
///
/// TTD cursor snapshots and DbgEng target snapshots expose different section names for the
/// same evidence (for example `active_threads` versus `threads`), so hypotheses list every
/// equivalent name and this filter reports the ones a caller can actually inspect.
fn present_sections(snapshot: &Value, candidates: &[&str]) -> Vec<String> {
    let Some(sections) = snapshot["sections"].as_object() else {
        return candidates.iter().map(|name| name.to_string()).collect();
    };
    candidates
        .iter()
        .filter(|name| sections.contains_key(**name))
        .map(|name| name.to_string())
        .collect()
}

pub fn triage_value(kind: &str, snapshot: Value) -> Value {
    let mut hypotheses = Vec::new();
    let diagnostics = snapshot["diagnostics"].clone();
    match kind {
        "symbol_health" => hypotheses.push(json!({
            "id": "symbol_health.requires_review",
            "confidence": "medium",
            "summary": "Review module symbol state and stack symbol names, then run symbols doctor for symbol_source and nearest_symbol evidence before trusting names or source paths.",
            "supporting_sections": present_sections(&snapshot, &["modules", "stack"])
        })),
        "loader" => hypotheses.push(json!({
            "id": "loader.module_review",
            "confidence": "medium",
            "summary": "Review module paths, duplicate module names, and recently loaded modules for loader anomalies.",
            "supporting_sections": present_sections(&snapshot, &["modules", "timeline_summary"])
        })),
        "deadlock" | "hang" => hypotheses.push(json!({
            "id": "hang.stack_threads_review",
            "confidence": "low",
            "summary": "Thread and stack evidence can identify waits, but this command does not yet prove lock ownership.",
            "supporting_sections": present_sections(&snapshot, &["active_threads", "threads", "stack"])
        })),
        "access_violation" | "crash" => hypotheses.push(json!({
            "id": "crash.exception_stack_review",
            "confidence": "medium",
            "summary": "Inspect exception/timeline, current disassembly, stack, and symbol quality before assigning root cause.",
            "supporting_sections": present_sections(
                &snapshot,
                &["exceptions", "timeline_summary", "event", "current_disassembly", "disassembly", "stack"]
            )
        })),
        "memory_corruption" => hypotheses.push(json!({
            "id": "memory_corruption.needs_watchpoint",
            "confidence": "low",
            "summary": "Snapshot evidence can identify suspicious pointers or stacks; use watchpoint planning before replaying or mutating.",
            "supporting_sections": present_sections(
                &snapshot,
                &["stack", "modules", "current_disassembly", "disassembly"]
            )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supporting_sections_reference_sections_the_snapshot_produced() {
        let ttd = triage_value(
            "hang",
            json!({ "sections": { "active_threads": {}, "stack": {}, "modules": {} } }),
        );
        assert_eq!(
            ttd["hypotheses"][0]["supporting_sections"],
            json!(["active_threads", "stack"])
        );

        let target = triage_value(
            "crash",
            json!({ "sections": { "threads": {}, "stack": {}, "disassembly": {}, "event": {} } }),
        );
        assert_eq!(
            target["hypotheses"][0]["supporting_sections"],
            json!(["event", "disassembly", "stack"])
        );

        let symbols = triage_value(
            "symbol_health",
            json!({ "sections": { "modules": {}, "stack": {} } }),
        );
        assert_eq!(
            symbols["hypotheses"][0]["supporting_sections"],
            json!(["modules", "stack"])
        );
    }
}
