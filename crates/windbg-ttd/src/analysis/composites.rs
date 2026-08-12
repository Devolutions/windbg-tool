use super::timeline::{
    collect_keyframe_events, collect_timeline_events, timeline_sequence, timeline_source_summary,
};
use super::triage::triage_value;
use crate::backend::{capability_catalog, capability_contract};
use crate::state::ServiceState;
use crate::targets::{TargetDisassembleRequest, TargetRequest, TargetStackTraceRequest};
use crate::ttd_replay::{
    CursorId, LoadTraceRequest, PositionOrPercent, PositionRequest, ReadMemoryRequest,
    RegisterContextRequest, SessionId, SymbolSettings,
};
use anyhow::{bail, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenTraceRequest {
    pub trace_path: PathBuf,
    #[serde(default)]
    pub companion_path: Option<PathBuf>,
    #[serde(default)]
    pub trace_index: Option<u32>,
    #[serde(default)]
    pub symbols: SymbolSettings,
    #[serde(default)]
    pub position: Option<PositionOrPercent>,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecipesArgs {
    #[serde(default)]
    pub topic: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DebugCapabilitiesArgs {
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default)]
    pub target_id: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ContextSnapshotRequest {
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default = "default_timeline_events")]
    pub max_timeline_events: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DebugSnapshotRequest {
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default)]
    pub target_id: Option<u64>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
    #[serde(default = "default_max_modules")]
    pub max_modules: usize,
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,
    #[serde(default = "default_disasm_count")]
    pub disasm_count: u32,
    #[serde(default = "default_section_timeout_ms")]
    pub section_timeout_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TriageRunRequest {
    pub kind: String,
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default)]
    pub target_id: Option<u64>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
    #[serde(default = "default_max_modules")]
    pub max_modules: usize,
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,
}

fn default_timeline_events() -> usize {
    16
}
fn default_max_frames() -> u32 {
    32
}
fn default_max_modules() -> usize {
    64
}
fn default_max_threads() -> usize {
    32
}
fn default_disasm_count() -> u32 {
    8
}
fn default_section_timeout_ms() -> u64 {
    2000
}

pub fn ttd_open(state: &mut ServiceState, request: OpenTraceRequest) -> anyhow::Result<Value> {
    let load = state.ttd.load_trace(LoadTraceRequest {
        trace_path: request.trace_path,
        companion_path: request.companion_path,
        trace_index: request.trace_index,
        symbols: request.symbols,
    })?;
    let cursor = state.ttd.create_cursor(load.session_id)?;
    let position = if let Some(position) = request.position {
        Some(state.ttd.set_position(PositionRequest {
            session_id: load.session_id,
            cursor_id: cursor.cursor_id,
            position,
            thread_unique_id: request.thread_unique_id,
        })?)
    } else {
        None
    };
    Ok(json!({
        "session_id": load.session_id,
        "cursor_id": cursor.cursor_id,
        "load": load,
        "cursor": cursor,
        "position": position,
    }))
}

pub fn debug_capabilities_offline() -> Value {
    debug_capabilities_response(None)
}

pub fn debug_capabilities(
    state: &mut ServiceState,
    args: DebugCapabilitiesArgs,
) -> anyhow::Result<Value> {
    if args.session_id.is_some() && args.target_id.is_some() {
        bail!("debug_capabilities accepts either session_id or target_id, not both");
    }
    let selected = if let Some(session_id) = args.session_id {
        let capabilities = state.ttd.capabilities(session_id)?;
        let architecture = if let Some(cursor_id) = args.cursor_id {
            Some(section_ok(state.ttd.register_context(
                RegisterContextRequest {
                    session_id,
                    cursor_id,
                    thread_id: None,
                },
            )?))
        } else {
            None
        };
        Some(json!({
            "subject": {
                "kind": "ttd_cursor",
                "session_id": session_id,
                "cursor_id": args.cursor_id
            },
            "capabilities": section_ok(capabilities),
            "architecture": architecture,
            "matrix": capability_contract("ttd_cursor")
        }))
    } else if let Some(target_id) = args.target_id {
        let status = state.targets.target_status(TargetRequest { target_id })?;
        let status_value = serde_json::to_value(&status)?;
        let backend =
            if status_value.pointer("/target/kind").and_then(Value::as_str) == Some("dump") {
                "dbgeng_dump"
            } else {
                "dbgeng_live"
            };
        Some(json!({
            "subject": { "kind": "target", "target_id": target_id },
            "status": section_ok(status_value),
            "matrix": capability_contract(backend)
        }))
    } else {
        None
    };

    Ok(debug_capabilities_response(selected))
}

fn debug_capabilities_response(selected: Option<Value>) -> Value {
    json!({
        "schema_version": 1,
        "canonical_command": "debug capabilities",
        "selected": selected,
        "backend_matrix": capability_catalog(),
        "safe_command_taxonomy": {
            "read_only": ["discover", "recipes_list", "recipes_get", "debug_capabilities", "debug_snapshot", "triage_run", "session_list", "daemon_health"],
            "cursor_state": ["ttd_open", "ttd_position_set", "ttd_step"],
            "target_execution": ["target_continue", "target_step_into", "target_step_over", "target_set_breakpoint"],
            "destructive": ["ttd_close_trace", "target_terminate", "target_close", "job_cancel"]
        }
    })
}

pub fn ttd_context_snapshot(
    state: &mut ServiceState,
    args: ContextSnapshotRequest,
) -> anyhow::Result<Value> {
    let sessions = state.ttd.session_summaries();
    let sessions_value = serde_json::to_value(&sessions)?;
    let (session_id, cursor_id) =
        select_session_cursor(&sessions_value, args.session_id, args.cursor_id)?;
    let mut snapshot = json!({
        "sessions": sessions_value,
        "selected": {
            "session_id": session_id,
            "cursor_id": cursor_id
        },
        "recipes": [
            "recipes_get topic=crash-triage",
            "recipes_get topic=stack-corruption",
            "recipes_get topic=symbol-health",
            "recipes_get topic=memory-provenance"
        ],
    });

    if let Some(session_id) = session_id {
        snapshot["trace_info"] = section_result(|| state.ttd.trace_info(session_id));
        snapshot["capabilities"] = section_result(|| state.ttd.capabilities(session_id));
        if let Some(cursor_id) = cursor_id {
            snapshot["position"] =
                section_result(|| state.ttd.cursor_position(session_id, cursor_id));
            snapshot["active_threads"] =
                section_result(|| state.ttd.active_threads(session_id, cursor_id));
            snapshot["stack"] = section_result(|| state.ttd.stack_info(session_id, cursor_id));
            snapshot["architecture_state"] = section_result(|| {
                state.ttd.register_context(RegisterContextRequest {
                    session_id,
                    cursor_id,
                    thread_id: None,
                })
            });
            snapshot["command_line"] =
                section_result(|| state.ttd.command_line(session_id, cursor_id));
            snapshot["current_disassembly"] =
                section_result(|| disasm_at_cursor(state, session_id, cursor_id, 4, 64));
        }
        snapshot["timeline_summary"] = section_result(|| {
            timeline_events(state, session_id, "all", args.max_timeline_events.max(1))
        });
    }

    Ok(snapshot)
}

pub fn debug_snapshot(
    state: &mut ServiceState,
    args: DebugSnapshotRequest,
) -> anyhow::Result<Value> {
    if args.session_id.is_some() && args.target_id.is_some() {
        bail!("debug_snapshot accepts either session/cursor or target_id, not both");
    }
    if let Some(target_id) = args.target_id {
        return debug_target_snapshot(state, target_id, &args);
    }
    let session_id = args
        .session_id
        .context("debug_snapshot requires session_id+cursor_id or target_id")?;
    let cursor_id = args
        .cursor_id
        .context("debug_snapshot requires cursor_id with session_id")?;
    let legacy = ttd_context_snapshot(
        state,
        ContextSnapshotRequest {
            session_id: Some(session_id),
            cursor_id: Some(cursor_id),
            max_timeline_events: 16,
        },
    )?;
    let mut sections = Map::new();
    add_legacy_section(&mut sections, "trace_info", &legacy, "info");
    add_legacy_section(&mut sections, "capabilities", &legacy, "debug capabilities");
    add_legacy_section(&mut sections, "position", &legacy, "position get");
    add_legacy_section(&mut sections, "active_threads", &legacy, "active-threads");
    add_legacy_section(&mut sections, "stack", &legacy, "stack info");
    add_legacy_section(
        &mut sections,
        "architecture_state",
        &legacy,
        "architecture state",
    );
    add_legacy_section(
        &mut sections,
        "current_disassembly",
        &legacy,
        "disasm --session <id> --cursor <id>",
    );
    add_legacy_section(&mut sections, "command_line", &legacy, "command-line");
    add_legacy_section(
        &mut sections,
        "timeline_summary",
        &legacy,
        "timeline events",
    );
    filter_sections(&mut sections, &args.include, &args.exclude);
    Ok(json!({
        "schema_version": 1,
        "canonical_command": "debug snapshot",
        "subject": {
            "kind": "ttd_cursor",
            "session_id": session_id,
            "cursor_id": cursor_id
        },
        "stability": "replayable_cursor",
        "section_timeout_ms": args.section_timeout_ms,
        "sections": sections,
        "diagnostics": [],
        "next_recommended_safe_commands": [
            format!("debug_capabilities session_id={session_id} cursor_id={cursor_id}"),
            format!("triage_run kind=crash session_id={session_id} cursor_id={cursor_id}"),
            "ttd_stack_info / ttd_list_exceptions"
        ],
        "legacy_snapshot": legacy
    }))
}

pub fn triage_run(state: &mut ServiceState, args: TriageRunRequest) -> anyhow::Result<Value> {
    let kind = normalize_triage_kind(&args.kind)?.to_string();
    let snapshot = debug_snapshot(
        state,
        DebugSnapshotRequest {
            session_id: args.session_id,
            cursor_id: args.cursor_id,
            target_id: args.target_id,
            include: args.include,
            exclude: args.exclude,
            max_frames: args.max_frames,
            max_modules: args.max_modules,
            max_threads: args.max_threads,
            disasm_count: 8,
            section_timeout_ms: 2000,
        },
    )?;
    Ok(triage_value(&kind, snapshot))
}

fn debug_target_snapshot(
    state: &mut ServiceState,
    target_id: u64,
    args: &DebugSnapshotRequest,
) -> anyhow::Result<Value> {
    let mut sections = Map::new();
    if section_enabled(args, "status") {
        sections.insert(
            "status".into(),
            section_result(|| state.targets.target_status(TargetRequest { target_id })),
        );
    }
    if section_enabled(args, "capabilities") {
        sections.insert(
            "capabilities".into(),
            json!({
                "status": "ok",
                "value": {
                    "candidates": [
                        capability_contract("dbgeng_live"),
                        capability_contract("dbgeng_dump")
                    ]
                },
                "command": "debug capabilities --target <id>"
            }),
        );
    }
    if section_enabled(args, "registers") {
        sections.insert(
            "registers".into(),
            section_result(|| state.targets.core_registers(TargetRequest { target_id })),
        );
    }
    if section_enabled(args, "event") {
        sections.insert(
            "event".into(),
            section_result(|| state.targets.last_event(TargetRequest { target_id })),
        );
    }
    if section_enabled(args, "threads") {
        sections.insert(
            "threads".into(),
            section_result(|| {
                let value =
                    serde_json::to_value(state.targets.list_threads(TargetRequest { target_id })?)?;
                Ok(bound_array(value, "threads", args.max_threads))
            }),
        );
    }
    if section_enabled(args, "modules") {
        sections.insert(
            "modules".into(),
            section_result(|| {
                let value =
                    serde_json::to_value(state.targets.list_modules(TargetRequest { target_id })?)?;
                Ok(bound_array(value, "modules", args.max_modules))
            }),
        );
    }
    if section_enabled(args, "stack") {
        sections.insert(
            "stack".into(),
            section_result(|| {
                state.targets.stack_trace(TargetStackTraceRequest {
                    target_id,
                    max_frames: args.max_frames,
                })
            }),
        );
    }
    if section_enabled(args, "disassembly") {
        sections.insert(
            "disassembly".into(),
            section_result(|| {
                state.targets.disassemble(TargetDisassembleRequest {
                    target_id,
                    address: None,
                    count: args.disasm_count,
                })
            }),
        );
    }
    if section_enabled(args, "breakpoints") {
        sections.insert(
            "breakpoints".into(),
            section_result(|| state.targets.list_breakpoints(TargetRequest { target_id })),
        );
    }
    filter_sections(&mut sections, &args.include, &args.exclude);
    Ok(json!({
        "schema_version": 1,
        "canonical_command": "debug snapshot",
        "subject": { "kind": "target", "target_id": target_id },
        "stability": "stopped_or_best_effort_live_state",
        "section_timeout_ms": args.section_timeout_ms,
        "sections": sections,
        "diagnostics": [
            {
                "id": "debug.snapshot.live_consistency",
                "severity": "info",
                "summary": "Live target sections are best-effort."
            }
        ],
        "next_recommended_safe_commands": [
            format!("debug_capabilities target_id={target_id}"),
            format!("target_stack_trace target_id={target_id}")
        ]
    }))
}

fn timeline_events(
    state: &mut ServiceState,
    session_id: SessionId,
    kind: &str,
    max_events: usize,
) -> anyhow::Result<Value> {
    let include = |wanted: &str| kind == "all" || kind == wanted;
    let mut events = Vec::new();
    let mut sources = Map::new();

    if include("modules") {
        let direct = serde_json::to_value(state.ttd.list_module_events(session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "module", &wrapped, "events");
        sources.insert(
            "modules".into(),
            timeline_source_summary(&wrapped, "events"),
        );
    }
    if include("threads") {
        let direct = serde_json::to_value(state.ttd.list_thread_events(session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "thread", &wrapped, "events");
        sources.insert(
            "threads".into(),
            timeline_source_summary(&wrapped, "events"),
        );
    }
    if include("exceptions") {
        let direct = serde_json::to_value(state.ttd.list_exceptions(session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "exception", &wrapped, "exceptions");
        sources.insert(
            "exceptions".into(),
            timeline_source_summary(&wrapped, "exceptions"),
        );
    }
    if include("keyframes") {
        let direct = serde_json::to_value(state.ttd.list_keyframes(session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_keyframe_events(&mut events, &wrapped);
        sources.insert(
            "keyframes".into(),
            timeline_source_summary(&wrapped, "keyframes"),
        );
    }

    events.sort_by(|left, right| {
        timeline_sequence(left)
            .cmp(&timeline_sequence(right))
            .then_with(|| left["kind"].as_str().cmp(&right["kind"].as_str()))
            .then_with(|| left.to_string().cmp(&right.to_string()))
    });

    let total_events = events.len();
    if events.len() > max_events {
        events.truncate(max_events);
    }
    Ok(json!({
        "session_id": session_id,
        "kind": kind,
        "total_events": total_events,
        "max_events": max_events,
        "returned": events.len(),
        "truncated": total_events > max_events,
        "events": events,
        "sources": Value::Object(sources),
    }))
}

fn disasm_at_cursor(
    state: &mut ServiceState,
    session_id: SessionId,
    cursor_id: CursorId,
    count: usize,
    bytes: u32,
) -> anyhow::Result<Value> {
    let context = state.ttd.register_context(RegisterContextRequest {
        session_id,
        cursor_id,
        thread_id: None,
    })?;
    let address = context.registers.rip;
    let read = state.ttd.read_memory(ReadMemoryRequest {
        session_id,
        cursor_id,
        address,
        size: bytes,
        policy: None,
    })?;
    let read_value = serde_json::to_value(&read)?;
    let data = read_value["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let decoded = super::util::hex_to_bytes(data)?;
    Ok(json!({
        "session_id": session_id,
        "cursor_id": cursor_id,
        "architecture": "x64",
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "context": { "source": "register_context", "register_context": context },
        "read": read_value,
        "instructions": super::disasm::disassemble_x64(address, &decoded, count),
    }))
}

fn select_session_cursor(
    sessions: &Value,
    session_id: Option<SessionId>,
    cursor_id: Option<CursorId>,
) -> anyhow::Result<(Option<SessionId>, Option<CursorId>)> {
    let sessions = sessions.as_array().cloned().unwrap_or_default();
    if let Some(session_id) = session_id {
        let session = sessions
            .iter()
            .find(|session| session["session_id"].as_u64() == Some(session_id))
            .with_context(|| format!("session {session_id} not found"))?;
        let cursor_id = match cursor_id {
            Some(cursor_id) => Some(cursor_id),
            None => session["cursors"]
                .as_array()
                .and_then(|cursors| cursors.first())
                .and_then(|cursor| cursor["cursor_id"].as_u64()),
        };
        return Ok((Some(session_id), cursor_id));
    }
    if sessions.is_empty() {
        return Ok((None, None));
    }
    let session = &sessions[0];
    let session_id = session["session_id"].as_u64();
    let cursor_id = session["cursors"]
        .as_array()
        .and_then(|cursors| cursors.first())
        .and_then(|cursor| cursor["cursor_id"].as_u64());
    Ok((session_id, cursor_id))
}

fn section_ok<T: serde::Serialize>(value: T) -> Value {
    json!({ "ok": true, "value": value })
}

fn section_result<T: serde::Serialize>(f: impl FnOnce() -> anyhow::Result<T>) -> Value {
    match f() {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

fn add_legacy_section(sections: &mut Map<String, Value>, key: &str, legacy: &Value, command: &str) {
    if let Some(value) = legacy.get(key) {
        sections.insert(
            key.to_string(),
            json!({
                "status": if value["ok"] == false { "error" } else { "ok" },
                "value": value.get("value").cloned().unwrap_or_else(|| value.clone()),
                "command": command
            }),
        );
    }
}

fn filter_sections(sections: &mut Map<String, Value>, include: &[String], exclude: &[String]) {
    if !include.is_empty() {
        let keep = include
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        sections.retain(|key, _| keep.contains(&key.to_ascii_lowercase()));
    }
    if !exclude.is_empty() {
        let drop = exclude
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        sections.retain(|key, _| !drop.contains(&key.to_ascii_lowercase()));
    }
}

fn section_enabled(args: &DebugSnapshotRequest, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if args
        .exclude
        .iter()
        .any(|item| item.eq_ignore_ascii_case(&name))
    {
        return false;
    }
    args.include.is_empty()
        || args
            .include
            .iter()
            .any(|item| item.eq_ignore_ascii_case(&name))
}

fn bound_array(mut value: Value, key: &str, max: usize) -> Value {
    if let Some(array) = value.get_mut(key).and_then(Value::as_array_mut) {
        if array.len() > max {
            array.truncate(max);
            value["truncated"] = Value::Bool(true);
            value["max"] = Value::from(max);
        }
    }
    value
}

fn normalize_triage_kind(kind: &str) -> anyhow::Result<&'static str> {
    Ok(match kind.trim().to_ascii_lowercase().as_str() {
        "crash" => "crash",
        "hang" => "hang",
        "access-violation" | "access_violation" | "av" => "access_violation",
        "memory-corruption" | "memory_corruption" => "memory_corruption",
        "loader" => "loader",
        "symbol-health" | "symbol_health" | "symbols" => "symbol_health",
        "deadlock" => "deadlock",
        other => bail!("unsupported triage kind: {other}"),
    })
}
