//! Phase 3 TTD analysis tools shared by MCP and CLI-facing daemon handlers.

use super::disasm::disassemble_x64;
use super::memory::{
    ascii_strings, classify_memory, memory_dump, plausible_x64_pointer, read_pointer_value,
    utf16le_strings,
};
use super::stack::recover_stack_candidates;
use super::timeline::{
    collect_keyframe_events, collect_timeline_events, timeline_sequence, timeline_source_summary,
};
use super::util::{hex_to_bytes, parse_u64_argument};
use crate::state::ServiceState;
use crate::ttd_replay::{
    AddressInfoRequest, CursorId, Position, PositionOrPercent, PositionRequest, QueryMemoryPolicy,
    ReadMemoryRequest, RegisterContextRequest, SessionId, StackReadRequest,
};
use anyhow::{ensure, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisassembleRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default = "default_disasm_count")]
    pub count: u32,
    #[serde(default = "default_disasm_bytes")]
    pub bytes: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
    #[serde(default)]
    pub thread_id: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StackRecoverRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    #[serde(default)]
    pub size: Option<u32>,
    #[serde(default)]
    pub offset_from_sp: Option<i64>,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
    #[serde(default)]
    pub target_info: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StackBacktraceRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    #[serde(default = "default_stack_size")]
    pub size: u32,
    #[serde(default)]
    pub offset_from_sp: Option<i64>,
    #[serde(default = "default_max_frames")]
    pub max_frames: usize,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
    #[serde(default)]
    pub target_info: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryAnalysisRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub address: String,
    #[serde(default = "default_memory_size")]
    pub size: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryDumpRequest {
    #[serde(flatten)]
    pub base: MemoryAnalysisRequest,
    #[serde(default = "default_dump_format")]
    pub format: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryStringsRequest {
    #[serde(flatten)]
    pub base: MemoryAnalysisRequest,
    #[serde(default = "default_encoding")]
    pub encoding: String,
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    #[serde(default = "default_max_strings")]
    pub max_strings: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryDpsRequest {
    #[serde(flatten)]
    pub base: MemoryAnalysisRequest,
    #[serde(default = "default_pointer_size")]
    pub pointer_size: u32,
    #[serde(default)]
    pub target_info: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryChaseRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub address: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_chase_depth")]
    pub depth: u32,
    #[serde(default = "default_pointer_size")]
    pub pointer_size: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
    #[serde(default)]
    pub target_info: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TimelineEventsRequest {
    pub session_id: SessionId,
    #[serde(default = "default_timeline_kind")]
    pub kind: String,
    #[serde(default = "default_max_events")]
    pub max_events: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExceptionFocusRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    #[serde(default)]
    pub index: usize,
}

fn default_disasm_count() -> u32 {
    16
}
fn default_disasm_bytes() -> u32 {
    128
}
fn default_max_candidates() -> usize {
    64
}
fn default_min_confidence() -> f64 {
    0.45
}
fn default_stack_size() -> u32 {
    4096
}
fn default_max_frames() -> usize {
    32
}
fn default_memory_size() -> u32 {
    256
}
fn default_dump_format() -> String {
    "db".to_string()
}
fn default_encoding() -> String {
    "both".to_string()
}
fn default_min_len() -> usize {
    4
}
fn default_max_strings() -> usize {
    256
}
fn default_pointer_size() -> u32 {
    8
}
fn default_chase_depth() -> u32 {
    8
}
fn default_timeline_kind() -> String {
    "all".to_string()
}
fn default_max_events() -> usize {
    512
}

pub fn ttd_disassemble(
    state: &mut ServiceState,
    request: DisassembleRequest,
) -> anyhow::Result<Value> {
    ensure!(request.count > 0, "count must be greater than zero");
    ensure!(
        request.count <= 256,
        "count must be 256 instructions or less"
    );
    ensure!(request.bytes > 0, "bytes must be greater than zero");
    ensure!(request.bytes <= 4096, "bytes must be 4096 or less");

    let (address, context) = resolve_disasm_address(state, &request)?;
    let read = state.ttd.read_memory(ReadMemoryRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address,
        size: request.bytes,
        policy: request.policy,
    })?;
    let read_value = serde_json::to_value(&read)?;
    let data = read_value["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "architecture": "x64",
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "context": context,
        "read": read_value,
        "instructions": disassemble_x64(address, &bytes, request.count as usize),
    }))
}

pub fn ttd_stack_recover(
    state: &mut ServiceState,
    request: StackRecoverRequest,
) -> anyhow::Result<Value> {
    ensure!(
        (0.0..=1.0).contains(&request.min_confidence),
        "min_confidence must be between 0.0 and 1.0"
    );
    ensure!(
        request.max_candidates > 0,
        "max_candidates must be greater than zero"
    );
    ensure!(
        request.max_candidates <= 512,
        "max_candidates must be 512 or less"
    );

    let stack_read = state.ttd.stack_read(StackReadRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        size: request.size.unwrap_or(4096),
        offset_from_sp: request.offset_from_sp.unwrap_or(0),
        decode_pointers: true,
    })?;
    let stack_value = serde_json::to_value(&stack_read)?;
    let mut candidates =
        recover_stack_candidates(&stack_value, request.max_candidates, request.min_confidence);
    if request.target_info {
        enrich_stack_candidates(
            state,
            request.session_id,
            request.cursor_id,
            &mut candidates,
        );
    }
    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "stack": stack_value,
        "candidates": candidates,
        "heuristics": [
            "Pointer-sized stack values that land inside a loaded module are likely return-address candidates.",
            "Confidence is higher for module hits, aligned stack slots, and values that look like canonical x64 pointers.",
            "This is recovery evidence, not a trusted unwind; validate candidates with symbols, disassembly, and call-site context."
        ],
        "follow_up": [
            "Use ttd_disassemble with address=<candidate> to inspect code near a candidate.",
            "Use ttd_memory_watchpoint on a corrupted return-address slot to find writes in TTD."
        ]
    }))
}

pub fn ttd_stack_backtrace(
    state: &mut ServiceState,
    request: StackBacktraceRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.max_frames > 0,
        "max_frames must be greater than zero"
    );
    ensure!(
        request.max_frames <= 1024,
        "max_frames must not exceed 1024"
    );
    ensure!(
        (0.0..=1.0).contains(&request.min_confidence),
        "min_confidence must be between 0.0 and 1.0"
    );

    let registers = state.ttd.registers(request.session_id, request.cursor_id)?;
    let registers_value = serde_json::to_value(&registers)?;
    let stack_read = state.ttd.stack_read(StackReadRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        size: request.size,
        offset_from_sp: request.offset_from_sp.unwrap_or(0),
        decode_pointers: true,
    })?;
    let stack_value = serde_json::to_value(&stack_read)?;
    let candidate_budget = request.max_frames.saturating_sub(1);
    let mut candidates =
        recover_stack_candidates(&stack_value, candidate_budget, request.min_confidence);
    if request.target_info {
        enrich_stack_candidates(
            state,
            request.session_id,
            request.cursor_id,
            &mut candidates,
        );
    }

    let mut frames = Vec::new();
    if let Some(pc) = registers_value["program_counter"].as_u64() {
        let mut current = json!({
            "index": 0,
            "kind": "current_instruction",
            "address": pc,
            "address_hex": format!("0x{pc:016x}"),
            "confidence": 1.0,
            "reasons": ["current_program_counter"],
        });
        if request.target_info {
            current["target_info"] =
                address_info_status(state, request.session_id, request.cursor_id, pc);
        }
        frames.push(current);
    }
    for (index, candidate) in candidates.into_iter().enumerate() {
        frames.push(json!({
            "index": frames.len(),
            "kind": "recovered_return_address",
            "address": candidate["target"],
            "address_hex": candidate["target_hex"],
            "stack_slot": candidate["slot_address"],
            "stack_slot_hex": candidate["slot_address_hex"],
            "module": candidate["module"],
            "confidence": candidate["confidence"],
            "reasons": candidate["reasons"],
            "target_info": candidate.get("target_info").cloned().unwrap_or(Value::Null),
            "candidate_rank": index,
        }));
    }

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "position": registers_value["position"],
        "thread": registers_value["thread"],
        "method": "heuristic_stack_scan",
        "trusted_unwind": false,
        "frames": frames,
        "stack_read": stack_value,
        "warnings": [
            "This is not a DbgHelp/DbgEng unwind and may include false positives.",
            "Use ttd_stack_recover, ttd_disassemble, symbols, and TTD watchpoints to validate suspicious return-address candidates."
        ]
    }))
}

pub fn ttd_memory_dump(
    state: &mut ServiceState,
    request: MemoryDumpRequest,
) -> anyhow::Result<Value> {
    let (address, read_value, bytes) = read_memory_bytes(state, &request.base)?;
    Ok(json!({
        "session_id": request.base.session_id,
        "cursor_id": request.base.cursor_id,
        "read": read_value,
        "dump": memory_dump(address, &bytes, &request.format)?,
    }))
}

pub fn ttd_memory_classify(
    state: &mut ServiceState,
    request: MemoryAnalysisRequest,
) -> anyhow::Result<Value> {
    let (address, read_value, bytes) = read_memory_bytes(state, &request)?;
    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "read": read_value,
        "classification": classify_memory(address, &bytes),
    }))
}

pub fn ttd_memory_strings(
    state: &mut ServiceState,
    request: MemoryStringsRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.max_strings <= 10_000,
        "max_strings must not exceed 10000"
    );
    ensure!(
        matches!(request.encoding.as_str(), "ascii" | "utf16" | "both"),
        "encoding must be ascii, utf16, or both"
    );
    let (address, read_value, bytes) = read_memory_bytes(state, &request.base)?;
    let mut strings = Vec::new();
    if request.encoding == "ascii" || request.encoding == "both" {
        strings.extend(
            ascii_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= request.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("ascii".to_string());
                    item
                }),
        );
    }
    if request.encoding == "utf16" || request.encoding == "both" {
        strings.extend(
            utf16le_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= request.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("utf16".to_string());
                    item
                }),
        );
    }
    strings.sort_by_key(|item| item["address"].as_u64().unwrap_or(u64::MAX));
    let total_strings = strings.len();
    if strings.len() > request.max_strings {
        strings.truncate(request.max_strings);
    }
    Ok(json!({
        "session_id": request.base.session_id,
        "cursor_id": request.base.cursor_id,
        "read": read_value,
        "encoding": request.encoding,
        "min_len": request.min_len,
        "total_strings": total_strings,
        "max_strings": request.max_strings,
        "returned": strings.len(),
        "limit": request.max_strings,
        "truncated": total_strings > request.max_strings,
        "strings": strings,
        "unavailable_bytes": if read_value["complete"].as_bool() == Some(false) {
            read_value["requested_size"]
                .as_u64()
                .unwrap_or_default()
                .saturating_sub(read_value["bytes_read"].as_u64().unwrap_or_default())
        } else {
            0
        }
    }))
}

pub fn ttd_memory_dps(
    state: &mut ServiceState,
    request: MemoryDpsRequest,
) -> anyhow::Result<Value> {
    ensure!(
        matches!(request.pointer_size, 4 | 8),
        "pointer_size must be 4 or 8"
    );
    let (base, read_value, bytes) = read_memory_bytes(state, &request.base)?;
    let mut rows = Vec::new();
    for (index, chunk) in bytes.chunks(request.pointer_size as usize).enumerate() {
        if chunk.len() < request.pointer_size as usize {
            break;
        }
        let slot = base + (index as u64 * request.pointer_size as u64);
        let target = read_pointer_value(chunk, request.pointer_size)?;
        let mut row = json!({
            "slot": slot,
            "slot_hex": format!("0x{slot:016x}"),
            "value": target,
            "value_hex": format!("0x{target:016x}"),
            "plausible_x64_pointer": plausible_x64_pointer(target),
            "null": target == 0
        });
        if request.target_info && target != 0 {
            row["target_info"] = address_info_status(
                state,
                request.base.session_id,
                request.base.cursor_id,
                target,
            );
        }
        rows.push(row);
    }
    Ok(json!({
        "session_id": request.base.session_id,
        "cursor_id": request.base.cursor_id,
        "read": read_value,
        "pointer_size": request.pointer_size,
        "row_count": rows.len(),
        "rows": rows
    }))
}

pub fn ttd_memory_chase(
    state: &mut ServiceState,
    request: MemoryChaseRequest,
) -> anyhow::Result<Value> {
    ensure!(request.depth > 0, "depth must be greater than zero");
    ensure!(request.depth <= 256, "depth must not exceed 256");
    ensure!(
        matches!(request.pointer_size, 4 | 8),
        "pointer_size must be 4 or 8"
    );

    let root_address = parse_u64_argument(&request.address)?;
    let mut current = root_address;
    let mut hops = Vec::new();
    let mut stop_reason = "max_depth";

    for depth in 0..request.depth {
        let read_address = current
            .checked_add(request.offset)
            .context("pointer read address overflowed")?;
        let read = state.ttd.read_memory(ReadMemoryRequest {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            address: read_address,
            size: request.pointer_size,
            policy: request.policy,
        })?;
        let read_value = serde_json::to_value(&read)?;
        let data = read_value["data"]
            .as_str()
            .context("ttd_read_memory response did not include hex data")?;
        let bytes = hex_to_bytes(data)?;
        let target = read_pointer_value(&bytes, request.pointer_size)?;
        let mut hop = json!({
            "index": depth,
            "base_address": current,
            "read_address": read_address,
            "offset": request.offset,
            "pointer_size": request.pointer_size,
            "bytes": data,
            "target": target,
            "target_hex": format!("0x{target:016x}"),
            "null": target == 0,
            "read": read_value,
        });
        if request.target_info && target != 0 {
            hop["target_info"] =
                address_info_status(state, request.session_id, request.cursor_id, target);
        }
        hops.push(hop);
        if target == 0 {
            stop_reason = "null_pointer";
            break;
        }
        current = target;
    }

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "root_address": root_address,
        "offset": request.offset,
        "pointer_size": request.pointer_size,
        "requested_depth": request.depth,
        "stop_reason": stop_reason,
        "hops": hops,
        "notes": [
            "Reads one pointer at base_address + offset per hop.",
            "Pointer chains are evidence, not proof of ownership or object type."
        ]
    }))
}

pub fn ttd_timeline_events(
    state: &mut ServiceState,
    request: TimelineEventsRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.max_events <= 100_000,
        "max_events must not exceed 100000"
    );
    ensure!(
        matches!(
            request.kind.as_str(),
            "all" | "modules" | "threads" | "exceptions" | "keyframes"
        ),
        "kind must be all, modules, threads, exceptions, or keyframes"
    );

    let include = |wanted: &str| request.kind == "all" || request.kind == wanted;
    let mut events = Vec::new();
    let mut sources = Map::new();

    if include("modules") {
        let direct = serde_json::to_value(state.ttd.list_module_events(request.session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "module", &wrapped, "events");
        sources.insert(
            "modules".into(),
            timeline_source_summary(&wrapped, "events"),
        );
    }
    if include("threads") {
        let direct = serde_json::to_value(state.ttd.list_thread_events(request.session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "thread", &wrapped, "events");
        sources.insert(
            "threads".into(),
            timeline_source_summary(&wrapped, "events"),
        );
    }
    if include("exceptions") {
        let direct = serde_json::to_value(state.ttd.list_exceptions(request.session_id)?)?;
        let wrapped = json!({ "ok": true, "value": direct });
        collect_timeline_events(&mut events, "exception", &wrapped, "exceptions");
        sources.insert(
            "exceptions".into(),
            timeline_source_summary(&wrapped, "exceptions"),
        );
    }
    if include("keyframes") {
        let direct = serde_json::to_value(state.ttd.list_keyframes(request.session_id)?)?;
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
    let mut event_counts = Map::new();
    for event in &events {
        if let Some(kind) = event["kind"].as_str() {
            let count = event_counts
                .entry(kind.to_string())
                .or_insert_with(|| Value::from(0_u64));
            *count = Value::from(count.as_u64().unwrap_or(0) + 1);
        }
    }
    if events.len() > request.max_events {
        events.truncate(request.max_events);
    }

    Ok(json!({
        "session_id": request.session_id,
        "kind": request.kind,
        "total_events": total_events,
        "event_counts": event_counts,
        "max_events": request.max_events,
        "returned": events.len(),
        "limit": request.max_events,
        "truncated": total_events > request.max_events,
        "events": events,
        "sources": Value::Object(sources),
        "unsupported_recording_metadata": [
            "record clients",
            "custom events",
            "activities",
            "islands",
            "bounded user-data payload extraction"
        ],
        "notes": [
            "This timeline merges currently exposed trace metadata.",
            "Sources include only status and item counts; use the corresponding metadata command for full source data."
        ]
    }))
}

pub fn ttd_exception_focus(
    state: &mut ServiceState,
    request: ExceptionFocusRequest,
) -> anyhow::Result<Value> {
    let exceptions = state.ttd.list_exceptions(request.session_id)?;
    let exception_items = serde_json::to_value(&exceptions)?;
    let exception_items = exception_items
        .as_array()
        .context("list_exceptions did not serialize to an array")?;
    let exception = exception_items
        .get(request.index)
        .cloned()
        .with_context(|| {
            format!(
                "exception index {} is outside the {} recorded exception events",
                request.index,
                exception_items.len()
            )
        })?;
    let requested_position = exception["position"].clone();
    let position: Position = serde_json::from_value(requested_position.clone())
        .context("exception position was not a valid TTD position")?;
    let requested_position_hex = format!("{:X}:{:X}", position.sequence, position.steps);
    let thread_unique_id = exception["thread_unique_id"].as_u64();
    let after = state.ttd.set_position(PositionRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        position: PositionOrPercent::Position(position),
        thread_unique_id,
    })?;
    let exception_code_hex = exception["code"]
        .as_u64()
        .map(|code| format!("0x{code:08X}"));

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "exception_index": request.index,
        "exception": exception,
        "exception_code_hex": exception_code_hex,
        "requested_position": requested_position,
        "requested_position_hex": requested_position_hex,
        "thread_unique_id": thread_unique_id,
        "position": after,
        "notes": [
            "This command uses the exception's JSON position directly, avoiding decimal/hexadecimal transcription errors.",
            "When the trace records an owning thread, the cursor seeks on that TTD thread."
        ],
        "next_recommended_safe_commands": [
            "ttd_registers",
            "ttd_stack_backtrace",
            "ttd_disassemble"
        ]
    }))
}

fn resolve_disasm_address(
    state: &mut ServiceState,
    request: &DisassembleRequest,
) -> anyhow::Result<(u64, Value)> {
    if let Some(address) = request.address.as_deref() {
        return Ok((
            parse_u64_argument(address)?,
            json!({ "source": "explicit" }),
        ));
    }
    let context = state.ttd.register_context(RegisterContextRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        thread_id: request.thread_id,
    })?;
    let context_value = serde_json::to_value(&context)?;
    let rip = context_value["registers"]["rip"]
        .as_u64()
        .or_else(|| context_value["rip"].as_u64())
        .context("ttd_register_context response did not include registers.rip")?;
    Ok((
        rip,
        json!({ "source": "cursor_rip", "register_context": context_value }),
    ))
}

fn read_memory_bytes(
    state: &mut ServiceState,
    request: &MemoryAnalysisRequest,
) -> anyhow::Result<(u64, Value, Vec<u8>)> {
    ensure!(request.size > 0, "size must be greater than zero");
    ensure!(request.size <= 1024 * 1024, "size must not exceed 1 MiB");
    let address = parse_u64_argument(&request.address)?;
    let read = state.ttd.read_memory(ReadMemoryRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address,
        size: request.size,
        policy: request.policy,
    })?;
    let read_value = serde_json::to_value(&read)?;
    let data = read_value["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read_value["address"].as_u64().unwrap_or(address);
    Ok((address, read_value, bytes))
}

fn enrich_stack_candidates(
    state: &mut ServiceState,
    session_id: SessionId,
    cursor_id: CursorId,
    candidates: &mut [Value],
) {
    for candidate in candidates {
        let Some(target) = candidate["target"].as_u64() else {
            continue;
        };
        candidate["target_info"] = address_info_status(state, session_id, cursor_id, target);
    }
}

fn address_info_status(
    state: &mut ServiceState,
    session_id: SessionId,
    cursor_id: CursorId,
    address: u64,
) -> Value {
    match state.ttd.address_info(AddressInfoRequest {
        session_id,
        cursor_id,
        address: address.to_string(),
    }) {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplayToRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub position: PositionOrPercent,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
}

/// Seek a cursor and return before/after positions (CLI `replay to`).
pub fn ttd_replay_to(state: &mut ServiceState, request: ReplayToRequest) -> anyhow::Result<Value> {
    let before = state
        .ttd
        .cursor_position(request.session_id, request.cursor_id)?;
    let after = state.ttd.set_position(PositionRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        position: request.position,
        thread_unique_id: request.thread_unique_id,
    })?;
    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "thread_unique_id": request.thread_unique_id,
        "before": before,
        "after": after,
    }))
}
