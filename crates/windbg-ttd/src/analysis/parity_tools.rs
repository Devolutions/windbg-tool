//! Phase 3b parity tools: architecture, modules, objects, source, breakpoints.

use super::modules::{audit_modules, normalize_dll_name, search_candidate};
use super::util::parse_u64_argument;
use crate::state::ServiceState;
use crate::ttd_replay::{
    AddressInfoRequest, CursorId, QueryMemoryPolicy, ReadMemoryRequest, RegisterContextRequest,
    SessionId,
};
use anyhow::{bail, ensure, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ArchitectureStateRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    #[serde(default)]
    pub thread_id: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ModuleAuditRequest {
    pub session_id: SessionId,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default = "default_max_suspicious")]
    pub max_suspicious: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ObjectVtableRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub address: String,
    #[serde(default = "default_vtable_entries")]
    pub entries: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ModuleSearchOrderRequest {
    pub dll: String,
    #[serde(default)]
    pub app_dir: Option<PathBuf>,
    #[serde(default)]
    pub current_dir: Option<PathBuf>,
    #[serde(default)]
    pub max_path_dirs: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SourceResolveRequest {
    pub recorded_path: String,
    #[serde(default)]
    pub search_paths: Vec<PathBuf>,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BreakpointPlanRequest {
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default)]
    pub target_id: Option<u64>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default = "default_breakpoint_kind")]
    pub kind: String,
    #[serde(default)]
    pub size: Option<u32>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
}

fn default_max_suspicious() -> usize {
    64
}
fn default_vtable_entries() -> u32 {
    16
}
fn default_max_candidates() -> usize {
    32
}
fn default_max_depth() -> usize {
    12
}
fn default_breakpoint_kind() -> String {
    "code".to_string()
}

fn status_value<T: serde::Serialize>(result: anyhow::Result<T>) -> Value {
    match result {
        Ok(value) => match serde_json::to_value(value) {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        },
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

pub fn ttd_architecture_state(
    state: &mut ServiceState,
    request: ArchitectureStateRequest,
) -> anyhow::Result<Value> {
    let capabilities = status_value(state.ttd.capabilities(request.session_id));
    let registers = status_value(state.ttd.registers(request.session_id, request.cursor_id));
    let context = status_value(state.ttd.register_context(RegisterContextRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        thread_id: request.thread_id,
    }));
    let architecture = context["value"]["architecture"]
        .as_str()
        .or_else(|| capabilities["value"]["architecture"].as_str())
        .unwrap_or("unknown");
    let x64 = architecture.eq_ignore_ascii_case("x64")
        || context["value"]["registers"]["rip"].is_u64()
        || registers["value"]["program_counter"].is_u64();

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "thread_id": request.thread_id,
        "architecture": architecture,
        "detected": {
            "x64": x64,
            "source": if context["ok"].as_bool() == Some(true) { "register_context" } else { "capabilities_or_fallback" }
        },
        "supported_helpers": {
            "compact_registers": registers["ok"],
            "x64_register_context": x64 && context["ok"].as_bool() == Some(true),
            "x64_disassembly": x64,
            "stack_info": true,
            "peb_teb_helpers": x64
        },
        "unsupported_or_partial": [
            {
                "architecture": "x86",
                "status": "not_yet_exposed",
                "note": "TTD headers can represent multiple architectures, but the current Rust register/disassembly model is x64-first."
            },
            {
                "architecture": "arm64",
                "status": "not_yet_exposed",
                "note": "ARM64 register and disassembly models need a separate decoder and typed register schema."
            }
        ],
        "capabilities": capabilities,
        "registers": registers,
        "register_context": context,
        "next_steps": [
            "Use ttd_register_context for full x64 scalar/SIMD state when available.",
            "Use ttd_disassemble only when x64_disassembly is true.",
            "Treat unsupported architectures as explicit gaps instead of retrying x64-only commands."
        ]
    }))
}

pub fn ttd_module_audit(
    state: &mut ServiceState,
    request: ModuleAuditRequest,
) -> anyhow::Result<Value> {
    ensure!(
        request.max_suspicious <= 10_000,
        "max_suspicious must not exceed 10000"
    );
    let modules_value = if let Some(cursor_id) = request.cursor_id {
        serde_json::to_value(state.ttd.cursor_modules(request.session_id, cursor_id)?)?
    } else {
        serde_json::to_value(state.ttd.list_modules(request.session_id)?)?
    };
    let module_items = modules_value["modules"]
        .as_array()
        .context("module list response did not include modules")?;
    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "source": if request.cursor_id.is_some() { "cursor_modules" } else { "trace_modules" },
        "module_count": module_items.len(),
        "audit": audit_modules(module_items, request.max_suspicious),
        "modules": modules_value,
        "notes": [
            "This is read-only triage based on module paths and load inventory.",
            "Suspicious paths are evidence for review, not proof of injection."
        ]
    }))
}

pub fn ttd_object_vtable(
    state: &mut ServiceState,
    request: ObjectVtableRequest,
) -> anyhow::Result<Value> {
    ensure!(request.entries > 0, "entries must be greater than zero");
    ensure!(request.entries <= 256, "entries must be 256 or less");
    let object_address = parse_u64_argument(&request.address)?;
    let object_read = state.ttd.read_memory(ReadMemoryRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address: object_address,
        size: 8,
        policy: request.policy,
    })?;
    let object_read_value = serde_json::to_value(&object_read)?;
    let object_bytes = super::util::hex_to_bytes(
        object_read_value["data"]
            .as_str()
            .context("object pointer read did not include hex data")?,
    )?;
    ensure!(
        object_bytes.len() >= 8,
        "object pointer read returned fewer than 8 bytes"
    );
    let vtable_address = u64::from_le_bytes(object_bytes[..8].try_into()?);
    ensure!(vtable_address != 0, "object vtable pointer is null");

    let table_size = request.entries.saturating_mul(8);
    let vtable_read = state.ttd.read_memory(ReadMemoryRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address: vtable_address,
        size: table_size,
        policy: request.policy,
    })?;
    let vtable_read_value = serde_json::to_value(&vtable_read)?;
    let vtable_bytes = super::util::hex_to_bytes(
        vtable_read_value["data"]
            .as_str()
            .context("vtable read did not include hex data")?,
    )?;
    let mut entries = Vec::new();
    for (index, chunk) in vtable_bytes.chunks_exact(8).enumerate() {
        let target = u64::from_le_bytes(chunk.try_into()?);
        let target_info = if target == 0 {
            json!({ "ok": false, "error": "null vtable entry" })
        } else {
            status_value(state.ttd.address_info(AddressInfoRequest {
                session_id: request.session_id,
                cursor_id: request.cursor_id,
                address: target.to_string(),
            }))
        };
        entries.push(json!({
            "index": index,
            "slot_address": vtable_address + (index as u64 * 8),
            "slot_address_hex": format!("0x{:X}", vtable_address + (index as u64 * 8)),
            "target": target,
            "target_hex": format!("0x{target:X}"),
            "plausible_x64_pointer": super::memory::plausible_x64_pointer(target),
            "target_info": target_info,
        }));
    }

    let vtable_info = status_value(state.ttd.address_info(AddressInfoRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address: vtable_address.to_string(),
    }));

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "object_address": object_address,
        "object_address_hex": format!("0x{object_address:X}"),
        "vtable_address": vtable_address,
        "vtable_address_hex": format!("0x{vtable_address:X}"),
        "object_read": object_read_value,
        "vtable_read": vtable_read_value,
        "vtable_info": vtable_info,
        "entries": entries,
        "safety": "read_only_analysis"
    }))
}

pub fn module_search_order(request: ModuleSearchOrderRequest) -> anyhow::Result<Value> {
    let dll = normalize_dll_name(&request.dll)?;
    let current_dir = request
        .current_dir
        .unwrap_or(std::env::current_dir().context("resolving current directory")?);
    let windows_dir = PathBuf::from(
        std::env::var("WINDIR")
            .or_else(|_| std::env::var("SystemRoot"))
            .unwrap_or_else(|_| String::from(r"C:\Windows")),
    );
    let system32 = windows_dir.join("System32");
    let system = windows_dir.join("System");
    let max_path_dirs = request.max_path_dirs.unwrap_or(64);

    let mut candidates = Vec::new();
    candidates.push(json!({
        "order": 0,
        "kind": "known_dlls",
        "directory": null,
        "candidate": null,
        "exists": null,
        "risk": "system_controlled",
        "notes": "KnownDLLs are resolved by the loader before filesystem probing when the name is registered."
    }));
    let mut order = 1usize;
    if let Some(app_dir) = request.app_dir {
        candidates.push(search_candidate(
            order,
            "application_directory",
            &app_dir,
            &dll,
        ));
        order += 1;
    }
    for (kind, directory) in [
        ("system32", system32.as_path()),
        ("system", system.as_path()),
        ("windows", windows_dir.as_path()),
        ("current_directory", current_dir.as_path()),
    ] {
        candidates.push(search_candidate(order, kind, directory, &dll));
        order += 1;
    }
    let path_dirs = std::env::var_os("PATH")
        .map(|value| {
            std::env::split_paths(&value)
                .take(max_path_dirs)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for directory in &path_dirs {
        candidates.push(search_candidate(order, "path_directory", directory, &dll));
        order += 1;
    }
    let risky_candidates = candidates
        .iter()
        .filter(|candidate| candidate["risk"] != "system_controlled")
        .count();
    Ok(json!({
        "dll": dll,
        "candidate_count": candidates.len(),
        "path_dirs_included": path_dirs.len(),
        "path_dirs_truncated": std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).count() > path_dirs.len())
            .unwrap_or(false),
        "risky_candidate_count": risky_candidates,
        "candidates": candidates,
        "notes": [
            "This is a diagnostic model for common user-mode DLL search-order reasoning, not a loader trace.",
            "SafeDllSearchMode, package identity, API sets, manifests, KnownDLLs, SetDllDirectory/AddDllDirectory, and LoadLibrary flags can change real behavior.",
            "Prefer absolute paths or application-local signed dependencies when diagnosing DLL search-order issues."
        ]
    }))
}

pub fn source_resolve(request: SourceResolveRequest) -> anyhow::Result<Value> {
    let recorded_components = normalized_components(Path::new(&request.recorded_path));
    if recorded_components.is_empty() {
        bail!("recorded source path has no usable path components")
    }
    let search_paths = if request.search_paths.is_empty() {
        vec![std::env::current_dir().context("resolving current directory")?]
    } else {
        request.search_paths
    };

    let mut matches = Vec::new();
    let recorded_path = PathBuf::from(&request.recorded_path);
    if recorded_path.exists() {
        matches.push(source_match_value(
            &recorded_path,
            &recorded_components,
            true,
        ));
    }

    for root in &search_paths {
        collect_source_matches(
            root,
            &recorded_components,
            request.max_candidates,
            request.max_depth,
            0,
            &mut matches,
        )?;
    }
    matches.sort_by(|left, right| {
        right["matched_components"]
            .as_u64()
            .cmp(&left["matched_components"].as_u64())
            .then_with(|| left["path"].as_str().cmp(&right["path"].as_str()))
    });
    matches.dedup_by(|left, right| left["path"] == right["path"]);
    if matches.len() > request.max_candidates {
        matches.truncate(request.max_candidates);
    }
    let best = matches.first().cloned();

    Ok(json!({
        "recorded_path": request.recorded_path,
        "recorded_components": recorded_components,
        "search_paths": search_paths,
        "best": best,
        "matches": matches,
        "strategy": "Trailing path-component match, preferring the candidate with the longest matching suffix.",
        "source_hash_verification": "future"
    }))
}

pub fn breakpoint_plan(request: BreakpointPlanRequest) -> anyhow::Result<Value> {
    if request.target_id.is_some() && (request.session_id.is_some() || request.cursor_id.is_some())
    {
        bail!("choose either target_id or session_id/cursor_id, not both");
    }
    if request.address.is_none() && request.symbol.is_none() {
        bail!("breakpoint plan requires address or symbol");
    }
    let address = request
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let kind = request.kind.as_str();

    let (subject_value, supported, command, reason, safety) = if let Some(target) =
        request.target_id
    {
        let subject = json!({ "kind": "target", "target_id": target });
        match kind {
            "code" => (
                subject,
                request.address.is_some(),
                json!([
                    "windbg-tool",
                    "breakpoint",
                    "set",
                    "--target",
                    target,
                    "--address",
                    request
                        .address
                        .clone()
                        .unwrap_or_else(|| "<address>".to_string())
                ]),
                if request.symbol.is_some() {
                    "Symbol breakpoint setting is not first-class yet; resolve the symbol to an address first."
                } else {
                    "DbgEng live targets support code breakpoints by address."
                },
                "mutating",
            ),
            _ => (
                subject,
                false,
                Value::Null,
                "Data watchpoints are not currently exposed for daemon-owned live targets.",
                "unsupported",
            ),
        }
    } else if let Some(session) = request.session_id {
        let cursor = request.cursor_id;
        let subject = json!({
            "kind": if cursor.is_some() { "ttd_cursor" } else { "ttd_session" },
            "session_id": session,
            "cursor_id": cursor
        });
        match kind {
                "write" | "read" | "read_write" => (
                    subject,
                    request.address.is_some() && cursor.is_some(),
                    json!([
                        "windbg-tool",
                        "replay",
                        "watch-memory",
                        "--session",
                        session,
                        "--cursor",
                        cursor,
                        "--address",
                        request
                            .address
                            .clone()
                            .unwrap_or_else(|| "<address>".to_string()),
                        "--size",
                        request.size.unwrap_or(1),
                        "--access",
                        kind,
                        "--direction",
                        request
                            .direction
                            .clone()
                            .unwrap_or_else(|| "previous".to_string())
                    ]),
                    "TTD memory watchpoints replay to the next or previous matching access.",
                    "bounded_replay",
                ),
                "code" | "execute" => (
                    subject,
                    false,
                    Value::Null,
                    "TTD code breakpoints are not exposed as persistent breakpoints; use position/disassembly/replay commands instead.",
                    "unsupported",
                ),
                _ => (
                    subject,
                    false,
                    Value::Null,
                    "Requested breakpoint/watchpoint kind is not supported on this subject.",
                    "unsupported",
                ),
            }
    } else {
        bail!("breakpoint plan requires target_id or session_id/cursor_id");
    };

    Ok(json!({
        "schema_version": 1,
        "subject": subject_value,
        "request": {
            "address": address.map(|value| format!("0x{value:X}")),
            "symbol": request.symbol,
            "module": request.module,
            "kind": kind,
            "size": request.size,
            "direction": request.direction,
            "thread_unique_id": request.thread_unique_id
        },
        "supported": supported,
        "safety": safety,
        "reason": reason,
        "command": command,
        "diagnostics": if supported {
            Vec::<Value>::new()
        } else {
            vec![json!({
                "id": "breakpoint.plan.unsupported",
                "severity": "warning",
                "summary": "Requested plan is not directly supported.",
                "detail": reason,
                "confidence": "high"
            })]
        }
    }))
}

fn collect_source_matches(
    root: &Path,
    recorded_components: &[String],
    max_candidates: usize,
    max_depth: usize,
    depth: usize,
    matches: &mut Vec<Value>,
) -> anyhow::Result<()> {
    if matches.len() >= max_candidates || depth > max_depth || !root.exists() {
        return Ok(());
    }
    let metadata = match std::fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    if metadata.is_file() {
        let matched = matching_suffix_len(&normalized_components(root), recorded_components);
        if matched > 0 {
            matches.push(source_match_value(root, recorded_components, false));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    for entry in entries {
        if matches.len() >= max_candidates {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                matches.push(json!({ "error": error.to_string() }));
                continue;
            }
        };
        collect_source_matches(
            &entry.path(),
            recorded_components,
            max_candidates,
            max_depth,
            depth + 1,
            matches,
        )?;
    }
    Ok(())
}

fn source_match_value(path: &Path, recorded_components: &[String], direct: bool) -> Value {
    let candidate_components = normalized_components(path);
    let matched_components = matching_suffix_len(&candidate_components, recorded_components);
    json!({
        "path": path,
        "direct": direct,
        "matched_components": matched_components,
        "candidate_components": candidate_components,
    })
}

fn matching_suffix_len(candidate: &[String], recorded: &[String]) -> usize {
    candidate
        .iter()
        .rev()
        .zip(recorded.iter().rev())
        .take_while(|(candidate, recorded)| candidate == recorded)
        .count()
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect()
}
