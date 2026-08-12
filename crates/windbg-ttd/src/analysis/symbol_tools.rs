//! PE inspect/exports and session symbol diagnosis/nearest/doctor tools.

use super::pe_symbols::{diagnose_pe, export_symbol_value, read_export_symbols, ExportSymbol};
use super::util::parse_u64_argument;
use crate::state::ServiceState;
use crate::targets::{TargetAddressRequest, TargetRequest};
use crate::ttd_replay::{AddressInfoRequest, CursorId, ModuleInfoRequest, SessionId};
use anyhow::{bail, ensure, Context};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PeInspectRequest {
    pub path: PathBuf,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PeExportsRequest {
    pub path: PathBuf,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default = "default_export_max")]
    pub max: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolsNearestRequest {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub address: String,
    #[serde(default)]
    pub include_exports: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolsDiagnoseRequest {
    pub session_id: SessionId,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolsDoctorRequest {
    #[serde(default)]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub cursor_id: Option<CursorId>,
    #[serde(default)]
    pub target_id: Option<u64>,
    #[serde(default)]
    pub address: Option<String>,
}

fn default_export_max() -> usize {
    256
}

pub fn pe_inspect(request: PeInspectRequest) -> anyhow::Result<Value> {
    diagnose_pe(&request.path)
}

pub fn pe_exports(request: PeExportsRequest) -> anyhow::Result<Value> {
    ensure!(
        request.max <= 10_000,
        "pe_exports max must not exceed 10000"
    );
    let exports = read_export_symbols(&request.path)?;
    let filter = request
        .filter
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let filtered = filter_exports(&exports, filter.as_deref());
    let values = filtered
        .iter()
        .take(request.max)
        .map(|export| export_symbol_value(export))
        .collect::<Vec<_>>();
    Ok(json!({
        "path": request.path,
        "total_exports": exports.len(),
        "filtered_exports": filtered.len(),
        "max": request.max,
        "returned": values.len(),
        "limit": request.max,
        "truncated": filtered.len() > request.max,
        "exports": values,
    }))
}

pub fn ttd_symbols_nearest(
    state: &mut ServiceState,
    request: SymbolsNearestRequest,
) -> anyhow::Result<Value> {
    let address = parse_u64_argument(&request.address)?;
    let address_info = state.ttd.address_info(AddressInfoRequest {
        session_id: request.session_id,
        cursor_id: request.cursor_id,
        address: request.address.clone(),
    })?;
    let address_info = serde_json::to_value(address_info)?;
    let Some(module) = address_info["module"].as_object() else {
        return Ok(json!({
            "session_id": request.session_id,
            "cursor_id": request.cursor_id,
            "address": address,
            "address_info": address_info,
            "symbol": null,
            "reason": "address did not resolve to a loaded module"
        }));
    };
    let Some(path) = module.get("path").and_then(Value::as_str) else {
        return Ok(json!({
            "session_id": request.session_id,
            "cursor_id": request.cursor_id,
            "address": address,
            "address_info": address_info,
            "symbol": null,
            "reason": "module path is not available"
        }));
    };
    let rva = module
        .get("rva")
        .and_then(Value::as_u64)
        .context("address_info module did not include an RVA")?;
    let path = PathBuf::from(path);
    let exports = read_export_symbols(&path)?;
    let nearest = nearest_export(&exports, rva as u32);
    let export_sample = request.include_exports.then(|| {
        exports
            .iter()
            .take(64)
            .map(export_symbol_value)
            .collect::<Vec<_>>()
    });
    let nearest_value = nearest.map(|export| {
        let displacement = rva.saturating_sub(export.rva as u64);
        json!({
            "export": export_symbol_value(export),
            "displacement": displacement,
            "displacement_hex": format!("{displacement:X}"),
            "display": export_display_name(export, displacement),
            "confidence": if export.forwarder.is_some() { "forwarder" } else { "export_nearest" }
        })
    });

    Ok(json!({
        "session_id": request.session_id,
        "cursor_id": request.cursor_id,
        "address": address,
        "address_info": address_info,
        "module_path": path,
        "rva": rva,
        "rva_hex": format!("{rva:X}"),
        "symbol": nearest_value,
        "exports": {
            "count": exports.len(),
            "sample": export_sample,
            "sample_limit": if request.include_exports { 64 } else { 0 },
            "sample_truncated": request.include_exports && exports.len() > 64
        },
        "notes": [
            "Nearest export is not the same as private PDB symbol lookup.",
            "Use this as a low-fidelity fallback when private symbols are unavailable."
        ]
    }))
}

pub fn symbols_diagnose(
    state: &mut ServiceState,
    request: SymbolsDiagnoseRequest,
) -> anyhow::Result<Value> {
    if request.name.is_some() && request.address.is_some() {
        bail!("symbols diagnose accepts either name or address, not both");
    }
    let trace_info = status_value(state.ttd.trace_info(request.session_id));
    let capabilities = status_value(state.ttd.capabilities(request.session_id));
    let module_scope = symbol_module_scope(state, &request)?;
    let checks = symbol_diagnostic_checks(capabilities.get("value"), &module_scope);
    Ok(json!({
        "session_id": request.session_id,
        "trace_info": trace_info,
        "capabilities": capabilities,
        "module_scope": module_scope,
        "checks": checks,
        "next_steps": [
            "Confirm symbols.symbol_path includes the expected symbol server or private symbol path.",
            "Confirm symbols.image_path includes local binaries when stack walking or disassembly is low fidelity.",
            "Use modules/module info to select a narrower module before future PDB/source diagnostics.",
            "Use windbg-tool recipes symbol-health for the broader TimDbg workflow."
        ]
    }))
}

pub fn symbols_doctor(
    state: &mut ServiceState,
    request: SymbolsDoctorRequest,
) -> anyhow::Result<Value> {
    let subject = resolve_doctor_subject(&request)?;
    let address = request
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    Ok(json!({
        "schema_version": 1,
        "subject": doctor_subject_value(&subject),
        "doctor": symbol_source_doctor_value(state, &subject, address)?
    }))
}

enum DoctorSubject {
    Ttd {
        session: SessionId,
        cursor: Option<CursorId>,
    },
    Target {
        target: u64,
    },
}

fn resolve_doctor_subject(request: &SymbolsDoctorRequest) -> anyhow::Result<DoctorSubject> {
    if request.target_id.is_some() && (request.session_id.is_some() || request.cursor_id.is_some())
    {
        bail!("choose either target_id or session_id/cursor_id, not both");
    }
    if let Some(target) = request.target_id {
        return Ok(DoctorSubject::Target { target });
    }
    match (request.session_id, request.cursor_id) {
        (Some(session), cursor) => Ok(DoctorSubject::Ttd { session, cursor }),
        (None, Some(_)) => bail!("session_id is required with cursor_id"),
        (None, None) => bail!("symbols doctor requires target_id or session_id"),
    }
}

fn doctor_subject_value(subject: &DoctorSubject) -> Value {
    match subject {
        DoctorSubject::Ttd { session, cursor } => json!({
            "kind": if cursor.is_some() { "ttd_cursor" } else { "ttd_session" },
            "backend": "ttd_replay",
            "ids": {
                "session_id": session,
                "cursor_id": cursor
            },
            "stability": "replayable"
        }),
        DoctorSubject::Target { target } => json!({
            "kind": "target",
            "backend": "dbgeng_target",
            "ids": {
                "target_id": target
            },
            "stability": "target_state"
        }),
    }
}

fn symbol_source_doctor_value(
    state: &mut ServiceState,
    subject: &DoctorSubject,
    address: Option<u64>,
) -> anyhow::Result<Value> {
    match subject {
        DoctorSubject::Ttd { session, cursor } => {
            let nearest = if let (Some(cursor), Some(address)) = (*cursor, address) {
                status_value(ttd_symbols_nearest(
                    state,
                    SymbolsNearestRequest {
                        session_id: *session,
                        cursor_id: cursor,
                        address: format!("0x{address:X}"),
                        include_exports: false,
                    },
                ))
            } else {
                json!({
                    "ok": false,
                    "error": "Pass cursor_id and address for nearest-symbol/source quality checks."
                })
            };
            Ok(json!({
                "status": "ok",
                "duration_ms": Value::Null,
                "truncated": false,
                "value": {
                    "trace_info": status_value(state.ttd.trace_info(*session)),
                    "nearest_symbol": nearest
                },
                "diagnostics": [
                    {
                        "id": "symbols.source.follow_up",
                        "severity": "info",
                        "summary": "Use focused symbol/source commands for deeper diagnosis.",
                        "detail": "This doctor composes currently available trace and nearest-symbol checks.",
                        "confidence": "high",
                        "fix": {
                            "description": "Run symbols diagnose or symbols nearest with the current address.",
                            "command": "windbg-tool symbols diagnose --session <id>"
                        }
                    }
                ],
                "command": "symbols doctor"
            }))
        }
        DoctorSubject::Target { target } => {
            let symbol = if let Some(address) = address {
                status_value(state.targets.symbol_by_offset(TargetAddressRequest {
                    target_id: *target,
                    address,
                }))
            } else {
                json!({ "ok": false, "error": "Pass address for target symbol/source checks." })
            };
            let source = if let Some(address) = address {
                status_value(state.targets.source_by_offset(TargetAddressRequest {
                    target_id: *target,
                    address,
                }))
            } else {
                json!({ "ok": false, "error": "Pass address for target symbol/source checks." })
            };
            let status = status_value(
                state
                    .targets
                    .target_status(TargetRequest { target_id: *target }),
            );
            Ok(json!({
                "status": "ok",
                "duration_ms": Value::Null,
                "truncated": false,
                "value": {
                    "target_status": status,
                    "symbol_by_offset": symbol,
                    "source_by_offset": source
                },
                "diagnostics": [
                    {
                        "id": "symbols.target.follow_up",
                        "severity": "info",
                        "summary": "Target symbol quality depends on DbgEng symbol path and loaded modules.",
                        "detail": "This doctor samples target status plus optional offset lookups.",
                        "confidence": "high",
                        "fix": {
                            "description": "Confirm symbol path and module load state on the target session.",
                            "command": null
                        }
                    }
                ],
                "command": "symbols doctor"
            }))
        }
    }
}

fn symbol_module_scope(
    state: &mut ServiceState,
    request: &SymbolsDiagnoseRequest,
) -> anyhow::Result<Value> {
    if request.name.is_none() && request.address.is_none() {
        let modules = status_value(state.ttd.list_modules(request.session_id));
        let pe_diagnostics = modules["value"]["modules"]
            .as_array()
            .map(|modules| session_pe_diagnostics(modules))
            .unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error": "module list is unavailable"
                })
            });
        return Ok(json!({
            "kind": "session",
            "modules": modules,
            "pe_diagnostics": pe_diagnostics
        }));
    }

    let address = request
        .address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let module = status_value(state.ttd.module_info(ModuleInfoRequest {
        session_id: request.session_id,
        name: request.name.clone(),
        address,
    }));
    let pe_diagnostics = module["value"]["module"]
        .as_object()
        .map(|_| module_pe_diagnostics(&module["value"]["module"]))
        .unwrap_or_else(|| {
            json!({
                "ok": false,
                "error": "module info is unavailable"
            })
        });
    Ok(json!({
        "kind": if request.name.is_some() { "module_name" } else { "module_address" },
        "module": module,
        "pe_diagnostics": pe_diagnostics
    }))
}

fn session_pe_diagnostics(modules: &[Value]) -> Value {
    const MAX_PARSED_MODULES: usize = 32;

    let mut with_path_count = 0usize;
    let mut local_file_count = 0usize;
    let mut parsed_count = 0usize;
    let mut samples = Vec::new();

    for module in modules {
        let Some(path) = module_path(module) else {
            continue;
        };
        with_path_count += 1;
        let path = PathBuf::from(path);
        if !path.exists() {
            continue;
        }
        local_file_count += 1;
        if samples.len() >= MAX_PARSED_MODULES {
            continue;
        }
        let diagnostic = module_pe_diagnostics(module);
        if diagnostic["ok"].as_bool() == Some(true) {
            parsed_count += 1;
        }
        samples.push(diagnostic);
    }

    json!({
        "ok": true,
        "total_modules": modules.len(),
        "modules_with_path": with_path_count,
        "local_files": local_file_count,
        "parsed_count": parsed_count,
        "sample_limit": MAX_PARSED_MODULES,
        "truncated": local_file_count > MAX_PARSED_MODULES,
        "samples": samples,
        "hint": "Use symbols diagnose with name or address for a single-module PE/PDB identity."
    })
}

fn module_pe_diagnostics(module: &Value) -> Value {
    let name = module["name"].as_str().unwrap_or_default();
    let Some(path) = module_path(module) else {
        return json!({
            "ok": false,
            "module": name,
            "reason": "module path is not available"
        });
    };
    let path = PathBuf::from(path);
    if !path.exists() {
        return json!({
            "ok": false,
            "module": name,
            "path": path,
            "reason": "module binary is not available at this path"
        });
    }

    match diagnose_pe(&path) {
        Ok(pe) => json!({
            "ok": true,
            "module": name,
            "path": path,
            "pe": pe
        }),
        Err(error) => json!({
            "ok": false,
            "module": name,
            "path": path,
            "error": error.to_string()
        }),
    }
}

fn module_path(module: &Value) -> Option<&str> {
    module["path"].as_str().filter(|path| !path.is_empty())
}

fn filter_exports<'a>(exports: &'a [ExportSymbol], filter: Option<&str>) -> Vec<&'a ExportSymbol> {
    exports
        .iter()
        .filter(|export| {
            let Some(filter) = filter else {
                return true;
            };
            export
                .name
                .as_deref()
                .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export
                    .forwarder
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export.ordinal.to_string().contains(filter)
        })
        .collect()
}

fn nearest_export(exports: &[ExportSymbol], rva: u32) -> Option<&ExportSymbol> {
    exports
        .iter()
        .filter(|export| export.forwarder.is_none() && export.rva <= rva)
        .max_by_key(|export| export.rva)
}

fn export_display_name(export: &ExportSymbol, displacement: u64) -> String {
    let name = export
        .name
        .clone()
        .unwrap_or_else(|| format!("#{}", export.ordinal));
    if displacement == 0 {
        name
    } else {
        format!("{name}+0x{displacement:x}")
    }
}

fn symbol_diagnostic_checks(capabilities: Option<&Value>, module_scope: &Value) -> Value {
    let symbols = capabilities.and_then(|value| value.get("symbols"));
    let native = capabilities
        .and_then(|value| value.get("native"))
        .and_then(Value::as_bool);
    let symbol_path = symbols
        .and_then(|value| value.get("symbol_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let image_path = symbols
        .and_then(|value| value.get("image_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_symbols = symbols
        .and_then(|value| value.get("microsoft_public_symbols"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let binary_path_count = symbols
        .and_then(|value| value.get("binary_path_count"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let module_data_available = module_scope["modules"]["ok"].as_bool() == Some(true)
        || module_scope["module"]["ok"].as_bool() == Some(true);
    let pe_diagnostics = &module_scope["pe_diagnostics"];
    let pe_identity_available = pe_diagnostics["ok"].as_bool() == Some(true)
        && (pe_diagnostics["parsed_count"].as_u64().unwrap_or_default() > 0
            || pe_diagnostics["pe"].is_object());
    let pdb_identity_available = pe_diagnostics["pe"]["codeview"].is_object()
        || pe_diagnostics["samples"].as_array().is_some_and(|samples| {
            samples
                .iter()
                .any(|sample| sample["pe"]["codeview"].is_object())
        });

    json!([
        {
            "id": "native-replay",
            "status": if native == Some(true) { "pass" } else { "warn" },
            "evidence": native,
            "why_it_matters": "Native replay is required for real module inventories and cursor-backed symbol context."
        },
        {
            "id": "symbol-path",
            "status": if symbol_path.is_empty() { "warn" } else { "pass" },
            "evidence": symbol_path,
            "why_it_matters": "DbgHelp/SymSrv need a symbol path before public or private PDBs can be found."
        },
        {
            "id": "microsoft-public-symbols",
            "status": if public_symbols { "pass" } else { "info" },
            "evidence": public_symbols,
            "why_it_matters": "Public Microsoft symbols are enough for many Windows module/function names."
        },
        {
            "id": "binary-path",
            "status": if !image_path.is_empty() || binary_path_count > 0 { "pass" } else { "info" },
            "evidence": {
                "image_path": image_path,
                "binary_path_count": binary_path_count
            },
            "why_it_matters": "Local binaries improve stack walking, disassembly, and symbol-server binary fallback workflows."
        },
        {
            "id": "module-data",
            "status": if module_data_available { "pass" } else { "warn" },
            "evidence": module_scope,
            "why_it_matters": "Module identity is the anchor for timestamp/size/PDB/source diagnostics."
        },
        {
            "id": "pe-image-identity",
            "status": if pe_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "PE timestamp and SizeOfImage form the symbol-server key for image/binary lookup."
        },
        {
            "id": "pdb-codeview-identity",
            "status": if pdb_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "RSDS GUID plus age form the symbol-server key for PDB lookup."
        },
        {
            "id": "source-fidelity",
            "status": "future",
            "evidence": "PDB source-file and checksum inspection is not implemented yet.",
            "why_it_matters": "Source paths should be resolved with trailing-component matching and verified with hashes where available."
        }
    ])
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
