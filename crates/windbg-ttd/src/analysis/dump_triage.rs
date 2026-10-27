//! Offline dump inspect/triage analysis shared by MCP tools and the CLI.

use super::util::parse_u64_argument;
use anyhow::Context;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use windbg_dbgeng::{
    open_dump_session, DebuggerSession, DumpOpenOptions, KernelDumpHeaderInventory,
    MinidumpException, ModuleInfo, UserDumpStreams,
};
use windbg_symbols::{
    image_matches, inspect_pe_image_identity, prefetch_image, prefetch_pdb, NativeImageStatus,
    NativeSymbolStatus, PeImageIdentity,
};

fn default_max_frames() -> u32 {
    8
}

fn default_symbol_cache() -> PathBuf {
    PathBuf::from(".windbg-symbol-cache")
}

fn default_image_path() -> Vec<PathBuf> {
    Vec::new()
}

/// Request for offline dump inspect / triage / pool-triage analysis.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DumpTriageRequest {
    /// Path to the dump file.
    pub path: PathBuf,
    /// Maximum stack frames to capture.
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
    /// Request DbgEng symbol reload for fault-related modules.
    #[serde(default)]
    pub refresh_symbols: bool,
    /// Local symbol/image cache directory.
    #[serde(default = "default_symbol_cache")]
    pub symbol_cache: PathBuf,
    /// Extra directories to search for matching PE images.
    #[serde(default = "default_image_path")]
    pub image_path: Vec<PathBuf>,
    /// Prefer offline cache-only symbol/image resolution.
    #[serde(default)]
    pub offline: bool,
    /// Optional address to probe with bounded inspection.
    #[serde(default)]
    pub inspect_address: Option<String>,
    /// Optional pool tracker table base for membership checks.
    #[serde(default)]
    pub tracker_table_base: Option<String>,
    /// Analysis profile: "inspect" | "triage" | "pool_triage".
    #[serde(default)]
    pub profile: Option<String>,
}

fn triage_profile_label(profile: Option<&str>) -> &'static str {
    match profile {
        Some("inspect") => "inspect",
        Some("triage") => "bugcheck_context",
        Some("pool_triage") | Some("pool-triage") => "bounded_pool_corruption",
        _ => "bounded_pool_corruption",
    }
}

/// Open a dump and produce the structured inspect/triage JSON payload.
pub fn dump_triage(request: DumpTriageRequest) -> anyhow::Result<Value> {
    let inspected_address = request
        .inspect_address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let tracker_table_base = request
        .tracker_table_base
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let dump_metadata = fs::metadata(&request.path)
        .with_context(|| format!("reading dump metadata for {}", request.path.display()))?;
    let minidump_directory = windbg_dbgeng::inspect_minidump_directory(&request.path);
    let kernel_dump_header = windbg_dbgeng::inspect_kernel_dump_header(&request.path);
    let operation_started = Instant::now();
    let opened_at = Instant::now();
    let session = open_dump_session(DumpOpenOptions {
        path: request.path.clone(),
    })?;
    let open_elapsed_ms = opened_at.elapsed().as_millis() as u64;
    let target = session.summary();
    let modules_started = Instant::now();
    let modules = session.modules()?;
    let modules_elapsed_ms = modules_started.elapsed().as_millis() as u64;
    let bugcheck_started = Instant::now();
    let bugcheck = session.bugcheck_data();
    let bugcheck_elapsed_ms = bugcheck_started.elapsed().as_millis() as u64;
    let mut user_exception = session.user_dump_exception(&minidump_directory)?;
    let symbols_started = Instant::now();
    let native_symbols = prepare_dump_native_symbols(
        &session,
        &modules,
        &bugcheck,
        user_exception.as_ref(),
        &request.symbol_cache,
        &request.image_path,
        request.offline,
    );
    let symbols_elapsed_ms = symbols_started.elapsed().as_millis() as u64;
    let threads_started = Instant::now();
    let threads = session.threads()?;
    let threads_elapsed_ms = threads_started.elapsed().as_millis() as u64;
    let registers_started = Instant::now();
    let registers = session.core_registers()?;
    let registers_elapsed_ms = registers_started.elapsed().as_millis() as u64;
    let stack_started = Instant::now();
    let stack = session.stack_trace_result(request.max_frames)?;
    let stack_elapsed_ms = stack_started.elapsed().as_millis() as u64;
    let triage_started = Instant::now();
    if let Some(exception) = &mut user_exception {
        session.unwind_user_dump_exception(exception, request.max_frames);
    }
    let user_streams = user_exception.as_ref().map(|exception| {
        windbg_dbgeng::inspect_user_dump_streams(
            &request.path,
            &minidump_directory,
            exception
                .record
                .as_ref()
                .map(|record| record.exception_address),
            exception.thread_system_id,
        )
    });
    let triage = dump_triage_value(
        &session,
        DumpTriageInput {
            target: &target,
            modules: &modules,
            bugcheck: &bugcheck,
            user_exception: user_exception.as_ref(),
            user_streams: user_streams.as_ref(),
            kernel_dump_header: &kernel_dump_header,
            current_stack: &stack,
            max_frames: request.max_frames,
            refresh_symbols: request.refresh_symbols,
            native_symbols,
            inspected_address,
            tracker_table_base,
        },
    );
    let triage_elapsed_ms = triage_started.elapsed().as_millis() as u64;
    Ok(json!({
        "triage_profile": if user_exception.is_some() && request.profile.as_deref() != Some("inspect") {
            "user_exception_context"
        } else {
            triage_profile_label(request.profile.as_deref())
        },
        "target": target,
        "minidump_directory": minidump_directory,
        "kernel_dump_header": kernel_dump_header,
        "modules": modules,
        "threads": threads,
        "registers": registers,
        "frames": stack.frames,
        "triage": triage,
        "telemetry": {
            "source": "host_monotonic_wall_clock",
            "dump_file_bytes": dump_metadata.len(),
            "dump_open_elapsed_ms": open_elapsed_ms,
            "module_enumeration_elapsed_ms": modules_elapsed_ms,
            "bugcheck_read_elapsed_ms": bugcheck_elapsed_ms,
            "native_symbol_preparation_elapsed_ms": symbols_elapsed_ms,
            "thread_enumeration_elapsed_ms": threads_elapsed_ms,
            "register_read_elapsed_ms": registers_elapsed_ms,
            "stack_walk_elapsed_ms": stack_elapsed_ms,
            "triage_elapsed_ms": triage_elapsed_ms,
            "total_elapsed_ms": operation_started.elapsed().as_millis() as u64,
            "bounded_operations": {
                "stack_frame_limit": request.max_frames,
                "minidump_directory_entry_limit": windbg_dbgeng::MAX_MINIDUMP_DIRECTORY_ENTRIES,
                "captured_event_code_byte_limit": windbg_dbgeng::MAX_CAPTURED_EVENT_CODE_BYTES,
                "minidump_stream_payloads_decoded": user_exception.as_ref().is_some_and(|exception| exception.record.is_some()) || user_streams.is_some(),
                "auxiliary_stream_limits": user_streams.as_ref().map(|_| json!({
                    "modules": windbg_dbgeng::MAX_STREAM_MODULES,
                    "unloaded_modules": windbg_dbgeng::MAX_STREAM_UNLOADED_MODULES,
                    "thread_names": windbg_dbgeng::MAX_STREAM_THREAD_NAMES,
                    "memory_regions": windbg_dbgeng::MAX_STREAM_MEMORY_REGIONS,
                    "handles": windbg_dbgeng::MAX_STREAM_HANDLES,
                    "string_bytes": windbg_dbgeng::MAX_STREAM_STRING_BYTES,
                })),
                "fault_origin_function_byte_limit": super::fault_origin::FAULT_ORIGIN_MAX_FUNCTION_BYTES,
                "fault_origin_hop_limit": super::fault_origin::FAULT_ORIGIN_MAX_HOPS,
                "user_exception_context_byte_limit": windbg_dbgeng::MAX_USER_EXCEPTION_CONTEXT_BYTES,
                "user_exception_nested_record_limit": windbg_dbgeng::MAX_NESTED_EXCEPTION_RECORDS,
                "user_exception_cpp_type_limit": windbg_dbgeng::MAX_CPP_EXCEPTION_TYPES,
                "user_exception_string_byte_limit": windbg_dbgeng::MAX_EXCEPTION_STRING_BYTES,
                "fault_instruction_byte_limit": super::fault_operand::FAULT_INSTRUCTION_BYTES,
                "user_exception_stack_frame_limit": windbg_dbgeng::MAX_USER_EXCEPTION_STACK_FRAMES,
                "whole_dump_scan": false,
            },
        },
    }))
}

fn prepare_dump_native_symbols(
    session: &DebuggerSession,
    _modules: &[ModuleInfo],
    bugcheck: &windbg_dbgeng::BugCheckDataResult,
    user_exception: Option<&MinidumpException>,
    cache_dir: &Path,
    extra_image_paths: &[PathBuf],
    offline: bool,
) -> Value {
    let fault_address =
        dump_target_fault_address(bugcheck.data.as_ref(), user_exception).or_else(|| {
            session
                .core_registers()
                .ok()
                .and_then(|registers| registers.instruction_offset)
        });
    let Some(fault_address) = fault_address else {
        return json!({
            "status": "not_applicable",
            "detail": "The dump did not provide a fault address or current instruction for native symbol prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let Some(module) = session.module_by_offset(fault_address).ok().flatten() else {
        return json!({
            "status": "unavailable",
            "detail": "DbgEng could not map the fault address to a module for native symbol prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let Some(parameters) = session
        .module_parameters(&[module.base_address])
        .ok()
        .and_then(|mut values| values.pop())
    else {
        return json!({
            "status": "unavailable",
            "module": module,
            "detail": "DbgEng did not provide module timestamp and image-size data needed to validate a host image.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let image_roots = dump_image_roots(extra_image_paths);
    let image_names = [
        module.image_name.as_deref(),
        module.loaded_image_name.as_deref(),
        module.symbol_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|name| Path::new(name).file_name())
    .collect::<BTreeSet<_>>();
    let Some(image_name) = image_names.iter().next().and_then(|name| name.to_str()) else {
        return json!({
            "status": "unavailable",
            "module": module,
            "module_parameters": parameters,
            "detail": "DbgEng did not provide a usable module image filename for native prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let expected_image = match PeImageIdentity::new(
        image_name,
        parameters.time_date_stamp,
        parameters.image_size,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "module": module,
                "module_parameters": parameters,
                "detail": format!("The dump module image identity was invalid: {error:#}"),
                "offline": offline,
                "cache_dir": cache_dir,
            });
        }
    };

    let mut rejected = Vec::new();
    let mut selected_image = None;
    for root in &image_roots {
        for name in &image_names {
            let image_path = root.join(name);
            if !image_path.is_file() {
                continue;
            }
            match image_matches(&image_path, &expected_image) {
                Ok(true) => {
                    selected_image = Some((
                        image_path,
                        json!({
                            "status": NativeImageStatus::Local,
                            "detail": "Used the caller-provided or host-local image after validating its timestamp and SizeOfImage."
                        }),
                    ));
                    break;
                }
                Ok(false) => match inspect_pe_image_identity(&image_path) {
                    Ok(identity) => rejected.push(json!({
                    "image_path": image_path,
                    "status": "mismatch",
                    "observed_timestamp": identity.image_timestamp,
                    "expected_timestamp": parameters.time_date_stamp,
                    "observed_image_size": identity.image_size,
                    "expected_image_size": parameters.image_size,
                    })),
                    Err(error) => rejected.push(json!({
                        "image_path": image_path,
                        "status": "unreadable",
                        "detail": format!("{error:#}"),
                    })),
                },
                Err(error) => rejected.push(json!({
                    "image_path": image_path,
                    "status": "unreadable",
                    "detail": format!("{error:#}"),
                })),
            }
        }
        if selected_image.is_some() {
            break;
        }
    }
    let (image_path, image_prefetch) = match selected_image {
        Some(selected) => selected,
        None => match prefetch_image(expected_image, cache_dir, offline) {
            Ok(image) => match image.image_path.clone() {
                Some(path) => (path, json!(image)),
                None => {
                    return json!({
                        "status": match image.status {
                            NativeImageStatus::OfflineMissing => "offline_image_missing",
                            NativeImageStatus::Unavailable => "unavailable",
                            _ => "image_not_found",
                        },
                        "module": module,
                        "module_parameters": parameters,
                        "image_prefetch": image,
                        "cache_dir": cache_dir,
                        "offline": offline,
                        "image_search_paths": image_roots,
                        "rejected_images": rejected,
                    });
                }
            },
            Err(error) => {
                return json!({
                    "status": "failed",
                    "module": module,
                    "module_parameters": parameters,
                    "cache_dir": cache_dir,
                    "offline": offline,
                    "image_search_paths": image_roots,
                    "rejected_images": rejected,
                    "detail": format!("Rust-native image prefetch failed: {error:#}"),
                });
            }
        },
    };
    let image_directory = image_path
        .parent()
        .expect("validated PE image path has a parent")
        .to_path_buf();
    let prefetch = match prefetch_pdb(&image_path, cache_dir, offline) {
        Ok(result) => result,
        Err(error) => {
            return json!({
                "status": "failed",
                "module": module,
                "image_path": image_path,
                "image_prefetch": image_prefetch,
                "cache_dir": cache_dir,
                "offline": offline,
                "detail": format!("Rust-native PDB prefetch failed: {error:#}"),
            });
        }
    };
    let Some(pdb_path) = prefetch.pdb_path.as_ref() else {
        return json!({
            "status": prefetch.status,
            "module": module,
            "image_path": image_path,
            "image_prefetch": image_prefetch,
            "prefetch": prefetch,
            "offline": offline,
        });
    };
    let pdb_directory = pdb_path
        .parent()
        .expect("PDB cache path has a parent")
        .to_path_buf();
    let configure = session.configure_local_symbol_paths(
        std::slice::from_ref(&pdb_directory),
        std::slice::from_ref(&image_directory),
    );
    let reload = configure.and_then(|()| {
        module
            .module_name
            .as_deref()
            .context("DbgEng did not provide a fault-module name for forced local reload")
            .and_then(|name| session.refresh_symbols(name))
    });
    let resolved_symbol = reload
        .as_ref()
        .ok()
        .and_then(|()| session.symbol_by_offset(fault_address).ok().flatten());
    json!({
        "status": match prefetch.status {
            NativeSymbolStatus::Cached => "configured_from_cache",
            NativeSymbolStatus::Downloaded => "downloaded_and_configured",
            NativeSymbolStatus::OfflineMissing => "offline_missing",
            NativeSymbolStatus::Unavailable => "unavailable",
        },
        "module": module,
        "module_parameters": parameters,
        "image_path": image_path,
        "image_prefetch": image_prefetch,
        "pdb_directory": pdb_directory,
        "prefetch": prefetch,
        "forced_reload": match reload {
            Ok(()) => json!({"status": "loaded"}),
            Err(error) => json!({"status": "failed", "detail": format!("{error:#}")}),
        },
        "resolved_fault_symbol": resolved_symbol,
        "offline": offline,
    })
}

fn dump_image_roots(extra_image_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = extra_image_paths.to_vec();
    if let Some(system_root) = env::var_os("SystemRoot").map(PathBuf::from) {
        roots.push(system_root.join("System32"));
        roots.push(system_root.join("System32").join("drivers"));
    }
    let mut deduplicated = Vec::new();
    for root in roots {
        if !deduplicated.contains(&root) {
            deduplicated.push(root);
        }
    }
    deduplicated
}

struct DumpTriageInput<'a> {
    target: &'a windbg_dbgeng::DebuggerSessionSummary,
    modules: &'a [ModuleInfo],
    bugcheck: &'a windbg_dbgeng::BugCheckDataResult,
    user_exception: Option<&'a MinidumpException>,
    user_streams: Option<&'a UserDumpStreams>,
    kernel_dump_header: &'a KernelDumpHeaderInventory,
    current_stack: &'a windbg_dbgeng::StackTraceResult,
    max_frames: u32,
    refresh_symbols: bool,
    native_symbols: Value,
    inspected_address: Option<u64>,
    tracker_table_base: Option<u64>,
}

fn dump_triage_value(session: &DebuggerSession, input: DumpTriageInput<'_>) -> Value {
    let bugcheck_data = input.bugcheck.data.as_ref();
    let fault_address = dump_target_fault_address(bugcheck_data, input.user_exception);
    let fault = fault_address.map(|address| dump_address_observation(session, address, 8));
    let exception_context = match input.user_exception {
        Some(exception) => Some(json!({
            "status": exception.context.status,
            "selection": exception.source,
            "thread_system_id": exception.thread_system_id,
            "context": exception.context,
            "detail": exception.context.detail,
        })),
        None => dump_exception_context(session, input.target, bugcheck_data, input.max_frames),
    };
    let exception_record = match input.user_exception {
        Some(exception) => Some(json!({
            "status": exception.status,
            "source": exception.source,
            "thread_system_id": exception.thread_system_id,
            "selection": exception.record,
            "detail": exception.detail,
        })),
        None => dump_exception_record(session, bugcheck_data, input.current_stack),
    };
    let snapshot_event = dump_snapshot_event_observation(session, input.bugcheck);
    let debugger_context = dump_debugger_context(session);
    let kernel_only = json!({
        "status": "not_applicable",
        "detail": "Kernel driver/pool attribution is not applicable to a user-mode dump.",
    });
    let verifier = if input.user_exception.is_some() {
        kernel_only.clone()
    } else {
        dump_verifier_observation(session)
    };
    let symbol_modules = dump_symbol_modules(session, fault_address, &exception_context);
    let symbol_readiness = dump_symbol_readiness(session, &symbol_modules, input.refresh_symbols);
    let driver_evidence = if input.user_exception.is_some() {
        kernel_only.clone()
    } else {
        dump_driver_evidence(
            session,
            input.modules,
            fault_address,
            input.current_stack,
            &exception_context,
        )
    };
    let pool_tracker = if input.user_exception.is_some() {
        kernel_only.clone()
    } else {
        dump_pool_tracker_observation(
            session,
            &exception_context,
            &fault,
            input.tracker_table_base,
        )
    };
    let address_inspection = input
        .inspected_address
        .map(|address| dump_address_inspection(session, address, input.tracker_table_base));
    let bugcheck_driver = if input.user_exception.is_some() {
        kernel_only.clone()
    } else {
        dump_bugcheck_driver(session)
    };
    let evidence = if input.user_exception.is_some() {
        json!({
            "source": "minidump_exception_stream",
            "detail": "The captured exception record/context describe the recorded exception, not its lifecycle cause. The current debugger stack remains separate from the exception-context unwind; kernel driver attribution is not applicable.",
        })
    } else {
        dump_evidence_grades(&driver_evidence, &pool_tracker, &bugcheck_driver)
    };

    json!({
        "bugcheck": dump_bugcheck_value(input.bugcheck),
        "bugcheck_reconciliation": dump_bugcheck_reconciliation(
            input.bugcheck,
            input.kernel_dump_header,
        ),
        "fault": fault,
        "fault_operand": input.user_exception.map_or(Value::Null, |exception| {
            super::fault_operand::fault_operand_hint(exception, &|address, size| {
                windbg_dbgeng::GuestMemory::read_guest(session, address, size)
            })
        }),
        "fault_origin": input.user_exception.map_or(Value::Null, |exception| {
            dump_fault_origin(session, exception, input.user_streams)
        }),
        "user_dump_streams": input.user_streams.map_or(Value::Null, |streams| {
            dump_user_streams_value(streams, input.user_exception)
        }),
        "exception_context": exception_context,
        "exception_record": exception_record,
        "snapshot_event": snapshot_event,
        "debugger_context": debugger_context,
        "driver_verifier": verifier,
        "current_stack": input.current_stack,
        "symbol_readiness": symbol_readiness,
        "native_symbol_prefetch": input.native_symbols,
        "driver_evidence": driver_evidence,
        "bugcheck_driver": bugcheck_driver,
        "pool_tracker": pool_tracker,
        "address_inspection": address_inspection,
        "evidence": evidence,
        "data_limits": dump_data_limits(
            input.target,
            input.current_stack,
            input.bugcheck,
            &fault,
            &exception_context,
        ),
        "recommendations": if input.user_exception.is_some() {
            json!([{
                "priority": "high",
                "detail": "Use the captured exception code, access parameters, fault-time registers and exception_context.context.stack. Top-level frames/registers and current_stack are debugger snapshot state, which may be inside WER. If the exception-context unwind is unavailable or invalid, do not substitute the snapshot stack or infer unobserved callers.",
            }, {
                "priority": "medium",
                "detail": "fault_operand names the faulting memory operand, base register and value from the captured context; it shows which pointer was bad at fault time, not why. Check exception_record.selection for C++ type names, fast-fail codes, CLR markers and nested records before inferring a cause.",
            }, {
                "priority": "medium",
                "detail": "fault_origin walks back (linearly, not path-sensitively) to the instruction that loaded the faulting register and re-reads the source slot/object from the dump; use it to name the field that held the bad pointer, then confirm with source or disassembly. user_dump_streams.fault_module gives the exact build (file version, timestamp, PDB GUID/age) to match symbols and source.",
            }])
        } else {
            dump_recommendations(input.bugcheck)
        },
    })
}

fn dump_fault_origin(
    session: &DebuggerSession,
    exception: &MinidumpException,
    streams: Option<&UserDumpStreams>,
) -> Value {
    let architecture = exception.context.architecture_kind();
    super::fault_origin::fault_origin(
        exception,
        &super::fault_origin::FaultOriginSources {
            read: &|address, size| windbg_dbgeng::GuestMemory::read_guest(session, address, size),
            function_start: &|address| session.function_start(address, architecture?),
            symbol: &|address| {
                session
                    .symbol_by_offset(address)
                    .ok()
                    .flatten()
                    .map(|symbol| (symbol.name, symbol.displacement))
            },
            region: &|address| {
                streams
                    .and_then(|streams| streams.region_for(address))
                    .map(|region| json!(region))
            },
        },
    )
}

fn dump_user_streams_value(
    streams: &UserDumpStreams,
    exception: Option<&MinidumpException>,
) -> Value {
    let mut value = json!(streams);
    let mut probes = Vec::new();
    if let Some(exception) = exception {
        let record = exception.record.as_ref();
        for (label, address) in [
            (
                "exception_address",
                record.map(|record| record.exception_address),
            ),
            (
                "access_address",
                record.and_then(|record| record.access.as_ref().map(|access| access.address)),
            ),
            ("stack_pointer", exception.context.stack_pointer),
        ] {
            if let Some(address) = address {
                probes.push(json!({
                    "label": label,
                    "address": address,
                    "region": streams.region_for(address),
                }));
            }
        }
    }
    value["probed_regions"] = json!(probes);
    value
}

fn dump_target_fault_address(
    bugcheck: Option<&windbg_dbgeng::BugCheckData>,
    user_exception: Option<&MinidumpException>,
) -> Option<u64> {
    match user_exception {
        Some(exception) => exception
            .record
            .as_ref()
            .map(|record| record.exception_address),
        None => bugcheck.and_then(dump_fault_address),
    }
}

fn dump_fault_address(data: &windbg_dbgeng::BugCheckData) -> Option<u64> {
    match data.code {
        0x0000_001E | 0x0000_003B => Some(data.parameters[1]),
        _ => None,
    }
}

fn dump_exception_context(
    session: &DebuggerSession,
    target: &windbg_dbgeng::DebuggerSessionSummary,
    bugcheck: Option<&windbg_dbgeng::BugCheckData>,
    max_frames: u32,
) -> Option<Value> {
    let data = bugcheck?;
    let candidates = match data.code {
        0x0000_003B => vec![("parameter_3_exception_context", data.parameters[2])],
        // KMODE_EXCEPTION_NOT_HANDLED does not promise a CONTEXT parameter. Some
        // contemporary kernel builds preserve one in parameter four, so probe only
        // the documented-size record and report the result as a heuristic.
        0x0000_001E => vec![
            ("heuristic_parameter_4_context", data.parameters[3]),
            ("heuristic_parameter_3_context", data.parameters[2]),
        ],
        _ => return None,
    };
    if target.processor_type != Some(0x8664) {
        return Some(json!({
            "status": "architecture_unsupported",
            "candidates": candidates.into_iter().map(|(source, address)| json!({
                "source": source,
                "context_record_address": address,
            })).collect::<Vec<_>>(),
            "detail": "The bugcheck supplied or suggested a context address, but x64 decoding is only implemented for AMD64 dump targets.",
        }));
    }

    let decoded = candidates
        .into_iter()
        .map(|(source, address)| {
            let context = session.x64_exception_context(address, max_frames);
            json!({
                "source": source,
                "context": context,
            })
        })
        .collect::<Vec<_>>();
    let selected = decoded.iter().find(|candidate| {
        matches!(
            candidate["context"]["status"].as_str(),
            Some("captured" | "context_captured_stack_unavailable")
        )
    });
    Some(json!({
        "status": selected
            .and_then(|candidate| candidate["context"]["status"].as_str())
            .unwrap_or("unavailable"),
        "selection": selected
            .and_then(|candidate| candidate["source"].as_str())
            .unwrap_or("none"),
        "context": selected.map(|candidate| candidate["context"].clone()),
        "candidates": decoded,
        "detail": if data.code == 0x0000_001E {
            "For bugcheck 0x1E, context candidates are bounded structural probes rather than a documented parameter contract."
        } else {
            "The decoded context comes from the documented SYSTEM_SERVICE_EXCEPTION context-record parameter."
        },
    }))
}

fn dump_bugcheck_value(bugcheck: &windbg_dbgeng::BugCheckDataResult) -> Value {
    let Some(data) = &bugcheck.data else {
        return json!({
            "status": bugcheck.status,
            "detail": bugcheck.detail,
        });
    };
    let name = match data.code {
        0x0000_001E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x0000_003B => "SYSTEM_SERVICE_EXCEPTION",
        0x0000_0051 => "REGISTRY_ERROR",
        _ => "UNKNOWN",
    };
    let parameter_roles = match data.code {
        0x0000_001E => json!([
            "exception_code",
            "fault_instruction_address",
            "exception_parameter_0",
            "exception_parameter_1_or_build_specific_context_candidate",
        ]),
        0x0000_003B => json!([
            "exception_code",
            "fault_instruction_address",
            "exception_context_record_address",
            "unused",
        ]),
        0x0000_0051 => json!([
            "reserved",
            "reserved",
            "registry_hive_pointer_if_available",
            "HvCheckHive_return_code_if_available",
        ]),
        _ => Value::Null,
    };
    json!({
        "status": bugcheck.status,
        "code": data.code,
        "name": name,
        "parameters": data.parameters,
        "parameter_roles": parameter_roles,
        "detail": bugcheck.detail,
    })
}

fn dump_exception_record(
    session: &DebuggerSession,
    bugcheck: Option<&windbg_dbgeng::BugCheckData>,
    stack: &windbg_dbgeng::StackTraceResult,
) -> Option<Value> {
    const MAX_STACK_SCAN_BYTES: u64 = 64 * 1024;
    let data = bugcheck?;
    if !matches!(data.code, 0x0000_001E | 0x0000_003B) {
        return None;
    }
    let mut stack_addresses = stack
        .frames
        .iter()
        .take(stack.valid_frames as usize)
        .flat_map(|frame| [frame.stack_offset, frame.frame_offset])
        .filter(|address| address >> 48 == 0xFFFF);
    let Some(start) = stack_addresses.next() else {
        return Some(json!({
            "status": "unavailable",
            "detail": "The validated stack has no canonical kernel-stack addresses to scan.",
        }));
    };
    let (start, end) = stack_addresses.fold((start, start), |(minimum, maximum), address| {
        (minimum.min(address), maximum.max(address))
    });
    let requested_size = end
        .saturating_add(0x200)
        .saturating_sub(start)
        .min(MAX_STACK_SCAN_BYTES) as u32;
    let memory = match session.read_memory(start, requested_size) {
        Ok(memory) => memory,
        Err(error) => {
            return Some(json!({
                "status": "unavailable",
                "scan_start": start,
                "requested_size": requested_size,
                "detail": format!("DbgEng could not read the bounded kernel-stack window: {error}"),
            }));
        }
    };
    let Some(bytes) = decode_hex_bytes(&memory.data) else {
        return Some(json!({
            "status": "unavailable",
            "scan_start": start,
            "requested_size": requested_size,
            "detail": "DbgEng returned malformed hexadecimal for the bounded kernel-stack window.",
        }));
    };
    let candidates =
        scan_x64_exception_records(start, &bytes, data.parameters[0] as u32, data.parameters[1]);
    Some(json!({
        "status": match candidates.len() {
            0 => "not_found",
            1 => "captured",
            _ => "ambiguous",
        },
        "selection": (candidates.len() == 1).then(|| candidates[0].clone()),
        "candidates": candidates,
        "scan_start": start,
        "bytes_read": memory.bytes_read,
        "requested_size": requested_size,
        "detail": "Candidates use the documented EXCEPTION_RECORD64 layout and must match both the bugcheck exception code and exact fault address. The kernel-stack scan is bounded to 64 KiB.",
    }))
}

fn scan_x64_exception_records(
    base_address: u64,
    bytes: &[u8],
    expected_code: u32,
    expected_address: u64,
) -> Vec<Value> {
    const HEADER_SIZE: usize = 0x20;
    let mut candidates = Vec::new();
    for offset in (0..bytes.len().saturating_sub(HEADER_SIZE - 1)).step_by(4) {
        let Some(code) = stack_u32(bytes, offset) else {
            continue;
        };
        let Some(address) = stack_u64(bytes, offset + 0x10) else {
            continue;
        };
        let Some(parameter_count) = stack_u32(bytes, offset + 0x18) else {
            continue;
        };
        if code != expected_code || address != expected_address || parameter_count > 15 {
            continue;
        }
        let record_size = HEADER_SIZE + parameter_count as usize * 8;
        if offset + record_size > bytes.len() {
            continue;
        }
        let parameters = (0..parameter_count as usize)
            .filter_map(|index| stack_u64(bytes, offset + HEADER_SIZE + index * 8))
            .collect::<Vec<_>>();
        candidates.push(json!({
            "record_address": base_address + offset as u64,
            "exception_code": code,
            "exception_flags": stack_u32(bytes, offset + 4),
            "nested_exception_record": stack_u64(bytes, offset + 8),
            "exception_address": address,
            "number_parameters": parameter_count,
            "parameters": parameters,
        }));
    }
    candidates
}

fn stack_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn stack_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn dump_bugcheck_reconciliation(
    bugcheck: &windbg_dbgeng::BugCheckDataResult,
    raw_header: &KernelDumpHeaderInventory,
) -> Value {
    let dbgeng = bugcheck.data.as_ref();
    let raw = raw_header.bugcheck_code.zip(raw_header.bugcheck_parameters);
    let status = match (dbgeng, raw) {
        (Some(dbgeng), Some((raw_code, raw_parameters)))
            if dbgeng.code == raw_code && dbgeng.parameters == raw_parameters =>
        {
            "exact_match"
        }
        (Some(_), Some(_)) => "mismatch",
        _ => "unavailable",
    };
    json!({
        "status": status,
        "dbgeng_source": "IDebugControl::ReadBugCheckData",
        "raw_source": raw_header.source,
        "raw_header_status": raw_header.status,
        "detail": match status {
            "exact_match" => "DbgEng and the independently decoded, signature-gated raw x64 kernel dump header report the same bugcheck code and four parameters.",
            "mismatch" => "DbgEng and the independently decoded raw x64 kernel dump header disagree. Do not select either tuple without resolving the discrepancy.",
            _ => "At least one bugcheck source was unavailable, so the tuples could not be reconciled.",
        },
    })
}

fn dump_debugger_context(session: &DebuggerSession) -> Value {
    let pseudo_registers = ["@$pid", "@$tid", "@$tpid", "@$ttid", "@$proc", "@$thread"]
        .into_iter()
        .map(|expression| match session.evaluate(expression) {
            Ok(value) => json!({
                "status": "captured",
                "value": value,
            }),
            Err(error) => json!({
                "status": "unavailable",
                "expression": expression,
                "detail": format!("{error:#}"),
            }),
        })
        .collect::<Vec<_>>();
    let target_executable = match session.current_process_executable_name() {
        Ok(name) => json!({
            "status": "captured",
            "name": name,
        }),
        Err(error) => json!({
            "status": "unavailable",
            "detail": format!("{error:#}"),
        }),
    };
    json!({
        "source": "documented_dbgeng_pseudo_registers",
        "debugger_target_executable": target_executable,
        "pseudo_registers": pseudo_registers,
        "detail": "The pseudo-registers identify DbgEng's selected dump process/thread context. The executable-name API can report the kernel target image rather than the selected EPROCESS image in kernel dumps. These observations are not promoted to fault-time identity unless the documented bugcheck context and validated stack independently link them.",
    })
}

fn dump_verifier_observation(session: &DebuggerSession) -> Value {
    let expression = "nt!VerifierLevel";
    let evaluation = match session.evaluate(expression) {
        Ok(value) => value,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "source": "fixed_symbol_and_bounded_memory_read",
                "expression": expression,
                "detail": format!("DbgEng could not resolve VerifierLevel: {error:#}"),
            });
        }
    };
    let Some(address) = evaluation.unsigned_value else {
        return json!({
            "status": "unavailable",
            "source": "fixed_symbol_and_bounded_memory_read",
            "expression": expression,
            "evaluation": evaluation,
            "detail": "DbgEng resolved VerifierLevel without an integer address.",
        });
    };
    let memory = match session.read_memory(address, 4) {
        Ok(memory) if memory.complete => memory,
        Ok(memory) => {
            return json!({
                "status": "partial",
                "source": "fixed_symbol_and_bounded_memory_read",
                "expression": expression,
                "address": address,
                "evaluation": evaluation,
                "memory": memory,
                "detail": "The bounded four-byte VerifierLevel read was incomplete.",
            });
        }
        Err(error) => {
            return json!({
                "status": "unavailable",
                "source": "fixed_symbol_and_bounded_memory_read",
                "expression": expression,
                "address": address,
                "evaluation": evaluation,
                "detail": format!("DbgEng could not read VerifierLevel: {error:#}"),
            });
        }
    };
    let level = decode_hex_bytes(&memory.data)
        .and_then(|bytes| bytes.get(..4)?.try_into().ok())
        .map(u32::from_le_bytes);
    let Some(level) = level else {
        return json!({
            "status": "unavailable",
            "source": "fixed_symbol_and_bounded_memory_read",
            "expression": expression,
            "address": address,
            "evaluation": evaluation,
            "memory": memory,
            "detail": "DbgEng returned malformed data for the bounded four-byte VerifierLevel read.",
        });
    };
    let configured_features = [(0x1_u32, "special_pool"), (0x8_u32, "pool_tracking")]
        .into_iter()
        .filter_map(|(mask, name)| (level & mask != 0).then_some(name))
        .collect::<Vec<_>>();
    json!({
        "status": "captured",
        "source": "fixed_symbol_and_bounded_memory_read",
        "expression": expression,
        "address": address,
        "evaluation": evaluation,
        "memory": memory,
        "level": level,
        "active": level != 0,
        "configured_features": configured_features,
        "target_driver": {
            "status": "not_established",
            "detail": "No private verifier-driver list layout is decoded. A nonzero global level establishes enabled verifier features, not which driver was targeted."
        },
        "detail": "VerifierLevel is captured by resolving one fixed symbol and reading exactly four bytes. The feature names report only the documented 0x1 Special Pool and 0x8 Pool Tracking bits; no verifier extension command or private structure traversal is used.",
    })
}

fn dump_snapshot_event_observation(
    session: &DebuggerSession,
    bugcheck: &windbg_dbgeng::BugCheckDataResult,
) -> Value {
    let fault_address = bugcheck.data.as_ref().and_then(dump_fault_address);
    let captured_code = session.captured_event_code();
    let (fault_code_snapshot, fault_code_bytes) = match fault_address {
        Some(address) => {
            match session.read_memory(address, windbg_dbgeng::MAX_CAPTURED_EVENT_CODE_BYTES) {
                Ok(memory) => {
                    let bytes = memory.complete.then_some(memory.data.clone());
                    (json!(memory), bytes)
                }
                Err(error) => (
                    json!({
                        "status": "unavailable",
                        "address": address,
                        "detail": format!(
                            "DbgEng could not read the bounded bugcheck fault-code snapshot: {error}"
                        ),
                    }),
                    None,
                ),
            }
        }
        None => (json!({"status": "not_applicable"}), None),
    };
    let code_offset_relation = match (captured_code.code_offset, fault_address) {
        (Some(captured), Some(fault)) if captured == fault => "exact_match",
        (Some(_), Some(_)) => "different_from_bugcheck_fault_address",
        (Some(_), None) => "bugcheck_has_no_documented_fault_address",
        (None, _) => "captured_event_offset_unavailable",
    };
    let code_bytes_relation = match code_offset_relation {
        "exact_match" => match (
            captured_code.code_bytes.as_deref(),
            fault_code_bytes.as_deref(),
        ) {
            (Some(captured), Some(fault)) if captured == fault => "exact_match",
            (Some(captured), Some(fault)) if fault.starts_with(captured) => {
                "captured_snapshot_matches_current_dump_prefix"
            }
            (Some(_), Some(_)) => "different_from_current_dump_memory",
            (Some(_), None) => "bugcheck_fault_code_unavailable",
            (None, _) => "captured_event_code_unavailable",
        },
        "different_from_bugcheck_fault_address" => "not_compared_different_addresses",
        "bugcheck_has_no_documented_fault_address" => "not_applicable",
        _ => "captured_event_code_unavailable",
    };
    let last_event = match session.last_event() {
        Ok(event) => json!({
            "status": "captured",
            "event": event,
        }),
        Err(error) => json!({
            "status": "unavailable",
            "detail": format!("DbgEng could not retrieve the dump's stored last event: {error}"),
        }),
    };
    json!({
        "provenance": "dump_stored_event_snapshot",
        "event_role": "metadata_only",
        "last_event": last_event,
        "captured_code": captured_code,
        "bugcheck_fault_code_snapshot": fault_code_snapshot,
        "code_offset_relation_to_bugcheck_fault_address": code_offset_relation,
        "code_bytes_relation_to_bugcheck_fault_snapshot": code_bytes_relation,
        "detail": "The bounded DbgEng captured-event requests report the dump's stored event snapshot. They are compared mechanically with the documented bugcheck fault address and a bounded current-dump memory read, but never promoted to original-exception, context, thread, fault-time register, or causation evidence without an independent provenance match.",
    })
}

fn dump_address_observation(
    session: &DebuggerSession,
    address: u64,
    disassembly_count: u32,
) -> Value {
    let module = match session.module_by_offset(address) {
        Ok(module) => serde_json::to_value(module).unwrap_or_else(|error| {
            json!({
                "status": "serialization_error",
                "detail": format!("Could not serialize the module owning 0x{address:X}: {error}"),
            })
        }),
        Err(error) => json!({
            "status": "unavailable",
            "detail": format!("DbgEng could not resolve the module owning 0x{address:X}: {error}"),
        }),
    };
    let disassembly = match session.disassemble(Some(address), disassembly_count) {
        Ok(disassembly) => serde_json::to_value(disassembly).unwrap_or_else(|error| {
            json!({
                "status": "serialization_error",
                "detail": format!("Could not serialize disassembly at 0x{address:X}: {error}"),
            })
        }),
        Err(error) => json!({
            "status": "unavailable",
            "detail": format!("The dump does not provide disassembly at 0x{address:X}: {error}"),
        }),
    };
    json!({
        "address": address,
        "module": module,
        "disassembly": disassembly,
    })
}

fn selected_exception_register(exception_context: &Option<Value>, name: &str) -> Option<u64> {
    exception_context
        .as_ref()?
        .get("context")?
        .get("registers")?
        .get(name)?
        .as_u64()
}

fn dump_bugcheck_driver(session: &DebuggerSession) -> Value {
    let pointer = match session.evaluate("poi(nt!KiBugCheckDriver)") {
        Ok(result) => match result.unsigned_value {
            Some(0) => {
                return json!({
                    "status": "not_set",
                    "pointer": 0,
                    "detail": "KiBugCheckDriver is null in this snapshot.",
                });
            }
            Some(pointer) => pointer,
            None => {
                return json!({
                    "status": "unavailable",
                    "detail": "DbgEng evaluated KiBugCheckDriver without an integer pointer result.",
                });
            }
        },
        Err(error) => {
            return json!({
                "status": "unavailable",
                "detail": format!("DbgEng could not evaluate KiBugCheckDriver: {error}"),
            });
        }
    };
    match session.read_memory(pointer, 260) {
        Ok(memory) => {
            let bytes = decode_hex_bytes(&memory.data);
            let driver_name = bytes
                .as_deref()
                .map(|bytes| {
                    let end = bytes
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(bytes.len());
                    bytes[..end]
                        .iter()
                        .map(|byte| {
                            if byte.is_ascii_graphic() || *byte == b' ' {
                                char::from(*byte)
                            } else {
                                '\u{FFFD}'
                            }
                        })
                        .collect::<String>()
                })
                .filter(|name| !name.is_empty());
            json!({
                "status": if driver_name.is_some() { "captured" } else { "pointer_present_name_unavailable" },
                "pointer": pointer,
                "driver_name": driver_name,
                "memory": memory,
                "detail": "KiBugCheckDriver is direct crash evidence only when the kernel recorded a non-null driver name.",
            })
        }
        Err(error) => json!({
            "status": "unavailable",
            "pointer": pointer,
            "detail": format!("DbgEng could not read the KiBugCheckDriver string: {error}"),
        }),
    }
}

fn dump_pool_tracker_observation(
    session: &DebuggerSession,
    exception_context: &Option<Value>,
    fault: &Option<Value>,
    supplied_table_base: Option<u64>,
) -> Value {
    const ENTRY_STRIDE: u64 = 0x50;
    let active_table = match evaluate_unsigned(session, "poi(nt!PoolTrackTable)") {
        Ok(value) if value != 0 => value,
        Ok(_) => {
            return json!({
                "status": "not_initialized",
                "detail": "nt!PoolTrackTable is null in this snapshot.",
            });
        }
        Err(error) => {
            return json!({
                "status": "unavailable",
                "detail": error,
            });
        }
    };
    let table_size = match evaluate_unsigned(session, "poi(nt!PoolTrackTableSize)") {
        Ok(value) if (1..=1_048_576).contains(&value) => value,
        Ok(value) => {
            return json!({
                "status": "unavailable",
                "active_table": active_table,
                "detail": format!("nt!PoolTrackTableSize has unsupported value {value}; bounded entry inspection was skipped."),
            });
        }
        Err(error) => {
            return json!({
                "status": "unavailable",
                "active_table": active_table,
                "detail": error,
            });
        }
    };
    let table_mask = evaluate_unsigned(session, "poi(nt!PoolTrackTableMask)").ok();
    let table_bytes = match table_size.checked_mul(ENTRY_STRIDE) {
        Some(value) => value,
        None => {
            return json!({
                "status": "unavailable",
                "active_table": active_table,
                "table_size": table_size,
                "detail": "Pool tracker table range overflowed while calculating its bounded address range.",
            });
        }
    };
    let table_end = match active_table.checked_add(table_bytes) {
        Some(value) => value,
        None => {
            return json!({
                "status": "unavailable",
                "active_table": active_table,
                "table_size": table_size,
                "detail": "Pool tracker table end overflowed while calculating its bounded address range.",
            });
        }
    };
    let entry_address = selected_exception_register(exception_context, "r8");
    let r14 = selected_exception_register(exception_context, "r14");
    let rax = selected_exception_register(exception_context, "rax");
    let entry_provenance = pool_tracker_entry_provenance(fault, entry_address, r14);
    let supplied_table =
        pool_tracker_table_relation(entry_address, supplied_table_base, table_size, ENTRY_STRIDE);
    let entry_relation = entry_address.map(|address| {
        if (active_table..table_end).contains(&address) {
            "within_active_table"
        } else {
            "outside_active_table"
        }
    });
    let nearby_entries = entry_address
        .map(|address| {
            [
                address.checked_sub(ENTRY_STRIDE),
                Some(address),
                address.checked_add(ENTRY_STRIDE),
            ]
            .into_iter()
            .flatten()
            .map(|address| pool_tracker_entry_snapshot(session, address))
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let observed_tag = nearby_entries
        .iter()
        .find(|entry| entry["address"].as_u64() == entry_address)
        .and_then(|entry| entry["tag"]["printable"].as_bool())
        .unwrap_or(false);
    let classification = match (supplied_table["relation"].as_str(), observed_tag) {
        (Some("within_supplied_table"), true) => "supplied_tracker_table_entry",
        _ => match (entry_relation, observed_tag) {
            (Some("outside_active_table"), true) => {
                "outside_central_table_tracker_like_unclassified"
            }
            (Some("outside_active_table"), false) => "outside_central_table_unclassified",
            (Some("within_active_table"), _) => "active_tracker_table_entry",
            _ => "no_validated_exception_entry_available",
        },
    };
    let per_cpu_topology = dump_per_cpu_tracker_topology(
        session,
        table_size,
        entry_address,
        supplied_table_base,
        ENTRY_STRIDE,
    );
    json!({
        "status": "captured",
        "layout": {
            "entry_stride_bytes": ENTRY_STRIDE,
            "source": "build-observed bounded layout",
            "detail": "The inspector reads raw fields at stable offsets and does not infer an allocation owner or free history from an entry.",
        },
        "active_table": active_table,
        "active_table_size": table_size,
        "active_table_mask": table_mask,
        "active_table_end_exclusive": table_end,
        "exception_entry_address": entry_address,
        "exception_entry_relation": entry_relation,
        "exception_entry_provenance": entry_provenance,
        "supplied_table": supplied_table,
        "register_derived_addresses": {
            "r8_plus_r14": entry_address.zip(r14).and_then(|(r8, r14)| r8.checked_add(r14)),
            "r8_plus_rax": entry_address.zip(rax).and_then(|(r8, rax)| r8.checked_add(rax)),
            "detail": "These are arithmetic observations from the selected exception context; fault-instruction interpretation remains in the disassembly evidence.",
        },
        "nearby_entries": nearby_entries,
        "per_cpu_topology": per_cpu_topology,
        "classification": classification,
    })
}

fn dump_per_cpu_tracker_topology(
    session: &DebuggerSession,
    table_size: u64,
    entry_address: Option<u64>,
    supplied_table_base: Option<u64>,
    entry_stride: u64,
) -> Value {
    const KNOWN_NT_TIMESTAMP: u32 = 0x4A63_AF4E;
    const KNOWN_NT_IMAGE_SIZE: u32 = 0x0145_0000;
    const PER_CPU_POINTER_ARRAY_RVA: u64 = 0x00EF_AB00;
    const MAX_PROCESSOR_SLOTS: usize = 128;
    let nt_base = match evaluate_unsigned(session, "nt") {
        Ok(value) => value,
        Err(error) => return json!({"status": "unsupported", "detail": error}),
    };
    let parameters = match session.module_parameters(&[nt_base]) {
        Ok(mut parameters) => parameters.pop(),
        Err(error) => {
            return json!({"status": "unavailable", "detail": format!("DbgEng could not read nt module parameters: {error}")})
        }
    };
    let Some(parameters) = parameters else {
        return json!({"status": "unavailable", "detail": "DbgEng returned no nt module parameters."});
    };
    if !is_known_per_cpu_tracker_layout(
        parameters.time_date_stamp,
        parameters.image_size,
        KNOWN_NT_TIMESTAMP,
        KNOWN_NT_IMAGE_SIZE,
    ) {
        return json!({
            "status": "unsupported_build",
            "nt_base": nt_base,
            "module_parameters": parameters,
            "detail": "The build-gated per-CPU pointer-array RVA is not validated for this nt image; no pointer-array read was attempted."
        });
    }
    let Some(array_address) = nt_base.checked_add(PER_CPU_POINTER_ARRAY_RVA) else {
        return json!({"status": "unavailable", "detail": "The build-gated per-CPU pointer-array address overflowed."});
    };
    let pointer_bytes = match session.read_memory(array_address, (MAX_PROCESSOR_SLOTS * 8) as u32) {
        Ok(memory) if memory.complete => match decode_hex_bytes(&memory.data) {
            Some(bytes) => bytes,
            None => {
                return json!({"status": "unavailable", "detail": "DbgEng returned invalid hexadecimal for the per-CPU pointer array."})
            }
        },
        Ok(memory) => {
            return json!({"status": "partial", "pointer_array": memory, "detail": "The bounded per-CPU pointer-array read was incomplete."})
        }
        Err(error) => {
            return json!({"status": "unavailable", "detail": format!("DbgEng could not read the build-gated per-CPU pointer array: {error}")})
        }
    };
    let fault_entry_slot = entry_address.and_then(|entry| {
        pointer_bytes
            .chunks_exact(8)
            .enumerate()
            .find_map(|(slot, chunk)| {
                let base = u64::from_le_bytes(chunk.try_into().expect("exact pointer chunk"));
                if base != 0 && base % 0x1000 == 0 {
                    let offset = entry.checked_sub(base)?;
                    (offset % entry_stride == 0 && offset / entry_stride < table_size)
                        .then(|| (slot, base, offset / entry_stride))
                } else {
                    None
                }
            })
    });
    let table_bytes = match table_size.checked_mul(entry_stride) {
        Some(bytes) => bytes,
        None => {
            return json!({"status": "unavailable", "detail": "The tracker table extent overflowed."})
        }
    };
    let mut tables = Vec::new();
    for (slot, chunk) in pointer_bytes.chunks_exact(8).enumerate() {
        let base = u64::from_le_bytes(chunk.try_into().expect("exact pointer chunk"));
        if base == 0 {
            continue;
        }
        let Some(end) = base.checked_add(table_bytes) else {
            tables.push(json!({"slot": slot, "base": base, "status": "invalid_extent"}));
            continue;
        };
        let first = pool_tracker_entry_snapshot(session, base);
        let last = pool_tracker_entry_snapshot(session, end - entry_stride);
        let fault_entry_record =
            (fault_entry_slot.is_some_and(|(_, fault_base, _)| fault_base == base)).then(|| {
                pool_tracker_entry_snapshot(session, entry_address.expect("fault slot has entry"))
            });
        let supplied_fault_index_record = entry_address
            .zip(supplied_table_base)
            .and_then(|(entry, supplied_base)| entry.checked_sub(supplied_base))
            .filter(|offset| offset % entry_stride == 0)
            .map(|offset| offset / entry_stride)
            .filter(|index| *index < table_size)
            .and_then(|index| {
                base.checked_add(index * entry_stride)
                    .map(|address| pool_tracker_entry_snapshot(session, address))
            });
        let extent_readable = first["status"].as_str() == Some("captured")
            && last["status"].as_str() == Some("captured");
        tables.push(json!({
            "slot": slot,
            "base": base,
            "end_exclusive": end,
            "base_alignment": base % 0x1000 == 0,
            "extent_boundary_readable": extent_readable,
            "first_entry": first,
            "last_entry": last,
            "fault_entry": fault_entry_record,
            "supplied_fault_index": supplied_fault_index_record,
        }));
    }
    json!({
        "status": "captured",
        "source": "build_gated_nt_rva_and_bounded_reads",
        "nt_base": nt_base,
        "module_parameters": parameters,
        "pointer_array_address": array_address,
        "slot_limit": MAX_PROCESSOR_SLOTS,
        "table_size": table_size,
        "entry_stride": entry_stride,
        "nonzero_tables": tables,
        "fault_table_match": fault_entry_slot.map(|(slot, base, index)| json!({
            "slot": slot,
            "table_base": base,
            "entry_index": index,
        })),
        "crash_cpu_correlation": fault_entry_slot.map_or_else(
            || json!({
                "status": "unavailable",
                "detail": "No bounded per-processor tracker table contains the validated fault record."
            }),
            |(slot, _, _)| json!({
                "status": "code_supported_inference",
                "processor_number": slot,
                "detail": "For this exact nt image, private-symbol disassembly of ExpInsertPoolTracker shows ExPoolTagTables[gs:1A4h]; the exact-image _KPCR/_KPRCB types place Prcb at 0x180 and Number at 0x24, so the selected slot is the current processor number. This is stronger than raw slot membership but remains an inference unless an independently saved processor identifier is captured."
            }),
        ),
        "detail": "Each nonzero base is checked only for page alignment and bounded first/last/fault-index reads. Matching tags or differing counters are snapshot observations, not allocation lifetime or race evidence."
    })
}

fn is_known_per_cpu_tracker_layout(
    time_date_stamp: u32,
    image_size: u32,
    expected_time_date_stamp: u32,
    expected_image_size: u32,
) -> bool {
    time_date_stamp == expected_time_date_stamp && image_size == expected_image_size
}

fn dump_address_inspection(
    session: &DebuggerSession,
    address: u64,
    supplied_table_base: Option<u64>,
) -> Value {
    const ENTRY_STRIDE: u64 = 0x50;
    let mapping = session.inspect_virtual_address(address);
    let table_size = evaluate_unsigned(session, "poi(nt!PoolTrackTableSize)").ok();
    let supplied_table = table_size.map(|size| {
        pool_tracker_table_relation(Some(address), supplied_table_base, size, ENTRY_STRIDE)
    });
    json!({
        "address": address,
        "mapping": mapping,
        "bounded_raw_window": pool_tracker_entry_snapshot(session, address),
        "supplied_table": supplied_table,
        "allocation_header": {
            "status": "unsupported",
            "detail": "DbgEng exposes no stable typed pool-header/owner API for this offline kernel dump. The raw 0x50-byte record is preserved, but no allocation lifetime, owner, or pool-header interpretation is inferred."
        },
        "detail": "The address probe is bounded and read-only. A successful dump read or virtual-to-physical translation does not establish write permission or the historical PTE state at the fault instant."
    })
}

fn pool_tracker_table_relation(
    address: Option<u64>,
    table_base: Option<u64>,
    table_size: u64,
    entry_stride: u64,
) -> Value {
    let Some(address) = address else {
        return json!({
            "status": "not_applicable",
            "relation": "no_address",
        });
    };
    let Some(table_base) = table_base else {
        return json!({
            "status": "not_provided",
            "relation": "table_base_not_provided",
        });
    };
    let Some(table_bytes) = table_size.checked_mul(entry_stride) else {
        return json!({
            "status": "unavailable",
            "relation": "range_overflow",
        });
    };
    let Some(table_end) = table_base.checked_add(table_bytes) else {
        return json!({
            "status": "unavailable",
            "relation": "range_overflow",
        });
    };
    if !(table_base..table_end).contains(&address) {
        return json!({
            "status": "captured",
            "relation": "outside_supplied_table",
            "table_base": table_base,
            "table_end_exclusive": table_end,
        });
    }
    let offset = address - table_base;
    let entry_aligned = offset % entry_stride == 0;
    json!({
        "status": "captured",
        "relation": if entry_aligned { "within_supplied_table" } else { "within_supplied_table_unaligned" },
        "table_base": table_base,
        "table_end_exclusive": table_end,
        "entry_offset": offset,
        "entry_index": offset / entry_stride,
        "entry_aligned": entry_aligned,
        "detail": "The supplied base is caller evidence. This range check establishes address membership only; it does not prove the table's allocation ownership or lifetime."
    })
}

fn pool_tracker_entry_provenance(
    fault: &Option<Value>,
    entry_address: Option<u64>,
    r14: Option<u64>,
) -> Value {
    let fault_symbol = fault
        .as_ref()
        .and_then(|value| value["disassembly"]["lines"].as_array())
        .and_then(|lines| lines.first())
        .and_then(|line| line["symbol"]["name"].as_str());
    let fault_instruction = fault
        .as_ref()
        .and_then(|value| value["disassembly"]["lines"].as_array())
        .and_then(|lines| lines.first())
        .and_then(|line| line["text"].as_str());
    let instruction_uses_r8 =
        fault_instruction
            .map(str::to_ascii_lowercase)
            .is_some_and(|instruction| {
                instruction.contains("[r14+r8]") || instruction.contains("[r8+r14]")
            });
    let tracker_charge_function = fault_symbol
        .map(str::to_ascii_lowercase)
        .is_some_and(|symbol| symbol.contains("exppooltrackerchargeentry"));
    json!({
        "status": if entry_address.is_some() && r14.is_some() && instruction_uses_r8 && tracker_charge_function {
            "validated"
        } else {
            "unvalidated"
        },
        "source": "fault_instruction_and_decoded_registers",
        "fault_symbol": fault_symbol,
        "fault_instruction": fault_instruction,
        "instruction_uses_r8_memory_operand": instruction_uses_r8,
        "tracker_charge_function": tracker_charge_function,
        "detail": "A validated result requires a captured R8/R14 context plus a fault instruction in ExpPoolTrackerChargeEntry that uses R8 as a memory operand. It establishes register-to-instruction provenance, not allocation ownership or free history.",
    })
}

fn evaluate_unsigned(session: &DebuggerSession, expression: &str) -> Result<u64, String> {
    session
        .evaluate(expression)
        .map_err(|error| format!("DbgEng could not evaluate {expression}: {error}"))?
        .unsigned_value
        .ok_or_else(|| format!("DbgEng evaluated {expression} without an unsigned integer result."))
}

fn pool_tracker_entry_snapshot(session: &DebuggerSession, address: u64) -> Value {
    const READ_SIZE: u32 = 0x50;
    match session.read_memory(address, READ_SIZE) {
        Ok(memory) => {
            let Some(bytes) = decode_hex_bytes(&memory.data) else {
                return json!({
                    "address": address,
                    "status": "invalid_hex",
                    "memory": memory,
                });
            };
            let read_u64 = |offset: usize| {
                bytes
                    .get(offset..offset + std::mem::size_of::<u64>())
                    .and_then(|value| value.try_into().ok())
                    .map(u64::from_le_bytes)
            };
            let tag = read_u64(0).map(|value| (value & u32::MAX as u64) as u32);
            json!({
                "address": address,
                "status": if memory.complete { "captured" } else { "partial" },
                "tag": tag.map(pool_tag_value),
                "raw_qwords": {
                    "offset_00": read_u64(0),
                    "offset_08": read_u64(8),
                    "offset_10": read_u64(16),
                    "offset_18": read_u64(24),
                    "offset_20": read_u64(32),
                    "offset_28": read_u64(40),
                    "offset_30": read_u64(48),
                    "offset_38": read_u64(56),
                    "offset_40": read_u64(64),
                    "offset_48": read_u64(72),
                },
                "memory": memory,
            })
        }
        Err(error) => json!({
            "address": address,
            "status": "unavailable",
            "detail": format!("DbgEng could not read the bounded pool tracker entry: {error}"),
        }),
    }
}

fn pool_tag_value(tag: u32) -> Value {
    let bytes = tag.to_le_bytes();
    let printable = bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ');
    let text = bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect::<String>();
    json!({
        "raw": tag,
        "text": text,
        "printable": printable,
    })
}

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn dump_evidence_grades(
    driver_evidence: &Value,
    pool_tracker: &Value,
    bugcheck_driver: &Value,
) -> Value {
    let tracker_classification = pool_tracker["classification"].as_str();
    let tracker_grade = match tracker_classification {
        Some("active_tracker_table_entry" | "supplied_tracker_table_entry") => "observed",
        Some(_) => "possible",
        None => "not_established",
    };
    let driver_grade = match bugcheck_driver["status"].as_str() {
        Some("captured") => "observed",
        Some("not_set") => "not_established",
        _ => "not_established",
    };
    let stack_participant_grade =
        if driver_evidence["observations"]
            .as_array()
            .is_some_and(|observations| {
                observations
                    .iter()
                    .any(|observation| observation["kind"] == "validated_stack_module")
            })
        {
            "observed"
        } else {
            "not_established"
        };
    json!({
        "grading_scale": {
            "observed": "Captured directly from the dump.",
            "strongly_consistent": "The observed facts match this explanation, but do not establish the initiating write or lifetime transition.",
            "possible": "The dump neither establishes nor excludes this explanation.",
            "not_established": "The dump contains no direct evidence for this explanation.",
        },
        "observations": [
            {
                "topic": "pool_tracker_entry_lifetime",
                "grade": tracker_grade,
                "detail": "Central-table range membership alone does not classify per-CPU tracker replicas. A supplied per-CPU base can establish bounded table membership, but not allocation ownership, free history, or a lifetime transition.",
            },
            {
                "topic": "bugcheck_driver",
                "grade": driver_grade,
                "detail": "KiBugCheckDriver is meaningful only when the kernel populated a non-null driver string.",
            },
            {
                "topic": "third_party_driver_stack_participation",
                "grade": stack_participant_grade,
                "detail": "A module in the validated saved stack is a direct participation observation, not an attribution of the initiating write or root cause.",
            },
            {
                "topic": "third_party_driver_causation",
                "grade": "not_established",
                "detail": "Neither loaded-module inventory nor a module's presence in the saved stack proves third-party-driver causation. A non-null bugcheck-driver record or faulting driver code remains separate evidence.",
            },
        ],
    })
}

fn dump_symbol_modules(
    session: &DebuggerSession,
    fault_address: Option<u64>,
    exception_context: &Option<Value>,
) -> Vec<ModuleInfo> {
    let mut bases = BTreeSet::new();
    let mut modules = Vec::new();
    for address in [
        fault_address,
        exception_context.as_ref().and_then(|context| {
            context["context"]["instruction_pointer"]
                .as_u64()
                .or_else(|| context["context"]["registers"]["rip"].as_u64())
        }),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(Some(module)) = session.module_by_offset(address) {
            if bases.insert(module.base_address) {
                modules.push(module);
            }
        }
    }
    modules
}

fn dump_symbol_readiness(
    session: &DebuggerSession,
    modules: &[ModuleInfo],
    refresh_symbols: bool,
) -> Value {
    if modules.is_empty() {
        return json!({
            "status": "not_applicable",
            "detail": "No observed fault or exception instruction could be mapped to a module.",
            "modules": [],
        });
    }
    let bases = modules
        .iter()
        .map(|module| module.base_address)
        .collect::<Vec<_>>();
    let refresh = if refresh_symbols {
        modules
            .iter()
            .map(|module| {
                let Some(module_name) = module.module_name.as_deref() else {
                    return json!({
                        "module_base": module.base_address,
                        "status": "unavailable",
                        "detail": "DbgEng did not provide a module basename for symbol reload.",
                    });
                };
                match session.refresh_symbols(module_name) {
                    Ok(()) => json!({
                        "module": module_name,
                        "status": "requested",
                    }),
                    Err(error) => json!({
                        "module": module_name,
                        "status": "failed",
                        "detail": format!("DbgEng could not refresh symbols: {error}"),
                    }),
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    match session.module_parameters(&bases) {
        Ok(parameters) => json!({
            "status": "captured",
            "modules": modules,
            "parameters": parameters,
            "refresh": refresh,
            "refresh_requested": refresh_symbols,
            "detail": "DbgEng symbol types report the current readiness of fault-related modules. A module-only name is not function-level symbol resolution.",
        }),
        Err(error) => json!({
            "status": "unavailable",
            "modules": modules,
            "refresh": refresh,
            "refresh_requested": refresh_symbols,
            "detail": format!("DbgEng could not query fault-module symbol readiness: {error}"),
        }),
    }
}

fn dump_driver_evidence(
    session: &DebuggerSession,
    modules: &[ModuleInfo],
    fault_address: Option<u64>,
    current_stack: &windbg_dbgeng::StackTraceResult,
    exception_context: &Option<Value>,
) -> Value {
    let mut direct_modules = BTreeSet::new();
    let mut stack_modules = BTreeSet::new();
    let mut observations = Vec::new();

    if let Some(address) = fault_address {
        match session.module_by_offset(address) {
            Ok(Some(module)) => {
                direct_modules.insert(
                    module
                        .module_name
                        .clone()
                        .unwrap_or_else(|| "<unnamed>".to_string()),
                );
                observations.push(json!({
                    "kind": "fault_instruction_module",
                    "rank": if module.module_name.as_deref() == Some("nt") { "location_only" } else { "high" },
                    "module": module,
                    "detail": "The module owns the fault instruction. Kernel ownership alone is not root-cause attribution.",
                }));
            }
            Ok(None) => observations.push(json!({
                "kind": "fault_instruction_module",
                "rank": "unavailable",
                "detail": "No loaded module owns the fault instruction.",
            })),
            Err(error) => observations.push(json!({
                "kind": "fault_instruction_module",
                "rank": "unavailable",
                "detail": format!("DbgEng could not map the fault instruction: {error}"),
            })),
        }
    }

    for frame in current_stack
        .frames
        .iter()
        .take(current_stack.valid_frames as usize)
    {
        if let Ok(Some(module)) = session.module_by_offset(frame.instruction_offset) {
            if module.module_name.as_deref() != Some("nt") {
                stack_modules.insert(
                    module
                        .module_name
                        .unwrap_or_else(|| "<unnamed>".to_string()),
                );
            }
        }
    }
    if let Some(context) = exception_context.as_ref() {
        let valid_frames = context["context"]["stack"]["valid_frames"]
            .as_u64()
            .unwrap_or(0) as usize;
        if let Some(context_stack) = context["context"]["stack"]["frames"].as_array() {
            for frame in context_stack.iter().take(valid_frames) {
                if let Some(address) = frame["instruction_offset"].as_u64() {
                    if let Ok(Some(module)) = session.module_by_offset(address) {
                        if module.module_name.as_deref() != Some("nt") {
                            stack_modules.insert(
                                module
                                    .module_name
                                    .unwrap_or_else(|| "<unnamed>".to_string()),
                            );
                        }
                    }
                }
            }
        }
    }
    let stack_module_details = modules
        .iter()
        .filter(|module| {
            module
                .module_name
                .as_ref()
                .is_some_and(|name| stack_modules.contains(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    let stack_module_parameters = if stack_module_details.is_empty() {
        json!({
            "status": "not_applicable",
            "modules": [],
            "parameters": [],
        })
    } else {
        let bases = stack_module_details
            .iter()
            .map(|module| module.base_address)
            .collect::<Vec<_>>();
        match session.module_parameters(&bases) {
            Ok(parameters) => json!({
                "status": "captured",
                "modules": stack_module_details,
                "parameters": parameters,
                "detail": "DbgEng module parameters capture image size, timestamp, checksum, flags, and symbol type for validated stack modules. They do not attribute causation.",
            }),
            Err(error) => json!({
                "status": "unavailable",
                "modules": stack_module_details,
                "parameters": [],
                "detail": format!("DbgEng could not query validated stack-module parameters: {error}"),
            }),
        }
    };
    for module in stack_modules {
        observations.push(json!({
            "kind": "validated_stack_module",
            "rank": "high",
            "module": module,
            "detail": "A non-kernel module appeared in a validated stack frame.",
        }));
    }

    json!({
        "status": if observations.iter().any(|item| item["rank"] == "high") {
            "direct_evidence_present"
        } else {
            "no_driver_implicated"
        },
        "observations": observations,
        "stack_module_parameters": stack_module_parameters,
        "loaded_module_count": modules.len(),
        "inventory_rank": "not_implicated",
        "detail": format!(
            "Loaded-module inventory is context only. {} direct fault-module observations were captured; dump-stack participants must not be treated as crash causes without a fault or stack reference.",
            direct_modules.len()
        ),
    })
}

fn dump_data_limits(
    target: &windbg_dbgeng::DebuggerSessionSummary,
    current_stack: &windbg_dbgeng::StackTraceResult,
    bugcheck: &windbg_dbgeng::BugCheckDataResult,
    fault: &Option<Value>,
    exception_context: &Option<Value>,
) -> Value {
    json!({
        "target_kind": target.kind,
        "bugcheck_data": bugcheck.status,
        "fault_instruction": fault.as_ref().map_or("not_applicable", |fault| {
            if fault["disassembly"]["status"].as_str() == Some("unavailable") {
                "dump_content_missing_or_unavailable"
            } else {
                "captured"
            }
        }),
        "exception_context": exception_context.as_ref().map_or("not_applicable", |context| {
            context["status"].as_str().unwrap_or("unknown")
        }),
        "stack": {
            "status": current_stack.status,
            "returned_frames": current_stack.returned_frames,
            "valid_frames": current_stack.valid_frames,
            "stop_reason": current_stack.stop_reason,
        },
        "detail": "A missing or partial context/code page is a dump-content limit. A captured context with an invalid stack is reported separately as an unwind/result limit rather than an invented caller.",
    })
}

fn dump_recommendations(bugcheck: &windbg_dbgeng::BugCheckDataResult) -> Value {
    let Some(data) = &bugcheck.data else {
        return json!([{
            "priority": "collect",
            "detail": "Capture a kernel or complete dump if the next crash needs bugcheck-specific triage.",
        }]);
    };
    match data.code {
        0x0000_003B => json!([
            {
                "priority": "high",
                "detail": "Use the captured exception context and fault instruction to identify a validated caller. If it remains unavailable, collect a kernel or complete dump.",
            },
            {
                "priority": "medium",
                "detail": "Treat a kernel-only fault location as possible data corruption until a driver appears in validated stack or bugcheck-driver evidence.",
            },
        ]),
        0x0000_0051 => json!([
            {
                "priority": "high",
                "detail": "Review storage, NTFS, and controller events around the crash; the registry hive pointer is evidence of registry failure, not a driver attribution.",
            },
            {
                "priority": "medium",
                "detail": "Use non-destructive disk health checks first, then collect a kernel or complete dump if the hive validation/caller evidence is absent.",
            },
        ]),
        _ => json!([{
            "priority": "collect",
            "detail": "Use the typed bugcheck parameters, validated stack, symbols, and driver evidence before attributing a crash.",
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn user_dump_without_exception_does_not_inherit_a_kernel_fault_address() {
        let bugcheck = windbg_dbgeng::BugCheckData {
            code: 0x3b,
            parameters: [0xc0000005, 0xfffff80012345678, 0, 0],
        };
        let user_exception = MinidumpException {
            source: "minidump_exception_stream",
            status: "not_present".into(),
            thread_system_id: None,
            record: None,
            context: Default::default(),
            detail: "No ExceptionStream".into(),
        };
        assert_eq!(
            dump_target_fault_address(Some(&bugcheck), None),
            Some(bugcheck.parameters[1])
        );
        assert_eq!(
            dump_target_fault_address(Some(&bugcheck), Some(&user_exception)),
            None
        );
        assert_eq!(dump_target_fault_address(None, None), None);
    }

    #[test]
    fn dump_triage_describes_system_service_exception_parameters() {
        let value = dump_bugcheck_value(&windbg_dbgeng::BugCheckDataResult {
            status: "captured".to_string(),
            data: Some(windbg_dbgeng::BugCheckData {
                code: 0x3B,
                parameters: [0xC000_0005, 0xFFFF_F800_A6D9_70B0, 0xFFFF_D100_8947_72F0, 0],
            }),
            detail: "fixture".to_string(),
        });

        assert_eq!(value["name"], "SYSTEM_SERVICE_EXCEPTION");
        assert_eq!(value["parameter_roles"][0], "exception_code");
        assert_eq!(
            value["parameter_roles"][2],
            "exception_context_record_address"
        );
        assert_eq!(
            dump_recommendations(&windbg_dbgeng::BugCheckDataResult {
                status: "captured".to_string(),
                data: Some(windbg_dbgeng::BugCheckData {
                    code: 0x3B,
                    parameters: [0; 4],
                }),
                detail: "fixture".to_string(),
            })[0]["priority"],
            "high"
        );
    }

    #[test]
    fn reconciles_matching_raw_and_dbgeng_bugcheck_tuples() {
        let bugcheck = windbg_dbgeng::BugCheckDataResult {
            status: "captured".to_string(),
            data: Some(windbg_dbgeng::BugCheckData {
                code: 0x3b,
                parameters: [0xC000_0005, 0xFFFF_F800_7166_70B0, 0x1234, 0],
            }),
            detail: "fixture".to_string(),
        };
        let raw = KernelDumpHeaderInventory {
            source: "raw_kernel_dump_header".to_string(),
            status: "captured".to_string(),
            file_bytes: Some(0x2000),
            signature: Some("PAGE".to_string()),
            valid_dump: Some("DU64".to_string()),
            major_version: Some(15),
            minor_version: Some(26100),
            machine_image_type: Some(0x8664),
            number_processors: Some(24),
            bugcheck_code: Some(0x3b),
            bugcheck_parameters: Some([0xC000_0005, 0xFFFF_F800_7166_70B0, 0x1234, 0]),
            dump_type: Some(5),
            dump_type_name: Some("bitmap_full".to_string()),
            required_dump_space: Some(0x2000),
            detail: "fixture".to_string(),
        };

        assert_eq!(
            dump_bugcheck_reconciliation(&bugcheck, &raw)["status"],
            "exact_match"
        );
    }

    #[test]
    fn exception_record_scan_requires_code_and_fault_address() {
        let mut bytes = vec![0_u8; 0x120];
        let offset = 0x40;
        bytes[offset..offset + 4].copy_from_slice(&0xC000_0005_u32.to_le_bytes());
        bytes[offset + 0x10..offset + 0x18]
            .copy_from_slice(&0xFFFF_F800_7166_70B0_u64.to_le_bytes());
        bytes[offset + 0x18..offset + 0x1c].copy_from_slice(&2_u32.to_le_bytes());
        bytes[offset + 0x20..offset + 0x28].copy_from_slice(&1_u64.to_le_bytes());
        bytes[offset + 0x28..offset + 0x30]
            .copy_from_slice(&0xFFFF_9B81_02B4_9540_u64.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&0xC000_0005_u32.to_le_bytes());
        bytes[0x90..0x98].copy_from_slice(&0xFFFF_F800_7166_70B1_u64.to_le_bytes());

        let records = scan_x64_exception_records(
            0xFFFF_8107_9A37_8000,
            &bytes,
            0xC000_0005,
            0xFFFF_F800_7166_70B0,
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["record_address"], 0xFFFF_8107_9A37_8040_u64);
        assert_eq!(records[0]["number_parameters"], 2);
        assert_eq!(records[0]["parameters"][0], 1);
        assert_eq!(records[0]["parameters"][1], 0xFFFF_9B81_02B4_9540_u64);
    }

    #[test]
    fn dump_triage_describes_kmode_exception_parameters_and_fault_address() {
        let data = windbg_dbgeng::BugCheckData {
            code: 0x1E,
            parameters: [0xC000_0005, 0xFFFF_F800_E439_70B0, 0, 0xFFFF_8581_BD06_8CC0],
        };
        let value = dump_bugcheck_value(&windbg_dbgeng::BugCheckDataResult {
            status: "captured".to_string(),
            data: Some(data.clone()),
            detail: "fixture".to_string(),
        });

        assert_eq!(value["name"], "KMODE_EXCEPTION_NOT_HANDLED");
        assert_eq!(value["parameter_roles"][1], "fault_instruction_address");
        assert_eq!(
            value["parameter_roles"][3],
            "exception_parameter_1_or_build_specific_context_candidate"
        );
        assert_eq!(dump_fault_address(&data), Some(0xFFFF_F800_E439_70B0));
    }

    #[test]
    fn per_cpu_tracker_match_derives_slot_and_index_without_caller_base() {
        let nt_base = 0xFFFF_F802_793F_0000;
        let table_size = 4097_u64;
        let stride = 0x50_u64;
        let slot = 19_usize;
        let table_base = 0xFFFF_CB81_A0CC_7000_u64;
        let entry_index = 1219_u64;
        let entry = table_base + entry_index * stride;
        let mut pointer_bytes = vec![0_u8; 128 * 8];
        pointer_bytes[slot * 8..slot * 8 + 8].copy_from_slice(&table_base.to_le_bytes());

        let matched = pointer_bytes
            .chunks_exact(8)
            .enumerate()
            .find_map(|(slot, chunk)| {
                let base = u64::from_le_bytes(chunk.try_into().expect("exact pointer chunk"));
                if base != 0 && base % 0x1000 == 0 {
                    let offset = entry.checked_sub(base)?;
                    (offset % stride == 0 && offset / stride < table_size)
                        .then(|| (slot, base, offset / stride))
                } else {
                    None
                }
            })
            .expect("pointer-array membership");

        assert_eq!(matched, (slot, table_base, entry_index));
        assert_eq!(
            matched.1 % 0x1000,
            0,
            "the exact-image tracker tables are page-aligned"
        );
        assert_ne!(
            matched.1,
            nt_base + 0x00EF_AB00,
            "a pointer-array base must not be confused with the pointer-array global"
        );
    }

    #[test]
    fn pool_tracker_helpers_preserve_raw_evidence() {
        assert_eq!(
            decode_hex_bytes("4B65792000000000"),
            Some(b"Key \0\0\0\0".to_vec())
        );
        assert_eq!(decode_hex_bytes("F"), None);
        assert_eq!(pool_tag_value(u32::from_le_bytes(*b"Key "))["text"], "Key ");
        assert_eq!(pool_tag_value(0)["printable"], false);

        let grades = dump_evidence_grades(
            &json!({"status": "inventory_only"}),
            &json!({"classification": "outside_central_table_tracker_like_unclassified"}),
            &json!({"status": "not_set"}),
        );
        assert_eq!(grades["observations"][0]["grade"], "possible");
        assert_eq!(grades["observations"][1]["grade"], "not_established");
        assert_eq!(grades["observations"][2]["grade"], "not_established");
        assert_eq!(grades["observations"][3]["grade"], "not_established");

        let stack_participant_grades = dump_evidence_grades(
            &json!({
                "status": "direct_evidence_present",
                "observations": [{
                    "kind": "validated_stack_module",
                    "module": "thirdparty"
                }]
            }),
            &json!({"classification": "outside_central_table_tracker_like_unclassified"}),
            &json!({"status": "not_set"}),
        );
        assert_eq!(
            stack_participant_grades["observations"][2]["topic"],
            "third_party_driver_stack_participation"
        );
        assert_eq!(
            stack_participant_grades["observations"][2]["grade"],
            "observed"
        );
        assert_eq!(
            stack_participant_grades["observations"][3]["topic"],
            "third_party_driver_causation"
        );
        assert_eq!(
            stack_participant_grades["observations"][3]["grade"],
            "not_established"
        );
    }

    #[test]
    fn pool_tracker_table_relation_requires_a_supplied_aligned_base() {
        let within = pool_tracker_table_relation(Some(0x150), Some(0x100), 4, 0x50);
        assert_eq!(within["relation"], "within_supplied_table");
        assert_eq!(within["entry_index"], 1);

        let unaligned = pool_tracker_table_relation(Some(0x151), Some(0x100), 4, 0x50);
        assert_eq!(unaligned["relation"], "within_supplied_table_unaligned");

        let missing = pool_tracker_table_relation(Some(0x150), None, 4, 0x50);
        assert_eq!(missing["relation"], "table_base_not_provided");
    }

    #[test]
    fn per_cpu_tracker_layout_requires_exact_module_fingerprint() {
        assert!(is_known_per_cpu_tracker_layout(
            0x4A63_AF4E,
            0x0145_0000,
            0x4A63_AF4E,
            0x0145_0000,
        ));
        assert!(!is_known_per_cpu_tracker_layout(
            0x4A63_AF4F,
            0x0145_0000,
            0x4A63_AF4E,
            0x0145_0000,
        ));
    }

    #[test]
    fn pool_tracker_provenance_requires_matching_fault_instruction() {
        let fault = Some(json!({
            "disassembly": {
                "lines": [{
                    "symbol": { "name": "nt!ExpPoolTrackerChargeEntry" },
                    "text": "lock xadd qword ptr [r14+r8], rbp"
                }]
            }
        }));
        assert_eq!(
            pool_tracker_entry_provenance(&fault, Some(0x1000), Some(0x20))["status"],
            "validated"
        );
        assert_eq!(
            pool_tracker_entry_provenance(&fault, Some(0x1000), None)["status"],
            "unvalidated"
        );
    }

    #[test]
    fn dump_triage_keeps_registry_parameters_reserved() {
        let value = dump_bugcheck_value(&windbg_dbgeng::BugCheckDataResult {
            status: "captured".to_string(),
            data: Some(windbg_dbgeng::BugCheckData {
                code: 0x51,
                parameters: [0x21, 0xFFFF_FFFF_C000_0005, 0x1234, 0],
            }),
            detail: "fixture".to_string(),
        });

        assert_eq!(value["name"], "REGISTRY_ERROR");
        assert_eq!(value["parameter_roles"][0], "reserved");
        assert_eq!(value["parameter_roles"][1], "reserved");
        assert_eq!(
            value["parameter_roles"][2],
            "registry_hive_pointer_if_available"
        );
    }
}
