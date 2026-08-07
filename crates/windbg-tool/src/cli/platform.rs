use anyhow::{bail, ensure, Context};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use windbg_dbgeng::{
    launch_live_session, live_launch_initial_break, open_dump_session, start_process_server,
    write_process_dump, BreakpointInfo, DebuggerOutputCaptureOptions, DebuggerSession, DumpKind,
    DumpOpenOptions, DumpWriteOptions, LiveInitialStop, LiveLaunchEnd, LiveLaunchOptions,
    LiveLaunchSessionOptions, ManagedCodeAvailability, ModuleInfo, ProcessDumpOptions,
    ProcessServerOptions,
};
use windbg_install::WindbgManager;
use windbg_symbols::{
    image_matches, inspect_pe_image_identity, prefetch_image, prefetch_pdb, NativeImageStatus,
    NativeSymbolStatus, PeImageIdentity,
};
use windbg_ttd::backend::capability_contract;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, UpdateProcThreadAttribute,
    WaitForInputIdle, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, STARTUPINFOEXW,
};

use super::output::{print_value, OutputOptions};
use super::{
    parse_u64_argument, CliDumpKind, DbgEngServerArgs, DumpCreateArgs, DumpInspectArgs,
    LiveLaunchArgs, LiveManagedBreakArgs, LiveStartupBreakArgs, LiveStartupProfileArgs,
    LiveStartupProfileCompareArgs, LiveStartupProfileReportArgs, StartupProfileContextEvent,
    StartupProfileReportFormat, TraceRecordArgs, TraceRecordProfile, TraceReplayCpuSupport,
    WindbgCommand,
};
use crate::pe_symbols::bounded_pe_file_metadata;

pub(super) fn run_dbgeng_server(
    args: DbgEngServerArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let result = start_process_server(ProcessServerOptions {
        transport: args.transport,
    })?;
    print_value(serde_json::to_value(result)?, output)
}

pub(super) fn run_live_launch(args: LiveLaunchArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let end = match args.end.as_str() {
        "detach" => LiveLaunchEnd::Detach,
        "terminate" => LiveLaunchEnd::Terminate,
        other => bail!("unsupported live launch end action: {other}"),
    };
    let result = live_launch_initial_break(LiveLaunchOptions {
        command_line: args.command_line,
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        end,
    })?;
    print_value(
        json!({
            "result": result,
            "session_persistence": "one_shot",
            "notes": [
                "This is the first live DbgEng primitive, not the daemon-backed live session manager.",
                "Use --end detach to leave the process running or --end terminate for disposable test targets."
            ]
        }),
        output,
    )
}

pub(super) fn run_live_startup_break(
    args: LiveStartupBreakArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let end = parse_live_launch_end(&args.end)?;
    let breakpoint_spec = startup_breakpoint_spec(&args)?;
    let module_load_filter = args
        .wait_for_module
        .as_deref()
        .map(validate_module_load_filter)
        .transpose()?;
    validate_startup_breakpoint_mode(args.hardware_execute, &breakpoint_spec)?;
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: if args.hardware_execute {
            LiveInitialStop::CreateProcessEvent
        } else {
            LiveInitialStop::SoftwareBreakpoint
        },
    })?;

    let result = (|| {
        let initial_event = session.summary();
        let module_load = module_load_filter
            .as_deref()
            .map(|module| {
                session
                    .execute_command(&format!("sxe ld:{module}"))
                    .with_context(|| format!("configuring DbgEng to stop when {module} loads"))?;
                let continued = session.continue_execution()?;
                let wait = session.wait_for_event(args.wait_timeout_ms)?;
                let event = session
                    .last_event()
                    .context("reading the requested DbgEng module-load event")?;
                ensure!(
                    event.event_name == "load_module" && event.module_base.is_some(),
                    "DbgEng did not stop on the requested {module} module-load event"
                );
                Ok::<_, anyhow::Error>(json!({
                    "module": module,
                    "continued": continued,
                    "wait": wait,
                    "event": event
                }))
            })
            .transpose()?;
        let requested_breakpoint = match breakpoint_spec {
            StartupBreakpointSpec::InitialBreak => None,
            _ if args.hardware_execute => Some(set_startup_hardware_execute_breakpoint(
                &session,
                &breakpoint_spec,
            )?),
            _ => Some(set_startup_breakpoint(&session, &breakpoint_spec)?),
        };
        let continued_to_breakpoint = requested_breakpoint
            .is_some()
            .then(|| session.continue_execution())
            .transpose()?;
        let event = requested_breakpoint
            .is_some()
            .then(|| session.wait_for_event(args.wait_timeout_ms))
            .transpose()?
            .unwrap_or_else(|| session.execution_status());
        let breakpoint_event = requested_breakpoint
            .is_some()
            .then(|| session.last_event())
            .transpose()?;
        let registers = session.core_registers()?;
        let instruction_offset = registers.instruction_offset;
        let context = live_stop_context(&session, registers, args.max_frames)?;
        let configured_breakpoint = match requested_breakpoint.as_ref() {
            Some(requested) => session
                .list_breakpoints()?
                .into_iter()
                .find(|breakpoint| breakpoint.id == requested.id),
            None => None,
        };
        let breakpoint_hit = instruction_offset
            .zip(
                configured_breakpoint
                    .as_ref()
                    .map(|breakpoint| breakpoint.offset),
            )
            .is_some_and(|(instruction_offset, breakpoint_offset)| {
                event.name.as_deref() == Some("break")
                    && breakpoint_event
                        .as_ref()
                        .is_some_and(|event| event.event_name == "breakpoint")
                    && breakpoint_event
                        .as_ref()
                        .and_then(|event| event.breakpoint_id)
                        == configured_breakpoint
                            .as_ref()
                            .map(|breakpoint| breakpoint.id)
                    && instruction_offset == breakpoint_offset
            });

        Ok(json!({
            "workflow": "live_startup_break",
            "command_line": args.command_line,
            "breakpoint_spec": breakpoint_spec,
            "breakpoint_mode": if args.hardware_execute { "hardware_execute" } else { "software_code" },
            "target_memory_writes": {
                "requested": false,
                "operations": []
            },
            "initial_event": initial_event,
            "module_load": module_load,
            "continued_to_breakpoint": continued_to_breakpoint,
            "event": event,
            "breakpoint": {
                "requested": requested_breakpoint,
                "configured": configured_breakpoint,
                "event": breakpoint_event,
                "hit": breakpoint_hit,
                "hit_evidence": if breakpoint_hit {
                    "DbgEng reported the configured breakpoint ID and the current instruction pointer equals its offset"
                } else if matches!(breakpoint_spec, StartupBreakpointSpec::InitialBreak) {
                    "the initial DbgEng process break was intentionally captured without setting a code breakpoint"
                } else {
                    "DbgEng did not report the configured breakpoint ID at its configured instruction pointer"
                }
            },
            "context": context,
            "end": end
        }))
    })();

    let cleanup = match end {
        LiveLaunchEnd::Detach => session.detach(),
        LiveLaunchEnd::Terminate => session.terminate(),
    };
    match (result, cleanup) {
        (Ok(result), Ok(())) => print_value(result, output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("failed to end the live debug session"),
    }
}

const STARTUP_PROFILE_CORECLR_MODULE: &str = "coreclr.dll";
const STARTUP_PROFILE_MAX_MODULE_IDENTITIES: usize = 128;
const STARTUP_PROFILE_MAX_FIRST_SEEN_MODULES: usize = 32;
const STARTUP_PROFILE_MAX_RANKED_GAPS: usize = 8;
const STARTUP_PROFILE_MAX_PROVENANCE_FILE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct StartupProfileModule {
    base_address: String,
    basename: Option<String>,
    module_name: Option<String>,
    image_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileEvent {
    index: usize,
    kind: String,
    observed_elapsed_ms: u64,
    resumed_wall_elapsed_ms: u64,
    event: windbg_dbgeng::DebuggerEventInfo,
    module: Option<StartupProfileModule>,
    loaded_module_count: Option<usize>,
    live_thread_count: Option<usize>,
    context: Value,
    thread_accounting: Value,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfilePhase {
    name: String,
    status: String,
    elapsed_ms: Option<u64>,
    start_event_index: Option<usize>,
    end_event_index: Option<usize>,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileEventReference {
    index: usize,
    kind: String,
    observed_elapsed_ms: u64,
    resumed_wall_elapsed_ms: u64,
    thread_system_id: u32,
    module: Option<StartupProfileModule>,
    description: Option<String>,
    exception_code: Option<String>,
    exception_first_chance: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileGap {
    rank: usize,
    elapsed_ms: u64,
    start: StartupProfileEventReference,
    end: StartupProfileEventReference,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileExcludedGap {
    start: StartupProfileEventReference,
    end: StartupProfileEventReference,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileCompletion {
    requested_module: Option<String>,
    settle_ms: Option<u32>,
    status: String,
    module_load: Option<StartupProfileEventReference>,
    quiet_resumed_elapsed_ms: Option<u64>,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct StartupProfileRun {
    run: u32,
    status: String,
    finish_reason: String,
    target: windbg_dbgeng::DebuggerSessionSummary,
    timing: Value,
    event_filters: Value,
    timeline: Vec<StartupProfileEvent>,
    phase_durations: Vec<StartupProfilePhase>,
    completion: StartupProfileCompletion,
    lifecycle_summary: Value,
    debuggee_output: Value,
    module_provenance: Value,
    dbgeng_module_parameters: Value,
    largest_observed_gaps: Vec<StartupProfileGap>,
    gaps_excluded_from_ranking: Vec<StartupProfileExcludedGap>,
    counts: Value,
    coverage: Value,
    cleanup: Value,
}

pub(super) fn run_live_startup_profile(
    args: LiveStartupProfileArgs,
    output_options: &OutputOptions,
) -> anyhow::Result<()> {
    let end = parse_live_launch_end(&args.end)?;
    let phase_module = args
        .phase_module
        .as_deref()
        .map(validate_module_load_filter)
        .transpose()?;
    let completion_module = args
        .completion_module
        .as_deref()
        .map(validate_module_load_filter)
        .transpose()?;
    let observed_phase_module = phase_module
        .as_deref()
        .or(completion_module.as_deref())
        .map(ToOwned::to_owned);
    ensure!(
        args.runs == 1 || matches!(end, LiveLaunchEnd::Terminate),
        "--runs greater than one requires --end terminate so a bounded run cannot leave a detached target behind"
    );
    if let Some(path) = args.output.as_deref() {
        ensure!(
            !path.exists(),
            "refusing to overwrite startup-profile artifact {}",
            path.display()
        );
        let parent = path
            .parent()
            .context("startup-profile artifact path must have a parent directory")?;
        ensure!(
            parent.is_dir(),
            "startup-profile artifact directory does not exist: {}",
            parent.display()
        );
    }

    let mut runs = Vec::with_capacity(args.runs as usize);
    let mut completed_runs = Vec::with_capacity(args.runs as usize);
    let mut completed_runs_with_process_exit = 0usize;
    for run_index in 1..=args.runs {
        match collect_startup_profile_run(
            &args,
            run_index,
            observed_phase_module.as_deref(),
            completion_module.as_deref(),
            end,
        ) {
            Ok(run) => {
                if run.status == "completed" {
                    if run.finish_reason == "exit_process" {
                        completed_runs_with_process_exit += 1;
                    }
                    completed_runs.push(run.clone());
                }
                let should_stop = run.status != "completed";
                runs.push(serde_json::to_value(run)?);
                if should_stop {
                    break;
                }
            }
            Err(error) => {
                runs.push(json!({
                    "run": run_index,
                    "status": "failed",
                    "error": error.to_string()
                }));
                break;
            }
        }
    }

    let debuggee_output_limitation = if args.capture_debuggee_output {
        "Opt-in debuggee output capture retains only bounded DbgEng debuggee categories and text. It can be unavailable if DbgEng rejects callback installation, and a preceding lifecycle-event reference establishes observation order rather than causation."
    } else {
        "Debuggee output is not captured into structured JSON because this command does not install an output callback; a target can still inherit the invoking console."
    };
    let mut result = json!({
        "workflow": "live_startup_profile",
        "command_line": args.command_line,
        "requested_runs": args.runs,
        "runs_completed": completed_runs.len(),
        "runs_completed_with_process_exit": completed_runs_with_process_exit,
        "runs": runs,
        "aggregate": startup_profile_aggregate(&completed_runs),
        "target_memory_writes": {
            "requested": false,
            "operations": [],
            "software_breakpoints": false,
            "hardware_breakpoints": false,
            "dac_bridge": false,
            "clr_notifications": false,
            "injection": false,
            "profiler": false
        },
        "measurement_semantics": {
            "clock": "host_monotonic_instant",
            "launch_to_create_ms": "Host elapsed time from before DbgEng session creation until windbg-tool observes the DbgEng create-process stop.",
            "phase_elapsed_ms": "Host wall time accumulated only while the target is resumed between observed DbgEng stops. It excludes windbg-tool's intentional stopped-state filter/context work, but includes debugger scheduling and event-delivery latency.",
            "event_timestamps": "Observed when DbgEng returns control to windbg-tool, not target-side instruction timestamps.",
            "completion_module": "A requested module load is an observable image-load boundary only. It does not establish UI readiness, managed assembly registration, first managed method execution, or successful application initialization.",
            "quiet_interval": "A requested settle interval establishes only that no configured DbgEng lifecycle stop was observed while the target was resumed for that duration. It does not establish CPU, I/O, UI, or application quiescence.",
            "lifecycle_phase_cpu_time": "not_available; lifecycle phases and inter-event gaps remain host wall-time measurements.",
            "thread_accounting": "When requested, separate read-only DbgEng per-thread CPU counters can be returned at selected lifecycle stops in raw 100 ns units and fixture-validated milliseconds. They do not attribute a lifecycle gap to CPU work.",
            "regression_interpretation": "Repeated values can identify wall-clock variability or candidates for comparison with a baseline. They do not attribute CPU use or prove a regression."
        },
        "limitations": [
            "DbgEng lifecycle events do not establish managed assembly registration, managed method execution, JIT activity, or CPU attribution.",
            "Optional per-thread accounting is a bounded, validity-gated DbgEng snapshot. It is independent from the lifecycle wall clock, returns raw 100 ns counters and fixture-validated millisecond projections, and never establishes causal attribution.",
            debuggee_output_limitation,
            "Largest observed gaps rank only adjacent retained events while the full lifecycle filter set was active. Tail-filter gaps are retained as excluded coverage diagnostics, not ranked evidence.",
            "First-chance exceptions are opt-in because managed startup can generate enough events to consume the bounded timeline."
        ]
    });
    if let Some(path) = args.output {
        fs::write(&path, serde_json::to_vec_pretty(&result)?)
            .with_context(|| format!("writing startup-profile artifact {}", path.display()))?;
        result["artifact"] = json!({
            "path": path,
            "format": "pretty_json",
            "written": true
        });
    }
    print_value(result, output_options)
}

const STARTUP_PROFILE_ARTIFACT_MAX_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn run_live_startup_compare(
    args: LiveStartupProfileCompareArgs,
    output_options: &OutputOptions,
) -> anyhow::Result<()> {
    let baseline = read_startup_profile_artifact(&args.baseline, "baseline")?;
    let candidate = read_startup_profile_artifact(&args.candidate, "candidate")?;
    let baseline_runs = startup_profile_completed_artifact_runs(&baseline.value);
    let candidate_runs = startup_profile_completed_artifact_runs(&candidate.value);
    let phase_comparison =
        startup_profile_compare_phase_distributions(&baseline_runs, &candidate_runs);
    let gap_comparison = startup_profile_compare_largest_gaps(&baseline_runs, &candidate_runs);
    let sequence_comparison = startup_profile_compare_sequences(
        &baseline_runs,
        &candidate_runs,
        args.max_sequence_events as usize,
    );

    print_value(
        json!({
            "workflow": "live_startup_profile_compare",
            "baseline": baseline.summary,
            "candidate": candidate.summary,
            "comparison": {
                "phase_wall_time_ms": phase_comparison,
                "largest_observed_inter_event_gap_wall_time_ms": gap_comparison,
                "lifecycle_sequence": sequence_comparison
            },
            "coverage": {
                "baseline_completed_runs": baseline_runs.len(),
                "candidate_completed_runs": candidate_runs.len(),
                "matched_run_pairs": baseline_runs.len().min(candidate_runs.len()),
                "unmatched_baseline_runs": baseline_runs.len().saturating_sub(candidate_runs.len()),
                "unmatched_candidate_runs": candidate_runs.len().saturating_sub(baseline_runs.len()),
                "sequence_event_limit_per_run": args.max_sequence_events
            },
            "interpretation": {
                "wall_time_only": true,
                "cpu_attribution": "not_available",
                "causal_attribution": "not_available",
                "regression_assessment": "The artifact comparison reports observed wall-time and lifecycle-sequence differences only. It does not establish a CPU regression, target-internal cause, managed-method timing, I/O cause, or UI readiness."
            }
        }),
        output_options,
    )
}

#[derive(Debug, Clone)]
struct StartupProfileReportFilters {
    run: u32,
    module_substring: Option<String>,
    runtime_only: bool,
    rdm_only: bool,
    min_resumed_ms: Option<u64>,
    max_rows: usize,
}

pub(super) fn run_live_startup_report(
    args: LiveStartupProfileReportArgs,
    output_options: &OutputOptions,
) -> anyhow::Result<()> {
    if matches!(args.format, StartupProfileReportFormat::Table) {
        ensure!(
            output_options.field.is_none() && !output_options.raw && !output_options.envelope,
            "--field, --raw, and --envelope require --format json for live startup-report"
        );
    }
    if let Some(path) = args.output.as_deref() {
        ensure!(
            !path.exists(),
            "refusing to overwrite startup-report artifact {}",
            path.display()
        );
        let parent = path
            .parent()
            .context("startup-report artifact path must have a parent directory")?;
        ensure!(
            parent.is_dir(),
            "startup-report artifact directory does not exist: {}",
            parent.display()
        );
    }

    let artifact = read_startup_profile_artifact(&args.artifact, "report source")?;
    let filters = StartupProfileReportFilters {
        run: args.run,
        module_substring: args.module,
        runtime_only: args.runtime_only,
        rdm_only: args.rdm_only,
        min_resumed_ms: args.min_resumed_ms,
        max_rows: args.max_rows as usize,
    };
    let mut report = startup_profile_module_report(&artifact, &filters)?;
    if let Some(path) = args.output {
        fs::write(&path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("writing startup-report artifact {}", path.display()))?;
        report["report_artifact"] = json!({
            "path": path,
            "format": "pretty_json",
            "written": true
        });
    }

    match args.format {
        StartupProfileReportFormat::Json => print_value(report, output_options),
        StartupProfileReportFormat::Table => {
            print!(
                "{}",
                startup_profile_module_report_table(
                    &report,
                    args.path_width as usize,
                    !args.no_summary
                )
            );
            Ok(())
        }
    }
}

struct StartupProfileArtifact {
    value: Value,
    summary: Value,
}

fn read_startup_profile_artifact(
    path: &Path,
    role: &str,
) -> anyhow::Result<StartupProfileArtifact> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading {role} startup-profile artifact {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{role} startup-profile artifact is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= STARTUP_PROFILE_ARTIFACT_MAX_BYTES,
        "{role} startup-profile artifact is {} bytes, exceeding the {}-byte artifact limit",
        metadata.len(),
        STARTUP_PROFILE_ARTIFACT_MAX_BYTES
    );
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading {role} startup-profile artifact {}", path.display()))?;
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing {role} startup-profile artifact {}", path.display()))?;
    ensure!(
        value["workflow"].as_str() == Some("live_startup_profile"),
        "{role} artifact is not a live startup-profile result"
    );
    let runs = value["runs"]
        .as_array()
        .with_context(|| format!("{role} startup-profile artifact has no runs array"))?;
    Ok(StartupProfileArtifact {
        summary: json!({
            "role": role,
            "path": path,
            "artifact_bytes": metadata.len(),
            "requested_runs": value["requested_runs"],
            "runs_returned": runs.len(),
            "runs_completed": value["runs_completed"],
            "runs_completed_with_process_exit": value["runs_completed_with_process_exit"]
        }),
        value,
    })
}

fn startup_profile_module_report(
    artifact: &StartupProfileArtifact,
    filters: &StartupProfileReportFilters,
) -> anyhow::Result<Value> {
    let runs = artifact.value["runs"]
        .as_array()
        .context("startup-profile artifact has no runs array")?;
    let run = runs
        .iter()
        .find(|candidate| candidate["run"].as_u64() == Some(u64::from(filters.run)))
        .with_context(|| {
            format!(
                "startup-profile artifact does not contain recorded run {}",
                filters.run
            )
        })?;
    let timeline = run["timeline"]
        .as_array()
        .with_context(|| format!("startup-profile run {} has no timeline array", filters.run))?;
    let module_parameters = startup_profile_report_module_parameters(run);
    let provenance = startup_profile_report_module_provenance(run);
    let phase_module = run["coverage"]["phase_module"].as_str();
    let mut first_seen = BTreeSet::new();
    let mut prior_first_module_resumed_ms = None;
    let mut all_rows = Vec::new();
    let mut module_load_events_without_module_identity = 0usize;

    for event in timeline
        .iter()
        .filter(|event| event["kind"].as_str() == Some("load_module"))
    {
        let Some(module) = event["module"].as_object() else {
            module_load_events_without_module_identity += 1;
            continue;
        };
        let Some(identity) = startup_profile_report_module_identity(module) else {
            module_load_events_without_module_identity += 1;
            continue;
        };
        if !first_seen.insert(identity.to_ascii_lowercase()) {
            continue;
        }

        let resumed_wall_elapsed_ms = event["resumed_wall_elapsed_ms"].as_u64();
        let delta_from_prior_first_module_load_resumed_wall_ms =
            match (prior_first_module_resumed_ms, resumed_wall_elapsed_ms) {
                (Some(prior), Some(current)) => current.checked_sub(prior),
                _ => None,
            };
        prior_first_module_resumed_ms = resumed_wall_elapsed_ms;

        let base_address = module
            .get("base_address")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let module_parameters_record = base_address
            .as_deref()
            .and_then(|address| module_parameters.get(&address.to_ascii_lowercase()))
            .cloned();
        let image_path = module
            .get("image_path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let provenance_record = image_path
            .as_deref()
            .and_then(|path| {
                provenance
                    .records_by_normalized_path
                    .get(&path.to_ascii_lowercase())
            })
            .cloned();
        let classifications = startup_profile_report_module_classifications(module, phase_module);
        let parameters = module_parameters_record
            .as_ref()
            .and_then(|record| record.get("parameters"))
            .cloned();
        let symbol_type_name = parameters
            .as_ref()
            .and_then(|parameters| parameters.get("symbol_type_name"))
            .cloned();

        all_rows.push(json!({
            "ordinal": all_rows.len() + 1,
            "event_index": event["index"],
            "observed_elapsed_ms": event["observed_elapsed_ms"],
            "resumed_wall_elapsed_ms": resumed_wall_elapsed_ms,
            "delta_from_prior_first_module_load_resumed_wall_ms":
                delta_from_prior_first_module_load_resumed_wall_ms,
            "classification": classifications,
            "module": Value::Object(module.clone()),
            "base_address": base_address,
            "image_size_bytes": parameters
                .as_ref()
                .and_then(|parameters| parameters.get("image_size"))
                .cloned(),
            "symbol_readiness": {
                "source": run["dbgeng_module_parameters"]["source"],
                "status": if parameters.is_some() {
                    Value::String("captured".to_string())
                } else {
                    run["dbgeng_module_parameters"]["status"].clone()
                },
                "symbol_type_name": symbol_type_name
            },
            "module_parameters": parameters,
            "provenance": provenance_record.unwrap_or_else(|| json!({
                "source": run["module_provenance"]["source"],
                "status": run["module_provenance"]["status"],
                "detail": run["module_provenance"]["detail"]
            }))
        }));
    }

    let matching_rows = all_rows
        .iter()
        .filter(|row| startup_profile_report_row_matches(row, filters))
        .cloned()
        .collect::<Vec<_>>();
    let matching_row_count = matching_rows.len();
    let rows_truncated = matching_row_count > filters.max_rows;
    let rows = matching_rows
        .into_iter()
        .take(filters.max_rows)
        .collect::<Vec<_>>();
    let process_exit = timeline
        .iter()
        .find(|event| event["kind"].as_str() == Some("exit_process"))
        .map(|event| {
            json!({
                "index": event["index"],
                "observed_elapsed_ms": event["observed_elapsed_ms"],
                "resumed_wall_elapsed_ms": event["resumed_wall_elapsed_ms"],
                "exit_code": event["event"]["exit_code"]
            })
        });

    Ok(json!({
        "workflow": "live_startup_profile_report",
        "offline": {
            "status": "offline_artifact_processing",
            "target_or_debugger_interaction": false,
            "detail": "This report reads only the explicitly supplied bounded startup-profile JSON artifact. It does not launch, attach, query, or modify a target or debugger, and it does not read observed module paths from the host."
        },
        "source_of_truth": {
            "artifact": artifact.summary,
            "detail": "The input live_startup_profile JSON remains the source of truth. This report is a bounded presentation and filter layer over its retained lifecycle events and enrichment records."
        },
        "run": {
            "number": filters.run,
            "status": run["status"],
            "finish_reason": run["finish_reason"],
            "completion": run["completion"],
            "process_exit": process_exit,
            "coverage": {
                "timeline_events_returned": run["coverage"]["timeline_events_returned"],
                "timeline_event_limit": run["coverage"]["timeline_event_limit"],
                "timeline_truncated": run["coverage"]["timeline_truncated"],
                "event_limit_reached": run["coverage"]["event_limit_reached"],
                "truncation_behavior": run["coverage"]["truncation_behavior"],
                "module_load_events": run["counts"]["module_load_events"],
                "module_load_events_without_module_identity": module_load_events_without_module_identity
            }
        },
        "filters": {
            "module_substring": filters.module_substring,
            "runtime_only": filters.runtime_only,
            "rdm_only": filters.rdm_only,
            "min_resumed_ms": filters.min_resumed_ms,
            "max_rows": filters.max_rows
        },
        "module_classification": {
            "runtime_loader": "The observed basename, DbgEng module name, or normalized image path matches coreclr.dll, hostfxr.dll, hostpolicy.dll, clrjit.dll, or mscoree.dll.",
            "rdm_application_path": "The normalized DbgEng-observed image path contains /RemoteDesktopManager/. This is a path label, not a managed assembly, CPU, or ownership claim.",
            "selected_phase_module": "The observed module identity matches the profile's requested phase module.",
            "other_module": "No runtime, RDM-path, or selected-phase classification matched."
        },
        "module_timeline": {
            "first_observed_module_load_count": all_rows.len(),
            "matching_row_count": matching_row_count,
            "rows_returned": rows.len(),
            "truncated_by_max_rows": rows_truncated,
            "delta_semantics": "delta_from_prior_first_module_load_resumed_wall_ms is target-resumed host wall time between retained first-observed module-load events before report filtering. It is not CPU, file-I/O, loader-internal, JIT, or managed-method duration.",
            "rows": rows
        },
        "summary": {
            "first_coreclr_load": run["lifecycle_summary"]["modules"]["first_coreclr_load"],
            "first_selected_phase_module_load": run["lifecycle_summary"]["modules"]["first_selected_phase_module_load"],
            "largest_observed_gaps": run["largest_observed_gaps"],
            "detail": "Milestones and ranked gaps are copied from the artifact's existing lifecycle summary and gap ranking. They remain DbgEng host-observed wall-time evidence only."
        },
        "measurement_semantics": artifact.value["measurement_semantics"],
        "limitations": [
            "Module timestamps are host-observed when DbgEng returned lifecycle control to windbg-tool; they are not target instruction timestamps.",
            "Observed or resumed wall-time values and module-to-module deltas are not CPU time, file-I/O duration, JIT duration, managed method timing, UI readiness, or causal attribution.",
            "Image size and symbol readiness appear only when the source profile requested bounded DbgEng module-parameter enrichment. Provenance appears only when it requested bounded host metadata for DbgEng-observed absolute paths.",
            "A truncated source timeline can omit lifecycle events. The report preserves source coverage rather than filling or inferring missing module loads."
        ]
    }))
}

struct StartupProfileReportProvenance {
    records_by_normalized_path: BTreeMap<String, Value>,
}

fn startup_profile_report_module_parameters(run: &Value) -> BTreeMap<String, Value> {
    run["dbgeng_module_parameters"]["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|record| {
            let base = record["base_address"].as_str()?;
            Some((base.to_ascii_lowercase(), record.clone()))
        })
        .collect()
}

fn startup_profile_report_module_provenance(run: &Value) -> StartupProfileReportProvenance {
    let records_by_normalized_path = run["module_provenance"]["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|record| {
            let path = record["observed_image_path"].as_str()?;
            Some((
                normalize_startup_profile_path(path).to_ascii_lowercase(),
                record.clone(),
            ))
        })
        .collect();
    StartupProfileReportProvenance {
        records_by_normalized_path,
    }
}

fn startup_profile_report_module_identity(
    module: &serde_json::Map<String, Value>,
) -> Option<String> {
    ["basename", "module_name", "image_path"]
        .into_iter()
        .find_map(|field| {
            module
                .get(field)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn startup_profile_report_module_classifications(
    module: &serde_json::Map<String, Value>,
    phase_module: Option<&str>,
) -> Vec<&'static str> {
    let candidates = ["basename", "module_name", "image_path"]
        .into_iter()
        .filter_map(|field| module.get(field).and_then(Value::as_str))
        .collect::<Vec<_>>();
    let mut classifications = Vec::with_capacity(3);
    if startup_profile_is_runtime_loader_module(&candidates) {
        classifications.push("runtime_loader");
    }
    if module
        .get("image_path")
        .and_then(Value::as_str)
        .is_some_and(|path| {
            normalize_startup_profile_path(path)
                .to_ascii_lowercase()
                .contains("/remotedesktopmanager/")
        })
    {
        classifications.push("rdm_application_path");
    }
    if phase_module.is_some_and(|phase_module| {
        candidates
            .iter()
            .any(|candidate| startup_profile_module_name_matches(candidate, phase_module))
    }) {
        classifications.push("selected_phase_module");
    }
    if classifications.is_empty() {
        classifications.push("other_module");
    }
    classifications
}

fn startup_profile_report_row_matches(row: &Value, filters: &StartupProfileReportFilters) -> bool {
    let classifications = row["classification"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if filters.runtime_only && !classifications.contains(&"runtime_loader") {
        return false;
    }
    if filters.rdm_only && !classifications.contains(&"rdm_application_path") {
        return false;
    }
    if let Some(minimum) = filters.min_resumed_ms {
        match row["resumed_wall_elapsed_ms"].as_u64() {
            Some(elapsed_ms) if elapsed_ms >= minimum => {}
            _ => return false,
        }
    }
    let Some(filter) = filters.module_substring.as_deref() else {
        return true;
    };
    let filter = filter.to_ascii_lowercase();
    ["basename", "module_name", "image_path"]
        .into_iter()
        .filter_map(|field| row["module"][field].as_str())
        .any(|candidate| candidate.to_ascii_lowercase().contains(&filter))
}

fn startup_profile_module_report_table(
    report: &Value,
    path_width: usize,
    include_summary: bool,
) -> String {
    let mut table = String::new();
    let source = &report["source_of_truth"]["artifact"];
    let run = &report["run"];
    let coverage = &run["coverage"];
    let completion = &run["completion"];
    let _ = writeln!(table, "Startup module timeline (offline artifact report)");
    let _ = writeln!(
        table,
        "Source: {} ({} bytes)",
        report_table_cell(&source["path"], 120),
        report_table_cell(&source["artifact_bytes"], 20)
    );
    let _ = writeln!(
        table,
        "Run: {} | status: {} | finish: {} | completion: {}",
        report_table_cell(&run["number"], 8),
        report_table_cell(&run["status"], 20),
        report_table_cell(&run["finish_reason"], 32),
        report_table_cell(&completion["status"], 32)
    );
    let _ = writeln!(
        table,
        "Coverage: events {}/{} | source timeline truncated: {} | event limit reached: {}",
        report_table_cell(&coverage["timeline_events_returned"], 12),
        report_table_cell(&coverage["timeline_event_limit"], 12),
        report_table_cell(&coverage["timeline_truncated"], 8),
        report_table_cell(&coverage["event_limit_reached"], 8)
    );
    let process_exit = &run["process_exit"];
    if process_exit.is_object() {
        let _ = writeln!(
            table,
            "Process exit: code {} at observed/resumed {} / {} ms",
            report_table_cell(&process_exit["exit_code"], 12),
            report_table_cell(&process_exit["observed_elapsed_ms"], 12),
            report_table_cell(&process_exit["resumed_wall_elapsed_ms"], 12)
        );
    } else {
        let _ = writeln!(table, "Process exit: not retained or not observed");
    }
    let _ = writeln!(
        table,
        "Time semantics: DbgEng host-observed lifecycle times; not CPU, file-I/O, JIT, managed-method, or UI-ready duration."
    );
    let _ = writeln!(
        table,
        "\n  # | OBS/RES ms     | +FIRST ms | CATEGORY                 | MODULE                           | BASE               | IMAGE BYTES | SYMBOLS      | NORMALIZED PATH"
    );
    let _ = writeln!(
        table,
        "----+----------------+-----------+--------------------------+----------------------------------+--------------------+-------------+--------------+{}",
        "-".repeat(path_width.saturating_add(1))
    );
    for row in report["module_timeline"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let classifications = row["classification"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let observed_resumed = format!(
            "{}/{}",
            report_table_cell(&row["observed_elapsed_ms"], 10),
            report_table_cell(&row["resumed_wall_elapsed_ms"], 10)
        );
        let symbol = row["symbol_readiness"]["symbol_type_name"]
            .as_str()
            .or_else(|| row["symbol_readiness"]["status"].as_str())
            .unwrap_or("-");
        let _ = writeln!(
            table,
            "{:>3} | {:<14} | {:>9} | {:<24} | {:<32} | {:<18} | {:>11} | {:<12} | {}",
            report_table_cell(&row["ordinal"], 3),
            report_table_cell_string(&observed_resumed, 14),
            report_table_cell(
                &row["delta_from_prior_first_module_load_resumed_wall_ms"],
                9
            ),
            report_table_cell_string(&classifications, 24),
            report_table_cell(&row["module"]["basename"], 32),
            report_table_cell(&row["base_address"], 18),
            report_table_cell(&row["image_size_bytes"], 11),
            report_table_cell_string(symbol, 12),
            report_table_cell(&row["module"]["image_path"], path_width)
        );
    }
    let _ = writeln!(
        table,
        "Rows: {} returned, {} matching before row bound, truncated by --max-rows: {}",
        report_table_cell(&report["module_timeline"]["rows_returned"], 12),
        report_table_cell(&report["module_timeline"]["matching_row_count"], 12),
        report_table_cell(&report["module_timeline"]["truncated_by_max_rows"], 8)
    );

    if include_summary {
        let summary = &report["summary"];
        let _ = writeln!(table, "\nMilestones copied from source artifact");
        let _ = writeln!(
            table,
            "  first coreclr: {}",
            report_table_event(&summary["first_coreclr_load"])
        );
        let _ = writeln!(
            table,
            "  first selected phase module: {}",
            report_table_event(&summary["first_selected_phase_module_load"])
        );
        let _ = writeln!(
            table,
            "\nLargest retained observed lifecycle gaps (source ranking)"
        );
        let _ = writeln!(table, " RANK | WALL ms | FROM -> TO");
        let _ = writeln!(
            table,
            "------+---------+----------------------------------------------------------"
        );
        for gap in summary["largest_observed_gaps"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let _ = writeln!(
                table,
                " {:>4} | {:>7} | {} -> {}",
                report_table_cell(&gap["rank"], 4),
                report_table_cell(&gap["elapsed_ms"], 7),
                report_table_event(&gap["start"]),
                report_table_event(&gap["end"])
            );
        }
    }
    table
}

fn report_table_event(event: &Value) -> String {
    if event.is_null() {
        return "-".to_string();
    }
    let label = event["module"]["basename"]
        .as_str()
        .or_else(|| event["kind"].as_str())
        .unwrap_or("-");
    format!(
        "{} @ {} ms",
        report_table_cell_string(label, 36),
        report_table_cell(&event["resumed_wall_elapsed_ms"], 12)
    )
}

fn report_table_cell(value: &Value, width: usize) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(text) => report_table_cell_string(text, width),
        Value::Number(number) => report_table_cell_string(&number.to_string(), width),
        Value::Bool(value) => report_table_cell_string(&value.to_string(), width),
        _ => "-".to_string(),
    }
}

fn report_table_cell_string(value: &str, width: usize) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if sanitized.chars().count() <= width {
        return sanitized;
    }
    let prefix_length = width.saturating_sub(3);
    format!(
        "{}...",
        sanitized.chars().take(prefix_length).collect::<String>()
    )
}

fn startup_profile_completed_artifact_runs(artifact: &Value) -> Vec<&Value> {
    artifact["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|run| run["status"].as_str() == Some("completed"))
        .collect()
}

fn startup_profile_compare_phase_distributions(
    baseline_runs: &[&Value],
    candidate_runs: &[&Value],
) -> Vec<Value> {
    let baseline = startup_profile_artifact_phase_samples(baseline_runs);
    let candidate = startup_profile_artifact_phase_samples(candidate_runs);
    let names = baseline
        .keys()
        .chain(candidate.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    names
        .into_iter()
        .map(|name| {
            let baseline_values = baseline.get(&name).cloned().unwrap_or_default();
            let candidate_values = candidate.get(&name).cloned().unwrap_or_default();
            let baseline_distribution = startup_profile_wall_time_distribution(&baseline_values);
            let candidate_distribution = startup_profile_wall_time_distribution(&candidate_values);
            let median_delta_ms = baseline_distribution["median_ms"]
                .as_f64()
                .zip(candidate_distribution["median_ms"].as_f64())
                .map(|(baseline, candidate)| candidate - baseline);
            json!({
                "name": name,
                "baseline": baseline_distribution,
                "candidate": candidate_distribution,
                "candidate_minus_baseline_median_ms": median_delta_ms,
                "detail": "Observed target-resumed host wall-time phase distribution. A delta is not a CPU, causal, or regression attribution."
            })
        })
        .collect()
}

fn startup_profile_artifact_phase_samples(runs: &[&Value]) -> BTreeMap<String, Vec<u64>> {
    let mut samples = BTreeMap::<String, Vec<u64>>::new();
    for run in runs {
        for phase in run["phase_durations"].as_array().into_iter().flatten() {
            let (Some(name), Some(elapsed_ms)) = (
                phase["name"].as_str(),
                (phase["status"].as_str() == Some("observed"))
                    .then(|| phase["elapsed_ms"].as_u64())
                    .flatten(),
            ) else {
                continue;
            };
            samples
                .entry(name.to_string())
                .or_default()
                .push(elapsed_ms);
        }
    }
    samples
}

fn startup_profile_compare_largest_gaps(
    baseline_runs: &[&Value],
    candidate_runs: &[&Value],
) -> Value {
    let baseline = startup_profile_artifact_largest_gap_samples(baseline_runs);
    let candidate = startup_profile_artifact_largest_gap_samples(candidate_runs);
    let baseline_distribution = startup_profile_wall_time_distribution(&baseline);
    let candidate_distribution = startup_profile_wall_time_distribution(&candidate);
    let median_delta_ms = baseline_distribution["median_ms"]
        .as_f64()
        .zip(candidate_distribution["median_ms"].as_f64())
        .map(|(baseline, candidate)| candidate - baseline);
    json!({
        "baseline": baseline_distribution,
        "candidate": candidate_distribution,
        "candidate_minus_baseline_median_ms": median_delta_ms,
        "detail": "One retained largest fully observed lifecycle gap from each completed run. This does not attribute time to CPU, I/O, JIT, or a target-internal cause."
    })
}

fn startup_profile_artifact_largest_gap_samples(runs: &[&Value]) -> Vec<u64> {
    runs.iter()
        .filter_map(|run| run["largest_observed_gaps"].as_array()?.first())
        .filter_map(|gap| gap["elapsed_ms"].as_u64())
        .collect()
}

fn startup_profile_wall_time_distribution(values: &[u64]) -> Value {
    let mut values = values.to_vec();
    values.sort_unstable();
    let sample_count = values.len();
    let median_ms = match sample_count {
        0 => None,
        count if count % 2 == 1 => Some(values[count / 2] as f64),
        count => Some((values[count / 2 - 1] as f64 + values[count / 2] as f64) / 2.0),
    };
    json!({
        "sample_count": sample_count,
        "min_ms": values.first(),
        "median_ms": median_ms,
        "max_ms": values.last()
    })
}

fn startup_profile_compare_sequences(
    baseline_runs: &[&Value],
    candidate_runs: &[&Value],
    max_events: usize,
) -> Value {
    let pairs = baseline_runs
        .iter()
        .zip(candidate_runs)
        .enumerate()
        .map(|(pair_index, (baseline, candidate))| {
            startup_profile_compare_run_sequence(pair_index + 1, baseline, candidate, max_events)
        })
        .collect::<Vec<_>>();
    let divergent_pairs = pairs
        .iter()
        .filter(|pair| pair["status"].as_str() == Some("diverged"))
        .count();
    json!({
        "pairs": pairs,
        "compared_pair_count": pairs.len(),
        "divergent_pair_count": divergent_pairs,
        "detail": "Event kinds, module basenames, and exception codes are compared in retained DbgEng lifecycle order. Thread system IDs are intentionally omitted because they are not stable across launches."
    })
}

fn startup_profile_compare_run_sequence(
    pair_index: usize,
    baseline: &Value,
    candidate: &Value,
    max_events: usize,
) -> Value {
    let baseline_events = baseline["timeline"].as_array().cloned().unwrap_or_default();
    let candidate_events = candidate["timeline"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let baseline_tokens = baseline_events
        .iter()
        .take(max_events)
        .map(startup_profile_artifact_event_token)
        .collect::<Vec<_>>();
    let candidate_tokens = candidate_events
        .iter()
        .take(max_events)
        .map(startup_profile_artifact_event_token)
        .collect::<Vec<_>>();
    let shared_prefix = baseline_tokens
        .iter()
        .zip(&candidate_tokens)
        .take_while(|(baseline, candidate)| baseline == candidate)
        .count();
    let first_divergence =
        if shared_prefix < baseline_tokens.len() && shared_prefix < candidate_tokens.len() {
            Some(json!({
                "index": shared_prefix,
                "baseline": baseline_tokens[shared_prefix],
                "candidate": candidate_tokens[shared_prefix]
            }))
        } else {
            None
        };
    let length_differs = baseline_tokens.len() != candidate_tokens.len();
    let status = if first_divergence.is_some() || length_differs {
        "diverged"
    } else {
        "shared_prefix_within_limit"
    };
    json!({
        "pair_index": pair_index,
        "baseline_run": baseline["run"],
        "candidate_run": candidate["run"],
        "status": status,
        "shared_prefix_event_count": shared_prefix,
        "first_divergence": first_divergence,
        "baseline_events_returned": baseline_events.len(),
        "candidate_events_returned": candidate_events.len(),
        "baseline_events_compared": baseline_tokens.len(),
        "candidate_events_compared": candidate_tokens.len(),
        "sequence_comparison_truncated": baseline_events.len() > max_events || candidate_events.len() > max_events,
        "baseline_profile_timeline_truncated": baseline["coverage"]["timeline_truncated"],
        "candidate_profile_timeline_truncated": candidate["coverage"]["timeline_truncated"]
    })
}

fn startup_profile_artifact_event_token(event: &Value) -> Value {
    json!({
        "kind": event["kind"],
        "module_basename": event["module"]["basename"],
        "exception_code": event["event"]["exception"]["code"]
            .as_u64()
            .map(|code| format!("0x{code:08X}"))
    })
}

fn collect_startup_profile_run(
    args: &LiveStartupProfileArgs,
    run_index: u32,
    phase_module: Option<&str>,
    completion_module: Option<&str>,
    end: LiveLaunchEnd,
) -> anyhow::Result<StartupProfileRun> {
    let command_started = Instant::now();
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: LiveInitialStop::CreateProcessEvent,
    })?;

    let result = collect_startup_profile_stops(
        &session,
        args,
        run_index,
        phase_module,
        completion_module,
        command_started,
    );
    let cleanup = match &result {
        Ok(run) if run.finish_reason == "exit_process" => Ok(json!({
            "action": "none",
            "status": "not_needed",
            "detail": "DbgEng reported exit_process before cleanup."
        })),
        _ => match end {
            LiveLaunchEnd::Detach => session.detach().map(|()| {
                json!({
                    "action": "detach",
                    "status": "ok"
                })
            }),
            LiveLaunchEnd::Terminate => session.terminate().map(|()| {
                json!({
                    "action": "terminate",
                    "status": "ok"
                })
            }),
        },
    };

    match (result, cleanup) {
        (Ok(mut run), Ok(cleanup)) => {
            run.cleanup = cleanup;
            Ok(run)
        }
        (Ok(mut run), Err(error)) => {
            run.status = "cleanup_failed".to_string();
            run.cleanup = json!({
                "action": end,
                "status": "error",
                "error": error.to_string()
            });
            Ok(run)
        }
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error).context(format!(
            "also failed to end the live debug session: {cleanup_error}"
        )),
    }
}

fn collect_startup_profile_stops(
    session: &DebuggerSession,
    args: &LiveStartupProfileArgs,
    run_index: u32,
    phase_module: Option<&str>,
    completion_module: Option<&str>,
    command_started: Instant,
) -> anyhow::Result<StartupProfileRun> {
    let initial_event = session
        .last_event()
        .context("reading the initial DbgEng create-process event")?;
    ensure!(
        initial_event.event_name == "create_process",
        "DbgEng did not stop on create-process: {initial_event:?}"
    );

    let mut recording = StartupProfileRecording {
        timeline: Vec::with_capacity(args.max_events as usize),
        ..StartupProfileRecording::default()
    };
    let mut resumed_elapsed = Duration::ZERO;
    record_startup_profile_event(
        session,
        &mut recording,
        args,
        initial_event,
        (command_started.elapsed(), resumed_elapsed),
    );

    let event_filters =
        configure_startup_profile_event_filters(session, args.include_first_chance_exceptions)?;
    let mut debuggee_output = if args.capture_debuggee_output {
        json!({
            "status": "unavailable",
            "source": "dbgeng_output_callback",
            "records": [],
            "detail": "DbgEng output capture was requested but is not available."
        })
    } else {
        json!({
            "status": "not_requested",
            "source": "dbgeng_output_callback",
            "records": [],
            "detail": "Debuggee output capture is disabled by default because debug strings can contain sensitive content."
        })
    };
    let output_capture = if args.capture_debuggee_output {
        match session.begin_debuggee_output_capture(DebuggerOutputCaptureOptions {
            started_at: command_started,
            max_records: args.max_output_records,
            max_chars_per_record: args.max_output_chars,
            max_total_chars: args.max_total_output_chars,
        }) {
            Ok(capture) => {
                capture
                    .set_preceding_event_index(recording.timeline.last().map(|event| event.index));
                Some(capture)
            }
            Err(error) => {
                debuggee_output = json!({
                    "status": "unavailable",
                    "source": "dbgeng_output_callback",
                    "records": [],
                    "detail": "The startup profile continued without output capture after DbgEng rejected callback installation.",
                    "error": error.to_string()
                });
                None
            }
        }
    } else {
        None
    };
    let mut timeline_truncated = false;
    let mut event_limit_reached = false;
    let mut tail_filter_commands = Vec::new();
    let mut tail_filter_started_after_event_index = None;
    let mut completion = StartupProfileCompletion {
        requested_module: completion_module.map(ToOwned::to_owned),
        settle_ms: args.settle_ms,
        status: if completion_module.is_some() {
            "waiting_for_module".to_string()
        } else {
            "not_requested".to_string()
        },
        module_load: None,
        quiet_resumed_elapsed_ms: None,
        detail: if completion_module.is_some() {
            "Waiting for the requested DbgEng module-load event.".to_string()
        } else {
            "No early module completion boundary was requested; collecting through exit, timeout, or bounded retention behavior.".to_string()
        },
    };
    let mut quiet_started_at = None;
    let finish_reason = loop {
        if completion_module.is_some() {
            if recording.timeline.len() >= args.max_events as usize {
                event_limit_reached = true;
                break "event_limit";
            }
        } else if !timeline_truncated && recording.timeline.len() >= args.max_events as usize - 1 {
            tail_filter_commands = configure_startup_profile_exit_tail_filters(
                session,
                args.include_first_chance_exceptions,
            )?;
            tail_filter_started_after_event_index =
                recording.timeline.last().map(|event| event.index);
            timeline_truncated = true;
        }
        let remaining =
            Duration::from_millis(u64::from(args.timeout_ms)).saturating_sub(resumed_elapsed);
        if remaining.is_zero() {
            break "timeout";
        }
        let wait_budget = quiet_started_at
            .zip(args.settle_ms)
            .map(|(started_at, settle_ms)| {
                Duration::from_millis(u64::from(settle_ms))
                    .saturating_sub(resumed_elapsed.saturating_sub(started_at))
            })
            .unwrap_or(remaining)
            .min(remaining);
        ensure!(
            !wait_budget.is_zero(),
            "startup-profile computed a zero event wait budget"
        );
        session.continue_execution()?;
        let resumed_at = Instant::now();
        let wait_timeout_ms = duration_millis(wait_budget).clamp(1, u64::from(u32::MAX)) as u32;
        let wait = session.wait_for_event(wait_timeout_ms)?;
        resumed_elapsed += resumed_at.elapsed();
        let event = (wait.name.as_deref() != Some("timeout"))
            .then(|| {
                session
                    .last_event()
                    .context("reading a DbgEng lifecycle event")
            })
            .transpose()?;
        if event.as_ref().is_none_or(startup_profile_no_event_sentinel) {
            if let Some(started_at) = quiet_started_at {
                let quiet_elapsed = resumed_elapsed.saturating_sub(started_at);
                if let Some(settle_ms) = args.settle_ms {
                    if quiet_elapsed >= Duration::from_millis(u64::from(settle_ms)) {
                        completion.status = "quiet_interval_observed".to_string();
                        completion.quiet_resumed_elapsed_ms = Some(duration_millis(quiet_elapsed));
                        completion.detail = "No configured DbgEng lifecycle stop was observed while the target was resumed for the requested settle interval. This is not a UI-ready or target-quiescence signal.".to_string();
                        break "completion_module_quiet_interval";
                    }
                }
            }
            break "timeout";
        }
        let event = event.expect("a non-timeout DbgEng wait has an event");
        let exiting = event.event_name == "exit_process";
        if !timeline_truncated || exiting {
            record_startup_profile_event(
                session,
                &mut recording,
                args,
                event,
                (command_started.elapsed(), resumed_elapsed),
            );
            if let Some(capture) = output_capture.as_ref() {
                capture
                    .set_preceding_event_index(recording.timeline.last().map(|event| event.index));
            }
        }
        if exiting {
            if quiet_started_at.is_some() {
                completion.status = "process_exit_before_quiet_interval".to_string();
                completion.detail = "DbgEng reported exit_process before the requested lifecycle quiet interval completed.".to_string();
            } else if completion_module.is_some() && completion.module_load.is_none() {
                completion.status = "process_exit_before_module".to_string();
                completion.detail =
                    "DbgEng reported exit_process before the requested module-load event."
                        .to_string();
            }
            break "exit_process";
        }
        if completion.module_load.is_none()
            && completion_module.is_some_and(|module| {
                startup_profile_event_matches_module(recording.timeline.last(), module)
            })
        {
            completion.module_load = recording
                .timeline
                .last()
                .map(startup_profile_event_reference);
            if let Some(settle_ms) = args.settle_ms {
                completion.status = "waiting_for_quiet_interval".to_string();
                completion.detail = format!(
                    "Observed the requested module-load boundary; waiting for {settle_ms} ms of target-resumed time without another configured DbgEng lifecycle stop."
                );
                quiet_started_at = Some(resumed_elapsed);
            } else {
                completion.status = "module_observed".to_string();
                completion.detail = "Observed the requested DbgEng module-load boundary. This does not establish UI readiness or application initialization completion.".to_string();
                break "completion_module";
            }
        } else if quiet_started_at.is_some() {
            quiet_started_at = Some(resumed_elapsed);
            completion.status = "waiting_for_quiet_interval".to_string();
            completion.detail = "A configured DbgEng lifecycle stop occurred after the completion-module boundary; restarting the observed lifecycle quiet interval.".to_string();
        }
    };

    let phase_durations = derive_startup_profile_phases(&recording.timeline, phase_module);
    if finish_reason == "timeout" && completion_module.is_some() {
        completion.status = if completion.module_load.is_some() {
            "quiet_interval_not_observed_before_timeout".to_string()
        } else {
            "module_not_observed_before_timeout".to_string()
        };
        completion.detail = "The profile target-resumed timeout elapsed before the requested completion condition was observed.".to_string();
    } else if finish_reason == "event_limit" && completion_module.is_some() {
        completion.status = if completion.module_load.is_some() {
            "quiet_interval_not_observed_before_event_limit".to_string()
        } else {
            "module_not_observed_before_event_limit".to_string()
        };
        completion.detail = "The retained lifecycle event limit was reached before the requested completion condition was observed. The target was not continued with filters disabled, so no quiet interval is inferred.".to_string();
    }
    let StartupProfileRecording {
        timeline,
        counts,
        module_identities,
        captured_contexts,
        captured_thread_accounting_snapshots,
        ..
    } = recording;
    let module_identities = module_identities
        .into_iter()
        .take(STARTUP_PROFILE_MAX_MODULE_IDENTITIES)
        .collect::<Vec<_>>();
    let module_identity_truncated =
        counts.unique_module_identity_count > STARTUP_PROFILE_MAX_MODULE_IDENTITIES;
    let timeline_len = timeline.len();
    if let Some(capture) = output_capture {
        debuggee_output = match capture.finish() {
            Ok(capture) => startup_profile_debuggee_output(capture, &timeline),
            Err(error) => json!({
                "status": "unavailable",
                "source": "dbgeng_output_callback",
                "records": [],
                "detail": "DbgEng output callback restoration failed; no output is returned because the capture lifecycle could not be confirmed.",
                "error": error.to_string()
            }),
        };
    }
    let module_provenance = startup_profile_module_provenance(&timeline, args);
    let dbgeng_module_parameters =
        startup_profile_dbgeng_module_parameters(session, &timeline, args);
    let lifecycle_summary =
        startup_profile_lifecycle_summary(&timeline, phase_module, &completion, &debuggee_output);
    let (largest_observed_gaps, gaps_excluded_from_ranking) =
        rank_startup_profile_observed_gaps(&timeline, tail_filter_started_after_event_index);
    let status = if matches!(
        finish_reason,
        "exit_process" | "completion_module" | "completion_module_quiet_interval"
    ) {
        "completed"
    } else {
        "incomplete"
    };
    Ok(StartupProfileRun {
        run: run_index,
        status: status.to_string(),
        finish_reason: finish_reason.to_string(),
        target: session.summary(),
        timing: json!({
            "command_to_create_observed_ms": timeline
                .first()
                .map(|event| event.observed_elapsed_ms),
            "target_resumed_wall_elapsed_ms": duration_millis(resumed_elapsed),
            "timeout_after_create_ms": args.timeout_ms,
            "timeout_clock": "host_monotonic_target_resumed_wall_time",
            "timeline_retention_limit_reached": timeline_truncated,
            "tail_filter_commands": tail_filter_commands,
            "tail_filter_started_after_event_index": tail_filter_started_after_event_index
        }),
        event_filters,
        lifecycle_summary,
        debuggee_output,
        module_provenance,
        dbgeng_module_parameters,
        largest_observed_gaps,
        gaps_excluded_from_ranking,
        timeline,
        phase_durations,
        completion,
        counts: json!({
            "module_load_events": counts.module_load_events,
            "module_unload_events": counts.module_unload_events,
            "create_thread_events": counts.create_thread_events,
            "exit_thread_events": counts.exit_thread_events,
            "exception_events": counts.exception_events,
            "first_chance_exception_events": counts.first_chance_exception_events,
            "peak_observed_live_thread_count": counts.peak_live_thread_count,
            "peak_observed_loaded_module_count": counts.peak_loaded_module_count,
            "unique_observed_module_identities": module_identities,
            "unique_observed_module_identity_count": counts.unique_module_identity_count,
            "unique_observed_module_identities_truncated": module_identity_truncated
        }),
        coverage: json!({
            "timeline_event_limit": args.max_events,
            "timeline_events_returned": timeline_len,
            "timeline_truncated": timeline_truncated,
            "event_limit_reached": event_limit_reached,
            "truncation_behavior": if timeline_truncated {
                "After retaining max_events - 1 lifecycle entries, windbg-tool disabled high-volume filters and waited only for exit_process so the final exit boundary remains observable."
            } else {
                "All observed lifecycle events were retained."
            },
            "finished_at_process_exit": finish_reason == "exit_process",
            "phase_module": phase_module,
            "completion_module": completion_module,
            "first_chance_exceptions_requested": args.include_first_chance_exceptions,
            "stop_context_requested": args.capture_stop_context,
            "stop_contexts_returned": captured_contexts,
            "native_symbol_entry_range_requested": args.capture_native_symbol_entry_range,
            "thread_accounting_requested": args.capture_thread_accounting,
            "thread_accounting_snapshot_limit": args.max_thread_accounting_snapshots,
            "thread_accounting_snapshots_attempted": captured_thread_accounting_snapshots,
            "thread_accounting_thread_limit": args.max_thread_accounting_threads,
            "module_provenance_requested": args.capture_module_provenance,
            "dbgeng_module_parameters_requested": args.capture_dbgeng_module_parameters,
            "dbgeng_module_parameter_limit": args.max_dbgeng_module_parameters
        }),
        cleanup: Value::Null,
    })
}

#[derive(Default)]
struct StartupProfileCounts {
    module_load_events: u32,
    module_unload_events: u32,
    create_thread_events: u32,
    exit_thread_events: u32,
    exception_events: u32,
    first_chance_exception_events: u32,
    peak_live_thread_count: usize,
    peak_loaded_module_count: usize,
    unique_module_identity_count: usize,
}

#[derive(Default)]
struct StartupProfileRecording {
    timeline: Vec<StartupProfileEvent>,
    counts: StartupProfileCounts,
    module_identities: BTreeSet<String>,
    captured_contexts: u32,
    captured_thread_accounting_snapshots: u32,
    prior_thread_accounting: HashMap<(u32, u32), (usize, windbg_dbgeng::ThreadAccountingEntry)>,
}

fn configure_startup_profile_event_filters(
    session: &DebuggerSession,
    include_first_chance_exceptions: bool,
) -> anyhow::Result<Value> {
    let mut commands = Vec::new();
    if include_first_chance_exceptions {
        session
            .execute_command("sxe *")
            .context("configuring DbgEng to stop on first-chance exceptions")?;
        commands.push("sxe *");
    }
    for (command, event) in [
        ("sxe cpr", "create_process"),
        ("sxe epr", "exit_process"),
        ("sxe ct", "create_thread"),
        ("sxe et", "exit_thread"),
        ("sxe ld", "load_module"),
        ("sxe ud", "unload_module"),
    ] {
        session
            .execute_command(command)
            .with_context(|| format!("configuring DbgEng {event} event filtering"))?;
        commands.push(command);
    }
    Ok(json!({
        "commands": commands,
        "first_chance_exceptions": if include_first_chance_exceptions {
            "all_requested_with_sxe_wildcard"
        } else {
            "not_requested; DbgEng's default unhandled-exception behavior remains observable if it stops the target"
        }
    }))
}

fn configure_startup_profile_exit_tail_filters(
    session: &DebuggerSession,
    include_first_chance_exceptions: bool,
) -> anyhow::Result<Vec<String>> {
    let mut commands = Vec::new();
    if include_first_chance_exceptions {
        session
            .execute_command("sxd *")
            .context("disabling first-chance exception stops after the startup timeline limit")?;
        commands.push("sxd *".to_string());
    }
    for (command, event) in [
        ("sxd ct", "create_thread"),
        ("sxd et", "exit_thread"),
        ("sxd ld", "load_module"),
        ("sxd ud", "unload_module"),
        ("sxe epr", "exit_process"),
    ] {
        session
            .execute_command(command)
            .with_context(|| format!("configuring DbgEng exit-tail {event} filtering"))?;
        commands.push(command.to_string());
    }
    Ok(commands)
}

fn startup_profile_no_event_sentinel(event: &windbg_dbgeng::DebuggerEventInfo) -> bool {
    // DbgEng 10.0.29547 can report S_OK for a bounded wait with no event, then
    // expose this all-default LastEventInformation record instead of S_FALSE.
    event.event_type == 0
        && event.event_name == "unknown"
        && event.process_system_id == u32::MAX
        && event.thread_system_id == u32::MAX
        && event.description.is_none()
        && event.extra_information_size == 0
        && event.breakpoint_id.is_none()
        && event.exception.is_none()
        && event.module_base.is_none()
        && event.exit_code.is_none()
}

fn record_startup_profile_event(
    session: &DebuggerSession,
    recording: &mut StartupProfileRecording,
    args: &LiveStartupProfileArgs,
    event: windbg_dbgeng::DebuggerEventInfo,
    timing: (Duration, Duration),
) {
    let (observed_elapsed, resumed_elapsed) = timing;
    let kind = event.event_name.clone();
    let module = event
        .module_base
        .and_then(|address| session.module_by_offset(address).ok().flatten())
        .map(normalize_startup_profile_module);
    let loaded_module_count = if matches!(kind.as_str(), "load_module" | "unload_module") {
        session.modules().ok().map(|modules| modules.len())
    } else {
        None
    };
    let live_thread_count = if matches!(
        kind.as_str(),
        "create_process" | "create_thread" | "exit_thread"
    ) {
        session.threads().ok().map(|threads| threads.len())
    } else {
        None
    };
    match kind.as_str() {
        "load_module" => recording.counts.module_load_events += 1,
        "unload_module" => recording.counts.module_unload_events += 1,
        "create_thread" => recording.counts.create_thread_events += 1,
        "exit_thread" => recording.counts.exit_thread_events += 1,
        "exception" => {
            recording.counts.exception_events += 1;
            if event
                .exception
                .as_ref()
                .is_some_and(|exception| exception.first_chance)
            {
                recording.counts.first_chance_exception_events += 1;
            }
        }
        _ => {}
    }
    if let Some(count) = loaded_module_count {
        recording.counts.peak_loaded_module_count =
            recording.counts.peak_loaded_module_count.max(count);
    }
    if let Some(count) = live_thread_count {
        recording.counts.peak_live_thread_count =
            recording.counts.peak_live_thread_count.max(count);
    }
    if let Some(module) = module.as_ref() {
        if let Some(identity) = module.basename.as_deref().or(module.module_name.as_deref()) {
            recording
                .module_identities
                .insert(identity.to_ascii_lowercase());
            recording.counts.unique_module_identity_count = recording.module_identities.len();
        }
    }
    let context = startup_profile_stop_context(session, recording, args, &kind);
    let thread_accounting = startup_profile_thread_accounting(session, recording, args, &kind);
    recording.timeline.push(StartupProfileEvent {
        index: recording.timeline.len(),
        kind,
        observed_elapsed_ms: duration_millis(observed_elapsed),
        resumed_wall_elapsed_ms: duration_millis(resumed_elapsed),
        event,
        module,
        loaded_module_count,
        live_thread_count,
        context,
        thread_accounting,
    });
}

fn startup_profile_thread_accounting(
    session: &DebuggerSession,
    recording: &mut StartupProfileRecording,
    args: &LiveStartupProfileArgs,
    event_kind: &str,
) -> Value {
    if !args.capture_thread_accounting {
        return json!({
            "status": "not_requested",
            "detail": "Read-only per-thread DbgEng accounting capture is disabled."
        });
    }
    if !startup_profile_thread_accounting_event_selected(args, event_kind) {
        return json!({
            "status": "not_selected",
            "detail": "This lifecycle event kind is outside --thread-accounting-on."
        });
    }
    if recording.captured_thread_accounting_snapshots >= args.max_thread_accounting_snapshots {
        return json!({
            "status": "limit_reached",
            "detail": "The bounded read-only thread-accounting snapshot limit was reached."
        });
    }

    recording.captured_thread_accounting_snapshots += 1;
    let event_index = recording.timeline.len();
    match session.thread_accounting_snapshot(args.max_thread_accounting_threads) {
        Ok(snapshot) => {
            let mut same_thread_deltas = Vec::new();
            for entry in &snapshot.threads {
                let key = (entry.thread.engine_id, entry.thread.system_id);
                if let Some((prior_event_index, previous)) =
                    recording.prior_thread_accounting.get(&key)
                {
                    let current_times = entry.kernel_time_raw.zip(entry.user_time_raw);
                    let previous_times = previous.kernel_time_raw.zip(previous.user_time_raw);
                    let delta = match (current_times, previous_times) {
                        (Some((kernel, user)), Some((previous_kernel, previous_user)))
                            if kernel >= previous_kernel && user >= previous_user =>
                        {
                            json!({
                                "status": "captured",
                                "kernel_time_delta_raw": kernel - previous_kernel,
                                "user_time_delta_raw": user - previous_user,
                                "total_time_delta_raw": kernel - previous_kernel + user - previous_user,
                                "kernel_time_delta_ms": (kernel - previous_kernel) as f64 / 10_000.0,
                                "user_time_delta_ms": (user - previous_user) as f64 / 10_000.0,
                                "total_time_delta_ms": (kernel - previous_kernel + user - previous_user) as f64 / 10_000.0,
                                "detail": "The same DbgEng engine/system thread identifier pair had validity-gated, nondecreasing 100 ns counters. Millisecond projections were fixture-validated, but do not attribute a lifecycle gap to CPU work."
                            })
                        }
                        (Some(_), Some(_)) => json!({
                            "status": "unavailable_counter_decreased",
                            "detail": "At least one raw counter decreased between selected stops, so no delta was emitted."
                        }),
                        _ => json!({
                            "status": "unavailable_missing_valid_timing_counters",
                            "detail": "One or both snapshots did not expose validity-gated kernel and user timing counters."
                        }),
                    };
                    same_thread_deltas.push(json!({
                        "engine_thread_id": entry.thread.engine_id,
                        "system_thread_id": entry.thread.system_id,
                        "prior_event_index": prior_event_index,
                        "current_event_index": event_index,
                        "delta": delta
                    }));
                }
                recording
                    .prior_thread_accounting
                    .insert(key, (event_index, entry.clone()));
            }
            json!({
                "status": snapshot.status,
                "source": snapshot.source,
                "counter_units": snapshot.counter_units,
                "snapshot": snapshot,
                "same_thread_deltas": same_thread_deltas,
                "detail": "The snapshot uses read-only IDebugAdvanced2::GetSystemObjectInformation. Deltas compare only entries with the same DbgEng engine/system thread identifier pair; they do not establish CPU causality for a lifecycle gap or a stable identity if the operating system later reuses a thread ID."
            })
        }
        Err(error) => json!({
            "status": "unavailable",
            "source": "dbgeng_iddebugadvanced2_getsystemobjectinformation",
            "detail": "DbgEng rejected the read-only thread-accounting query.",
            "error": error.to_string()
        }),
    }
}

fn startup_profile_stop_context(
    session: &DebuggerSession,
    recording: &mut StartupProfileRecording,
    args: &LiveStartupProfileArgs,
    event_kind: &str,
) -> Value {
    if !args.capture_stop_context {
        return json!({
            "status": "not_requested",
            "detail": "Read-only stop-context capture is disabled."
        });
    }
    if !startup_profile_context_event_selected(args, event_kind) {
        return json!({
            "status": "not_selected",
            "detail": "This lifecycle event kind is outside --context-on."
        });
    }
    if recording.captured_contexts >= args.max_context_events {
        return json!({
            "status": "limit_reached",
            "detail": "The bounded read-only stop-context capture limit was reached."
        });
    }

    recording.captured_contexts += 1;
    match session.core_registers() {
        Ok(registers) => {
            let instruction_offset = registers.instruction_offset;
            match live_stop_context(session, registers, args.max_frames) {
                Ok(context) => {
                    let native_symbol_entry_range = if args.capture_native_symbol_entry_range {
                        match instruction_offset {
                            Some(address) => match session.symbol_entry_range_by_offset(address) {
                                Ok(range) => json!({
                                    "status": range.status,
                                    "source": range.source,
                                    "value": range,
                                    "detail": "The bounded DbgEng symbol-entry query can cause host-side symbol-resolution I/O through the configured symbol path. It is not target timing or proof of managed execution."
                                }),
                                Err(error) => json!({
                                    "status": "unavailable",
                                    "source": "dbgeng_idebugsymbols5_symbol_entry",
                                    "error": error.to_string()
                                }),
                            },
                            None => json!({
                                "status": "unavailable",
                                "source": "dbgeng_idebugsymbols5_symbol_entry",
                                "detail": "The read-only stop context had no instruction offset."
                            }),
                        }
                    } else {
                        json!({
                            "status": "not_requested",
                            "detail": "Native symbol-entry range capture is disabled."
                        })
                    };
                    json!({
                        "status": "captured",
                        "source": "dbgeng_read_only_stop_snapshot",
                        "value": context,
                        "native_symbol_entry_range": native_symbol_entry_range
                    })
                }
                Err(error) => json!({
                    "status": "unavailable",
                    "source": "dbgeng_read_only_stop_snapshot",
                    "error": error.to_string()
                }),
            }
        }
        Err(error) => json!({
            "status": "unavailable",
            "source": "dbgeng_read_only_stop_snapshot",
            "error": error.to_string()
        }),
    }
}

fn startup_profile_context_event_selected(args: &LiveStartupProfileArgs, event_kind: &str) -> bool {
    let selected = if args.context_on.is_empty() {
        &[
            StartupProfileContextEvent::LoadModule,
            StartupProfileContextEvent::CreateThread,
            StartupProfileContextEvent::Exception,
            StartupProfileContextEvent::ExitProcess,
        ][..]
    } else {
        args.context_on.as_slice()
    };
    selected.iter().any(|selected| {
        matches!(
            (selected, event_kind),
            (StartupProfileContextEvent::CreateProcess, "create_process")
                | (StartupProfileContextEvent::ExitProcess, "exit_process")
                | (StartupProfileContextEvent::CreateThread, "create_thread")
                | (StartupProfileContextEvent::ExitThread, "exit_thread")
                | (StartupProfileContextEvent::LoadModule, "load_module")
                | (StartupProfileContextEvent::UnloadModule, "unload_module")
                | (StartupProfileContextEvent::Exception, "exception")
        )
    })
}

fn startup_profile_thread_accounting_event_selected(
    args: &LiveStartupProfileArgs,
    event_kind: &str,
) -> bool {
    let selected = if args.thread_accounting_on.is_empty() {
        &[
            StartupProfileContextEvent::CreateProcess,
            StartupProfileContextEvent::LoadModule,
            StartupProfileContextEvent::CreateThread,
            StartupProfileContextEvent::ExitProcess,
        ][..]
    } else {
        args.thread_accounting_on.as_slice()
    };
    selected.iter().any(|selected| {
        matches!(
            (selected, event_kind),
            (StartupProfileContextEvent::CreateProcess, "create_process")
                | (StartupProfileContextEvent::ExitProcess, "exit_process")
                | (StartupProfileContextEvent::CreateThread, "create_thread")
                | (StartupProfileContextEvent::ExitThread, "exit_thread")
                | (StartupProfileContextEvent::LoadModule, "load_module")
                | (StartupProfileContextEvent::UnloadModule, "unload_module")
                | (StartupProfileContextEvent::Exception, "exception")
        )
    })
}

fn normalize_startup_profile_module(module: ModuleInfo) -> StartupProfileModule {
    let image_path = [
        module.loaded_image_name.as_deref(),
        module.image_name.as_deref(),
        module.module_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|value| !value.trim().is_empty())
    .map(normalize_startup_profile_path);
    let basename = image_path
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned);
    StartupProfileModule {
        base_address: format!("0x{:X}", module.base_address),
        basename,
        module_name: module.module_name,
        image_path,
    }
}

fn normalize_startup_profile_path(value: &str) -> String {
    value.replace('\\', "/")
}

fn startup_profile_event_reference(event: &StartupProfileEvent) -> StartupProfileEventReference {
    StartupProfileEventReference {
        index: event.index,
        kind: event.kind.clone(),
        observed_elapsed_ms: event.observed_elapsed_ms,
        resumed_wall_elapsed_ms: event.resumed_wall_elapsed_ms,
        thread_system_id: event.event.thread_system_id,
        module: event.module.clone(),
        description: event.event.description.clone(),
        exception_code: event
            .event
            .exception
            .as_ref()
            .map(|exception| format!("0x{:08X}", exception.code)),
        exception_first_chance: event
            .event
            .exception
            .as_ref()
            .map(|exception| exception.first_chance),
    }
}

fn startup_profile_event_matches_module(
    event: Option<&StartupProfileEvent>,
    requested_module: &str,
) -> bool {
    event.is_some_and(|event| {
        event.kind == "load_module"
            && event.module.as_ref().is_some_and(|module| {
                [
                    module.basename.as_deref(),
                    module.module_name.as_deref(),
                    module.image_path.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|candidate| startup_profile_module_name_matches(candidate, requested_module))
            })
    })
}

fn startup_profile_lifecycle_summary(
    timeline: &[StartupProfileEvent],
    phase_module: Option<&str>,
    completion: &StartupProfileCompletion,
    debuggee_output: &Value,
) -> Value {
    let first = timeline.first().map(startup_profile_event_reference);
    let last = timeline.last().map(startup_profile_event_reference);
    let first_module_load = timeline
        .iter()
        .find(|event| event.kind == "load_module")
        .map(startup_profile_event_reference);
    let last_module_load = timeline
        .iter()
        .rfind(|event| event.kind == "load_module")
        .map(startup_profile_event_reference);
    let first_coreclr_load =
        find_startup_profile_module_event(timeline, STARTUP_PROFILE_CORECLR_MODULE)
            .map(startup_profile_event_reference);
    let first_phase_module_load = phase_module
        .and_then(|module| find_startup_profile_module_event(timeline, module))
        .map(startup_profile_event_reference);
    let first_thread_start = timeline
        .iter()
        .find(|event| event.kind == "create_thread")
        .map(startup_profile_event_reference);
    let last_thread_start = timeline
        .iter()
        .rfind(|event| event.kind == "create_thread")
        .map(startup_profile_event_reference);
    let first_thread_exit = timeline
        .iter()
        .find(|event| event.kind == "exit_thread")
        .map(startup_profile_event_reference);
    let last_thread_exit = timeline
        .iter()
        .rfind(|event| event.kind == "exit_thread")
        .map(startup_profile_event_reference);
    let first_exception = timeline
        .iter()
        .find(|event| event.kind == "exception")
        .map(startup_profile_event_reference);
    let last_exception = timeline
        .iter()
        .rfind(|event| event.kind == "exception")
        .map(startup_profile_event_reference);
    let process_exit = timeline
        .iter()
        .find(|event| event.kind == "exit_process")
        .map(startup_profile_event_reference);

    let mut seen = BTreeSet::new();
    let mut first_seen_modules = Vec::new();
    let mut runtime_loader_modules = Vec::new();
    let mut total_unique_modules = 0usize;
    for event in timeline.iter().filter(|event| event.kind == "load_module") {
        let Some(module) = event.module.as_ref() else {
            continue;
        };
        let Some(identity) = module.basename.as_deref().or(module.module_name.as_deref()) else {
            continue;
        };
        if !seen.insert(identity.to_ascii_lowercase()) {
            continue;
        }
        total_unique_modules += 1;
        let classification = startup_profile_module_classification(module, phase_module);
        let value = json!({
            "classification": classification,
            "event": startup_profile_event_reference(event)
        });
        if classification == "runtime_loader" {
            runtime_loader_modules.push(value.clone());
        }
        if first_seen_modules.len() < STARTUP_PROFILE_MAX_FIRST_SEEN_MODULES {
            first_seen_modules.push(value);
        }
    }
    let first_seen_returned = first_seen_modules.len();

    json!({
        "first_observed_event": first,
        "last_observed_event": last,
        "process": {
            "create": timeline
                .iter()
                .find(|event| event.kind == "create_process")
                .map(startup_profile_event_reference),
            "exit": process_exit,
            "exit_observed": timeline.iter().any(|event| event.kind == "exit_process")
        },
        "modules": {
            "first_load": first_module_load,
            "last_load": last_module_load,
            "first_coreclr_load": first_coreclr_load,
            "first_selected_phase_module_load": first_phase_module_load,
            "first_seen": first_seen_modules,
            "first_seen_returned": first_seen_returned,
            "first_seen_total_unique": total_unique_modules,
            "first_seen_truncated": total_unique_modules > STARTUP_PROFILE_MAX_FIRST_SEEN_MODULES,
            "runtime_loader_first_seen": runtime_loader_modules
        },
        "threads": {
            "first_start": first_thread_start,
            "last_start": last_thread_start,
            "first_exit": first_thread_exit,
            "last_exit": last_thread_exit
        },
        "exceptions": {
            "first": first_exception,
            "last": last_exception,
            "status": if timeline.iter().any(|event| event.kind == "exception") {
                "observed"
            } else {
                "not_observed"
            }
        },
        "debuggee_output": {
            "status": debuggee_output["status"],
            "records_returned": debuggee_output["records_returned"],
            "dropped_record_count": debuggee_output["dropped_record_count"],
            "detail": debuggee_output["detail"]
        },
        "completion_boundary": completion
    })
}

fn startup_profile_debuggee_output(
    capture: windbg_dbgeng::DebuggerOutputCaptureResult,
    timeline: &[StartupProfileEvent],
) -> Value {
    let records = capture
        .records
        .into_iter()
        .map(|record| {
            let preceding_event = record
                .preceding_event_index
                .and_then(|index| timeline.get(index))
                .map(startup_profile_event_reference);
            json!({
                "elapsed_ms": record.elapsed_ms,
                "preceding_event_index": record.preceding_event_index,
                "preceding_event": preceding_event,
                "mask": format!("0x{:X}", record.mask),
                "categories": record.categories,
                "text": record.text,
                "text_truncated": record.text_truncated
            })
        })
        .collect::<Vec<_>>();
    json!({
        "status": capture.status,
        "source": capture.source,
        "records": records,
        "records_returned": capture.records_returned,
        "dropped_record_count": capture.dropped_record_count,
        "dropped_text_char_count": capture.dropped_text_char_count,
        "max_records": capture.max_records,
        "max_chars_per_record": capture.max_chars_per_record,
        "max_total_chars": capture.max_total_chars,
        "detail": capture.detail
    })
}

fn startup_profile_dbgeng_module_parameters(
    session: &DebuggerSession,
    timeline: &[StartupProfileEvent],
    args: &LiveStartupProfileArgs,
) -> Value {
    if !args.capture_dbgeng_module_parameters {
        return json!({
            "status": "not_requested",
            "source": "dbgeng_idebugsymbols5_getmoduleparameters",
            "records": [],
            "detail": "DbgEng module-parameter capture is disabled by default because configured symbol paths can cause host-side resolution I/O."
        });
    }
    let mut modules = BTreeMap::new();
    for event in timeline {
        if let (Some(base_address), Some(module)) = (event.event.module_base, event.module.as_ref())
        {
            modules
                .entry(base_address)
                .or_insert_with(|| module.clone());
        }
    }
    let observed_module_count = modules.len();
    let selected = modules
        .into_iter()
        .take(args.max_dbgeng_module_parameters as usize)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return json!({
            "status": "not_observed",
            "source": "dbgeng_idebugsymbols5_getmoduleparameters",
            "records": [],
            "detail": "No retained lifecycle event had a DbgEng module base address to query."
        });
    }
    let base_addresses = selected
        .iter()
        .map(|(base_address, _)| *base_address)
        .collect::<Vec<_>>();
    match session.module_parameters(&base_addresses) {
        Ok(parameters) => {
            let records = selected
                .into_iter()
                .zip(parameters)
                .map(|((base_address, module), parameters)| {
                    json!({
                        "module": module,
                        "base_address": format!("0x{base_address:X}"),
                        "parameters": parameters
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "status": "captured",
                "source": "dbgeng_idebugsymbols5_getmoduleparameters",
                "records": records,
                "records_returned": base_addresses.len(),
                "observed_module_base_count": observed_module_count,
                "truncated": observed_module_count > base_addresses.len(),
                "detail": "These are bounded DbgEng module/symbol-readiness parameters for lifecycle-observed bases. They are not target timing or target-memory evidence. The configured symbol path can cause host-side symbol-resolution I/O."
            })
        }
        Err(error) => json!({
            "status": "unavailable",
            "source": "dbgeng_idebugsymbols5_getmoduleparameters",
            "records": [],
            "detail": "DbgEng rejected the bounded module-parameter query; lifecycle collection continued.",
            "error": error.to_string()
        }),
    }
}

fn startup_profile_module_provenance(
    timeline: &[StartupProfileEvent],
    args: &LiveStartupProfileArgs,
) -> Value {
    if !args.capture_module_provenance {
        return json!({
            "status": "not_requested",
            "source": "host_file_metadata",
            "records": [],
            "detail": "Host-side module provenance is disabled by default. When enabled, windbg-tool reads only bounded metadata for DbgEng-observed module image paths."
        });
    }

    let mut seen_paths = BTreeSet::new();
    let mut candidates = Vec::new();
    for event in timeline {
        if event.kind != "load_module" {
            continue;
        }
        let Some(image_path) = event
            .module
            .as_ref()
            .and_then(|module| module.image_path.as_deref())
        else {
            continue;
        };
        if seen_paths.insert(image_path.to_ascii_lowercase()) {
            candidates.push((
                image_path.to_string(),
                startup_profile_event_reference(event),
            ));
        }
    }

    let candidate_count = candidates.len();
    let truncated = candidate_count > args.max_module_provenance as usize;
    let records = candidates
        .into_iter()
        .take(args.max_module_provenance as usize)
        .map(|(image_path, event)| {
            if !Path::new(&image_path).is_absolute() {
                return json!({
                    "event": event,
                    "observed_image_path": image_path,
                    "status": "rejected_non_absolute_path",
                    "detail": "DbgEng did not provide an absolute image path, so windbg-tool did not perform a host file read."
                });
            }
            match bounded_pe_file_metadata(
                Path::new(&image_path),
                STARTUP_PROFILE_MAX_PROVENANCE_FILE_BYTES,
            ) {
                Ok(metadata) => json!({
                    "event": event,
                    "observed_image_path": image_path,
                    "status": "captured",
                    "metadata": metadata
                }),
                Err(error) => json!({
                    "event": event,
                    "observed_image_path": image_path,
                    "status": "unavailable",
                    "error": error.to_string(),
                    "detail": "The debugger-observed path could not be inspected under the host metadata limits."
                }),
            }
        })
        .collect::<Vec<_>>();
    json!({
        "status": "captured",
        "source": "host_file_metadata",
        "records": records,
        "unique_observed_image_paths": candidate_count,
        "returned": records.len(),
        "limit": args.max_module_provenance,
        "truncated": truncated,
        "host_file_read_limit_bytes_per_module": STARTUP_PROFILE_MAX_PROVENANCE_FILE_BYTES,
        "detail": "Metadata is read from host files only after DbgEng reported their absolute image paths. It is not target-memory evidence and its timestamps are not lifecycle timing."
    })
}

fn startup_profile_module_classification(
    module: &StartupProfileModule,
    phase_module: Option<&str>,
) -> &'static str {
    let candidates = [
        module.basename.as_deref(),
        module.module_name.as_deref(),
        module.image_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if startup_profile_is_runtime_loader_module(&candidates) {
        "runtime_loader"
    } else if phase_module.is_some_and(|phase_module| {
        candidates
            .into_iter()
            .any(|candidate| startup_profile_module_name_matches(candidate, phase_module))
    }) {
        "selected_phase_module"
    } else {
        "other_module"
    }
}

fn startup_profile_is_runtime_loader_module(candidates: &[&str]) -> bool {
    [
        "coreclr.dll",
        "hostfxr.dll",
        "hostpolicy.dll",
        "clrjit.dll",
        "mscoree.dll",
    ]
    .iter()
    .any(|runtime_module| {
        candidates
            .iter()
            .any(|candidate| startup_profile_module_name_matches(candidate, runtime_module))
    })
}

fn rank_startup_profile_observed_gaps(
    timeline: &[StartupProfileEvent],
    tail_filter_started_after_event_index: Option<usize>,
) -> (Vec<StartupProfileGap>, Vec<StartupProfileExcludedGap>) {
    let mut gaps = Vec::new();
    let mut excluded = Vec::new();
    for pair in timeline.windows(2) {
        let [start, end] = pair else {
            continue;
        };
        let Some(elapsed_ms) = end
            .resumed_wall_elapsed_ms
            .checked_sub(start.resumed_wall_elapsed_ms)
        else {
            continue;
        };
        let start = startup_profile_event_reference(start);
        let end = startup_profile_event_reference(end);
        if tail_filter_started_after_event_index.is_some_and(|tail_start| start.index >= tail_start)
        {
            excluded.push(StartupProfileExcludedGap {
                start,
                end,
                reason: "DbgEng high-volume lifecycle filters were disabled for the exit-only tail, so intervening events may be omitted.".to_string(),
            });
            continue;
        }
        gaps.push(StartupProfileGap {
            rank: 0,
            elapsed_ms,
            start,
            end,
            detail: "Target-resumed host wall time between adjacent observed DbgEng lifecycle stops while the full lifecycle filter set was active; not CPU time.".to_string(),
        });
    }
    gaps.sort_by(|left, right| {
        right
            .elapsed_ms
            .cmp(&left.elapsed_ms)
            .then_with(|| left.start.index.cmp(&right.start.index))
    });
    gaps.truncate(STARTUP_PROFILE_MAX_RANKED_GAPS);
    for (index, gap) in gaps.iter_mut().enumerate() {
        gap.rank = index + 1;
    }
    (gaps, excluded)
}

fn derive_startup_profile_phases(
    timeline: &[StartupProfileEvent],
    phase_module: Option<&str>,
) -> Vec<StartupProfilePhase> {
    let create = timeline.iter().find(|event| event.kind == "create_process");
    let coreclr = find_startup_profile_module_event(timeline, STARTUP_PROFILE_CORECLR_MODULE);
    let selected =
        phase_module.and_then(|module| find_startup_profile_module_event(timeline, module));
    let exit = timeline.iter().find(|event| event.kind == "exit_process");
    let mut phases = Vec::with_capacity(5);
    phases.push(match create {
        Some(event) => StartupProfilePhase {
            name: "launch_to_create_process".to_string(),
            status: "observed".to_string(),
            elapsed_ms: Some(event.observed_elapsed_ms),
            start_event_index: None,
            end_event_index: Some(event.index),
            detail: "Host command-start to observed DbgEng create-process stop.".to_string(),
        },
        None => unavailable_startup_profile_phase(
            "launch_to_create_process",
            "DbgEng did not report a create-process event.",
        ),
    });
    phases.push(startup_profile_phase_between(
        "create_process_to_coreclr_load",
        create,
        coreclr,
        "Requires observed create-process and coreclr.dll load events.",
    ));
    if let Some(module) = phase_module {
        phases.push(startup_profile_phase_between(
            "coreclr_load_to_selected_module_load",
            coreclr,
            selected,
            &format!("Requires observed coreclr.dll and selected module ({module}) load events."),
        ));
        phases.push(startup_profile_phase_between(
            "selected_module_load_to_exit_process",
            selected,
            exit,
            &format!("Requires observed selected module ({module}) load and exit-process events."),
        ));
    } else {
        phases.push(unavailable_startup_profile_phase(
            "coreclr_load_to_selected_module_load",
            "No --phase-module was requested.",
        ));
        phases.push(unavailable_startup_profile_phase(
            "selected_module_load_to_exit_process",
            "No --phase-module was requested.",
        ));
    }
    phases.push(startup_profile_phase_between(
        "create_process_to_exit_process",
        create,
        exit,
        "Requires observed create-process and exit-process events.",
    ));
    phases
}

fn find_startup_profile_module_event<'a>(
    timeline: &'a [StartupProfileEvent],
    requested_module: &str,
) -> Option<&'a StartupProfileEvent> {
    timeline.iter().find(|event| {
        event.kind == "load_module"
            && event.module.as_ref().is_some_and(|module| {
                [
                    module.basename.as_deref(),
                    module.module_name.as_deref(),
                    module.image_path.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|candidate| startup_profile_module_name_matches(candidate, requested_module))
            })
    })
}

fn startup_profile_module_name_matches(candidate: &str, requested: &str) -> bool {
    module_name_matches(candidate, requested)
        || Path::new(candidate)
            .file_stem()
            .zip(Path::new(requested).file_stem())
            .is_some_and(|(candidate, requested)| candidate.eq_ignore_ascii_case(requested))
}

fn startup_profile_phase_between(
    name: &str,
    start: Option<&StartupProfileEvent>,
    end: Option<&StartupProfileEvent>,
    missing_detail: &str,
) -> StartupProfilePhase {
    match (start, end) {
        (Some(start), Some(end)) if end.resumed_wall_elapsed_ms >= start.resumed_wall_elapsed_ms => {
            StartupProfilePhase {
                name: name.to_string(),
                status: "observed".to_string(),
                elapsed_ms: Some(end.resumed_wall_elapsed_ms - start.resumed_wall_elapsed_ms),
                start_event_index: Some(start.index),
                end_event_index: Some(end.index),
                detail: "Host monotonic wall time accumulated while the target was resumed between observed DbgEng stops.".to_string(),
            }
        }
        (Some(start), Some(end)) => StartupProfilePhase {
            name: name.to_string(),
            status: "unavailable".to_string(),
            elapsed_ms: None,
            start_event_index: Some(start.index),
            end_event_index: Some(end.index),
            detail: "Observed event order was not monotonic; duration is intentionally omitted.".to_string(),
        },
        _ => unavailable_startup_profile_phase(name, missing_detail),
    }
}

fn unavailable_startup_profile_phase(name: &str, detail: &str) -> StartupProfilePhase {
    StartupProfilePhase {
        name: name.to_string(),
        status: "unavailable".to_string(),
        elapsed_ms: None,
        start_event_index: None,
        end_event_index: None,
        detail: detail.to_string(),
    }
}

fn startup_profile_aggregate(completed_runs: &[StartupProfileRun]) -> Value {
    let mut values_by_phase = BTreeMap::<String, Vec<u64>>::new();
    let mut phase_occurrences = BTreeMap::<String, usize>::new();
    let mut largest_gap_values = Vec::new();
    let mut largest_gap_boundaries = BTreeMap::<String, usize>::new();
    for run in completed_runs {
        for phase in &run.phase_durations {
            *phase_occurrences.entry(phase.name.clone()).or_default() += 1;
            if phase.status == "observed" {
                if let Some(value) = phase.elapsed_ms {
                    values_by_phase
                        .entry(phase.name.clone())
                        .or_default()
                        .push(value);
                }
            }
        }
        if let Some(gap) = run.largest_observed_gaps.first() {
            largest_gap_values.push(gap.elapsed_ms);
            *largest_gap_boundaries
                .entry(startup_profile_gap_boundary_name(gap))
                .or_default() += 1;
        }
    }
    let phases = phase_occurrences
        .into_iter()
        .map(|(name, count)| {
            let mut values = values_by_phase.remove(&name).unwrap_or_default();
            values.sort_unstable();
            let sample_count = values.len();
            let median_ms = if sample_count == 0 {
                None
            } else if sample_count % 2 == 1 {
                Some(values[sample_count / 2] as f64)
            } else {
                Some((values[sample_count / 2 - 1] as f64 + values[sample_count / 2] as f64) / 2.0)
            };
            json!({
                "name": name,
                "sample_count": sample_count,
                "missing_count": count - sample_count,
                "min_ms": values.first(),
                "median_ms": median_ms,
                "max_ms": values.last(),
                "regression_assessment": {
                    "status": "no_baseline",
                    "detail": "This aggregate has no reference baseline, so it reports wall-clock variability only and does not label a regression or CPU cause."
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "completed_run_count": completed_runs.len(),
        "phase_wall_time_ms": phases,
        "largest_observed_inter_event_gap_wall_time_ms": startup_profile_gap_distribution(
            largest_gap_values,
            largest_gap_boundaries
        ),
        "coverage": "Only runs that reached the requested completion condition contribute samples. A missing boundary remains missing rather than inferred."
    })
}

fn startup_profile_gap_boundary_name(gap: &StartupProfileGap) -> String {
    format!(
        "{} -> {}",
        startup_profile_event_boundary_name(&gap.start),
        startup_profile_event_boundary_name(&gap.end)
    )
}

fn startup_profile_event_boundary_name(event: &StartupProfileEventReference) -> String {
    let module = event
        .module
        .as_ref()
        .and_then(|module| module.basename.as_deref().or(module.module_name.as_deref()));
    match module {
        Some(module) => format!("{}:{module}", event.kind),
        None => event.kind.clone(),
    }
}

fn startup_profile_gap_distribution(
    mut values: Vec<u64>,
    boundary_counts: BTreeMap<String, usize>,
) -> Value {
    values.sort_unstable();
    let sample_count = values.len();
    let median_ms = if sample_count == 0 {
        None
    } else if sample_count % 2 == 1 {
        Some(values[sample_count / 2] as f64)
    } else {
        Some((values[sample_count / 2 - 1] as f64 + values[sample_count / 2] as f64) / 2.0)
    };
    let boundaries = boundary_counts
        .into_iter()
        .map(|(boundary, occurrence_count)| {
            json!({
                "boundary": boundary,
                "occurrence_count": occurrence_count
            })
        })
        .collect::<Vec<_>>();
    json!({
        "sample_count": sample_count,
        "min_ms": values.first(),
        "median_ms": median_ms,
        "max_ms": values.last(),
        "largest_gap_boundaries": boundaries,
        "detail": "One largest ranked adjacent event gap is sampled from each completed run. Gaps with tail-filtered coverage are excluded."
    })
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

pub(super) fn run_live_managed_break(
    args: LiveManagedBreakArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    if args.hardware_execute {
        return run_live_managed_hardware_break(args, output);
    }

    const CORECLR_MODULE: &str = "coreclr.dll";
    const CLR_NOTIFICATION_EXCEPTION: u32 = 0xe044_4143;
    const CLR_NOTIFICATION_FILTER: &str = "clrn";

    let end = parse_live_launch_end(&args.end)?;
    let managed_module = validate_managed_module(&args.managed_module)?;
    let method = validate_managed_breakpoint_token(&args.method, "--method")?;
    let signature = parse_managed_method_signature(args.signature.as_deref())?;
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: LiveInitialStop::CreateProcessEvent,
    })?;

    let result = (|| {
        let initial_event = session.summary();
        session
            .execute_command(&format!("sxe ld:{CORECLR_MODULE}"))
            .context("configuring the non-invasive CoreCLR module-load stop")?;
        session
            .execute_command(&format!("sxe {CLR_NOTIFICATION_FILTER}"))
            .context("configuring CLR code-generation notification handling")?;

        let continued_to_coreclr = session.continue_execution()?;
        let coreclr_wait = session
            .wait_for_event(args.wait_timeout_ms)
            .context("waiting for CoreCLR to load")?;
        let coreclr_event = session
            .last_event()
            .context("reading the CoreCLR module-load event")?;
        ensure!(
            coreclr_wait.name.as_deref() == Some("break")
                && coreclr_event.event_name == "load_module"
                && coreclr_event.module_base.is_some(),
            "DbgEng did not stop on the requested CoreCLR module-load event: wait={coreclr_wait:?}, event={coreclr_event:?}"
        );

        let modules_after_coreclr_load = session.modules()?;
        let coreclr_module = find_loaded_module(&modules_after_coreclr_load, CORECLR_MODULE)?;
        let coreclr_path = module_image_path(coreclr_module, "CoreCLR")?;
        let mut dac = session
            .open_coreclr_dac_bridge(&coreclr_path, args.allow_runtime_write)
            .context("initializing the exact-version CoreCLR DAC bridge")?;
        dac.enable_module_load_notifications()
            .context("requesting CLR managed-module load notifications")?;

        session
            .execute_command(&format!("sxe ld:{managed_module}"))
            .with_context(|| {
                format!("configuring the managed-module load stop for {managed_module}")
            })?;
        let managed_module_load = wait_for_dbgeng_managed_module_load(
            &session,
            args.wait_timeout_ms,
            CLR_NOTIFICATION_EXCEPTION,
        )?;
        let modules_after_managed_load = session.modules()?;
        let loaded_managed_module =
            find_loaded_module(&modules_after_managed_load, &managed_module)?;
        let managed_module_path = module_image_path(loaded_managed_module, "managed assembly")?;
        let (managed_module_observation, managed_module_notification_pending) =
            if dac.is_module_loaded(&managed_module_path)? {
                (
                    json!({
                        "module_available": true,
                        "source": "immediately_after_dbgeng_load_event",
                        "notifications": []
                    }),
                    false,
                )
            } else {
                (
                    wait_for_managed_module_in_dac(
                        &session,
                        &dac,
                        &managed_module_path,
                        args.wait_timeout_ms,
                        CLR_NOTIFICATION_EXCEPTION,
                    )?,
                    true,
                )
            };
        dac.disable_module_load_notifications()
            .context("disabling CLR managed-module load notifications after module discovery")?;
        let (resolved_method, availability) = dac
            .resolve_and_notify(&managed_module_path, &method, signature.as_deref())
            .with_context(|| {
                format!(
                    "resolving {method} in the selected managed module {managed_module} through the DAC"
                )
            })?;

        let (code_notification, generated_method, clr_notification_pending) = match availability {
            ManagedCodeAvailability::Available => (
                None,
                resolved_method.clone(),
                managed_module_notification_pending,
            ),
            ManagedCodeAvailability::PendingJit => {
                let continued =
                    continue_after_clr_notification(&session, managed_module_notification_pending)?;
                let wait = session
                    .wait_for_event(args.wait_timeout_ms)
                    .context("waiting for the requested CLR code-generation notification")?;
                let event = session
                    .last_event()
                    .context("reading the CLR code-generation notification")?;
                ensure!(
                    wait.name.as_deref() == Some("break")
                        && event.event_name == "exception"
                        && event
                            .exception
                            .as_ref()
                            .is_some_and(|exception| exception.code == CLR_NOTIFICATION_EXCEPTION),
                    "DbgEng did not stop on the requested CLR code-generation notification"
                );
                let generated = dac.refresh_method_code().context(
                    "refreshing the selected method after its CLR code-generation notification",
                )?;
                ensure!(
                    generated.representative_entry_address.is_some(),
                    "the CLR notification did not produce a representative native entry address"
                );
                (
                    Some(json!({
                        "exception_code": format!("0x{CLR_NOTIFICATION_EXCEPTION:08X}"),
                        "continued": continued,
                        "wait": wait,
                        "event": event,
                        "selected_method_code_available": true
                    })),
                    generated,
                    true,
                )
            }
        };
        ensure!(
            generated_method.token == resolved_method.token,
            "the DAC returned generated code for a different MethodDef token"
        );
        let native_entry_address = generated_method
            .representative_entry_address
            .context("the selected managed method has no generated native entry address")?;
        let code_breakpoint = session.add_code_breakpoint(native_entry_address)?;
        let (breakpoint_stop, code_breakpoint_hit) = wait_for_managed_code_breakpoint(
            &session,
            &code_breakpoint,
            native_entry_address,
            args.wait_timeout_ms,
            CLR_NOTIFICATION_EXCEPTION,
            clr_notification_pending,
        )?;
        let registers = session.core_registers()?;
        let context = live_stop_context(&session, registers, args.max_frames)?;
        Ok(json!({
            "workflow": "live_managed_break_dac",
            "command_line": args.command_line,
            "initial_event": initial_event,
            "coreclr_module_load": {
                "module": CORECLR_MODULE,
                "continued": continued_to_coreclr,
                "wait": coreclr_wait,
                "event": coreclr_event,
                "loaded_module": coreclr_module,
                "runtime": dac.runtime_info()
            },
            "managed_module_load": {
                "managed_module": managed_module,
                "dbgeng_load": managed_module_load,
                "observation": managed_module_observation,
                "notifications_disabled_after_observation": true,
                "loaded_module": loaded_managed_module
            },
            "managed_resolution": {
                "method_request": method,
                "signature_request_hex": signature.as_deref().map(format_managed_method_signature),
                "resolved_method": resolved_method,
                "method_after_code_generation": generated_method,
                "runtime_writes_explicitly_allowed": args.allow_runtime_write,
                "exact_overload_signature_selection": signature.is_some(),
                "private_methods_supported": true
            },
            "code_generation": {
                "notification_filter": CLR_NOTIFICATION_FILTER,
                "notification": code_notification,
                "representative_native_entry_address": format!("0x{native_entry_address:X}")
            },
            "managed_breakpoint": {
                "kind": "software_code",
                "configured": code_breakpoint,
                "stop": breakpoint_stop,
                "hit": code_breakpoint_hit,
                "hit_evidence": if code_breakpoint_hit {
                    "the DbgEng code breakpoint event ID and current instruction pointer both match the DAC-mapped native entry for the selected MethodDef"
                } else {
                    "the selected MethodDef was resolved by the DAC, but DbgEng did not report a matching code breakpoint hit"
                }
            },
            "context": context,
            "limitations": [
                "Overloads require --signature with an exact ECMA-335 MethodDef signature blob; generic instantiations are not selected separately.",
                "The breakpoint covers the DAC representative entry address. Generic instantiations, tiered recompilation, ReadyToRun entry indirection, and re-JIT/unload transitions require additional validation."
            ],
            "end": end
        }))
    })();

    let cleanup = match end {
        LiveLaunchEnd::Detach => session.detach(),
        LiveLaunchEnd::Terminate => session.terminate(),
    };
    match (result, cleanup) {
        (Ok(result), Ok(())) => print_value(result, output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("failed to end the live debug session"),
    }
}

fn run_live_managed_hardware_break(
    args: LiveManagedBreakArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    const CORECLR_MODULE: &str = "coreclr.dll";

    ensure!(
        !args.allow_runtime_write,
        "--hardware-execute cannot be combined with --allow-runtime-write"
    );
    let end = parse_live_launch_end(&args.end)?;
    let managed_module = validate_managed_module(&args.managed_module)?;
    let method = validate_managed_breakpoint_token(&args.method, "--method")?;
    let signature = parse_managed_method_signature(args.signature.as_deref())?;
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: LiveInitialStop::CreateProcessEvent,
    })?;

    let result = (|| {
        let initial_event = session.summary();
        session
            .execute_command(&format!("sxe ld:{CORECLR_MODULE}"))
            .context("configuring the non-invasive CoreCLR module-load stop")?;
        let coreclr_wait = continue_to_dbgeng_module_load(
            &session,
            args.wait_timeout_ms,
            "CoreCLR module-load event",
        )?;
        let modules_after_coreclr_load = session.modules()?;
        let coreclr_module = find_loaded_module(&modules_after_coreclr_load, CORECLR_MODULE)?;
        let coreclr_path = module_image_path(coreclr_module, "CoreCLR")?;
        let mut dac = session
            .open_coreclr_dac_bridge(&coreclr_path, false)
            .context("initializing the exact-version read-only CoreCLR DAC bridge")?;

        session
            .execute_command(&format!("sxe ld:{managed_module}"))
            .with_context(|| {
                format!("configuring the managed-module load stop for {managed_module}")
            })?;
        let managed_module_load = continue_to_dbgeng_module_load(
            &session,
            args.wait_timeout_ms,
            "managed module-load event",
        )?;
        let modules_after_managed_load = session.modules()?;
        let loaded_managed_module =
            find_loaded_module(&modules_after_managed_load, &managed_module)?;
        let managed_module_path = module_image_path(loaded_managed_module, "managed assembly")?;
        let module_available = dac.is_module_loaded(&managed_module_path)?;

        let (
            resolved_method,
            availability,
            configured_breakpoint,
            breakpoint_stop,
            hit,
            binding_state,
        ) = if !module_available {
            (
                None,
                None,
                None,
                None,
                false,
                "module_not_observable_without_runtime_write",
            )
        } else {
            let (resolved_method, availability) = dac
                    .resolve_read_only(&managed_module_path, &method, signature.as_deref())
                    .with_context(|| {
                        format!(
                            "resolving {method} in the selected managed module {managed_module} through the read-only DAC"
                        )
                    })?;
            match availability {
                ManagedCodeAvailability::PendingJit => (
                    Some(resolved_method),
                    Some("pending_jit"),
                    None,
                    None,
                    false,
                    "pending_jit_unobservable_without_runtime_write",
                ),
                ManagedCodeAvailability::Available => {
                    let native_entry_address =
                        resolved_method.representative_entry_address.context(
                            "the selected managed method has no generated native entry address",
                        )?;
                    let breakpoint =
                        session.add_hardware_execute_breakpoint(native_entry_address)?;
                    let (stop, hit) = wait_for_managed_hardware_execute_breakpoint(
                        &session,
                        &breakpoint,
                        native_entry_address,
                        args.wait_timeout_ms,
                    )?;
                    (
                        Some(resolved_method),
                        Some("available"),
                        Some(breakpoint),
                        Some(stop),
                        hit,
                        if hit {
                            "hardware_execute_hit"
                        } else {
                            "hardware_execute_not_hit"
                        },
                    )
                }
            }
        };

        let registers = session.core_registers()?;
        let context = live_stop_context(&session, registers, args.max_frames)?;
        Ok(json!({
            "workflow": "live_managed_break_dac_hardware_execute",
            "command_line": args.command_line,
            "initial_event": initial_event,
            "target_memory_writes": {
                "requested": false,
                "dac_notification_registration": false,
                "software_code_breakpoint": false,
                "operations": []
            },
            "coreclr_module_load": {
                "module": CORECLR_MODULE,
                "load": coreclr_wait,
                "loaded_module": coreclr_module,
                "runtime": dac.runtime_info()
            },
            "managed_module_load": {
                "managed_module": managed_module,
                "load": managed_module_load,
                "loaded_module": loaded_managed_module,
                "module_available_to_read_only_dac": module_available
            },
            "managed_resolution": {
                "method_request": method,
                "signature_request_hex": signature.as_deref().map(format_managed_method_signature),
                "resolved_method": resolved_method,
                "code_availability": availability,
                "exact_overload_signature_selection": signature.is_some(),
                "private_methods_resolve_as_metadata": true
            },
            "managed_breakpoint": {
                "kind": "hardware_execute",
                "configured": configured_breakpoint,
                "stop": breakpoint_stop,
                "hit": hit,
                "binding_state": binding_state,
                "hit_evidence": if hit {
                    "DbgEng reported the configured processor breakpoint ID and the current instruction pointer both match the DAC-mapped native entry for the selected MethodDef"
                } else {
                    "No managed hit is claimed: a hardware breakpoint can be set only for native code already visible to the read-only DAC at the managed module-load stop"
                }
            },
            "limitations": [
                "Without CLR code notifications, a method first JIT-compiled after this module-load event is not observable and cannot be bound.",
                "Tiered recompilation, ReadyToRun indirection, re-JIT, generic instantiations, and unload transitions can replace or invalidate a native entry.",
                "x64 processor breakpoints use a constrained per-thread debug-register resource; no thread restriction is configured by this command."
            ],
            "context": context,
            "end": end
        }))
    })();

    let cleanup = match end {
        LiveLaunchEnd::Detach => session.detach(),
        LiveLaunchEnd::Terminate => session.terminate(),
    };
    match (result, cleanup) {
        (Ok(result), Ok(())) => print_value(result, output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("failed to end the live debug session"),
    }
}

fn continue_to_dbgeng_module_load(
    session: &DebuggerSession,
    wait_timeout_ms: u32,
    description: &str,
) -> anyhow::Result<Value> {
    let continued = session.continue_execution()?;
    let wait = session
        .wait_for_event(wait_timeout_ms)
        .with_context(|| format!("waiting for the {description}"))?;
    let event = session
        .last_event()
        .with_context(|| format!("reading the {description}"))?;
    ensure!(
        wait.name.as_deref() == Some("break")
            && event.event_name == "load_module"
            && event.module_base.is_some(),
        "DbgEng did not stop on the requested {description}: wait={wait:?}, event={event:?}"
    );
    Ok(json!({
        "continued": continued,
        "wait": wait,
        "event": event
    }))
}

fn wait_for_managed_hardware_execute_breakpoint(
    session: &DebuggerSession,
    breakpoint: &BreakpointInfo,
    native_entry_address: u64,
    wait_timeout_ms: u32,
) -> anyhow::Result<(Value, bool)> {
    let continued = session.continue_execution()?;
    let wait = session
        .wait_for_event(wait_timeout_ms)
        .context("waiting for the managed processor execute breakpoint")?;
    let event = (wait.name.as_deref() == Some("break"))
        .then(|| session.last_event())
        .transpose()?;
    let registers = session.core_registers()?;
    let hit = event.as_ref().is_some_and(|event| {
        event.event_name == "breakpoint"
            && event.breakpoint_id == Some(breakpoint.id)
            && registers.instruction_offset == Some(native_entry_address)
    });
    Ok((
        json!({
            "continued": continued,
            "wait": wait,
            "event": event,
            "instruction_pointer": registers.instruction_offset
        }),
        hit,
    ))
}

fn continue_after_clr_notification(
    session: &DebuggerSession,
    clr_notification_pending: bool,
) -> anyhow::Result<windbg_dbgeng::DebuggerExecutionStatus> {
    if clr_notification_pending {
        session.continue_execution_handled()
    } else {
        session.continue_execution()
    }
}

fn wait_for_managed_code_breakpoint(
    session: &DebuggerSession,
    breakpoint: &BreakpointInfo,
    native_entry_address: u64,
    wait_timeout_ms: u32,
    clr_notification_exception: u32,
    mut clr_notification_pending: bool,
) -> anyhow::Result<(Value, bool)> {
    const MAX_PRELIMINARY_NOTIFICATIONS: usize = 64;

    let deadline = Instant::now() + Duration::from_millis(u64::from(wait_timeout_ms));
    let mut preliminary_notifications = Vec::new();
    for attempt in 1..=MAX_PRELIMINARY_NOTIFICATIONS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for the managed code breakpoint"
        );
        let remaining_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let continued = continue_after_clr_notification(session, clr_notification_pending)?;
        let wait = session
            .wait_for_event(remaining_ms)
            .context("waiting for the managed code breakpoint")?;
        let event = session
            .last_event()
            .context("reading the managed code breakpoint event")?;
        let registers = session.core_registers()?;
        let code_breakpoint_hit = wait.name.as_deref() == Some("break")
            && event.event_name == "breakpoint"
            && event.breakpoint_id == Some(breakpoint.id)
            && registers.instruction_offset == Some(native_entry_address);
        if code_breakpoint_hit {
            return Ok((
                json!({
                    "continued": continued,
                    "wait": wait,
                    "event": event,
                    "preliminary_clr_notifications": preliminary_notifications
                }),
                true,
            ));
        }

        let is_clr_notification = wait.name.as_deref() == Some("break")
            && event.event_name == "exception"
            && event
                .exception
                .as_ref()
                .is_some_and(|exception| exception.code == clr_notification_exception);
        ensure!(
            is_clr_notification,
            "DbgEng stopped before the managed code breakpoint: wait={wait:?}, event={event:?}, instruction_pointer={:?}",
            registers.instruction_offset
        );
        preliminary_notifications.push(json!({
            "attempt": attempt,
            "continued": continued,
            "wait": wait,
            "event": event
        }));
        clr_notification_pending = true;
    }

    bail!(
        "the CLR emitted {MAX_PRELIMINARY_NOTIFICATIONS} notifications before the managed code breakpoint"
    )
}

fn validate_module_load_filter(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "--wait-for-module must not be empty");
    ensure!(
        value
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-')),
        "--wait-for-module must be a module basename"
    );
    Ok(value.to_string())
}

fn live_stop_context(
    session: &DebuggerSession,
    registers: windbg_dbgeng::CoreRegisterState,
    max_frames: u32,
) -> anyhow::Result<Value> {
    let instruction_offset = registers.instruction_offset;
    let current_module = instruction_offset
        .map(|address| session.module_by_offset(address))
        .transpose()?
        .flatten();
    let current_symbol = instruction_offset
        .map(|address| session.symbol_by_offset(address))
        .transpose()?
        .flatten();
    let stack = match session.stack_trace(max_frames) {
        Ok(frames) => json!({
            "status": "ok",
            "frames": frames,
            "frame_limit": max_frames
        }),
        Err(error) => json!({
            "status": "error",
            "error": error.to_string(),
            "frames": [],
            "frame_limit": max_frames
        }),
    };
    Ok(json!({
        "target": session.summary(),
        "registers": registers,
        "instruction_pointer": instruction_offset,
        "current_module": current_module,
        "current_symbol": current_symbol,
        "stack": stack
    }))
}

fn validate_managed_breakpoint_token(value: &str, argument: &str) -> anyhow::Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{argument} must not be empty");
    ensure!(
        value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '$' | '`')
        }),
        "{argument} contains unsupported characters"
    );
    Ok(value.to_string())
}

fn parse_managed_method_signature(value: Option<&str>) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let value = value.trim();
    ensure!(!value.is_empty(), "--signature must not be empty");
    ensure!(
        value.chars().all(|character| {
            character.is_ascii_hexdigit()
                || character.is_ascii_whitespace()
                || matches!(character, '-' | '_' | ':')
        }),
        "--signature must contain hexadecimal byte pairs separated only by whitespace, '-', '_', or ':'"
    );
    let hexadecimal = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>();
    ensure!(
        hexadecimal.len() % 2 == 0,
        "--signature must contain complete hexadecimal byte pairs"
    );
    ensure!(
        hexadecimal.len() <= 1022,
        "--signature exceeds the 511-byte direct DAC selector limit"
    );

    let signature = hexadecimal
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .context("parsing the high nibble of --signature")?;
            let low = (pair[1] as char)
                .to_digit(16)
                .context("parsing the low nibble of --signature")?;
            Ok((high << 4 | low) as u8)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Some(signature))
}

fn format_managed_method_signature(signature: &[u8]) -> String {
    signature.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn validate_managed_module(value: &str) -> anyhow::Result<String> {
    let path = validate_module_load_filter(value)?;
    ensure!(
        Path::new(&path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("dll") || extension.eq_ignore_ascii_case("exe")
            }),
        "--managed-module must be a managed .dll or .exe basename"
    );
    Ok(path)
}

fn module_image_path(module: &ModuleInfo, role: &str) -> anyhow::Result<PathBuf> {
    [
        module.loaded_image_name.as_deref(),
        module.image_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .with_context(|| {
        format!("DbgEng did not report an accessible {role} image path for the selected module")
    })
}

fn wait_for_dbgeng_managed_module_load(
    session: &DebuggerSession,
    wait_timeout_ms: u32,
    clr_notification_exception: u32,
) -> anyhow::Result<Value> {
    const MAX_PRELIMINARY_NOTIFICATIONS: usize = 64;

    let deadline = Instant::now() + Duration::from_millis(u64::from(wait_timeout_ms));
    let mut preliminary_notifications = Vec::new();
    let mut continue_as_handled = false;
    for attempt in 1..=MAX_PRELIMINARY_NOTIFICATIONS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for DbgEng's managed module-load event"
        );
        let remaining_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let continued = if continue_as_handled {
            session.continue_execution_handled()?
        } else {
            session.continue_execution()?
        };
        let wait = session
            .wait_for_event(remaining_ms)
            .context("waiting for the managed module-load event")?;
        let event = session
            .last_event()
            .context("reading the managed module-load event")?;
        if wait.name.as_deref() == Some("break")
            && event.event_name == "load_module"
            && event.module_base.is_some()
        {
            return Ok(json!({
                "continued": continued,
                "wait": wait,
                "event": event,
                "preliminary_clr_notifications": preliminary_notifications
            }));
        }

        let is_clr_notification = wait.name.as_deref() == Some("break")
            && event.event_name == "exception"
            && event
                .exception
                .as_ref()
                .is_some_and(|exception| exception.code == clr_notification_exception);
        ensure!(
            is_clr_notification,
            "DbgEng stopped before the requested managed module-load event: wait={wait:?}, event={event:?}"
        );
        preliminary_notifications.push(json!({
            "attempt": attempt,
            "continued": continued,
            "wait": wait,
            "event": event
        }));
        continue_as_handled = true;
    }

    bail!(
        "the CLR emitted {MAX_PRELIMINARY_NOTIFICATIONS} notifications before DbgEng reported the managed module-load event"
    )
}

fn wait_for_managed_module_in_dac(
    session: &DebuggerSession,
    dac: &windbg_dbgeng::CoreClrDacBridge,
    managed_module_path: &Path,
    wait_timeout_ms: u32,
    clr_notification_exception: u32,
) -> anyhow::Result<Value> {
    const MAX_CLR_NOTIFICATIONS: usize = 64;

    let deadline = Instant::now() + Duration::from_millis(u64::from(wait_timeout_ms));
    let mut notifications = Vec::new();
    let mut continue_as_handled = false;
    for attempt in 1..=MAX_CLR_NOTIFICATIONS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for the CLR to register the selected managed module"
        );
        let remaining_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let continued = if continue_as_handled {
            session.continue_execution_handled()?
        } else {
            session.continue_execution()?
        };
        let wait = session
            .wait_for_event(remaining_ms)
            .context("waiting for the next CLR managed-module notification")?;
        let event = session
            .last_event()
            .context("reading the CLR managed-module notification")?;
        let is_clr_notification = event.event_name == "exception"
            && event
                .exception
                .as_ref()
                .is_some_and(|exception| exception.code == clr_notification_exception);
        ensure!(
            wait.name.as_deref() == Some("break") && is_clr_notification,
            "DbgEng stopped before the CLR registered the selected managed module"
        );
        let module_available = dac.is_module_loaded(managed_module_path)?;
        notifications.push(json!({
            "attempt": attempt,
            "continued": continued,
            "wait": wait,
            "event": event,
            "module_available": module_available
        }));
        if module_available {
            return Ok(json!({
                "notification_exception_code": format!("0x{clr_notification_exception:08X}"),
                "notifications": notifications,
                "module_available": true
            }));
        }
        continue_as_handled = true;
    }

    bail!(
        "the CLR emitted {MAX_CLR_NOTIFICATIONS} notifications without registering the selected managed module"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StartupBreakpointSpec {
    InitialBreak,
    Address { address: u64 },
    ModuleOffset { module: String, offset: u64 },
    Symbol { expression: String },
}

fn startup_breakpoint_spec(args: &LiveStartupBreakArgs) -> anyhow::Result<StartupBreakpointSpec> {
    let selections = usize::from(args.initial_break)
        + usize::from(args.address.is_some())
        + usize::from(args.module_offset.is_some())
        + usize::from(args.symbol.is_some());
    ensure!(
        selections == 1,
        "specify exactly one of --initial-break, --address, --module with --module-offset, or --symbol"
    );
    if args.initial_break {
        return Ok(StartupBreakpointSpec::InitialBreak);
    }
    if let Some(address) = args.address.as_deref() {
        return Ok(StartupBreakpointSpec::Address {
            address: parse_debug_address(address)?,
        });
    }
    if let Some(offset) = args.module_offset.as_deref() {
        return Ok(StartupBreakpointSpec::ModuleOffset {
            module: args
                .module
                .clone()
                .context("--module-offset requires --module")?,
            offset: parse_debug_address(offset)?,
        });
    }
    let expression = args
        .symbol
        .as_deref()
        .context("a startup breakpoint specification is required")?
        .trim();
    ensure!(!expression.is_empty(), "--symbol must not be empty");
    Ok(StartupBreakpointSpec::Symbol {
        expression: expression.to_string(),
    })
}

fn validate_startup_breakpoint_mode(
    hardware_execute: bool,
    spec: &StartupBreakpointSpec,
) -> anyhow::Result<()> {
    ensure!(
        !hardware_execute || !matches!(spec, StartupBreakpointSpec::InitialBreak),
        "--hardware-execute requires --address, --module with --module-offset, or --symbol"
    );
    Ok(())
}

fn set_startup_breakpoint(
    session: &DebuggerSession,
    spec: &StartupBreakpointSpec,
) -> anyhow::Result<BreakpointInfo> {
    match spec {
        StartupBreakpointSpec::InitialBreak => {
            bail!("initial-break capture does not create a code breakpoint")
        }
        StartupBreakpointSpec::Address { address } => session.add_code_breakpoint(*address),
        StartupBreakpointSpec::ModuleOffset { module, offset } => {
            let modules = session.modules()?;
            let module = find_loaded_module(&modules, module)?;
            let address = module
                .base_address
                .checked_add(*offset)
                .context("module base plus breakpoint offset overflowed")?;
            session.add_code_breakpoint(address)
        }
        StartupBreakpointSpec::Symbol { expression } => {
            session.add_code_breakpoint_expression(expression)
        }
    }
}

fn set_startup_hardware_execute_breakpoint(
    session: &DebuggerSession,
    spec: &StartupBreakpointSpec,
) -> anyhow::Result<BreakpointInfo> {
    let address = startup_breakpoint_address(session, spec)?;
    session.add_hardware_execute_breakpoint(address)
}

fn startup_breakpoint_address(
    session: &DebuggerSession,
    spec: &StartupBreakpointSpec,
) -> anyhow::Result<u64> {
    match spec {
        StartupBreakpointSpec::InitialBreak => {
            bail!("initial-break capture does not identify a processor execute breakpoint address")
        }
        StartupBreakpointSpec::Address { address } => Ok(*address),
        StartupBreakpointSpec::ModuleOffset { module, offset } => {
            let modules = session.modules()?;
            let module = find_loaded_module(&modules, module)?;
            module
                .base_address
                .checked_add(*offset)
                .context("module base plus breakpoint offset overflowed")
        }
        StartupBreakpointSpec::Symbol { expression } => {
            let evaluation = session
                .evaluate(expression)
                .with_context(|| format!("evaluating hardware breakpoint symbol '{expression}'"))?;
            evaluation
                .unsigned_value
                .or_else(|| {
                    evaluation
                        .signed_value
                        .and_then(|address| u64::try_from(address).ok())
                })
                .with_context(|| {
                    format!(
                        "DbgEng did not resolve hardware breakpoint symbol '{expression}' to an unsigned address"
                    )
                })
        }
    }
}

fn find_loaded_module<'a>(
    modules: &'a [ModuleInfo],
    requested_module: &str,
) -> anyhow::Result<&'a ModuleInfo> {
    modules
        .iter()
        .find(|module| {
            [
                module.module_name.as_deref(),
                module.image_name.as_deref(),
                module.loaded_image_name.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|candidate| module_name_matches(candidate, requested_module))
        })
        .with_context(|| format!("module '{requested_module}' is not loaded at the initial break"))
}

fn module_name_matches(candidate: &str, requested: &str) -> bool {
    candidate.eq_ignore_ascii_case(requested)
        || Path::new(candidate)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(requested))
}

fn parse_debug_address(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    };
    parsed.with_context(|| {
        format!("invalid address '{value}'; use decimal or 0x-prefixed hexadecimal")
    })
}

fn parse_live_launch_end(value: &str) -> anyhow::Result<LiveLaunchEnd> {
    match value {
        "detach" => Ok(LiveLaunchEnd::Detach),
        "terminate" => Ok(LiveLaunchEnd::Terminate),
        other => bail!("unsupported live launch end action: {other}"),
    }
}

pub(super) fn run_trace_record(
    args: TraceRecordArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let mut plan = trace_record_plan(&args)?;
    let launcher = trace_record_launcher()?;
    if args.disable_user_shadow_stack {
        plan.target = TraceRecordTarget::Attach {
            process_id: launch_target_with_shadow_stacks_disabled(&plan.command_line)?,
        };
    }
    let started = Instant::now();
    let execution = execute_trace_recording(&plan, &launcher)?;
    let status = execution.status;
    ensure!(
        status.success(),
        "TTD recorder exited with {}",
        status
            .code()
            .map_or_else(|| "no exit code".to_string(), |code| code.to_string())
    );
    ensure!(
        plan.output.is_file(),
        "TTD recorder completed without creating {}",
        plan.output.display()
    );

    let artifact_paths = trace_artifact_paths(&plan.output);
    let diagnostics = trace_record_diagnostics(&plan, started.elapsed())?;
    let completion_note = if plan.capture.record_for_seconds.is_some() {
        "The bounded stop finalizes TTD recording without terminating the target process."
    } else {
        "The trace is finalized after the launched target exits."
    };
    print_value(
        json!({
            "recorder": plan.ttd_exe,
            "output": plan.output,
            "command_line": plan.command_line,
            "recording_mode": plan.target.name(),
            "target_process_id": plan.target.process_id(),
            "exit_code": status.code(),
            "elevation": launcher.name(),
            "capture": trace_capture_value(&plan.capture),
            "lifecycle": {
                "record_for_seconds": plan.capture.record_for_seconds,
                "stopped_after_limit": execution.stopped_after_limit,
                "stop_exit_code": execution.stop_exit_code,
            },
            "artifacts": artifact_paths,
            "diagnostics": diagnostics,
            "notes": [
                "TTD recording is invasive and can significantly slow the target process.",
                completion_note,
                "TTD traces can contain sensitive process-memory data."
            ]
        }),
        output,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceRecordPlan {
    ttd_exe: PathBuf,
    output: PathBuf,
    command_line: String,
    recorder_args: Vec<OsString>,
    target: TraceRecordTarget,
    capture: TraceCaptureSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceCaptureSettings {
    profile: Option<TraceRecordProfile>,
    modules: Vec<String>,
    max_file_mb: Option<u32>,
    ring: bool,
    replay_cpu_support: Option<TraceReplayCpuSupport>,
    num_vcpu: Option<u32>,
    record_for_seconds: Option<u32>,
}

struct TraceRecordExecution {
    status: ExitStatus,
    stopped_after_limit: bool,
    stop_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceRecordTarget {
    Launch,
    Attach { process_id: u32 },
}

impl TraceRecordTarget {
    fn name(&self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::Attach { .. } => "attach_after_cet_disabled_launch",
        }
    }

    fn process_id(&self) -> Option<u32> {
        match self {
            Self::Launch => None,
            Self::Attach { process_id } => Some(*process_id),
        }
    }
}

fn trace_record_plan(args: &TraceRecordArgs) -> anyhow::Result<TraceRecordPlan> {
    ensure!(
        !args.command_line.trim().is_empty(),
        "--command-line must not be empty"
    );
    ensure!(
        args.output
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("run")),
        "--output must name a .run trace file"
    );
    let output_parent = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(
        output_parent.is_dir(),
        "trace output directory does not exist: {}",
        output_parent.display()
    );
    ensure!(
        !args.output.exists(),
        "trace output already exists: {}",
        args.output.display()
    );
    ensure!(
        args.profile.is_none() || (args.max_file_mb.is_none() && !args.ring),
        "--profile cannot be combined with --max-file-mb or --ring"
    );
    if let Some(record_for_seconds) = args.record_for_seconds {
        ensure!(
            record_for_seconds > 0,
            "--record-for-seconds must be greater than zero"
        );
        ensure!(
            args.disable_user_shadow_stack,
            "--record-for-seconds requires --disable-user-shadow-stack so windbg-tool knows the target PID"
        );
    }

    let ttd_exe = resolve_ttd_exe(args.ttd_exe.as_deref())?;
    let mut recorder_args = vec![
        OsString::from("-noUI"),
        OsString::from("-out"),
        args.output.as_os_str().to_os_string(),
        OsString::from("-accepteula"),
    ];
    let (max_file_mb, ring) = trace_size_settings(args)?;
    let modules = args
        .modules
        .iter()
        .map(|module| validate_ttd_module_name(module))
        .collect::<anyhow::Result<Vec<_>>>()?;

    if args.children {
        recorder_args.push(OsString::from("-children"));
    }
    for module in &modules {
        recorder_args.push(OsString::from("-module"));
        recorder_args.push(OsString::from(module));
    }
    if let Some(max_file_mb) = max_file_mb {
        recorder_args.push(OsString::from("-maxFile"));
        recorder_args.push(OsString::from(max_file_mb.to_string()));
    }
    if ring {
        recorder_args.push(OsString::from("-ring"));
    }
    if let Some(replay_cpu_support) = args.replay_cpu_support {
        recorder_args.push(OsString::from("-replayCpuSupport"));
        recorder_args.push(OsString::from(replay_cpu_support.ttd_value()));
    }
    if let Some(num_vcpu) = args.num_vcpu {
        ensure!(num_vcpu > 0, "--num-vcpu must be greater than zero");
        recorder_args.push(OsString::from("-numVCpu"));
        recorder_args.push(OsString::from(num_vcpu.to_string()));
    }
    Ok(TraceRecordPlan {
        ttd_exe,
        output: args.output.clone(),
        command_line: args.command_line.clone(),
        recorder_args,
        target: TraceRecordTarget::Launch,
        capture: TraceCaptureSettings {
            profile: args.profile,
            modules,
            max_file_mb,
            ring,
            replay_cpu_support: args.replay_cpu_support,
            num_vcpu: args.num_vcpu,
            record_for_seconds: args.record_for_seconds,
        },
    })
}

fn trace_size_settings(args: &TraceRecordArgs) -> anyhow::Result<(Option<u32>, bool)> {
    if let Some(profile) = args.profile {
        return Ok(match profile {
            TraceRecordProfile::Startup => (Some(1024), false),
            TraceRecordProfile::Recent => (Some(2048), true),
        });
    }

    if let Some(max_file_mb) = args.max_file_mb {
        ensure!(max_file_mb > 0, "--max-file-mb must be greater than zero");
    }
    ensure!(
        !args.ring || args.max_file_mb.is_some(),
        "--ring requires --max-file-mb"
    );
    Ok((args.max_file_mb, args.ring))
}

fn validate_ttd_module_name(module: &str) -> anyhow::Result<String> {
    let module = module.trim();
    ensure!(!module.is_empty(), "--module must not be empty");
    ensure!(
        !module.contains(['\\', '/']),
        "--module must be a native module basename, not a path: {module}"
    );
    Ok(module.to_string())
}

fn trace_capture_value(capture: &TraceCaptureSettings) -> Value {
    json!({
        "profile": capture.profile.map(TraceRecordProfile::name),
        "modules": capture.modules,
        "max_file_mb": capture.max_file_mb,
        "ring": capture.ring,
        "replay_cpu_support": capture.replay_cpu_support.map(TraceReplayCpuSupport::ttd_value),
        "num_vcpu": capture.num_vcpu,
        "record_for_seconds": capture.record_for_seconds,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TtdSidecarSummary {
    allocated_vcpus: Option<u32>,
    running_threads: Option<u32>,
    simulation_duration_ms: Option<u64>,
    recording_engine_initialized: bool,
    tracing_started: bool,
    tracing_completed: bool,
    trace_dumped: bool,
}

fn trace_record_diagnostics(plan: &TraceRecordPlan, elapsed: Duration) -> anyhow::Result<Value> {
    let metadata = std::fs::metadata(&plan.output)
        .with_context(|| format!("reading trace metadata from {}", plan.output.display()))?;
    let trace_size_bytes = metadata.len();
    let elapsed_ms = elapsed.as_millis() as u64;
    let write_rate_mib_per_second = if elapsed.is_zero() {
        None
    } else {
        Some((trace_size_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64())
    };
    let sidecar_path = plan.output.with_extension("out");
    let (sidecar, sidecar_read_error) = match std::fs::read_to_string(&sidecar_path) {
        Ok(contents) => (Some(parse_ttd_sidecar(&contents)), None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let mut warnings = Vec::new();
    if let Some(rate) = write_rate_mib_per_second {
        if rate >= 32.0 {
            warnings.push(format!(
                "Trace growth is high at {rate:.1} MiB/s; use --max-file-mb, --ring, --record-for-seconds, or --module to bound future captures."
            ));
        }
    }
    if trace_size_bytes >= 1024 * 1024 * 1024 {
        warnings.push(
            "The trace exceeds 1 GiB. Keep it local and use bounded capture settings for exploratory recordings."
                .to_string(),
        );
    }
    if plan.capture.ring {
        warnings.push(
            "Ring mode retains only the newest portion of the recording once the size limit is reached."
                .to_string(),
        );
    }
    if let Some(sidecar) = sidecar.as_ref() {
        if !sidecar.recording_engine_initialized || !sidecar.trace_dumped {
            warnings.push(
                "TTD sidecar did not confirm both recording-engine initialization and trace finalization; inspect the .out file before relying on this capture."
                    .to_string(),
            );
        }
    }

    Ok(json!({
        "trace_size_bytes": trace_size_bytes,
        "trace_size_mib": trace_size_bytes as f64 / 1024.0 / 1024.0,
        "elapsed_ms": elapsed_ms,
        "write_rate_mib_per_second": write_rate_mib_per_second,
        "sidecar": {
            "path": sidecar_path,
            "available": sidecar.is_some(),
            "read_error": sidecar_read_error,
            "allocated_vcpus": sidecar.as_ref().and_then(|summary| summary.allocated_vcpus),
            "running_threads": sidecar.as_ref().and_then(|summary| summary.running_threads),
            "simulation_duration_ms": sidecar.as_ref().and_then(|summary| summary.simulation_duration_ms),
            "recording_engine_initialized": sidecar.as_ref().map(|summary| summary.recording_engine_initialized),
            "tracing_started": sidecar.as_ref().map(|summary| summary.tracing_started),
            "tracing_completed": sidecar.as_ref().map(|summary| summary.tracing_completed),
            "trace_dumped": sidecar.as_ref().map(|summary| summary.trace_dumped),
        },
        "warnings": warnings,
    }))
}

fn parse_ttd_sidecar(contents: &str) -> TtdSidecarSummary {
    let mut summary = TtdSidecarSummary {
        recording_engine_initialized: contents
            .contains("RecordingEngine initialization successful."),
        tracing_started: contents.contains("Tracing started at:"),
        tracing_completed: contents.contains("Tracing completed at:"),
        trace_dumped: contents.contains("Trace dumped to "),
        ..Default::default()
    };
    for line in contents.lines() {
        if let Some(values) = line.strip_prefix("Allocated processors:") {
            if let Some((vcpus, threads)) = values.split_once(", running threads:") {
                summary.allocated_vcpus = vcpus.trim().parse().ok();
                summary.running_threads = threads.trim_end_matches('.').trim().parse().ok();
            }
        }
        if line.starts_with("Simulation time of ") {
            summary.simulation_duration_ms = line
                .rsplit_once(':')
                .and_then(|(_, duration)| duration.trim().strip_suffix("ms."))
                .and_then(|duration| duration.parse().ok());
        }
    }
    summary
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceRecordLauncher {
    Direct,
    Sudo {
        executable: PathBuf,
        working_directory: PathBuf,
        mode: WindowsSudoMode,
    },
}

impl TraceRecordLauncher {
    fn name(&self) -> &'static str {
        match self {
            Self::Direct => "already_elevated",
            Self::Sudo {
                mode: WindowsSudoMode::Inline,
                ..
            } => "windows_sudo_inline",
            Self::Sudo {
                mode: WindowsSudoMode::DisableInput,
                ..
            } => "windows_sudo_disable_input",
            Self::Sudo {
                mode: WindowsSudoMode::ForceNewWindow,
                ..
            } => "windows_sudo_force_new_window",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSudoMode {
    DisableInput,
    Inline,
    ForceNewWindow,
}

fn trace_record_launcher() -> anyhow::Result<TraceRecordLauncher> {
    if current_process_is_elevated()? {
        return Ok(TraceRecordLauncher::Direct);
    }

    let (sudo, mode) = find_enabled_sudo()?.context(
        "TTD recording requires elevation, but Windows sudo is unavailable or disabled; run windbg-tool from an elevated terminal or enable sudo in Settings > System > Advanced",
    )?;
    if mode == WindowsSudoMode::ForceNewWindow {
        bail!(
            "Windows sudo is configured for Force New Window mode, which cannot synchronously wait for TTD recording; run windbg-tool from an elevated terminal or configure sudo for Input Closed or Inline mode in Settings > System > Advanced"
        );
    }
    let working_directory =
        env::current_dir().context("resolving the current working directory")?;
    Ok(TraceRecordLauncher::Sudo {
        executable: sudo,
        working_directory,
        mode,
    })
}

fn command_from_trace_record_plan(
    plan: &TraceRecordPlan,
    launcher: &TraceRecordLauncher,
) -> Command {
    let mut command = ttd_command(&plan.ttd_exe, launcher);
    command.args(&plan.recorder_args);
    match plan.target {
        TraceRecordTarget::Launch => {
            command.arg("-launch");
            // TTD requires its target command line after -launch. raw_arg preserves the caller's
            // Windows command-line quoting without introducing a shell.
            command.raw_arg(&plan.command_line);
        }
        TraceRecordTarget::Attach { process_id } => {
            command.arg("-attach").arg(process_id.to_string());
        }
    }
    command
}

fn ttd_command(ttd_exe: &Path, launcher: &TraceRecordLauncher) -> Command {
    match launcher {
        TraceRecordLauncher::Direct => Command::new(ttd_exe),
        TraceRecordLauncher::Sudo {
            executable,
            working_directory,
            mode,
        } => {
            let mut command = Command::new(executable);
            command
                .arg("--preserve-env")
                .arg("--chdir")
                .arg(working_directory);
            match mode {
                WindowsSudoMode::DisableInput => {
                    command.arg("--disable-input");
                }
                WindowsSudoMode::Inline => {
                    command.arg("--inline");
                }
                WindowsSudoMode::ForceNewWindow => {
                    unreachable!("asynchronous sudo mode is rejected")
                }
            }
            command.arg(ttd_exe);
            command
        }
    }
}

fn execute_trace_recording(
    plan: &TraceRecordPlan,
    launcher: &TraceRecordLauncher,
) -> anyhow::Result<TraceRecordExecution> {
    let mut child = command_from_trace_record_plan(plan, launcher)
        .spawn()
        .with_context(|| format!("launching TTD recorder {}", plan.ttd_exe.display()))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(child.wait());
    });

    let Some(record_for_seconds) = plan.capture.record_for_seconds else {
        return Ok(TraceRecordExecution {
            status: receiver
                .recv()
                .context("waiting for the TTD recorder process")??,
            stopped_after_limit: false,
            stop_exit_code: None,
        });
    };

    match receiver.recv_timeout(Duration::from_secs(record_for_seconds.into())) {
        Ok(status) => Ok(TraceRecordExecution {
            status: status.context("waiting for the TTD recorder process")?,
            stopped_after_limit: false,
            stop_exit_code: None,
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let process_id = plan
                .target
                .process_id()
                .context("--record-for-seconds requires a trace target with a known process id")?;
            let stop_status = command_from_ttd_stop(&plan.ttd_exe, launcher, process_id)
                .status()
                .context("stopping the bounded TTD recording")?;
            ensure!(
                stop_status.success(),
                "TTD recorder stop request exited with {}; the recording may still be active",
                stop_status
                    .code()
                    .map_or_else(|| "no exit code".to_string(), |code| code.to_string())
            );
            Ok(TraceRecordExecution {
                status: receiver
                    .recv()
                    .context("waiting for TTD trace finalization after the stop request")??,
                stopped_after_limit: true,
                stop_exit_code: stop_status.code(),
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("TTD recorder wait worker disconnected unexpectedly")
        }
    }
}

fn command_from_ttd_stop(
    ttd_exe: &Path,
    launcher: &TraceRecordLauncher,
    process_id: u32,
) -> Command {
    let mut command = ttd_command(ttd_exe, launcher);
    command
        .arg("-accepteula")
        .arg("-stop")
        .arg(process_id.to_string());
    command
}

const CET_USER_SHADOW_STACKS_ALWAYS_OFF: u64 = 0x0000_0000_2000_0000;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
const WAIT_FAILED: u32 = u32::MAX;

fn launch_target_with_shadow_stacks_disabled(command_line: &str) -> anyhow::Result<u32> {
    let mut attribute_list_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut attribute_list_size,
        );
    }
    ensure!(
        attribute_list_size > 0,
        "allocating the process mitigation attribute list"
    );
    let mut attribute_list_storage =
        vec![0usize; attribute_list_size.div_ceil(std::mem::size_of::<usize>())];
    let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list_storage.as_mut_ptr().cast());
    let mut mitigation_policy = [0u64, CET_USER_SHADOW_STACKS_ALWAYS_OFF];
    let mut startup = STARTUPINFOEXW::default();
    let mut process_information = PROCESS_INFORMATION::default();
    let mut command_line = wide_null(command_line);
    let current_directory =
        env::current_dir().context("resolving the current working directory")?;
    let current_directory = wide_null(current_directory.as_os_str());

    unsafe {
        InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_list_size)
            .context("initializing the process mitigation attribute list")?;
        let update = UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            Some(mitigation_policy.as_mut_ptr().cast()),
            std::mem::size_of_val(&mitigation_policy),
            None,
            None,
        );
        if let Err(error) = update {
            DeleteProcThreadAttributeList(attribute_list);
            return Err(error).context("setting the per-process CET mitigation");
        }

        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attribute_list;
        let created = CreateProcessW(
            None,
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR(current_directory.as_ptr()),
            &startup.StartupInfo,
            &mut process_information,
        );
        DeleteProcThreadAttributeList(attribute_list);
        created.context("launching the target with CET shadow stacks disabled")?;
        let input_idle = WaitForInputIdle(process_information.hProcess, 10_000);
        CloseHandle(process_information.hThread).context("closing the target thread handle")?;
        CloseHandle(process_information.hProcess).context("closing the target process handle")?;
        ensure!(
            input_idle != WAIT_FAILED,
            "waiting for the target process to initialize"
        );
    }

    Ok(process_information.dwProcessId)
}

fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn current_process_is_elevated() -> anyhow::Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("opening the current process token")?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token).context("closing the current process token")?;
        result.context("querying the current process elevation")?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn find_enabled_sudo() -> anyhow::Result<Option<(PathBuf, WindowsSudoMode)>> {
    let Some(sudo) = find_executable_on_path("sudo.exe") else {
        return Ok(None);
    };
    let output = Command::new(&sudo)
        .arg("config")
        .output()
        .context("checking Windows sudo configuration")?;
    ensure!(
        output.status.success(),
        "Windows sudo configuration check failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mode = parse_windows_sudo_mode(&String::from_utf8_lossy(&output.stdout)).context(
        "Windows sudo returned an unrecognized configuration; run `sudo config` to inspect it",
    )?;
    Ok(Some((sudo, mode)))
}

fn parse_windows_sudo_mode(output: &str) -> Option<WindowsSudoMode> {
    let normalized = output.to_ascii_lowercase().replace([' ', '-'], "");
    if normalized.contains("forcenewwindow") {
        Some(WindowsSudoMode::ForceNewWindow)
    } else if normalized.contains("disableinput") || normalized.contains("inputclosed") {
        Some(WindowsSudoMode::DisableInput)
    } else if normalized.contains("inline") || normalized.contains("normal") {
        Some(WindowsSudoMode::Inline)
    } else {
        None
    }
}

fn resolve_ttd_exe(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return validate_ttd_exe(path);
    }
    if let Some(path) = env::var_os("TTD_EXE") {
        return validate_ttd_exe(Path::new(&path));
    }
    find_executable_on_path("ttd.exe").context(ttd_not_found_message())
}

fn ttd_not_found_message() -> &'static str {
    "could not find TTD.exe; install it with `winget install --id Microsoft.TimeTravelDebugging`, then open a new elevated terminal. Alternatively, add it to PATH, set TTD_EXE, or pass --ttd-exe"
}

fn validate_ttd_exe(path: &Path) -> anyhow::Result<PathBuf> {
    ensure!(
        path.is_file(),
        "TTD recorder executable does not exist: {}",
        path.display()
    );
    Ok(path.to_path_buf())
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn trace_artifact_paths(output: &Path) -> Vec<PathBuf> {
    let mut artifacts = vec![output.to_path_buf()];
    let sidecar = output.with_extension("out");
    if sidecar.exists() {
        artifacts.push(sidecar);
    }
    let index = output.with_extension("idx");
    if index.exists() {
        artifacts.push(index);
    }
    artifacts
}

pub(super) fn run_dump_create(args: DumpCreateArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let result = write_process_dump(ProcessDumpOptions {
        process_id: args.process_id,
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        write: DumpWriteOptions {
            path: args.output,
            kind: cli_dump_kind(args.kind),
            overwrite: args.overwrite,
        },
    })?;
    print_value(
        json!({
            "result": result,
            "session_persistence": "one_shot",
            "notes": [
                "DbgHelp writes the dump from a process handle using the Microsoft Debugging Platform runtime staged by cargo xtask deps."
            ]
        }),
        output,
    )
}

pub(super) fn run_dump_inspect(
    args: DumpInspectArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let inspected_address = args
        .inspect_address
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let tracker_table_base = args
        .tracker_table_base
        .as_deref()
        .map(parse_u64_argument)
        .transpose()?;
    let dump_metadata = fs::metadata(&args.path)
        .with_context(|| format!("reading dump metadata for {}", args.path.display()))?;
    let operation_started = Instant::now();
    let opened_at = Instant::now();
    let session = open_dump_session(DumpOpenOptions {
        path: args.path.clone(),
    })?;
    let open_elapsed_ms = opened_at.elapsed().as_millis() as u64;
    let target = session.summary();
    let modules_started = Instant::now();
    let modules = session.modules()?;
    let modules_elapsed_ms = modules_started.elapsed().as_millis() as u64;
    let bugcheck_started = Instant::now();
    let bugcheck = session.bugcheck_data();
    let bugcheck_elapsed_ms = bugcheck_started.elapsed().as_millis() as u64;
    let symbols_started = Instant::now();
    let native_symbols = prepare_dump_native_symbols(
        &session,
        &modules,
        &bugcheck,
        &args.symbol_cache,
        &args.image_path,
        args.offline,
    );
    let symbols_elapsed_ms = symbols_started.elapsed().as_millis() as u64;
    let threads_started = Instant::now();
    let threads = session.threads()?;
    let threads_elapsed_ms = threads_started.elapsed().as_millis() as u64;
    let registers_started = Instant::now();
    let registers = session.core_registers()?;
    let registers_elapsed_ms = registers_started.elapsed().as_millis() as u64;
    let stack_started = Instant::now();
    let stack = session.stack_trace_result(args.max_frames)?;
    let stack_elapsed_ms = stack_started.elapsed().as_millis() as u64;
    let triage_started = Instant::now();
    let triage = dump_triage_value(
        &session,
        DumpTriageInput {
            target: &target,
            modules: &modules,
            bugcheck: &bugcheck,
            current_stack: &stack,
            max_frames: args.max_frames,
            refresh_symbols: args.refresh_symbols,
            native_symbols,
            inspected_address,
            tracker_table_base,
        },
    );
    let triage_elapsed_ms = triage_started.elapsed().as_millis() as u64;
    print_value(
        json!({
            "triage_profile": "bounded_pool_corruption",
            "target": target,
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
                    "stack_frame_limit": args.max_frames,
                    "whole_dump_scan": false,
                },
            },
        }),
        output,
    )
}

fn prepare_dump_native_symbols(
    session: &DebuggerSession,
    _modules: &[ModuleInfo],
    bugcheck: &windbg_dbgeng::BugCheckDataResult,
    cache_dir: &Path,
    extra_image_paths: &[PathBuf],
    offline: bool,
) -> Value {
    let fault_address = bugcheck
        .data
        .as_ref()
        .and_then(dump_fault_address)
        .or_else(|| {
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
    current_stack: &'a windbg_dbgeng::StackTraceResult,
    max_frames: u32,
    refresh_symbols: bool,
    native_symbols: Value,
    inspected_address: Option<u64>,
    tracker_table_base: Option<u64>,
}

fn dump_triage_value(session: &DebuggerSession, input: DumpTriageInput<'_>) -> Value {
    let bugcheck_data = input.bugcheck.data.as_ref();
    let fault_address = bugcheck_data.and_then(dump_fault_address);
    let fault = fault_address.map(|address| dump_address_observation(session, address, 8));
    let exception_context =
        dump_exception_context(session, input.target, bugcheck_data, input.max_frames);
    let symbol_modules = dump_symbol_modules(session, fault_address, &exception_context);
    let symbol_readiness = dump_symbol_readiness(session, &symbol_modules, input.refresh_symbols);
    let driver_evidence = dump_driver_evidence(
        session,
        input.modules,
        fault_address,
        input.current_stack,
        &exception_context,
    );
    let pool_tracker = dump_pool_tracker_observation(
        session,
        &exception_context,
        &fault,
        input.tracker_table_base,
    );
    let address_inspection = input
        .inspected_address
        .map(|address| dump_address_inspection(session, address, input.tracker_table_base));
    let bugcheck_driver = dump_bugcheck_driver(session);
    let evidence = dump_evidence_grades(&driver_evidence, &pool_tracker, &bugcheck_driver);

    json!({
        "bugcheck": dump_bugcheck_value(input.bugcheck),
        "fault": fault,
        "exception_context": exception_context,
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
        "recommendations": dump_recommendations(input.bugcheck),
    })
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
    let entry_index = entry_address
        .zip(supplied_table_base)
        .and_then(|(entry, base)| entry.checked_sub(base))
        .filter(|offset| offset % entry_stride == 0)
        .map(|offset| offset / entry_stride)
        .filter(|index| *index < table_size);
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
        let fault_index_record = entry_index.and_then(|index| {
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
            "fault_index": entry_index,
            "fault_index_entry": fault_index_record,
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
        "crash_cpu_correlation": {
            "status": "unavailable",
            "detail": "The saved bugcheck CONTEXT and faulting stack do not carry a documented processor-slot identifier exposed by this dump path. Membership in a supplied slot-19 table validates the table relation, not the faulting CPU identity."
        },
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
    let external_driver_grade =
        if driver_evidence["status"].as_str() == Some("direct_evidence_present") {
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
                "topic": "third_party_driver_causation",
                "grade": external_driver_grade,
                "detail": "Loaded modules are inventory only. Attribution requires a fault, validated stack, or populated bugcheck-driver observation.",
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
        exception_context
            .as_ref()
            .and_then(|context| context["context"]["registers"]["rip"].as_u64()),
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

fn cli_dump_kind(kind: CliDumpKind) -> DumpKind {
    match kind {
        CliDumpKind::Mini => DumpKind::Mini,
        CliDumpKind::Full => DumpKind::Full,
    }
}

pub(super) fn live_capabilities() -> Value {
    json!({
        "backend_contract": capability_contract("dbgeng_live"),
        "implemented": [
            "dbgeng server",
            "live launch --command-line <cmd> --end detach|terminate",
            "live startup-break --command-line <cmd> --initial-break|--address <addr>|--module <name> --module-offset <rva>|--symbol <expr>",
            "live startup-profile --command-line <cmd> [--runs <count>] [--phase-module <basename>] [--completion-module <basename> [--settle-ms <milliseconds>]]",
            "live startup-report <artifact> [--run <number>] [--format table|json]",
            "live start --command-line <cmd>",
            "live attach --process-id <pid>",
            "dump create --process-id <pid> --output <path>",
            "dump inspect <path>",
            "dump triage <path>",
            "dump pool-triage <path>",
            "target dump --target <id> --output <path>",
            "target list/status/wait/continue/continue-wait/step/step-over for live targets",
            "target threads/modules/registers/memory/stack/disasm/symbol/source for live targets"
        ],
        "partial": [
            {
                "feature": "live launch",
                "status": "one_shot_initial_event",
                "notes": "Launches under DbgEng, waits for the initial event, reports execution status, then detaches or terminates."
            },
            {
                "feature": "startup breakpoint workflow",
                "status": "one_shot_structured_context",
                "notes": "Launches at the initial break, sets an absolute, module-RVA, or deferred symbol-expression code breakpoint, then reports bounded hit evidence, thread/IP/module/register/stack context."
            },
            {
                "feature": "startup profile workflow",
                "status": "non_invasive_bounded_lifecycle_collection",
                "notes": "Launches at a create-process event, configures DbgEng lifecycle event filters only, and reports host-monotonic wall-time observations. A requested completion module can stop at an observed image load or after a bounded observed lifecycle-quiet interval. It sets no software/hardware breakpoint, opens no DAC, and performs no target-memory operation."
            },
            {
                "feature": "startup profile artifact report",
                "status": "offline_bounded_module_timeline",
                "notes": "Reads one explicit live startup-profile JSON artifact up to 16 MiB and renders a bounded table or structured report. It does not launch, attach, query, or modify DbgEng or a target."
            },
            {
                "feature": "managed method breakpoint workflow",
                "status": "x64_coreclr_dac_vertical_slice",
                "notes": "Uses a matching CoreCLR DAC through the active DbgEng client, resolves a metadata method by name and optional exact signature, requests CLR code generation, and then sets a DbgEng software code breakpoint. CLR notification writes require --allow-runtime-write and an approved test VM."
            },
            {
                "feature": "dump creation",
                "status": "dbghelp_minidump_writer",
                "notes": "Creates mini or full process dumps through DbgHelp from the Microsoft Debugging Platform runtime, either one-shot from a process id or from a daemon-owned live target."
            },
            {
                "feature": "daemon-backed live sessions",
                "status": "persistent_core_control",
                "notes": "Daemon-owned live targets cover launch, attach, status, event wait, continue, bounded continue-and-wait with optional debuggee output capture, step-into, step-over, modules, threads, registers, memory, stack, symbol/source lookup, disassembly, and breakpoints."
            }
        ],
        "gaps": [
            "step-out control",
            "module/symbol reload management",
            "event callbacks",
            "continuous debugger output/event streaming"
        ],
        "safety": [
            "Live debugging mutates target execution state.",
            "Commands that launch or attach are explicit and are not hidden behind read-only names."
        ]
    })
}

pub(super) fn breakpoint_capabilities() -> Value {
    json!({
        "backend_contracts": [
            capability_contract("ttd_cursor"),
            capability_contract("dbgeng_live")
        ],
        "implemented": [
            "memory watchpoint",
            "replay watch-memory",
            "sweep watch-memory",
            "breakpoint list --target <id>",
            "breakpoint set --target <id> --address <addr>|--symbol <expr>",
            "breakpoint enable/disable --target <id> --breakpoint-id <id>",
            "breakpoint remove --target <id> --breakpoint-id <id>"
        ],
        "partial": [
            {
                "feature": "TTD multi-hit memory watchpoint sweeps",
                "status": "bounded_foreground_sweep",
                "command": "sweep watch-memory",
                "bounds": ["--max-hits"],
                "notes": "Collects repeated first-hit memory watchpoints by advancing the cursor one step after each hit."
            },
            {
                "feature": "live breakpoint manager",
                "status": "core_code_data_and_deferred_symbol_breakpoints",
                "commands": [
                    "breakpoint list",
                    "breakpoint set",
                    "breakpoint enable",
                    "breakpoint disable",
                    "breakpoint remove"
                ],
                "notes": "Live DbgEng targets support absolute code breakpoints, deferred code symbol expressions, data breakpoints with read/write/execute access masks, and explicit enablement changes."
            }
        ],
        "gaps": [
            "source breakpoints",
            "position watchpoints",
            "call/return trace jobs",
            "conditional/logging breakpoint actions"
        ],
        "safe_next_steps": [
            "Use memory watchpoint for one hit.",
            "Use sweep watch-memory for bounded repeated TTD data-access hits.",
            "Use target status and target wait to inspect live targets around breakpoint hits."
        ]
    })
}

pub(super) fn datamodel_capabilities() -> Value {
    json!({
        "target_backend_contracts": [
            capability_contract("dbgeng_live"),
            capability_contract("dbgeng_dump")
        ],
        "implemented": [
            "structured JSON command output",
            "discover.command_metadata",
            "recipes",
            "context snapshot",
            "architecture state",
            "datamodel eval --target <id> --expression <expr>"
        ],
        "partial": [
            {
                "feature": "DbgEng expression evaluation",
                "status": "scalar_expression_bridge",
                "notes": "Daemon-owned live and dump targets can evaluate basic DbgEng expressions and return structured scalar results."
            },
            {
                "feature": "data-model-like discovery",
                "status": "JSON manifests and command metadata",
                "notes": "Commands expose stable structured data, but do not yet bridge full DbgEng dx or TargetModel object graphs."
            }
        ],
        "gaps": [
            "DbgEng dx expression evaluation",
            "Debugger data model object projection",
            "Microsoft.Debugging.TargetModel.SDK component hosting",
            "dx object expansion and formatting",
            "data-model-aware synthetic providers"
        ],
        "recommended_abstractions": [
            "memory",
            "registers",
            "modules",
            "symbols",
            "threads",
            "events",
            "stack",
            "disassembly",
            "breakpoints"
        ]
    })
}

pub(super) fn run_windbg_command(
    command: WindbgCommand,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    match command {
        WindbgCommand::Status(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.status(true)?)?, output)
        }
        WindbgCommand::Install(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.install(args.force)?)?, output)
        }
        WindbgCommand::Update(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.update()?)?, output)
        }
        WindbgCommand::Path(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(json!({ "dbgx_path": manager.dbgx_path()? }), output)
        }
        WindbgCommand::Run(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            let installed = manager.install(false)?;
            let status = Command::new(&installed.dbgx_path)
                .args(&args.args)
                .status()
                .with_context(|| format!("launching {}", installed.dbgx_path.display()))?;
            print_value(
                json!({
                    "dbgx_path": installed.dbgx_path,
                    "success": status.success(),
                    "exit_code": status.code(),
                }),
                output,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn record_args(output: PathBuf) -> TraceRecordArgs {
        TraceRecordArgs {
            output,
            command_line: r#""C:\Program Files\App\app.exe" --flag "two words""#.to_string(),
            ttd_exe: Some(env::current_exe().unwrap()),
            children: true,
            modules: vec![
                "RemoteDesktopManager_x64.exe".to_string(),
                "coreclr.dll".to_string(),
            ],
            max_file_mb: Some(128),
            ring: true,
            replay_cpu_support: Some(TraceReplayCpuSupport::MostAggressive),
            num_vcpu: Some(16),
            profile: None,
            record_for_seconds: None,
            disable_user_shadow_stack: false,
        }
    }

    fn test_directory() -> PathBuf {
        env::temp_dir().join(format!(
            "windbg-tool-record-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn trace_record_plan_uses_documented_ttd_arguments() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");

        let plan = trace_record_plan(&record_args(output.clone())).unwrap();

        assert_eq!(plan.output, output);
        assert_eq!(
            plan.recorder_args,
            vec![
                "-noUI",
                "-out",
                output.to_string_lossy().as_ref(),
                "-accepteula",
                "-children",
                "-module",
                "RemoteDesktopManager_x64.exe",
                "-module",
                "coreclr.dll",
                "-maxFile",
                "128",
                "-ring",
                "-replayCpuSupport",
                "MostAggressive",
                "-numVCpu",
                "16",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert_eq!(plan.command_line, record_args(output).command_line);

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_existing_or_non_run_output() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let existing = temp.join("capture.run");
        fs::write(&existing, []).unwrap();
        assert!(trace_record_plan(&record_args(existing)).is_err());
        assert!(trace_record_plan(&record_args(temp.join("capture.ttd"))).is_err());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_profiles_resolve_bounded_capture_settings() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.children = false;
        args.modules.clear();
        args.max_file_mb = None;
        args.ring = false;
        args.replay_cpu_support = None;
        args.num_vcpu = None;
        args.profile = Some(TraceRecordProfile::Startup);

        let startup = trace_record_plan(&args).unwrap();
        assert_eq!(startup.capture.max_file_mb, Some(1024));
        assert!(!startup.capture.ring);
        assert_eq!(startup.capture.profile, Some(TraceRecordProfile::Startup));

        args.profile = Some(TraceRecordProfile::Recent);
        let recent = trace_record_plan(&args).unwrap();
        assert_eq!(recent.capture.max_file_mb, Some(2048));
        assert!(recent.capture.ring);

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_module_paths_and_zero_vcpus() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.modules = vec![r"C:\Windows\System32\kernel32.dll".to_string()];
        assert!(trace_record_plan(&args).is_err());

        args.modules = vec!["kernel32.dll".to_string()];
        args.num_vcpu = Some(0);
        assert!(trace_record_plan(&args).is_err());

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_unbounded_profile_conflicts_and_invalid_duration() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.profile = Some(TraceRecordProfile::Startup);
        assert!(trace_record_plan(&args).is_err());

        args.profile = None;
        args.max_file_mb = None;
        args.ring = false;
        args.record_for_seconds = Some(0);
        assert!(trace_record_plan(&args).is_err());

        args.record_for_seconds = Some(10);
        assert!(trace_record_plan(&args).is_err());

        args.disable_user_shadow_stack = true;
        assert_eq!(
            trace_record_plan(&args).unwrap().capture.record_for_seconds,
            Some(10)
        );

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn ttd_sidecar_parser_extracts_recording_summary() {
        let summary = parse_ttd_sidecar(
            "Allocated processors:55, running threads:16.\n\
             RecordingEngine initialization successful.\n\
             Tracing started at: Thu Jul  9 20:04:35 2026 (UTC)\n\
             Simulation time of '' (x64): 188031ms.\n\
             Tracing completed at: Thu Jul  9 20:07:43 2026 (UTC)\n\
             Trace dumped to C:\\trace\\capture.run\n",
        );

        assert_eq!(
            summary,
            TtdSidecarSummary {
                allocated_vcpus: Some(55),
                running_threads: Some(16),
                simulation_duration_ms: Some(188031),
                recording_engine_initialized: true,
                tracing_started: true,
                tracing_completed: true,
                trace_dumped: true,
            }
        );
    }

    #[test]
    fn ttd_stop_command_uses_the_target_process_id() {
        let command = command_from_ttd_stop(
            Path::new(r"C:\tools\TTD.exe"),
            &TraceRecordLauncher::Direct,
            4242,
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            command.get_program(),
            Path::new(r"C:\tools\TTD.exe").as_os_str()
        );
        assert_eq!(arguments, ["-accepteula", "-stop", "4242"]);
    }

    #[test]
    fn sudo_launcher_wraps_ttd_and_preserves_working_directory() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let plan = trace_record_plan(&record_args(temp.join("capture.run"))).unwrap();
        let launcher = TraceRecordLauncher::Sudo {
            executable: PathBuf::from(r"C:\Windows\System32\sudo.exe"),
            working_directory: PathBuf::from(r"D:\work"),
            mode: WindowsSudoMode::DisableInput,
        };

        let command = command_from_trace_record_plan(&plan, &launcher);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            command.get_program(),
            Path::new(r"C:\Windows\System32\sudo.exe").as_os_str()
        );
        assert_eq!(
            arguments[..6],
            [
                "--preserve-env",
                "--chdir",
                r"D:\work",
                "--disable-input",
                plan.ttd_exe.to_string_lossy().as_ref(),
                "-noUI",
            ]
        );
        assert_eq!(launcher.name(), "windows_sudo_disable_input");

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn cet_compatibility_mode_records_by_target_attach() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let mut plan = trace_record_plan(&record_args(temp.join("capture.run"))).unwrap();
        plan.target = TraceRecordTarget::Attach { process_id: 4242 };

        let command = command_from_trace_record_plan(&plan, &TraceRecordLauncher::Direct);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(arguments[arguments.len() - 2..], ["-attach", "4242"]);
        assert_eq!(plan.target.name(), "attach_after_cet_disabled_launch");
        assert_eq!(plan.target.process_id(), Some(4242));

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn parses_windows_sudo_modes() {
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Force New Window mode"),
            Some(WindowsSudoMode::ForceNewWindow)
        );
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Input Closed mode"),
            Some(WindowsSudoMode::DisableInput)
        );
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Inline mode"),
            Some(WindowsSudoMode::Inline)
        );
    }

    #[test]
    fn ttd_not_found_message_includes_official_install_command() {
        assert!(
            ttd_not_found_message().contains("winget install --id Microsoft.TimeTravelDebugging")
        );
    }

    #[test]
    fn matches_loaded_module_by_basename_or_full_path() {
        let modules = [ModuleInfo {
            base_address: 0x140000000,
            module_name: Some("RemoteDesktopManager_x64".to_string()),
            image_name: Some(
                r"C:\Temp\windbg-tool-ttd\rdm\RemoteDesktopManager_x64.exe".to_string(),
            ),
            loaded_image_name: None,
            symbol_file: None,
        }];

        assert_eq!(
            find_loaded_module(&modules, "remotedesktopmanager_x64.exe")
                .unwrap()
                .base_address,
            0x140000000
        );
        assert_eq!(
            find_loaded_module(
                &modules,
                r"C:\Temp\windbg-tool-ttd\rdm\RemoteDesktopManager_x64.exe"
            )
            .unwrap()
            .base_address,
            0x140000000
        );
    }

    #[test]
    fn parses_decimal_and_hexadecimal_breakpoint_addresses() {
        assert_eq!(parse_debug_address("0x140001000").unwrap(), 0x140001000);
        assert_eq!(parse_debug_address("4096").unwrap(), 4096);
        assert!(parse_debug_address("not-an-address").is_err());
    }

    #[test]
    fn startup_breakpoint_requires_exactly_one_location_kind() {
        let args = LiveStartupBreakArgs {
            command_line: "target.exe".to_string(),
            initial_break: false,
            hardware_execute: false,
            address: Some("0x140001000".to_string()),
            module: Some("target.exe".to_string()),
            module_offset: Some("0x1000".to_string()),
            symbol: None,
            wait_for_module: None,
            initial_break_timeout_ms: 5000,
            wait_timeout_ms: 10000,
            max_frames: 16,
            end: "terminate".to_string(),
        };
        assert!(startup_breakpoint_spec(&args).is_err());

        let symbol_args = LiveStartupBreakArgs {
            initial_break: false,
            address: None,
            module: None,
            module_offset: None,
            symbol: Some("target!entry".to_string()),
            ..args
        };
        assert_eq!(
            startup_breakpoint_spec(&symbol_args).unwrap(),
            StartupBreakpointSpec::Symbol {
                expression: "target!entry".to_string()
            }
        );

        let initial_break_args = LiveStartupBreakArgs {
            initial_break: true,
            symbol: None,
            ..symbol_args
        };
        assert_eq!(
            startup_breakpoint_spec(&initial_break_args).unwrap(),
            StartupBreakpointSpec::InitialBreak
        );
        assert!(
            validate_startup_breakpoint_mode(true, &StartupBreakpointSpec::InitialBreak).is_err()
        );
        assert!(validate_startup_breakpoint_mode(
            true,
            &StartupBreakpointSpec::Address {
                address: 0x140001000
            }
        )
        .is_ok());
    }

    #[test]
    fn validates_managed_breakpoint_metadata_tokens() {
        assert_eq!(
            validate_managed_breakpoint_token(
                "Devolutions.RemoteDesktopManager.Program.Main",
                "--method"
            )
            .unwrap(),
            "Devolutions.RemoteDesktopManager.Program.Main"
        );
        assert_eq!(
            validate_managed_breakpoint_token("Outer+Inner.Method`1", "--method").unwrap(),
            "Outer+Inner.Method`1"
        );
        assert!(validate_managed_breakpoint_token("Program.Main;qd", "--method").is_err());
        assert!(validate_managed_breakpoint_token(r#"Program.Main""#, "--method").is_err());
    }

    #[test]
    fn parses_exact_managed_method_signature_bytes() {
        assert_eq!(
            parse_managed_method_signature(Some("00-01:0E 0e")).unwrap(),
            Some(vec![0x00, 0x01, 0x0e, 0x0e])
        );
        assert_eq!(
            format_managed_method_signature(&[0x00, 0x01, 0x0e, 0x0e]),
            "00010E0E"
        );
        assert_eq!(parse_managed_method_signature(None).unwrap(), None);
        assert!(parse_managed_method_signature(Some("")).is_err());
        assert!(parse_managed_method_signature(Some("001")).is_err());
        assert!(parse_managed_method_signature(Some("00zz")).is_err());
        assert!(parse_managed_method_signature(Some(&"AA".repeat(512))).is_err());
    }

    #[test]
    fn validates_managed_module_basename() {
        assert_eq!(
            validate_managed_module("RemoteDesktopManager.dll").unwrap(),
            "RemoteDesktopManager.dll"
        );
        assert!(validate_managed_module("RemoteDesktopManager").is_err());
        assert!(validate_managed_module(r#"RemoteDesktopManager.dll;qd"#).is_err());
    }

    fn startup_profile_event_for_test(
        index: usize,
        kind: &str,
        observed_elapsed_ms: u64,
        resumed_wall_elapsed_ms: u64,
        module: Option<&str>,
    ) -> StartupProfileEvent {
        StartupProfileEvent {
            index,
            kind: kind.to_string(),
            observed_elapsed_ms,
            resumed_wall_elapsed_ms,
            event: windbg_dbgeng::DebuggerEventInfo {
                event_type: 0,
                event_name: kind.to_string(),
                process_system_id: 1,
                thread_system_id: 2,
                description: None,
                extra_information_size: 0,
                breakpoint_id: None,
                exception: None,
                module_base: module.map(|_| 0x1000),
                exit_code: None,
            },
            module: module.map(|basename| StartupProfileModule {
                base_address: "0x1000".to_string(),
                basename: Some(basename.to_string()),
                module_name: Some(basename.to_string()),
                image_path: Some(format!("C:/fixture/{basename}")),
            }),
            loaded_module_count: None,
            live_thread_count: None,
            context: json!({
                "status": "not_requested",
                "detail": "test"
            }),
            thread_accounting: json!({
                "status": "not_requested",
                "detail": "test"
            }),
        }
    }

    #[test]
    fn startup_profile_derives_only_observed_lifecycle_phases() {
        let timeline = vec![
            startup_profile_event_for_test(0, "create_process", 12, 0, None),
            startup_profile_event_for_test(1, "load_module", 20, 5, Some("coreclr.dll")),
            startup_profile_event_for_test(
                2,
                "load_module",
                30,
                15,
                Some("RemoteDesktopManager.dll"),
            ),
            startup_profile_event_for_test(3, "exit_process", 40, 35, None),
        ];

        let phases = derive_startup_profile_phases(&timeline, Some("RemoteDesktopManager.dll"));

        assert_eq!(phases[0].elapsed_ms, Some(12));
        assert_eq!(phases[1].elapsed_ms, Some(5));
        assert_eq!(phases[2].elapsed_ms, Some(10));
        assert_eq!(phases[3].elapsed_ms, Some(20));
        assert_eq!(phases[4].elapsed_ms, Some(35));

        let missing = derive_startup_profile_phases(&timeline[..2], Some("app.dll"));
        assert_eq!(missing[2].status, "unavailable");
        assert_eq!(missing[2].elapsed_ms, None);
        assert_eq!(missing[3].elapsed_ms, None);
        assert_eq!(missing[4].elapsed_ms, None);
    }

    fn startup_profile_run_for_test(run: u32, phase_values: &[u64]) -> StartupProfileRun {
        StartupProfileRun {
            run,
            status: "completed".to_string(),
            finish_reason: "exit_process".to_string(),
            target: windbg_dbgeng::DebuggerSessionSummary {
                kind: windbg_dbgeng::DebuggerSessionKind::Live,
                target: "fixture.exe".to_string(),
                process_id: Some(run),
                dump_path: None,
                processor_type: Some(0x8664),
                processor_name: Some("AMD64".to_string()),
                execution_status: windbg_dbgeng::DebuggerExecutionStatus {
                    raw: Some(0),
                    name: Some("break".to_string()),
                },
                symbol_path: "srv*cache*https://msdl.microsoft.com/download/symbols".to_string(),
                runtime: windbg_dbgeng::DbgEngRuntime {
                    source: "test_fixture".to_string(),
                    directory: None,
                    architecture: Some("x64".to_string()),
                    components: Vec::new(),
                    compatible: true,
                },
            },
            timing: json!({}),
            event_filters: json!({}),
            timeline: Vec::new(),
            phase_durations: phase_values
                .iter()
                .map(|elapsed_ms| StartupProfilePhase {
                    name: "create_process_to_exit_process".to_string(),
                    status: "observed".to_string(),
                    elapsed_ms: Some(*elapsed_ms),
                    start_event_index: Some(0),
                    end_event_index: Some(1),
                    detail: "test".to_string(),
                })
                .collect(),
            completion: StartupProfileCompletion {
                requested_module: None,
                settle_ms: None,
                status: "not_requested".to_string(),
                module_load: None,
                quiet_resumed_elapsed_ms: None,
                detail: "test".to_string(),
            },
            lifecycle_summary: json!({}),
            debuggee_output: json!({
                "status": "not_requested",
                "source": "dbgeng_output_callback",
                "records": [],
                "records_returned": 0,
                "dropped_record_count": 0,
                "dropped_text_char_count": 0,
                "detail": "test"
            }),
            module_provenance: json!({
                "status": "not_requested",
                "source": "host_file_metadata",
                "records": [],
                "detail": "test"
            }),
            dbgeng_module_parameters: json!({
                "status": "not_requested",
                "source": "dbgeng_idebugsymbols5_getmoduleparameters",
                "records": [],
                "detail": "test"
            }),
            largest_observed_gaps: Vec::new(),
            gaps_excluded_from_ranking: Vec::new(),
            counts: json!({}),
            coverage: json!({}),
            cleanup: json!({}),
        }
    }

    #[test]
    fn startup_profile_aggregate_reports_wall_time_median_without_regression_claim() {
        let mut runs = [
            startup_profile_run_for_test(1, &[10]),
            startup_profile_run_for_test(2, &[30]),
            startup_profile_run_for_test(3, &[20]),
        ];
        let gap_timeline = vec![
            startup_profile_event_for_test(0, "create_process", 0, 0, None),
            startup_profile_event_for_test(1, "load_module", 10, 10, Some("coreclr.dll")),
            startup_profile_event_for_test(2, "create_thread", 40, 40, None),
        ];
        let gaps = rank_startup_profile_observed_gaps(&gap_timeline, None).0;
        for run in &mut runs {
            run.largest_observed_gaps = gaps.clone();
        }

        let aggregate = startup_profile_aggregate(&runs);
        let phase = &aggregate["phase_wall_time_ms"][0];

        assert_eq!(aggregate["completed_run_count"], 3);
        assert_eq!(phase["sample_count"], 3);
        assert_eq!(phase["min_ms"], 10);
        assert_eq!(phase["median_ms"], 20.0);
        assert_eq!(phase["max_ms"], 30);
        assert_eq!(phase["regression_assessment"]["status"], "no_baseline");
        assert_eq!(
            aggregate["largest_observed_inter_event_gap_wall_time_ms"]["sample_count"],
            3
        );
        assert_eq!(
            aggregate["largest_observed_inter_event_gap_wall_time_ms"]["median_ms"],
            30.0
        );
    }

    #[test]
    fn startup_profile_aggregate_samples_one_largest_gap_per_run() {
        let mut run = startup_profile_run_for_test(1, &[10]);
        run.phase_durations.push(StartupProfilePhase {
            name: "coreclr_load_to_selected_module_load".to_string(),
            status: "observed".to_string(),
            elapsed_ms: Some(5),
            start_event_index: Some(1),
            end_event_index: Some(2),
            detail: "test".to_string(),
        });
        let timeline = vec![
            startup_profile_event_for_test(0, "create_process", 0, 0, None),
            startup_profile_event_for_test(1, "load_module", 10, 10, Some("coreclr.dll")),
        ];
        run.largest_observed_gaps = rank_startup_profile_observed_gaps(&timeline, None).0;

        let aggregate = startup_profile_aggregate(&[run]);

        assert_eq!(
            aggregate["largest_observed_inter_event_gap_wall_time_ms"]["sample_count"],
            1
        );
    }

    #[test]
    fn startup_profile_module_paths_are_normalized_for_output() {
        let module = normalize_startup_profile_module(ModuleInfo {
            base_address: 0x140000000,
            module_name: Some("fixture".to_string()),
            image_name: None,
            loaded_image_name: Some(r"C:\fixture\bin\fixture.dll".to_string()),
            symbol_file: None,
        });

        assert_eq!(module.basename.as_deref(), Some("fixture.dll"));
        assert_eq!(
            module.image_path.as_deref(),
            Some("C:/fixture/bin/fixture.dll")
        );
        assert!(startup_profile_module_name_matches(
            "coreclr",
            "coreclr.dll"
        ));
        assert!(startup_profile_module_name_matches(
            "ManagedBreakpointFixture",
            "ManagedBreakpointFixture.dll"
        ));
    }

    #[test]
    fn startup_profile_recognizes_dbgeng_no_event_sentinel() {
        let sentinel = windbg_dbgeng::DebuggerEventInfo {
            event_type: 0,
            event_name: "unknown".to_string(),
            process_system_id: u32::MAX,
            thread_system_id: u32::MAX,
            description: None,
            extra_information_size: 0,
            breakpoint_id: None,
            exception: None,
            module_base: None,
            exit_code: None,
        };

        assert!(startup_profile_no_event_sentinel(&sentinel));

        let real_event = windbg_dbgeng::DebuggerEventInfo {
            event_name: "create_thread".to_string(),
            ..sentinel
        };
        assert!(!startup_profile_no_event_sentinel(&real_event));
    }

    #[test]
    fn startup_profile_lifecycle_summary_classifies_runtime_and_selected_modules() {
        let mut exception = startup_profile_event_for_test(5, "exception", 100, 100, None);
        exception.event.exception = Some(windbg_dbgeng::DebuggerExceptionInfo {
            code: 0xc000_0005,
            flags: 0,
            address: 0x1234,
            first_chance: true,
            parameters: vec![],
        });
        let timeline = vec![
            startup_profile_event_for_test(0, "create_process", 5, 0, None),
            startup_profile_event_for_test(1, "load_module", 10, 5, Some("hostfxr.dll")),
            startup_profile_event_for_test(2, "load_module", 15, 10, Some("coreclr.dll")),
            startup_profile_event_for_test(
                3,
                "load_module",
                20,
                15,
                Some("RemoteDesktopManager.dll"),
            ),
            startup_profile_event_for_test(4, "create_thread", 25, 20, None),
            exception,
        ];
        let completion = StartupProfileCompletion {
            requested_module: Some("RemoteDesktopManager.dll".to_string()),
            settle_ms: Some(500),
            status: "waiting_for_quiet_interval".to_string(),
            module_load: Some(startup_profile_event_reference(&timeline[3])),
            quiet_resumed_elapsed_ms: None,
            detail: "test".to_string(),
        };

        let summary = startup_profile_lifecycle_summary(
            &timeline,
            Some("RemoteDesktopManager.dll"),
            &completion,
            &json!({
                "status": "not_requested",
                "records_returned": 0,
                "dropped_record_count": 0,
                "detail": "test"
            }),
        );

        assert_eq!(
            summary["modules"]["first_coreclr_load"]["module"]["basename"],
            "coreclr.dll"
        );
        assert_eq!(
            summary["modules"]["first_selected_phase_module_load"]["module"]["basename"],
            "RemoteDesktopManager.dll"
        );
        assert_eq!(
            summary["modules"]["runtime_loader_first_seen"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(summary["threads"]["first_start"]["index"], 4);
        assert_eq!(
            summary["exceptions"]["first"]["exception_code"],
            "0xC0000005"
        );
        assert_eq!(summary["debuggee_output"]["status"], "not_requested");
    }

    #[test]
    fn startup_profile_output_records_reference_the_latest_lifecycle_event() {
        let timeline = vec![
            startup_profile_event_for_test(0, "create_process", 5, 0, None),
            startup_profile_event_for_test(1, "load_module", 12, 7, Some("coreclr.dll")),
        ];
        let output = startup_profile_debuggee_output(
            windbg_dbgeng::DebuggerOutputCaptureResult {
                status: "captured".to_string(),
                source: "dbgeng_output_callback".to_string(),
                records: vec![windbg_dbgeng::DebuggerOutputRecord {
                    elapsed_ms: 13,
                    preceding_event_index: Some(1),
                    mask: 0x80,
                    categories: vec!["debuggee".to_string()],
                    text: "fixture-output".to_string(),
                    text_truncated: false,
                }],
                records_returned: 1,
                dropped_record_count: 0,
                dropped_text_char_count: 0,
                max_records: 4,
                max_chars_per_record: 64,
                max_total_chars: 128,
                detail: "test".to_string(),
            },
            &timeline,
        );

        assert_eq!(output["records_returned"], 1);
        assert_eq!(output["records"][0]["text"], "fixture-output");
        assert_eq!(
            output["records"][0]["preceding_event"]["module"]["basename"],
            "coreclr.dll"
        );
    }

    #[test]
    fn startup_profile_comparator_reports_wall_time_and_sequence_differences() {
        let baseline = json!({
            "status": "completed",
            "run": 1,
            "phase_durations": [{
                "name": "create_process_to_coreclr_load",
                "status": "observed",
                "elapsed_ms": 10
            }],
            "largest_observed_gaps": [{ "elapsed_ms": 7 }],
            "timeline": [
                { "kind": "create_process", "module": null, "event": { "exception": null } },
                { "kind": "load_module", "module": { "basename": "coreclr.dll" }, "event": { "exception": null } }
            ],
            "coverage": { "timeline_truncated": false }
        });
        let candidate = json!({
            "status": "completed",
            "run": 1,
            "phase_durations": [{
                "name": "create_process_to_coreclr_load",
                "status": "observed",
                "elapsed_ms": 15
            }],
            "largest_observed_gaps": [{ "elapsed_ms": 9 }],
            "timeline": [
                { "kind": "create_process", "module": null, "event": { "exception": null } },
                { "kind": "load_module", "module": { "basename": "hostfxr.dll" }, "event": { "exception": null } }
            ],
            "coverage": { "timeline_truncated": false }
        });
        let baseline_runs = [&baseline];
        let candidate_runs = [&candidate];

        let phases = startup_profile_compare_phase_distributions(&baseline_runs, &candidate_runs);
        let sequence = startup_profile_compare_sequences(&baseline_runs, &candidate_runs, 8);

        assert_eq!(phases[0]["candidate_minus_baseline_median_ms"], json!(5.0));
        assert_eq!(sequence["divergent_pair_count"], 1);
        assert_eq!(sequence["pairs"][0]["first_divergence"]["index"], 1);
        assert_eq!(
            sequence["pairs"][0]["first_divergence"]["candidate"]["module_basename"],
            "hostfxr.dll"
        );
    }

    #[test]
    fn startup_profile_report_preserves_first_seen_module_timing_and_enrichment() {
        let artifact = StartupProfileArtifact {
            summary: json!({
                "role": "test",
                "path": "C:/reports/fixture.json",
                "artifact_bytes": 1024
            }),
            value: json!({
                "workflow": "live_startup_profile",
                "measurement_semantics": {
                    "clock": "host_monotonic_instant"
                },
                "runs": [{
                    "run": 1,
                    "status": "completed",
                    "finish_reason": "exit_process",
                    "completion": {
                        "status": "not_requested"
                    },
                    "coverage": {
                        "phase_module": "RemoteDesktopManager.dll",
                        "timeline_events_returned": 6,
                        "timeline_event_limit": 16,
                        "timeline_truncated": false,
                        "event_limit_reached": false,
                        "truncation_behavior": "test"
                    },
                    "counts": {
                        "module_load_events": 4
                    },
                    "timeline": [
                        {
                            "index": 0,
                            "kind": "create_process",
                            "observed_elapsed_ms": 10,
                            "resumed_wall_elapsed_ms": 0,
                            "event": { "exit_code": null }
                        },
                        {
                            "index": 1,
                            "kind": "load_module",
                            "observed_elapsed_ms": 15,
                            "resumed_wall_elapsed_ms": 5,
                            "module": {
                                "basename": "ntdll.dll",
                                "module_name": "ntdll",
                                "image_path": "ntdll.dll",
                                "base_address": "0x100"
                            }
                        },
                        {
                            "index": 2,
                            "kind": "load_module",
                            "observed_elapsed_ms": 48,
                            "resumed_wall_elapsed_ms": 38,
                            "module": {
                                "basename": "coreclr.dll",
                                "module_name": "coreclr",
                                "image_path": "C:/dotnet/coreclr.dll",
                                "base_address": "0x200"
                            }
                        },
                        {
                            "index": 3,
                            "kind": "load_module",
                            "observed_elapsed_ms": 51,
                            "resumed_wall_elapsed_ms": 41,
                            "module": {
                                "basename": "coreclr.dll",
                                "module_name": "coreclr",
                                "image_path": "C:/dotnet/coreclr.dll",
                                "base_address": "0x200"
                            }
                        },
                        {
                            "index": 4,
                            "kind": "load_module",
                            "observed_elapsed_ms": 90,
                            "resumed_wall_elapsed_ms": 80,
                            "module": {
                                "basename": "RemoteDesktopManager.dll",
                                "module_name": "RemoteDesktopManager",
                                "image_path": "D:/RDM/RemoteDesktopManager/Program/RemoteDesktopManager.dll",
                                "base_address": "0x300"
                            }
                        },
                        {
                            "index": 5,
                            "kind": "exit_process",
                            "observed_elapsed_ms": 100,
                            "resumed_wall_elapsed_ms": 90,
                            "event": { "exit_code": 0 }
                        }
                    ],
                    "dbgeng_module_parameters": {
                        "source": "dbgeng_idebugsymbols5_getmoduleparameters",
                        "status": "captured",
                        "records": [{
                            "base_address": "0x200",
                            "parameters": {
                                "image_size": 4096,
                                "symbol_type_name": "pdb"
                            }
                        }]
                    },
                    "module_provenance": {
                        "source": "host_file_metadata",
                        "status": "captured",
                        "records": [{
                            "observed_image_path": "D:/RDM/RemoteDesktopManager/Program/RemoteDesktopManager.dll",
                            "status": "captured",
                            "metadata": { "file_size": 1024 }
                        }]
                    },
                    "lifecycle_summary": {
                        "modules": {
                            "first_coreclr_load": {
                                "kind": "load_module",
                                "resumed_wall_elapsed_ms": 38,
                                "module": { "basename": "coreclr.dll" }
                            },
                            "first_selected_phase_module_load": {
                                "kind": "load_module",
                                "resumed_wall_elapsed_ms": 80,
                                "module": { "basename": "RemoteDesktopManager.dll" }
                            }
                        }
                    },
                    "largest_observed_gaps": [{
                        "rank": 1,
                        "elapsed_ms": 42,
                        "start": {
                            "kind": "load_module",
                            "resumed_wall_elapsed_ms": 38,
                            "module": { "basename": "coreclr.dll" }
                        },
                        "end": {
                            "kind": "load_module",
                            "resumed_wall_elapsed_ms": 80,
                            "module": { "basename": "RemoteDesktopManager.dll" }
                        }
                    }]
                }]
            }),
        };
        let all_modules = startup_profile_module_report(
            &artifact,
            &StartupProfileReportFilters {
                run: 1,
                module_substring: None,
                runtime_only: false,
                rdm_only: false,
                min_resumed_ms: None,
                max_rows: 8,
            },
        )
        .unwrap();

        let rows = all_modules["module_timeline"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1]["module"]["basename"], "coreclr.dll");
        assert_eq!(
            rows[1]["delta_from_prior_first_module_load_resumed_wall_ms"],
            33
        );
        assert_eq!(rows[1]["image_size_bytes"], 4096);
        assert_eq!(rows[1]["symbol_readiness"]["symbol_type_name"], "pdb");
        assert_eq!(
            rows[2]["delta_from_prior_first_module_load_resumed_wall_ms"],
            42
        );
        assert_eq!(
            rows[2]["classification"],
            json!(["rdm_application_path", "selected_phase_module"])
        );
        assert_eq!(rows[2]["provenance"]["metadata"]["file_size"], 1024);
        assert_eq!(all_modules["run"]["process_exit"]["exit_code"], 0);

        let rdm_modules = startup_profile_module_report(
            &artifact,
            &StartupProfileReportFilters {
                run: 1,
                module_substring: None,
                runtime_only: false,
                rdm_only: true,
                min_resumed_ms: Some(50),
                max_rows: 1,
            },
        )
        .unwrap();
        assert_eq!(rdm_modules["module_timeline"]["matching_row_count"], 1);
        assert_eq!(rdm_modules["module_timeline"]["rows"][0]["ordinal"], 3);

        let table = startup_profile_module_report_table(&all_modules, 32, true);
        assert!(table.contains("Startup module timeline (offline artifact report)"));
        assert!(table.contains("coreclr.dll"));
        assert!(table.contains("Largest retained observed lifecycle gaps"));
    }

    #[test]
    fn startup_profile_ranks_only_full_filter_observed_gaps() {
        let timeline = vec![
            startup_profile_event_for_test(0, "create_process", 1, 0, None),
            startup_profile_event_for_test(1, "load_module", 11, 10, Some("coreclr.dll")),
            startup_profile_event_for_test(2, "create_thread", 61, 60, None),
            startup_profile_event_for_test(3, "exit_process", 161, 160, None),
        ];

        let (gaps, excluded) = rank_startup_profile_observed_gaps(&timeline, Some(2));

        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0].elapsed_ms, 50);
        assert_eq!(gaps[0].start.index, 1);
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].start.index, 2);
        assert_eq!(excluded[0].end.index, 3);
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
