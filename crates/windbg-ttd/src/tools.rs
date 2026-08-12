use crate::analysis::{
    breakpoint_plan, debug_capabilities, debug_log_summarize, debug_snapshot, discover_manifest,
    dump_triage, module_search_order, pe_exports, pe_inspect, recipes_value,
    remote_connect_command, remote_doctor, remote_explain, remote_plan, remote_server_command,
    remote_status, source_resolve, symbols_diagnose, symbols_doctor, target_disassemble,
    target_memory_chase, target_memory_classify, target_memory_dps, target_memory_dump,
    target_memory_strings, target_stack_recover, triage_run, ttd_architecture_state,
    ttd_context_snapshot, ttd_disassemble, ttd_exception_focus, ttd_memory_chase,
    ttd_memory_classify, ttd_memory_dps, ttd_memory_dump, ttd_memory_strings, ttd_module_audit,
    ttd_object_vtable, ttd_open, ttd_replay_to, ttd_stack_backtrace, ttd_stack_recover,
    ttd_symbols_nearest, ttd_timeline_events, ArchitectureStateRequest, BreakpointPlanRequest,
    ContextSnapshotRequest, DebugCapabilitiesArgs, DebugLogSummarizeRequest, DebugSnapshotRequest,
    DisassembleRequest, DumpTriageRequest, ExceptionFocusRequest, MemoryAnalysisRequest,
    MemoryChaseRequest, MemoryDpsRequest, MemoryDumpRequest, MemoryStringsRequest,
    ModuleAuditRequest, ModuleSearchOrderRequest, ObjectVtableRequest, OpenTraceRequest,
    PeExportsRequest, PeInspectRequest, RecipesArgs, RemoteConnectCommandRequest,
    RemoteDoctorRequest, RemoteExplainRequest, RemotePlanRequest, RemoteServerCommandRequest,
    RemoteStatusRequest, ReplayToRequest, SourceResolveRequest, StackBacktraceRequest,
    StackRecoverRequest, SymbolsDiagnoseRequest, SymbolsDoctorRequest, SymbolsNearestRequest,
    TargetDisassembleAnalysisRequest, TargetMemoryAnalysisRequest, TargetMemoryChaseRequest,
    TargetMemoryDpsRequest, TargetMemoryDumpRequest, TargetMemoryStringsRequest,
    TargetStackRecoverRequest, TimelineEventsRequest, TriageRunRequest,
};
use crate::jobs::{ttd_watch_memory_sweep, JobRequest, SweepWatchMemoryJobRequest};
use crate::state::ServiceState;
use crate::targets::{
    DumpOpenRequest, LiveAttachRequest, LiveLaunchRequest, TargetAddressRequest,
    TargetBreakpointEnableRequest, TargetBreakpointRemoveRequest, TargetBreakpointSetRequest,
    TargetContinueWaitRequest, TargetDisassembleRequest, TargetExpressionRequest,
    TargetMemoryMapRequest, TargetMemoryReadRequest, TargetModuleParametersRequest, TargetRequest,
    TargetStackTraceRequest, TargetThreadAccountingRequest, TargetThreadContextRequest,
    TargetWaitRequest, TargetWriteDumpRequest,
};
use crate::ttd_replay::{
    AddressInfoRequest, CursorId, IndexBuildRequest, IndexStatsRequest, IndexStatusRequest,
    LoadTraceRequest, MemoryAccessDirection, MemoryBufferRequest, MemoryRangeRequest,
    MemoryWatchpointRequest, ModuleInfoRequest, Position, PositionRequest, ReadMemoryRequest,
    RegisterContextRequest, SessionId, StackReadRequest, StepRequest, TraceListRequest,
};
use anyhow::{bail, Context};
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionArg {
    session_id: SessionId,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CursorArg {
    session_id: SessionId,
    cursor_id: CursorId,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EmptyArgs {
    #[serde(default)]
    _reserved: Option<bool>,
}

pub fn definitions() -> Vec<Tool> {
    vec![
        tool::<EmptyArgs>(
            "daemon_health",
            "Return health, uptime, and active session/target/job counts for the shared windbg-tool daemon (or in-process service).",
        ),
        tool::<EmptyArgs>(
            "session_list",
            "List daemon-owned TTD trace sessions and cursors shared with the CLI.",
        ),
        tool::<EmptyArgs>(
            "discover",
            "Catalog preferred MCP entrypoints, recipes, backend capabilities, and daemon session model.",
        ),
        tool::<EmptyArgs>(
            "recipes_list",
            "List TimDbg-inspired investigation recipes available to agents.",
        ),
        tool::<RecipesArgs>(
            "recipes_get",
            "Fetch recipes by id or tag such as crash-triage, stack-corruption, or symbol-health.",
        ),
        tool::<DebugCapabilitiesArgs>(
            "debug_capabilities",
            "Return the cross-backend capability matrix, optionally focused on a TTD session/cursor or live/dump target.",
        ),
        tool::<OpenTraceRequest>(
            "ttd_open",
            "Load a TTD trace, create a cursor, and optionally seek to a position in one call.",
        ),
        tool::<ContextSnapshotRequest>(
            "ttd_context_snapshot",
            "Capture a TTD-focused agent context snapshot (position, stack, registers, timeline, disassembly).",
        ),
        tool::<DebugSnapshotRequest>(
            "debug_snapshot",
            "Capture a section-filterable debug snapshot for a TTD cursor or live/dump target.",
        ),
        tool::<TriageRunRequest>(
            "triage_run",
            "Run a bounded triage pack (crash/hang/access_violation/memory_corruption/loader/symbol_health/deadlock).",
        ),
        tool::<DisassembleRequest>(
            "ttd_disassemble",
            "Disassemble x64 instructions at an address or the current cursor RIP with classification tags.",
        ),
        tool::<StackRecoverRequest>(
            "ttd_stack_recover",
            "Recover return-address candidates from a bounded stack scan (heuristic, not a trusted unwind).",
        ),
        tool::<StackBacktraceRequest>(
            "ttd_stack_backtrace",
            "Build a heuristic backtrace from the current PC plus recovered stack return-address candidates.",
        ),
        tool::<MemoryDumpRequest>(
            "ttd_memory_dump",
            "Read guest memory and format it as db/dq/ascii/utf16 dump rows.",
        ),
        tool::<MemoryAnalysisRequest>(
            "ttd_memory_classify",
            "Classify a memory window (entropy, strings, pointer-like qwords, instruction hints).",
        ),
        tool::<MemoryStringsRequest>(
            "ttd_memory_strings",
            "Extract bounded ASCII/UTF-16 strings from a guest memory window.",
        ),
        tool::<MemoryDpsRequest>(
            "ttd_memory_dps",
            "Dump pointer-sized slots (dps-style) with optional address_info enrichment.",
        ),
        tool::<MemoryChaseRequest>(
            "ttd_memory_chase",
            "Follow a bounded pointer chain (base + offset) through guest memory.",
        ),
        tool::<TimelineEventsRequest>(
            "ttd_timeline_events",
            "Merge module/thread/exception/keyframe events into a chronological timeline.",
        ),
        tool::<ExceptionFocusRequest>(
            "ttd_exception_focus",
            "Seek a cursor to a recorded exception by index, preserving exact TTD position and thread.",
        ),
        tool::<ArchitectureStateRequest>(
            "ttd_architecture_state",
            "Report architecture detection and which x64 helpers are available for a TTD cursor.",
        ),
        tool::<ModuleAuditRequest>(
            "ttd_module_audit",
            "Audit loaded modules for suspicious paths, missing binaries, and duplicate basenames.",
        ),
        tool::<ObjectVtableRequest>(
            "ttd_object_vtable",
            "Read a COM/C++ object vtable pointer and classify vtable entries (read-only).",
        ),
        tool::<ModuleSearchOrderRequest>(
            "module_search_order",
            "Model common user-mode DLL search-order candidates for a basename (host diagnostic).",
        ),
        tool::<SourceResolveRequest>(
            "source_resolve",
            "Resolve a recorded source path via trailing path-component match under search roots.",
        ),
        tool::<BreakpointPlanRequest>(
            "breakpoint_plan",
            "Plan a code breakpoint or TTD memory watchpoint for a target or TTD session/cursor.",
        ),
        tool::<PeInspectRequest>(
            "pe_inspect",
            "Inspect PE image identity (timestamp, SizeOfImage, CodeView/PDB keys, export summary) from a host path.",
        ),
        tool::<PeExportsRequest>(
            "pe_exports",
            "List and optionally filter PE export symbols from a host path.",
        ),
        tool::<SymbolsNearestRequest>(
            "ttd_symbols_nearest",
            "Resolve nearest PE export for a TTD address via module path + RVA (low-fidelity fallback).",
        ),
        tool::<SymbolsDiagnoseRequest>(
            "symbols_diagnose",
            "Diagnose TTD session symbol readiness: paths, PE/PDB identity samples, and capability checks.",
        ),
        tool::<SymbolsDoctorRequest>(
            "symbols_doctor",
            "Compose a bounded symbol/source doctor pack for a TTD session/cursor or live/dump target.",
        ),
        tool::<LoadTraceRequest>(
            "ttd_load_trace",
            "Load a .run/.idx/.ttd trace for offline replay.",
        ),
        tool::<TraceListRequest>(
            "ttd_trace_list",
            "Enumerate traces inside a .run/.idx/.ttd file or trace pack without opening a replay session.",
        ),
        tool::<SessionArg>("ttd_close_trace", "Close an offline TTD trace session."),
        tool::<SessionArg>(
            "ttd_trace_info",
            "Return summary metadata for a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_capabilities",
            "Return backend features available for a loaded TTD trace session.",
        ),
        tool::<IndexStatusRequest>(
            "ttd_index_status",
            "Return TTD index status for a loaded trace session.",
        ),
        tool::<IndexStatsRequest>(
            "ttd_index_stats",
            "Return TTD index file statistics for a loaded trace session.",
        ),
        tool::<IndexBuildRequest>(
            "ttd_build_index",
            "Synchronously build the TTD index for a loaded trace session.",
        ),
        tool::<SessionArg>(
            "ttd_list_threads",
            "List threads captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_list_modules",
            "List modules and module instances captured in a loaded TTD trace.",
        ),
        tool::<CursorArg>(
            "ttd_cursor_modules",
            "List modules loaded at a replay cursor position.",
        ),
        tool::<SessionArg>(
            "ttd_list_keyframes",
            "List replay keyframe positions captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_module_events",
            "List module load and unload events captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_thread_events",
            "List thread create and terminate events captured in a loaded TTD trace.",
        ),
        tool::<ModuleInfoRequest>(
            "ttd_module_info",
            "Find a loaded module by name or guest address.",
        ),
        tool::<AddressInfoRequest>(
            "ttd_address_info",
            "Translate a runtime address into module/RVA coordinates with current cursor context.",
        ),
        tool::<CursorArg>(
            "ttd_active_threads",
            "List active threads at a replay cursor position with runtime PCs and module/RVA coordinates.",
        ),
        tool::<SessionArg>(
            "ttd_list_exceptions",
            "List exception events captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_cursor_create",
            "Create an independent replay cursor for a loaded trace.",
        ),
        tool::<CursorArg>(
            "ttd_position_get",
            "Read the current position of a replay cursor.",
        ),
        tool::<PositionRequest>(
            "ttd_position_set",
            "Move a replay cursor to a HEX:HEX position, approximate percent, or nearest position on a TTD unique thread.",
        ),
        tool::<StepRequest>(
            "ttd_step",
            "Step or trace a replay cursor forward or backward.",
        ),
        tool::<CursorArg>(
            "ttd_registers",
            "Read core register and thread state at a replay cursor position.",
        ),
        tool::<RegisterContextRequest>(
            "ttd_register_context",
            "Read x64 scalar and SIMD/vector register context at a replay cursor position.",
        ),
        tool::<CursorArg>(
            "ttd_stack_info",
            "Read current thread stack bounds and stack registers at a replay cursor position.",
        ),
        tool::<StackReadRequest>(
            "ttd_stack_read",
            "Read a bounded stack window around the current stack pointer.",
        ),
        tool::<CursorArg>(
            "ttd_command_line",
            "Read the process command line from PEB process parameters at a replay cursor position.",
        ),
        tool::<ReadMemoryRequest>(
            "ttd_read_memory",
            "Read guest memory at a replay cursor position.",
        ),
        tool::<MemoryRangeRequest>(
            "ttd_memory_range",
            "Query the trace-backed contiguous memory range and provenance for a guest address.",
        ),
        tool::<MemoryBufferRequest>(
            "ttd_memory_buffer",
            "Read guest memory with per-subrange trace provenance for decompiler correlation.",
        ),
        tool::<MemoryWatchpointRequest>(
            "ttd_memory_watchpoint",
            "Find the previous or next access matching a TTD DataAccessMask for a guest memory range.",
        ),
        tool::<LiveLaunchRequest>(
            "live_launch_session",
            "Launch a process under DbgEng and keep it alive as a daemon-owned live session.",
        ),
        tool::<LiveAttachRequest>(
            "live_attach_process",
            "Attach DbgEng to a process id and keep it alive as a daemon-owned live session.",
        ),
        tool::<DumpOpenRequest>(
            "dump_open_session",
            "Open a dump file as a daemon-owned read-only target session.",
        ),
        tool::<DumpTriageRequest>(
            "dump_inspect",
            "Open a dump offline and return bounded inspect evidence (modules, threads, registers, stack, triage).",
        ),
        tool::<DumpTriageRequest>(
            "dump_triage",
            "Open a dump offline and return structured bugcheck-context triage without a daemon session.",
        ),
        tool::<DumpTriageRequest>(
            "dump_pool_triage",
            "Open a dump offline and return bounded pool-corruption triage (pool tracker, address probes).",
        ),
        tool::<RemoteExplainRequest>(
            "remote_explain",
            "Explain DbgSrv versus NTSD/CDB remote debugging workflows and when to use each.",
        ),
        tool::<RemoteServerCommandRequest>(
            "remote_server_command",
            "Generate a target-side process-server or ntsd/cdb -server command line.",
        ),
        tool::<RemoteConnectCommandRequest>(
            "remote_connect_command",
            "Generate a host-side WinDbg/cdb -remote connect command line.",
        ),
        tool::<RemoteDoctorRequest>(
            "remote_doctor",
            "Diagnose remote debugging setup (transport parse, optional TCP probe, command plan).",
        ),
        tool::<RemoteStatusRequest>(
            "remote_status",
            "Report remote transport parse status and optional TCP connectivity probe.",
        ),
        tool::<RemotePlanRequest>(
            "remote_plan",
            "Produce a stepwise remote debugging plan with server and connect commands.",
        ),
        tool::<DebugLogSummarizeRequest>(
            "debug_log_summarize",
            "Summarize a windbg-tool action JSONL log (path or WINDBG_TOOL_ACTION_LOG).",
        ),
        tool::<ReplayToRequest>(
            "ttd_replay_to",
            "Seek a TTD cursor to a position/percent and return before/after positions.",
        ),
        tool::<SweepWatchMemoryJobRequest>(
            "ttd_watch_memory_sweep",
            "Synchronously collect multiple TTD memory-watchpoint hits (bounded; mutates cursor).",
        ),
        tool::<TargetDisassembleAnalysisRequest>(
            "target_disassemble_analysis",
            "Disassemble x64 instructions from a live/dump target using the shared iced-x86 helper.",
        ),
        tool::<TargetMemoryDumpRequest>(
            "target_memory_dump",
            "Format a live/dump target memory window (db/dq/ascii/utf16).",
        ),
        tool::<TargetMemoryAnalysisRequest>(
            "target_memory_classify",
            "Classify a live/dump target memory window (entropy, strings, pointer-like qwords).",
        ),
        tool::<TargetMemoryStringsRequest>(
            "target_memory_strings",
            "Extract bounded ASCII/UTF-16 strings from a live/dump target memory window.",
        ),
        tool::<TargetMemoryDpsRequest>(
            "target_memory_dps",
            "Dump pointer-sized slots from a live/dump target memory window.",
        ),
        tool::<TargetMemoryChaseRequest>(
            "target_memory_chase",
            "Follow a bounded pointer chain through live/dump target memory.",
        ),
        tool::<TargetStackRecoverRequest>(
            "target_stack_recover",
            "Recover return-address candidates from a live/dump target stack window.",
        ),
        tool::<EmptyArgs>("target_list", "List daemon-owned live and dump target sessions."),
        tool::<TargetRequest>(
            "target_status",
            "Return execution status and metadata for a daemon-owned target session.",
        ),
        tool::<TargetRequest>(
            "target_close",
            "Close a daemon-owned target session, detaching live targets.",
        ),
        tool::<TargetRequest>(
            "target_terminate",
            "Terminate and close a daemon-owned live target session.",
        ),
        tool::<TargetWaitRequest>(
            "target_wait",
            "Wait for an event in a daemon-owned live target session.",
        ),
        tool::<TargetRequest>(
            "target_continue",
            "Continue execution of a daemon-owned live target session.",
        ),
        tool::<TargetRequest>(
            "target_step_into",
            "Single-step a daemon-owned live target session.",
        ),
        tool::<TargetRequest>(
            "target_step_over",
            "Step over one instruction in a daemon-owned live target session.",
        ),
        tool::<TargetContinueWaitRequest>(
            "target_continue_wait",
            "Continue a live target and wait for one bounded stop, with optional bounded debuggee output capture.",
        ),
        tool::<TargetRequest>(
            "target_core_registers",
            "Read current thread and instruction, stack, and frame offsets from a daemon-owned target session.",
        ),
        tool::<TargetRequest>(
            "target_last_event",
            "Read the last DbgEng event, including bounded exception, breakpoint, module, or exit evidence when available.",
        ),
        tool::<TargetMemoryReadRequest>(
            "target_read_memory",
            "Read memory from a daemon-owned live or dump target session.",
        ),
        tool::<TargetMemoryMapRequest>(
            "target_memory_map",
            "Return a bounded user-mode virtual-memory region map through DbgEng IDebugDataSpaces4::QueryVirtual.",
        ),
        tool::<TargetAddressRequest>(
            "target_inspect_address",
            "Inspect one target address through bounded DbgEng virtual-to-physical and QueryVirtual probes; unavailable mapping or protection evidence is reported explicitly.",
        ),
        tool::<TargetThreadAccountingRequest>(
            "target_thread_accounting",
            "Return bounded read-only DbgEng per-thread accounting from IDebugAdvanced2.",
        ),
        tool::<TargetModuleParametersRequest>(
            "target_module_parameters",
            "Return bounded DbgEng symbol-readiness parameters for supplied observed module bases.",
        ),
        tool::<TargetAddressRequest>(
            "target_symbol_entry_range",
            "Return bounded DbgEng symbol-entry offset regions for one existing native address.",
        ),
        tool::<TargetRequest>(
            "target_list_threads",
            "List threads from a daemon-owned live or dump target session.",
        ),
        tool::<TargetRequest>(
            "target_list_modules",
            "List modules from a daemon-owned live or dump target session.",
        ),
        tool::<TargetAddressRequest>(
            "target_symbol_by_offset",
            "Resolve the nearest symbol for an address in a daemon-owned live or dump target session.",
        ),
        tool::<TargetAddressRequest>(
            "target_source_by_offset",
            "Resolve source file and line information for an address in a daemon-owned live or dump target session.",
        ),
        tool::<TargetStackTraceRequest>(
            "target_stack_trace",
            "Walk the current stack for a daemon-owned live or dump target session.",
        ),
        tool::<TargetThreadContextRequest>(
            "target_thread_context",
            "Read bounded registers, module/symbol, stack, and disassembly for one engine thread, then restore the prior current thread.",
        ),
        tool::<TargetDisassembleRequest>(
            "target_disassemble",
            "Disassemble instructions from a daemon-owned live or dump target session.",
        ),
        tool::<TargetRequest>(
            "target_list_breakpoints",
            "List breakpoints from a daemon-owned live target session.",
        ),
        tool::<TargetBreakpointSetRequest>(
            "target_set_breakpoint",
            "Set a code, data, or deferred symbol code breakpoint in a daemon-owned live target session.",
        ),
        tool::<TargetBreakpointEnableRequest>(
            "target_set_breakpoint_enabled",
            "Enable or disable an existing breakpoint in a daemon-owned live target session.",
        ),
        tool::<TargetBreakpointRemoveRequest>(
            "target_remove_breakpoint",
            "Remove a breakpoint from a daemon-owned live target session.",
        ),
        tool::<TargetExpressionRequest>(
            "target_evaluate_expression",
            "Evaluate a DbgEng expression against a daemon-owned live or dump target session.",
        ),
        tool::<TargetWriteDumpRequest>(
            "target_write_dump",
            "Write a process dump from a daemon-owned live target session.",
        ),
        tool::<SweepWatchMemoryJobRequest>(
            "job_start_watch_memory_sweep",
            "Start a daemon-owned background replay job that collects multiple watch-memory hits.",
        ),
        tool::<EmptyArgs>("job_list", "List daemon-owned background replay jobs."),
        tool::<JobRequest>("job_status", "Show the current status of a daemon-owned replay job."),
        tool::<JobRequest>(
            "job_result",
            "Fetch the latest result payload for a daemon-owned replay job.",
        ),
        tool::<JobRequest>("job_cancel", "Request cancellation for a daemon-owned replay job."),
    ]
}

pub async fn call(state: &mut ServiceState, call: ToolCall) -> anyhow::Result<Value> {
    match call.name.as_str() {
        // Handled by ReplayService::call_tool so health/uptime stay accurate.
        "daemon_health" | "session_list" => {
            bail!("{} must be dispatched by ReplayService", call.name)
        }
        "discover" => {
            let names = definitions()
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect::<Vec<_>>();
            Ok(discover_manifest(&names))
        }
        "recipes_list" => Ok(recipes_value(None)?),
        "recipes_get" => {
            let request = parse::<RecipesArgs>(call.arguments)?;
            Ok(recipes_value(request.topic.as_deref())?)
        }
        "debug_capabilities" => {
            let request = parse::<DebugCapabilitiesArgs>(call.arguments)?;
            debug_capabilities(state, request)
        }
        "ttd_open" => {
            let request = parse::<OpenTraceRequest>(call.arguments)?;
            ttd_open(state, request)
        }
        "ttd_context_snapshot" => {
            let request = parse::<ContextSnapshotRequest>(call.arguments)?;
            ttd_context_snapshot(state, request)
        }
        "debug_snapshot" => {
            let request = parse::<DebugSnapshotRequest>(call.arguments)?;
            debug_snapshot(state, request)
        }
        "triage_run" => {
            let request = parse::<TriageRunRequest>(call.arguments)?;
            triage_run(state, request)
        }
        "ttd_disassemble" => {
            let request = parse::<DisassembleRequest>(call.arguments)?;
            ttd_disassemble(state, request)
        }
        "ttd_stack_recover" => {
            let request = parse::<StackRecoverRequest>(call.arguments)?;
            ttd_stack_recover(state, request)
        }
        "ttd_stack_backtrace" => {
            let request = parse::<StackBacktraceRequest>(call.arguments)?;
            ttd_stack_backtrace(state, request)
        }
        "ttd_memory_dump" => {
            let request = parse::<MemoryDumpRequest>(call.arguments)?;
            ttd_memory_dump(state, request)
        }
        "ttd_memory_classify" => {
            let request = parse::<MemoryAnalysisRequest>(call.arguments)?;
            ttd_memory_classify(state, request)
        }
        "ttd_memory_strings" => {
            let request = parse::<MemoryStringsRequest>(call.arguments)?;
            ttd_memory_strings(state, request)
        }
        "ttd_memory_dps" => {
            let request = parse::<MemoryDpsRequest>(call.arguments)?;
            ttd_memory_dps(state, request)
        }
        "ttd_memory_chase" => {
            let request = parse::<MemoryChaseRequest>(call.arguments)?;
            ttd_memory_chase(state, request)
        }
        "ttd_timeline_events" => {
            let request = parse::<TimelineEventsRequest>(call.arguments)?;
            ttd_timeline_events(state, request)
        }
        "ttd_exception_focus" => {
            let request = parse::<ExceptionFocusRequest>(call.arguments)?;
            ttd_exception_focus(state, request)
        }
        "ttd_architecture_state" => {
            let request = parse::<ArchitectureStateRequest>(call.arguments)?;
            ttd_architecture_state(state, request)
        }
        "ttd_module_audit" => {
            let request = parse::<ModuleAuditRequest>(call.arguments)?;
            ttd_module_audit(state, request)
        }
        "ttd_object_vtable" => {
            let request = parse::<ObjectVtableRequest>(call.arguments)?;
            ttd_object_vtable(state, request)
        }
        "module_search_order" => {
            let request = parse::<ModuleSearchOrderRequest>(call.arguments)?;
            module_search_order(request)
        }
        "source_resolve" => {
            let request = parse::<SourceResolveRequest>(call.arguments)?;
            source_resolve(request)
        }
        "breakpoint_plan" => {
            let request = parse::<BreakpointPlanRequest>(call.arguments)?;
            breakpoint_plan(request)
        }
        "pe_inspect" => {
            let request = parse::<PeInspectRequest>(call.arguments)?;
            pe_inspect(request)
        }
        "pe_exports" => {
            let request = parse::<PeExportsRequest>(call.arguments)?;
            pe_exports(request)
        }
        "ttd_symbols_nearest" => {
            let request = parse::<SymbolsNearestRequest>(call.arguments)?;
            ttd_symbols_nearest(state, request)
        }
        "symbols_diagnose" => {
            let request = parse::<SymbolsDiagnoseRequest>(call.arguments)?;
            symbols_diagnose(state, request)
        }
        "symbols_doctor" => {
            let request = parse::<SymbolsDoctorRequest>(call.arguments)?;
            symbols_doctor(state, request)
        }
        "ttd_load_trace" => {
            let request = parse::<LoadTraceRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.load_trace(request)?)?)
        }
        "ttd_trace_list" => {
            let request = parse::<TraceListRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.list_trace_file(request)?)?)
        }
        "ttd_close_trace" => {
            let request = parse::<SessionArg>(call.arguments)?;
            state.ttd.close_trace(request.session_id)?;
            Ok(json!({ "closed": true, "session_id": request.session_id }))
        }
        "ttd_trace_info" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.trace_info(request.session_id)?,
            )?)
        }
        "ttd_capabilities" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.capabilities(request.session_id)?,
            )?)
        }
        "ttd_index_status" => {
            let request = parse::<IndexStatusRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.index_status(request)?)?)
        }
        "ttd_index_stats" => {
            let request = parse::<IndexStatsRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.index_stats(request)?)?)
        }
        "ttd_build_index" => {
            let request = parse::<IndexBuildRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.build_index(request)?)?)
        }
        "ttd_list_threads" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_threads(request.session_id)?,
            )?)
        }
        "ttd_list_modules" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_modules(request.session_id)?,
            )?)
        }
        "ttd_cursor_modules" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state
                    .ttd
                    .cursor_modules(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_list_keyframes" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_keyframes(request.session_id)?,
            )?)
        }
        "ttd_module_events" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_module_events(request.session_id)?,
            )?)
        }
        "ttd_thread_events" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_thread_events(request.session_id)?,
            )?)
        }
        "ttd_module_info" => {
            let request = parse::<ModuleInfoRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.module_info(request)?)?)
        }
        "ttd_address_info" => {
            let request = parse::<AddressInfoRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.address_info(request)?)?)
        }
        "ttd_active_threads" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state
                    .ttd
                    .active_threads(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_list_exceptions" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.list_exceptions(request.session_id)?,
            )?)
        }
        "ttd_cursor_create" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.create_cursor(request.session_id)?,
            )?)
        }
        "ttd_position_get" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state
                    .ttd
                    .cursor_position(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_position_set" => {
            let request = parse::<PositionRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.set_position(request)?)?)
        }
        "ttd_step" => {
            let request = parse::<StepRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.step(request)?)?)
        }
        "ttd_registers" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state.ttd.registers(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_register_context" => {
            let request = parse::<RegisterContextRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.register_context(request)?)?)
        }
        "ttd_stack_info" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state
                    .ttd
                    .stack_info(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_stack_read" => {
            let request = parse::<StackReadRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.stack_read(request)?)?)
        }
        "ttd_command_line" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                state
                    .ttd
                    .command_line(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_read_memory" => {
            let request = parse::<ReadMemoryRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.read_memory(request)?)?)
        }
        "ttd_memory_range" => {
            let request = parse::<MemoryRangeRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.memory_range(request)?)?)
        }
        "ttd_memory_buffer" => {
            let request = parse::<MemoryBufferRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.ttd.memory_buffer(request)?)?)
        }
        "ttd_memory_watchpoint" => {
            let request = parse::<MemoryWatchpointRequest>(call.arguments)?;
            if request.direction == MemoryAccessDirection::Unknown {
                bail!("direction must be 'previous' or 'next'");
            }
            Ok(serde_json::to_value(state.ttd.memory_watchpoint(request)?)?)
        }
        "live_launch_session" => {
            let request = parse::<LiveLaunchRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.launch_live(request)?)?)
        }
        "live_attach_process" => {
            let request = parse::<LiveAttachRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.attach_live(request)?)?)
        }
        "dump_open_session" => {
            let request = parse::<DumpOpenRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.open_dump(request)?)?)
        }
        "dump_inspect" => {
            let mut request = parse::<DumpTriageRequest>(call.arguments)?;
            if request.profile.is_none() {
                request.profile = Some("inspect".to_string());
            }
            dump_triage(request)
        }
        "dump_triage" => {
            let mut request = parse::<DumpTriageRequest>(call.arguments)?;
            if request.profile.is_none() {
                request.profile = Some("triage".to_string());
            }
            dump_triage(request)
        }
        "dump_pool_triage" => {
            let mut request = parse::<DumpTriageRequest>(call.arguments)?;
            if request.profile.is_none() {
                request.profile = Some("pool_triage".to_string());
            }
            dump_triage(request)
        }
        "remote_explain" => {
            let request = parse::<RemoteExplainRequest>(call.arguments)?;
            remote_explain(request)
        }
        "remote_server_command" => {
            let request = parse::<RemoteServerCommandRequest>(call.arguments)?;
            remote_server_command(request)
        }
        "remote_connect_command" => {
            let request = parse::<RemoteConnectCommandRequest>(call.arguments)?;
            remote_connect_command(request)
        }
        "remote_doctor" => {
            let request = parse::<RemoteDoctorRequest>(call.arguments)?;
            remote_doctor(request)
        }
        "remote_status" => {
            let request = parse::<RemoteStatusRequest>(call.arguments)?;
            remote_status(request)
        }
        "remote_plan" => {
            let request = parse::<RemotePlanRequest>(call.arguments)?;
            remote_plan(request)
        }
        "debug_log_summarize" => {
            let request = parse::<DebugLogSummarizeRequest>(call.arguments)?;
            debug_log_summarize(request)
        }
        "ttd_replay_to" => {
            let request = parse::<ReplayToRequest>(call.arguments)?;
            ttd_replay_to(state, request)
        }
        "ttd_watch_memory_sweep" => {
            let request = parse::<SweepWatchMemoryJobRequest>(call.arguments)?;
            ttd_watch_memory_sweep(state, request)
        }
        "target_disassemble_analysis" => {
            let request = parse::<TargetDisassembleAnalysisRequest>(call.arguments)?;
            target_disassemble(state, request)
        }
        "target_memory_dump" => {
            let request = parse::<TargetMemoryDumpRequest>(call.arguments)?;
            target_memory_dump(state, request)
        }
        "target_memory_classify" => {
            let request = parse::<TargetMemoryAnalysisRequest>(call.arguments)?;
            target_memory_classify(state, request)
        }
        "target_memory_strings" => {
            let request = parse::<TargetMemoryStringsRequest>(call.arguments)?;
            target_memory_strings(state, request)
        }
        "target_memory_dps" => {
            let request = parse::<TargetMemoryDpsRequest>(call.arguments)?;
            target_memory_dps(state, request)
        }
        "target_memory_chase" => {
            let request = parse::<TargetMemoryChaseRequest>(call.arguments)?;
            target_memory_chase(state, request)
        }
        "target_stack_recover" => {
            let request = parse::<TargetStackRecoverRequest>(call.arguments)?;
            target_stack_recover(state, request)
        }
        "target_list" => {
            let _request = parse::<EmptyArgs>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.list_targets()?)?)
        }
        "target_status" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.target_status(request)?)?)
        }
        "target_close" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.close_target(request)?)?)
        }
        "target_terminate" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.terminate_target(request)?,
            )?)
        }
        "target_wait" => {
            let request = parse::<TargetWaitRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.wait_for_event(request)?,
            )?)
        }
        "target_continue" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.continue_execution(request)?,
            )?)
        }
        "target_step_into" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.step_into(request)?)?)
        }
        "target_step_over" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.step_over(request)?)?)
        }
        "target_continue_wait" => {
            let request = parse::<TargetContinueWaitRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.continue_and_wait(request)?,
            )?)
        }
        "target_core_registers" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.core_registers(request)?,
            )?)
        }
        "target_last_event" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.last_event(request)?)?)
        }
        "target_read_memory" => {
            let request = parse::<TargetMemoryReadRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.read_memory(request)?)?)
        }
        "target_memory_map" => {
            let request = parse::<TargetMemoryMapRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.memory_map(request)?)?)
        }
        "target_inspect_address" => {
            let request = parse::<TargetAddressRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.inspect_address(request)?,
            )?)
        }
        "target_thread_accounting" => {
            let request = parse::<TargetThreadAccountingRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.thread_accounting(request)?,
            )?)
        }
        "target_module_parameters" => {
            let request = parse::<TargetModuleParametersRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.module_parameters(request)?,
            )?)
        }
        "target_symbol_entry_range" => {
            let request = parse::<TargetAddressRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.symbol_entry_range(request)?,
            )?)
        }
        "target_list_threads" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.list_threads(request)?)?)
        }
        "target_list_modules" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.list_modules(request)?)?)
        }
        "target_symbol_by_offset" => {
            let request = parse::<TargetAddressRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.symbol_by_offset(request)?,
            )?)
        }
        "target_source_by_offset" => {
            let request = parse::<TargetAddressRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.source_by_offset(request)?,
            )?)
        }
        "target_stack_trace" => {
            let request = parse::<TargetStackTraceRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.stack_trace(request)?)?)
        }
        "target_thread_context" => {
            let request = parse::<TargetThreadContextRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.thread_context(request)?,
            )?)
        }
        "target_disassemble" => {
            let request = parse::<TargetDisassembleRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.disassemble(request)?)?)
        }
        "target_list_breakpoints" => {
            let request = parse::<TargetRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.list_breakpoints(request)?,
            )?)
        }
        "target_set_breakpoint" => {
            let request = parse::<TargetBreakpointSetRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.set_breakpoint(request)?,
            )?)
        }
        "target_set_breakpoint_enabled" => {
            let request = parse::<TargetBreakpointEnableRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.set_breakpoint_enabled(request)?,
            )?)
        }
        "target_remove_breakpoint" => {
            let request = parse::<TargetBreakpointRemoveRequest>(call.arguments)?;
            Ok(serde_json::to_value(
                state.targets.remove_breakpoint(request)?,
            )?)
        }
        "target_evaluate_expression" => {
            let request = parse::<TargetExpressionRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.evaluate(request)?)?)
        }
        "target_write_dump" => {
            let request = parse::<TargetWriteDumpRequest>(call.arguments)?;
            Ok(serde_json::to_value(state.targets.write_dump(request)?)?)
        }
        _ => bail!("unknown tool: {}", call.name),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(value: Value) -> anyhow::Result<T> {
    serde_json::from_value(value).context("invalid tool arguments")
}

fn tool<T: JsonSchema>(name: &str, description: &str) -> Tool {
    let input_schema = input_schema::<T>();
    Tool::new(
        name.to_string(),
        description.to_string(),
        Arc::new(input_schema),
    )
    .annotate(tool_annotations(name))
}

fn tool_annotations(name: &str) -> ToolAnnotations {
    let mut annotations = ToolAnnotations::new()
        .read_only(tool_is_read_only(name))
        .destructive(tool_is_destructive(name))
        .idempotent(tool_is_idempotent(name))
        .open_world(tool_is_open_world(name));
    annotations.title = Some(name.replace('_', " "));
    annotations
}

fn tool_is_read_only(name: &str) -> bool {
    !matches!(
        name,
        "ttd_open"
            | "ttd_load_trace"
            | "ttd_close_trace"
            | "ttd_index_build"
            | "ttd_position_set"
            | "ttd_exception_focus"
            | "ttd_step"
            | "ttd_replay_to"
            | "ttd_watch_memory_sweep"
            | "job_start_watch_memory_sweep"
            | "job_cancel"
            | "target_write_dump"
            | "target_close"
            | "target_terminate"
            | "target_continue"
            | "target_continue_wait"
            | "target_step_into"
            | "target_step_over"
            | "target_set_breakpoint"
            | "target_set_breakpoint_enabled"
            | "target_remove_breakpoint"
            | "live_launch_session"
            | "live_attach_process"
            | "dump_open_session"
    )
}

fn tool_is_destructive(name: &str) -> bool {
    matches!(
        name,
        "ttd_close_trace" | "job_cancel" | "target_close" | "target_terminate"
    )
}

fn tool_is_idempotent(name: &str) -> bool {
    matches!(
        name,
        "daemon_health"
            | "session_list"
            | "discover"
            | "recipes_list"
            | "recipes_get"
            | "debug_capabilities"
            | "ttd_context_snapshot"
            | "debug_snapshot"
            | "triage_run"
            | "dump_inspect"
            | "dump_triage"
            | "dump_pool_triage"
            | "remote_explain"
            | "remote_server_command"
            | "remote_connect_command"
            | "remote_doctor"
            | "remote_status"
            | "remote_plan"
            | "debug_log_summarize"
            | "ttd_disassemble"
            | "ttd_stack_recover"
            | "ttd_stack_backtrace"
            | "ttd_memory_dump"
            | "ttd_memory_classify"
            | "ttd_memory_strings"
            | "ttd_memory_dps"
            | "ttd_memory_chase"
            | "ttd_timeline_events"
            | "ttd_architecture_state"
            | "ttd_module_audit"
            | "ttd_object_vtable"
            | "module_search_order"
            | "source_resolve"
            | "breakpoint_plan"
            | "pe_inspect"
            | "pe_exports"
            | "ttd_symbols_nearest"
            | "symbols_diagnose"
            | "symbols_doctor"
            | "ttd_trace_info"
            | "ttd_capabilities"
            | "ttd_index_status"
            | "ttd_index_stats"
            | "ttd_list_threads"
            | "ttd_list_modules"
            | "ttd_list_keyframes"
            | "ttd_list_exceptions"
            | "ttd_position_get"
            | "ttd_read_memory"
            | "job_list"
            | "job_status"
            | "job_result"
            | "target_capabilities"
            | "target_list"
            | "target_status"
            | "target_disassemble_analysis"
            | "target_memory_dump"
            | "target_memory_classify"
            | "target_memory_strings"
            | "target_memory_dps"
            | "target_memory_chase"
            | "target_stack_recover"
    )
}

fn tool_is_open_world(name: &str) -> bool {
    matches!(
        name,
        "ttd_open"
            | "ttd_load_trace"
            | "ttd_trace_list"
            | "live_launch_session"
            | "live_attach_process"
            | "dump_open_session"
            | "dump_inspect"
            | "dump_triage"
            | "dump_pool_triage"
            | "debug_log_summarize"
            | "remote_doctor"
            | "remote_status"
            | "pe_inspect"
            | "pe_exports"
            | "source_resolve"
            | "target_write_dump"
    )
}

fn input_schema<T: JsonSchema>() -> JsonObject {
    let input_schema = serde_json::to_value(schema_for!(T)).expect("tool schema is serializable");
    match input_schema {
        Value::Object(object) => object,
        _ => JsonObject::new(),
    }
}

#[allow(dead_code)]
fn _position_schema_anchor(_: Position) {}
