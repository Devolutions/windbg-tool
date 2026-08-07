use crate::jobs::{JobRequest, SweepWatchMemoryJobRequest};
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
        tool::<JobRequest>("job_result", "Fetch the latest result payload for a daemon-owned replay job."),
        tool::<JobRequest>("job_cancel", "Request cancellation for a daemon-owned replay job."),
    ]
}

pub async fn call(state: &mut ServiceState, call: ToolCall) -> anyhow::Result<Value> {
    match call.name.as_str() {
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
        "ttd_load_trace"
            | "ttd_close_trace"
            | "ttd_index_build"
            | "ttd_position_set"
            | "ttd_step"
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
            | "sweep_watch_memory_start"
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
        "ttd_trace_info"
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
    )
}

fn tool_is_open_world(name: &str) -> bool {
    matches!(
        name,
        "ttd_load_trace"
            | "ttd_trace_list"
            | "live_launch_session"
            | "live_attach_process"
            | "dump_open_session"
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
