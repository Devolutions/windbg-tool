use anyhow::{bail, ensure, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Instant;
use windbg_dbgeng::{
    attach_live_session, launch_live_session, open_dump_session, BreakpointInfo, CoreRegisterState,
    DebuggerEventInfo, DebuggerExecutionStatus, DebuggerOutputCaptureOptions, DebuggerRunResult,
    DebuggerSession, DebuggerSessionKind, DebuggerSessionSummary, DisassemblyResult, DumpKind,
    DumpOpenOptions, DumpWriteOptions, DumpWriteResult, EvaluationResult, LiveAttachOptions,
    LiveInitialStop, LiveLaunchSessionOptions, MemoryReadResult, ModuleDebugParameters, ModuleInfo,
    SourceLocation, StackFrameInfo, SymbolEntryRange, SymbolInfo, ThreadAccountingSnapshot,
    ThreadContext, ThreadInfo, VirtualAddressInspection, VirtualMemoryMap,
    MAX_MODULE_PARAMETER_QUERIES, MAX_THREAD_ACCOUNTING_THREADS, MAX_VIRTUAL_MEMORY_MAP_REGIONS,
};
use windbg_symbols::{
    image_matches, inspect_pe_image_identity, prefetch_image, prefetch_pdb, NativeImageStatus,
    NativeSymbolStatus, PeImageIdentity,
};

pub type TargetId = u64;

#[derive(Default)]
pub struct TargetRegistry {
    next_target_id: TargetId,
    targets: HashMap<TargetId, ManagedTarget>,
}

struct ManagedTarget {
    worker: EngineWorker,
    native_symbols: Value,
    native_symbol_options: Option<NativeSymbolOptions>,
}

enum EngineCommand {
    Run(Box<dyn FnOnce(&DebuggerSession) + Send + 'static>),
    Shutdown {
        detach_live_target: bool,
        response: mpsc::Sender<()>,
    },
}

/// Owns a DbgEng client on one dedicated thread. DbgEng requests are serialized
/// even when future daemon callers no longer hold the global service-state lock.
struct EngineWorker {
    kind: DebuggerSessionKind,
    sender: Option<SyncSender<EngineCommand>>,
    join: Option<JoinHandle<()>>,
}

impl EngineWorker {
    fn new(session: DebuggerSession) -> anyhow::Result<Self> {
        let kind = session.kind();
        let (sender, receiver) = mpsc::sync_channel::<EngineCommand>(64);
        let join = thread::Builder::new()
            .name("windbg-dbgeng-engine".to_string())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        EngineCommand::Run(operation) => operation(&session),
                        EngineCommand::Shutdown {
                            detach_live_target,
                            response,
                        } => {
                            if detach_live_target && session.kind() == DebuggerSessionKind::Live {
                                let _ = session.detach();
                            }
                            let _ = response.send(());
                            break;
                        }
                    }
                }
            })
            .context("starting the serialized DbgEng engine worker")?;
        Ok(Self {
            kind,
            sender: Some(sender),
            join: Some(join),
        })
    }

    fn kind(&self) -> DebuggerSessionKind {
        self.kind
    }

    fn call<T, F>(&self, operation: &'static str, action: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&DebuggerSession) -> anyhow::Result<T> + Send + 'static,
    {
        let sender = self
            .sender
            .as_ref()
            .context("DbgEng engine worker is closed")?;
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        sender
            .send(EngineCommand::Run(Box::new(move |session| {
                let _ = response_sender.send(action(session));
            })))
            .map_err(|_| {
                anyhow::anyhow!("DbgEng engine worker closed while queueing {operation}")
            })?;
        response_receiver
            .recv()
            .with_context(|| format!("waiting for DbgEng {operation} response"))?
    }

    fn shutdown(&mut self, detach_live_target: bool) -> anyhow::Result<()> {
        let Some(sender) = self.sender.take() else {
            return Ok(());
        };
        let (response_sender, response_receiver) = mpsc::channel();
        sender
            .send(EngineCommand::Shutdown {
                detach_live_target,
                response: response_sender,
            })
            .map_err(|_| anyhow::anyhow!("DbgEng engine worker closed during shutdown"))?;
        response_receiver
            .recv()
            .context("waiting for DbgEng engine worker shutdown")?;
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| anyhow::anyhow!("DbgEng engine worker panicked during shutdown"))?;
        }
        Ok(())
    }
}

impl Drop for EngineWorker {
    fn drop(&mut self) {
        let _ = self.shutdown(true);
    }
}

impl ManagedTarget {
    fn kind(&self) -> DebuggerSessionKind {
        self.worker.kind()
    }

    fn summary(&self) -> anyhow::Result<DebuggerSessionSummary> {
        self.worker.call("summary", |session| Ok(session.summary()))
    }
}

#[derive(Clone)]
struct NativeSymbolOptions {
    cache_dir: PathBuf,
    image_paths: Vec<PathBuf>,
    offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LiveLaunchRequest {
    pub command_line: String,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub initial_break_timeout_ms: u32,
    #[serde(default)]
    pub create_process_stop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LiveAttachRequest {
    pub process_id: u32,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub initial_break_timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpOpenRequest {
    pub path: PathBuf,
    #[serde(default = "default_native_symbol_cache")]
    pub symbol_cache: PathBuf,
    #[serde(default)]
    pub image_paths: Vec<PathBuf>,
    #[serde(default)]
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetRequest {
    pub target_id: TargetId,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetWaitRequest {
    pub target_id: TargetId,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetContinueWaitRequest {
    pub target_id: TargetId,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub capture_debuggee_output: bool,
    #[serde(default = "default_target_output_records")]
    #[schemars(range(min = 1, max = 128))]
    pub max_output_records: u32,
    #[serde(default = "default_target_output_chars")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_output_chars: u32,
    #[serde(default = "default_target_output_total_chars")]
    #[schemars(range(min = 1, max = 32768))]
    pub max_total_output_chars: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetMemoryReadRequest {
    pub target_id: TargetId,
    pub address: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetMemoryMapRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_memory_map_regions")]
    #[schemars(
        range(min = 1, max = 4096),
        description = "Maximum DbgEng virtual-memory regions returned; must be from 1 through 4096."
    )]
    pub region_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetThreadAccountingRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_thread_accounting_threads")]
    #[schemars(
        range(min = 1, max = 128),
        description = "Maximum DbgEng threads returned; must be from 1 through 128."
    )]
    pub max_threads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetModuleParametersRequest {
    pub target_id: TargetId,
    #[schemars(
        length(min = 1, max = 128),
        description = "Distinct DbgEng-observed module base addresses; at most 128."
    )]
    pub module_base_addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetAddressRequest {
    pub target_id: TargetId,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetStackTraceRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_stack_frames")]
    pub max_frames: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetThreadContextRequest {
    pub target_id: TargetId,
    #[schemars(description = "DbgEng engine thread id returned by target_list_threads")]
    pub engine_thread_id: u32,
    #[serde(default = "default_target_stack_frames")]
    pub max_frames: u32,
    #[serde(default = "default_target_disasm_count")]
    pub disassembly_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetDisassembleRequest {
    pub target_id: TargetId,
    pub address: Option<u64>,
    #[serde(default = "default_target_disasm_count")]
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetExpressionRequest {
    pub target_id: TargetId,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetWriteDumpRequest {
    pub target_id: TargetId,
    pub path: PathBuf,
    #[serde(default)]
    pub kind: TargetDumpKind,
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetDumpKind {
    #[default]
    Mini,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetBreakpointKind {
    Code,
    Read,
    Write,
    Execute,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetBreakpointSetRequest {
    pub target_id: TargetId,
    pub address: Option<u64>,
    pub symbol: Option<String>,
    #[serde(default)]
    pub kind: Option<TargetBreakpointKind>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetBreakpointRemoveRequest {
    pub target_id: TargetId,
    pub breakpoint_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetBreakpointEnableRequest {
    pub target_id: TargetId,
    pub breakpoint_id: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetOpenedResponse {
    pub target_id: TargetId,
    pub target: DebuggerSessionSummary,
    pub native_symbols: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
    pub target_id: TargetId,
    pub target: DebuggerSessionSummary,
    pub native_symbols: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetListResponse {
    pub targets: Vec<TargetSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetClosedResponse {
    pub target_id: TargetId,
    pub closed: bool,
    pub detached: bool,
    pub terminated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadList {
    pub target_id: TargetId,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetRegisterState {
    pub target_id: TargetId,
    pub registers: CoreRegisterState,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEventResponse {
    pub target_id: TargetId,
    pub event: DebuggerEventInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetContinueWaitResponse {
    pub target_id: TargetId,
    pub run: DebuggerRunResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadContextResponse {
    pub target_id: TargetId,
    pub context: ThreadContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetMemoryReadResponse {
    pub target_id: TargetId,
    pub memory: MemoryReadResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetMemoryMapResponse {
    pub target_id: TargetId,
    pub memory_map: VirtualMemoryMap,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetAddressInspectionResponse {
    pub target_id: TargetId,
    pub inspection: VirtualAddressInspection,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadAccountingResponse {
    pub target_id: TargetId,
    pub thread_accounting: ThreadAccountingSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetModuleParametersResponse {
    pub target_id: TargetId,
    pub source: String,
    pub parameters: Vec<ModuleDebugParameters>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSymbolEntryRangeResponse {
    pub target_id: TargetId,
    pub symbol_entry_range: SymbolEntryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetModuleList {
    pub target_id: TargetId,
    pub modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSymbolResponse {
    pub target_id: TargetId,
    pub symbol: Option<SymbolInfo>,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSourceResponse {
    pub target_id: TargetId,
    pub source: Option<SourceLocation>,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetStackTraceResponse {
    pub target_id: TargetId,
    pub frames: Vec<StackFrameInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetDisassemblyResponse {
    pub target_id: TargetId,
    pub disassembly: DisassemblyResult,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetBreakpointList {
    pub target_id: TargetId,
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetBreakpointChangeResponse {
    pub target_id: TargetId,
    pub breakpoint: Option<BreakpointInfo>,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEvaluationResponse {
    pub target_id: TargetId,
    pub evaluation: EvaluationResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetWriteDumpResponse {
    pub target_id: TargetId,
    pub dump: DumpWriteResult,
}

impl TargetRegistry {
    pub fn list_targets(&self) -> anyhow::Result<TargetListResponse> {
        let mut targets = self
            .targets
            .iter()
            .map(|(target_id, target)| {
                Ok(TargetSummary {
                    target_id: *target_id,
                    target: target.summary()?,
                    native_symbols: target.native_symbols.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        targets.sort_by_key(|target| target.target_id);
        Ok(TargetListResponse { targets })
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn live_target_count(&self) -> usize {
        self.targets
            .values()
            .filter(|target| target.kind() == DebuggerSessionKind::Live)
            .count()
    }

    pub fn dump_target_count(&self) -> usize {
        self.targets
            .values()
            .filter(|target| target.kind() == DebuggerSessionKind::Dump)
            .count()
    }

    pub fn launch_live(
        &mut self,
        request: LiveLaunchRequest,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let session = launch_live_session(LiveLaunchSessionOptions {
            command_line: request.command_line,
            initial_break_timeout_ms: request.initial_break_timeout_ms,
            initial_stop: if request.create_process_stop {
                LiveInitialStop::CreateProcessEvent
            } else {
                LiveInitialStop::SoftwareBreakpoint
            },
        })?;
        self.insert_target(session, Value::Null, None)
    }

    pub fn attach_live(
        &mut self,
        request: LiveAttachRequest,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let session = attach_live_session(LiveAttachOptions {
            process_id: request.process_id,
            initial_break_timeout_ms: request.initial_break_timeout_ms,
        })?;
        self.insert_target(session, Value::Null, None)
    }

    pub fn open_dump(&mut self, request: DumpOpenRequest) -> anyhow::Result<TargetOpenedResponse> {
        let session = open_dump_session(DumpOpenOptions { path: request.path })?;
        let native_symbol_options = NativeSymbolOptions {
            cache_dir: request.symbol_cache,
            image_paths: request.image_paths,
            offline: request.offline,
        };
        let native_symbols = prefetch_dump_symbols(
            &session,
            None,
            &native_symbol_options.cache_dir,
            &native_symbol_options.image_paths,
            native_symbol_options.offline,
        );
        self.insert_target(session, native_symbols, Some(native_symbol_options))
    }

    pub fn target_status(&self, request: TargetRequest) -> anyhow::Result<TargetSummary> {
        let target = self.target(request.target_id)?;
        Ok(TargetSummary {
            target_id: request.target_id,
            target: target.summary()?,
            native_symbols: target.native_symbols.clone(),
        })
    }

    pub fn close_target(&mut self, request: TargetRequest) -> anyhow::Result<TargetClosedResponse> {
        let mut target = self
            .targets
            .remove(&request.target_id)
            .with_context(|| format!("unknown target id: {}", request.target_id))?;
        let detached = matches!(target.kind(), DebuggerSessionKind::Live);
        if detached {
            target.worker.call("detach", |session| session.detach())?;
        }
        target.worker.shutdown(false)?;
        Ok(TargetClosedResponse {
            target_id: request.target_id,
            closed: true,
            detached,
            terminated: false,
        })
    }

    pub fn terminate_target(
        &mut self,
        request: TargetRequest,
    ) -> anyhow::Result<TargetClosedResponse> {
        let mut target = self
            .targets
            .remove(&request.target_id)
            .with_context(|| format!("unknown target id: {}", request.target_id))?;
        if target.kind() != DebuggerSessionKind::Live {
            bail!("target {} is not a live session", request.target_id);
        }
        target
            .worker
            .call("terminate", |session| session.terminate())?;
        target.worker.shutdown(false)?;
        Ok(TargetClosedResponse {
            target_id: request.target_id,
            closed: true,
            detached: false,
            terminated: true,
        })
    }

    pub fn wait_for_event(
        &self,
        request: TargetWaitRequest,
    ) -> anyhow::Result<DebuggerExecutionStatus> {
        let timeout_ms = request.timeout_ms;
        self.target(request.target_id)?
            .worker
            .call("wait_for_event", move |session| {
                session.wait_for_event(timeout_ms)
            })
    }

    pub fn continue_execution(
        &self,
        request: TargetRequest,
    ) -> anyhow::Result<DebuggerExecutionStatus> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        target
            .worker
            .call("continue_execution", |session| session.continue_execution())
    }

    pub fn step_into(&self, request: TargetRequest) -> anyhow::Result<DebuggerExecutionStatus> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        target
            .worker
            .call("step_into", |session| session.step_into())
    }

    pub fn step_over(&self, request: TargetRequest) -> anyhow::Result<DebuggerExecutionStatus> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        target
            .worker
            .call("step_over", |session| session.step_over())
    }

    pub fn continue_and_wait(
        &self,
        request: TargetContinueWaitRequest,
    ) -> anyhow::Result<TargetContinueWaitResponse> {
        validate_target_output_capture(&request)?;
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let timeout_ms = request.timeout_ms;
        let output_options =
            request
                .capture_debuggee_output
                .then(|| DebuggerOutputCaptureOptions {
                    started_at: Instant::now(),
                    max_records: request.max_output_records,
                    max_chars_per_record: request.max_output_chars,
                    max_total_chars: request.max_total_output_chars,
                });
        Ok(TargetContinueWaitResponse {
            target_id: request.target_id,
            run: target.worker.call("continue_and_wait", move |session| {
                session.continue_and_wait(timeout_ms, output_options)
            })?,
        })
    }

    pub fn core_registers(&self, request: TargetRequest) -> anyhow::Result<TargetRegisterState> {
        let target = self.target(request.target_id)?;
        Ok(TargetRegisterState {
            target_id: request.target_id,
            registers: target
                .worker
                .call("core_registers", |session| session.core_registers())?,
        })
    }

    pub fn last_event(&self, request: TargetRequest) -> anyhow::Result<TargetEventResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        Ok(TargetEventResponse {
            target_id: request.target_id,
            event: target
                .worker
                .call("last_event", |session| session.last_event())?,
        })
    }

    pub fn read_memory(
        &self,
        request: TargetMemoryReadRequest,
    ) -> anyhow::Result<TargetMemoryReadResponse> {
        let target = self.target(request.target_id)?;
        let address = request.address;
        let size = request.size;
        Ok(TargetMemoryReadResponse {
            target_id: request.target_id,
            memory: target.worker.call("read_memory", move |session| {
                session.read_memory(address, size)
            })?,
        })
    }

    pub fn memory_map(
        &self,
        request: TargetMemoryMapRequest,
    ) -> anyhow::Result<TargetMemoryMapResponse> {
        validate_target_memory_map_region_limit(request.region_limit)?;
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let region_limit = request.region_limit;
        Ok(TargetMemoryMapResponse {
            target_id: request.target_id,
            memory_map: target.worker.call("virtual_memory_map", move |session| {
                session.virtual_memory_map(region_limit)
            })?,
        })
    }

    pub fn inspect_address(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetAddressInspectionResponse> {
        let target = self.target(request.target_id)?;
        let address = request.address;
        Ok(TargetAddressInspectionResponse {
            target_id: request.target_id,
            inspection: target
                .worker
                .call("inspect_virtual_address", move |session| {
                    Ok(session.inspect_virtual_address(address))
                })?,
        })
    }

    pub fn list_threads(&self, request: TargetRequest) -> anyhow::Result<TargetThreadList> {
        let target = self.target(request.target_id)?;
        Ok(TargetThreadList {
            target_id: request.target_id,
            threads: target
                .worker
                .call("list_threads", |session| session.threads())?,
        })
    }

    pub fn thread_accounting(
        &self,
        request: TargetThreadAccountingRequest,
    ) -> anyhow::Result<TargetThreadAccountingResponse> {
        validate_target_thread_accounting_limit(request.max_threads)?;
        let target = self.target(request.target_id)?;
        let max_threads = request.max_threads;
        Ok(TargetThreadAccountingResponse {
            target_id: request.target_id,
            thread_accounting: target
                .worker
                .call("thread_accounting_snapshot", move |session| {
                    session.thread_accounting_snapshot(max_threads)
                })?,
        })
    }

    pub fn module_parameters(
        &self,
        request: TargetModuleParametersRequest,
    ) -> anyhow::Result<TargetModuleParametersResponse> {
        validate_target_module_parameter_bases(&request.module_base_addresses)?;
        let target = self.target(request.target_id)?;
        let module_base_addresses = request.module_base_addresses;
        Ok(TargetModuleParametersResponse {
            target_id: request.target_id,
            source: "dbgeng_idebugsymbols5_getmoduleparameters".to_string(),
            parameters: target.worker.call("module_parameters", move |session| {
                session.module_parameters(&module_base_addresses)
            })?,
            detail: "This bounded DbgEng symbol-readiness query applies only to supplied module base addresses. Its result describes debugger module metadata, not target timing; configured symbol paths can cause host-side symbol-resolution I/O.".to_string(),
        })
    }

    pub fn symbol_entry_range(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSymbolEntryRangeResponse> {
        let target = self.target(request.target_id)?;
        let address = request.address;
        Ok(TargetSymbolEntryRangeResponse {
            target_id: request.target_id,
            symbol_entry_range: target
                .worker
                .call("symbol_entry_range_by_offset", move |session| {
                    session.symbol_entry_range_by_offset(address)
                })?,
        })
    }

    pub fn list_modules(&self, request: TargetRequest) -> anyhow::Result<TargetModuleList> {
        let target = self.target(request.target_id)?;
        Ok(TargetModuleList {
            target_id: request.target_id,
            modules: target
                .worker
                .call("list_modules", |session| session.modules())?,
        })
    }

    pub fn symbol_by_offset(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSymbolResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = prefetch_target_address(target, request.address)?;
        let address = request.address;
        Ok(TargetSymbolResponse {
            target_id: request.target_id,
            symbol: target.worker.call("symbol_by_offset", move |session| {
                session.symbol_by_offset(address)
            })?,
            native_symbols,
        })
    }

    pub fn source_by_offset(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSourceResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = prefetch_target_address(target, request.address)?;
        let address = request.address;
        Ok(TargetSourceResponse {
            target_id: request.target_id,
            source: target.worker.call("source_by_offset", move |session| {
                session.source_by_offset(address)
            })?,
            native_symbols,
        })
    }

    pub fn stack_trace(
        &self,
        request: TargetStackTraceRequest,
    ) -> anyhow::Result<TargetStackTraceResponse> {
        let target = self.target(request.target_id)?;
        let max_frames = request.max_frames;
        Ok(TargetStackTraceResponse {
            target_id: request.target_id,
            frames: target.worker.call("stack_trace", move |session| {
                session.stack_trace(max_frames)
            })?,
        })
    }

    pub fn thread_context(
        &self,
        request: TargetThreadContextRequest,
    ) -> anyhow::Result<TargetThreadContextResponse> {
        let target = self.target(request.target_id)?;
        let engine_thread_id = request.engine_thread_id;
        let max_frames = request.max_frames;
        let disassembly_count = request.disassembly_count;
        Ok(TargetThreadContextResponse {
            target_id: request.target_id,
            context: target.worker.call("thread_context", move |session| {
                session.thread_context(engine_thread_id, max_frames, disassembly_count)
            })?,
        })
    }

    pub fn disassemble(
        &self,
        request: TargetDisassembleRequest,
    ) -> anyhow::Result<TargetDisassemblyResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = match request.address {
            Some(address) => prefetch_target_address(target, address)?,
            None => None,
        };
        let address = request.address;
        let count = request.count;
        Ok(TargetDisassemblyResponse {
            target_id: request.target_id,
            disassembly: target.worker.call("disassemble", move |session| {
                session.disassemble(address, count)
            })?,
            native_symbols,
        })
    }

    pub fn list_breakpoints(&self, request: TargetRequest) -> anyhow::Result<TargetBreakpointList> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        Ok(TargetBreakpointList {
            target_id: request.target_id,
            breakpoints: target
                .worker
                .call("list_breakpoints", |session| session.list_breakpoints())?,
        })
    }

    pub fn set_breakpoint(
        &self,
        request: TargetBreakpointSetRequest,
    ) -> anyhow::Result<TargetBreakpointChangeResponse> {
        validate_breakpoint_set_request(&request)?;
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let kind = request.kind.unwrap_or(TargetBreakpointKind::Code);
        let address = request.address;
        let symbol = request.symbol;
        let size = request.size.unwrap_or(1);
        let breakpoint = target
            .worker
            .call("set_breakpoint", move |session| match kind {
                TargetBreakpointKind::Code => match (address, symbol.as_deref()) {
                    (Some(address), None) => session.add_code_breakpoint(address),
                    (None, Some(symbol)) => session.add_code_breakpoint_expression(symbol),
                    _ => unreachable!("validated code breakpoint location"),
                },
                TargetBreakpointKind::Read => session.add_data_breakpoint(
                    address.context("data breakpoint requires an address")?,
                    size,
                    BREAK_READ,
                ),
                TargetBreakpointKind::Write => session.add_data_breakpoint(
                    address.context("data breakpoint requires an address")?,
                    size,
                    BREAK_WRITE,
                ),
                TargetBreakpointKind::Execute => session.add_data_breakpoint(
                    address.context("data breakpoint requires an address")?,
                    size,
                    BREAK_EXECUTE,
                ),
                TargetBreakpointKind::ReadWrite => session.add_data_breakpoint(
                    address.context("data breakpoint requires an address")?,
                    size,
                    BREAK_READ | BREAK_WRITE,
                ),
            })?;
        Ok(TargetBreakpointChangeResponse {
            target_id: request.target_id,
            breakpoint: Some(breakpoint),
            removed: false,
        })
    }

    pub fn set_breakpoint_enabled(
        &self,
        request: TargetBreakpointEnableRequest,
    ) -> anyhow::Result<TargetBreakpointChangeResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let breakpoint_id = request.breakpoint_id;
        let enabled = request.enabled;
        let breakpoint = target
            .worker
            .call("set_breakpoint_enabled", move |session| {
                session.set_breakpoint_enabled(breakpoint_id, enabled)
            })?;
        Ok(TargetBreakpointChangeResponse {
            target_id: request.target_id,
            breakpoint: Some(breakpoint),
            removed: false,
        })
    }

    pub fn remove_breakpoint(
        &self,
        request: TargetBreakpointRemoveRequest,
    ) -> anyhow::Result<TargetBreakpointChangeResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let breakpoint_id = request.breakpoint_id;
        target.worker.call("remove_breakpoint", move |session| {
            session.remove_breakpoint(breakpoint_id)
        })?;
        Ok(TargetBreakpointChangeResponse {
            target_id: request.target_id,
            breakpoint: None,
            removed: true,
        })
    }

    pub fn evaluate(
        &self,
        request: TargetExpressionRequest,
    ) -> anyhow::Result<TargetEvaluationResponse> {
        let target = self.target(request.target_id)?;
        let expression = request.expression;
        Ok(TargetEvaluationResponse {
            target_id: request.target_id,
            evaluation: target
                .worker
                .call("evaluate", move |session| session.evaluate(&expression))?,
        })
    }

    pub fn write_dump(
        &self,
        request: TargetWriteDumpRequest,
    ) -> anyhow::Result<TargetWriteDumpResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, target.kind())?;
        let options = DumpWriteOptions {
            path: request.path,
            kind: request.kind.into(),
            overwrite: request.overwrite,
        };
        Ok(TargetWriteDumpResponse {
            target_id: request.target_id,
            dump: target
                .worker
                .call("write_dump", move |session| session.write_dump(options))?,
        })
    }

    fn insert_target(
        &mut self,
        session: DebuggerSession,
        native_symbols: Value,
        native_symbol_options: Option<NativeSymbolOptions>,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let target_id = self.allocate_target_id();
        let target = session.summary();
        let worker = EngineWorker::new(session)?;
        self.targets.insert(
            target_id,
            ManagedTarget {
                worker,
                native_symbols: native_symbols.clone(),
                native_symbol_options,
            },
        );
        Ok(TargetOpenedResponse {
            target_id,
            target,
            native_symbols,
        })
    }

    fn allocate_target_id(&mut self) -> TargetId {
        self.next_target_id += 1;
        self.next_target_id
    }

    fn target(&self, target_id: TargetId) -> anyhow::Result<&ManagedTarget> {
        self.targets
            .get(&target_id)
            .with_context(|| format!("unknown target id: {target_id}"))
    }
}

fn default_live_wait_timeout_ms() -> u32 {
    5000
}

fn default_native_symbol_cache() -> PathBuf {
    PathBuf::from(".windbg-symbol-cache")
}

fn prefetch_target_address(target: &ManagedTarget, address: u64) -> anyhow::Result<Option<Value>> {
    let Some(options) = target.native_symbol_options.clone() else {
        return Ok(None);
    };
    target
        .worker
        .call("prefetch_dump_symbols", move |session| {
            Ok(prefetch_dump_symbols(
                session,
                Some(address),
                &options.cache_dir,
                &options.image_paths,
                options.offline,
            ))
        })
        .map(Some)
}

fn prefetch_dump_symbols(
    session: &DebuggerSession,
    address_override: Option<u64>,
    cache_dir: &PathBuf,
    extra_image_paths: &[PathBuf],
    offline: bool,
) -> Value {
    let fault_address = address_override.or_else(|| {
        session
            .bugcheck_data()
            .data
            .and_then(|data| (data.code == 0x0000_003B).then_some(data.parameters[1]))
            .or_else(|| {
                session
                    .core_registers()
                    .ok()
                    .and_then(|registers| registers.instruction_offset)
            })
    });
    let Some(fault_address) = fault_address else {
        return json!({
            "status": "not_applicable",
            "detail": "No supported dump fault module was available for native symbol prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let Some(module) = session.module_by_offset(fault_address).ok().flatten() else {
        return json!({"status": "unavailable", "detail": "DbgEng could not map the fault address to a module."});
    };
    let Some(parameters) = session
        .module_parameters(&[module.base_address])
        .ok()
        .and_then(|mut values| values.pop())
    else {
        return json!({"status": "unavailable", "module": module, "detail": "DbgEng did not provide module identity metadata."});
    };
    let mut roots = extra_image_paths.to_vec();
    if let Some(system_root) = env::var_os("SystemRoot").map(PathBuf::from) {
        roots.push(system_root.join("System32"));
        roots.push(system_root.join("System32").join("drivers"));
    }
    let mut deduplicated_roots = Vec::new();
    for root in roots {
        if !deduplicated_roots.contains(&root) {
            deduplicated_roots.push(root);
        }
    }
    let mut image_names = Vec::new();
    for name in [
        module.image_name.as_deref(),
        module.loaded_image_name.as_deref(),
        module.symbol_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some(file_name) = Path::new(name).file_name().map(|name| name.to_owned()) else {
            continue;
        };
        if !image_names.contains(&file_name) {
            image_names.push(file_name);
        }
    }
    let Some(image_name) = image_names.first().and_then(|name| name.to_str()) else {
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
    for root in &deduplicated_roots {
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
                        "image_search_paths": deduplicated_roots,
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
                    "image_search_paths": deduplicated_roots,
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
    let pdb_dir = pdb_path
        .parent()
        .expect("PDB path has parent")
        .to_path_buf();
    let reload = session
        .configure_local_symbol_paths(std::slice::from_ref(&pdb_dir), &[image_directory])
        .and_then(|()| {
            module
                .module_name
                .as_deref()
                .context("DbgEng did not provide a fault-module name")
                .and_then(|name| session.refresh_symbols(name))
        });
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
        "pdb_directory": pdb_dir,
        "prefetch": prefetch,
        "forced_reload": match reload {
            Ok(()) => json!({"status": "loaded"}),
            Err(error) => json!({"status": "failed", "detail": format!("{error:#}")}),
        },
        "resolved_fault_symbol": session.symbol_by_offset(fault_address).ok().flatten(),
        "offline": offline,
    })
}

const BREAK_READ: u32 = 1;
const BREAK_WRITE: u32 = 2;
const BREAK_EXECUTE: u32 = 4;

fn default_target_stack_frames() -> u32 {
    32
}

fn default_target_memory_map_regions() -> u32 {
    256
}

fn default_target_thread_accounting_threads() -> u32 {
    32
}

fn default_target_output_records() -> u32 {
    32
}

fn default_target_output_chars() -> u32 {
    512
}

fn default_target_output_total_chars() -> u32 {
    8192
}

fn validate_target_memory_map_region_limit(region_limit: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_VIRTUAL_MEMORY_MAP_REGIONS).contains(&region_limit),
        "target memory-map region_limit must be from 1 through {MAX_VIRTUAL_MEMORY_MAP_REGIONS}"
    );
    Ok(())
}

fn validate_target_thread_accounting_limit(max_threads: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_THREAD_ACCOUNTING_THREADS).contains(&max_threads),
        "target thread-accounting max_threads must be from 1 through {MAX_THREAD_ACCOUNTING_THREADS}"
    );
    Ok(())
}

fn validate_target_module_parameter_bases(base_addresses: &[u64]) -> anyhow::Result<()> {
    ensure!(
        !base_addresses.is_empty(),
        "target module-parameters requires at least one module base address"
    );
    ensure!(
        base_addresses.len() <= MAX_MODULE_PARAMETER_QUERIES,
        "target module-parameters supports at most {MAX_MODULE_PARAMETER_QUERIES} module base addresses"
    );
    let mut unique_bases = base_addresses.to_vec();
    unique_bases.sort_unstable();
    unique_bases.dedup();
    ensure!(
        unique_bases.len() == base_addresses.len(),
        "target module-parameters requires distinct module base addresses"
    );
    Ok(())
}

fn validate_target_output_capture(request: &TargetContinueWaitRequest) -> anyhow::Result<()> {
    if !request.capture_debuggee_output {
        return Ok(());
    }
    ensure!(
        (1..=128).contains(&request.max_output_records),
        "target continue-wait max_output_records must be from 1 through 128"
    );
    ensure!(
        (1..=4096).contains(&request.max_output_chars),
        "target continue-wait max_output_chars must be from 1 through 4096"
    );
    ensure!(
        (1..=32768).contains(&request.max_total_output_chars),
        "target continue-wait max_total_output_chars must be from 1 through 32768"
    );
    Ok(())
}

fn validate_breakpoint_set_request(request: &TargetBreakpointSetRequest) -> anyhow::Result<()> {
    ensure!(
        request.address.is_some() != request.symbol.is_some(),
        "target breakpoint requires exactly one of address or symbol"
    );
    let kind = request.kind.clone().unwrap_or(TargetBreakpointKind::Code);
    if request.symbol.is_some() {
        ensure!(
            matches!(kind, TargetBreakpointKind::Code),
            "target symbol breakpoints only support kind=code"
        );
        ensure!(
            request
                .symbol
                .as_deref()
                .is_some_and(|symbol| !symbol.trim().is_empty()),
            "target symbol breakpoint expression cannot be empty"
        );
    }
    Ok(())
}

fn default_target_disasm_count() -> u32 {
    16
}

fn ensure_live_target(target_id: TargetId, kind: DebuggerSessionKind) -> anyhow::Result<()> {
    if kind != DebuggerSessionKind::Live {
        bail!("target {target_id} is not a live session")
    }
    Ok(())
}

impl From<TargetDumpKind> for DumpKind {
    fn from(kind: TargetDumpKind) -> Self {
        match kind {
            TargetDumpKind::Mini => DumpKind::Mini,
            TargetDumpKind::Full => DumpKind::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_memory_map_region_limit_before_accessing_a_target() {
        assert!(validate_target_memory_map_region_limit(1).is_ok());
        assert!(validate_target_memory_map_region_limit(MAX_VIRTUAL_MEMORY_MAP_REGIONS).is_ok());
        assert!(validate_target_memory_map_region_limit(0).is_err());
        assert!(
            validate_target_memory_map_region_limit(MAX_VIRTUAL_MEMORY_MAP_REGIONS + 1).is_err()
        );
    }

    #[test]
    fn validates_thread_accounting_limit_before_accessing_a_target() {
        assert!(validate_target_thread_accounting_limit(1).is_ok());
        assert!(validate_target_thread_accounting_limit(MAX_THREAD_ACCOUNTING_THREADS).is_ok());
        assert!(validate_target_thread_accounting_limit(0).is_err());
        assert!(
            validate_target_thread_accounting_limit(MAX_THREAD_ACCOUNTING_THREADS + 1).is_err()
        );
    }

    #[test]
    fn validates_module_parameter_bases_before_accessing_a_target() {
        assert!(validate_target_module_parameter_bases(&[0x1000]).is_ok());
        assert!(validate_target_module_parameter_bases(&[]).is_err());
        assert!(validate_target_module_parameter_bases(&[0x1000, 0x1000]).is_err());
        assert!(validate_target_module_parameter_bases(
            &(0..=MAX_MODULE_PARAMETER_QUERIES as u64).collect::<Vec<_>>()
        )
        .is_err());
    }

    #[test]
    fn validates_address_or_deferred_symbol_breakpoint_locations() {
        let address = TargetBreakpointSetRequest {
            target_id: 1,
            address: Some(0x1000),
            symbol: None,
            kind: Some(TargetBreakpointKind::Code),
            size: None,
        };
        assert!(validate_breakpoint_set_request(&address).is_ok());

        let symbol = TargetBreakpointSetRequest {
            target_id: 1,
            address: None,
            symbol: Some("kernel32!CreateFileW".to_string()),
            kind: Some(TargetBreakpointKind::Code),
            size: None,
        };
        assert!(validate_breakpoint_set_request(&symbol).is_ok());

        let mut invalid = symbol.clone();
        invalid.address = Some(0x1000);
        assert!(validate_breakpoint_set_request(&invalid).is_err());
        invalid.address = None;
        invalid.symbol = Some("  ".to_string());
        assert!(validate_breakpoint_set_request(&invalid).is_err());
        invalid.symbol = Some("kernel32!CreateFileW".to_string());
        invalid.kind = Some(TargetBreakpointKind::Write);
        assert!(validate_breakpoint_set_request(&invalid).is_err());
    }

    #[test]
    fn validates_output_capture_bounds_only_when_enabled() {
        let disabled = TargetContinueWaitRequest {
            target_id: 1,
            timeout_ms: 1,
            capture_debuggee_output: false,
            max_output_records: 0,
            max_output_chars: 0,
            max_total_output_chars: 0,
        };
        assert!(validate_target_output_capture(&disabled).is_ok());

        let enabled = TargetContinueWaitRequest {
            capture_debuggee_output: true,
            ..disabled
        };
        assert!(validate_target_output_capture(&enabled).is_err());
    }
}
