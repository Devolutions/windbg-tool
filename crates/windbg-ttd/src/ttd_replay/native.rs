use super::types::{
    ActiveThreadState, CursorRegisters, CursorThreadState, IndexBuildProgress, IndexStatsResponse,
    IndexStatusResponse, IndexTreeStats, MemoryAccessDirection, MemoryAccessKind, MemoryAccessMask,
    MemoryBufferRange, MemoryBufferResponse, MemoryRangeResponse, MemoryWatchpointRequest,
    MemoryWatchpointResponse, ModuleEventKind, QueryMemoryPolicy, ReadMemoryResponse,
    RegisterContextResponse, StepDirection, StepKind, StepResult, ThreadEventKind, TraceException,
    TraceFileInfo, TraceListEntry, TraceListResponse, TraceModule, TraceModuleEvent, TraceThread,
    TraceThreadEvent, VectorRegister128, VectorRegister256, X64RegisterSet,
};
use super::{Position, ResolvedSymbolConfig};
use anyhow::{bail, Context};
use libloading::{Library, Symbol};
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

const NATIVE_BRIDGE_DLL: &str = "ttd_replay_bridge.dll";
const TTD_MCP_OK: i32 = 0;
const MODULE_NAME_CHARS: usize = 260;
const MODULE_PATH_CHARS: usize = 1024;
const TRACE_FILE_CHARS: usize = 1024;
const EXCEPTION_PARAMETER_COUNT: usize = 15;

#[repr(C)]
struct TtdMcpTrace;

#[repr(C)]
struct TtdMcpCursor;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpPosition {
    sequence: u64,
    steps: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TtdMcpTraceInfo {
    first_position: TtdMcpPosition,
    last_position: TtdMcpPosition,
    peb_address: u64,
    process_id: u32,
    thread_count: u32,
    module_count: u32,
    module_instance_count: u32,
    exception_count: u32,
    keyframe_count: u32,
}

#[repr(C)]
struct TtdMcpSymbolConfig {
    symbol_path: *const u16,
    image_path: *const u16,
    symbol_cache_dir: *const u16,
    symbol_runtime_dir: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TtdMcpTraceFileInfo {
    file_type: u32,
    file_name: [u16; TRACE_FILE_CHARS],
    companion_file_name: [u16; TRACE_FILE_CHARS],
    trace_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpTraceListEntry {
    session_id: TtdMcpGuid,
    group_id: TtdMcpGuid,
    recording_type: u32,
    file_info: TtdMcpTraceFileInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpIndexBuildProgress {
    keyframe_count: u32,
    keyframes_processed: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpIndexTreeStats {
    page_size: u64,
    page_count: u64,
    inner_page_count: u64,
    inner_page_entry_count: u64,
    inner_page_entry_capacity: u64,
    inner_page_entry_size: u64,
    leaf_page_count: u64,
    leaf_page_entry_count: u64,
    leaf_page_entry_capacity: u64,
    leaf_page_entry_size: u64,
    maximum_leaf_depth: u64,
    sum_of_leaf_depths: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpIndexFileStats {
    global_memory: TtdMcpIndexTreeStats,
    segment_memory: TtdMcpIndexTreeStats,
    map_page_call_count: u64,
    lock_page_call_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpThreadInfo {
    unique_id: u64,
    thread_id: u32,
    lifetime_start: TtdMcpPosition,
    lifetime_end: TtdMcpPosition,
    active_start: TtdMcpPosition,
    active_end: TtdMcpPosition,
    has_active_time: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TtdMcpModuleInfo {
    name: [u16; MODULE_NAME_CHARS],
    path: [u16; MODULE_PATH_CHARS],
    base_address: u64,
    size: u64,
    load_position: TtdMcpPosition,
    unload_position: TtdMcpPosition,
    has_unload_position: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpExceptionInfo {
    position: TtdMcpPosition,
    thread_unique_id: u64,
    code: u32,
    flags: u32,
    program_counter: u64,
    record_address: u64,
    parameter_count: u32,
    parameters: [u64; EXCEPTION_PARAMETER_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpModuleEventInfo {
    kind: u8,
    position: TtdMcpPosition,
    module: TtdMcpModuleInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpThreadEventInfo {
    kind: u8,
    position: TtdMcpPosition,
    thread: TtdMcpThreadInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryRead {
    address: u64,
    bytes_read: u32,
    complete: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpCursorState {
    position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    thread_unique_id: u64,
    thread_id: u32,
    teb_address: u64,
    program_counter: u64,
    stack_pointer: u64,
    frame_pointer: u64,
    basic_return_value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpVector128 {
    low: u64,
    high: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpX64Context {
    position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    thread_unique_id: u64,
    thread_id: u32,
    teb_address: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    vector_control: u64,
    debug_control: u64,
    last_branch_to_rip: u64,
    last_branch_from_rip: u64,
    last_exception_to_rip: u64,
    last_exception_from_rip: u64,
    xmm: [TtdMcpVector128; 16],
    ymm_high: [TtdMcpVector128; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpActiveThreadInfo {
    thread: TtdMcpThreadInfo,
    current_position: TtdMcpPosition,
    last_valid_position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    has_last_valid_position: u8,
    has_previous_position: u8,
    teb_address: u64,
    program_counter: u64,
    stack_pointer: u64,
    frame_pointer: u64,
    basic_return_value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryRangeInfo {
    address: u64,
    bytes_available: u64,
    bytes_copied: u32,
    sequence: u64,
    complete: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryBufferInfo {
    address: u64,
    bytes_read: u32,
    range_count: u32,
    ranges_copied: u32,
    complete: u8,
    ranges_truncated: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryBufferRangeInfo {
    address: u64,
    size: u64,
    sequence: u64,
    offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpStepResult {
    position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    stop_reason: u32,
    steps_executed: u64,
    instructions_executed: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryWatchpointResult {
    position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    stop_reason: u32,
    found: u8,
    thread_unique_id: u64,
    thread_id: u32,
    program_counter: u64,
    match_address: u64,
    match_size: u64,
    match_access: u32,
}

type OpenTraceFn =
    unsafe extern "C" fn(*const u16, *const TtdMcpSymbolConfig, *mut *mut TtdMcpTrace) -> i32;
type OpenTraceAtIndexFn = unsafe extern "C" fn(
    *const u16,
    *const u16,
    u32,
    *const TtdMcpSymbolConfig,
    *mut *mut TtdMcpTrace,
) -> i32;
type CloseTraceFn = unsafe extern "C" fn(*mut TtdMcpTrace);
type ListTracesFn =
    unsafe extern "C" fn(*const u16, *const u16, *mut TtdMcpTraceListEntry, u32, *mut u32) -> i32;
type IndexStatusFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut u32) -> i32;
type IndexFileStatsFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpIndexFileStats) -> i32;
type BuildIndexFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, u32, *mut TtdMcpIndexBuildProgress, *mut u32) -> i32;
type TraceInfoFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpTraceInfo) -> i32;
type ListThreadsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpThreadInfo, u32, *mut u32) -> i32;
type ListModulesFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpModuleInfo, u32, *mut u32) -> i32;
type ListExceptionsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpExceptionInfo, u32, *mut u32) -> i32;
type ListKeyframesFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpPosition, u32, *mut u32) -> i32;
type ListModuleEventsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpModuleEventInfo, u32, *mut u32) -> i32;
type ListThreadEventsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpThreadEventInfo, u32, *mut u32) -> i32;
type NewCursorFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut *mut TtdMcpCursor) -> i32;
type FreeCursorFn = unsafe extern "C" fn(*mut TtdMcpCursor);
type CursorPositionFn = unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpPosition) -> i32;
type SetPositionFn = unsafe extern "C" fn(*mut TtdMcpCursor, TtdMcpPosition) -> i32;
type SetPositionOnThreadFn = unsafe extern "C" fn(*mut TtdMcpCursor, u32, TtdMcpPosition) -> i32;
type ReadMemoryFn =
    unsafe extern "C" fn(*mut TtdMcpCursor, u64, *mut u8, u32, u32, *mut TtdMcpMemoryRead) -> i32;
type QueryMemoryRangeFn = unsafe extern "C" fn(
    *mut TtdMcpCursor,
    u64,
    *mut u8,
    u32,
    u32,
    *mut TtdMcpMemoryRangeInfo,
) -> i32;
type QueryMemoryBufferWithRangesFn = unsafe extern "C" fn(
    *mut TtdMcpCursor,
    u64,
    *mut u8,
    u32,
    *mut TtdMcpMemoryBufferRangeInfo,
    u32,
    u32,
    *mut TtdMcpMemoryBufferInfo,
) -> i32;
type CursorStateFn = unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpCursorState) -> i32;
type X64ContextFn = unsafe extern "C" fn(*mut TtdMcpCursor, u32, *mut TtdMcpX64Context) -> i32;
type ActiveThreadsFn =
    unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpActiveThreadInfo, u32, *mut u32) -> i32;
type CursorModulesFn =
    unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpModuleInfo, u32, *mut u32) -> i32;
type StepCursorFn =
    unsafe extern "C" fn(*mut TtdMcpCursor, u32, u32, u8, *mut TtdMcpStepResult) -> i32;
type MemoryWatchpointFn = unsafe extern "C" fn(
    *mut TtdMcpCursor,
    u64,
    u32,
    u32,
    u32,
    u64,
    *mut TtdMcpMemoryWatchpointResult,
) -> i32;
type LastErrorFn = unsafe extern "C" fn() -> *const i8;

pub struct NativeBridge {
    library: Library,
}

pub struct NativeTrace {
    bridge: Arc<NativeBridge>,
    handle: NonNull<TtdMcpTrace>,
}

pub struct NativeCursor {
    bridge: Arc<NativeBridge>,
    handle: NonNull<TtdMcpCursor>,
}

unsafe impl Send for NativeBridge {}
unsafe impl Sync for NativeBridge {}
unsafe impl Send for NativeTrace {}
unsafe impl Send for NativeCursor {}

impl NativeBridge {
    pub fn load() -> anyhow::Result<Arc<Self>> {
        let mut errors = Vec::new();
        for path in bridge_candidates() {
            if !path.is_file() {
                continue;
            }

            add_dll_search_paths(&path);
            let library = unsafe { Library::new(&path) };
            match library {
                Ok(library) => return Ok(Arc::new(Self { library })),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }

        if errors.is_empty() {
            bail!("native TTD replay bridge DLL was not found; run cargo xtask native-build")
        }

        bail!(
            "failed to load native TTD replay bridge: {}",
            errors.join("; ")
        )
    }

    pub fn open_trace(
        self: &Arc<Self>,
        trace_path: &Path,
        symbols: &ResolvedSymbolConfig,
    ) -> anyhow::Result<NativeTrace> {
        let trace_path = wide_path(trace_path);
        let symbol_path = wide_str(&symbols.symbol_path);
        let image_path = wide_str(&symbols.image_path);
        let symbol_cache_dir = wide_path(&symbols.symbol_cache_dir);
        let symbol_runtime_dir = symbols
            .symbol_runtime_dir
            .as_ref()
            .map(|path| wide_path(path))
            .unwrap_or_else(wide_empty);

        let config = TtdMcpSymbolConfig {
            symbol_path: symbol_path.as_ptr(),
            image_path: image_path.as_ptr(),
            symbol_cache_dir: symbol_cache_dir.as_ptr(),
            symbol_runtime_dir: symbol_runtime_dir.as_ptr(),
        };

        let mut handle = std::ptr::null_mut();
        let open_trace: Symbol<OpenTraceFn> = unsafe { self.symbol(b"ttd_mcp_open_trace\0")? };
        let status = unsafe { open_trace(trace_path.as_ptr(), &config, &mut handle) };
        self.ensure_ok(status, "opening TTD trace")?;
        let handle = NonNull::new(handle).context("native bridge returned a null trace handle")?;

        Ok(NativeTrace {
            bridge: Arc::clone(self),
            handle,
        })
    }

    pub fn open_trace_at_index(
        self: &Arc<Self>,
        trace_path: &Path,
        companion_path: Option<&Path>,
        trace_index: u32,
        symbols: &ResolvedSymbolConfig,
    ) -> anyhow::Result<NativeTrace> {
        let trace_path = wide_path(trace_path);
        let companion_path = companion_path.map(wide_path).unwrap_or_else(wide_empty);
        let symbol_path = wide_str(&symbols.symbol_path);
        let image_path = wide_str(&symbols.image_path);
        let symbol_cache_dir = wide_path(&symbols.symbol_cache_dir);
        let symbol_runtime_dir = symbols
            .symbol_runtime_dir
            .as_ref()
            .map(|path| wide_path(path))
            .unwrap_or_else(wide_empty);

        let config = TtdMcpSymbolConfig {
            symbol_path: symbol_path.as_ptr(),
            image_path: image_path.as_ptr(),
            symbol_cache_dir: symbol_cache_dir.as_ptr(),
            symbol_runtime_dir: symbol_runtime_dir.as_ptr(),
        };

        let mut handle = std::ptr::null_mut();
        let open_trace_at_index: Symbol<OpenTraceAtIndexFn> =
            unsafe { self.symbol(b"ttd_mcp_open_trace_at_index\0")? };
        let status = unsafe {
            open_trace_at_index(
                trace_path.as_ptr(),
                companion_path.as_ptr(),
                trace_index,
                &config,
                &mut handle,
            )
        };
        self.ensure_ok(status, "opening TTD trace from trace list")?;
        let handle = NonNull::new(handle).context("native bridge returned a null trace handle")?;

        Ok(NativeTrace {
            bridge: Arc::clone(self),
            handle,
        })
    }

    pub fn list_traces(
        &self,
        trace_path: &Path,
        companion_path: Option<&Path>,
    ) -> anyhow::Result<TraceListResponse> {
        let trace_path_wide = wide_path(trace_path);
        let companion_path_wide = companion_path.map(wide_path).unwrap_or_else(wide_empty);
        let list_traces: Symbol<ListTracesFn> = unsafe { self.symbol(b"ttd_mcp_list_traces\0")? };
        let mut count = 0;
        let status = unsafe {
            list_traces(
                trace_path_wide.as_ptr(),
                companion_path_wide.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut count,
            )
        };
        self.ensure_ok(status, "querying trace-list count")?;

        let mut traces = vec![TtdMcpTraceListEntry::default(); count as usize];
        let status = unsafe {
            list_traces(
                trace_path_wide.as_ptr(),
                companion_path_wide.as_ptr(),
                traces.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.ensure_ok(status, "listing traces")?;
        traces.truncate(count as usize);

        Ok(TraceListResponse {
            trace_path: trace_path.to_path_buf(),
            companion_path: companion_path.map(Path::to_path_buf),
            trace_count: traces.len(),
            traces: traces.into_iter().map(TraceListEntry::from).collect(),
        })
    }

    unsafe fn symbol<T>(&self, name: &[u8]) -> anyhow::Result<Symbol<'_, T>> {
        self.library
            .get(name)
            .with_context(|| format!("loading native symbol {}", String::from_utf8_lossy(name)))
    }

    fn ensure_ok(&self, status: i32, operation: &str) -> anyhow::Result<()> {
        if status == TTD_MCP_OK {
            return Ok(());
        }

        bail!(
            "native bridge failed while {operation}: {}",
            self.last_error()
        )
    }

    fn last_error(&self) -> String {
        let last_error: anyhow::Result<Symbol<LastErrorFn>> =
            unsafe { self.symbol(b"ttd_mcp_last_error\0") };
        let Ok(last_error) = last_error else {
            return "native bridge did not expose ttd_mcp_last_error".to_string();
        };

        let pointer = unsafe { last_error() };
        if pointer.is_null() {
            return "native bridge did not provide an error string".to_string();
        }

        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

impl NativeTrace {
    pub fn trace_info(&self) -> anyhow::Result<TtdMcpTraceInfo> {
        let trace_info: Symbol<TraceInfoFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_trace_info\0")? };
        let mut info = TtdMcpTraceInfo::default();

        let status = unsafe { trace_info(self.handle.as_ptr(), &mut info) };
        self.bridge.ensure_ok(status, "reading trace info")?;
        Ok(info)
    }

    pub fn index_status(&self, session_id: u64) -> anyhow::Result<IndexStatusResponse> {
        let index_status: Symbol<IndexStatusFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_index_status\0")? };
        let mut raw_status = 0;
        let status = unsafe { index_status(self.handle.as_ptr(), &mut raw_status) };
        self.bridge.ensure_ok(status, "reading index status")?;
        Ok(IndexStatusResponse {
            session_id,
            status: index_status_name(raw_status).to_string(),
            raw_status,
        })
    }

    pub fn index_file_stats(&self, session_id: u64) -> anyhow::Result<IndexStatsResponse> {
        let index_file_stats: Symbol<IndexFileStatsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_index_file_stats\0")? };
        let mut stats = TtdMcpIndexFileStats::default();
        let status = unsafe { index_file_stats(self.handle.as_ptr(), &mut stats) };
        self.bridge.ensure_ok(status, "reading index file stats")?;
        Ok(IndexStatsResponse {
            session_id,
            global_memory: stats.global_memory.into(),
            segment_memory: stats.segment_memory.into(),
            map_page_call_count: stats.map_page_call_count,
            lock_page_call_count: stats.lock_page_call_count,
        })
    }

    pub fn build_index(
        &self,
        session_id: u64,
        raw_flags: u32,
        flags: Vec<String>,
    ) -> anyhow::Result<super::types::IndexBuildResponse> {
        let build_index: Symbol<BuildIndexFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_build_index\0")? };
        let mut progress = TtdMcpIndexBuildProgress::default();
        let mut raw_status = 0;
        let status = unsafe {
            build_index(
                self.handle.as_ptr(),
                raw_flags,
                &mut progress,
                &mut raw_status,
            )
        };
        self.bridge.ensure_ok(status, "building index")?;
        Ok(super::types::IndexBuildResponse {
            session_id,
            status: index_status_name(raw_status).to_string(),
            raw_status,
            flags,
            raw_flags,
            progress: progress.into(),
        })
    }

    pub fn new_cursor(&self) -> anyhow::Result<NativeCursor> {
        let new_cursor: Symbol<NewCursorFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_new_cursor\0")? };
        let mut handle = std::ptr::null_mut();
        let status = unsafe { new_cursor(self.handle.as_ptr(), &mut handle) };
        self.bridge.ensure_ok(status, "creating replay cursor")?;
        let handle = NonNull::new(handle).context("native bridge returned a null cursor handle")?;

        Ok(NativeCursor {
            bridge: Arc::clone(&self.bridge),
            handle,
        })
    }

    pub fn list_threads(&self) -> anyhow::Result<Vec<TraceThread>> {
        let list_threads: Symbol<ListThreadsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_threads\0")? };
        let mut count = 0;
        let status =
            unsafe { list_threads(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying thread count")?;

        let mut threads = vec![TtdMcpThreadInfo::default(); count as usize];
        let status = unsafe {
            list_threads(
                self.handle.as_ptr(),
                threads.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing threads")?;
        threads.truncate(count as usize);
        Ok(threads.into_iter().map(TraceThread::from).collect())
    }

    pub fn list_modules(&self) -> anyhow::Result<Vec<TraceModule>> {
        let list_modules: Symbol<ListModulesFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_modules\0")? };
        let mut count = 0;
        let status =
            unsafe { list_modules(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying module count")?;

        let mut modules = vec![TtdMcpModuleInfo::default(); count as usize];
        let status = unsafe {
            list_modules(
                self.handle.as_ptr(),
                modules.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing modules")?;
        modules.truncate(count as usize);
        Ok(modules.into_iter().map(TraceModule::from).collect())
    }

    pub fn list_exceptions(&self) -> anyhow::Result<Vec<TraceException>> {
        let list_exceptions: Symbol<ListExceptionsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_exceptions\0")? };
        let mut count = 0;
        let status =
            unsafe { list_exceptions(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying exception count")?;

        let mut exceptions = vec![TtdMcpExceptionInfo::default(); count as usize];
        let status = unsafe {
            list_exceptions(
                self.handle.as_ptr(),
                exceptions.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing exceptions")?;
        exceptions.truncate(count as usize);
        Ok(exceptions.into_iter().map(TraceException::from).collect())
    }

    pub fn list_keyframes(&self) -> anyhow::Result<Vec<Position>> {
        let list_keyframes: Symbol<ListKeyframesFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_keyframes\0")? };
        let mut count = 0;
        let status =
            unsafe { list_keyframes(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying keyframe count")?;

        let mut keyframes = vec![TtdMcpPosition::default(); count as usize];
        let status = unsafe {
            list_keyframes(
                self.handle.as_ptr(),
                keyframes.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing keyframes")?;
        keyframes.truncate(count as usize);
        Ok(keyframes.into_iter().map(Position::from).collect())
    }

    pub fn list_module_events(&self) -> anyhow::Result<Vec<TraceModuleEvent>> {
        let list_module_events: Symbol<ListModuleEventsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_module_events\0")? };
        let mut count = 0;
        let status = unsafe {
            list_module_events(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count)
        };
        self.bridge
            .ensure_ok(status, "querying module event count")?;

        let mut events = vec![TtdMcpModuleEventInfo::default(); count as usize];
        let status = unsafe {
            list_module_events(self.handle.as_ptr(), events.as_mut_ptr(), count, &mut count)
        };
        self.bridge.ensure_ok(status, "listing module events")?;
        events.truncate(count as usize);
        Ok(events.into_iter().map(TraceModuleEvent::from).collect())
    }

    pub fn list_thread_events(&self) -> anyhow::Result<Vec<TraceThreadEvent>> {
        let list_thread_events: Symbol<ListThreadEventsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_thread_events\0")? };
        let mut count = 0;
        let status = unsafe {
            list_thread_events(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count)
        };
        self.bridge
            .ensure_ok(status, "querying thread event count")?;

        let mut events = vec![TtdMcpThreadEventInfo::default(); count as usize];
        let status = unsafe {
            list_thread_events(self.handle.as_ptr(), events.as_mut_ptr(), count, &mut count)
        };
        self.bridge.ensure_ok(status, "listing thread events")?;
        events.truncate(count as usize);
        Ok(events.into_iter().map(TraceThreadEvent::from).collect())
    }
}

impl Drop for NativeTrace {
    fn drop(&mut self) {
        let close_trace: anyhow::Result<Symbol<CloseTraceFn>> =
            unsafe { self.bridge.symbol(b"ttd_mcp_close_trace\0") };
        if let Ok(close_trace) = close_trace {
            unsafe { close_trace(self.handle.as_ptr()) };
        }
    }
}

impl NativeCursor {
    pub fn position(&self) -> anyhow::Result<Position> {
        let cursor_position: Symbol<CursorPositionFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_cursor_position\0")? };
        let mut position = TtdMcpPosition {
            sequence: 0,
            steps: 0,
        };
        let status = unsafe { cursor_position(self.handle.as_ptr(), &mut position) };
        self.bridge.ensure_ok(status, "reading cursor position")?;
        Ok(position.into())
    }

    pub fn set_position(&self, position: Position) -> anyhow::Result<()> {
        let set_position: Symbol<SetPositionFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_set_position\0")? };
        let status = unsafe { set_position(self.handle.as_ptr(), position.into()) };
        self.bridge.ensure_ok(status, "setting cursor position")
    }

    pub fn set_position_on_thread(
        &self,
        thread_unique_id: u32,
        position: Position,
    ) -> anyhow::Result<()> {
        let set_position_on_thread: Symbol<SetPositionOnThreadFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_set_position_on_thread\0")? };
        let status = unsafe {
            set_position_on_thread(self.handle.as_ptr(), thread_unique_id, position.into())
        };
        self.bridge
            .ensure_ok(status, "setting cursor position on thread")
    }

    pub fn read_memory(
        &self,
        session_id: u64,
        cursor_id: u64,
        address: u64,
        size: u32,
        policy: QueryMemoryPolicy,
    ) -> anyhow::Result<ReadMemoryResponse> {
        let read_memory: Symbol<ReadMemoryFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_read_memory\0")? };
        let mut buffer = vec![0; size as usize];
        let mut result = TtdMcpMemoryRead::default();
        let status = unsafe {
            read_memory(
                self.handle.as_ptr(),
                address,
                buffer.as_mut_ptr(),
                size,
                query_memory_policy_code(policy),
                &mut result,
            )
        };
        self.bridge.ensure_ok(status, "reading cursor memory")?;

        let bytes_read = (result.bytes_read as usize).min(buffer.len());
        buffer.truncate(bytes_read);
        Ok(ReadMemoryResponse {
            session_id,
            cursor_id,
            requested_address: address,
            address: result.address,
            requested_size: size,
            bytes_read,
            complete: result.complete != 0,
            policy,
            encoding: "hex".to_string(),
            data: bytes_to_hex(&buffer),
        })
    }

    pub fn memory_range(
        &self,
        session_id: u64,
        cursor_id: u64,
        address: u64,
        max_bytes: u32,
        policy: QueryMemoryPolicy,
    ) -> anyhow::Result<MemoryRangeResponse> {
        let query_memory_range: Symbol<QueryMemoryRangeFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_query_memory_range\0")? };
        let mut buffer = vec![0; max_bytes as usize];
        let mut result = TtdMcpMemoryRangeInfo::default();
        let status = unsafe {
            query_memory_range(
                self.handle.as_ptr(),
                address,
                buffer.as_mut_ptr(),
                max_bytes,
                query_memory_policy_code(policy),
                &mut result,
            )
        };
        self.bridge
            .ensure_ok(status, "querying cursor memory range")?;

        let bytes_returned = (result.bytes_copied as usize).min(buffer.len());
        buffer.truncate(bytes_returned);
        Ok(MemoryRangeResponse {
            session_id,
            cursor_id,
            requested_address: address,
            range_address: result.address,
            sequence: result.sequence,
            bytes_available: result.bytes_available,
            bytes_returned,
            complete: result.complete != 0,
            policy,
            encoding: "hex".to_string(),
            data: bytes_to_hex(&buffer),
            module: None,
        })
    }

    pub fn memory_buffer_with_ranges(
        &self,
        session_id: u64,
        cursor_id: u64,
        address: u64,
        size: u32,
        max_ranges: u32,
        policy: QueryMemoryPolicy,
    ) -> anyhow::Result<MemoryBufferResponse> {
        let query_memory_buffer_with_ranges: Symbol<QueryMemoryBufferWithRangesFn> = unsafe {
            self.bridge
                .symbol(b"ttd_mcp_query_memory_buffer_with_ranges\0")?
        };
        let mut buffer = vec![0; size as usize];
        let mut ranges = vec![TtdMcpMemoryBufferRangeInfo::default(); max_ranges as usize];
        let mut result = TtdMcpMemoryBufferInfo::default();
        let status = unsafe {
            query_memory_buffer_with_ranges(
                self.handle.as_ptr(),
                address,
                buffer.as_mut_ptr(),
                size,
                ranges.as_mut_ptr(),
                max_ranges,
                query_memory_policy_code(policy),
                &mut result,
            )
        };
        self.bridge
            .ensure_ok(status, "querying cursor memory buffer with ranges")?;

        let bytes_read = (result.bytes_read as usize).min(buffer.len());
        buffer.truncate(bytes_read);
        ranges.truncate((result.ranges_copied as usize).min(ranges.len()));
        Ok(MemoryBufferResponse {
            session_id,
            cursor_id,
            requested_address: address,
            requested_size: size,
            address: result.address,
            bytes_read,
            complete: result.complete != 0,
            ranges_truncated: result.ranges_truncated != 0,
            policy,
            encoding: "hex".to_string(),
            data: bytes_to_hex(&buffer),
            ranges: ranges.into_iter().map(MemoryBufferRange::from).collect(),
        })
    }

    pub fn registers(&self, session_id: u64, cursor_id: u64) -> anyhow::Result<CursorRegisters> {
        let cursor_state: Symbol<CursorStateFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_cursor_state\0")? };
        let mut state = TtdMcpCursorState::default();
        let status = unsafe { cursor_state(self.handle.as_ptr(), &mut state) };
        self.bridge
            .ensure_ok(status, "reading cursor register state")?;

        Ok(CursorRegisters {
            session_id,
            cursor_id,
            position: state.position.into(),
            previous_position: valid_position(state.previous_position).map(Into::into),
            thread: (state.thread_unique_id != 0 || state.thread_id != 0).then_some(
                CursorThreadState {
                    unique_id: state.thread_unique_id,
                    thread_id: state.thread_id,
                },
            ),
            teb_address: (state.teb_address != 0).then_some(state.teb_address),
            program_counter: state.program_counter,
            stack_pointer: state.stack_pointer,
            frame_pointer: state.frame_pointer,
            basic_return_value: state.basic_return_value,
        })
    }

    pub fn x64_context(
        &self,
        session_id: u64,
        cursor_id: u64,
        thread_id: Option<u32>,
    ) -> anyhow::Result<RegisterContextResponse> {
        let x64_context: Symbol<X64ContextFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_x64_context\0")? };
        let mut context = TtdMcpX64Context::default();
        let status = unsafe {
            x64_context(
                self.handle.as_ptr(),
                thread_id.unwrap_or_default(),
                &mut context,
            )
        };
        self.bridge
            .ensure_ok(status, "reading x64 register context")?;

        Ok(RegisterContextResponse {
            session_id,
            cursor_id,
            position: context.position.into(),
            previous_position: valid_position(context.previous_position).map(Into::into),
            thread: (context.thread_unique_id != 0 || context.thread_id != 0).then_some(
                CursorThreadState {
                    unique_id: context.thread_unique_id,
                    thread_id: context.thread_id,
                },
            ),
            teb_address: (context.teb_address != 0).then_some(context.teb_address),
            architecture: "x64".to_string(),
            registers: context.into(),
            module: None,
        })
    }

    pub fn active_threads(&self) -> anyhow::Result<Vec<ActiveThreadState>> {
        let active_threads: Symbol<ActiveThreadsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_active_threads\0")? };
        let mut count = 0;
        let status =
            unsafe { active_threads(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge
            .ensure_ok(status, "querying active thread count")?;

        let mut threads = vec![TtdMcpActiveThreadInfo::default(); count as usize];
        let status = unsafe {
            active_threads(
                self.handle.as_ptr(),
                threads.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing active threads")?;
        threads.truncate(count as usize);
        Ok(threads.into_iter().map(ActiveThreadState::from).collect())
    }

    pub fn cursor_modules(&self) -> anyhow::Result<Vec<TraceModule>> {
        let cursor_modules: Symbol<CursorModulesFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_cursor_modules\0")? };
        let mut count = 0;
        let status =
            unsafe { cursor_modules(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge
            .ensure_ok(status, "querying cursor module count")?;

        let mut modules = vec![TtdMcpModuleInfo::default(); count as usize];
        let status = unsafe {
            cursor_modules(
                self.handle.as_ptr(),
                modules.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing cursor modules")?;
        modules.truncate(count as usize);
        Ok(modules.into_iter().map(TraceModule::from).collect())
    }

    pub fn step(
        &self,
        session_id: u64,
        cursor_id: u64,
        direction: StepDirection,
        kind: StepKind,
        count: u32,
    ) -> anyhow::Result<StepResult> {
        let step_cursor: Symbol<StepCursorFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_step_cursor\0")? };
        let mut result = TtdMcpStepResult::default();
        let native_direction = match direction {
            StepDirection::Forward => 0,
            StepDirection::Backward => 1,
        };
        let only_current_thread = matches!(kind, StepKind::Step) as u8;
        let status = unsafe {
            step_cursor(
                self.handle.as_ptr(),
                native_direction,
                count,
                only_current_thread,
                &mut result,
            )
        };
        self.bridge.ensure_ok(status, "stepping replay cursor")?;

        Ok(StepResult {
            session_id,
            cursor_id,
            position: result.position.into(),
            previous_position: valid_position(result.previous_position).map(Into::into),
            direction,
            kind,
            requested_count: count,
            steps_executed: result.steps_executed,
            instructions_executed: result.instructions_executed,
            stop_reason: stop_reason_name(result.stop_reason).to_string(),
            stop_reason_code: result.stop_reason,
        })
    }

    pub fn memory_watchpoint(
        &self,
        request: &MemoryWatchpointRequest,
    ) -> anyhow::Result<MemoryWatchpointResponse> {
        let memory_watchpoint: Symbol<MemoryWatchpointFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_memory_watchpoint\0")? };
        let native_access = native_memory_access_mask(request.access);
        let native_direction = match request.direction {
            MemoryAccessDirection::Next => 0,
            MemoryAccessDirection::Previous => 1,
            MemoryAccessDirection::Unknown => bail!("direction must be 'previous' or 'next'"),
        };
        let mut result = TtdMcpMemoryWatchpointResult::default();
        let status = unsafe {
            memory_watchpoint(
                self.handle.as_ptr(),
                request.address,
                request.size,
                native_access,
                native_direction,
                request.thread_unique_id.unwrap_or_default(),
                &mut result,
            )
        };
        self.bridge
            .ensure_ok(status, "replaying to a memory watchpoint")?;

        let found = result.found != 0;
        Ok(MemoryWatchpointResponse {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            requested_address: request.address,
            requested_size: request.size,
            requested_access: request.access,
            requested_thread_unique_id: request.thread_unique_id,
            direction: request.direction,
            found,
            position: result.position.into(),
            previous_position: valid_position(result.previous_position).map(Into::into),
            thread: (result.thread_unique_id != 0 || result.thread_id != 0).then_some(
                CursorThreadState {
                    unique_id: result.thread_unique_id,
                    thread_id: result.thread_id,
                },
            ),
            program_counter: result.program_counter,
            match_address: found.then_some(result.match_address),
            match_size: found.then_some(result.match_size),
            match_access: found.then_some(memory_access_kind(result.match_access)),
            stop_reason: stop_reason_name(result.stop_reason).to_string(),
            stop_reason_code: result.stop_reason,
        })
    }
}

impl Drop for NativeCursor {
    fn drop(&mut self) {
        let free_cursor: anyhow::Result<Symbol<FreeCursorFn>> =
            unsafe { self.bridge.symbol(b"ttd_mcp_free_cursor\0") };
        if let Ok(free_cursor) = free_cursor {
            unsafe { free_cursor(self.handle.as_ptr()) };
        }
    }
}

impl From<TtdMcpPosition> for Position {
    fn from(position: TtdMcpPosition) -> Self {
        Self {
            sequence: position.sequence,
            steps: position.steps,
        }
    }
}

impl From<Position> for TtdMcpPosition {
    fn from(position: Position) -> Self {
        Self {
            sequence: position.sequence,
            steps: position.steps,
        }
    }
}

impl Default for TtdMcpTraceFileInfo {
    fn default() -> Self {
        Self {
            file_type: 0,
            file_name: [0; TRACE_FILE_CHARS],
            companion_file_name: [0; TRACE_FILE_CHARS],
            trace_index: 0,
        }
    }
}

impl From<TtdMcpTraceListEntry> for TraceListEntry {
    fn from(entry: TtdMcpTraceListEntry) -> Self {
        Self {
            index: entry.file_info.trace_index,
            session_id: guid_string(entry.session_id),
            group_id: guid_string(entry.group_id),
            recording_type: recording_type_name(entry.recording_type).to_string(),
            file: entry.file_info.into(),
        }
    }
}

impl From<TtdMcpTraceFileInfo> for TraceFileInfo {
    fn from(info: TtdMcpTraceFileInfo) -> Self {
        let file_name = utf16_fixed_to_string(&info.file_name);
        let companion_file_name = utf16_fixed_to_string(&info.companion_file_name);
        Self {
            file_type: trace_file_type_name(info.file_type).to_string(),
            file_name: (!file_name.is_empty()).then(|| PathBuf::from(file_name)),
            companion_file_name: (!companion_file_name.is_empty())
                .then(|| PathBuf::from(companion_file_name)),
            trace_index: info.trace_index,
        }
    }
}

impl From<TtdMcpIndexTreeStats> for IndexTreeStats {
    fn from(stats: TtdMcpIndexTreeStats) -> Self {
        Self {
            page_size: stats.page_size,
            page_count: stats.page_count,
            inner_page_count: stats.inner_page_count,
            inner_page_entry_count: stats.inner_page_entry_count,
            inner_page_entry_capacity: stats.inner_page_entry_capacity,
            inner_page_entry_size: stats.inner_page_entry_size,
            leaf_page_count: stats.leaf_page_count,
            leaf_page_entry_count: stats.leaf_page_entry_count,
            leaf_page_entry_capacity: stats.leaf_page_entry_capacity,
            leaf_page_entry_size: stats.leaf_page_entry_size,
            maximum_leaf_depth: stats.maximum_leaf_depth,
            sum_of_leaf_depths: stats.sum_of_leaf_depths,
        }
    }
}

impl From<TtdMcpIndexBuildProgress> for IndexBuildProgress {
    fn from(progress: TtdMcpIndexBuildProgress) -> Self {
        Self {
            keyframe_count: progress.keyframe_count,
            keyframes_processed: progress.keyframes_processed,
        }
    }
}

impl Default for TtdMcpModuleInfo {
    fn default() -> Self {
        Self {
            name: [0; MODULE_NAME_CHARS],
            path: [0; MODULE_PATH_CHARS],
            base_address: 0,
            size: 0,
            load_position: TtdMcpPosition::default(),
            unload_position: TtdMcpPosition::default(),
            has_unload_position: 0,
        }
    }
}

impl From<TtdMcpThreadInfo> for TraceThread {
    fn from(thread: TtdMcpThreadInfo) -> Self {
        Self {
            unique_id: thread.unique_id,
            thread_id: thread.thread_id,
            lifetime_start: thread.lifetime_start.into(),
            lifetime_end: thread.lifetime_end.into(),
            active_start: (thread.has_active_time != 0).then(|| thread.active_start.into()),
            active_end: (thread.has_active_time != 0).then(|| thread.active_end.into()),
        }
    }
}

impl From<TtdMcpModuleInfo> for TraceModule {
    fn from(module: TtdMcpModuleInfo) -> Self {
        let path = utf16_fixed_to_string(&module.path);
        let mut name = utf16_fixed_to_string(&module.name);
        if name.is_empty() && !path.is_empty() {
            name = Path::new(&path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
        }

        Self {
            name,
            path: (!path.is_empty()).then(|| PathBuf::from(path)),
            base_address: module.base_address,
            size: module.size,
            load_position: Some(module.load_position.into()),
            unload_position: (module.has_unload_position != 0)
                .then(|| module.unload_position.into()),
        }
    }
}

impl From<TtdMcpExceptionInfo> for TraceException {
    fn from(exception: TtdMcpExceptionInfo) -> Self {
        let parameter_count = (exception.parameter_count as usize).min(EXCEPTION_PARAMETER_COUNT);
        Self {
            position: exception.position.into(),
            thread_unique_id: (exception.thread_unique_id != 0)
                .then_some(exception.thread_unique_id),
            code: exception.code,
            flags: exception.flags,
            program_counter: exception.program_counter,
            record_address: exception.record_address,
            parameters: exception.parameters[..parameter_count].to_vec(),
        }
    }
}

impl From<TtdMcpModuleEventInfo> for TraceModuleEvent {
    fn from(event: TtdMcpModuleEventInfo) -> Self {
        Self {
            kind: match event.kind {
                0 => ModuleEventKind::Load,
                _ => ModuleEventKind::Unload,
            },
            position: event.position.into(),
            module: event.module.into(),
        }
    }
}

impl From<TtdMcpThreadEventInfo> for TraceThreadEvent {
    fn from(event: TtdMcpThreadEventInfo) -> Self {
        Self {
            kind: match event.kind {
                0 => ThreadEventKind::Create,
                _ => ThreadEventKind::Terminate,
            },
            position: event.position.into(),
            thread: event.thread.into(),
        }
    }
}

impl From<TtdMcpActiveThreadInfo> for ActiveThreadState {
    fn from(thread: TtdMcpActiveThreadInfo) -> Self {
        Self {
            thread: thread.thread.into(),
            current_position: thread.current_position.into(),
            last_valid_position: (thread.has_last_valid_position != 0)
                .then(|| thread.last_valid_position.into()),
            previous_position: (thread.has_previous_position != 0)
                .then(|| thread.previous_position.into()),
            teb_address: (thread.teb_address != 0).then_some(thread.teb_address),
            program_counter: thread.program_counter,
            stack_pointer: thread.stack_pointer,
            frame_pointer: thread.frame_pointer,
            basic_return_value: thread.basic_return_value,
            module: None,
        }
    }
}

impl From<TtdMcpX64Context> for X64RegisterSet {
    fn from(context: TtdMcpX64Context) -> Self {
        let xmm = context
            .xmm
            .into_iter()
            .map(VectorRegister128::from)
            .collect::<Vec<_>>();
        let ymm = context
            .xmm
            .into_iter()
            .zip(context.ymm_high)
            .map(|(low, high)| vector256_from_parts(low, high))
            .collect::<Vec<_>>();

        Self {
            context_flags: context.context_flags,
            mx_csr: context.mx_csr,
            seg_cs: context.seg_cs,
            seg_ds: context.seg_ds,
            seg_es: context.seg_es,
            seg_fs: context.seg_fs,
            seg_gs: context.seg_gs,
            seg_ss: context.seg_ss,
            eflags: context.eflags,
            dr0: context.dr0,
            dr1: context.dr1,
            dr2: context.dr2,
            dr3: context.dr3,
            dr6: context.dr6,
            dr7: context.dr7,
            rax: context.rax,
            rcx: context.rcx,
            rdx: context.rdx,
            rbx: context.rbx,
            rsp: context.rsp,
            rbp: context.rbp,
            rsi: context.rsi,
            rdi: context.rdi,
            r8: context.r8,
            r9: context.r9,
            r10: context.r10,
            r11: context.r11,
            r12: context.r12,
            r13: context.r13,
            r14: context.r14,
            r15: context.r15,
            rip: context.rip,
            vector_control: context.vector_control,
            debug_control: context.debug_control,
            last_branch_to_rip: context.last_branch_to_rip,
            last_branch_from_rip: context.last_branch_from_rip,
            last_exception_to_rip: context.last_exception_to_rip,
            last_exception_from_rip: context.last_exception_from_rip,
            xmm,
            ymm,
        }
    }
}

impl From<TtdMcpVector128> for VectorRegister128 {
    fn from(value: TtdMcpVector128) -> Self {
        Self {
            low: value.low,
            high: value.high,
            hex: vector128_hex(value),
        }
    }
}

fn vector256_from_parts(low: TtdMcpVector128, high: TtdMcpVector128) -> VectorRegister256 {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(&vector128_bytes(low));
    bytes[16..].copy_from_slice(&vector128_bytes(high));
    VectorRegister256 {
        low: low.into(),
        high: high.into(),
        hex: bytes_to_hex(&bytes),
    }
}

fn vector128_hex(value: TtdMcpVector128) -> String {
    bytes_to_hex(&vector128_bytes(value))
}

fn vector128_bytes(value: TtdMcpVector128) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.low.to_le_bytes());
    bytes[8..].copy_from_slice(&value.high.to_le_bytes());
    bytes
}

impl From<TtdMcpMemoryBufferRangeInfo> for MemoryBufferRange {
    fn from(range: TtdMcpMemoryBufferRangeInfo) -> Self {
        Self {
            offset: range.offset,
            address: range.address,
            size: range.size,
            sequence: range.sequence,
            module: None,
        }
    }
}

impl TtdMcpTraceInfo {
    pub fn lifetime_start(&self) -> Position {
        self.first_position.into()
    }

    pub fn lifetime_end(&self) -> Position {
        self.last_position.into()
    }

    pub fn peb_address(&self) -> Option<u64> {
        (self.peb_address != 0).then_some(self.peb_address)
    }

    pub fn process_id(&self) -> Option<u32> {
        (self.process_id != 0).then_some(self.process_id)
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count as usize
    }

    pub fn module_count(&self) -> usize {
        self.module_count as usize
    }

    pub fn module_instance_count(&self) -> usize {
        self.module_instance_count as usize
    }

    pub fn exception_count(&self) -> usize {
        self.exception_count as usize
    }

    pub fn keyframe_count(&self) -> Option<usize> {
        Some(self.keyframe_count as usize)
    }
}

fn bridge_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("TTD_NATIVE_BRIDGE_DLL").map(PathBuf::from) {
        candidates.push(path);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join(NATIVE_BRIDGE_DLL));
        }
    }

    let build_dir = PathBuf::from("target/native/ttd-replay-bridge");
    candidates.push(build_dir.join("bin/Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("bin/Debug").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Debug").join(NATIVE_BRIDGE_DLL));

    if let Some(root) = workspace_root() {
        let build_dir = root.join("target/native/ttd-replay-bridge");
        candidates.push(build_dir.join("bin/Release").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("bin/Debug").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("Release").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("Debug").join(NATIVE_BRIDGE_DLL));
    }

    candidates
}

fn add_dll_search_paths(bridge_path: &Path) {
    let mut paths = Vec::new();
    if let Some(bridge_dir) = bridge_path.parent() {
        paths.push(bridge_dir.to_path_buf());
    }
    if let Some(runtime_dir) = std::env::var_os("TTD_RUNTIME_DIR").map(PathBuf::from) {
        paths.push(runtime_dir);
    } else {
        paths.push(PathBuf::from("target/ttd-runtime"));
        if let Some(root) = workspace_root() {
            paths.push(root.join("target/ttd-runtime"));
        }
    }
    if let Some(symbol_runtime_dir) = std::env::var_os("TTD_SYMBOL_RUNTIME_DIR").map(PathBuf::from)
    {
        paths.push(symbol_runtime_dir);
    } else {
        paths.push(PathBuf::from("target/symbol-runtime"));
        if let Some(root) = workspace_root() {
            paths.push(root.join("target/symbol-runtime"));
        }
    }

    let mut path_var = std::env::var_os("PATH").unwrap_or_default();
    for path in paths {
        ensure_path_component(&mut path_var, &path);
    }
    std::env::set_var("PATH", path_var);
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn ensure_path_component(path_var: &mut std::ffi::OsString, path: &Path) {
    if !path.is_dir() {
        return;
    }

    let already_present = std::env::split_paths(path_var).any(|existing| existing == path);
    if already_present {
        return;
    }

    let mut paths = vec![path.to_path_buf()];
    paths.extend(std::env::split_paths(path_var));
    if let Ok(joined) = std::env::join_paths(paths) {
        *path_var = joined;
    }
}

fn wide_empty() -> Vec<u16> {
    vec![0]
}

fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_fixed_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn valid_position(position: TtdMcpPosition) -> Option<TtdMcpPosition> {
    (position.sequence != u64::MAX).then_some(position)
}

fn query_memory_policy_code(policy: QueryMemoryPolicy) -> u32 {
    match policy {
        QueryMemoryPolicy::Default => 0,
        QueryMemoryPolicy::ThreadLocal => 1,
        QueryMemoryPolicy::GloballyConservative => 2,
        QueryMemoryPolicy::GloballyAggressive => 3,
        QueryMemoryPolicy::InFragmentAggressive => 4,
    }
}

fn native_memory_access_mask(access: MemoryAccessMask) -> u32 {
    match access {
        MemoryAccessMask::Read => 0x01,
        MemoryAccessMask::Write => 0x02,
        MemoryAccessMask::Execute => 0x04,
        MemoryAccessMask::CodeFetch => 0x08,
        MemoryAccessMask::Overwrite => 0x10,
        MemoryAccessMask::DataMismatch => 0x20,
        MemoryAccessMask::NewData => 0x40,
        MemoryAccessMask::RedundantData => 0x80,
        MemoryAccessMask::ReadWrite => 0x03,
        MemoryAccessMask::All => 0xff,
    }
}

fn memory_access_kind(access: u32) -> MemoryAccessKind {
    match access {
        0 => MemoryAccessKind::Read,
        1 => MemoryAccessKind::Write,
        2 => MemoryAccessKind::Execute,
        3 => MemoryAccessKind::CodeFetch,
        4 => MemoryAccessKind::Overwrite,
        5 => MemoryAccessKind::DataMismatch,
        6 => MemoryAccessKind::NewData,
        7 => MemoryAccessKind::RedundantData,
        _ => MemoryAccessKind::Unknown,
    }
}

fn stop_reason_name(stop_reason: u32) -> &'static str {
    match stop_reason {
        0 => "MemoryWatchpoint",
        1 => "PositionWatchpoint",
        2 => "Exception",
        3 => "Gap",
        4 => "Thread",
        5 => "StepCount",
        6 => "Position",
        7 => "Process",
        8 => "Interrupted",
        9 => "Error",
        _ => "Unknown",
    }
}

fn recording_type_name(value: u32) -> &'static str {
    match value {
        0 => "invalid",
        1 => "full",
        2 => "selective",
        3 => "chunk",
        _ => "unknown",
    }
}

fn index_status_name(value: u32) -> &'static str {
    match value {
        0 => "loaded",
        1 => "not_present",
        2 => "unloadable",
        _ => "unknown",
    }
}

fn trace_file_type_name(value: u32) -> &'static str {
    match value {
        0 => "trace",
        1 => "index",
        2 => "pack",
        _ => "unknown",
    }
}

fn guid_string(guid: TtdMcpGuid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(not(windows))]
fn wide_path(path: &Path) -> Vec<u16> {
    path.to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}
