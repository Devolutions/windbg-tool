use super::{Position, PositionOrPercent, ResolvedSymbolConfig, SymbolSettings};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadTraceRequest {
    pub trace_path: PathBuf,
    #[serde(default)]
    pub companion_path: Option<PathBuf>,
    #[serde(default)]
    pub trace_index: Option<u32>,
    #[serde(default)]
    pub symbols: SymbolSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTraceResponse {
    pub session_id: u64,
    pub trace: TraceInfo,
    pub symbol_path: String,
    pub symbols: ResolvedSymbolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    pub trace_path: PathBuf,
    pub backend: String,
    pub index_status: String,
    pub trace_file: Option<TraceFileInfo>,
    pub trace_session_id: Option<String>,
    pub trace_group_id: Option<String>,
    pub recording_type: Option<String>,
    pub process_id: Option<u32>,
    pub peb_address: Option<u64>,
    pub lifetime_start: Position,
    pub lifetime_end: Position,
    pub architecture: Option<String>,
    pub thread_count: usize,
    pub module_count: usize,
    pub module_instance_count: usize,
    pub exception_count: usize,
    pub keyframe_count: Option<usize>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TraceListRequest {
    pub trace_path: PathBuf,
    #[serde(default)]
    pub companion_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceListResponse {
    pub trace_path: PathBuf,
    pub companion_path: Option<PathBuf>,
    pub trace_count: usize,
    pub traces: Vec<TraceListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceListEntry {
    pub index: u32,
    pub session_id: String,
    pub group_id: String,
    pub recording_type: String,
    pub file: TraceFileInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFileInfo {
    pub file_type: String,
    pub file_name: Option<PathBuf>,
    pub companion_file_name: Option<PathBuf>,
    pub trace_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IndexStatusRequest {
    pub session_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatusResponse {
    pub session_id: u64,
    pub status: String,
    pub raw_status: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IndexStatsRequest {
    pub session_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatsResponse {
    pub session_id: u64,
    pub global_memory: IndexTreeStats,
    pub segment_memory: IndexTreeStats,
    pub map_page_call_count: u64,
    pub lock_page_call_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexTreeStats {
    pub page_size: u64,
    pub page_count: u64,
    pub inner_page_count: u64,
    pub inner_page_entry_count: u64,
    pub inner_page_entry_capacity: u64,
    pub inner_page_entry_size: u64,
    pub leaf_page_count: u64,
    pub leaf_page_entry_count: u64,
    pub leaf_page_entry_capacity: u64,
    pub leaf_page_entry_size: u64,
    pub maximum_leaf_depth: u64,
    pub sum_of_leaf_depths: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IndexBuildRequest {
    pub session_id: u64,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexBuildResponse {
    pub session_id: u64,
    pub status: String,
    pub raw_status: u32,
    pub flags: Vec<String>,
    pub raw_flags: u32,
    pub progress: IndexBuildProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexBuildProgress {
    pub keyframe_count: u32,
    pub keyframes_processed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub session_id: u64,
    pub backend: String,
    pub native: bool,
    pub symbols: ResolvedSymbolConfig,
    pub features: ReplayCapabilities,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCapabilities {
    pub trace_info: bool,
    pub trace_list: bool,
    pub index_status: bool,
    pub index_stats: bool,
    pub build_index: bool,
    pub close_trace: bool,
    pub list_threads: bool,
    pub list_modules: bool,
    pub cursor_modules: bool,
    pub list_keyframes: bool,
    pub module_events: bool,
    pub thread_events: bool,
    pub active_threads: bool,
    pub module_info: bool,
    pub address_info: bool,
    pub list_exceptions: bool,
    pub cursor_create: bool,
    pub position_get: bool,
    pub position_set: bool,
    pub position_set_thread: bool,
    pub step: bool,
    pub compact_registers: bool,
    pub full_registers: bool,
    pub avx_registers: bool,
    pub stack_info: bool,
    pub stack_read: bool,
    pub command_line: bool,
    pub read_memory: bool,
    pub memory_query_policy: bool,
    pub memory_range: bool,
    pub memory_buffer_ranges: bool,
    pub memory_watchpoint: bool,
    pub memory_regions: bool,
    pub search_memory: bool,
    pub search_trace_strings: bool,
    pub symbol_resolution: bool,
    pub api_calls: bool,
    pub call_trace: bool,
    pub console_output: bool,
    pub stdout_events: bool,
    pub network_summary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceThread {
    pub unique_id: u64,
    pub thread_id: u32,
    pub lifetime_start: Position,
    pub lifetime_end: Position,
    pub active_start: Option<Position>,
    pub active_end: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModule {
    pub name: String,
    pub path: Option<PathBuf>,
    pub base_address: u64,
    pub size: u64,
    pub load_position: Option<Position>,
    pub unload_position: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleList {
    pub modules: Vec<TraceModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorModuleList {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub modules: Vec<TraceModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyframeList {
    pub keyframes: Vec<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEventList {
    pub events: Vec<TraceModuleEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModuleEvent {
    pub kind: ModuleEventKind,
    pub position: Position,
    pub module: TraceModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleEventKind {
    Load,
    Unload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEventList {
    pub events: Vec<TraceThreadEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceThreadEvent {
    pub kind: ThreadEventKind,
    pub position: Position,
    pub thread: TraceThread,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadEventKind {
    Create,
    Terminate,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ModuleInfoRequest {
    pub session_id: u64,
    pub name: Option<String>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfoResponse {
    pub session_id: u64,
    pub matched_by: String,
    pub module: TraceModule,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddressInfoRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfoResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub address_hex: String,
    pub position: Position,
    pub thread: Option<CursorThreadState>,
    pub classification: AddressClassification,
    pub module: Option<AddressModuleCoordinate>,
    pub registers: AddressRegisterContext,
    pub stack: Option<AddressStackContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClassification {
    Module,
    Stack,
    Teb,
    Peb,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressModuleCoordinate {
    pub name: String,
    pub path: Option<PathBuf>,
    pub runtime_base: u64,
    pub runtime_base_hex: String,
    pub size: u64,
    pub size_hex: String,
    pub rva: u64,
    pub rva_hex: String,
    pub module_offset: String,
    pub load_position: Option<Position>,
    pub unload_position: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRegisterContext {
    pub program_counter: u64,
    pub program_counter_hex: String,
    pub stack_pointer: u64,
    pub stack_pointer_hex: String,
    pub frame_pointer: u64,
    pub frame_pointer_hex: String,
    pub basic_return_value: u64,
    pub basic_return_value_hex: String,
    pub teb_address: Option<u64>,
    pub teb_address_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStackContext {
    pub stack_base: u64,
    pub stack_base_hex: String,
    pub stack_limit: u64,
    pub stack_limit_hex: String,
    pub stack_pointer_in_range: bool,
    pub address_in_stack: bool,
    pub offset_from_sp: Option<i64>,
    pub offset_from_fp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceException {
    pub position: Position,
    pub thread_unique_id: Option<u64>,
    pub code: u32,
    pub flags: u32,
    pub program_counter: u64,
    pub record_address: u64,
    pub parameters: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorPosition {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorThreadState {
    pub unique_id: u64,
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorRegisters {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub thread: Option<CursorThreadState>,
    pub teb_address: Option<u64>,
    pub program_counter: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub basic_return_value: u64,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RegisterContextRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    #[serde(default)]
    pub thread_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterContextResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub thread: Option<CursorThreadState>,
    pub teb_address: Option<u64>,
    pub architecture: String,
    pub registers: X64RegisterSet,
    pub module: Option<AddressModuleCoordinate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64RegisterSet {
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
    pub xmm: Vec<VectorRegister128>,
    pub ymm: Vec<VectorRegister256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRegister128 {
    pub low: u64,
    pub high: u64,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRegister256 {
    pub low: VectorRegister128,
    pub high: VectorRegister128,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveThreadList {
    pub session_id: u64,
    pub cursor_id: u64,
    pub cursor_position: Position,
    pub threads: Vec<ActiveThreadState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveThreadState {
    pub thread: TraceThread,
    pub current_position: Position,
    pub last_valid_position: Option<Position>,
    pub previous_position: Option<Position>,
    pub teb_address: Option<u64>,
    pub program_counter: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub basic_return_value: u64,
    pub module: Option<AddressModuleCoordinate>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MemoryRangeRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    #[serde(default = "default_memory_range_max_bytes")]
    pub max_bytes: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRangeResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub range_address: u64,
    pub sequence: u64,
    pub bytes_available: u64,
    pub bytes_returned: usize,
    pub complete: bool,
    pub policy: QueryMemoryPolicy,
    pub encoding: String,
    pub data: String,
    pub module: Option<AddressModuleCoordinate>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MemoryBufferRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
    #[serde(default = "default_memory_buffer_max_ranges")]
    pub max_ranges: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBufferResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub requested_size: u32,
    pub address: u64,
    pub bytes_read: usize,
    pub complete: bool,
    pub ranges_truncated: bool,
    pub policy: QueryMemoryPolicy,
    pub encoding: String,
    pub data: String,
    pub ranges: Vec<MemoryBufferRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBufferRange {
    pub offset: u32,
    pub address: u64,
    pub size: u64,
    pub sequence: u64,
    pub module: Option<AddressModuleCoordinate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackInfo {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub thread: Option<CursorThreadState>,
    pub teb_address: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub stack_pointer_in_range: bool,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StackReadRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    #[serde(default = "default_stack_read_size")]
    pub size: u32,
    #[serde(default)]
    pub offset_from_sp: i64,
    #[serde(default)]
    pub decode_pointers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackReadResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub stack_pointer: u64,
    pub offset_from_sp: i64,
    pub address: u64,
    pub requested_size: u32,
    pub bytes_read: usize,
    pub complete: bool,
    pub encoding: String,
    pub data: String,
    pub pointer_size: u8,
    pub pointers: Vec<StackPointerValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackPointerValue {
    pub offset: u32,
    pub address: u64,
    pub value: u64,
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCommandLine {
    pub session_id: u64,
    pub cursor_id: u64,
    pub peb_address: u64,
    pub process_parameters_address: u64,
    pub command_line_address: u64,
    pub command_line: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PositionRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: PositionOrPercent,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StepRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    #[serde(default)]
    pub direction: StepDirection,
    #[serde(default)]
    pub kind: StepKind,
    #[serde(default = "default_step_count")]
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub direction: StepDirection,
    pub kind: StepKind,
    pub requested_count: u32,
    pub steps_executed: u64,
    pub instructions_executed: u64,
    pub stop_reason: String,
    pub stop_reason_code: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepDirection {
    #[default]
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    #[default]
    Step,
    Trace,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReadMemoryRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
    #[serde(default)]
    pub policy: Option<QueryMemoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadMemoryResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub address: u64,
    pub requested_size: u32,
    pub bytes_read: usize,
    pub complete: bool,
    pub policy: QueryMemoryPolicy,
    pub encoding: String,
    pub data: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMemoryPolicy {
    #[default]
    Default,
    ThreadLocal,
    GloballyConservative,
    GloballyAggressive,
    InFragmentAggressive,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MemoryWatchpointRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
    pub access: MemoryAccessMask,
    pub direction: MemoryAccessDirection,
    #[serde(default)]
    pub thread_unique_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWatchpointResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub requested_size: u32,
    pub requested_access: MemoryAccessMask,
    pub requested_thread_unique_id: Option<u64>,
    pub direction: MemoryAccessDirection,
    pub found: bool,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub thread: Option<CursorThreadState>,
    pub program_counter: u64,
    pub match_address: Option<u64>,
    pub match_size: Option<u64>,
    pub match_access: Option<MemoryAccessKind>,
    pub stop_reason: String,
    pub stop_reason_code: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessMask {
    Read,
    Write,
    Execute,
    CodeFetch,
    Overwrite,
    DataMismatch,
    NewData,
    RedundantData,
    ReadWrite,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessDirection {
    Previous,
    Next,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessKind {
    Read,
    Write,
    Execute,
    CodeFetch,
    Overwrite,
    DataMismatch,
    NewData,
    RedundantData,
    Unknown,
}

fn default_step_count() -> u32 {
    1
}

fn default_stack_read_size() -> u32 {
    256
}

fn default_memory_range_max_bytes() -> u32 {
    256
}

fn default_memory_buffer_max_ranges() -> u32 {
    64
}
