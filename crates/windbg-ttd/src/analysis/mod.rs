//! Shared investigation helpers used by MCP tools and the CLI.
//!
//! Keep these pure or JSON-oriented so both surfaces call one implementation.

pub mod composites;
pub mod debug_log;
pub mod disasm;
pub mod discover;
pub mod dump_triage;
pub mod fault_operand;
pub mod memory;
pub mod modules;
pub mod parity_tools;
pub mod pe_symbols;
pub mod recipes;
pub mod remote;
pub mod stack;
pub mod symbol_tools;
pub mod target_analysis;
pub mod timeline;
pub mod triage;
pub mod ttd_analysis;
pub mod util;

pub use composites::{
    debug_capabilities, debug_capabilities_offline, debug_snapshot, triage_run,
    ttd_context_snapshot, ttd_open, ContextSnapshotRequest, DebugCapabilitiesArgs,
    DebugSnapshotRequest, OpenTraceRequest, RecipesArgs, TriageRunRequest,
};
pub use debug_log::{debug_log_summarize, DebugLogSummarizeRequest};
pub use disasm::disassemble_x64;
pub use discover::discover_manifest;
pub use dump_triage::{dump_triage, DumpTriageRequest};
pub use memory::{
    ascii_strings, classify_memory, instruction_hints, memory_dump, plausible_x64_pointer,
    qword_values, read_pointer_value, utf16le_strings,
};
pub use modules::{audit_modules, directory_risk, normalize_dll_name, search_candidate};
pub use parity_tools::{
    breakpoint_plan, module_search_order, source_resolve, ttd_architecture_state, ttd_module_audit,
    ttd_object_vtable, ArchitectureStateRequest, BreakpointPlanRequest, ModuleAuditRequest,
    ModuleSearchOrderRequest, ObjectVtableRequest, SourceResolveRequest,
};
pub use pe_symbols::{
    bounded_pe_file_metadata, diagnose_pe, export_symbol_value, read_export_symbols, ExportSymbol,
};
pub use recipes::{recipe_matches_topic, recipes_manifest, recipes_value};
pub use remote::{
    remote_connect_command, remote_doctor, remote_explain, remote_plan, remote_server_command,
    remote_status, RemoteConnectCommandRequest, RemoteDoctorRequest, RemoteExplainRequest,
    RemoteKind, RemotePlanRequest, RemoteServerCommandRequest, RemoteStatusRequest,
};
pub use stack::{recover_stack_candidates, stack_candidate_confidence, stack_candidate_reasons};
pub use symbol_tools::{
    pe_exports, pe_inspect, symbols_diagnose, symbols_doctor, ttd_symbols_nearest,
    PeExportsRequest, PeInspectRequest, SymbolsDiagnoseRequest, SymbolsDoctorRequest,
    SymbolsNearestRequest,
};
pub use target_analysis::{
    target_disassemble, target_memory_chase, target_memory_classify, target_memory_dps,
    target_memory_dump, target_memory_strings, target_stack_recover,
    TargetDisassembleAnalysisRequest, TargetMemoryAnalysisRequest, TargetMemoryChaseRequest,
    TargetMemoryDpsRequest, TargetMemoryDumpRequest, TargetMemoryStringsRequest,
    TargetStackRecoverRequest,
};
pub use timeline::{
    collect_keyframe_events, collect_timeline_events, timeline_sequence, timeline_source_items,
    timeline_source_summary,
};
pub use triage::triage_value;
pub use ttd_analysis::{
    ttd_disassemble, ttd_exception_focus, ttd_memory_chase, ttd_memory_classify, ttd_memory_dps,
    ttd_memory_dump, ttd_memory_strings, ttd_replay_to, ttd_stack_backtrace, ttd_stack_recover,
    ttd_timeline_events, DisassembleRequest, ExceptionFocusRequest, MemoryAnalysisRequest,
    MemoryChaseRequest, MemoryDpsRequest, MemoryDumpRequest, MemoryStringsRequest, ReplayToRequest,
    StackBacktraceRequest, StackRecoverRequest, TimelineEventsRequest,
};
pub use util::{hex_to_bytes, parse_u64_argument};
