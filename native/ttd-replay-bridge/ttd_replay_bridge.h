#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef _WIN32
#define TTD_MCP_EXPORT __declspec(dllexport)
#else
#define TTD_MCP_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TtdMcpTrace TtdMcpTrace;
typedef struct TtdMcpCursor TtdMcpCursor;

typedef struct TtdMcpPosition {
    uint64_t sequence;
    uint64_t steps;
} TtdMcpPosition;

typedef struct TtdMcpTraceInfo {
    TtdMcpPosition first_position;
    TtdMcpPosition last_position;
    uint64_t peb_address;
    uint32_t process_id;
    uint32_t thread_count;
    uint32_t module_count;
    uint32_t module_instance_count;
    uint32_t exception_count;
    uint32_t keyframe_count;
} TtdMcpTraceInfo;

typedef struct TtdMcpSymbolConfig {
    const wchar_t* symbol_path;
    const wchar_t* image_path;
    const wchar_t* symbol_cache_dir;
    const wchar_t* symbol_runtime_dir;
} TtdMcpSymbolConfig;

typedef struct TtdMcpGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} TtdMcpGuid;

typedef struct TtdMcpTraceFileInfo {
    uint32_t file_type;
    wchar_t file_name[1024];
    wchar_t companion_file_name[1024];
    uint32_t trace_index;
} TtdMcpTraceFileInfo;

typedef struct TtdMcpTraceListEntry {
    TtdMcpGuid session_id;
    TtdMcpGuid group_id;
    uint32_t recording_type;
    TtdMcpTraceFileInfo file_info;
} TtdMcpTraceListEntry;

typedef struct TtdMcpIndexBuildProgress {
    uint32_t keyframe_count;
    uint32_t keyframes_processed;
} TtdMcpIndexBuildProgress;

typedef struct TtdMcpIndexTreeStats {
    uint64_t page_size;
    uint64_t page_count;
    uint64_t inner_page_count;
    uint64_t inner_page_entry_count;
    uint64_t inner_page_entry_capacity;
    uint64_t inner_page_entry_size;
    uint64_t leaf_page_count;
    uint64_t leaf_page_entry_count;
    uint64_t leaf_page_entry_capacity;
    uint64_t leaf_page_entry_size;
    uint64_t maximum_leaf_depth;
    uint64_t sum_of_leaf_depths;
} TtdMcpIndexTreeStats;

typedef struct TtdMcpIndexFileStats {
    TtdMcpIndexTreeStats global_memory;
    TtdMcpIndexTreeStats segment_memory;
    uint64_t map_page_call_count;
    uint64_t lock_page_call_count;
} TtdMcpIndexFileStats;

typedef struct TtdMcpThreadInfo {
    uint64_t unique_id;
    uint32_t thread_id;
    TtdMcpPosition lifetime_start;
    TtdMcpPosition lifetime_end;
    TtdMcpPosition active_start;
    TtdMcpPosition active_end;
    uint8_t has_active_time;
} TtdMcpThreadInfo;

typedef struct TtdMcpModuleInfo {
    wchar_t name[260];
    wchar_t path[1024];
    uint64_t base_address;
    uint64_t size;
    TtdMcpPosition load_position;
    TtdMcpPosition unload_position;
    uint8_t has_unload_position;
} TtdMcpModuleInfo;

typedef struct TtdMcpExceptionInfo {
    TtdMcpPosition position;
    uint64_t thread_unique_id;
    uint32_t code;
    uint32_t flags;
    uint64_t program_counter;
    uint64_t record_address;
    uint32_t parameter_count;
    uint64_t parameters[15];
} TtdMcpExceptionInfo;

typedef struct TtdMcpModuleEventInfo {
    uint8_t kind;
    TtdMcpPosition position;
    TtdMcpModuleInfo module;
} TtdMcpModuleEventInfo;

typedef struct TtdMcpThreadEventInfo {
    uint8_t kind;
    TtdMcpPosition position;
    TtdMcpThreadInfo thread;
} TtdMcpThreadEventInfo;

typedef struct TtdMcpMemoryRead {
    uint64_t address;
    uint32_t bytes_read;
    uint8_t complete;
} TtdMcpMemoryRead;

typedef struct TtdMcpCursorState {
    TtdMcpPosition position;
    TtdMcpPosition previous_position;
    uint64_t thread_unique_id;
    uint32_t thread_id;
    uint64_t teb_address;
    uint64_t program_counter;
    uint64_t stack_pointer;
    uint64_t frame_pointer;
    uint64_t basic_return_value;
} TtdMcpCursorState;

typedef struct TtdMcpVector128 {
    uint64_t low;
    uint64_t high;
} TtdMcpVector128;

typedef struct TtdMcpX64Context {
    TtdMcpPosition position;
    TtdMcpPosition previous_position;
    uint64_t thread_unique_id;
    uint32_t thread_id;
    uint64_t teb_address;
    uint32_t context_flags;
    uint32_t mx_csr;
    uint16_t seg_cs;
    uint16_t seg_ds;
    uint16_t seg_es;
    uint16_t seg_fs;
    uint16_t seg_gs;
    uint16_t seg_ss;
    uint32_t eflags;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t vector_control;
    uint64_t debug_control;
    uint64_t last_branch_to_rip;
    uint64_t last_branch_from_rip;
    uint64_t last_exception_to_rip;
    uint64_t last_exception_from_rip;
    TtdMcpVector128 xmm[16];
    TtdMcpVector128 ymm_high[16];
} TtdMcpX64Context;

typedef struct TtdMcpActiveThreadInfo {
    TtdMcpThreadInfo thread;
    TtdMcpPosition current_position;
    TtdMcpPosition last_valid_position;
    TtdMcpPosition previous_position;
    uint8_t has_last_valid_position;
    uint8_t has_previous_position;
    uint64_t teb_address;
    uint64_t program_counter;
    uint64_t stack_pointer;
    uint64_t frame_pointer;
    uint64_t basic_return_value;
} TtdMcpActiveThreadInfo;

typedef struct TtdMcpMemoryRangeInfo {
    uint64_t address;
    uint64_t bytes_available;
    uint32_t bytes_copied;
    uint64_t sequence;
    uint8_t complete;
} TtdMcpMemoryRangeInfo;

typedef struct TtdMcpMemoryBufferInfo {
    uint64_t address;
    uint32_t bytes_read;
    uint32_t range_count;
    uint32_t ranges_copied;
    uint8_t complete;
    uint8_t ranges_truncated;
} TtdMcpMemoryBufferInfo;

typedef struct TtdMcpMemoryBufferRangeInfo {
    uint64_t address;
    uint64_t size;
    uint64_t sequence;
    uint32_t offset;
} TtdMcpMemoryBufferRangeInfo;

typedef struct TtdMcpStepResult {
    TtdMcpPosition position;
    TtdMcpPosition previous_position;
    uint32_t stop_reason;
    uint64_t steps_executed;
    uint64_t instructions_executed;
} TtdMcpStepResult;

typedef struct TtdMcpMemoryWatchpointResult {
    TtdMcpPosition position;
    TtdMcpPosition previous_position;
    uint32_t stop_reason;
    uint8_t found;
    uint64_t thread_unique_id;
    uint32_t thread_id;
    uint64_t program_counter;
    uint64_t match_address;
    uint64_t match_size;
    uint32_t match_access;
} TtdMcpMemoryWatchpointResult;

typedef enum TtdMcpStatus {
    TTD_MCP_OK = 0,
    TTD_MCP_ERROR = 1,
    TTD_MCP_NOT_IMPLEMENTED = 2,
    TTD_MCP_INVALID_ARGUMENT = 3,
} TtdMcpStatus;

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t* trace_path, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace_at_index(const wchar_t* trace_path, const wchar_t* companion_path, uint32_t trace_index, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace);
TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace* trace);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_traces(const wchar_t* trace_path, const wchar_t* companion_path, TtdMcpTraceListEntry* entries, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_status(TtdMcpTrace* trace, uint32_t* status);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_file_stats(TtdMcpTrace* trace, TtdMcpIndexFileStats* stats);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_build_index(TtdMcpTrace* trace, uint32_t flags, TtdMcpIndexBuildProgress* progress, uint32_t* status);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace* trace, TtdMcpTraceInfo* info);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace* trace, TtdMcpThreadInfo* threads, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace* trace, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace* trace, TtdMcpExceptionInfo* exceptions, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_keyframes(TtdMcpTrace* trace, TtdMcpPosition* keyframes, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_module_events(TtdMcpTrace* trace, TtdMcpModuleEventInfo* events, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_thread_events(TtdMcpTrace* trace, TtdMcpThreadEventInfo* events, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace* trace, TtdMcpCursor** cursor);
TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor* cursor);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor* cursor, TtdMcpPosition* position);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor* cursor, TtdMcpPosition position);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position_on_thread(TtdMcpCursor* cursor, uint32_t thread_unique_id, TtdMcpPosition position);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_read_memory(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, uint32_t policy, TtdMcpMemoryRead* result);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_range(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, uint32_t policy, TtdMcpMemoryRangeInfo* result);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_buffer_with_ranges(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, TtdMcpMemoryBufferRangeInfo* ranges, uint32_t range_capacity, uint32_t policy, TtdMcpMemoryBufferInfo* result);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_state(TtdMcpCursor* cursor, TtdMcpCursorState* state);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_x64_context(TtdMcpCursor* cursor, uint32_t thread_id, TtdMcpX64Context* context);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_active_threads(TtdMcpCursor* cursor, TtdMcpActiveThreadInfo* threads, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_modules(TtdMcpCursor* cursor, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_step_cursor(TtdMcpCursor* cursor, uint32_t direction, uint32_t count, uint8_t only_current_thread, TtdMcpStepResult* result);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_memory_watchpoint(TtdMcpCursor* cursor, uint64_t address, uint32_t size, uint32_t access_mask, uint32_t direction, uint64_t thread_unique_id, TtdMcpMemoryWatchpointResult* result);
TTD_MCP_EXPORT const char* ttd_mcp_last_error(void);

#ifdef __cplusplus
}
#endif
