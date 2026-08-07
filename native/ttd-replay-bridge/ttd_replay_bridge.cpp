#include "ttd_replay_bridge.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace {
thread_local std::string g_last_error;

void set_error(char const* message) noexcept {
    g_last_error = message == nullptr ? "unknown error" : message;
}
}

#if defined(TTD_MCP_USE_TTD_REPLAY)
#ifndef DBG_ASSERT
#define DBG_ASSERT(cond) do {} while (false)
#endif
#ifndef DBG_ASSERT_MSG
#define DBG_ASSERT_MSG(cond, ...) DBG_ASSERT(cond)
#endif

#include <TTD/ErrorReporting.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>

namespace {
TtdMcpPosition to_bridge_position(TTD::Replay::Position const& position) noexcept {
    return TtdMcpPosition{
        static_cast<uint64_t>(position.Sequence),
        static_cast<uint64_t>(position.Steps),
    };
}

TTD::Replay::Position to_replay_position(TtdMcpPosition position) noexcept {
    return TTD::Replay::Position(
        static_cast<TTD::SequenceId>(position.sequence),
        static_cast<TTD::Replay::StepCount>(position.steps));
}

TtdMcpPosition to_bridge_position(TTD::SequenceId sequence) noexcept {
    return TtdMcpPosition{ static_cast<uint64_t>(sequence), 0 };
}

bool is_valid_sequence(TTD::SequenceId sequence) noexcept {
    return sequence != TTD::SequenceId::Invalid;
}

bool is_valid_position(TTD::Replay::Position const& position) noexcept {
    return is_valid_sequence(position.Sequence);
}

void copy_wide(wchar_t* destination, size_t capacity, wchar_t const* source, size_t length) noexcept {
    if (destination == nullptr || capacity == 0) {
        return;
    }

    destination[0] = L'\0';
    if (source == nullptr || length == 0) {
        return;
    }

    size_t const copied = std::min(length, capacity - 1);
    std::wmemcpy(destination, source, copied);
    destination[copied] = L'\0';
}

void copy_wide_z(wchar_t* destination, size_t capacity, wchar_t const* source) noexcept {
    copy_wide(destination, capacity, source, source == nullptr ? 0 : std::wcslen(source));
}

TtdMcpGuid to_bridge_guid(GUID const& guid) noexcept {
    TtdMcpGuid output{
        guid.Data1,
        guid.Data2,
        guid.Data3,
        {},
    };
    std::copy(std::begin(guid.Data4), std::end(guid.Data4), std::begin(output.data4));
    return output;
}

TtdMcpStatus validate_list_request(void const* trace, void const* buffer, uint32_t capacity, uint32_t* count) noexcept {
    if (trace == nullptr || count == nullptr) {
        set_error("trace and count pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && buffer == nullptr) {
        set_error("output buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    return TTD_MCP_OK;
}

TtdMcpStatus set_required_count(size_t required, uint32_t* count) noexcept {
    if (required > std::numeric_limits<uint32_t>::max()) {
        set_error("native list is too large for the bridge ABI");
        return TTD_MCP_ERROR;
    }

    *count = static_cast<uint32_t>(required);
    return TTD_MCP_OK;
}

TtdMcpThreadInfo to_bridge_thread(TTD::Replay::ThreadInfo const& thread) noexcept {
    return TtdMcpThreadInfo{
        static_cast<uint64_t>(thread.UniqueId),
        static_cast<uint32_t>(thread.Id),
        to_bridge_position(thread.Lifetime.Min),
        to_bridge_position(thread.Lifetime.Max),
        to_bridge_position(thread.ActiveTime.Min),
        to_bridge_position(thread.ActiveTime.Max),
        thread.ActiveTime.IsValid() ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
    };
}

TtdMcpModuleInfo to_bridge_module(TTD::Replay::Module const* module) noexcept {
    TtdMcpModuleInfo output = {};
    if (module == nullptr) {
        return output;
    }

    wchar_t const* const base_name = TTD::Replay::GetModuleBaseName(module->pName, module->NameLength);
    size_t const base_name_length = module->NameLength - static_cast<size_t>(base_name - module->pName);
    copy_wide(output.name, std::size(output.name), base_name, base_name_length);
    copy_wide(output.path, std::size(output.path), module->pName, module->NameLength);
    output.base_address = static_cast<uint64_t>(module->Address);
    output.size = module->Size;
    return output;
}

TtdMcpTraceListEntry to_bridge_trace_list_entry(TTD::Replay::TraceInfo const& trace_info) noexcept {
    TtdMcpTraceListEntry output = {};
    output.session_id = to_bridge_guid(trace_info.SessionId);
    output.group_id = to_bridge_guid(trace_info.GroupId);
    output.recording_type = static_cast<uint32_t>(trace_info.RecordingType);
    output.file_info.file_type = static_cast<uint32_t>(trace_info.FileInfo.FileType);
    output.file_info.trace_index = trace_info.FileInfo.TraceIndex;
    copy_wide_z(output.file_info.file_name, std::size(output.file_info.file_name), trace_info.FileInfo.pFileName);
    copy_wide_z(output.file_info.companion_file_name, std::size(output.file_info.companion_file_name), trace_info.FileInfo.pCompanionFileName);
    return output;
}

TtdMcpIndexTreeStats to_bridge_index_tree_stats(TTD::Replay::IndexTreeStats const& stats) noexcept {
    return TtdMcpIndexTreeStats{
        stats.m_pageSize,
        stats.m_pageCount,
        stats.m_innerPageCount,
        stats.m_innerPageEntryCount,
        stats.m_innerPageEntryCapacity,
        stats.m_innerPageEntrySize,
        stats.m_leafPageCount,
        stats.m_leafPageEntryCount,
        stats.m_leafPageEntryCapacity,
        stats.m_leafPageEntrySize,
        stats.m_maximumLeafDepth,
        stats.m_sumOfLeafDepths,
    };
}

TtdMcpIndexFileStats to_bridge_index_file_stats(TTD::Replay::IndexFileStats const& stats) noexcept {
    return TtdMcpIndexFileStats{
        to_bridge_index_tree_stats(stats.m_globalMemoryIndexStats),
        to_bridge_index_tree_stats(stats.m_segmentMemoryIndexStats),
        stats.m_mapPageCallCount,
        stats.m_lockPageCallCount,
    };
}

void __stdcall index_build_progress_callback(
    void const* caller_context,
    TTD::Replay::IndexBuildProgressType const* progress_data) noexcept {
    auto* progress = const_cast<TtdMcpIndexBuildProgress*>(
        static_cast<TtdMcpIndexBuildProgress const*>(caller_context));
    if (progress == nullptr || progress_data == nullptr) {
        return;
    }

    progress->keyframe_count = progress_data->KeyframeCount;
    progress->keyframes_processed = progress_data->KeyframesProcessed;
}

TtdMcpVector128 to_bridge_vector(M128BIT const& value) noexcept {
    return TtdMcpVector128{
        value.Low,
        static_cast<uint64_t>(value.High),
    };
}

bool to_data_access_mask(uint32_t value, TTD::Replay::DataAccessMask* access_mask) noexcept {
    if (access_mask == nullptr) {
        return false;
    }

    constexpr uint32_t allowed_mask = static_cast<uint32_t>(TTD::Replay::DataAccessMask::All);
    if (value == 0 || (value & ~allowed_mask) != 0) {
        return false;
    }

    *access_mask = static_cast<TTD::Replay::DataAccessMask>(value);
    return true;
}

bool to_query_memory_policy(uint32_t value, TTD::Replay::QueryMemoryPolicy* policy) noexcept {
    if (policy == nullptr) {
        return false;
    }

    switch (value) {
    case 0:
        *policy = TTD::Replay::QueryMemoryPolicy::Default;
        return true;
    case 1:
        *policy = TTD::Replay::QueryMemoryPolicy::ThreadLocal;
        return true;
    case 2:
        *policy = TTD::Replay::QueryMemoryPolicy::GloballyConservative;
        return true;
    case 3:
        *policy = TTD::Replay::QueryMemoryPolicy::GloballyAggressive;
        return true;
    case 4:
        *policy = TTD::Replay::QueryMemoryPolicy::InFragmentAggressive;
        return true;
    default:
        return false;
    }
}
}

struct TtdMcpTrace {
    TTD::Replay::UniqueReplayEngine engine;
    std::wstring symbol_path;
    std::wstring image_path;
    std::wstring symbol_cache_dir;
    std::wstring symbol_runtime_dir;
    std::mutex mutex;
};

struct TtdMcpCursor {
    TtdMcpTrace* trace;
    TTD::Replay::UniqueCursor cursor;
};

class BridgeErrorReporting final : public TTD::ErrorReporting {
public:
    void __fastcall VPrintError(char const* const format, va_list args) override {
        char buffer[2048] = {};
        vsprintf_s(buffer, format, args);
        set_error(buffer);
    }
};

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t* trace_path, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace) {
    if (trace_path == nullptr || trace == nullptr) {
        set_error("trace_path and trace output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto [engine, result] = TTD::Replay::MakeReplayEngine();
    if (result != 0 || engine == nullptr) {
        set_error("failed to create TTD replay engine");
        return TTD_MCP_ERROR;
    }

    static BridgeErrorReporting error_reporting;
    engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &error_reporting);

    if (!engine->Initialize(trace_path)) {
        set_error("failed to initialize TTD replay engine with trace file");
        return TTD_MCP_ERROR;
    }

    auto* owned = new TtdMcpTrace{
        std::move(engine),
        symbols != nullptr && symbols->symbol_path != nullptr ? symbols->symbol_path : L"",
        symbols != nullptr && symbols->image_path != nullptr ? symbols->image_path : L"",
        symbols != nullptr && symbols->symbol_cache_dir != nullptr ? symbols->symbol_cache_dir : L"",
        symbols != nullptr && symbols->symbol_runtime_dir != nullptr ? symbols->symbol_runtime_dir : L"",
        {}
    };
    *trace = owned;
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace_at_index(const wchar_t* trace_path, const wchar_t* companion_path, uint32_t trace_index, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace) {
    if (trace_path == nullptr || trace == nullptr) {
        set_error("trace_path and trace output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto [trace_list, list_result] = TTD::Replay::MakeTraceList();
    if (list_result != 0 || trace_list == nullptr) {
        set_error("failed to create TTD trace list");
        return TTD_MCP_ERROR;
    }

    static BridgeErrorReporting error_reporting;
    trace_list->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &error_reporting);

    wchar_t const* const companion = companion_path != nullptr && companion_path[0] != L'\0'
        ? companion_path
        : nullptr;
    if (!trace_list->LoadFile(trace_path, companion)) {
        set_error("failed to load trace file into TTD trace list");
        return TTD_MCP_ERROR;
    }

    size_t const trace_count = trace_list->GetTraceCount();
    if (trace_index >= trace_count) {
        set_error("trace_index is outside the loaded trace list");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::UniqueReplayEngine engine(trace_list->OpenTrace(trace_index));
    if (engine == nullptr) {
        set_error("failed to open trace from TTD trace list");
        return TTD_MCP_ERROR;
    }

    engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &error_reporting);
    auto* owned = new TtdMcpTrace{
        std::move(engine),
        symbols != nullptr && symbols->symbol_path != nullptr ? symbols->symbol_path : L"",
        symbols != nullptr && symbols->image_path != nullptr ? symbols->image_path : L"",
        symbols != nullptr && symbols->symbol_cache_dir != nullptr ? symbols->symbol_cache_dir : L"",
        symbols != nullptr && symbols->symbol_runtime_dir != nullptr ? symbols->symbol_runtime_dir : L"",
        {}
    };
    *trace = owned;
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace* trace) {
    delete trace;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_traces(const wchar_t* trace_path, const wchar_t* companion_path, TtdMcpTraceListEntry* entries, uint32_t capacity, uint32_t* count) {
    if (trace_path == nullptr || count == nullptr) {
        set_error("trace_path and count output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && entries == nullptr) {
        set_error("entries output buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto [trace_list, list_result] = TTD::Replay::MakeTraceList();
    if (list_result != 0 || trace_list == nullptr) {
        set_error("failed to create TTD trace list");
        return TTD_MCP_ERROR;
    }

    static BridgeErrorReporting error_reporting;
    trace_list->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &error_reporting);

    wchar_t const* const companion = companion_path != nullptr && companion_path[0] != L'\0'
        ? companion_path
        : nullptr;
    if (!trace_list->LoadFile(trace_path, companion)) {
        set_error("failed to load trace file into TTD trace list");
        return TTD_MCP_ERROR;
    }

    size_t const required = trace_list->GetTraceCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    for (size_t index = 0; index < required; ++index) {
        entries[index] = to_bridge_trace_list_entry(trace_list->GetTraceInfo(index));
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_status(TtdMcpTrace* trace, uint32_t* status) {
    if (trace == nullptr || status == nullptr) {
        set_error("trace and status pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    *status = static_cast<uint32_t>(trace->engine->GetIndexStatus());
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_file_stats(TtdMcpTrace* trace, TtdMcpIndexFileStats* stats) {
    if (trace == nullptr || stats == nullptr) {
        set_error("trace and stats pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    *stats = to_bridge_index_file_stats(trace->engine->GetIndexFileStats());
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_build_index(TtdMcpTrace* trace, uint32_t flags, TtdMcpIndexBuildProgress* progress, uint32_t* status) {
    if (trace == nullptr || progress == nullptr || status == nullptr) {
        set_error("trace, progress, and status pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    constexpr uint32_t allowed_flags =
        static_cast<uint32_t>(TTD::Replay::IndexBuildFlags::DeleteExistingUnloadableIndexFile)
        | static_cast<uint32_t>(TTD::Replay::IndexBuildFlags::TemporaryIndexFile)
        | static_cast<uint32_t>(TTD::Replay::IndexBuildFlags::MakeSelfContained);
    if ((flags & ~allowed_flags) != 0) {
        set_error("unsupported index build flags");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    *progress = {};
    *status = static_cast<uint32_t>(trace->engine->BuildIndex(
        index_build_progress_callback,
        progress,
        static_cast<TTD::Replay::IndexBuildFlags>(flags)));
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace* trace, TtdMcpTraceInfo* info) {
    if (trace == nullptr || info == nullptr) {
        set_error("trace and info pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(trace->mutex);
    auto const& first = trace->engine->GetFirstPosition();
    auto const& last = trace->engine->GetLastPosition();
    auto const& system_info = trace->engine->GetSystemInfo();

    *info = TtdMcpTraceInfo{
        to_bridge_position(first),
        to_bridge_position(last),
        static_cast<uint64_t>(trace->engine->GetPebAddress()),
        system_info.ProcessId,
        static_cast<uint32_t>(trace->engine->GetThreadCount()),
        static_cast<uint32_t>(trace->engine->GetModuleCount()),
        static_cast<uint32_t>(trace->engine->GetModuleInstanceCount()),
        static_cast<uint32_t>(trace->engine->GetExceptionEventCount()),
        static_cast<uint32_t>(trace->engine->GetKeyframeCount()),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace* trace, TtdMcpThreadInfo* threads, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, threads, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetThreadCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ThreadInfo const* const source = trace->engine->GetThreadList();
    for (size_t index = 0; index < required; ++index) {
        threads[index] = to_bridge_thread(source[index]);
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace* trace, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, modules, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetModuleInstanceCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ModuleInstance const* const source = trace->engine->GetModuleInstanceList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ModuleInstance const& instance = source[index];
        TtdMcpModuleInfo output = to_bridge_module(instance.pModule);
        output.load_position = to_bridge_position(instance.LoadTime);
        output.unload_position = to_bridge_position(instance.UnloadTime);
        output.has_unload_position = is_valid_sequence(instance.UnloadTime) ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);
        modules[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace* trace, TtdMcpExceptionInfo* exceptions, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, exceptions, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetExceptionEventCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ExceptionEvent const* const source = trace->engine->GetExceptionEventList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ExceptionEvent const& exception = source[index];
        TtdMcpExceptionInfo output = {};
        output.position = to_bridge_position(exception.Position);
        output.thread_unique_id = exception.pThreadInfo != nullptr ? static_cast<uint64_t>(exception.pThreadInfo->UniqueId) : 0;
        output.code = exception.Code;
        output.flags = exception.Flags;
        output.program_counter = static_cast<uint64_t>(exception.ProgramCounter);
        output.record_address = static_cast<uint64_t>(exception.RecordAddress);
        output.parameter_count = std::min(exception.ParameterCount, static_cast<uint32_t>(std::size(output.parameters)));
        for (uint32_t parameter_index = 0; parameter_index < output.parameter_count; ++parameter_index) {
            output.parameters[parameter_index] = exception.Parameters[parameter_index];
        }
        exceptions[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_keyframes(TtdMcpTrace* trace, TtdMcpPosition* keyframes, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, keyframes, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetKeyframeCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::Position const* const source = trace->engine->GetKeyframeList();
    for (size_t index = 0; index < required; ++index) {
        keyframes[index] = to_bridge_position(source[index]);
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_module_events(TtdMcpTrace* trace, TtdMcpModuleEventInfo* events, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, events, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const loaded_count = trace->engine->GetModuleLoadedEventCount();
    size_t const unloaded_count = trace->engine->GetModuleUnloadedEventCount();
    size_t const required = loaded_count + unloaded_count;
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ModuleLoadedEvent const* const loaded = trace->engine->GetModuleLoadedEventList();
    for (size_t index = 0; index < loaded_count; ++index) {
        TTD::Replay::ModuleLoadedEvent const& event = loaded[index];
        TtdMcpModuleEventInfo output = {};
        output.kind = 0;
        output.position = to_bridge_position(event.Position);
        output.module = to_bridge_module(event.pModule);
        output.module.load_position = output.position;
        events[index] = output;
    }

    TTD::Replay::ModuleUnloadedEvent const* const unloaded = trace->engine->GetModuleUnloadedEventList();
    for (size_t index = 0; index < unloaded_count; ++index) {
        TTD::Replay::ModuleUnloadedEvent const& event = unloaded[index];
        TtdMcpModuleEventInfo output = {};
        output.kind = 1;
        output.position = to_bridge_position(event.Position);
        output.module = to_bridge_module(event.pModule);
        output.module.unload_position = output.position;
        output.module.has_unload_position = 1;
        events[loaded_count + index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_thread_events(TtdMcpTrace* trace, TtdMcpThreadEventInfo* events, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, events, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const created_count = trace->engine->GetThreadCreatedEventCount();
    size_t const terminated_count = trace->engine->GetThreadTerminatedEventCount();
    size_t const required = created_count + terminated_count;
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ThreadCreatedEvent const* const created = trace->engine->GetThreadCreatedEventList();
    for (size_t index = 0; index < created_count; ++index) {
        TTD::Replay::ThreadCreatedEvent const& event = created[index];
        TtdMcpThreadEventInfo output = {};
        output.kind = 0;
        output.position = to_bridge_position(event.Position);
        if (event.pThreadInfo != nullptr) {
            output.thread = to_bridge_thread(*event.pThreadInfo);
        }
        events[index] = output;
    }

    TTD::Replay::ThreadTerminatedEvent const* const terminated = trace->engine->GetThreadTerminatedEventList();
    for (size_t index = 0; index < terminated_count; ++index) {
        TTD::Replay::ThreadTerminatedEvent const& event = terminated[index];
        TtdMcpThreadEventInfo output = {};
        output.kind = 1;
        output.position = to_bridge_position(event.Position);
        if (event.pThreadInfo != nullptr) {
            output.thread = to_bridge_thread(*event.pThreadInfo);
        }
        events[created_count + index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace* trace, TtdMcpCursor** cursor) {
    if (trace == nullptr || cursor == nullptr) {
        set_error("trace and cursor output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(trace->mutex);
    TTD::Replay::UniqueCursor owned_cursor(trace->engine->NewCursor());
    if (owned_cursor == nullptr) {
        set_error("failed to create replay cursor");
        return TTD_MCP_ERROR;
    }

    *cursor = new TtdMcpCursor{ trace, std::move(owned_cursor) };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor* cursor) {
    delete cursor;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor* cursor, TtdMcpPosition* position) {
    if (cursor == nullptr || position == nullptr) {
        set_error("cursor and position pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto const current = cursor->cursor->GetPosition();
    *position = to_bridge_position(current);
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor* cursor, TtdMcpPosition position) {
    if (cursor == nullptr) {
        set_error("cursor pointer is required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    cursor->cursor->SetPosition(to_replay_position(position));
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position_on_thread(TtdMcpCursor* cursor, uint32_t thread_unique_id, TtdMcpPosition position) {
    if (cursor == nullptr) {
        set_error("cursor pointer is required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (thread_unique_id == 0) {
        set_error("thread_unique_id must be non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    cursor->cursor->SetPositionOnThread(
        static_cast<TTD::Replay::UniqueThreadId>(thread_unique_id),
        to_replay_position(position));
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_read_memory(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, uint32_t policy, TtdMcpMemoryRead* result) {
    if (cursor == nullptr || buffer == nullptr || result == nullptr) {
        set_error("cursor, buffer, and result pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity == 0) {
        set_error("capacity must be greater than zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::QueryMemoryPolicy memory_policy = TTD::Replay::QueryMemoryPolicy::Default;
    if (!to_query_memory_policy(policy, &memory_policy)) {
        set_error("invalid query memory policy");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    auto const memory = cursor->cursor->QueryMemoryBuffer(
        static_cast<TTD::GuestAddress>(address),
        TTD::BufferView(buffer, capacity),
        memory_policy);
    size_t const bytes_read = std::min(static_cast<size_t>(capacity), memory.Memory.Size);
    void const* const source = memory.Memory.BaseAddress;
    if (source != nullptr && source != buffer && bytes_read > 0) {
        std::memmove(buffer, source, bytes_read);
    }

    *result = TtdMcpMemoryRead{
        static_cast<uint64_t>(memory.Address),
        static_cast<uint32_t>(bytes_read),
        memory.Address == static_cast<TTD::GuestAddress>(address) && bytes_read == capacity ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_range(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, uint32_t policy, TtdMcpMemoryRangeInfo* result) {
    if (cursor == nullptr || result == nullptr) {
        set_error("cursor and result pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (address == 0) {
        set_error("address must be non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && buffer == nullptr) {
        set_error("buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::QueryMemoryPolicy memory_policy = TTD::Replay::QueryMemoryPolicy::Default;
    if (!to_query_memory_policy(policy, &memory_policy)) {
        set_error("invalid query memory policy");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    auto const memory = cursor->cursor->QueryMemoryRange(static_cast<TTD::GuestAddress>(address), memory_policy);
    size_t const bytes_available = memory.Memory.Size;
    size_t const bytes_copied = std::min(static_cast<size_t>(capacity), bytes_available);
    if (buffer != nullptr && memory.Memory.BaseAddress != nullptr && bytes_copied > 0) {
        std::memmove(buffer, memory.Memory.BaseAddress, bytes_copied);
    }

    *result = TtdMcpMemoryRangeInfo{
        static_cast<uint64_t>(memory.Address),
        static_cast<uint64_t>(bytes_available),
        static_cast<uint32_t>(bytes_copied),
        static_cast<uint64_t>(memory.Sequence),
        bytes_copied == bytes_available ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_buffer_with_ranges(TtdMcpCursor* cursor, uint64_t address, uint8_t* buffer, uint32_t capacity, TtdMcpMemoryBufferRangeInfo* ranges, uint32_t range_capacity, uint32_t policy, TtdMcpMemoryBufferInfo* result) {
    if (cursor == nullptr || buffer == nullptr || result == nullptr) {
        set_error("cursor, buffer, and result pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity == 0) {
        set_error("capacity must be greater than zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (address == 0) {
        set_error("address must be non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (range_capacity == 0 || ranges == nullptr) {
        set_error("at least one output range is required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::QueryMemoryPolicy memory_policy = TTD::Replay::QueryMemoryPolicy::Default;
    if (!to_query_memory_policy(policy, &memory_policy)) {
        set_error("invalid query memory policy");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    std::vector<TTD::Replay::MemoryRange> native_ranges(range_capacity);
    auto const memory = cursor->cursor->QueryMemoryBufferWithRanges(
        static_cast<TTD::GuestAddress>(address),
        TTD::BufferView(buffer, capacity),
        native_ranges.size(),
        native_ranges.data(),
        memory_policy);

    size_t const bytes_read = std::min(static_cast<size_t>(capacity), memory.Memory.Size);
    void const* const source = memory.Memory.BaseAddress;
    if (source != nullptr && source != buffer && bytes_read > 0) {
        std::memmove(buffer, source, bytes_read);
    }

    size_t const ranges_copied = std::min(memory.RangeCount, native_ranges.size());
    for (size_t index = 0; index < ranges_copied; ++index) {
        TTD::Replay::MemoryRange const& native_range = native_ranges[index];
        uint64_t const range_address = static_cast<uint64_t>(native_range.Address);
        uint32_t offset = 0;
        if (range_address >= static_cast<uint64_t>(memory.Address)) {
            uint64_t const delta = range_address - static_cast<uint64_t>(memory.Address);
            offset = delta > std::numeric_limits<uint32_t>::max()
                ? std::numeric_limits<uint32_t>::max()
                : static_cast<uint32_t>(delta);
        }
        ranges[index] = TtdMcpMemoryBufferRangeInfo{
            range_address,
            static_cast<uint64_t>(native_range.Memory.Size),
            static_cast<uint64_t>(native_range.Sequence),
            offset,
        };
    }

    *result = TtdMcpMemoryBufferInfo{
        static_cast<uint64_t>(memory.Address),
        static_cast<uint32_t>(bytes_read),
        memory.RangeCount > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : static_cast<uint32_t>(memory.RangeCount),
        static_cast<uint32_t>(ranges_copied),
        memory.Address == static_cast<TTD::GuestAddress>(address) && bytes_read == capacity ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
        memory.RangeCount > native_ranges.size() ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_state(TtdMcpCursor* cursor, TtdMcpCursorState* state) {
    if (cursor == nullptr || state == nullptr) {
        set_error("cursor and state pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    TTD::Replay::ThreadInfo const& thread = cursor->cursor->GetThreadInfo();
    *state = TtdMcpCursorState{
        to_bridge_position(cursor->cursor->GetPosition()),
        to_bridge_position(cursor->cursor->GetPreviousPosition()),
        static_cast<uint64_t>(thread.UniqueId),
        static_cast<uint32_t>(thread.Id),
        static_cast<uint64_t>(cursor->cursor->GetTebAddress()),
        static_cast<uint64_t>(cursor->cursor->GetProgramCounter()),
        static_cast<uint64_t>(cursor->cursor->GetStackPointer()),
        static_cast<uint64_t>(cursor->cursor->GetFramePointer()),
        cursor->cursor->GetBasicReturnValue(),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_x64_context(TtdMcpCursor* cursor, uint32_t thread_id, TtdMcpX64Context* context) {
    if (cursor == nullptr || context == nullptr) {
        set_error("cursor and context pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    TTD::ThreadId const native_thread_id = thread_id == 0
        ? TTD::ThreadId::Invalid
        : static_cast<TTD::ThreadId>(thread_id);
    TTD::Replay::ThreadInfo const& thread = cursor->cursor->GetThreadInfo(native_thread_id);
    CROSS_PLATFORM_CONTEXT const cross_platform = cursor->cursor->GetCrossPlatformContext(native_thread_id);
    AVX_EXTENDED_CONTEXT const avx = cursor->cursor->GetAvxExtendedContext(native_thread_id);
    AMD64_CONTEXT const& amd64 = cross_platform.Amd64Context;

    TtdMcpX64Context output = TtdMcpX64Context{
        to_bridge_position(cursor->cursor->GetPosition(native_thread_id)),
        to_bridge_position(cursor->cursor->GetPreviousPosition(native_thread_id)),
        static_cast<uint64_t>(thread.UniqueId),
        static_cast<uint32_t>(thread.Id),
        static_cast<uint64_t>(cursor->cursor->GetTebAddress(native_thread_id)),
        amd64.ContextFlags,
        amd64.MxCsr,
        amd64.SegCs,
        amd64.SegDs,
        amd64.SegEs,
        amd64.SegFs,
        amd64.SegGs,
        amd64.SegSs,
        amd64.EFlags,
        amd64.Dr0,
        amd64.Dr1,
        amd64.Dr2,
        amd64.Dr3,
        amd64.Dr6,
        amd64.Dr7,
        amd64.Rax,
        amd64.Rcx,
        amd64.Rdx,
        amd64.Rbx,
        amd64.Rsp,
        amd64.Rbp,
        amd64.Rsi,
        amd64.Rdi,
        amd64.R8,
        amd64.R9,
        amd64.R10,
        amd64.R11,
        amd64.R12,
        amd64.R13,
        amd64.R14,
        amd64.R15,
        amd64.Rip,
        amd64.VectorControl,
        amd64.DebugControl,
        amd64.LastBranchToRip,
        amd64.LastBranchFromRip,
        amd64.LastExceptionToRip,
        amd64.LastExceptionFromRip,
    };

    for (size_t index = 0; index < std::size(output.xmm); ++index) {
        output.xmm[index] = to_bridge_vector(amd64.FltSave.XmmRegisters[index]);
    }

    M128BIT const* const ymm_high = &avx.YmmRegisters.HighPart.Ymm0;
    for (size_t index = 0; index < std::size(output.ymm_high); ++index) {
        output.ymm_high[index] = to_bridge_vector(ymm_high[index]);
    }

    *context = output;
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_active_threads(TtdMcpCursor* cursor, TtdMcpActiveThreadInfo* threads, uint32_t capacity, uint32_t* count) {
    if (cursor == nullptr || count == nullptr) {
        set_error("cursor and count pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && threads == nullptr) {
        set_error("output buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    size_t const required = cursor->cursor->GetThreadCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ActiveThreadInfo const* const source = cursor->cursor->GetThreadList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ActiveThreadInfo const& active = source[index];
        TtdMcpActiveThreadInfo output = {};
        output.current_position = to_bridge_position(active.CurrentPosition);
        output.last_valid_position = to_bridge_position(active.LastValidPosition);
        output.has_last_valid_position = is_valid_position(active.LastValidPosition) ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);

        if (active.pThread != nullptr) {
            output.thread = to_bridge_thread(*active.pThread);
            TTD::ThreadId const thread_id = active.pThread->Id;
            TTD::Replay::Position const& previous_position = cursor->cursor->GetPreviousPosition(thread_id);
            output.previous_position = to_bridge_position(previous_position);
            output.has_previous_position = is_valid_position(previous_position) ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);
            output.teb_address = static_cast<uint64_t>(cursor->cursor->GetTebAddress(thread_id));
            output.program_counter = static_cast<uint64_t>(cursor->cursor->GetProgramCounter(thread_id));
            output.stack_pointer = static_cast<uint64_t>(cursor->cursor->GetStackPointer(thread_id));
            output.frame_pointer = static_cast<uint64_t>(cursor->cursor->GetFramePointer(thread_id));
            output.basic_return_value = cursor->cursor->GetBasicReturnValue(thread_id);
        }

        threads[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_modules(TtdMcpCursor* cursor, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count) {
    if (cursor == nullptr || count == nullptr) {
        set_error("cursor and count pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && modules == nullptr) {
        set_error("output buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    size_t const required = cursor->cursor->GetModuleCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ModuleInstance const* const source = cursor->cursor->GetModuleList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ModuleInstance const& instance = source[index];
        TtdMcpModuleInfo output = to_bridge_module(instance.pModule);
        output.load_position = to_bridge_position(instance.LoadTime);
        output.unload_position = to_bridge_position(instance.UnloadTime);
        output.has_unload_position = is_valid_sequence(instance.UnloadTime) ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);
        modules[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_step_cursor(TtdMcpCursor* cursor, uint32_t direction, uint32_t count, uint8_t only_current_thread, TtdMcpStepResult* result) {
    if (cursor == nullptr || result == nullptr) {
        set_error("cursor and result pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (count == 0) {
        set_error("count must be greater than zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (direction > 1) {
        set_error("direction must be 0 for forward or 1 for backward");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(cursor->trace->mutex);
    TTD::Replay::ReplayFlags const previous_flags = cursor->cursor->GetReplayFlags();
    TTD::Replay::ReplayFlags next_flags = previous_flags;
    if (only_current_thread != 0) {
        next_flags = next_flags | TTD::Replay::ReplayOnlyCurrentThread;
    }
    cursor->cursor->SetReplayFlags(next_flags);

    TTD::Replay::ICursorView::ReplayResult const replay_result = direction == 0
        ? cursor->cursor->ReplayForward(static_cast<TTD::Replay::StepCount>(count))
        : cursor->cursor->ReplayBackward(static_cast<TTD::Replay::StepCount>(count));

    cursor->cursor->SetReplayFlags(previous_flags);

    *result = TtdMcpStepResult{
        to_bridge_position(cursor->cursor->GetPosition()),
        to_bridge_position(cursor->cursor->GetPreviousPosition()),
        static_cast<uint32_t>(replay_result.StopReason),
        static_cast<uint64_t>(replay_result.StepsExecuted),
        static_cast<uint64_t>(replay_result.InstructionsExecuted),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_memory_watchpoint(TtdMcpCursor* cursor, uint64_t address, uint32_t size, uint32_t access_mask, uint32_t direction, uint64_t thread_unique_id, TtdMcpMemoryWatchpointResult* result) {
    if (cursor == nullptr || result == nullptr) {
        set_error("cursor and result pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (address == 0) {
        set_error("address must be non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (size == 0) {
        set_error("size must be greater than zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (direction > 1) {
        set_error("direction must be 0 for forward or 1 for backward");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::DataAccessMask native_access_mask = TTD::Replay::DataAccessMask::None;
    if (!to_data_access_mask(access_mask, &native_access_mask)) {
        set_error("access_mask must be a non-zero TTD DataAccessMask bitset");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    TTD::Replay::UniqueThreadId const native_thread =
        thread_unique_id == 0
            ? TTD::Replay::UniqueThreadId::Invalid
            : static_cast<TTD::Replay::UniqueThreadId>(thread_unique_id);

    TTD::Replay::MemoryWatchpointData const watchpoint{
        static_cast<TTD::GuestAddress>(address),
        static_cast<uint64_t>(size),
        native_access_mask,
        native_thread,
    };

    std::scoped_lock lock(cursor->trace->mutex);
    if (!cursor->cursor->AddMemoryWatchpoint(watchpoint)) {
        set_error("failed to add memory watchpoint");
        return TTD_MCP_ERROR;
    }

    TTD::Replay::ICursorView::ReplayResult const replay_result = direction == 0
        ? cursor->cursor->ReplayForward(TTD::Replay::StepCount::Max)
        : cursor->cursor->ReplayBackward(TTD::Replay::StepCount::Max);

    bool const removed = cursor->cursor->RemoveMemoryWatchpoint(watchpoint);
    if (!removed) {
        set_error("failed to remove memory watchpoint");
        return TTD_MCP_ERROR;
    }

    TTD::Replay::ThreadInfo const& thread = cursor->cursor->GetThreadInfo();
    bool const found = replay_result.StopReason == TTD::Replay::EventType::MemoryWatchpoint;
    *result = TtdMcpMemoryWatchpointResult{
        to_bridge_position(cursor->cursor->GetPosition()),
        to_bridge_position(cursor->cursor->GetPreviousPosition()),
        static_cast<uint32_t>(replay_result.StopReason),
        found ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
        static_cast<uint64_t>(thread.UniqueId),
        static_cast<uint32_t>(thread.Id),
        static_cast<uint64_t>(cursor->cursor->GetProgramCounter()),
        found ? static_cast<uint64_t>(replay_result.MemoryWatchpoint.Address) : 0,
        found ? replay_result.MemoryWatchpoint.Size : 0,
        found ? static_cast<uint32_t>(replay_result.MemoryWatchpoint.AccessType) : 0,
    };
    return TTD_MCP_OK;
}
#else
struct TtdMcpTrace {};
struct TtdMcpCursor {};

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t*, const TtdMcpSymbolConfig*, TtdMcpTrace**) {
    set_error("TTD_MCP_USE_TTD_REPLAY is not enabled for this bridge build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace_at_index(const wchar_t*, const wchar_t*, uint32_t, const TtdMcpSymbolConfig*, TtdMcpTrace**) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace*) {}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_traces(const wchar_t*, const wchar_t*, TtdMcpTraceListEntry*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_status(TtdMcpTrace*, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_index_file_stats(TtdMcpTrace*, TtdMcpIndexFileStats*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_build_index(TtdMcpTrace*, uint32_t, TtdMcpIndexBuildProgress*, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace*, TtdMcpTraceInfo*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace*, TtdMcpThreadInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace*, TtdMcpModuleInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace*, TtdMcpExceptionInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_keyframes(TtdMcpTrace*, TtdMcpPosition*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_module_events(TtdMcpTrace*, TtdMcpModuleEventInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_thread_events(TtdMcpTrace*, TtdMcpThreadEventInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace*, TtdMcpCursor**) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor*) {}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor*, TtdMcpPosition*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor*, TtdMcpPosition) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position_on_thread(TtdMcpCursor*, uint32_t, TtdMcpPosition) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_read_memory(TtdMcpCursor*, uint64_t, uint8_t*, uint32_t, uint32_t, TtdMcpMemoryRead*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_range(TtdMcpCursor*, uint64_t, uint8_t*, uint32_t, uint32_t, TtdMcpMemoryRangeInfo*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_query_memory_buffer_with_ranges(TtdMcpCursor*, uint64_t, uint8_t*, uint32_t, TtdMcpMemoryBufferRangeInfo*, uint32_t, uint32_t, TtdMcpMemoryBufferInfo*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_state(TtdMcpCursor*, TtdMcpCursorState*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_x64_context(TtdMcpCursor*, uint32_t, TtdMcpX64Context*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_active_threads(TtdMcpCursor*, TtdMcpActiveThreadInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_modules(TtdMcpCursor*, TtdMcpModuleInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_step_cursor(TtdMcpCursor*, uint32_t, uint32_t, uint8_t, TtdMcpStepResult*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_memory_watchpoint(TtdMcpCursor*, uint64_t, uint32_t, uint32_t, uint32_t, uint64_t, TtdMcpMemoryWatchpointResult*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}
#endif

TTD_MCP_EXPORT const char* ttd_mcp_last_error(void) {
    return g_last_error.c_str();
}
