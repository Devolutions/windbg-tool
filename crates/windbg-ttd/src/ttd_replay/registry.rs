use super::native::{NativeBridge, NativeCursor, NativeTrace};
use super::types::*;
use super::{Position, ResolvedSymbolConfig};
use anyhow::{bail, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const PEB_PROCESS_PARAMETERS_OFFSET_X64: usize = 0x20;
const TEB_STACK_BASE_OFFSET_X64: usize = 0x08;
const TEB_STACK_LIMIT_OFFSET_X64: usize = 0x10;
const RTL_USER_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X64: usize = 0x70;
const UNICODE_STRING_X64_SIZE: usize = 16;
const MAX_COMMAND_LINE_BYTES: usize = 0x8000;
const MAX_STACK_READ_BYTES: u32 = 0x1000;
const MAX_MEMORY_RANGE_BYTES: u32 = 0x10000;
const MAX_MEMORY_BUFFER_RANGES: u32 = 1024;
const POINTER_SIZE_X64: usize = 8;

pub type SessionId = u64;
pub type CursorId = u64;

#[derive(Default)]
pub struct SessionRegistry {
    next_session_id: SessionId,
    sessions: HashMap<SessionId, TraceSession>,
}

struct TraceSession {
    info: TraceInfo,
    symbols: ResolvedSymbolConfig,
    native: Option<NativeTrace>,
    next_cursor_id: CursorId,
    cursors: HashMap<CursorId, ReplayCursor>,
}

struct ReplayCursor {
    position: Position,
    native: Option<NativeCursor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CursorCreated {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: SessionId,
    pub trace_path: std::path::PathBuf,
    pub backend: String,
    pub cursor_count: usize,
    pub cursors: Vec<CursorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorSummary {
    pub cursor_id: CursorId,
    pub position: Position,
    pub native: bool,
}

impl SessionRegistry {
    pub fn load_trace(&mut self, request: LoadTraceRequest) -> anyhow::Result<LoadTraceResponse> {
        validate_trace_path(&request.trace_path)?;

        let session_id = self.allocate_session_id();
        let symbols = request.symbols.resolve_for_process();
        let symbol_path = symbols.symbol_path.clone();
        let needs_trace_list = request.trace_index.is_some() || request.companion_path.is_some();
        let (info, native) = match try_open_native_trace(&request, &symbols) {
            Ok((info, native)) => (info, Some(native)),
            Err(error) if needs_trace_list => return Err(error),
            Err(error) => (
                placeholder_trace_info(request.trace_path.clone(), error),
                None,
            ),
        };

        self.sessions.insert(
            session_id,
            TraceSession {
                info: info.clone(),
                symbols: symbols.clone(),
                native,
                next_cursor_id: 0,
                cursors: HashMap::new(),
            },
        );

        Ok(LoadTraceResponse {
            session_id,
            trace: info,
            symbol_path,
            symbols,
        })
    }

    pub fn list_trace_file(&self, request: TraceListRequest) -> anyhow::Result<TraceListResponse> {
        validate_trace_path(&request.trace_path)?;
        NativeBridge::load()?.list_traces(&request.trace_path, request.companion_path.as_deref())
    }

    pub fn close_trace(&mut self, session_id: SessionId) -> anyhow::Result<()> {
        self.sessions
            .remove(&session_id)
            .map(|_| ())
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn cursor_count(&self) -> usize {
        self.sessions
            .values()
            .map(|session| session.cursors.len())
            .sum()
    }

    pub fn session_summaries(&self) -> Vec<SessionSummary> {
        let mut sessions = self
            .sessions
            .iter()
            .map(|(session_id, session)| {
                let mut cursors = session
                    .cursors
                    .iter()
                    .map(|(cursor_id, cursor)| CursorSummary {
                        cursor_id: *cursor_id,
                        position: cursor.position,
                        native: cursor.native.is_some(),
                    })
                    .collect::<Vec<_>>();
                cursors.sort_by_key(|cursor| cursor.cursor_id);

                SessionSummary {
                    session_id: *session_id,
                    trace_path: session.info.trace_path.clone(),
                    backend: session.info.backend.clone(),
                    cursor_count: cursors.len(),
                    cursors,
                }
            })
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| session.session_id);
        sessions
    }

    pub fn trace_info(&self, session_id: SessionId) -> anyhow::Result<TraceInfo> {
        Ok(self.session(session_id)?.info.clone())
    }

    pub fn capabilities(&self, session_id: SessionId) -> anyhow::Result<CapabilitiesResponse> {
        let session = self.session(session_id)?;
        let native = session.native.is_some();
        let command_line = native && session.info.peb_address.is_some();
        let mut limitations = Vec::new();

        if let Some(warning) = session.info.warning.as_ref() {
            limitations.push(warning.clone());
        }
        if !native {
            limitations.push(
                "native replay is unavailable; cursor replay, registers, memory, and watchpoints require the native bridge".to_string(),
            );
        }
        limitations.extend([
            "memory region enumeration is not exposed yet".to_string(),
            "symbol resolution is not exposed yet".to_string(),
            "API/call tracing is not exposed yet".to_string(),
            "console/stdout/network summary helpers are not exposed yet".to_string(),
        ]);

        Ok(CapabilitiesResponse {
            session_id,
            backend: session.info.backend.clone(),
            native,
            symbols: session.symbols.clone(),
            features: ReplayCapabilities {
                trace_info: true,
                trace_list: native,
                index_status: native,
                index_stats: native,
                build_index: native,
                close_trace: true,
                list_threads: native,
                list_modules: native,
                cursor_modules: native,
                list_keyframes: native,
                module_events: native,
                thread_events: native,
                active_threads: native,
                module_info: native,
                address_info: native,
                list_exceptions: native,
                cursor_create: true,
                position_get: true,
                position_set: true,
                position_set_thread: native,
                step: native,
                compact_registers: native,
                full_registers: native,
                avx_registers: native,
                stack_info: native,
                stack_read: native,
                command_line,
                read_memory: native,
                memory_query_policy: native,
                memory_range: native,
                memory_buffer_ranges: native,
                memory_watchpoint: native,
                memory_regions: false,
                search_memory: false,
                search_trace_strings: false,
                symbol_resolution: false,
                api_calls: false,
                call_trace: false,
                console_output: false,
                stdout_events: false,
                network_summary: false,
            },
            limitations,
        })
    }

    pub fn index_status(&self, request: IndexStatusRequest) -> anyhow::Result<IndexStatusResponse> {
        let session = self.session(request.session_id)?;
        let Some(native) = session.native.as_ref() else {
            bail!("ttd_index_status requires a native TTD replay session")
        };
        native.index_status(request.session_id)
    }

    pub fn index_stats(&self, request: IndexStatsRequest) -> anyhow::Result<IndexStatsResponse> {
        let session = self.session(request.session_id)?;
        let Some(native) = session.native.as_ref() else {
            bail!("ttd_index_stats requires a native TTD replay session")
        };
        native.index_file_stats(request.session_id)
    }

    pub fn build_index(&self, request: IndexBuildRequest) -> anyhow::Result<IndexBuildResponse> {
        let session = self.session(request.session_id)?;
        let Some(native) = session.native.as_ref() else {
            bail!("ttd_build_index requires a native TTD replay session")
        };
        let raw_flags = index_build_flags(&request.flags)?;
        native.build_index(request.session_id, raw_flags, request.flags)
    }

    pub fn list_threads(&self, session_id: SessionId) -> anyhow::Result<Vec<TraceThread>> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return native.list_threads();
        }
        Ok(Vec::new())
    }

    pub fn list_modules(&self, session_id: SessionId) -> anyhow::Result<ModuleList> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return Ok(ModuleList {
                modules: native.list_modules()?,
            });
        }

        Ok(ModuleList {
            modules: Vec::new(),
        }
        .with_symbol_hint(session.symbols.symbol_path.clone()))
    }

    pub fn cursor_modules(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<CursorModuleList> {
        let position = self.cursor_position(session_id, cursor_id)?.position;
        let cursor = self.cursor(session_id, cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_cursor_modules requires a native TTD replay cursor")
        };

        Ok(CursorModuleList {
            session_id,
            cursor_id,
            position,
            modules: native.cursor_modules()?,
        })
    }

    pub fn list_keyframes(&self, session_id: SessionId) -> anyhow::Result<KeyframeList> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return Ok(KeyframeList {
                keyframes: native.list_keyframes()?,
            });
        }

        Ok(KeyframeList {
            keyframes: Vec::new(),
        })
    }

    pub fn list_module_events(&self, session_id: SessionId) -> anyhow::Result<ModuleEventList> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return Ok(ModuleEventList {
                events: native.list_module_events()?,
            });
        }

        Ok(ModuleEventList { events: Vec::new() })
    }

    pub fn list_thread_events(&self, session_id: SessionId) -> anyhow::Result<ThreadEventList> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return Ok(ThreadEventList {
                events: native.list_thread_events()?,
            });
        }

        Ok(ThreadEventList { events: Vec::new() })
    }

    pub fn module_info(&self, request: ModuleInfoRequest) -> anyhow::Result<ModuleInfoResponse> {
        ensure!(
            request.name.is_some() || request.address.is_some(),
            "name or address is required"
        );
        let modules = self.list_modules(request.session_id)?.modules;

        if let Some(address) = request.address {
            if let Some(module) = modules
                .iter()
                .find(|module| address_in_module(address, module))
                .cloned()
            {
                return Ok(ModuleInfoResponse {
                    session_id: request.session_id,
                    matched_by: "address".to_string(),
                    module,
                });
            }
        }

        if let Some(name) = request.name.as_deref() {
            if let Some(module) = modules
                .iter()
                .find(|module| module_name_matches(module, name))
                .cloned()
            {
                return Ok(ModuleInfoResponse {
                    session_id: request.session_id,
                    matched_by: "name".to_string(),
                    module,
                });
            }
        }

        bail!("no matching module found")
    }

    pub fn address_info(&self, request: AddressInfoRequest) -> anyhow::Result<AddressInfoResponse> {
        let address = parse_address(&request.address)?;
        let registers = self.registers(request.session_id, request.cursor_id)?;
        let session = self.session(request.session_id)?;
        let peb_address = session.info.peb_address;
        let modules = self
            .cursor_modules(request.session_id, request.cursor_id)
            .map(|modules| modules.modules)
            .unwrap_or_else(|_| {
                self.list_modules(request.session_id)
                    .map(|modules| modules.modules)
                    .unwrap_or_default()
            });
        let module = modules
            .iter()
            .find(|module| address_in_module(address, module))
            .map(|module| module_coordinate(address, module));
        let stack = self
            .stack_info(request.session_id, request.cursor_id)
            .ok()
            .map(|stack| stack_context(address, &stack));
        let classification = classify_address(
            address,
            &registers,
            peb_address,
            module.as_ref(),
            stack.as_ref(),
        );

        Ok(AddressInfoResponse {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            address,
            address_hex: hex_u64(address),
            position: registers.position,
            thread: registers.thread.clone(),
            classification,
            module,
            registers: register_context(&registers),
            stack,
        })
    }

    pub fn active_threads(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<ActiveThreadList> {
        let cursor_position = self.cursor_position(session_id, cursor_id)?.position;
        let cursor = self.cursor(session_id, cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_active_threads requires a native TTD replay cursor")
        };

        let modules = self.cursor_modules(session_id, cursor_id)?.modules;
        let mut threads = native.active_threads()?;
        for thread in &mut threads {
            thread.module = modules
                .iter()
                .find(|module| address_in_module(thread.program_counter, module))
                .map(|module| module_coordinate(thread.program_counter, module));
        }

        Ok(ActiveThreadList {
            session_id,
            cursor_id,
            cursor_position,
            threads,
        })
    }

    pub fn list_exceptions(&self, session_id: SessionId) -> anyhow::Result<Vec<TraceException>> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return native.list_exceptions();
        }
        Ok(Vec::new())
    }

    pub fn create_cursor(&mut self, session_id: SessionId) -> anyhow::Result<CursorCreated> {
        let session = self.session_mut(session_id)?;
        session.next_cursor_id += 1;
        let cursor_id = session.next_cursor_id;
        let native = session
            .native
            .as_ref()
            .map(NativeTrace::new_cursor)
            .transpose()?;
        let position = if let Some(native) = native.as_ref() {
            native.position()?
        } else {
            session.info.lifetime_start
        };
        session
            .cursors
            .insert(cursor_id, ReplayCursor { position, native });
        Ok(CursorCreated {
            session_id,
            cursor_id,
            position,
        })
    }

    pub fn cursor_position(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<CursorPosition> {
        let cursor = self.cursor(session_id, cursor_id)?;
        let position = if let Some(native) = cursor.native.as_ref() {
            native.position()?
        } else {
            cursor.position
        };
        Ok(CursorPosition {
            session_id,
            cursor_id,
            position,
        })
    }

    pub fn set_position(&mut self, request: PositionRequest) -> anyhow::Result<CursorPosition> {
        let session = self.session_mut(request.session_id)?;
        let position = request
            .position
            .resolve_against(session.info.lifetime_start, session.info.lifetime_end)?;
        let cursor = session
            .cursors
            .get_mut(&request.cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {}", request.cursor_id))?;
        let actual_position = if let Some(thread_unique_id) = request.thread_unique_id {
            ensure!(thread_unique_id != 0, "thread_unique_id must be non-zero");
            ensure!(
                thread_unique_id <= u32::MAX as u64,
                "thread_unique_id is outside the native TTD range"
            );
            let Some(native) = cursor.native.as_ref() else {
                bail!("thread_unique_id requires a native TTD replay cursor")
            };
            native.set_position_on_thread(thread_unique_id as u32, position)?;
            native.position()?
        } else if let Some(native) = cursor.native.as_ref() {
            native.set_position(position)?;
            native.position()?
        } else {
            position
        };
        cursor.position = actual_position;
        Ok(CursorPosition {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            position: actual_position,
        })
    }

    pub fn step(&mut self, request: StepRequest) -> anyhow::Result<StepResult> {
        ensure!(request.count > 0, "count must be greater than zero");
        ensure!(request.count <= 10_000, "count must be 10,000 or less");
        let cursor = self.cursor_mut(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_step requires a native TTD replay cursor")
        };

        let result = native.step(
            request.session_id,
            request.cursor_id,
            request.direction,
            request.kind,
            request.count,
        )?;
        cursor.position = result.position;
        Ok(result)
    }

    pub fn registers(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<CursorRegisters> {
        let cursor = self.cursor(session_id, cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_registers requires a native TTD replay cursor")
        };

        native.registers(session_id, cursor_id)
    }

    pub fn register_context(
        &self,
        request: RegisterContextRequest,
    ) -> anyhow::Result<RegisterContextResponse> {
        let cursor = self.cursor(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_register_context requires a native TTD replay cursor")
        };

        let modules = self
            .cursor_modules(request.session_id, request.cursor_id)?
            .modules;
        let mut context =
            native.x64_context(request.session_id, request.cursor_id, request.thread_id)?;
        context.module = modules
            .iter()
            .find(|module| address_in_module(context.registers.rip, module))
            .map(|module| module_coordinate(context.registers.rip, module));
        Ok(context)
    }

    pub fn stack_info(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<StackInfo> {
        let registers = self.registers(session_id, cursor_id)?;
        let teb_address = registers
            .teb_address
            .ok_or_else(|| anyhow::anyhow!("register state does not include a TEB address"))?;
        let cursor = self.cursor(session_id, cursor_id)?;
        let teb = read_exact_memory(
            cursor,
            session_id,
            cursor_id,
            teb_address,
            (TEB_STACK_LIMIT_OFFSET_X64 + POINTER_SIZE_X64) as u32,
            "TEB stack fields",
        )?;
        let stack_base = read_u64(&teb, TEB_STACK_BASE_OFFSET_X64)
            .ok_or_else(|| anyhow::anyhow!("TEB read did not include StackBase"))?;
        let stack_limit = read_u64(&teb, TEB_STACK_LIMIT_OFFSET_X64)
            .ok_or_else(|| anyhow::anyhow!("TEB read did not include StackLimit"))?;
        let stack_pointer_in_range =
            stack_limit <= registers.stack_pointer && registers.stack_pointer <= stack_base;

        Ok(StackInfo {
            session_id,
            cursor_id,
            position: registers.position,
            thread: registers.thread,
            teb_address,
            stack_base,
            stack_limit,
            stack_pointer: registers.stack_pointer,
            frame_pointer: registers.frame_pointer,
            stack_pointer_in_range,
        })
    }

    pub fn stack_read(&self, request: StackReadRequest) -> anyhow::Result<StackReadResponse> {
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(
            request.size <= MAX_STACK_READ_BYTES,
            "size must be 4 KiB or less"
        );
        let registers = self.registers(request.session_id, request.cursor_id)?;
        let address = apply_i64_offset(registers.stack_pointer, request.offset_from_sp)?;
        ensure!(address != 0, "computed stack read address must be non-zero");
        let memory = self.read_memory(ReadMemoryRequest {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            address,
            size: request.size,
            policy: None,
        })?;
        let pointers = if request.decode_pointers {
            let bytes = hex_to_bytes(&memory.data)?;
            let modules = self.list_modules(request.session_id)?.modules;
            decode_stack_pointers(memory.address, &bytes, &modules)
        } else {
            Vec::new()
        };

        Ok(StackReadResponse {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            position: registers.position,
            stack_pointer: registers.stack_pointer,
            offset_from_sp: request.offset_from_sp,
            address: memory.address,
            requested_size: request.size,
            bytes_read: memory.bytes_read,
            complete: memory.complete,
            encoding: memory.encoding,
            data: memory.data,
            pointer_size: POINTER_SIZE_X64 as u8,
            pointers,
        })
    }

    pub fn command_line(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<ProcessCommandLine> {
        let session = self.session(session_id)?;
        let peb_address = session
            .info
            .peb_address
            .ok_or_else(|| anyhow::anyhow!("trace info does not include a PEB address"))?;
        let cursor = self.cursor(session_id, cursor_id)?;

        let peb = read_exact_memory(
            cursor,
            session_id,
            cursor_id,
            peb_address,
            (PEB_PROCESS_PARAMETERS_OFFSET_X64 + 8) as u32,
            "PEB",
        )?;
        let process_parameters_address = read_u64(&peb, PEB_PROCESS_PARAMETERS_OFFSET_X64)
            .ok_or_else(|| anyhow::anyhow!("PEB read did not include ProcessParameters"))?;
        ensure!(
            process_parameters_address != 0,
            "PEB ProcessParameters pointer is null"
        );

        let process_parameters = read_exact_memory(
            cursor,
            session_id,
            cursor_id,
            process_parameters_address + RTL_USER_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X64 as u64,
            UNICODE_STRING_X64_SIZE as u32,
            "RTL_USER_PROCESS_PARAMETERS.CommandLine",
        )?;

        let command_line_length = read_u16(&process_parameters, 0)
            .ok_or_else(|| anyhow::anyhow!("CommandLine read did not include Length"))?
            as usize;
        let command_line_maximum_length = read_u16(&process_parameters, 2)
            .ok_or_else(|| anyhow::anyhow!("CommandLine read did not include MaximumLength"))?
            as usize;
        let command_line_address = read_u64(&process_parameters, 8)
            .ok_or_else(|| anyhow::anyhow!("CommandLine read did not include Buffer"))?;

        ensure!(command_line_length > 0, "CommandLine length is zero");
        ensure!(
            command_line_length <= command_line_maximum_length,
            "CommandLine length exceeds maximum length"
        );
        ensure!(
            command_line_length <= MAX_COMMAND_LINE_BYTES,
            "CommandLine length is larger than supported maximum"
        );
        ensure!(
            command_line_length.is_multiple_of(2),
            "CommandLine length is not UTF-16 aligned"
        );
        ensure!(
            command_line_address != 0,
            "CommandLine buffer pointer is null"
        );

        let command_line_bytes = read_exact_memory(
            cursor,
            session_id,
            cursor_id,
            command_line_address,
            command_line_length as u32,
            "CommandLine buffer",
        )?;
        let command_line = utf16le_to_string(&command_line_bytes)?;

        Ok(ProcessCommandLine {
            session_id,
            cursor_id,
            peb_address,
            process_parameters_address,
            command_line_address,
            command_line,
        })
    }

    pub fn read_memory(&self, request: ReadMemoryRequest) -> anyhow::Result<ReadMemoryResponse> {
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(request.size <= 0x10000, "size must be 64 KiB or less");
        ensure!(request.address != 0, "address must be non-zero");
        let cursor = self.cursor(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_read_memory requires a native TTD replay cursor")
        };

        let policy = request.policy.unwrap_or_default();
        native.read_memory(
            request.session_id,
            request.cursor_id,
            request.address,
            request.size,
            policy,
        )
    }

    pub fn memory_range(&self, request: MemoryRangeRequest) -> anyhow::Result<MemoryRangeResponse> {
        ensure!(request.address != 0, "address must be non-zero");
        ensure!(
            request.max_bytes <= MAX_MEMORY_RANGE_BYTES,
            "max_bytes must be 64 KiB or less"
        );
        let cursor = self.cursor(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_memory_range requires a native TTD replay cursor")
        };

        let policy = request.policy.unwrap_or_default();
        let mut range = native.memory_range(
            request.session_id,
            request.cursor_id,
            request.address,
            request.max_bytes,
            policy,
        )?;
        let modules = self
            .cursor_modules(request.session_id, request.cursor_id)?
            .modules;
        range.module = modules
            .iter()
            .find(|module| address_in_module(range.range_address, module))
            .map(|module| module_coordinate(range.range_address, module));
        Ok(range)
    }

    pub fn memory_buffer(
        &self,
        request: MemoryBufferRequest,
    ) -> anyhow::Result<MemoryBufferResponse> {
        ensure!(request.address != 0, "address must be non-zero");
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(
            request.size <= MAX_MEMORY_RANGE_BYTES,
            "size must be 64 KiB or less"
        );
        ensure!(
            request.max_ranges > 0,
            "max_ranges must be greater than zero"
        );
        ensure!(
            request.max_ranges <= MAX_MEMORY_BUFFER_RANGES,
            "max_ranges must be 1024 or less"
        );
        let cursor = self.cursor(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_memory_buffer requires a native TTD replay cursor")
        };

        let policy = request.policy.unwrap_or_default();
        let mut response = native.memory_buffer_with_ranges(
            request.session_id,
            request.cursor_id,
            request.address,
            request.size,
            request.max_ranges,
            policy,
        )?;
        let modules = self
            .cursor_modules(request.session_id, request.cursor_id)?
            .modules;
        for range in &mut response.ranges {
            range.module = modules
                .iter()
                .find(|module| address_in_module(range.address, module))
                .map(|module| module_coordinate(range.address, module));
        }
        Ok(response)
    }

    pub fn memory_watchpoint(
        &mut self,
        request: MemoryWatchpointRequest,
    ) -> anyhow::Result<MemoryWatchpointResponse> {
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(request.address != 0, "address must be non-zero");
        let cursor = self.cursor_mut(request.session_id, request.cursor_id)?;
        let Some(native) = cursor.native.as_ref() else {
            bail!("ttd_memory_watchpoint requires a native TTD replay cursor")
        };

        let result = native.memory_watchpoint(&request)?;
        cursor.position = result.position;
        Ok(result)
    }

    fn allocate_session_id(&mut self) -> SessionId {
        self.next_session_id += 1;
        self.next_session_id
    }

    fn session(&self, session_id: SessionId) -> anyhow::Result<&TraceSession> {
        self.sessions
            .get(&session_id)
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    fn session_mut(&mut self, session_id: SessionId) -> anyhow::Result<&mut TraceSession> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    fn cursor(&self, session_id: SessionId, cursor_id: CursorId) -> anyhow::Result<&ReplayCursor> {
        self.session(session_id)?
            .cursors
            .get(&cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {cursor_id}"))
    }

    fn cursor_mut(
        &mut self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<&mut ReplayCursor> {
        self.session_mut(session_id)?
            .cursors
            .get_mut(&cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {cursor_id}"))
    }
}

fn read_exact_memory(
    cursor: &ReplayCursor,
    session_id: SessionId,
    cursor_id: CursorId,
    address: u64,
    size: u32,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let Some(native) = cursor.native.as_ref() else {
        bail!("{label} read requires a native TTD replay cursor")
    };
    let response = native.read_memory(
        session_id,
        cursor_id,
        address,
        size,
        QueryMemoryPolicy::Default,
    )?;
    ensure!(
        response.address == address,
        "{label} read started at {:#x}, expected {:#x}",
        response.address,
        address
    );
    ensure!(
        response.bytes_read == size as usize,
        "{label} read returned {} bytes, expected {}",
        response.bytes_read,
        size
    );
    hex_to_bytes(&response.data)
}

fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(
        hex.len().is_multiple_of(2),
        "hex string length must be even"
    );
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let high = hex_digit(chunk[0])?;
        let low = hex_digit(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> anyhow::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid hex digit"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn utf16le_to_string(bytes: &[u8]) -> anyhow::Result<String> {
    ensure!(
        bytes.len().is_multiple_of(2),
        "UTF-16LE byte count must be even"
    );
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(Into::into)
}

fn apply_i64_offset(base: u64, offset: i64) -> anyhow::Result<u64> {
    let address = if offset >= 0 {
        base.checked_add(offset as u64)
    } else {
        base.checked_sub(offset.unsigned_abs())
    };
    address.ok_or_else(|| anyhow::anyhow!("stack offset is outside the guest address range"))
}

fn decode_stack_pointers(
    stack_address: u64,
    bytes: &[u8],
    modules: &[TraceModule],
) -> Vec<StackPointerValue> {
    bytes
        .chunks_exact(POINTER_SIZE_X64)
        .enumerate()
        .filter_map(|(index, chunk)| {
            let offset = (index * POINTER_SIZE_X64) as u32;
            let raw: [u8; POINTER_SIZE_X64] = chunk.try_into().ok()?;
            let value = u64::from_le_bytes(raw);
            if value == 0 {
                return None;
            }
            Some(StackPointerValue {
                offset,
                address: stack_address.saturating_add(offset as u64),
                value,
                module: modules
                    .iter()
                    .find(|module| address_in_module(value, module))
                    .map(|module| module.name.clone()),
            })
        })
        .collect()
}

fn address_in_module(address: u64, module: &TraceModule) -> bool {
    let Some(end) = module.base_address.checked_add(module.size) else {
        return false;
    };
    module.base_address <= address && address < end
}

fn module_name_matches(module: &TraceModule, query: &str) -> bool {
    module.name.eq_ignore_ascii_case(query)
        || module
            .path
            .as_ref()
            .is_some_and(|path| path.to_string_lossy().eq_ignore_ascii_case(query))
        || module.path.as_ref().is_some_and(|path| {
            path.file_name()
                .is_some_and(|file_name| file_name.to_string_lossy().eq_ignore_ascii_case(query))
        })
}

fn parse_address(address: &str) -> anyhow::Result<u64> {
    let trimmed = address.trim();
    ensure!(!trimmed.is_empty(), "address must not be empty");
    let (digits, radix) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .map(|hex| (hex, 16))
        .unwrap_or((trimmed, 10));
    ensure!(!digits.is_empty(), "address must include digits");
    u64::from_str_radix(digits, radix)
        .map_err(|error| anyhow::anyhow!("invalid address {address:?}: {error}"))
}

fn classify_address(
    address: u64,
    registers: &CursorRegisters,
    peb_address: Option<u64>,
    module: Option<&AddressModuleCoordinate>,
    stack: Option<&AddressStackContext>,
) -> AddressClassification {
    if module.is_some() {
        AddressClassification::Module
    } else if stack.is_some_and(|stack| stack.address_in_stack) {
        AddressClassification::Stack
    } else if registers.teb_address == Some(address) {
        AddressClassification::Teb
    } else if peb_address == Some(address) {
        AddressClassification::Peb
    } else {
        AddressClassification::Unknown
    }
}

fn module_coordinate(address: u64, module: &TraceModule) -> AddressModuleCoordinate {
    let rva = address - module.base_address;
    AddressModuleCoordinate {
        name: module.name.clone(),
        path: module.path.clone(),
        runtime_base: module.base_address,
        runtime_base_hex: hex_u64(module.base_address),
        size: module.size,
        size_hex: hex_u64(module.size),
        rva,
        rva_hex: hex_u64(rva),
        module_offset: format!("{}+{}", module.name, hex_u64(rva)),
        load_position: module.load_position,
        unload_position: module.unload_position,
    }
}

fn register_context(registers: &CursorRegisters) -> AddressRegisterContext {
    AddressRegisterContext {
        program_counter: registers.program_counter,
        program_counter_hex: hex_u64(registers.program_counter),
        stack_pointer: registers.stack_pointer,
        stack_pointer_hex: hex_u64(registers.stack_pointer),
        frame_pointer: registers.frame_pointer,
        frame_pointer_hex: hex_u64(registers.frame_pointer),
        basic_return_value: registers.basic_return_value,
        basic_return_value_hex: hex_u64(registers.basic_return_value),
        teb_address: registers.teb_address,
        teb_address_hex: registers.teb_address.map(hex_u64),
    }
}

fn stack_context(address: u64, stack: &StackInfo) -> AddressStackContext {
    AddressStackContext {
        stack_base: stack.stack_base,
        stack_base_hex: hex_u64(stack.stack_base),
        stack_limit: stack.stack_limit,
        stack_limit_hex: hex_u64(stack.stack_limit),
        stack_pointer_in_range: stack.stack_pointer_in_range,
        address_in_stack: stack.stack_limit <= address && address < stack.stack_base,
        offset_from_sp: signed_delta(address, stack.stack_pointer),
        offset_from_fp: signed_delta(address, stack.frame_pointer),
    }
}

fn signed_delta(address: u64, base: u64) -> Option<i64> {
    if address >= base {
        i64::try_from(address - base).ok()
    } else {
        i64::try_from(base - address)
            .ok()
            .and_then(i64::checked_neg)
    }
}

fn hex_u64(value: u64) -> String {
    format!("{value:#x}")
}

fn try_open_native_trace(
    request: &LoadTraceRequest,
    symbols: &ResolvedSymbolConfig,
) -> anyhow::Result<(TraceInfo, NativeTrace)> {
    let bridge = NativeBridge::load()?;
    let trace_index = request.trace_index.unwrap_or_default();
    let needs_trace_list = request.trace_index.is_some() || request.companion_path.is_some();
    let trace_metadata =
        match bridge.list_traces(&request.trace_path, request.companion_path.as_deref()) {
            Ok(traces) => traces
                .traces
                .into_iter()
                .find(|trace| trace.index == trace_index),
            Err(error) if needs_trace_list => return Err(error),
            Err(_) => None,
        };
    if needs_trace_list && trace_metadata.is_none() {
        bail!("trace index {trace_index} was not found");
    }

    let native = if needs_trace_list {
        bridge.open_trace_at_index(
            &request.trace_path,
            request.companion_path.as_deref(),
            trace_index,
            symbols,
        )?
    } else {
        bridge.open_trace(&request.trace_path, symbols)?
    };
    let info = native.trace_info()?;
    let trace_file = trace_metadata
        .as_ref()
        .map(|metadata| metadata.file.clone());
    let trace_session_id = trace_metadata
        .as_ref()
        .map(|metadata| metadata.session_id.clone());
    let trace_group_id = trace_metadata
        .as_ref()
        .map(|metadata| metadata.group_id.clone());
    let recording_type = trace_metadata
        .as_ref()
        .map(|metadata| metadata.recording_type.clone());

    Ok((
        TraceInfo {
            trace_path: request.trace_path.clone(),
            backend: "ttd-replay-native".to_string(),
            index_status: "loaded".to_string(),
            trace_file,
            trace_session_id,
            trace_group_id,
            recording_type,
            process_id: info.process_id(),
            peb_address: info.peb_address(),
            lifetime_start: info.lifetime_start(),
            lifetime_end: info.lifetime_end(),
            architecture: None,
            thread_count: info.thread_count(),
            module_count: info.module_count(),
            module_instance_count: info.module_instance_count(),
            exception_count: info.exception_count(),
            keyframe_count: info.keyframe_count(),
            warning: None,
        },
        native,
    ))
}

fn placeholder_trace_info(
    trace_path: impl Into<std::path::PathBuf>,
    error: anyhow::Error,
) -> TraceInfo {
    TraceInfo {
        trace_path: trace_path.into(),
        backend: "unavailable-native-bridge".to_string(),
        index_status: "unknown".to_string(),
        trace_file: None,
        trace_session_id: None,
        trace_group_id: None,
        recording_type: None,
        process_id: None,
        peb_address: None,
        lifetime_start: Position::MIN,
        lifetime_end: Position::MIN,
        architecture: None,
        thread_count: 0,
        module_count: 0,
        module_instance_count: 0,
        exception_count: 0,
        keyframe_count: None,
        warning: Some(format!(
            "Native TTD Replay API bridge is not available yet: {error}"
        )),
    }
}

fn validate_trace_path(path: &Path) -> anyhow::Result<()> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    ensure!(
        matches!(extension.as_str(), "run" | "idx" | "ttd"),
        "trace_path must point to a .run, .idx, or .ttd trace file"
    );
    Ok(())
}

fn index_build_flags(flags: &[String]) -> anyhow::Result<u32> {
    let mut raw_flags = 0;
    for flag in flags {
        raw_flags |= match flag.as_str() {
            "delete_existing_unloadable" | "delete-existing-unloadable" => 0x01,
            "temporary" | "temporary_index_file" | "temporary-index-file" => 0x02,
            "self_contained" | "self-contained" | "make_self_contained" | "make-self-contained" => {
                0x04
            }
            "all" => 0x01 | 0x02 | 0x04,
            "none" => 0,
            other => bail!("unsupported index build flag: {other}"),
        };
    }
    Ok(raw_flags)
}

trait ModuleListExt {
    fn with_symbol_hint(self, symbol_path: String) -> Self;
}

impl ModuleListExt for ModuleList {
    fn with_symbol_hint(self, _symbol_path: String) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::ttd_replay::SymbolSettings;

    #[test]
    fn rejects_non_ttd_extensions() {
        let error = validate_trace_path(Path::new("trace.dmp")).unwrap_err();
        assert!(error.to_string().contains(".run, .idx, or .ttd"));
    }

    #[test]
    fn creates_placeholder_session_and_cursor() {
        let mut registry = SessionRegistry::default();
        let loaded = registry
            .load_trace(LoadTraceRequest {
                trace_path: PathBuf::from("sample.run"),
                companion_path: None,
                trace_index: None,
                symbols: SymbolSettings::default(),
            })
            .unwrap();
        let cursor = registry.create_cursor(loaded.session_id).unwrap();
        assert_eq!(cursor.position, Position::MIN);
    }

    #[test]
    fn trace_index_load_errors_instead_of_placeholder() {
        let mut registry = SessionRegistry::default();
        let error = registry
            .load_trace(LoadTraceRequest {
                trace_path: PathBuf::from("sample.run"),
                companion_path: None,
                trace_index: Some(7),
                symbols: SymbolSettings::default(),
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("trace")
                || error.to_string().contains("native")
                || error.to_string().contains("bridge"),
            "unexpected trace-index error: {error}"
        );
    }

    #[test]
    fn parses_index_build_flags() {
        let flags = vec![
            "delete-existing-unloadable".to_string(),
            "temporary".to_string(),
            "self_contained".to_string(),
        ];
        assert_eq!(index_build_flags(&flags).unwrap(), 0x07);
        assert!(index_build_flags(&["unknown".to_string()]).is_err());
    }
}
