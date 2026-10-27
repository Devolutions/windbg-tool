use super::{
    minidump_stream_range_status, minidump_u32, minidump_u64, MinidumpDirectoryEntry,
    MinidumpDirectoryInventory, StackTraceResult, X64ExceptionRegisters, X64_CONTEXT_SIZE,
};
use anyhow::{ensure, Context};
use serde::Serialize;
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const EXCEPTION_STREAM_SIZE: usize = 168;
const MAX_EXCEPTION_PARAMETERS: u32 = 15;
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const CONTEXT_EX_PREFIX_SIZE: u32 = 24;
const XSAVE_AREA_HEADER_SIZE: u32 = 64;
const CPP_EXCEPTION_CODE: u32 = 0xE06D_7363;
const CPP_EXCEPTION_MAGIC: [u64; 4] = [0x1993_0520, 0x1993_0521, 0x1993_0522, 0x0199_4000];
const CPP_STD_EXCEPTION_TYPE: &str = ".?AVexception@std@@";
const MAX_CPP_CATCHABLE_TYPE_COUNT: u32 = 64;
pub const MAX_USER_EXCEPTION_STACK_FRAMES: u32 = 128;
pub const MAX_USER_EXCEPTION_CONTEXT_BYTES: u32 = X64_CONTEXT_SIZE;
pub const MAX_NESTED_EXCEPTION_RECORDS: usize = 8;
pub const MAX_CPP_EXCEPTION_TYPES: u32 = 16;
pub const MAX_EXCEPTION_STRING_BYTES: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextArchitecture {
    X86,
    Amd64,
    Arm64,
}

impl ContextArchitecture {
    pub fn from_processor_architecture(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::X86),
            9 => Some(Self::Amd64),
            12 => Some(Self::Arm64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    pub fn pointer_size(self) -> u32 {
        match self {
            Self::X86 => 4,
            Self::Amd64 | Self::Arm64 => 8,
        }
    }

    pub fn context_size(self) -> usize {
        match self {
            Self::X86 => 0x2CC,
            Self::Amd64 => X64_CONTEXT_SIZE as usize,
            Self::Arm64 => 0x390,
        }
    }

    fn minimum_context_size(self) -> usize {
        match self {
            // CONTEXT_i386 without the 512-byte ExtendedRegisters tail.
            Self::X86 => 0xCC,
            _ => self.context_size(),
        }
    }

    fn flags_offset(self) -> usize {
        match self {
            Self::Amd64 => 0x30,
            Self::X86 | Self::Arm64 => 0,
        }
    }

    fn architecture_flag(self) -> u32 {
        match self {
            Self::X86 => 0x0001_0000,
            Self::Amd64 => 0x0010_0000,
            Self::Arm64 => 0x0040_0000,
        }
    }

    fn xstate_flag(self) -> u32 {
        match self {
            Self::Arm64 => 0x20,
            Self::X86 | Self::Amd64 => 0x40,
        }
    }

    #[cfg(windows)]
    fn machine_type(self) -> u32 {
        match self {
            Self::X86 => 0x014C,
            Self::Amd64 => 0x8664,
            Self::Arm64 => 0xAA64,
        }
    }
}

/// Reads guest virtual memory captured in a dump. Implementations may return fewer bytes than
/// requested when the dump only captured part of the range.
pub trait GuestMemory {
    fn read_guest(&self, address: u64, size: u32) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug, Serialize)]
pub struct MinidumpException {
    pub source: &'static str,
    pub status: String,
    pub thread_system_id: Option<u32>,
    pub record: Option<MinidumpExceptionRecord>,
    pub context: MinidumpExceptionContext,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct MinidumpExceptionRecord {
    pub exception_code: u32,
    pub code_name: Option<&'static str>,
    pub exception_flags: u32,
    pub noncontinuable: bool,
    pub nested_exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub parameters: Vec<u64>,
    pub access: Option<ExceptionAccess>,
    pub fast_fail: Option<FastFailInfo>,
    pub cpp_exception: Option<CppExceptionInfo>,
    pub clr_exception: Option<ClrExceptionInfo>,
    pub nested_records: NestedExceptionChain,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionAccess {
    pub operation: &'static str,
    pub mode: u64,
    pub address: u64,
    pub io_status: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct FastFailInfo {
    pub code: u64,
    pub name: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ClrExceptionInfo {
    pub runtime: &'static str,
    pub hresult: Option<u32>,
    pub detail: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct CppExceptionInfo {
    pub status: String,
    pub magic: Option<u64>,
    pub object: Option<u64>,
    pub throw_info: Option<u64>,
    pub image_base: Option<u64>,
    pub catchable_type_count: Option<u32>,
    pub types: Vec<CppExceptionType>,
    pub types_truncated: bool,
    pub what: Option<String>,
    pub what_truncated: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct CppExceptionType {
    pub decorated_name: String,
    pub name: Option<String>,
    pub name_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct NestedExceptionChain {
    pub status: String,
    pub records: Vec<NestedExceptionRecord>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct NestedExceptionRecord {
    pub record_address: u64,
    pub exception_code: u32,
    pub code_name: Option<&'static str>,
    pub exception_flags: u32,
    pub nested_exception_record: u64,
    pub exception_address: u64,
    pub parameters: Vec<u64>,
    pub access: Option<ExceptionAccess>,
}

#[derive(Debug, Clone, Serialize)]
pub struct X86ExceptionRegisters {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub eflags: u32,
    pub cs: u32,
    pub ss: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Arm64ExceptionRegisters {
    pub x: Vec<u64>,
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
}

#[derive(Debug, Default, Serialize)]
pub struct ExtendedStateSummary {
    pub status: String,
    pub context_ex_offset: Option<u32>,
    pub xstate_offset: Option<i32>,
    pub xstate_length: Option<u32>,
    pub mask: Option<u64>,
    pub compaction_mask: Option<u64>,
    pub compacted: Option<bool>,
    pub features: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Default, Serialize)]
pub struct MinidumpExceptionContext {
    pub status: String,
    pub context_record_rva: Option<u32>,
    pub declared_size: Option<u32>,
    pub bytes_read: u32,
    pub processor_architecture: Option<u16>,
    pub architecture: Option<&'static str>,
    pub context_flags: Option<u32>,
    pub instruction_pointer: Option<u64>,
    pub stack_pointer: Option<u64>,
    pub registers: Option<X64ExceptionRegisters>,
    pub x86_registers: Option<X86ExceptionRegisters>,
    pub arm64_registers: Option<Arm64ExceptionRegisters>,
    pub extended_state: Option<ExtendedStateSummary>,
    pub stack: Option<StackTraceResult>,
    pub detail: String,
    #[serde(skip)]
    raw_context: Vec<u8>,
    #[serde(skip)]
    arch: Option<ContextArchitecture>,
}

impl MinidumpExceptionContext {
    pub fn architecture_kind(&self) -> Option<ContextArchitecture> {
        self.arch
    }
}

fn inspect_exception(path: &Path, directory: &MinidumpDirectoryInventory) -> MinidumpException {
    let mut result = MinidumpException {
        source: "minidump_exception_stream",
        status: "unavailable".into(),
        thread_system_id: None,
        record: None,
        context: MinidumpExceptionContext {
            status: "not_present".into(),
            detail: "No exception context descriptor has been captured.".into(),
            ..Default::default()
        },
        detail: String::new(),
    };
    if directory.status == "not_minidump" {
        result.status = "not_minidump".into();
        result.detail = "User exception decoding requires the documented MDMP format.".into();
        return result;
    }
    let capture = (|| -> anyhow::Result<()> {
        ensure!(
            matches!(
                directory.status.as_str(),
                "captured" | "captured_with_invalid_stream_ranges"
            ),
            "The MINIDUMP directory is unavailable: {}",
            directory.detail
        );
        ensure!(
            directory.version.map(|version| version & 0xffff) == Some(0xa793),
            "Unsupported MINIDUMP header version"
        );
        let Some(entry) = unique_stream(directory, 6)? else {
            result.status = "not_present".into();
            result.detail = "The dump has no ExceptionStream; current thread state is not substituted for exception evidence.".into();
            return Ok(());
        };
        let mut file = File::open(path).context("opening dump for bounded exception inspection")?;
        let file_bytes = file.metadata()?.len();
        let bytes = read_prefix(
            &mut file,
            file_bytes,
            entry.data_rva,
            entry.data_size,
            EXCEPTION_STREAM_SIZE,
        )?;
        let number_parameters = minidump_u32(&bytes, 32);
        ensure!(
            number_parameters <= MAX_EXCEPTION_PARAMETERS,
            "Exception parameter count exceeds 15"
        );
        let parameters = (0..number_parameters as usize)
            .map(|index| minidump_u64(&bytes, 40 + index * 8))
            .collect::<Vec<_>>();
        result.thread_system_id = Some(minidump_u32(&bytes, 0));
        result.record = Some(exception_record(
            minidump_u32(&bytes, 8),
            minidump_u32(&bytes, 12),
            minidump_u64(&bytes, 16),
            minidump_u64(&bytes, 24),
            parameters,
        ));
        result.status = "captured".into();
        result.detail = "Captured the documented ExceptionStream record, not a stack scan or current debugger event. Nested records and C++ throw details are read from dump memory separately and only when captured.".into();
        result.context.declared_size = Some(minidump_u32(&bytes, 160));
        result.context.context_record_rva = Some(minidump_u32(&bytes, 164));
        if let Err(error) = read_context(&mut file, file_bytes, directory, &mut result.context) {
            result.context.status = "unavailable".into();
            result.context.detail =
                format!("Exception record captured, but context unavailable: {error:#}");
        }
        Ok(())
    })();
    if let Err(error) = capture {
        result.detail = format!("Could not capture a unique, valid ExceptionStream: {error:#}");
    }
    result
}

fn exception_record(
    exception_code: u32,
    exception_flags: u32,
    nested_exception_record: u64,
    exception_address: u64,
    parameters: Vec<u64>,
) -> MinidumpExceptionRecord {
    MinidumpExceptionRecord {
        exception_code,
        code_name: exception_code_name(exception_code),
        exception_flags,
        noncontinuable: exception_flags & EXCEPTION_NONCONTINUABLE != 0,
        nested_exception_record,
        exception_address,
        number_parameters: parameters.len() as u32,
        access: exception_access(exception_code, &parameters),
        fast_fail: fast_fail(exception_code, &parameters),
        cpp_exception: None,
        clr_exception: clr_exception(exception_code, &parameters),
        nested_records: if nested_exception_record == 0 {
            NestedExceptionChain {
                status: "none".into(),
                records: Vec::new(),
                detail: "The captured record has no nested exception pointer.".into(),
            }
        } else {
            NestedExceptionChain {
                status: "not_followed".into(),
                records: Vec::new(),
                detail: "The nested exception pointer has not been followed through dump memory."
                    .into(),
            }
        },
        parameters,
    }
}

pub fn exception_code_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x4000_001F => "STATUS_WX86_BREAKPOINT",
        0x4001_0005 => "DBG_CONTROL_C",
        0x8000_0001 => "STATUS_GUARD_PAGE_VIOLATION",
        0x8000_0002 => "STATUS_DATATYPE_MISALIGNMENT",
        0x8000_0003 => "STATUS_BREAKPOINT",
        0x8000_0004 => "STATUS_SINGLE_STEP",
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0006 => "STATUS_IN_PAGE_ERROR",
        0xC000_0008 => "STATUS_INVALID_HANDLE",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0025 => "STATUS_NONCONTINUABLE_EXCEPTION",
        0xC000_0026 => "STATUS_INVALID_DISPOSITION",
        0xC000_008C => "STATUS_ARRAY_BOUNDS_EXCEEDED",
        0xC000_008E => "STATUS_FLOAT_DIVIDE_BY_ZERO",
        0xC000_0090 => "STATUS_FLOAT_INVALID_OPERATION",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_0095 => "STATUS_INTEGER_OVERFLOW",
        0xC000_0096 => "STATUS_PRIVILEGED_INSTRUCTION",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0xC000_0194 => "STATUS_POSSIBLE_DEADLOCK",
        0xC000_027B => "STATUS_STOWED_EXCEPTION",
        0xC000_0374 => "STATUS_HEAP_CORRUPTION",
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xC000_0417 => "STATUS_INVALID_CRUNTIME_PARAMETER",
        0xC000_041D => "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
        0xC000_0420 => "STATUS_ASSERTION_FAILURE",
        0xC000_0602 => "STATUS_FAIL_FAST_EXCEPTION",
        CPP_EXCEPTION_CODE => "MSVC_CPP_EXCEPTION",
        0xE043_4352 => "CLR_EXCEPTION",
        0xE043_4F4D => "CLR_EXCEPTION_LEGACY",
        _ => return None,
    })
}

pub fn fast_fail_name(code: u64) -> Option<&'static str> {
    Some(match code {
        0 => "FAST_FAIL_LEGACY_GS_VIOLATION",
        1 => "FAST_FAIL_VTGUARD_CHECK_FAILURE",
        2 => "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE",
        3 => "FAST_FAIL_CORRUPT_LIST_ENTRY",
        4 => "FAST_FAIL_INCORRECT_STACK",
        5 => "FAST_FAIL_INVALID_ARG",
        6 => "FAST_FAIL_GS_COOKIE_INIT",
        7 => "FAST_FAIL_FATAL_APP_EXIT",
        8 => "FAST_FAIL_RANGE_CHECK_FAILURE",
        9 => "FAST_FAIL_UNSAFE_REGISTRY_ACCESS",
        10 => "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
        11 => "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE",
        12 => "FAST_FAIL_INVALID_FIBER_SWITCH",
        13 => "FAST_FAIL_INVALID_SET_OF_CONTEXT",
        14 => "FAST_FAIL_INVALID_REFERENCE_COUNT",
        18 => "FAST_FAIL_INVALID_JUMP_BUFFER",
        19 => "FAST_FAIL_MRDATA_MODIFIED",
        20 => "FAST_FAIL_CERTIFICATION_FAILURE",
        21 => "FAST_FAIL_INVALID_EXCEPTION_CHAIN",
        22 => "FAST_FAIL_CRYPTO_LIBRARY",
        23 => "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT",
        24 => "FAST_FAIL_INVALID_IMAGE_BASE",
        25 => "FAST_FAIL_DLOAD_PROTECTION_FAILURE",
        26 => "FAST_FAIL_UNSAFE_EXTENSION_CALL",
        27 => "FAST_FAIL_DEPRECATED_SERVICE_INVOKED",
        28 => "FAST_FAIL_INVALID_BUFFER_ACCESS",
        29 => "FAST_FAIL_INVALID_BALANCED_TREE",
        30 => "FAST_FAIL_INVALID_NEXT_THREAD",
        32 => "FAST_FAIL_APCS_DISABLED",
        33 => "FAST_FAIL_INVALID_IDLE_STATE",
        34 => "FAST_FAIL_MRDATA_PROTECTION_FAILURE",
        35 => "FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION",
        36 => "FAST_FAIL_INVALID_LOCK_STATE",
        38 => "FAST_FAIL_INVALID_LONGJUMP_TARGET",
        39 => "FAST_FAIL_INVALID_DISPATCH_CONTEXT",
        40 => "FAST_FAIL_INVALID_THREAD",
        44 => "FAST_FAIL_GUARD_SS_FAILURE",
        46 => "FAST_FAIL_GUARD_EXPORT_SUPPRESSION_FAILURE",
        47 => "FAST_FAIL_INVALID_CONTROL_STACK",
        48 => "FAST_FAIL_SET_CONTEXT_DENIED",
        49 => "FAST_FAIL_INVALID_IAT",
        50 => "FAST_FAIL_HEAP_METADATA_CORRUPTION",
        51 => "FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION",
        53 => "FAST_FAIL_ENCLAVE_CALL_FAILURE",
        54 => "FAST_FAIL_UNHANDLED_LSS_EXCEPTON",
        56 => "FAST_FAIL_UNEXPECTED_CALL",
        57 => "FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS",
        58 => "FAST_FAIL_UNEXPECTED_HOST_BEHAVIOR",
        59 => "FAST_FAIL_FLAGS_CORRUPTION",
        60 => "FAST_FAIL_VEH_CORRUPTION",
        61 => "FAST_FAIL_ETW_CORRUPTION",
        62 => "FAST_FAIL_RIO_ABORT",
        63 => "FAST_FAIL_INVALID_PFN",
        64 => "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE_XFG",
        66 => "FAST_FAIL_HOST_VISIBILITY_CHANGE",
        67 => "FAST_FAIL_KERNEL_CET_SHADOW_STACK_ASSIST",
        68 => "FAST_FAIL_PATCH_CALLBACK_FAILED",
        69 => "FAST_FAIL_NTDLL_PATCH_FAILED",
        70 => "FAST_FAIL_INVALID_FLS_DATA",
        72 => "FAST_FAIL_CLR_EXCEPTION_AOT",
        73 => "FAST_FAIL_POINTER_AUTH_INVALID_RETURN_ADDRESS",
        74 => "FAST_FAIL_INVALID_THREAD_STATE",
        75 => "FAST_FAIL_CORRUPT_WOW64_STATE",
        76 => "FAST_FAIL_INVALID_EXTENDED_STATE",
        77 => "FAST_FAIL_KERNEL_POINTER_EXPECTED",
        _ => return None,
    })
}

fn exception_access(code: u32, parameters: &[u64]) -> Option<ExceptionAccess> {
    let io_status = match code {
        0xC000_0005 if parameters.len() >= 2 => None,
        0xC000_0006 if parameters.len() >= 3 => Some(parameters[2]),
        _ => return None,
    };
    Some(ExceptionAccess {
        operation: match parameters[0] {
            0 => "read",
            1 => "write",
            8 => "execute",
            _ => "unknown",
        },
        mode: parameters[0],
        address: parameters[1],
        io_status,
    })
}

fn fast_fail(code: u32, parameters: &[u64]) -> Option<FastFailInfo> {
    if code != 0xC000_0409 {
        return None;
    }
    let code = *parameters.first()?;
    Some(FastFailInfo {
        code,
        name: fast_fail_name(code),
    })
}

fn clr_exception(code: u32, parameters: &[u64]) -> Option<ClrExceptionInfo> {
    let runtime = match code {
        0xE043_4352 => ".NET Framework 4+ or CoreCLR",
        0xE043_4F4D => ".NET Framework 1.x/2.0",
        _ => return None,
    };
    Some(ClrExceptionInfo {
        runtime,
        hresult: parameters.first().map(|value| *value as u32),
        detail: "Managed exception object, type and message are not decoded from the native record; use SOS (!pe) or the CoreCLR DAC.",
    })
}

/// Follows nested exception records and decodes MSVC C++ throw details through dump memory.
pub fn decode_guest_exception_details(
    record: &mut MinidumpExceptionRecord,
    architecture: Option<ContextArchitecture>,
    memory: &dyn GuestMemory,
) {
    record.nested_records =
        nested_exception_chain(record.nested_exception_record, architecture, memory);
    record.cpp_exception = cpp_exception(
        record.exception_code,
        &record.parameters,
        architecture,
        memory,
    );
}

fn nested_exception_chain(
    first: u64,
    architecture: Option<ContextArchitecture>,
    memory: &dyn GuestMemory,
) -> NestedExceptionChain {
    let mut chain = NestedExceptionChain {
        status: "none".into(),
        records: Vec::new(),
        detail: "The captured record has no nested exception pointer.".into(),
    };
    if first == 0 {
        return chain;
    }
    let Some(architecture) = architecture else {
        chain.status = "architecture_unknown".into();
        chain.detail =
            "The nested EXCEPTION_RECORD layout depends on the SystemInfo architecture.".into();
        return chain;
    };
    let mut visited = HashSet::new();
    let mut next = first;
    loop {
        if next == 0 {
            chain.status = "captured".into();
            chain.detail = format!(
                "Followed {} nested EXCEPTION_RECORD pointer(s) through dump memory.",
                chain.records.len()
            );
            break;
        }
        if !visited.insert(next) {
            chain.status = "cycle_detected".into();
            chain.detail = format!("Nested record {next:#x} was already visited; stopped.");
            break;
        }
        if chain.records.len() >= MAX_NESTED_EXCEPTION_RECORDS {
            chain.status = "depth_limited".into();
            chain.detail = format!(
                "Stopped after {MAX_NESTED_EXCEPTION_RECORDS} nested records; next pointer {next:#x} was not followed."
            );
            break;
        }
        match read_guest_exception_record(memory, architecture, next) {
            Ok(record) => {
                next = record.nested_exception_record;
                chain.records.push(record);
            }
            Err(error) => {
                chain.status = "unreadable".into();
                chain.detail =
                    format!("Could not read nested EXCEPTION_RECORD at {next:#x}: {error:#}");
                break;
            }
        }
    }
    chain
}

fn read_guest_exception_record(
    memory: &dyn GuestMemory,
    architecture: ContextArchitecture,
    address: u64,
) -> anyhow::Result<NestedExceptionRecord> {
    let wide = architecture.pointer_size() == 8;
    let size = if wide { 152 } else { 80 };
    let bytes = memory.read_guest(address, size)?;
    ensure!(
        bytes.len() == size as usize,
        "Only {} of {size} bytes are captured",
        bytes.len()
    );
    let pointer = |offset: usize| {
        if wide {
            minidump_u64(&bytes, offset)
        } else {
            u64::from(minidump_u32(&bytes, offset))
        }
    };
    let (record_offset, address_offset, count_offset, info_offset) = if wide {
        (8, 16, 24, 32)
    } else {
        (8, 12, 16, 20)
    };
    let count = minidump_u32(&bytes, count_offset);
    ensure!(
        count <= MAX_EXCEPTION_PARAMETERS,
        "Nested exception parameter count {count} exceeds 15"
    );
    let step = architecture.pointer_size() as usize;
    let parameters = (0..count as usize)
        .map(|index| pointer(info_offset + index * step))
        .collect::<Vec<_>>();
    let code = minidump_u32(&bytes, 0);
    Ok(NestedExceptionRecord {
        record_address: address,
        exception_code: code,
        code_name: exception_code_name(code),
        exception_flags: minidump_u32(&bytes, 4),
        nested_exception_record: pointer(record_offset),
        exception_address: pointer(address_offset),
        access: exception_access(code, &parameters),
        parameters,
    })
}

fn cpp_exception(
    code: u32,
    parameters: &[u64],
    architecture: Option<ContextArchitecture>,
    memory: &dyn GuestMemory,
) -> Option<CppExceptionInfo> {
    if code != CPP_EXCEPTION_CODE {
        return None;
    }
    let mut info = CppExceptionInfo {
        status: "unavailable".into(),
        magic: parameters.first().copied(),
        object: parameters.get(1).copied(),
        throw_info: parameters.get(2).copied(),
        ..Default::default()
    };
    let result = (|| -> anyhow::Result<()> {
        let architecture = architecture.context("Architecture is unknown")?;
        let pointer_size = architecture.pointer_size();
        let relative = pointer_size == 8;
        let required = if relative { 4 } else { 3 };
        ensure!(
            parameters.len() >= required,
            "MSVC C++ exception has {} parameters, expected at least {required}",
            parameters.len()
        );
        ensure!(
            CPP_EXCEPTION_MAGIC.contains(&parameters[0]),
            "Unrecognized MSVC C++ exception magic {:#x}",
            parameters[0]
        );
        let object = parameters[1];
        let throw_info = parameters[2];
        let image_base = relative.then(|| parameters[3]);
        info.image_base = image_base;
        ensure!(
            throw_info != 0,
            "ThrowInfo is null (rethrow without an active object or non-standard throw)"
        );
        let resolve = |value: u32| match image_base {
            Some(base) => base.wrapping_add(u64::from(value)),
            None => u64::from(value),
        };
        let throw_info_bytes = read_exact(memory, throw_info, 16).context("reading ThrowInfo")?;
        let catchable_array_field = minidump_u32(&throw_info_bytes, 12);
        ensure!(
            catchable_array_field != 0,
            "ThrowInfo has no CatchableTypeArray"
        );
        let catchable_array = resolve(catchable_array_field);
        let count = minidump_u32(
            &read_exact(memory, catchable_array, 4).context("reading CatchableTypeArray")?,
            0,
        );
        ensure!(
            (1..=MAX_CPP_CATCHABLE_TYPE_COUNT).contains(&count),
            "Implausible catchable type count {count}"
        );
        info.catchable_type_count = Some(count);
        let take = count.min(MAX_CPP_EXCEPTION_TYPES);
        info.types_truncated = count > take;
        let entries = read_exact(memory, catchable_array + 4, take * 4)
            .context("reading CatchableTypeArray entries")?;
        for index in 0..take as usize {
            let catchable_type = resolve(minidump_u32(&entries, index * 4));
            let catchable = read_exact(memory, catchable_type, 8)
                .with_context(|| format!("reading CatchableType {index}"))?;
            let type_descriptor = resolve(minidump_u32(&catchable, 4));
            let (decorated_name, name_truncated) =
                read_c_string(memory, type_descriptor + u64::from(pointer_size) * 2)
                    .with_context(|| format!("reading TypeDescriptor {index} name"))?;
            info.types.push(CppExceptionType {
                name: undecorate_type_name(&decorated_name),
                decorated_name,
                name_truncated,
            });
        }
        if object != 0
            && info
                .types
                .iter()
                .any(|entry| entry.decorated_name == CPP_STD_EXCEPTION_TYPE)
        {
            let what_pointer = read_exact(memory, object + u64::from(pointer_size), pointer_size)
                .context("reading std::exception data")?;
            let what_pointer = if relative {
                minidump_u64(&what_pointer, 0)
            } else {
                u64::from(minidump_u32(&what_pointer, 0))
            };
            if what_pointer != 0 {
                let (what, truncated) =
                    read_c_string(memory, what_pointer).context("reading what() string")?;
                info.what = Some(what);
                info.what_truncated = truncated;
            }
        }
        info.status = "decoded".into();
        info.detail = format!(
            "Decoded MSVC ThrowInfo catchable types through dump memory ({} layout). what() is read only for std::exception-derived objects with the MSVC layout, bounded to {MAX_EXCEPTION_STRING_BYTES} bytes, with control characters replaced.",
            if relative { "image-relative" } else { "absolute-pointer" }
        );
        Ok(())
    })();
    if let Err(error) = result {
        info.detail = format!(
            "MSVC C++ exception details are unavailable (the dump may not capture the throw metadata): {error:#}"
        );
    }
    Some(info)
}

fn read_exact(memory: &dyn GuestMemory, address: u64, size: u32) -> anyhow::Result<Vec<u8>> {
    let bytes = memory.read_guest(address, size)?;
    ensure!(
        bytes.len() == size as usize,
        "Only {} of {size} bytes at {address:#x} are captured",
        bytes.len()
    );
    Ok(bytes)
}

fn read_c_string(memory: &dyn GuestMemory, address: u64) -> anyhow::Result<(String, bool)> {
    let bytes = memory.read_guest(address, MAX_EXCEPTION_STRING_BYTES)?;
    ensure!(!bytes.is_empty(), "No bytes at {address:#x} are captured");
    let end = bytes.iter().position(|byte| *byte == 0);
    let text = String::from_utf8_lossy(&bytes[..end.unwrap_or(bytes.len())])
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect();
    Ok((text, end.is_none()))
}

pub fn undecorate_type_name(decorated: &str) -> Option<String> {
    let body = decorated
        .strip_prefix(".?AV")
        .or_else(|| decorated.strip_prefix(".?AU"))?
        .strip_suffix("@@")?;
    if body.is_empty() || body.contains(['?', '$']) {
        return None;
    }
    let parts = body.split('@').collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    Some(parts.into_iter().rev().collect::<Vec<_>>().join("::"))
}

fn unique_stream(
    directory: &MinidumpDirectoryInventory,
    stream_type: u32,
) -> anyhow::Result<Option<&MinidumpDirectoryEntry>> {
    let mut entries = directory
        .entries
        .iter()
        .filter(|entry| entry.stream_type == stream_type);
    let first = entries.next();
    ensure!(
        entries.next().is_none(),
        "Ambiguous stream type {stream_type}: multiple entries"
    );
    Ok(first)
}

fn read_prefix(
    file: &mut File,
    file_bytes: u64,
    rva: u32,
    declared_size: u32,
    prefix_size: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        minidump_stream_range_status(file_bytes, rva, declared_size) == "within_file",
        "MINIDUMP file range is invalid (RVA {rva:#x}, size {declared_size})"
    );
    ensure!(
        declared_size as usize >= prefix_size,
        "Partial record: {declared_size} bytes declared, {prefix_size} required"
    );
    file.seek(SeekFrom::Start(u64::from(rva)))?;
    let mut bytes = vec![0; prefix_size];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_context(
    file: &mut File,
    file_bytes: u64,
    directory: &MinidumpDirectoryInventory,
    context: &mut MinidumpExceptionContext,
) -> anyhow::Result<()> {
    let system =
        unique_stream(directory, 7)?.context("No SystemInfoStream for architecture validation")?;
    ensure!(
        system.data_size >= 56,
        "Partial MINIDUMP_SYSTEM_INFO record"
    );
    let info = read_prefix(file, file_bytes, system.data_rva, system.data_size, 2)?;
    let processor = u16::from_le_bytes([info[0], info[1]]);
    context.processor_architecture = Some(processor);
    let Some(arch) = ContextArchitecture::from_processor_architecture(processor) else {
        context.status = "architecture_unsupported".into();
        context.detail = format!(
            "Exception records are architecture-independent, but context decoding supports x86 (0), AMD64 (9) and ARM64 (12) SystemInfo; found {processor}."
        );
        return Ok(());
    };
    context.arch = Some(arch);
    context.architecture = Some(arch.name());
    let rva = context.context_record_rva.context("No context RVA")?;
    let declared = context.declared_size.context("No context size")?;
    ensure!(
        declared as usize >= arch.minimum_context_size(),
        "Partial {} CONTEXT: {declared} bytes declared, {} required",
        arch.name(),
        arch.minimum_context_size()
    );
    let read_size = (declared as usize).min(arch.context_size());
    let mut bytes = read_prefix(file, file_bytes, rva, declared, read_size)?;
    context.bytes_read = bytes.len() as u32;
    let flags = minidump_u32(&bytes, arch.flags_offset());
    context.context_flags = Some(flags);
    let required = arch.architecture_flag() | 0x3;
    ensure!(
        flags & 0x00ff_0000 == arch.architecture_flag() && flags & required == required,
        "CONTEXT lacks the {} control and integer register groups (flags {flags:#x})",
        arch.name()
    );
    match arch {
        ContextArchitecture::Amd64 => {
            let registers = X64ExceptionRegisters {
                rax: minidump_u64(&bytes, 0x78),
                rcx: minidump_u64(&bytes, 0x80),
                rdx: minidump_u64(&bytes, 0x88),
                rbx: minidump_u64(&bytes, 0x90),
                rsp: minidump_u64(&bytes, 0x98),
                rbp: minidump_u64(&bytes, 0xa0),
                rsi: minidump_u64(&bytes, 0xa8),
                rdi: minidump_u64(&bytes, 0xb0),
                r8: minidump_u64(&bytes, 0xb8),
                r9: minidump_u64(&bytes, 0xc0),
                r10: minidump_u64(&bytes, 0xc8),
                r11: minidump_u64(&bytes, 0xd0),
                r12: minidump_u64(&bytes, 0xd8),
                r13: minidump_u64(&bytes, 0xe0),
                r14: minidump_u64(&bytes, 0xe8),
                r15: minidump_u64(&bytes, 0xf0),
                rip: minidump_u64(&bytes, 0xf8),
                eflags: minidump_u32(&bytes, 0x44),
            };
            context.instruction_pointer = Some(registers.rip);
            context.stack_pointer = Some(registers.rsp);
            context.registers = Some(registers);
        }
        ContextArchitecture::X86 => {
            let registers = X86ExceptionRegisters {
                edi: minidump_u32(&bytes, 0x9c),
                esi: minidump_u32(&bytes, 0xa0),
                ebx: minidump_u32(&bytes, 0xa4),
                edx: minidump_u32(&bytes, 0xa8),
                ecx: minidump_u32(&bytes, 0xac),
                eax: minidump_u32(&bytes, 0xb0),
                ebp: minidump_u32(&bytes, 0xb4),
                eip: minidump_u32(&bytes, 0xb8),
                cs: minidump_u32(&bytes, 0xbc),
                eflags: minidump_u32(&bytes, 0xc0),
                esp: minidump_u32(&bytes, 0xc4),
                ss: minidump_u32(&bytes, 0xc8),
            };
            context.instruction_pointer = Some(u64::from(registers.eip));
            context.stack_pointer = Some(u64::from(registers.esp));
            context.x86_registers = Some(registers);
        }
        ContextArchitecture::Arm64 => {
            let registers = Arm64ExceptionRegisters {
                x: (0..29)
                    .map(|index| minidump_u64(&bytes, 8 + index * 8))
                    .collect(),
                fp: minidump_u64(&bytes, 0xf0),
                lr: minidump_u64(&bytes, 0xf8),
                sp: minidump_u64(&bytes, 0x100),
                pc: minidump_u64(&bytes, 0x108),
                cpsr: minidump_u32(&bytes, 4),
            };
            context.instruction_pointer = Some(registers.pc);
            context.stack_pointer = Some(registers.sp);
            context.arm64_registers = Some(registers);
        }
    }
    context.extended_state = extended_state_summary(file, file_bytes, arch, flags, rva, declared);
    // The unwind copy is the legacy CONTEXT only: drop XSTATE (no CONTEXT_EX follows it) and
    // x86 extended registers when the dump did not capture that tail.
    let mut unwind_flags = flags & !arch.xstate_flag();
    if bytes.len() < arch.context_size() {
        unwind_flags &= !0x20;
        bytes.resize(arch.context_size(), 0);
    }
    let offset = arch.flags_offset();
    bytes[offset..offset + 4].copy_from_slice(&unwind_flags.to_le_bytes());
    context.raw_context = bytes;
    context.status = "context_captured_stack_unavailable".into();
    context.detail = format!(
        "Captured {} bytes of the {} CONTEXT from a file RVA, not a guest virtual address. An exception-context stack has not been captured.",
        context.bytes_read,
        arch.name()
    );
    Ok(())
}

fn extended_state_summary(
    file: &mut File,
    file_bytes: u64,
    arch: ContextArchitecture,
    flags: u32,
    rva: u32,
    declared: u32,
) -> Option<ExtendedStateSummary> {
    if flags & arch.xstate_flag() == 0 {
        return None;
    }
    let mut summary = ExtendedStateSummary {
        status: "unavailable".into(),
        ..Default::default()
    };
    if arch == ContextArchitecture::Arm64 {
        summary.status = "present_not_decoded".into();
        summary.detail =
            "CONTEXT_ARM64_XSTATE is set; ARM64 extended (SVE) state is not decoded.".into();
        return Some(summary);
    }
    let base = arch.context_size() as u32;
    if declared < base + CONTEXT_EX_PREFIX_SIZE {
        summary.status = "not_captured".into();
        summary.detail = format!(
            "CONTEXT_XSTATE is set in ContextFlags, but the dump's context descriptor covers only {declared} bytes, so no CONTEXT_EX/XSAVE area follows the {base}-byte legacy CONTEXT."
        );
        return Some(summary);
    }
    summary.context_ex_offset = Some(base);
    let result = (|| -> anyhow::Result<()> {
        let ex_rva = rva.checked_add(base).context("CONTEXT_EX RVA overflows")?;
        let ex = read_prefix(
            file,
            file_bytes,
            ex_rva,
            declared - base,
            CONTEXT_EX_PREFIX_SIZE as usize,
        )?;
        let legacy_offset = minidump_u32(&ex, 8) as i32;
        let legacy_length = minidump_u32(&ex, 12);
        ensure!(
            legacy_offset == -(base as i32) && legacy_length == base,
            "CONTEXT_EX legacy chunk ({legacy_offset}, {legacy_length}) does not describe the {base}-byte CONTEXT"
        );
        let xstate_offset = minidump_u32(&ex, 16) as i32;
        let xstate_length = minidump_u32(&ex, 20);
        summary.xstate_offset = Some(xstate_offset);
        summary.xstate_length = Some(xstate_length);
        ensure!(
            xstate_offset > 0 && xstate_length >= XSAVE_AREA_HEADER_SIZE,
            "CONTEXT_EX XState chunk is empty or invalid"
        );
        let header_offset = base
            .checked_add(xstate_offset as u32)
            .context("XSAVE header offset overflows")?;
        ensure!(
            header_offset
                .checked_add(XSAVE_AREA_HEADER_SIZE)
                .is_some_and(|end| end <= declared),
            "XSAVE_AREA_HEADER lies outside the declared context"
        );
        let header_rva = rva
            .checked_add(header_offset)
            .context("XSAVE header RVA overflows")?;
        let header = read_prefix(file, file_bytes, header_rva, declared - header_offset, 16)?;
        let mask = minidump_u64(&header, 0);
        let compaction_mask = minidump_u64(&header, 8);
        summary.mask = Some(mask);
        summary.compaction_mask = Some(compaction_mask);
        summary.compacted = Some(compaction_mask & (1 << 63) != 0);
        summary.features = xstate_feature_names(mask);
        summary.status = "captured".into();
        summary.detail = "Decoded the CONTEXT_EX XState chunk and XSAVE_AREA_HEADER feature masks only; extended register contents are not decoded.".into();
        Ok(())
    })();
    if let Err(error) = result {
        summary.detail = format!("{error:#}");
    }
    Some(summary)
}

fn xstate_feature_names(mask: u64) -> Vec<String> {
    (0..64)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| {
            match bit {
                0 => "x87",
                1 => "sse",
                2 => "avx",
                3 => "mpx_bndregs",
                4 => "mpx_bndcsr",
                5 => "avx512_kmask",
                6 => "avx512_zmm_h",
                7 => "avx512_zmm",
                8 => "ipt",
                10 => "pasid",
                11 => "cet_u",
                12 => "cet_s",
                17 => "amx_tile_config",
                18 => "amx_tile_data",
                62 => "lwp",
                _ => return format!("bit_{bit}"),
            }
            .to_string()
        })
        .collect()
}

#[cfg(windows)]
fn validate_context_stack_request(
    architecture: ContextArchitecture,
    context_size: usize,
    max_frames: u32,
) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_USER_EXCEPTION_STACK_FRAMES).contains(&max_frames),
        "Exception stack frame limit must be 1..={MAX_USER_EXCEPTION_STACK_FRAMES}"
    );
    ensure!(
        context_size == architecture.context_size(),
        "A complete {} CONTEXT is required",
        architecture.name()
    );
    Ok(())
}

#[cfg(windows)]
impl GuestMemory for super::DebuggerSession {
    fn read_guest(&self, address: u64, size: u32) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![0u8; size as usize];
        let mut bytes_read = 0u32;
        unsafe {
            self.data_spaces.ReadVirtual(
                address,
                buffer.as_mut_ptr().cast(),
                size,
                Some(&mut bytes_read),
            )?;
        }
        buffer.truncate(bytes_read as usize);
        Ok(buffer)
    }
}

#[cfg(windows)]
impl super::DebuggerSession {
    /// Returns the start of the function containing `address` and how it was found. On AMD64 the
    /// image's RUNTIME_FUNCTION entry is used (following chained unwind info back to the primary
    /// entry); otherwise, or when no entry exists, the nearest preceding symbol within 64 KiB.
    pub fn function_start(
        &self,
        address: u64,
        architecture: ContextArchitecture,
    ) -> Option<(u64, &'static str)> {
        if architecture == ContextArchitecture::Amd64 {
            if let Some(start) = self.amd64_runtime_function_start(address) {
                return Some((start, "runtime_function_entry"));
            }
        }
        let symbol = self.symbol_by_offset(address).ok()??;
        (symbol.displacement <= 0x1_0000 && symbol.displacement <= address)
            .then(|| (address - symbol.displacement, "nearest_symbol"))
    }

    fn amd64_runtime_function_start(&self, address: u64) -> Option<u64> {
        const UNW_FLAG_CHAININFO: u8 = 0x4;
        let mut base = 0u64;
        unsafe {
            self.symbols
                .GetModuleByOffset(address, 0, None, Some(&mut base))
                .ok()?
        };
        let mut entry = [0u8; 12];
        let mut needed = 0u32;
        unsafe {
            self.symbols
                .GetFunctionEntryByOffset(
                    address,
                    0,
                    Some(entry.as_mut_ptr().cast()),
                    entry.len() as u32,
                    Some(&mut needed),
                )
                .ok()?
        };
        let rva = |bytes: &[u8], offset: usize| {
            u64::from(u32::from_le_bytes(
                bytes[offset..offset + 4].try_into().unwrap(),
            ))
        };
        let (mut begin, end) = (rva(&entry, 0), rva(&entry, 4));
        if !(begin <= address.checked_sub(base)? && address - base < end) {
            return None;
        }
        let mut unwind = rva(&entry, 8);
        for _ in 0..8 {
            let header = self.read_guest(base + unwind, 4).ok()?;
            if header.len() < 4 || header[0] >> 3 & UNW_FLAG_CHAININFO == 0 {
                return Some(base + begin);
            }
            let chained_offset = 4 + ((u64::from(header[2]) + 1) & !1) * 2;
            let chained = self.read_guest(base + unwind + chained_offset, 12).ok()?;
            if chained.len() < 12 {
                return None;
            }
            begin = rva(&chained, 0);
            unwind = rva(&chained, 8);
        }
        None
    }

    pub fn user_dump_exception(
        &self,
        directory: &MinidumpDirectoryInventory,
    ) -> anyhow::Result<Option<MinidumpException>> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_CLASS_USER_WINDOWS;
        if self.kind != super::DebuggerSessionKind::Dump {
            return Ok(None);
        }
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier)? };
        if class != DEBUG_CLASS_USER_WINDOWS {
            return Ok(None);
        }
        let mut exception = inspect_exception(
            self.dump_path
                .as_deref()
                .context("Dump path is unavailable")?,
            directory,
        );
        let architecture = exception.context.arch;
        if let Some(record) = exception.record.as_mut() {
            decode_guest_exception_details(record, architecture, self);
        }
        Ok(Some(exception))
    }

    pub fn unwind_user_dump_exception(&self, exception: &mut MinidumpException, max_frames: u32) {
        exception.context.stack = None;
        let (Some(architecture), Some(pc)) = (
            exception.context.arch,
            exception.context.instruction_pointer,
        ) else {
            return;
        };
        if exception.context.raw_context.is_empty() {
            return;
        }
        let result = self.exception_context_stack(
            exception.thread_system_id,
            architecture,
            &exception.context.raw_context,
            pc,
            max_frames,
        );
        match result {
            Ok(stack) => {
                exception.context.status = "captured".into();
                exception.context.detail = format!(
                    "Decoded the file-backed {} CONTEXT and used DbgEng GetContextStackTrace on the verified exception thread, restoring the previous thread. Stack status: {}; the unwind copy omits XSTATE.",
                    architecture.name(),
                    stack.status
                );
                exception.context.stack = Some(stack);
            }
            Err(error) => {
                exception.context.status = "context_captured_stack_unavailable".into();
                exception.context.detail = format!(
                    "Exception registers are captured, but no exception-context stack is claimed: {error:#}"
                );
            }
        }
    }

    fn exception_context_stack(
        &self,
        thread_system_id: Option<u32>,
        architecture: ContextArchitecture,
        bytes: &[u8],
        pc: u64,
        max_frames: u32,
    ) -> anyhow::Result<StackTraceResult> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STACK_FRAME;
        validate_context_stack_request(architecture, bytes.len(), max_frames)?;
        ensure!(
            self.kind == super::DebuggerSessionKind::Dump,
            "Exception-context unwinding requires a dump session"
        );
        let thread_id = thread_system_id.context("No captured exception thread ID")?;
        let engine_id = unsafe { self.system_objects.GetThreadIdBySystemId(thread_id)? };
        let previous = unsafe { self.system_objects.GetCurrentThreadId()? };
        unsafe { self.system_objects.SetCurrentThreadId(engine_id)? };
        let result = (|| -> anyhow::Result<StackTraceResult> {
            ensure!(
                self.current_thread_system_id()? == thread_id,
                "DbgEng selected thread does not match the exception thread"
            );
            ensure!(
                unsafe { self.control.GetEffectiveProcessorType()? } == architecture.machine_type(),
                "DbgEng effective processor does not match the {} SystemInfo",
                architecture.name()
            );
            #[repr(C, align(16))]
            struct AlignedContext([u8; X64_CONTEXT_SIZE as usize]);
            let mut context = AlignedContext([0; X64_CONTEXT_SIZE as usize]);
            context.0[..bytes.len()].copy_from_slice(bytes);
            let mut frames = vec![DEBUG_STACK_FRAME::default(); max_frames as usize];
            let mut filled = 0;
            unsafe {
                self.control.GetContextStackTrace(
                    Some(context.0.as_ptr().cast()),
                    bytes.len() as u32,
                    Some(&mut frames),
                    None,
                    0,
                    0,
                    Some(&mut filled),
                )?;
            }
            ensure!(
                filled > 0 && filled <= max_frames,
                "DbgEng returned an empty or invalid frame count"
            );
            ensure!(
                frames[0].InstructionOffset == pc,
                "First unwound frame does not match the captured instruction pointer"
            );
            frames.truncate(filled as usize);
            Ok(self.describe_stack_frames(frames, max_frames, filled))
        })();
        let restore = unsafe { self.system_objects.SetCurrentThreadId(previous) };
        match (result, restore) {
            (Ok(stack), Ok(())) => Ok(stack),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error).context("Failed to restore current debugger thread"),
            (Err(error), Err(restore)) => Err(error).context(format!(
                "Also failed to restore current debugger thread: {restore}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inspect_minidump_directory, tests::temporary_runtime_directory};

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x200 + X64_CONTEXT_SIZE as usize];
        bytes[..4].copy_from_slice(b"MDMP");
        put32(&mut bytes, 4, 0xa793);
        put32(&mut bytes, 8, 2);
        put32(&mut bytes, 12, 32);
        for (offset, kind, size, rva) in [(32, 6, 168, 0x80), (44, 7, 56, 0x140)] {
            put32(&mut bytes, offset, kind);
            put32(&mut bytes, offset + 4, size);
            put32(&mut bytes, offset + 8, rva);
        }
        put32(&mut bytes, 0x80, 42);
        put32(&mut bytes, 0x88, 0xc000_0005);
        put64(&mut bytes, 0x98, 0x140001234);
        put32(&mut bytes, 0xa0, 2);
        put32(&mut bytes, 0x120, X64_CONTEXT_SIZE);
        put32(&mut bytes, 0x124, 0x200);
        bytes[0x140] = 9;
        put32(&mut bytes, 0x230, 0x10005f);
        put32(&mut bytes, 0x244, 0x202);
        for index in 0..17 {
            put64(&mut bytes, 0x278 + index * 8, 0x1000 + index as u64);
        }
        put64(&mut bytes, 0x280, 0);
        put64(&mut bytes, 0x2f8, 0x140001234);
        bytes
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn inspect(bytes: &[u8]) -> MinidumpException {
        let directory = temporary_runtime_directory("exception-stream");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("fixture.dmp");
        std::fs::write(&path, bytes).unwrap();
        let result = inspect_exception(&path, &inspect_minidump_directory(&path));
        std::fs::remove_dir_all(directory).unwrap();
        result
    }

    struct MapMemory(Vec<(u64, Vec<u8>)>);

    impl GuestMemory for MapMemory {
        fn read_guest(&self, address: u64, size: u32) -> anyhow::Result<Vec<u8>> {
            for (base, bytes) in &self.0 {
                if address >= *base && address < base + bytes.len() as u64 {
                    let start = (address - base) as usize;
                    let end = (start + size as usize).min(bytes.len());
                    return Ok(bytes[start..end].to_vec());
                }
            }
            anyhow::bail!("not captured")
        }
    }

    #[test]
    fn captures_exception_record_and_file_backed_amd64_registers_without_inventing_stack() {
        let result = inspect(&fixture());
        assert_eq!(result.status, "captured");
        assert_eq!(result.thread_system_id, Some(42));
        let record = result.record.unwrap();
        assert_eq!(record.exception_code, 0xc000_0005);
        assert_eq!(record.code_name, Some("STATUS_ACCESS_VIOLATION"));
        assert_eq!(record.exception_address, 0x140001234);
        assert_eq!(record.parameters, [0, 0]);
        assert_eq!(record.nested_records.status, "none");
        let access = record.access.unwrap();
        assert_eq!(access.operation, "read");
        assert_eq!(access.address, 0);
        let context = result.context;
        assert_eq!(context.architecture, Some("amd64"));
        assert_eq!(context.context_record_rva, Some(0x200));
        assert_eq!(context.context_flags, Some(0x10005f));
        assert_eq!(context.bytes_read, 1232);
        assert_eq!(context.raw_context.len(), 1232);
        assert_eq!(
            minidump_u32(&context.raw_context, 0x30),
            0x10001f,
            "unwind copy drops XSTATE"
        );
        assert_eq!(context.instruction_pointer, Some(0x140001234));
        assert_eq!(context.stack_pointer, Some(0x1004));
        assert_eq!(context.status, "context_captured_stack_unavailable");
        assert_eq!(
            context.extended_state.as_ref().unwrap().status,
            "not_captured"
        );
        assert!(context.stack.is_none());
        let r = context.registers.unwrap();
        assert_eq!((r.rax, r.rcx, r.rdx, r.rbx), (0x1000, 0, 0x1002, 0x1003));
        assert_eq!(
            (r.rsp, r.rbp, r.rsi, r.rdi),
            (0x1004, 0x1005, 0x1006, 0x1007)
        );
        assert_eq!((r.r8, r.r9, r.r10, r.r11), (0x1008, 0x1009, 0x100a, 0x100b));
        assert_eq!(
            (r.r12, r.r13, r.r14, r.r15),
            (0x100c, 0x100d, 0x100e, 0x100f)
        );
        assert_eq!((r.rip, r.eflags), (0x140001234, 0x202));
    }

    #[test]
    fn decodes_x86_context_including_short_legacy_contexts() {
        for declared in [0x2cc, 0xcc] {
            let mut bytes = fixture();
            bytes[0x140] = 0;
            put32(&mut bytes, 0x120, declared);
            bytes[0x200..0x200 + 0x2cc].fill(0);
            put32(&mut bytes, 0x200, 0x1003f);
            for (index, offset) in [0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc]
                .into_iter()
                .enumerate()
            {
                put32(&mut bytes, 0x200 + offset, 0x100 + index as u32);
            }
            put32(&mut bytes, 0x200 + 0xc0, 0x246);
            put32(&mut bytes, 0x200 + 0xc4, 0x0019_f000);
            put32(&mut bytes, 0x200 + 0xc8, 0x2b);
            let context = inspect(&bytes).context;
            assert_eq!(context.status, "context_captured_stack_unavailable");
            assert_eq!(context.architecture, Some("x86"));
            assert_eq!(context.bytes_read, declared);
            assert_eq!(context.raw_context.len(), 0x2cc);
            let expected_flags = if declared == 0xcc { 0x1001f } else { 0x1003f };
            assert_eq!(minidump_u32(&context.raw_context, 0), expected_flags);
            let r = context.x86_registers.unwrap();
            assert_eq!((r.edi, r.esi, r.ebx, r.edx), (0x100, 0x101, 0x102, 0x103));
            assert_eq!((r.ecx, r.eax, r.ebp, r.eip), (0x104, 0x105, 0x106, 0x107));
            assert_eq!(
                (r.cs, r.eflags, r.esp, r.ss),
                (0x108, 0x246, 0x0019_f000, 0x2b)
            );
            assert_eq!(context.instruction_pointer, Some(0x107));
            assert_eq!(context.stack_pointer, Some(0x0019_f000));
            assert!(context.registers.is_none());
        }
        let mut short = fixture();
        short[0x140] = 0;
        put32(&mut short, 0x120, 0xcb);
        assert_eq!(inspect(&short).context.status, "unavailable");
    }

    #[test]
    fn decodes_arm64_context() {
        let mut bytes = fixture();
        bytes[0x140] = 12;
        put32(&mut bytes, 0x120, 0x390);
        bytes[0x200..0x200 + 0x390].fill(0);
        put32(&mut bytes, 0x200, 0x400027);
        put32(&mut bytes, 0x204, 0x6000_0000);
        for index in 0..29 {
            put64(&mut bytes, 0x208 + index * 8, 0x2000 + index as u64);
        }
        put64(&mut bytes, 0x2f0, 0xf0);
        put64(&mut bytes, 0x2f8, 0xf8);
        put64(&mut bytes, 0x300, 0x7ff0_0000);
        put64(&mut bytes, 0x308, 0x1_4000_1234);
        let context = inspect(&bytes).context;
        assert_eq!(context.status, "context_captured_stack_unavailable");
        assert_eq!(context.architecture, Some("arm64"));
        assert_eq!(context.raw_context.len(), 0x390);
        assert_eq!(minidump_u32(&context.raw_context, 0), 0x400007);
        let r = context.arm64_registers.unwrap();
        assert_eq!(r.x.len(), 29);
        assert_eq!((r.x[0], r.x[28]), (0x2000, 0x201c));
        assert_eq!(
            (r.fp, r.lr, r.sp, r.pc),
            (0xf0, 0xf8, 0x7ff0_0000, 0x1_4000_1234)
        );
        assert_eq!(r.cpsr, 0x6000_0000);
        assert_eq!(context.instruction_pointer, Some(0x1_4000_1234));
        assert_eq!(
            context.extended_state.unwrap().status,
            "present_not_decoded"
        );
    }

    #[test]
    fn summarizes_amd64_xstate_only_when_context_ex_is_consistent() {
        let base = X64_CONTEXT_SIZE as usize;
        let declared = base + 0x40 + 0x100;
        let build = |legacy_offset: i32| {
            let mut bytes = fixture();
            bytes.resize(0x200 + declared, 0);
            put32(&mut bytes, 0x120, declared as u32);
            let ex = 0x200 + base;
            put32(&mut bytes, ex, (-(base as i32)) as u32);
            put32(&mut bytes, ex + 4, declared as u32);
            put32(&mut bytes, ex + 8, legacy_offset as u32);
            put32(&mut bytes, ex + 12, base as u32);
            put32(&mut bytes, ex + 16, 0x40);
            put32(&mut bytes, ex + 20, 0x100);
            put64(&mut bytes, ex + 0x40, 0b111 | (1 << 11));
            put64(&mut bytes, ex + 0x48, (1 << 63) | 0b111);
            bytes
        };
        let context = inspect(&build(-(base as i32))).context;
        assert_eq!(context.bytes_read, 1232);
        let state = context.extended_state.unwrap();
        assert_eq!(state.status, "captured");
        assert_eq!(state.context_ex_offset, Some(1232));
        assert_eq!(state.mask, Some(0b111 | (1 << 11)));
        assert_eq!(state.compacted, Some(true));
        assert_eq!(state.features, ["x87", "sse", "avx", "cet_u"]);
        let state = inspect(&build(0)).context.extended_state.unwrap();
        assert_eq!(state.status, "unavailable");
        assert!(state.mask.is_none());
    }

    #[test]
    fn interprets_access_violation_in_page_and_fast_fail_parameters() {
        for (mode, operation) in [(0, "read"), (1, "write"), (8, "execute"), (3, "unknown")] {
            let access = exception_access(0xc000_0005, &[mode, 0x1234]).unwrap();
            assert_eq!(access.operation, operation);
            assert_eq!(access.mode, mode);
            assert_eq!(access.address, 0x1234);
            assert!(access.io_status.is_none());
        }
        assert!(exception_access(0xc000_0005, &[]).is_none());
        assert!(exception_access(0xc000_0005, &[1]).is_none());
        assert!(exception_access(0x80000003, &[1, 0x1234]).is_none());
        let in_page = exception_access(0xc000_0006, &[0, 0x5000, 0xc000_009c]).unwrap();
        assert_eq!(in_page.io_status, Some(0xc000_009c));
        assert!(exception_access(0xc000_0006, &[0, 0x5000]).is_none());
        let record = exception_record(0xc000_0409, 1, 0, 0x1000, vec![7]);
        assert!(record.noncontinuable);
        assert_eq!(record.code_name, Some("STATUS_STACK_BUFFER_OVERRUN"));
        let fast_fail = record.fast_fail.unwrap();
        assert_eq!(fast_fail.name, Some("FAST_FAIL_FATAL_APP_EXIT"));
        assert!(fast_fail_name(15).is_none());
        assert_eq!(
            fast_fail_name(77),
            Some("FAST_FAIL_KERNEL_POINTER_EXPECTED")
        );
        assert!(exception_record(0xc000_0409, 0, 0, 0, vec![])
            .fast_fail
            .is_none());
        let clr = exception_record(0xe043_4352, 1, 0, 0, vec![0x8013_1500, 0, 0, 0, 0])
            .clr_exception
            .unwrap();
        assert_eq!(clr.hresult, Some(0x8013_1500));
        assert!(exception_code_name(0x1234_5678).is_none());
    }

    #[test]
    fn follows_nested_records_with_depth_cycle_and_read_limits() {
        let record64 = |code: u32, next: u64| {
            let mut bytes = vec![0; 152];
            put32(&mut bytes, 0, code);
            put64(&mut bytes, 8, next);
            put64(&mut bytes, 16, 0x7000);
            put32(&mut bytes, 24, 2);
            put64(&mut bytes, 32, 1);
            put64(&mut bytes, 40, 0x10);
            bytes
        };
        let memory = MapMemory(vec![
            (0x1000, record64(0xc000_0005, 0x2000)),
            (0x2000, record64(0x8000_0003, 0)),
        ]);
        let chain = nested_exception_chain(0x1000, Some(ContextArchitecture::Amd64), &memory);
        assert_eq!(chain.status, "captured");
        assert_eq!(chain.records.len(), 2);
        assert_eq!(chain.records[0].access.as_ref().unwrap().operation, "write");
        assert_eq!(chain.records[1].code_name, Some("STATUS_BREAKPOINT"));
        let cycle = MapMemory(vec![(0x1000, record64(1, 0x1000))]);
        assert_eq!(
            nested_exception_chain(0x1000, Some(ContextArchitecture::Amd64), &cycle).status,
            "cycle_detected"
        );
        let deep = MapMemory(
            (1..=10)
                .map(|index| (index * 0x1000, record64(1, (index + 1) * 0x1000)))
                .collect(),
        );
        let chain = nested_exception_chain(0x1000, Some(ContextArchitecture::Amd64), &deep);
        assert_eq!(chain.status, "depth_limited");
        assert_eq!(chain.records.len(), MAX_NESTED_EXCEPTION_RECORDS);
        assert_eq!(
            nested_exception_chain(0x9000, Some(ContextArchitecture::Amd64), &memory).status,
            "unreadable"
        );
        assert_eq!(
            nested_exception_chain(0x1000, None, &memory).status,
            "architecture_unknown"
        );
        let mut record32 = vec![0; 80];
        put32(&mut record32, 0, 0xc000_0005);
        put32(&mut record32, 12, 0x401000);
        put32(&mut record32, 16, 2);
        put32(&mut record32, 24, 0x44);
        let chain = nested_exception_chain(
            0x3000,
            Some(ContextArchitecture::X86),
            &MapMemory(vec![(0x3000, record32)]),
        );
        assert_eq!(chain.status, "captured");
        assert_eq!(chain.records[0].exception_address, 0x401000);
        assert_eq!(chain.records[0].parameters, [0, 0x44]);
    }

    fn cpp_memory(image_base: u64, relative: bool, what: &[u8]) -> MapMemory {
        let address = |rva: u64| {
            if relative {
                rva as u32
            } else {
                (image_base + rva) as u32
            }
        };
        let mut throw_info = vec![0; 16];
        put32(&mut throw_info, 12, address(0x200));
        let mut array = vec![0; 12];
        put32(&mut array, 0, 2);
        put32(&mut array, 4, address(0x300));
        put32(&mut array, 8, address(0x340));
        let mut catchable = vec![0; 0x80];
        put32(&mut catchable, 4, address(0x400));
        put32(&mut catchable, 0x44, address(0x500));
        let pointer = if relative { 8 } else { 4 };
        let mut runtime_error = vec![0; pointer * 2];
        runtime_error.extend_from_slice(b".?AVruntime_error@std@@\0");
        let mut exception = vec![0; pointer * 2];
        exception.extend_from_slice(b".?AVexception@std@@\0");
        let mut object = vec![0; pointer * 2];
        object[pointer..pointer + 4].copy_from_slice(&0x9000u32.to_le_bytes());
        MapMemory(vec![
            (image_base + 0x100, throw_info),
            (image_base + 0x200, array),
            (image_base + 0x300, catchable),
            (image_base + 0x400, runtime_error),
            (image_base + 0x500, exception),
            (0x8000, object),
            (0x9000, what.to_vec()),
        ])
    }

    #[test]
    fn decodes_msvc_cpp_exception_types_and_bounded_what_for_both_layouts() {
        for (architecture, image_base, parameters) in [
            (
                ContextArchitecture::Amd64,
                0x1_4000_0000u64,
                vec![0x1993_0520, 0x8000, 0x1_4000_0100, 0x1_4000_0000],
            ),
            (
                ContextArchitecture::X86,
                0x40_0000u64,
                vec![0x1993_0520, 0x8000, 0x40_0100],
            ),
        ] {
            let relative = architecture == ContextArchitecture::Amd64;
            let memory = cpp_memory(image_base, relative, b"bad\nthing\0");
            let info = cpp_exception(CPP_EXCEPTION_CODE, &parameters, Some(architecture), &memory)
                .unwrap();
            assert_eq!(info.status, "decoded", "{}", info.detail);
            assert_eq!(info.catchable_type_count, Some(2));
            assert_eq!(info.types[0].name.as_deref(), Some("std::runtime_error"));
            assert_eq!(info.types[1].decorated_name, CPP_STD_EXCEPTION_TYPE);
            assert_eq!(info.what.as_deref(), Some("bad?thing"));
            assert!(!info.what_truncated);
        }
        let long = vec![b'a'; 300];
        let memory = cpp_memory(0x1_4000_0000, true, &long);
        let parameters = [0x1993_0520, 0x8000, 0x1_4000_0100, 0x1_4000_0000];
        let info = cpp_exception(
            CPP_EXCEPTION_CODE,
            &parameters,
            Some(ContextArchitecture::Amd64),
            &memory,
        )
        .unwrap();
        assert_eq!(
            info.what.unwrap().len(),
            MAX_EXCEPTION_STRING_BYTES as usize
        );
        assert!(info.what_truncated);
        for parameters in [
            vec![0x1234, 0x8000, 0x1_4000_0100, 0x1_4000_0000],
            vec![0x1993_0520, 0x8000, 0, 0x1_4000_0000],
            vec![0x1993_0520, 0x8000, 0x1_4000_0100],
            vec![0x1993_0520, 0x8000, 0x2_0000_0000, 0x1_4000_0000],
        ] {
            let info = cpp_exception(
                CPP_EXCEPTION_CODE,
                &parameters,
                Some(ContextArchitecture::Amd64),
                &memory,
            )
            .unwrap();
            assert_eq!(info.status, "unavailable");
            assert!(info.what.is_none());
        }
        assert!(cpp_exception(0xc000_0005, &[], None, &memory).is_none());
    }

    #[test]
    fn undecorates_only_simple_msvc_type_names() {
        assert_eq!(
            undecorate_type_name(".?AVexception@std@@").as_deref(),
            Some("std::exception")
        );
        assert_eq!(
            undecorate_type_name(".?AUinner@outer@ns@@").as_deref(),
            Some("ns::outer::inner")
        );
        assert!(undecorate_type_name(".?AV?$basic_string@DU?$char_traits@D@std@@@std@@").is_none());
        assert!(undecorate_type_name(".PEAX").is_none());
    }

    #[test]
    fn preserves_zero_and_maximum_parameter_counts_without_following_nested_records() {
        for count in [0, 15] {
            let mut bytes = fixture();
            put32(&mut bytes, 0xa0, count);
            put64(&mut bytes, 0x90, u64::MAX);
            for index in 0..count {
                put64(
                    &mut bytes,
                    0xa8 + index as usize * 8,
                    0x100 + u64::from(index),
                );
            }
            let result = inspect(&bytes);
            assert_eq!(result.status, "captured");
            let record = result.record.unwrap();
            assert_eq!(record.number_parameters, count);
            assert_eq!(
                record.parameters,
                (0..count)
                    .map(|index| 0x100 + u64::from(index))
                    .collect::<Vec<_>>()
            );
            assert_eq!(record.nested_exception_record, u64::MAX);
            assert_eq!(record.nested_records.status, "not_followed");
            if count == 0 {
                assert!(record.access.is_none());
            }
            assert_eq!(result.context.bytes_read, 1232);
        }
    }

    #[test]
    fn rejects_missing_duplicate_short_or_out_of_range_exception_streams() {
        let mut missing = fixture();
        put32(&mut missing, 32, 10);
        let result = inspect(&missing);
        assert_eq!(result.status, "not_present");
        assert!(result.record.is_none());
        for (offset, value) in [
            (44, 6),
            (36, 167),
            (40, u32::MAX),
            (40, 0),
            (0xa0, 16),
            (12, u32::MAX),
            (8, 513),
            (4, 0),
        ] {
            let mut bytes = fixture();
            put32(&mut bytes, offset, value);
            let result = inspect(&bytes);
            assert_eq!(result.status, "unavailable", "field {offset}");
            assert!(result.record.is_none(), "field {offset}");
            assert!(result.context.registers.is_none());
        }
    }

    #[test]
    fn preserves_exception_when_context_is_partial_invalid_missing_or_wrong_architecture() {
        for (offset, value) in [
            (0x120, 1231),
            (0x120, u32::MAX),
            (0x124, u32::MAX),
            (0x124, 0),
            (0x230, 0x100001),
            (0x230, 0x100003 | 0x400000),
            (44, 10),
            (48, 55),
            (52, u32::MAX),
        ] {
            let mut bytes = fixture();
            put32(&mut bytes, offset, value);
            let result = inspect(&bytes);
            assert_eq!(result.status, "captured");
            assert_eq!(result.record.unwrap().exception_code, 0xc000_0005);
            assert_eq!(result.context.status, "unavailable", "field {offset}");
            assert!(result.context.registers.is_none());
            assert!(result.context.stack.is_none());
        }
        let mut duplicate_system = fixture();
        put32(&mut duplicate_system, 8, 3);
        put32(&mut duplicate_system, 56, 7);
        let result = inspect(&duplicate_system);
        assert_eq!(result.status, "captured");
        assert_eq!(result.context.status, "unavailable");
        assert!(result.context.detail.contains("Ambiguous"));
        assert!(result.context.registers.is_none());
        for architecture in [5, 6] {
            let mut bytes = fixture();
            bytes[0x140] = architecture;
            let result = inspect(&bytes);
            assert_eq!(result.status, "captured");
            assert_eq!(result.context.status, "architecture_unsupported");
            assert!(result.context.registers.is_none());
            assert!(result.context.architecture_kind().is_none());
        }
        for architecture in [0, 12] {
            let mut bytes = fixture();
            bytes[0x140] = architecture;
            let result = inspect(&bytes);
            assert_eq!(result.context.status, "unavailable", "AMD64 flags rejected");
            assert!(result.context.instruction_pointer.is_none());
        }
    }

    #[test]
    fn bounds_context_reads_and_refuses_kernel_headers() {
        let mut bytes = fixture();
        bytes.extend_from_slice(&[0xa5; 64]);
        put32(&mut bytes, 0x120, 1296);
        let result = inspect(&bytes);
        assert_eq!(result.context.bytes_read, 1232);
        assert_eq!(result.context.raw_context.len(), 1232);
        bytes[..8].copy_from_slice(b"PAGEDU64");
        let result = inspect(&bytes);
        assert_eq!(result.status, "not_minidump");
        assert!(result.record.is_none());
        assert!(result.context.registers.is_none());
    }

    #[test]
    #[cfg(windows)]
    fn enforces_context_size_and_stack_frame_limit_boundaries() {
        let amd64 = ContextArchitecture::Amd64;
        assert!(validate_context_stack_request(amd64, 1232, 1).is_ok());
        assert!(validate_context_stack_request(amd64, 1232, 128).is_ok());
        assert!(validate_context_stack_request(amd64, 1232, 0).is_err());
        assert!(validate_context_stack_request(amd64, 1232, 129).is_err());
        assert!(validate_context_stack_request(amd64, 1231, 24).is_err());
        assert!(validate_context_stack_request(amd64, 1233, 24).is_err());
        assert!(validate_context_stack_request(ContextArchitecture::X86, 0x2cc, 24).is_ok());
        assert!(validate_context_stack_request(ContextArchitecture::X86, 0xcc, 24).is_err());
        assert!(validate_context_stack_request(ContextArchitecture::Arm64, 0x390, 24).is_ok());
    }
}
