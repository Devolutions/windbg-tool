use super::{
    minidump_stream_range_status, minidump_u32, minidump_u64, MinidumpDirectoryEntry,
    MinidumpDirectoryInventory, StackTraceResult, X64ExceptionRegisters,
    CONTEXT_X64_REQUIRED_REGISTER_FLAGS, X64_CONTEXT_SIZE,
};
use anyhow::{ensure, Context};
use serde::Serialize;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const EXCEPTION_STREAM_SIZE: usize = 168;
pub const MAX_USER_EXCEPTION_STACK_FRAMES: u32 = 128;

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
    pub exception_flags: u32,
    pub nested_exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub parameters: Vec<u64>,
    pub access: Option<ExceptionAccess>,
}

#[derive(Debug, Serialize)]
pub struct ExceptionAccess {
    pub operation: &'static str,
    pub mode: u64,
    pub address: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct MinidumpExceptionContext {
    pub status: String,
    pub context_record_rva: Option<u32>,
    pub declared_size: Option<u32>,
    pub bytes_read: u32,
    pub processor_architecture: Option<u16>,
    pub context_flags: Option<u32>,
    pub registers: Option<X64ExceptionRegisters>,
    pub stack: Option<StackTraceResult>,
    pub detail: String,
    #[serde(skip)]
    raw_context: Vec<u8>,
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
            number_parameters <= 15,
            "Exception parameter count exceeds 15"
        );
        let parameters = (0..number_parameters as usize)
            .map(|index| minidump_u64(&bytes, 40 + index * 8))
            .collect::<Vec<_>>();
        let exception_code = minidump_u32(&bytes, 8);
        let access = exception_access(exception_code, &parameters);
        result.thread_system_id = Some(minidump_u32(&bytes, 0));
        result.record = Some(MinidumpExceptionRecord {
            exception_code,
            exception_flags: minidump_u32(&bytes, 12),
            nested_exception_record: minidump_u64(&bytes, 16),
            exception_address: minidump_u64(&bytes, 24),
            number_parameters,
            parameters,
            access,
        });
        result.status = "captured".into();
        result.detail = "Captured the documented ExceptionStream record, not a stack scan or current debugger event. Nested exception pointers are not followed.".into();
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

fn exception_access(code: u32, parameters: &[u64]) -> Option<ExceptionAccess> {
    if code != 0xc000_0005 || parameters.len() < 2 {
        return None;
    }
    Some(ExceptionAccess {
        operation: match parameters[0] {
            0 => "read",
            1 => "write",
            8 => "execute",
            _ => "unknown",
        },
        mode: parameters[0],
        address: parameters[1],
    })
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
    let architecture = u16::from_le_bytes([info[0], info[1]]);
    context.processor_architecture = Some(architecture);
    if architecture != 9 {
        context.status = "architecture_unsupported".into();
        context.detail = "Exception records are architecture-independent, but context decoding/unwinding currently requires AMD64 SystemInfo (9).".into();
        return Ok(());
    }
    let bytes = read_prefix(
        file,
        file_bytes,
        context.context_record_rva.context("No context RVA")?,
        context.declared_size.context("No context size")?,
        X64_CONTEXT_SIZE as usize,
    )?;
    context.bytes_read = bytes.len() as u32;
    let flags = minidump_u32(&bytes, 0x30);
    context.context_flags = Some(flags);
    ensure!(
        flags & 0x00ff_0000 == 0x0010_0000
            && flags & CONTEXT_X64_REQUIRED_REGISTER_FLAGS == CONTEXT_X64_REQUIRED_REGISTER_FLAGS,
        "CONTEXT lacks the AMD64 control and integer register groups (flags {flags:#x})"
    );
    context.registers = Some(X64ExceptionRegisters {
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
    });
    context.raw_context = bytes;
    context.status = "context_captured_stack_unavailable".into();
    context.detail = "Captured the 1232-byte AMD64 CONTEXT from a file RVA, not a guest virtual address. Extended/XSTATE data is not decoded; an exception-context stack has not been captured.".into();
    Ok(())
}

#[cfg(windows)]
fn validate_context_stack_request(context_size: usize, max_frames: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_USER_EXCEPTION_STACK_FRAMES).contains(&max_frames),
        "Exception stack frame limit must be 1..={MAX_USER_EXCEPTION_STACK_FRAMES}"
    );
    ensure!(
        context_size == X64_CONTEXT_SIZE as usize,
        "A complete AMD64 CONTEXT is required"
    );
    Ok(())
}

#[cfg(windows)]
impl super::DebuggerSession {
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
        Ok(Some(inspect_exception(
            self.dump_path
                .as_deref()
                .context("Dump path is unavailable")?,
            directory,
        )))
    }

    pub fn unwind_user_dump_exception(&self, exception: &mut MinidumpException, max_frames: u32) {
        exception.context.stack = None;
        let Some(registers) = &exception.context.registers else {
            return;
        };
        let result = self.exception_context_stack(
            exception.thread_system_id,
            &exception.context.raw_context,
            registers.rip,
            max_frames,
        );
        match result {
            Ok(stack) => {
                exception.context.status = "captured".into();
                exception.context.detail = format!(
                    "Decoded the file-backed AMD64 CONTEXT and used DbgEng GetContextStackTrace on the verified exception thread, restoring the previous thread. Stack status: {}; extended/XSTATE data is not decoded.",
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
        bytes: &[u8],
        rip: u64,
        max_frames: u32,
    ) -> anyhow::Result<StackTraceResult> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STACK_FRAME;
        validate_context_stack_request(bytes.len(), max_frames)?;
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
                unsafe { self.control.GetEffectiveProcessorType()? } == 0x8664,
                "DbgEng effective processor is not AMD64"
            );
            #[repr(C, align(16))]
            struct AlignedContext([u8; X64_CONTEXT_SIZE as usize]);
            let mut context = AlignedContext([0; X64_CONTEXT_SIZE as usize]);
            context.0.copy_from_slice(bytes);
            let mut frames = vec![DEBUG_STACK_FRAME::default(); max_frames as usize];
            let mut filled = 0;
            unsafe {
                self.control.GetContextStackTrace(
                    Some(context.0.as_ptr().cast()),
                    X64_CONTEXT_SIZE,
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
                frames[0].InstructionOffset == rip,
                "First unwound frame does not match captured RIP"
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

    #[test]
    fn captures_exception_record_and_file_backed_amd64_registers_without_inventing_stack() {
        let result = inspect(&fixture());
        assert_eq!(result.status, "captured");
        assert_eq!(result.thread_system_id, Some(42));
        let record = result.record.unwrap();
        assert_eq!(record.exception_code, 0xc000_0005);
        assert_eq!(record.exception_address, 0x140001234);
        assert_eq!(record.parameters, [0, 0]);
        let access = record.access.unwrap();
        assert_eq!(access.operation, "read");
        assert_eq!(access.address, 0);
        let context = result.context;
        assert_eq!(context.context_record_rva, Some(0x200));
        assert_eq!(context.context_flags, Some(0x10005f));
        assert_eq!(context.bytes_read, 1232);
        assert_eq!(context.raw_context.len(), 1232);
        assert_eq!(context.status, "context_captured_stack_unavailable");
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
    fn interprets_only_complete_access_violation_parameters() {
        for (mode, operation) in [(0, "read"), (1, "write"), (8, "execute"), (3, "unknown")] {
            let access = exception_access(0xc000_0005, &[mode, 0x1234]).unwrap();
            assert_eq!(access.operation, operation);
            assert_eq!(access.mode, mode);
            assert_eq!(access.address, 0x1234);
        }
        assert!(exception_access(0xc000_0005, &[]).is_none());
        assert!(exception_access(0xc000_0005, &[1]).is_none());
        assert!(exception_access(0x80000003, &[1, 0x1234]).is_none());
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
        for architecture in [0, 5, 12] {
            let mut bytes = fixture();
            bytes[0x140] = architecture;
            let result = inspect(&bytes);
            assert_eq!(result.status, "captured");
            assert_eq!(result.context.status, "architecture_unsupported");
            assert!(result.context.registers.is_none());
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
        assert!(validate_context_stack_request(1232, 1).is_ok());
        assert!(validate_context_stack_request(1232, 128).is_ok());
        assert!(validate_context_stack_request(1232, 0).is_err());
        assert!(validate_context_stack_request(1232, 129).is_err());
        assert!(validate_context_stack_request(1231, 24).is_err());
        assert!(validate_context_stack_request(1233, 24).is_err());
    }
}
