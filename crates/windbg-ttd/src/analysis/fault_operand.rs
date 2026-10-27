//! Heuristic fault-operand hints for captured user-mode access violations.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter, OpKind, Register};
use serde_json::{json, Value};
use windbg_dbgeng::{
    ExceptionAccess, MinidumpException, X64ExceptionRegisters, X86ExceptionRegisters,
};

pub const FAULT_INSTRUCTION_BYTES: u32 = 16;
const NULL_PAGE_LIMIT: u64 = 0x1_0000;
const FILL_PATTERN_SLACK: u64 = 0x1_0000;
const DEBUG_FILL_PATTERNS: [(u32, &str); 7] = [
    (0xFEEE_FEEE, "heap_freed_fill"),
    (0xDDDD_DDDD, "crt_freed_fill"),
    (0xCDCD_CDCD, "crt_uninitialized_heap_fill"),
    (0xCCCC_CCCC, "uninitialized_stack_fill"),
    (0xBAAD_F00D, "heap_uninitialized_fill"),
    (0xABAB_ABAB, "heap_guard_fill"),
    (0xFDFD_FDFD, "crt_guard_fill"),
];

#[derive(Clone, Copy)]
pub enum FaultRegisters<'a> {
    Amd64(&'a X64ExceptionRegisters),
    X86(&'a X86ExceptionRegisters),
}

impl<'a> FaultRegisters<'a> {
    pub(super) fn from_exception(exception: &'a MinidumpException) -> Option<Self> {
        let context = &exception.context;
        context
            .registers
            .as_ref()
            .map(Self::Amd64)
            .or_else(|| context.x86_registers.as_ref().map(Self::X86))
    }

    pub(super) fn bitness(self) -> u32 {
        match self {
            Self::Amd64(_) => 64,
            Self::X86(_) => 32,
        }
    }

    pub(super) fn value(self, register: Register) -> Option<u64> {
        let full = match self {
            Self::Amd64(r) => match register.full_register() {
                Register::RAX => r.rax,
                Register::RBX => r.rbx,
                Register::RCX => r.rcx,
                Register::RDX => r.rdx,
                Register::RSI => r.rsi,
                Register::RDI => r.rdi,
                Register::RBP => r.rbp,
                Register::RSP => r.rsp,
                Register::R8 => r.r8,
                Register::R9 => r.r9,
                Register::R10 => r.r10,
                Register::R11 => r.r11,
                Register::R12 => r.r12,
                Register::R13 => r.r13,
                Register::R14 => r.r14,
                Register::R15 => r.r15,
                Register::RIP => r.rip,
                _ => return None,
            },
            Self::X86(r) => u64::from(match register.full_register32() {
                Register::EAX => r.eax,
                Register::EBX => r.ebx,
                Register::ECX => r.ecx,
                Register::EDX => r.edx,
                Register::ESI => r.esi,
                Register::EDI => r.edi,
                Register::EBP => r.ebp,
                Register::ESP => r.esp,
                Register::EIP => r.eip,
                _ => return None,
            }),
        };
        Some(match register.size() {
            8 => full,
            size => full & ((1u64 << (size * 8)) - 1),
        })
    }
}

/// Builds a fault-operand hint from the captured exception, reading instruction bytes through
/// `read` (which may return fewer bytes than requested).
pub fn fault_operand_hint(
    exception: &MinidumpException,
    read: &dyn Fn(u64, u32) -> anyhow::Result<Vec<u8>>,
) -> Value {
    let Some(record) = &exception.record else {
        return status("not_applicable", "No exception record was captured.");
    };
    let Some(access) = &record.access else {
        return status(
            "not_applicable",
            "Fault-operand hints apply only to access violations and in-page errors with access parameters.",
        );
    };
    let context = &exception.context;
    let registers = if let Some(registers) = &context.registers {
        FaultRegisters::Amd64(registers)
    } else if let Some(registers) = &context.x86_registers {
        FaultRegisters::X86(registers)
    } else if context.arm64_registers.is_some() {
        return status(
            "architecture_unsupported",
            "ARM64 fault-operand decoding is not implemented; use the captured registers and disassembly.",
        );
    } else {
        return status(
            "context_unavailable",
            "Fault-time registers were not captured, so no operand can be evaluated.",
        );
    };
    if access.operation == "execute" {
        let mut value = status(
            "execute_fault",
            "The fault is an instruction fetch; the faulting address is the branch target, not a data operand.",
        );
        value["access"] = access_value(access);
        value["hints"] = json!(address_hints(access.address, registers.bitness()));
        return value;
    }
    let bytes = match read(record.exception_address, FAULT_INSTRUCTION_BYTES) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return status(
                "instruction_bytes_unavailable",
                "The dump does not capture instruction bytes at the exception address.",
            )
        }
        Err(error) => {
            return status(
                "instruction_bytes_unavailable",
                &format!("Could not read instruction bytes at the exception address: {error:#}"),
            )
        }
    };
    analyze_fault_operand(registers, record.exception_address, access, &bytes)
}

pub fn analyze_fault_operand(
    registers: FaultRegisters<'_>,
    exception_address: u64,
    access: &ExceptionAccess,
    bytes: &[u8],
) -> Value {
    let bitness = registers.bitness();
    let mut decoder = Decoder::with_ip(bitness, bytes, exception_address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return status(
            "undecodable",
            "The captured bytes at the exception address do not decode as one instruction.",
        );
    }
    let mut text = String::new();
    NasmFormatter::new().format(&instruction, &mut text);
    let address_mask = if bitness == 32 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    let mut operands = Vec::new();
    let mut matched = None;
    for index in 0..instruction.op_count() {
        let Some(operand) = memory_operand(&instruction, index, registers, address_mask) else {
            continue;
        };
        if matched.is_none() && operand.effective_address == Some(access.address) {
            matched = Some(operands.len());
        }
        operands.push(operand);
    }
    let mut hints = address_hints(access.address, bitness);
    match matched.map(|index| &operands[index]) {
        Some(operand) => {
            if let (Some(base), Some(0)) = (&operand.base, operand.base_value) {
                hints.push(json!({
                    "kind": "null_base_register",
                    "register": base,
                    "displacement": operand.displacement,
                    "detail": format!(
                        "The faulting operand dereferences {base}=0 at displacement {:#x}; the pointer held in {base} was null when the instruction executed.",
                        operand.displacement
                    ),
                }));
            }
            for (register, value) in [
                (operand.base.as_ref(), operand.base_value),
                (operand.index.as_ref(), operand.index_value),
            ] {
                if let (Some(register), Some(value)) = (register, value) {
                    if let Some(pattern) = fill_pattern(value) {
                        hints.push(json!({
                            "kind": "debug_fill_pattern",
                            "register": register,
                            "value": value,
                            "pattern": pattern,
                            "detail": "The register holds a debug-heap/CRT fill pattern, which suggests freed or uninitialized memory was used as a pointer. Fill patterns appear only when the corresponding debug heap/CRT feature is active.",
                        }));
                    }
                }
            }
        }
        None if operands.is_empty() => hints.push(json!({
            "kind": "no_memory_operand",
            "detail": "The decoded instruction has no explicit memory operand; the access may be implicit (stack, string or system instruction).",
        })),
        None => hints.push(json!({
            "kind": "no_operand_matches_fault_address",
            "detail": "No decoded memory operand evaluates to the faulting address from the captured registers (segment-relative, implicit or instruction-modified addresses are not modeled).",
        })),
    }
    json!({
        "status": "decoded",
        "source": "captured_exception_context_and_dump_instruction_bytes",
        "instruction": {
            "address": exception_address,
            "length": instruction.len(),
            "bytes": bytes[..instruction.len().min(bytes.len())]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>(),
            "text": text,
        },
        "access": access_value(access),
        "memory_operands": operands.iter().map(MemoryOperand::to_value).collect::<Vec<_>>(),
        "matched_operand": matched,
        "hints": hints,
        "detail": "Heuristic computed from fault-time registers and instruction bytes captured in the dump (or mapped from a matching image). It identifies the faulting pointer register and value, not who cleared, freed or corrupted it.",
    })
}

pub(super) struct MemoryOperand {
    operand_index: u32,
    segment: Option<String>,
    base: Option<String>,
    base_value: Option<u64>,
    index: Option<String>,
    index_value: Option<u64>,
    scale: u32,
    displacement: u64,
    pub(super) effective_address: Option<u64>,
    detail: Option<&'static str>,
    pub(super) base_register: Register,
}

impl MemoryOperand {
    fn to_value(&self) -> Value {
        json!({
            "operand_index": self.operand_index,
            "segment": self.segment,
            "base": self.base,
            "base_value": self.base_value,
            "index": self.index,
            "index_value": self.index_value,
            "scale": self.scale,
            "displacement": self.displacement,
            "effective_address": self.effective_address,
            "detail": self.detail,
        })
    }
}

pub(super) fn memory_operand(
    instruction: &Instruction,
    index: u32,
    registers: FaultRegisters<'_>,
    address_mask: u64,
) -> Option<MemoryOperand> {
    let (base, index_register, scale, displacement) = match instruction.op_kind(index) {
        OpKind::Memory => (
            instruction.memory_base(),
            instruction.memory_index(),
            instruction.memory_index_scale(),
            instruction.memory_displacement64(),
        ),
        OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI => (
            string_register(instruction, Register::RSI),
            Register::None,
            1,
            0,
        ),
        OpKind::MemorySegDI
        | OpKind::MemorySegEDI
        | OpKind::MemorySegRDI
        | OpKind::MemoryESDI
        | OpKind::MemoryESEDI
        | OpKind::MemoryESRDI => (
            string_register(instruction, Register::RDI),
            Register::None,
            1,
            0,
        ),
        _ => return None,
    };
    let segment = instruction.memory_segment();
    let base_value = (base != Register::None)
        .then(|| registers.value(base))
        .flatten();
    let index_value = (index_register != Register::None)
        .then(|| registers.value(index_register))
        .flatten();
    let segment_relative = matches!(segment, Register::FS | Register::GS);
    let ip_relative = instruction.is_ip_rel_memory_operand();
    let effective_address = if segment_relative {
        None
    } else if ip_relative {
        Some(instruction.ip_rel_memory_address() & address_mask)
    } else {
        let base_part = if base == Register::None {
            Some(0)
        } else {
            base_value
        };
        let index_part = if index_register == Register::None {
            Some(0)
        } else {
            index_value.map(|value| value.wrapping_mul(u64::from(scale)))
        };
        match (base_part, index_part) {
            (Some(base), Some(index)) => {
                Some(base.wrapping_add(index).wrapping_add(displacement) & address_mask)
            }
            _ => None,
        }
    };
    Some(MemoryOperand {
        operand_index: index,
        segment: register_name(segment),
        base: register_name(base),
        base_value: if ip_relative { None } else { base_value },
        index: register_name(index_register),
        index_value,
        scale,
        displacement,
        effective_address,
        detail: if segment_relative {
            Some("FS/GS-relative operand; the segment base is not captured in CONTEXT.")
        } else {
            None
        },
        base_register: if ip_relative { Register::None } else { base },
    })
}

fn string_register(instruction: &Instruction, register64: Register) -> Register {
    let size = match instruction.op_kind(0) {
        OpKind::MemorySegSI | OpKind::MemorySegDI | OpKind::MemoryESDI => 2,
        OpKind::MemorySegESI | OpKind::MemorySegEDI | OpKind::MemoryESEDI => 4,
        _ => 8,
    };
    match (register64, size) {
        (Register::RSI, 2) => Register::SI,
        (Register::RSI, 4) => Register::ESI,
        (Register::RDI, 2) => Register::DI,
        (Register::RDI, 4) => Register::EDI,
        (register, _) => register,
    }
}

fn address_hints(address: u64, bitness: u32) -> Vec<Value> {
    let mut hints = Vec::new();
    if address < NULL_PAGE_LIMIT {
        hints.push(json!({
            "kind": "null_page_access",
            "address": address,
            "detail": "The faulting address is inside the first 64 KiB, which is never mapped in user mode; this is consistent with a null pointer plus a small offset.",
        }));
    }
    if bitness == 64 && (address == u64::MAX || !is_canonical(address)) {
        hints.push(json!({
            "kind": "non_canonical_address",
            "address": address,
            "detail": "The faulting address is non-canonical (or reported as all ones for a general-protection fault); the pointer value is likely garbage, freed or corrupted.",
        }));
    }
    if let Some(pattern) = fill_pattern(address) {
        hints.push(json!({
            "kind": "debug_fill_pattern",
            "address": address,
            "pattern": pattern,
            "detail": "The faulting address is near a debug-heap/CRT fill pattern.",
        }));
    }
    hints
}

fn is_canonical(address: u64) -> bool {
    let upper = address >> 47;
    upper == 0 || upper == 0x1_FFFF
}

pub(super) fn fill_pattern(value: u64) -> Option<&'static str> {
    DEBUG_FILL_PATTERNS.iter().find_map(|(pattern, name)| {
        let narrow = u64::from(*pattern);
        let wide = narrow | (narrow << 32);
        (value.wrapping_sub(narrow) < FILL_PATTERN_SLACK
            || value.wrapping_sub(wide) < FILL_PATTERN_SLACK)
            .then_some(*name)
    })
}

fn access_value(access: &ExceptionAccess) -> Value {
    json!({ "operation": access.operation, "address": access.address })
}

pub(super) fn register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| format!("{register:?}").to_ascii_lowercase())
}

fn status(status: &str, detail: &str) -> Value {
    json!({ "status": status, "detail": detail })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amd64(rbx: u64, rcx: u64) -> X64ExceptionRegisters {
        X64ExceptionRegisters {
            rax: 1,
            rbx,
            rcx,
            rdx: 3,
            rsi: 4,
            rdi: 5,
            rbp: 6,
            rsp: 7,
            r8: 8,
            r9: 9,
            r10: 10,
            r11: 11,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,
            rip: 0x7ff6_c8e3_f853,
            eflags: 0x202,
        }
    }

    fn access(operation: &'static str, mode: u64, address: u64) -> ExceptionAccess {
        ExceptionAccess {
            operation,
            mode,
            address,
            io_status: None,
        }
    }

    fn kinds(value: &Value) -> Vec<&str> {
        value["hints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hint| hint["kind"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn identifies_null_base_register_for_mov_rax_from_rcx() {
        let registers = amd64(0x1000, 0);
        let value = analyze_fault_operand(
            FaultRegisters::Amd64(&registers),
            0x7ff6_c8e3_f853,
            &access("read", 0, 0),
            &[0x48, 0x8b, 0x01, 0xff, 0x50, 0x08],
        );
        assert_eq!(value["status"], "decoded");
        assert_eq!(value["instruction"]["text"], "mov rax,[rcx]");
        assert_eq!(value["instruction"]["bytes"], "488B01");
        assert_eq!(value["matched_operand"], 0);
        assert_eq!(value["memory_operands"][0]["base"], "rcx");
        assert_eq!(value["memory_operands"][0]["effective_address"], 0);
        assert_eq!(kinds(&value), ["null_page_access", "null_base_register"]);
        assert_eq!(value["hints"][1]["register"], "rcx");
    }

    #[test]
    fn evaluates_base_index_scale_displacement_and_fill_patterns() {
        let mut registers = amd64(0xFEEE_FEEE_FEEE_FEEE, 2);
        registers.rcx = 2;
        // mov eax, [rbx+rcx*4+0x10]
        let address = 0xFEEE_FEEE_FEEE_FEEEu64 + 8 + 0x10;
        let value = analyze_fault_operand(
            FaultRegisters::Amd64(&registers),
            0x1000,
            &access("read", 0, address),
            &[0x8b, 0x44, 0x8b, 0x10],
        );
        assert_eq!(value["matched_operand"], 0);
        assert_eq!(value["memory_operands"][0]["index"], "rcx");
        assert_eq!(value["memory_operands"][0]["scale"], 4);
        assert!(kinds(&value).contains(&"debug_fill_pattern"));
        assert!(kinds(&value).contains(&"non_canonical_address"));
    }

    #[test]
    fn handles_x86_rip_relative_segment_and_unmatched_operands() {
        let registers = X86ExceptionRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0x20,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0,
            eip: 0x401000,
            eflags: 0,
            cs: 0,
            ss: 0,
        };
        // mov dword [ecx+4], 1
        let value = analyze_fault_operand(
            FaultRegisters::X86(&registers),
            0x401000,
            &access("write", 1, 0x24),
            &[0xc7, 0x41, 0x04, 0x01, 0x00, 0x00, 0x00],
        );
        assert_eq!(value["matched_operand"], 0);
        assert_eq!(kinds(&value), ["null_page_access"]);
        // mov eax, fs:[0x18]
        let value = analyze_fault_operand(
            FaultRegisters::X86(&registers),
            0x401000,
            &access("read", 0, 0x18),
            &[0x64, 0xa1, 0x18, 0x00, 0x00, 0x00],
        );
        assert!(value["memory_operands"][0]["effective_address"].is_null());
        assert!(kinds(&value).contains(&"no_operand_matches_fault_address"));
        let registers = amd64(0, 0);
        // mov rax, [rip+0x10]
        let value = analyze_fault_operand(
            FaultRegisters::Amd64(&registers),
            0x1000,
            &access("read", 0, 0x1017),
            &[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00],
        );
        assert_eq!(value["memory_operands"][0]["effective_address"], 0x1017);
        assert_eq!(value["matched_operand"], 0);
        let value = analyze_fault_operand(
            FaultRegisters::Amd64(&registers),
            0x1000,
            &access("read", 0, 0x1017),
            &[0x90],
        );
        assert!(kinds(&value).contains(&"no_memory_operand"));
        let value = analyze_fault_operand(
            FaultRegisters::Amd64(&registers),
            0x1000,
            &access("read", 0, 0x1017),
            &[0x0f],
        );
        assert_eq!(value["status"], "undecodable");
    }
}
