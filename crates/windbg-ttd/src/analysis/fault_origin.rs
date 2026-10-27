//! Heuristic "where did the faulting pointer come from" analysis for captured user-mode access
//! violations. Starting at the faulting memory operand's base register, it decodes the containing
//! function linearly up to the fault and walks back to the instruction that last wrote that
//! register, following plain register copies. When the writer is a memory load whose address
//! registers are unchanged at fault time, the source slot and the containing object are
//! re-read from the dump.

use super::fault_operand::{fill_pattern, memory_operand, register_name, FaultRegisters};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    Mnemonic, NasmFormatter, OpAccess, OpKind, Register,
};
use serde_json::{json, Value};
use windbg_dbgeng::MinidumpException;

/// Maximum bytes decoded between the function start and the fault address.
pub const FAULT_ORIGIN_MAX_FUNCTION_BYTES: u64 = 4096;
/// Maximum register-copy hops followed backwards.
pub const FAULT_ORIGIN_MAX_HOPS: usize = 4;
const FAULT_INSTRUCTION_BYTES: u32 = super::fault_operand::FAULT_INSTRUCTION_BYTES;

/// Callbacks into the dump: guest reads (may be partial), function start lookup, nearest symbol
/// (name, displacement) and captured memory-region description.
pub struct FaultOriginSources<'a> {
    pub read: &'a dyn Fn(u64, u32) -> anyhow::Result<Vec<u8>>,
    pub function_start: &'a dyn Fn(u64) -> Option<(u64, &'static str)>,
    pub symbol: &'a dyn Fn(u64) -> Option<(String, u64)>,
    pub region: &'a dyn Fn(u64) -> Option<Value>,
}

pub fn fault_origin(exception: &MinidumpException, sources: &FaultOriginSources<'_>) -> Value {
    let Some(record) = &exception.record else {
        return status("not_applicable", "No exception record was captured.");
    };
    let Some(access) = record
        .access
        .as_ref()
        .filter(|access| access.operation != "execute")
    else {
        return status(
            "not_applicable",
            "Fault-origin tracing applies only to data access violations with access parameters.",
        );
    };
    if exception.context.arm64_registers.is_some() {
        return status(
            "architecture_unsupported",
            "ARM64 fault-origin tracing is not implemented.",
        );
    }
    let Some(registers) = FaultRegisters::from_exception(exception) else {
        return status(
            "context_unavailable",
            "Fault-time registers were not captured.",
        );
    };
    let fault_address = record.exception_address;
    let Some(fault_bytes) = (sources.read)(fault_address, FAULT_INSTRUCTION_BYTES)
        .ok()
        .filter(|bytes| !bytes.is_empty())
    else {
        return status(
            "bytes_unavailable",
            "Instruction bytes at the exception address are not captured.",
        );
    };
    let bitness = registers.bitness();
    let fault_instruction =
        Decoder::with_ip(bitness, &fault_bytes, fault_address, DecoderOptions::NONE).decode();
    let mask = if bitness == 32 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    let base = (0..fault_instruction.op_count())
        .filter_map(|index| memory_operand(&fault_instruction, index, registers, mask))
        .find(|operand| operand.effective_address == Some(access.address))
        .map(|operand| operand.base_register)
        .filter(|register| *register != Register::None);
    let Some(base) = base else {
        return status(
            "not_applicable",
            "No faulting memory operand with a base register matches the access address.",
        );
    };
    let Some((start, start_source)) = (sources.function_start)(fault_address) else {
        let mut value = status(
            "function_start_unavailable",
            "Neither unwind data nor symbols identify the start of the faulting function, so the instructions before the fault cannot be decoded reliably.",
        );
        value["fault_register"] = json!(register_name(base));
        return value;
    };
    let distance = fault_address.wrapping_sub(start);
    if start > fault_address || distance > FAULT_ORIGIN_MAX_FUNCTION_BYTES {
        let mut value = status(
            "too_far",
            &format!(
                "The fault is {distance:#x} bytes into the function; tracing decodes at most {FAULT_ORIGIN_MAX_FUNCTION_BYTES:#x} bytes."
            ),
        );
        value["function_start"] = json!({ "address": start, "source": start_source });
        return value;
    }
    let bytes = match (sources.read)(start, distance as u32) {
        Ok(bytes) if bytes.len() as u64 == distance => bytes,
        _ => {
            return status(
                "bytes_unavailable",
                "The function bytes between its start and the fault are not fully captured.",
            )
        }
    };
    trace(
        registers,
        &fault_instruction,
        base,
        start,
        start_source,
        &bytes,
        sources,
    )
}

fn trace(
    registers: FaultRegisters<'_>,
    fault_instruction: &Instruction,
    base: Register,
    start: u64,
    start_source: &'static str,
    bytes: &[u8],
    sources: &FaultOriginSources<'_>,
) -> Value {
    let bitness = registers.bitness();
    let fault_address = fault_instruction.ip();
    let mut decoder = Decoder::with_ip(bitness, bytes, start, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        instructions.push(instruction);
    }
    let function = json!({ "address": start, "source": start_source });
    let end = instructions.last().map_or(start, Instruction::next_ip);
    if end != fault_address {
        let mut value = status(
            "decode_desynchronized",
            "Linear decoding from the function start does not land on the faulting instruction (data in code, overlapping instructions or a wrong start).",
        );
        value["function_start"] = function;
        return value;
    }
    let mut factory = InstructionInfoFactory::new();
    let mut steps = Vec::new();
    let mut register = base;
    let mut before = instructions.len();
    let mut outcome = "writer_not_found";
    for _ in 0..FAULT_ORIGIN_MAX_HOPS {
        let Some(index) = last_writer(&mut factory, &instructions[..before], register, bitness)
        else {
            break;
        };
        let instruction = &instructions[index];
        let (kind, step) = classify(
            instruction,
            register,
            &instructions[index + 1..],
            &mut factory,
            registers,
            sources,
        );
        steps.push(step);
        outcome = "traced";
        if kind != "register_copy" {
            break;
        }
        register = instruction.op1_register();
        before = index;
    }
    json!({
        "status": outcome,
        "source": "linear_decode_of_dump_code_bytes_and_fault_time_registers",
        "function_start": function,
        "fault_instruction": instruction_value(fault_instruction),
        "fault_register": register_name(base),
        "fault_register_value": registers.value(base),
        "decoded_instructions": instructions.len(),
        "steps": steps,
        "detail": "Heuristic: the containing function is decoded in linear address order and the last earlier instruction that writes the register is reported. It is not path-sensitive (a branch could reach the fault from elsewhere), calls are assumed to clobber volatile registers, and a re-read source slot shows the value captured in the dump, not who stored it.",
    })
}

fn last_writer(
    factory: &mut InstructionInfoFactory,
    instructions: &[Instruction],
    register: Register,
    bitness: u32,
) -> Option<usize> {
    instructions.iter().rposition(|instruction| {
        writes(factory, instruction, register)
            || (is_call(instruction) && is_volatile(register, bitness))
    })
}

fn writes(
    factory: &mut InstructionInfoFactory,
    instruction: &Instruction,
    register: Register,
) -> bool {
    factory
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used| {
            used.register().full_register() == register.full_register()
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::ReadWrite
                        | OpAccess::CondWrite
                        | OpAccess::ReadCondWrite
                )
        })
}

fn conditionally_writes(
    factory: &mut InstructionInfoFactory,
    instruction: &Instruction,
    register: Register,
) -> bool {
    factory
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used| {
            used.register().full_register() == register.full_register()
                && matches!(used.access(), OpAccess::CondWrite | OpAccess::ReadCondWrite)
        })
}

fn is_call(instruction: &Instruction) -> bool {
    matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    )
}

fn is_volatile(register: Register, bitness: u32) -> bool {
    let full = register.full_register();
    match bitness {
        64 => matches!(
            full,
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
        ),
        _ => matches!(full, Register::RAX | Register::RCX | Register::RDX),
    }
}

fn classify(
    instruction: &Instruction,
    register: Register,
    after: &[Instruction],
    factory: &mut InstructionInfoFactory,
    registers: FaultRegisters<'_>,
    sources: &FaultOriginSources<'_>,
) -> (&'static str, Value) {
    let mut step = json!({
        "register": register_name(register),
        "writer": instruction_value(instruction),
    });
    let kind = if is_call(instruction) {
        step["call_target"] = match instruction.op0_kind() {
            OpKind::NearBranch64 | OpKind::NearBranch32 => {
                let target = instruction.near_branch_target();
                json!({
                    "address": target,
                    "symbol": symbol_value(sources, target),
                })
            }
            _ => Value::Null,
        };
        if register.full_register() == Register::RAX {
            "call_result"
        } else {
            "clobbered_by_call"
        }
    } else if matches!(instruction.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
        && instruction.op_count() == 2
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register()
    {
        "self_zeroing"
    } else if instruction.mnemonic() == Mnemonic::Mov
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op1_register().full_register() != Register::None
    {
        let source = instruction.op1_register();
        step["source_register"] = json!(register_name(source));
        "register_copy"
    } else if matches!(instruction.code(), Code::Mov_r64_rm64 | Code::Mov_r32_rm32)
        && instruction.op1_kind() == OpKind::Memory
    {
        step["load"] = memory_load(instruction, after, factory, registers, sources);
        "memory_load"
    } else if conditionally_writes(factory, instruction, register) {
        "conditional_write"
    } else if instruction.mnemonic() == Mnemonic::Lea {
        "address_computation"
    } else {
        "other"
    };
    step["kind"] = json!(kind);
    (kind, step)
}

fn memory_load(
    instruction: &Instruction,
    after: &[Instruction],
    factory: &mut InstructionInfoFactory,
    registers: FaultRegisters<'_>,
    sources: &FaultOriginSources<'_>,
) -> Value {
    let base = instruction.memory_base();
    let index = instruction.memory_index();
    let displacement = instruction.memory_displacement64();
    let address_registers = [base, index]
        .into_iter()
        .filter(|register| *register != Register::None && *register != Register::RIP)
        .collect::<Vec<_>>();
    let modified = address_registers
        .iter()
        .find(|register| {
            writes(factory, instruction, **register)
                || after.iter().any(|later| {
                    writes(factory, later, **register)
                        || (is_call(later) && is_volatile(**register, registers.bitness()))
                })
        })
        .copied();
    let mut value = json!({
        "base": register_name(base),
        "index": register_name(index),
        "scale": instruction.memory_index_scale(),
        "displacement": displacement,
        "segment_relative": matches!(instruction.memory_segment(), Register::FS | Register::GS),
    });
    if let Some(register) = modified {
        value["status"] = json!("address_registers_modified");
        value["modified_register"] = json!(register_name(register));
        value["detail"] = json!("A register used to address the source slot changes before the fault, so its fault-time value cannot be used to locate the slot.");
        return value;
    }
    if matches!(instruction.memory_segment(), Register::FS | Register::GS) {
        value["status"] = json!("segment_relative");
        value["detail"] = json!(
            "The source slot is FS/GS-relative; the segment base is not captured in CONTEXT."
        );
        return value;
    }
    let mask = if registers.bitness() == 32 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    let source_address = if instruction.is_ip_rel_memory_operand() {
        Some(instruction.ip_rel_memory_address() & mask)
    } else {
        let base_value = if base == Register::None {
            Some(0)
        } else {
            registers.value(base)
        };
        let index_value = if index == Register::None {
            Some(0)
        } else {
            registers
                .value(index)
                .map(|value| value.wrapping_mul(u64::from(instruction.memory_index_scale())))
        };
        base_value
            .zip(index_value)
            .map(|(base, index)| base.wrapping_add(index).wrapping_add(displacement) & mask)
    };
    let Some(source_address) = source_address else {
        value["status"] = json!("address_unavailable");
        return value;
    };
    let width = instruction.memory_size().size() as u32;
    let current = read_value(sources, source_address, width);
    let loaded = registers.value(instruction.op0_register());
    value["status"] = json!("resolved");
    value["source_address"] = json!(source_address);
    value["source_region"] = (sources.region)(source_address).unwrap_or(Value::Null);
    value["current_value"] = json!(current);
    value["matches_loaded_register"] = json!(current.zip(loaded).map(|(a, b)| a == b));
    if let Some(pattern) = current.and_then(fill_pattern) {
        value["current_value_fill_pattern"] = json!(pattern);
    }
    if base != Register::None && index == Register::None && !instruction.is_ip_rel_memory_operand()
    {
        let object = registers.value(base).unwrap_or_default();
        let stack = matches!(base.full_register(), Register::RSP | Register::RBP);
        value["object"] = if stack {
            json!({
                "kind": "stack_slot",
                "detail": "The slot is addressed relative to the stack/frame pointer, so it is a local or spilled value rather than an object field.",
            })
        } else {
            object_value(object, displacement, registers.bitness(), sources)
        };
    }
    value["detail"] = json!("The slot was re-read from the dump using fault-time register values. A matching value shows the slot still held the bad pointer when the dump was written; it does not show which code stored it.");
    value
}

fn object_value(
    object: u64,
    field_offset: u64,
    bitness: u32,
    sources: &FaultOriginSources<'_>,
) -> Value {
    let pointer_size = bitness / 8;
    let first_pointer = read_value(sources, object, pointer_size);
    let symbol = first_pointer.and_then(|pointer| (sources.symbol)(pointer));
    let class = symbol.as_ref().and_then(|(name, displacement)| {
        if *displacement == 0 {
            vftable_class(name)
        } else {
            None
        }
    });
    json!({
        "kind": "object_field",
        "address": object,
        "field_offset": field_offset,
        "region": (sources.region)(object).unwrap_or(Value::Null),
        "fill_pattern": fill_pattern(object),
        "first_pointer": first_pointer,
        "first_pointer_symbol": symbol.map(|(name, displacement)| json!({ "name": name, "displacement": displacement })),
        "vftable_class": class,
        "detail": "The base register is treated as an object pointer and its first pointer-sized field as a possible vtable. vftable_class is set only when that pointer resolves exactly to a `vftable` symbol; with multiple inheritance this may be a base-class subobject.",
    })
}

fn vftable_class(symbol: &str) -> Option<String> {
    let name = symbol.split_once('!').map_or(symbol, |(_, name)| name);
    let class = name
        .strip_suffix("::`vftable'")
        .or_else(|| name.split_once("::`vftable'").map(|(class, _)| class))?;
    Some(class.trim_start_matches("const ").to_string())
}

fn read_value(sources: &FaultOriginSources<'_>, address: u64, width: u32) -> Option<u64> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let bytes = (sources.read)(address, width).ok()?;
    (bytes.len() == width as usize).then(|| {
        let mut buffer = [0u8; 8];
        buffer[..bytes.len()].copy_from_slice(&bytes);
        u64::from_le_bytes(buffer)
    })
}

fn symbol_value(sources: &FaultOriginSources<'_>, address: u64) -> Value {
    (sources.symbol)(address)
        .map(|(name, displacement)| json!({ "name": name, "displacement": displacement }))
        .unwrap_or(Value::Null)
}

fn instruction_value(instruction: &Instruction) -> Value {
    let mut text = String::new();
    NasmFormatter::new().format(instruction, &mut text);
    json!({ "address": instruction.ip(), "length": instruction.len(), "text": text })
}

fn status(status: &str, detail: &str) -> Value {
    json!({ "status": status, "detail": detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use windbg_dbgeng::{
        ExceptionAccess, MinidumpExceptionContext, MinidumpExceptionRecord, NestedExceptionChain,
        X64ExceptionRegisters,
    };

    const START: u64 = 0x7ff6_c8e3_f800;
    const FAULT: u64 = START + 0x53;

    fn registers(rbx: u64, rcx: u64) -> X64ExceptionRegisters {
        X64ExceptionRegisters {
            rax: 0,
            rbx,
            rcx,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0x1000,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: FAULT,
            eflags: 0x202,
        }
    }

    fn exception(registers: X64ExceptionRegisters, address: u64) -> MinidumpException {
        MinidumpException {
            source: "test",
            status: "captured".into(),
            thread_system_id: Some(1),
            record: Some(MinidumpExceptionRecord {
                exception_code: 0xC000_0005,
                code_name: None,
                exception_flags: 0,
                noncontinuable: false,
                nested_exception_record: 0,
                exception_address: FAULT,
                number_parameters: 2,
                parameters: vec![0, address],
                access: Some(ExceptionAccess {
                    operation: "read",
                    mode: 0,
                    address,
                    io_status: None,
                }),
                fast_fail: None,
                cpp_exception: None,
                clr_exception: None,
                nested_records: NestedExceptionChain {
                    status: "none".into(),
                    records: Vec::new(),
                    detail: String::new(),
                },
            }),
            context: {
                let mut context = MinidumpExceptionContext::default();
                context.registers = Some(registers);
                context
            },
            detail: String::new(),
        }
    }

    /// Function body: `prefix` padded with NOPs up to FAULT, then the faulting `mov rax,[rcx]`.
    fn memory(prefix: &[u8]) -> HashMap<u64, u8> {
        let mut code = vec![0x90u8; (FAULT - START) as usize];
        code[(FAULT - START) as usize - prefix.len()..].copy_from_slice(prefix);
        code.extend([0x48, 0x8b, 0x01]);
        let mut memory = HashMap::new();
        for (offset, byte) in code.into_iter().enumerate() {
            memory.insert(START + offset as u64, byte);
        }
        memory
    }

    fn run(memory: &HashMap<u64, u8>, exception: &MinidumpException) -> Value {
        let read = |address: u64, size: u32| -> anyhow::Result<Vec<u8>> {
            Ok((0..u64::from(size))
                .map_while(|offset| memory.get(&(address + offset)).copied())
                .collect())
        };
        let function_start = |_| Some((START, "runtime_function_entry"));
        let symbol = |address: u64| {
            (address == 0x7ff6_c8f0_0000)
                .then(|| ("rdpshell!HookZOrderSync::`vftable'".to_string(), 0))
        };
        let region =
            |address: u64| (address >= 0x5000).then(|| json!({ "state_name": "MEM_COMMIT" }));
        fault_origin(
            exception,
            &FaultOriginSources {
                read: &read,
                function_start: &function_start,
                symbol: &symbol,
                region: &region,
            },
        )
    }

    #[test]
    fn traces_null_interface_member_to_object_field() {
        // mov rcx,[rbx+10h]
        let mut memory = memory(&[0x48, 0x8b, 0x4b, 0x10]);
        for (offset, byte) in 0x7ff6_c8f0_0000u64.to_le_bytes().into_iter().enumerate() {
            memory.insert(0x5000 + offset as u64, byte);
        }
        for offset in 0..8 {
            memory.insert(0x5010 + offset, 0);
        }
        let value = run(&memory, &exception(registers(0x5000, 0), 0));
        assert_eq!(value["status"], "traced", "{value:#}");
        assert_eq!(value["fault_register"], "rcx");
        assert_eq!(value["fault_instruction"]["text"], "mov rax,[rcx]");
        let step = &value["steps"][0];
        assert_eq!(step["kind"], "memory_load");
        assert_eq!(step["writer"]["text"], "mov rcx,[rbx+10h]");
        assert_eq!(step["writer"]["address"], FAULT - 4);
        let load = &step["load"];
        assert_eq!(load["status"], "resolved");
        assert_eq!(load["source_address"], 0x5010);
        assert_eq!(load["current_value"], 0);
        assert_eq!(load["matches_loaded_register"], true);
        assert_eq!(load["object"]["address"], 0x5000);
        assert_eq!(load["object"]["field_offset"], 0x10);
        assert_eq!(load["object"]["vftable_class"], "HookZOrderSync");
        assert_eq!(load["source_region"]["state_name"], "MEM_COMMIT");
    }

    #[test]
    fn follows_register_copies_and_reports_calls_and_zeroing() {
        // mov rcx,[rbx+10h]; mov rdx,rcx; mov rcx,rdx
        let copies = memory(&[0x48, 0x8b, 0x4b, 0x10, 0x48, 0x89, 0xca, 0x48, 0x89, 0xd1]);
        let value = run(&copies, &exception(registers(0x5000, 0), 0));
        let kinds = value["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["register_copy", "register_copy", "memory_load"]);
        assert_eq!(value["steps"][2]["load"]["status"], "resolved");
        assert!(value["steps"][2]["load"]["current_value"].is_null());

        // mov rcx,[rbx+10h]; call rel32 (clobbers rcx)
        let called = memory_with_call();
        let value = run(&called, &exception(registers(0x5000, 0), 0));
        assert_eq!(value["steps"][0]["kind"], "clobbered_by_call");

        // xor ecx,ecx
        let zeroing = memory(&[0x31, 0xc9]);
        let value = run(&zeroing, &exception(registers(0x5000, 0), 0));
        assert_eq!(value["steps"][0]["kind"], "self_zeroing");

        // mov rcx,[rbx+10h]; mov rbx,rax -> source address register modified
        let modified = memory(&[0x48, 0x8b, 0x4b, 0x10, 0x48, 0x89, 0xc3]);
        let value = run(&modified, &exception(registers(0x5000, 0), 0));
        assert_eq!(
            value["steps"][0]["load"]["status"],
            "address_registers_modified"
        );
        assert_eq!(value["steps"][0]["load"]["modified_register"], "rbx");
    }

    fn memory_with_call() -> HashMap<u64, u8> {
        memory(&[0x48, 0x8b, 0x4b, 0x10, 0xe8, 0x00, 0x00, 0x00, 0x00])
    }

    #[test]
    fn reports_limits() {
        let memory = memory(&[]);
        let value = run(&memory, &exception(registers(0x5000, 0), 0));
        assert_eq!(value["status"], "writer_not_found");

        let value = run(&memory, &exception(registers(0x5000, 0x40), 0x40));
        assert_eq!(value["status"], "writer_not_found");

        let mut unaligned = memory.clone();
        // A 5-byte instruction straddling the fault start desynchronizes decoding.
        unaligned.insert(FAULT - 2, 0xe8);
        let value = run(&unaligned, &exception(registers(0x5000, 0), 0));
        assert_eq!(value["status"], "decode_desynchronized");

        let value = run(&memory, &exception(registers(0x5000, 0), 0x99));
        assert_eq!(value["status"], "not_applicable");

        assert_eq!(
            vftable_class("m!A::B::`vftable'{for `C'}").as_deref(),
            Some("A::B")
        );
        assert_eq!(vftable_class("m!A::Run"), None);
    }
}
