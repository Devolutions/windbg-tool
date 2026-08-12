use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter, OpKind, Register,
};
use serde_json::{json, Value};

pub fn disassemble_x64(address: u64, bytes: &[u8], count: usize) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instructions = Vec::new();
    while decoder.can_decode() && instructions.len() < count {
        let instruction = decoder.decode();
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let len = instruction.len();
        let offset = instruction.ip().saturating_sub(address) as usize;
        let end = offset.saturating_add(len).min(bytes.len());
        let instruction_bytes = if offset < bytes.len() {
            bytes[offset..end]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        instructions.push(json!({
            "address": instruction.ip(),
            "address_hex": format!("0x{:X}", instruction.ip()),
            "length": len,
            "bytes": instruction_bytes,
            "text": text,
            "mnemonic": format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
            "flow_control": format!("{:?}", instruction.flow_control()).to_ascii_lowercase(),
            "classification": instruction_classification(&instruction, &text),
            "operands": instruction_operands(&instruction),
        }));
    }
    instructions
}

fn instruction_classification(instruction: &Instruction, text: &str) -> Value {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    match instruction.flow_control() {
        FlowControl::Next => {}
        FlowControl::Call | FlowControl::IndirectCall => tags.push("call"),
        FlowControl::Return => tags.push("return"),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => tags.push("jump"),
        FlowControl::ConditionalBranch => tags.push("conditional_jump"),
        FlowControl::Interrupt | FlowControl::XbeginXabortXend => tags.push("control_transfer"),
        _ => tags.push("control_transfer"),
    }
    if has_memory_operand(instruction) {
        tags.push("memory_access");
    }
    if lower.contains("rsp")
        || lower.contains("rbp")
        || lower.contains("esp")
        || lower.contains("ebp")
    {
        tags.push("stack_related");
    }
    if instruction.memory_segment() == Register::FS || instruction.memory_segment() == Register::GS
    {
        tags.push("teb_tls_segment");
    }
    if lower.contains("int3") || lower == "db 0cch" {
        tags.push("breakpoint");
    }
    if lower.starts_with("syscall") || lower.starts_with("sysenter") {
        tags.push("system_call");
    }
    json!({
        "tags": tags,
        "is_control_flow": instruction.flow_control() != FlowControl::Next,
        "has_memory_operand": has_memory_operand(instruction),
        "is_stack_related": lower.contains("rsp") || lower.contains("rbp") || lower.contains("esp") || lower.contains("ebp"),
    })
}

fn instruction_operands(instruction: &Instruction) -> Vec<Value> {
    (0..instruction.op_count())
        .map(|index| {
            let op_kind = instruction.op_kind(index);
            let mut operand = json!({
                "index": index,
                "kind": format!("{op_kind:?}").to_ascii_lowercase(),
            });
            if is_memory_op_kind(op_kind) {
                operand["memory"] = json!({
                    "segment": register_name(instruction.memory_segment()),
                    "base": register_name(instruction.memory_base()),
                    "index": register_name(instruction.memory_index()),
                    "scale": instruction.memory_index_scale(),
                    "displacement": instruction.memory_displacement64(),
                    "displacement_hex": format!("0x{:X}", instruction.memory_displacement64()),
                });
            }
            operand
        })
        .collect()
}

fn has_memory_operand(instruction: &Instruction) -> bool {
    (0..instruction.op_count()).any(|index| is_memory_op_kind(instruction.op_kind(index)))
}

fn is_memory_op_kind(op_kind: OpKind) -> bool {
    matches!(
        op_kind,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| format!("{register:?}").to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::util::hex_to_bytes;

    #[test]
    fn disassembles_and_classifies_x64_instructions() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("554889e5e801000000c3")?;
        let instructions = disassemble_x64(0x140001000, &bytes, 4);
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "call"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "return"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "stack_related"))),
            "{instructions:?}"
        );
        Ok(())
    }
}
