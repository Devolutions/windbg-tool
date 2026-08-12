use anyhow::{bail, ensure};
use serde_json::{json, Value};

pub fn memory_dump(address: u64, bytes: &[u8], format: &str) -> anyhow::Result<Value> {
    let rows = match format {
        "db" => dump_db_rows(address, bytes),
        "dq" => dump_dq_rows(address, bytes),
        "ascii" => ascii_strings(address, bytes),
        "utf16" => utf16le_strings(address, bytes),
        other => bail!("unsupported memory dump format: {other}"),
    };
    Ok(json!({
        "format": format,
        "rows": rows,
    }))
}

pub fn dump_db_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "bytes": chunk.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>(),
                "ascii": chunk.iter().map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' }).collect::<String>(),
            })
        })
        .collect()
}

pub fn dump_dq_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            let qwords = chunk
                .chunks(8)
                .filter(|chunk| chunk.len() == 8)
                .map(|chunk| {
                    let value = u64::from_le_bytes(chunk.try_into().expect("chunk length checked"));
                    json!({
                        "value": value,
                        "hex": format!("0x{value:016X}"),
                        "plausible_x64_pointer": plausible_x64_pointer(value),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "qwords": qwords,
            })
        })
        .collect()
}

pub fn classify_memory(address: u64, bytes: &[u8]) -> Value {
    json!({
        "address": address,
        "size": bytes.len(),
        "byte_histogram": byte_histogram_summary(bytes),
        "entropy_bits_per_byte": shannon_entropy(bytes),
        "ascii_strings": ascii_strings(address, bytes),
        "utf16le_strings": utf16le_strings(address, bytes),
        "qwords": qword_values(address, bytes),
        "instruction_hints": instruction_hints(bytes),
        "summary": memory_summary(bytes),
    })
}

pub fn memory_summary(bytes: &[u8]) -> Vec<&'static str> {
    let mut summary = Vec::new();
    if bytes.is_empty() {
        summary.push("empty");
        return summary;
    }
    let histogram = byte_counts(bytes);
    let zero_ratio = histogram[0] as f64 / bytes.len() as f64;
    let ff_ratio = histogram[0xff] as f64 / bytes.len() as f64;
    let max_ratio = histogram.iter().copied().max().unwrap_or_default() as f64 / bytes.len() as f64;
    let entropy = shannon_entropy(bytes);
    if zero_ratio >= 0.90 {
        summary.push("mostly_zero");
    }
    if ff_ratio >= 0.90 {
        summary.push("mostly_ff");
    }
    if max_ratio >= 0.90 {
        summary.push("repeated_fill_pattern");
    }
    if entropy >= 7.5 {
        summary.push("high_entropy");
    }
    if !ascii_strings(0, bytes).is_empty() {
        summary.push("contains_ascii");
    }
    if !utf16le_strings(0, bytes).is_empty() {
        summary.push("contains_utf16le");
    }
    if qword_values(0, bytes).as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["plausible_x64_pointer"] == true)
    }) {
        summary.push("contains_plausible_pointer");
    }
    if !instruction_hints(bytes).is_empty() {
        summary.push("instruction_like_prefix");
    }
    if summary.is_empty() {
        summary.push("unclassified");
    }
    summary
}

fn byte_histogram_summary(bytes: &[u8]) -> Value {
    let histogram = byte_counts(bytes);
    let mut top = histogram
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(byte, count)| {
            json!({
                "byte": byte,
                "hex": format!("{byte:02X}"),
                "count": count,
            })
        })
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right["count"]
            .as_u64()
            .cmp(&left["count"].as_u64())
            .then_with(|| left["byte"].as_u64().cmp(&right["byte"].as_u64()))
    });
    top.truncate(8);
    json!({
        "unique_bytes": histogram.iter().filter(|count| **count > 0).count(),
        "top": top,
    })
}

fn byte_counts(bytes: &[u8]) -> [usize; 256] {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let counts = byte_counts(bytes);
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

pub fn ascii_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            push_ascii_string(address, bytes, begin, index, &mut strings);
        }
    }
    if let Some(begin) = start {
        push_ascii_string(address, bytes, begin, bytes.len(), &mut strings);
    }
    strings
}

fn push_ascii_string(
    address: u64,
    bytes: &[u8],
    begin: usize,
    end: usize,
    strings: &mut Vec<Value>,
) {
    if end.saturating_sub(begin) >= 4 {
        strings.push(json!({
            "address": address + begin as u64,
            "offset": begin,
            "length": end - begin,
            "text": String::from_utf8_lossy(&bytes[begin..end]),
        }));
    }
}

pub fn utf16le_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        let begin = index;
        let mut values = Vec::new();
        while index + 1 < bytes.len() {
            let value = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
            let Some(character) = char::from_u32(value as u32) else {
                break;
            };
            if !(character.is_ascii_graphic() || character == ' ') {
                break;
            }
            values.push(value);
            index += 2;
        }
        if values.len() >= 4 {
            strings.push(json!({
                "address": address + begin as u64,
                "offset": begin,
                "code_units": values.len(),
                "text": String::from_utf16_lossy(&values),
            }));
        }
        index = begin + 2;
    }
    strings
}

pub fn qword_values(address: u64, bytes: &[u8]) -> Value {
    let qwords = bytes
        .chunks_exact(8)
        .take(32)
        .enumerate()
        .map(|(index, chunk)| {
            let value = u64::from_le_bytes(chunk.try_into().expect("chunk size is exact"));
            json!({
                "address": address + (index * 8) as u64,
                "offset": index * 8,
                "value": value,
                "hex": format!("0x{value:016X}"),
                "aligned": value.is_multiple_of(8),
                "plausible_x64_pointer": plausible_x64_pointer(value),
            })
        })
        .collect::<Vec<_>>();
    json!(qwords)
}

pub fn plausible_x64_pointer(value: u64) -> bool {
    value != 0
        && value.is_multiple_of(8)
        && !(0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&value)
}

pub fn instruction_hints(bytes: &[u8]) -> Vec<Value> {
    let mut hints = Vec::new();
    if let Some(first) = bytes.first() {
        match *first {
            0x55 => hints.push(json!({"offset": 0, "kind": "push_rbp_prologue"})),
            0x48 | 0x4c => hints.push(json!({"offset": 0, "kind": "x64_rex_prefix"})),
            0xe8 => hints.push(json!({"offset": 0, "kind": "relative_call"})),
            0xe9 | 0xeb => hints.push(json!({"offset": 0, "kind": "relative_jump"})),
            0xc3 | 0xc2 => hints.push(json!({"offset": 0, "kind": "return"})),
            0xcc => hints.push(json!({"offset": 0, "kind": "int3_breakpoint"})),
            _ => {}
        }
    }
    for (offset, window) in bytes.windows(2).take(32).enumerate() {
        if window == [0x0f, 0x05] {
            hints.push(json!({"offset": offset, "kind": "syscall"}));
        }
    }
    hints
}

pub fn read_pointer_value(bytes: &[u8], pointer_size: u32) -> anyhow::Result<u64> {
    match pointer_size {
        4 => {
            ensure!(bytes.len() >= 4, "pointer read returned fewer than 4 bytes");
            let mut value = [0_u8; 4];
            value.copy_from_slice(&bytes[..4]);
            Ok(u32::from_le_bytes(value) as u64)
        }
        8 => {
            ensure!(bytes.len() >= 8, "pointer read returned fewer than 8 bytes");
            let mut value = [0_u8; 8];
            value.copy_from_slice(&bytes[..8]);
            Ok(u64::from_le_bytes(value))
        }
        other => bail!("unsupported pointer size: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::util::hex_to_bytes;

    #[test]
    fn classifies_strings_fill_and_pointers() {
        let bytes = [
            b'H', b'e', b'l', b'l', b'o', 0, 0, 0, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let classification = classify_memory(0x1000, &bytes);
        assert!(
            classification["ascii_strings"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["text"] == "Hello")),
            "{classification}"
        );
        assert!(
            classification["qwords"]
                .as_array()
                .is_some_and(|items| items
                    .iter()
                    .any(|item| item["plausible_x64_pointer"] == true)),
            "{classification}"
        );
    }

    #[test]
    fn parses_hex_bytes_for_memory_classification() -> anyhow::Result<()> {
        assert_eq!(hex_to_bytes("4869ff")?, vec![0x48, 0x69, 0xff]);
        assert!(hex_to_bytes("123").is_err());
        Ok(())
    }

    #[test]
    fn dumps_memory_as_db_and_dq_rows() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("48656c6c6f0000000010400000000000")?;
        let db = memory_dump(0x1000, &bytes, "db")?;
        assert_eq!(db["rows"][0]["ascii"], "Hello.....@.....");
        let dq = memory_dump(0x1000, &bytes, "dq")?;
        assert_eq!(dq["rows"][0]["qwords"].as_array().unwrap().len(), 2);
        Ok(())
    }

    #[test]
    fn reads_little_endian_pointer_values() -> anyhow::Result<()> {
        assert_eq!(
            read_pointer_value(&hex_to_bytes("78563412")?, 4)?,
            0x12345678
        );
        assert_eq!(
            read_pointer_value(&hex_to_bytes("8877665544332211")?, 8)?,
            0x1122334455667788
        );
        assert!(read_pointer_value(&[0, 1, 2], 4).is_err());
        Ok(())
    }
}
