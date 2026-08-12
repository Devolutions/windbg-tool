use anyhow::{bail, ensure, Context};

pub fn hex_to_bytes(data: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(data.len().is_multiple_of(2), "hex data length must be even");
    (0..data.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&data[index..index + 2], 16)
                .with_context(|| format!("parsing hex byte at offset {index}"))
        })
        .collect()
}

pub fn parse_u64_argument(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).context("parsing hexadecimal integer");
    }
    value.parse::<u64>().context("parsing decimal integer")
}

pub fn ensure_json_object(value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    if value.is_object() {
        Ok(value)
    } else {
        bail!("tool arguments must be a JSON object")
    }
}
