use anyhow::{bail, ensure, Context};

pub fn hex_to_bytes(data: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(data.is_ascii(), "hex data must be ASCII");
    ensure!(data.len().is_multiple_of(2), "hex data length must be even");
    // `from_str_radix` accepts a leading '+', so validate digits explicitly.
    ensure!(
        data.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "hex data must contain only hexadecimal digits"
    );
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
    ensure!(!value.is_empty(), "integer argument must not be empty");
    ensure!(
        !value.starts_with(['+', '-']),
        "unsigned integer argument must not have a sign prefix"
    );
    let cleaned = if value.contains(['`', '_']) {
        std::borrow::Cow::Owned(value.replace(['`', '_'], ""))
    } else {
        std::borrow::Cow::Borrowed(value)
    };
    let prefixed_hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"));
    // WinDbg's `high`low` address form is always hexadecimal, even without 0x.
    let hex = prefixed_hex.or_else(|| value.contains('`').then_some(cleaned.as_ref()));
    if let Some(hex) = hex {
        ensure!(
            !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "hexadecimal integer must contain only hexadecimal digits"
        );
        return u64::from_str_radix(hex, 16).context("parsing hexadecimal integer");
    }
    cleaned.parse::<u64>().context("parsing decimal integer")
}

pub fn ensure_json_object(value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    if value.is_object() {
        Ok(value)
    } else {
        bail!("tool arguments must be a JSON object")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windbg_backtick_addresses_as_hex() -> anyhow::Result<()> {
        assert_eq!(parse_u64_argument("00000000`00401000")?, 0x401000);
        assert_eq!(parse_u64_argument("00007ff6`12345678")?, 0x7ff6_1234_5678);
        assert_eq!(parse_u64_argument("0x00007ff6`12345678")?, 0x7ff6_1234_5678);
        assert_eq!(parse_u64_argument("0x10")?, 0x10);
        assert_eq!(parse_u64_argument("1_000")?, 1000);
        assert_eq!(parse_u64_argument("4096")?, 4096);
        Ok(())
    }

    #[test]
    fn rejects_sign_after_hex_prefix() {
        assert!(parse_u64_argument("0x+10").is_err());
        assert!(parse_u64_argument("0x").is_err());
        assert!(parse_u64_argument("+10").is_err());
        assert!(hex_to_bytes("+f").is_err());
        assert!(hex_to_bytes("+f+f").is_err());
    }
}
