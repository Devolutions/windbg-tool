use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Position {
    pub sequence: u64,
    pub steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PositionOrPercent {
    Position(Position),
    Text(String),
    Percent(u8),
}

#[derive(Debug, Error)]
pub enum PositionParseError {
    #[error("position must be HEX:HEX")]
    MissingSeparator,
    #[error("invalid hexadecimal sequence component")]
    InvalidSequence,
    #[error("invalid hexadecimal step component")]
    InvalidSteps,
}

impl Position {
    pub const MIN: Self = Self {
        sequence: 0,
        steps: 0,
    };
}

impl fmt::Display for Position {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:X}:{:X}", self.sequence, self.steps)
    }
}

impl FromStr for Position {
    type Err = PositionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (sequence, steps) = value
            .trim()
            .split_once(':')
            .ok_or(PositionParseError::MissingSeparator)?;
        Ok(Self {
            sequence: parse_hex_component(sequence).ok_or(PositionParseError::InvalidSequence)?,
            steps: parse_hex_component(steps).ok_or(PositionParseError::InvalidSteps)?,
        })
    }
}

fn parse_hex_component(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Recognizes textual percentages such as `"50%"` or `"50"`. Text containing `:` is a
/// `HEX:HEX` position and is left to `Position::from_str`.
fn parse_percent_text(text: &str) -> anyhow::Result<Option<u8>> {
    let trimmed = text.trim();
    if trimmed.contains(':') {
        return Ok(None);
    }
    let digits = trimmed.strip_suffix('%').unwrap_or(trimmed).trim();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let percent = digits.parse::<u64>().unwrap_or(u64::MAX);
    anyhow::ensure!(
        percent <= 100,
        "position percentage must be between 0 and 100, got {digits}"
    );
    Ok(Some(percent as u8))
}

impl PositionOrPercent {
    pub fn resolve_against(self, start: Position, end: Position) -> anyhow::Result<Position> {
        match self {
            Self::Position(position) => Ok(position),
            Self::Text(text) => match parse_percent_text(&text)? {
                Some(percent) => Self::Percent(percent).resolve_against(start, end),
                None => Ok(text.parse()?),
            },
            Self::Percent(percent) => {
                anyhow::ensure!(
                    percent <= 100,
                    "position percentage must be between 0 and 100, got {percent}"
                );
                if percent == 0 {
                    return Ok(start);
                }
                if percent == 100 {
                    return Ok(end);
                }
                let percent = percent as u128;
                let start_sequence = start.sequence as u128;
                let end_sequence = end.sequence as u128;
                let sequence = start_sequence
                    + ((end_sequence.saturating_sub(start_sequence) * percent) / 100);
                Ok(Position {
                    sequence: sequence as u64,
                    steps: 0,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windbg_position() {
        let position: Position = "3065BF:1A".parse().unwrap();
        assert_eq!(position.sequence, 0x3065bf);
        assert_eq!(position.steps, 0x1a);
        assert_eq!(position.to_string(), "3065BF:1A");

        let prefixed: Position = "0x3065BF:0x1A".parse().unwrap();
        assert_eq!(prefixed, position);
        assert!("+10:0".parse::<Position>().is_err());
    }

    #[test]
    fn resolves_percent_to_sequence_range() {
        let start = Position {
            sequence: 0x10,
            steps: 5,
        };
        let end = Position {
            sequence: 0x30,
            steps: 9,
        };
        let position = PositionOrPercent::Percent(50)
            .resolve_against(start, end)
            .unwrap();
        assert_eq!(
            position,
            Position {
                sequence: 0x20,
                steps: 0
            }
        );
        assert_eq!(
            PositionOrPercent::Percent(0)
                .resolve_against(start, end)
                .unwrap(),
            start
        );
        assert_eq!(
            PositionOrPercent::Percent(100)
                .resolve_against(start, end)
                .unwrap(),
            end
        );
        assert!(PositionOrPercent::Percent(101)
            .resolve_against(start, end)
            .is_err());
    }

    #[test]
    fn resolves_textual_percent() {
        let start = Position {
            sequence: 0x10,
            steps: 5,
        };
        let end = Position {
            sequence: 0x30,
            steps: 9,
        };
        let half = Position {
            sequence: 0x20,
            steps: 0,
        };
        for text in ["50%", " 50 % ", "50"] {
            assert_eq!(
                PositionOrPercent::Text(text.to_string())
                    .resolve_against(start, end)
                    .unwrap(),
                half,
                "{text:?}"
            );
        }
        assert_eq!(
            PositionOrPercent::Text("100%".to_string())
                .resolve_against(start, end)
                .unwrap(),
            end
        );
        assert!(PositionOrPercent::Text("150%".to_string())
            .resolve_against(start, end)
            .unwrap_err()
            .to_string()
            .contains("between 0 and 100"));
        assert_eq!(
            PositionOrPercent::Text("20:1".to_string())
                .resolve_against(start, end)
                .unwrap(),
            Position {
                sequence: 0x20,
                steps: 1
            }
        );
    }
}
