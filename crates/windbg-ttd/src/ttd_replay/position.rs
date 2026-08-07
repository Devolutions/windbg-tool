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
            .split_once(':')
            .ok_or(PositionParseError::MissingSeparator)?;
        Ok(Self {
            sequence: u64::from_str_radix(sequence.trim(), 16)
                .map_err(|_| PositionParseError::InvalidSequence)?,
            steps: u64::from_str_radix(steps.trim(), 16)
                .map_err(|_| PositionParseError::InvalidSteps)?,
        })
    }
}

impl PositionOrPercent {
    pub fn resolve_against(self, start: Position, end: Position) -> anyhow::Result<Position> {
        match self {
            Self::Position(position) => Ok(position),
            Self::Text(text) => Ok(text.parse()?),
            Self::Percent(percent) => {
                let percent = percent.min(100) as u128;
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
    }

    #[test]
    fn resolves_percent_to_sequence_range() {
        let position = PositionOrPercent::Percent(50)
            .resolve_against(
                Position {
                    sequence: 0x10,
                    steps: 0,
                },
                Position {
                    sequence: 0x30,
                    steps: 0,
                },
            )
            .unwrap();
        assert_eq!(
            position,
            Position {
                sequence: 0x20,
                steps: 0
            }
        );
    }
}
