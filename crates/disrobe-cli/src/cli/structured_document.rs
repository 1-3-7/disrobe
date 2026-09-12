use std::fmt;
use std::io::Write;

use serde::Serialize;

const MAX_DOCUMENT_OUTPUT_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum StructuredDocumentError {
    InvalidUtcTimestamp,
    EmptyAuthor,
    OutputTooLong { actual: usize, limit: usize },
    AllocationFailed { requested: usize },
    Serialize(serde_json::Error),
}

impl fmt::Display for StructuredDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtcTimestamp => formatter
                .write_str("timestamp must use the canonical UTC form YYYY-MM-DDTHH:MM:SSZ"),
            Self::EmptyAuthor => formatter.write_str("author must not be empty"),
            Self::OutputTooLong { actual, limit } => write!(
                formatter,
                "output would reach {actual} bytes, exceeding the {limit}-byte limit"
            ),
            Self::AllocationFailed { requested } => {
                write!(formatter, "output allocation of {requested} bytes failed")
            }
            Self::Serialize(error) => write!(formatter, "serialization failed: {error}"),
        }
    }
}

impl std::error::Error for StructuredDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LimitFailure {
    actual: usize,
}

struct BoundedSizer {
    bytes: usize,
    failure: Option<LimitFailure>,
}

impl BoundedSizer {
    const fn new() -> Self {
        Self {
            bytes: 0,
            failure: None,
        }
    }
}

impl Write for BoundedSizer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let required: usize = self.bytes.saturating_add(buffer.len());
        if required > MAX_DOCUMENT_OUTPUT_BYTES {
            self.failure = Some(LimitFailure { actual: required });
            return Err(std::io::Error::other(
                "structured document output limit exceeded",
            ));
        }
        self.bytes = required;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn validate_utc_timestamp(value: &str) -> Result<(), StructuredDocumentError> {
    let bytes: &[u8] = value.as_bytes();
    let separators_valid: bool = bytes.len() == 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.get(19) == Some(&b'Z');
    if !separators_valid {
        return Err(StructuredDocumentError::InvalidUtcTimestamp);
    }
    let year: u32 = parse_digits(bytes, 0, 4)?;
    let month: u32 = parse_digits(bytes, 5, 2)?;
    let day: u32 = parse_digits(bytes, 8, 2)?;
    let hour: u32 = parse_digits(bytes, 11, 2)?;
    let minute: u32 = parse_digits(bytes, 14, 2)?;
    let second: u32 = parse_digits(bytes, 17, 2)?;
    let leap_year: bool =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day: u32 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum_day || hour > 23 || minute > 59 || second > 59 {
        return Err(StructuredDocumentError::InvalidUtcTimestamp);
    }
    Ok(())
}

fn parse_digits(bytes: &[u8], start: usize, length: usize) -> Result<u32, StructuredDocumentError> {
    let end: usize = start
        .checked_add(length)
        .ok_or(StructuredDocumentError::InvalidUtcTimestamp)?;
    let digits: &[u8] = bytes
        .get(start..end)
        .ok_or(StructuredDocumentError::InvalidUtcTimestamp)?;
    digits.iter().try_fold(0u32, |value: u32, digit: &u8| {
        if !digit.is_ascii_digit() {
            return Err(StructuredDocumentError::InvalidUtcTimestamp);
        }
        Ok(value * 10 + u32::from(*digit - b'0'))
    })
}

pub(crate) fn require_author(value: &str) -> Result<(), StructuredDocumentError> {
    if value.trim().is_empty() {
        return Err(StructuredDocumentError::EmptyAuthor);
    }
    Ok(())
}

pub(crate) fn to_bounded_pretty_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, StructuredDocumentError> {
    let mut sizer: BoundedSizer = BoundedSizer::new();
    if let Err(error) = serde_json::to_writer_pretty(&mut sizer, value) {
        return sizer.failure.map_or(
            Err(StructuredDocumentError::Serialize(error)),
            |failure: LimitFailure| {
                Err(StructuredDocumentError::OutputTooLong {
                    actual: failure.actual,
                    limit: MAX_DOCUMENT_OUTPUT_BYTES,
                })
            },
        );
    }
    let requested: usize = sizer.bytes;
    let mut output: Vec<u8> = Vec::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| StructuredDocumentError::AllocationFailed { requested })?;
    serde_json::to_writer_pretty(&mut output, value).map_err(StructuredDocumentError::Serialize)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_timestamp_rejects_invalid_calendar_values() {
        assert!(validate_utc_timestamp("2024-02-29T23:59:59Z").is_ok());
        assert!(validate_utc_timestamp("2023-02-29T23:59:59Z").is_err());
        assert!(validate_utc_timestamp("2024-01-01T24:00:00Z").is_err());
        assert!(validate_utc_timestamp("2024-01-01 00:00:00Z").is_err());
    }
}
