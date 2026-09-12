use crate::error::{Error, Result};

pub(crate) const MAX_BINARY_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_C_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_C_SOURCE_LINES: usize = 1_000_000;

pub(crate) fn validate_binary_input_size(resource: &'static str, bytes: usize) -> Result<()> {
    let bytes: u64 = u64::try_from(bytes).map_or(u64::MAX, |value: u64| value);
    if bytes > MAX_BINARY_INPUT_BYTES {
        return Err(Error::InputTooLarge {
            resource,
            bytes,
            max_bytes: MAX_BINARY_INPUT_BYTES,
        });
    }
    Ok(())
}

pub(crate) const fn validate_c_source_size(bytes: usize) -> Result<()> {
    if bytes > MAX_C_SOURCE_BYTES {
        return Err(Error::CSourceTooLarge {
            bytes,
            max_bytes: MAX_C_SOURCE_BYTES,
        });
    }
    Ok(())
}

pub(crate) fn validate_c_source(source: &str) -> Result<()> {
    validate_c_source_size(source.len())?;
    let line_breaks: usize = source
        .bytes()
        .filter(|byte: &u8| *byte == b'\n')
        .take(MAX_C_SOURCE_LINES.saturating_add(1usize))
        .count();
    if line_breaks > MAX_C_SOURCE_LINES {
        return Err(Error::CSourceComplexityExceeded {
            resource: "line",
            count: line_breaks,
            max_count: MAX_C_SOURCE_LINES,
        });
    }
    Ok(())
}
