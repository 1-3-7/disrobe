use serde::{Deserialize, Serialize};

use crate::detect::{
    ELF_MAGIC, MACHO_MAGIC_BE, MACHO_MAGIC_LE, MACHO_MAGIC_LE_64, TRUFFLE_AOT_MARKER,
};
use crate::error::{Result, RubyError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TruffleRubyAot {
    pub container_format: String,
    pub marker_offset: u32,
    pub size_hint: u32,
}

pub(crate) fn walk(bytes: &[u8]) -> Result<TruffleRubyAot> {
    let container: &str = if bytes.starts_with(ELF_MAGIC) {
        "elf"
    } else if bytes.starts_with(MACHO_MAGIC_BE)
        || bytes.starts_with(MACHO_MAGIC_LE)
        || bytes.starts_with(MACHO_MAGIC_LE_64)
    {
        "mach-o"
    } else if bytes.starts_with(b"MZ") {
        "pe"
    } else {
        return Err(RubyError::TruffleRubyUnknownImage);
    };
    let marker_offset: u32 = match find_window(bytes, TRUFFLE_AOT_MARKER) {
        Some(offset) => u32::try_from(offset).unwrap_or(u32::MAX),
        None => return Err(RubyError::TruffleRubyUnknownImage),
    };
    Ok(TruffleRubyAot {
        container_format: container.to_owned(),
        marker_offset,
        size_hint: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
    })
}

#[inline]
fn find_window(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn walks_elf_with_marker() {
        let mut bytes: Vec<u8> = b"\x7FELF".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(TRUFFLE_AOT_MARKER);
        let aot: TruffleRubyAot = walk(&bytes).expect("walk");
        assert_eq!(aot.container_format, "elf");
        assert_eq!(aot.marker_offset, 36);
    }

    #[test]
    fn rejects_unknown_container() {
        let bytes: Vec<u8> = b"\x00\x00\x00\x00".to_vec();
        let err: RubyError = walk(&bytes).expect_err("unknown");
        assert!(matches!(err, RubyError::TruffleRubyUnknownImage));
    }
}
