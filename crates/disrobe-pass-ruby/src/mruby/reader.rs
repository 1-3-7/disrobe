use serde::{Deserialize, Serialize};

use crate::detect::RITE_MAGIC;
use crate::error::{Result, RubyError};

pub(crate) const RITE_HEADER_SIZE: usize = 22;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiteHeader {
    pub magic: [u8; 4],
    pub format_version: [u8; 4],
    pub binary_size: u32,
    pub compiler_name: [u8; 4],
    pub compiler_version: [u8; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiteSection {
    pub identifier: [u8; 4],
    pub size: u32,
    pub offset: u32,
    pub body_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiteBinary {
    pub header: RiteHeader,
    pub sections: Vec<RiteSection>,
    pub irep_count: u32,
    pub has_debug: bool,
    pub has_lvar: bool,
}

const KNOWN_SECTIONS: &[&[u8; 4]] = &[b"IREP", b"DBG ", b"LVAR", b"END "];

pub(crate) fn read_rite(bytes: &[u8]) -> Result<RiteBinary> {
    if bytes.len() < RITE_HEADER_SIZE {
        return Err(RubyError::Truncated {
            got: bytes.len(),
            need: RITE_HEADER_SIZE,
        });
    }
    let magic: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    if &magic != RITE_MAGIC {
        return Err(RubyError::MrubyBadMagic { got: magic });
    }
    let format_version: [u8; 4] = bytes[4..8]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    if !is_supported_format(format_version) {
        return Err(RubyError::MrubyUnsupportedVersion {
            version: format_version,
        });
    }
    let binary_size: u32 = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| RubyError::MrubySectionTruncated { offset: 10 })?,
    );
    let compiler_name: [u8; 4] = bytes[14..18]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    let compiler_version: [u8; 4] = bytes[18..22]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    let header: RiteHeader = RiteHeader {
        magic,
        format_version,
        binary_size,
        compiler_name,
        compiler_version,
    };
    let mut sections: Vec<RiteSection> = Vec::new();
    let mut irep_count: u32 = 0u32;
    let mut has_debug: bool = false;
    let mut has_lvar: bool = false;
    let mut cursor: usize = RITE_HEADER_SIZE;
    while cursor + 8 <= bytes.len() {
        let id: [u8; 4] = bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RubyError::MrubySectionTruncated { offset: cursor })?;
        let size: u32 = u32::from_be_bytes(
            bytes[cursor + 4..cursor + 8]
                .try_into()
                .map_err(|_| RubyError::MrubySectionTruncated { offset: cursor + 4 })?,
        );
        let known: bool = KNOWN_SECTIONS.contains(&&id);
        if !known {
            return Err(RubyError::MrubyUnknownSection { section: id });
        }
        let body_len: u32 = size.saturating_sub(8);
        sections.push(RiteSection {
            identifier: id,
            size,
            offset: u32::try_from(cursor).unwrap_or(u32::MAX),
            body_len,
        });
        match &id {
            b"IREP" => irep_count += 1,
            b"DBG " => has_debug = true,
            b"LVAR" => has_lvar = true,
            b"END " => break,
            _ => {}
        }
        let advance: usize = if size == 0 { 8 } else { size as usize };
        cursor = cursor.saturating_add(advance);
        if cursor > bytes.len() {
            break;
        }
    }
    Ok(RiteBinary {
        header,
        sections,
        irep_count,
        has_debug,
        has_lvar,
    })
}

#[inline]
const fn is_supported_format(version: [u8; 4]) -> bool {
    matches!(
        &version,
        b"0001"
            | b"0002"
            | b"0003"
            | b"0004"
            | b"0005"
            | b"0006"
            | b"0007"
            | b"0030"
            | b"0200"
            | b"0300"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn synth_rite(format_version: [u8; 4], body: &[u8]) -> Vec<u8> {
        let total: u32 = u32::try_from(RITE_HEADER_SIZE + body.len()).expect("size fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(total as usize);
        v.extend_from_slice(RITE_MAGIC);
        v.extend_from_slice(&format_version);
        v.extend_from_slice(&[0u8, 0u8]);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(b"MATZ");
        v.extend_from_slice(b"0000");
        v.extend_from_slice(body);
        v
    }

    fn synth_section(id: [u8; 4], body: &[u8]) -> Vec<u8> {
        let size: u32 = 8u32 + u32::try_from(body.len()).expect("body fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(size as usize);
        v.extend_from_slice(&id);
        v.extend_from_slice(&size.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parses_valid_rite() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&synth_section(*b"IREP", &[0u8; 16]));
        body.extend_from_slice(&synth_section(*b"DBG ", &[0u8; 8]));
        body.extend_from_slice(&synth_section(*b"LVAR", &[0u8; 4]));
        body.extend_from_slice(&synth_section(*b"END ", &[]));
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let r: RiteBinary = read_rite(&bytes).expect("rite");
        assert_eq!(r.irep_count, 1);
        assert!(r.has_debug);
        assert!(r.has_lvar);
        assert_eq!(r.sections.len(), 4);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes: Vec<u8> = synth_rite(*b"0300", &[]);
        bytes[0] = b'X';
        let err: RubyError = read_rite(&bytes).expect_err("bad magic");
        assert!(matches!(err, RubyError::MrubyBadMagic { .. }));
    }

    #[test]
    fn rejects_unsupported_format() {
        let bytes: Vec<u8> = synth_rite(*b"9999", &[]);
        let err: RubyError = read_rite(&bytes).expect_err("unsupported");
        assert!(matches!(err, RubyError::MrubyUnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_unknown_section() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&synth_section(*b"XXXX", &[0u8; 4]));
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let err: RubyError = read_rite(&bytes).expect_err("unknown sec");
        assert!(matches!(err, RubyError::MrubyUnknownSection { .. }));
    }
}
