use serde::{Deserialize, Serialize};

use crate::detect::RITE_MAGIC;
use crate::error::{Result, RubyError};

pub(crate) const RITE_HEADER_SIZE: usize = 20;
const RITE_HEADER_SIZE_WITH_CRC: usize = 22;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiteHeader {
    pub magic: [u8; 4],
    pub format_version: [u8; 4],
    pub crc_present: bool,
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

const KNOWN_SECTIONS: &[&[u8; 4]] = &[b"IREP", b"DBG\0", b"LVAR", b"END\0"];

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
    let crc_present: bool = header_has_crc_field(bytes);
    let header_size: usize = if crc_present {
        RITE_HEADER_SIZE_WITH_CRC
    } else {
        RITE_HEADER_SIZE
    };
    if bytes.len() < header_size {
        return Err(RubyError::Truncated {
            got: bytes.len(),
            need: header_size,
        });
    }
    let field_base: usize = if crc_present { 10 } else { 8 };
    let binary_size: u32 = u32::from_be_bytes(
        bytes[field_base..field_base + 4]
            .try_into()
            .map_err(|_| RubyError::MrubySectionTruncated { offset: field_base })?,
    );
    let compiler_name: [u8; 4] = bytes[field_base + 4..field_base + 8]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    let compiler_version: [u8; 4] = bytes[field_base + 8..field_base + 12]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    let header: RiteHeader = RiteHeader {
        magic,
        format_version,
        crc_present,
        binary_size,
        compiler_name,
        compiler_version,
    };
    let mut sections: Vec<RiteSection> = Vec::new();
    let mut irep_count: u32 = 0u32;
    let mut has_debug: bool = false;
    let mut has_lvar: bool = false;
    let mut cursor: usize = header_size;
    while cursor <= bytes.len().saturating_sub(8) {
        let id: [u8; 4] = bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RubyError::MrubySectionTruncated { offset: cursor })?;
        let size: u32 = u32::from_be_bytes(
            bytes[cursor + 4..cursor + 8]
                .try_into()
                .map_err(|_| RubyError::MrubySectionTruncated { offset: cursor + 4 })?,
        );
        let known: bool = KNOWN_SECTIONS.contains(&&id);
        if size < 8 {
            return Err(RubyError::MrubySectionTruncated { offset: cursor });
        }
        let section_len: usize = size as usize;
        let section_end: usize = cursor
            .checked_add(section_len)
            .ok_or(RubyError::MrubySectionTruncated { offset: cursor })?;
        if section_end > bytes.len() {
            return Err(RubyError::MrubySectionTruncated { offset: cursor });
        }
        let body_len: u32 = size - 8;
        if known {
            sections.push(RiteSection {
                identifier: id,
                size,
                offset: u32::try_from(cursor).unwrap_or(u32::MAX),
                body_len,
            });
            match &id {
                b"IREP" => irep_count += 1,
                b"DBG\0" => has_debug = true,
                b"LVAR" => has_lvar = true,
                b"END\0" => break,
                _ => {}
            }
        }
        cursor = section_end;
    }
    Ok(RiteBinary {
        header,
        sections,
        irep_count,
        has_debug,
        has_lvar,
    })
}

fn header_has_crc_field(bytes: &[u8]) -> bool {
    let looks_like_section = |id: Option<&[u8]>| -> bool {
        id.and_then(|id: &[u8]| <[u8; 4]>::try_from(id).ok())
            .is_some_and(|id: [u8; 4]| KNOWN_SECTIONS.contains(&&id))
    };
    let without_crc: bool = looks_like_section(bytes.get(RITE_HEADER_SIZE..RITE_HEADER_SIZE + 4));
    let with_crc: bool =
        looks_like_section(bytes.get(RITE_HEADER_SIZE_WITH_CRC..RITE_HEADER_SIZE_WITH_CRC + 4));
    with_crc && !without_crc
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
        body.extend_from_slice(&synth_section(*b"DBG\0", &[0u8; 8]));
        body.extend_from_slice(&synth_section(*b"LVAR", &[0u8; 4]));
        body.extend_from_slice(&synth_section(*b"END\0", &[]));
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
    fn skips_unknown_section_without_recording_it() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&synth_section(*b"XXXX", &[0u8; 4]));
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let r: RiteBinary = read_rite(&bytes).expect("unknown section must not fail parsing");
        assert!(
            r.sections.is_empty(),
            "a skipped section must not be recorded as a structural section"
        );
        assert_eq!(r.irep_count, 0);
    }

    #[test]
    fn skips_unknown_section_and_still_finds_the_irep_and_end_after_it() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&synth_section(*b"XXXX", &[0u8; 12]));
        body.extend_from_slice(&synth_section(*b"IREP", &[0u8; 16]));
        body.extend_from_slice(&synth_section(*b"END\0", &[]));
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let r: RiteBinary = read_rite(&bytes).expect("unknown section must not fail parsing");
        assert_eq!(
            r.irep_count, 1,
            "the IREP section after the skip must count"
        );
        assert_eq!(
            r.sections.len(),
            2,
            "only the two known sections are recorded, the unknown one is skipped"
        );
    }

    #[test]
    fn rejects_section_size_smaller_than_header() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"IREP");
        body.extend_from_slice(&4u32.to_be_bytes());
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let err: RubyError = read_rite(&bytes).expect_err("short sec");
        assert!(matches!(err, RubyError::MrubySectionTruncated { .. }));
    }

    #[test]
    fn rejects_section_body_past_input() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"IREP");
        body.extend_from_slice(&64u32.to_be_bytes());
        let bytes: Vec<u8> = synth_rite(*b"0300", &body);
        let err: RubyError = read_rite(&bytes).expect_err("oversized sec");
        assert!(matches!(err, RubyError::MrubySectionTruncated { .. }));
    }
}
