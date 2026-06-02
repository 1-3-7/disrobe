use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::alt_runtimes::{AltRuntimeError, Result};

const MPY_MAGIC: u8 = b'M';
const MPY_MIN_VERSION: u8 = 0;
const MPY_MAX_VERSION: u8 = 6;
const MPY_FEATURE_BYTECODE: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyVersion(pub u8);

impl MpyVersion {
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn supports_native(self) -> bool {
        self.0 >= 3
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroPythonModule {
    pub version: MpyVersion,
    pub features: u8,
    pub small_int_bits: u8,
    pub qstr_window_size: u16,
    pub raw_code: Vec<u8>,
    pub opcode_histogram: BTreeMap<u8, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyInsn {
    pub offset: usize,
    pub opcode: u8,
}

pub fn parse(bytes: &[u8]) -> Result<MicroPythonModule> {
    let header_len: usize = header_len_for(bytes)?;
    if bytes.len() < header_len {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: header_len,
            had: bytes.len(),
        });
    }
    if bytes[0] != MPY_MAGIC {
        return Err(AltRuntimeError::BadMagic {
            runtime: "micropython",
            got: u32::from(bytes[0]),
        });
    }
    let version: u8 = bytes[1];
    if !(MPY_MIN_VERSION..=MPY_MAX_VERSION).contains(&version) {
        return Err(AltRuntimeError::UnsupportedVersion {
            runtime: "micropython",
            version: u32::from(version),
        });
    }
    let features: u8 = bytes[2];
    let small_int_bits: u8 = bytes[3];
    let qstr_window_size: u16 = if version >= 5 {
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else {
        0u16
    };
    let raw_code: Vec<u8> = bytes[header_len..].to_vec();
    let opcode_histogram: BTreeMap<u8, u32> = histogram(&raw_code);
    Ok(MicroPythonModule {
        version: MpyVersion(version),
        features,
        small_int_bits,
        qstr_window_size,
        raw_code,
        opcode_histogram,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == MPY_MAGIC
        && (MPY_MIN_VERSION..=MPY_MAX_VERSION).contains(&bytes[1])
        && (bytes[2] & 0x03) == MPY_FEATURE_BYTECODE
}

fn header_len_for(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 4 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 4,
            had: bytes.len(),
        });
    }
    let version: u8 = bytes[1];
    if version >= 5 { Ok(6) } else { Ok(4) }
}

impl MicroPythonModule {
    pub fn opcodes(&self) -> impl Iterator<Item = MpyInsn> + '_ {
        self.raw_code
            .iter()
            .enumerate()
            .map(|(i, &op): (usize, &u8)| -> MpyInsn {
                MpyInsn {
                    offset: i,
                    opcode: op,
                }
            })
    }
}

fn histogram(payload: &[u8]) -> BTreeMap<u8, u32> {
    let mut out: BTreeMap<u8, u32> = BTreeMap::new();
    for &b in payload {
        *out.entry(b).or_insert(0u32) += 1u32;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn build_header(version: u8) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(8);
        bytes.push(MPY_MAGIC);
        bytes.push(version);
        bytes.push(MPY_FEATURE_BYTECODE);
        bytes.push(31);
        if version >= 5 {
            bytes.extend_from_slice(&[16u8, 0u8]);
        }
        bytes
    }

    #[test]
    fn parses_mpy_v0_header() {
        let mut bytes: Vec<u8> = build_header(0);
        bytes.extend_from_slice(&[1u8, 2u8, 3u8]);
        let module: MicroPythonModule = parse(&bytes).expect("parse mpy v0");
        assert_eq!(module.version.raw(), 0);
        assert_eq!(module.raw_code, vec![1u8, 2u8, 3u8]);
    }

    #[test]
    fn parses_mpy_v6_header_with_qstr_window() {
        let mut bytes: Vec<u8> = build_header(6);
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let module: MicroPythonModule = parse(&bytes).expect("parse mpy v6");
        assert_eq!(module.version.raw(), 6);
        assert_eq!(module.qstr_window_size, 16);
        assert_eq!(module.raw_code, vec![0xAA, 0xBB]);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 8] = [b'X', 3u8, 0u8, 31u8, 0u8, 0u8, 0u8, 0u8];
        let err: AltRuntimeError = parse(&bytes).expect_err("reject bad magic");
        assert!(matches!(err, AltRuntimeError::BadMagic { .. }));
    }

    #[test]
    fn rejects_unsupported_version() {
        let bytes: [u8; 8] = [MPY_MAGIC, 99u8, 0u8, 31u8, 0u8, 0u8, 0u8, 0u8];
        let err: AltRuntimeError = parse(&bytes).expect_err("reject");
        assert!(matches!(err, AltRuntimeError::UnsupportedVersion { .. }));
    }

    #[test]
    fn detects_all_versions() {
        for v in MPY_MIN_VERSION..=MPY_MAX_VERSION {
            let bytes: Vec<u8> = build_header(v);
            assert!(detect(&bytes), "should detect v{v}");
        }
    }
}
