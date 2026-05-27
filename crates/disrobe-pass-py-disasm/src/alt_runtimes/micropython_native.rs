use serde::{Deserialize, Serialize};

use crate::alt_runtimes::{AltRuntimeError, Result};

const MPY_MAGIC: u8 = b'M';
const NATIVE_FEATURE_MASK: u8 = 0x03;
const NATIVE_FEATURE_NATIVE: u8 = 0x02;
const NATIVE_FEATURE_VIPER: u8 = 0x03;
const MIN_NATIVE_VERSION: u8 = 3;
const MAX_NATIVE_VERSION: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeKind {
    Native,
    Viper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeArch {
    Unknown,
    X86,
    X64,
    Armv6m,
    Armv7m,
    Armv7em,
    Xtensa,
    XtensaWin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroPythonNativeModule {
    pub version: u8,
    pub kind: NativeKind,
    pub arch: NativeArch,
    pub features_raw: u8,
    pub small_int_bits: u8,
    pub qstr_window_size: u16,
    pub native_code: Vec<u8>,
}

pub fn parse(bytes: &[u8]) -> Result<MicroPythonNativeModule> {
    if bytes.len() < 6 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 6,
            had: bytes.len(),
        });
    }
    if bytes[0] != MPY_MAGIC {
        return Err(AltRuntimeError::BadMagic {
            runtime: "micropython-native",
            got: u32::from(bytes[0]),
        });
    }
    let version: u8 = bytes[1];
    if !(MIN_NATIVE_VERSION..=MAX_NATIVE_VERSION).contains(&version) {
        return Err(AltRuntimeError::UnsupportedVersion {
            runtime: "micropython-native",
            version: u32::from(version),
        });
    }
    let features_raw: u8 = bytes[2];
    let kind: NativeKind = match features_raw & NATIVE_FEATURE_MASK {
        NATIVE_FEATURE_NATIVE => NativeKind::Native,
        NATIVE_FEATURE_VIPER => NativeKind::Viper,
        _ => {
            return Err(AltRuntimeError::NotDetected("micropython-native"));
        }
    };
    let small_int_bits: u8 = bytes[3];
    let arch: NativeArch = decode_arch(features_raw);
    let qstr_window_size: u16 = if version >= 5 {
        u16::from_le_bytes([bytes[4], bytes[5]])
    } else {
        0u16
    };
    let header_len: usize = if version >= 5 { 6 } else { 4 };
    let native_code: Vec<u8> = bytes[header_len..].to_vec();
    Ok(MicroPythonNativeModule {
        version,
        kind,
        arch,
        features_raw,
        small_int_bits,
        qstr_window_size,
        native_code,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == MPY_MAGIC
        && (MIN_NATIVE_VERSION..=MAX_NATIVE_VERSION).contains(&bytes[1])
        && {
            let masked: u8 = bytes[2] & NATIVE_FEATURE_MASK;
            masked == NATIVE_FEATURE_NATIVE || masked == NATIVE_FEATURE_VIPER
        }
}

const fn decode_arch(features: u8) -> NativeArch {
    match (features >> 2) & 0x0F {
        1 => NativeArch::X86,
        2 => NativeArch::X64,
        3 => NativeArch::Armv6m,
        4 => NativeArch::Armv7m,
        5 => NativeArch::Armv7em,
        6 => NativeArch::Xtensa,
        7 => NativeArch::XtensaWin,
        _ => NativeArch::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn make_native_header(version: u8, kind: u8, arch: u8) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(8);
        bytes.push(MPY_MAGIC);
        bytes.push(version);
        bytes.push(kind | (arch << 2));
        bytes.push(31);
        if version >= 5 {
            bytes.extend_from_slice(&[8u8, 0u8]);
        }
        bytes
    }

    #[test]
    fn parses_native_v6_x64() {
        let mut bytes: Vec<u8> = make_native_header(6, NATIVE_FEATURE_NATIVE, 2);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let module: MicroPythonNativeModule = parse(&bytes).expect("parse native");
        assert_eq!(module.version, 6);
        assert_eq!(module.kind, NativeKind::Native);
        assert_eq!(module.arch, NativeArch::X64);
        assert_eq!(module.native_code, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parses_viper_v5_armv7m() {
        let mut bytes: Vec<u8> = make_native_header(5, NATIVE_FEATURE_VIPER, 4);
        bytes.extend_from_slice(&[0x55, 0x66]);
        let module: MicroPythonNativeModule = parse(&bytes).expect("parse viper");
        assert_eq!(module.kind, NativeKind::Viper);
        assert_eq!(module.arch, NativeArch::Armv7m);
    }

    #[test]
    fn rejects_pure_bytecode_features() {
        let bytes: Vec<u8> = make_native_header(6, 0x00, 0);
        let err: AltRuntimeError = parse(&bytes).expect_err("must reject bytecode");
        assert!(matches!(err, AltRuntimeError::NotDetected(_)));
    }

    #[test]
    fn detect_rejects_bytecode_only() {
        let bytes: Vec<u8> = make_native_header(6, 0x00, 0);
        assert!(!detect(&bytes));
    }

    #[test]
    fn detect_accepts_native_v3() {
        let bytes: Vec<u8> = make_native_header(3, NATIVE_FEATURE_NATIVE, 1);
        assert!(detect(&bytes));
    }
}
