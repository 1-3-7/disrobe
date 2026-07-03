use serde::{Deserialize, Serialize};

use crate::detect::PyarmorVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialKind {
    DefaultTrial,
    LicenseId,
    Unknown,
}

impl SerialKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DefaultTrial => "default-trial",
            Self::LicenseId => "license-id",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeKeyClass {
    Embedded,
    Outer,
    Unknown,
}

impl RuntimeKeyClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Outer => "outer",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialClassification {
    pub serial: String,
    pub kind: SerialKind,
    pub license_id: Option<String>,
    pub format_version: Option<u8>,
    pub format_version_high_confidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderModeFlags {
    pub restrict_mode: bool,
    pub advanced_restrict: bool,
    pub obf_module: bool,
    pub obf_code: bool,
    pub wrap_mode: bool,
    pub outer_runtime_key: bool,
    pub bcc_protection: bool,
    pub raw_restrict_byte: u8,
    pub raw_mode_byte_0: u8,
    pub raw_mode_byte_1: u8,
    pub raw_mode_byte_2: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeKeyClassification {
    pub serial: SerialClassification,
    pub mode_flags: Option<HeaderModeFlags>,
    pub runtime_key_class: RuntimeKeyClass,
    pub notes: Vec<String>,
}

const HEADER_MIN_LEN: usize = 40;
const RESTRICT_BYTE_OFFSET: usize = 16;
const PROTECTION_TYPE_OFFSET: usize = 20;
const MODE_BYTE_0_OFFSET: usize = 36;
const MODE_BYTE_1_OFFSET: usize = 37;
const MODE_BYTE_2_OFFSET: usize = 38;

const MODE0_RESTRICT: u8 = 0x04;
const MODE0_ADVANCED: u8 = 0x08;
const MODE1_OBF_MODULE: u8 = 0x01;
const MODE1_OBF_CODE: u8 = 0x08;
const MODE2_WRAP: u8 = 0x04;
const MODE2_OUTER_KEY: u8 = 0x08;
const PROTECTION_BCC: u8 = 0x09;

#[must_use]
pub fn classify_serial(serial: &str) -> SerialClassification {
    let trimmed: &str = serial.trim_end_matches('\0');
    if trimmed.len() != 6 || !trimmed.bytes().all(|b: u8| b.is_ascii_digit()) {
        return SerialClassification {
            serial: trimmed.to_owned(),
            kind: SerialKind::Unknown,
            license_id: None,
            format_version: None,
            format_version_high_confidence: false,
        };
    }

    let head: &str = &trimmed[..3];

    let (format_version, high_confidence, kind, license_id): (
        Option<u8>,
        bool,
        SerialKind,
        Option<String>,
    ) = match head {
        "008" => (Some(8u8), true, SerialKind::DefaultTrial, None),
        "009" => (Some(9u8), true, SerialKind::DefaultTrial, None),
        "000" => (None, false, SerialKind::DefaultTrial, None),
        _ => (None, false, SerialKind::LicenseId, Some(head.to_owned())),
    };

    SerialClassification {
        serial: trimmed.to_owned(),
        kind,
        license_id,
        format_version,
        format_version_high_confidence: high_confidence,
    }
}

#[must_use]
pub const fn map_format_version(version: u8) -> Option<PyarmorVersion> {
    match version {
        8u8 => Some(PyarmorVersion::V8),
        9u8 => Some(PyarmorVersion::V9),
        _ => None,
    }
}

#[must_use]
pub fn decode_mode_flags(header: &[u8]) -> Option<HeaderModeFlags> {
    if header.len() < HEADER_MIN_LEN {
        return None;
    }
    let restrict_byte: u8 = header[RESTRICT_BYTE_OFFSET];
    let protection: u8 = header[PROTECTION_TYPE_OFFSET];
    let mode0: u8 = header[MODE_BYTE_0_OFFSET];
    let mode1: u8 = header[MODE_BYTE_1_OFFSET];
    let mode2: u8 = header[MODE_BYTE_2_OFFSET];

    Some(HeaderModeFlags {
        restrict_mode: mode0 & MODE0_RESTRICT != 0,
        advanced_restrict: mode0 & MODE0_ADVANCED != 0,
        obf_module: mode1 & MODE1_OBF_MODULE != 0,
        obf_code: mode1 & MODE1_OBF_CODE != 0,
        wrap_mode: mode2 & MODE2_WRAP != 0,
        outer_runtime_key: mode2 & MODE2_OUTER_KEY != 0,
        bcc_protection: protection == PROTECTION_BCC,
        raw_restrict_byte: restrict_byte,
        raw_mode_byte_0: mode0,
        raw_mode_byte_1: mode1,
        raw_mode_byte_2: mode2,
    })
}

#[must_use]
pub fn classify_runtime_key(serial: &str, header: &[u8]) -> RuntimeKeyClassification {
    let serial_class: SerialClassification = classify_serial(serial);
    let mode_flags: Option<HeaderModeFlags> = decode_mode_flags(header);

    let runtime_key_class: RuntimeKeyClass = match mode_flags.as_ref() {
        Some(flags) if flags.outer_runtime_key => RuntimeKeyClass::Outer,
        Some(_) => RuntimeKeyClass::Embedded,
        None => RuntimeKeyClass::Unknown,
    };

    let mut notes: Vec<String> = Vec::new();
    match serial_class.kind {
        SerialKind::LicenseId => notes.push(format!(
            "DR-PYARM-KEY: serial {} is license-id-derived (id prefix {}); the runtime package directory is named pyarmor_runtime_{} and the AES module key is still recovered from that runtime, not the license. The serial does not encode the pyarmor format version (the same id ships from 8.x and 9.x builds), so the version is resolved from the runtime descriptor word",
            serial_class.serial,
            serial_class.license_id.as_deref().unwrap_or("?"),
            serial_class.serial
        )),
        SerialKind::DefaultTrial => notes.push(format!(
            "DR-PYARM-KEY: serial {} is a default/trial serial (format-version marker in the leading field)",
            serial_class.serial
        )),
        SerialKind::Unknown => {}
    }
    if matches!(runtime_key_class, RuntimeKeyClass::Outer) {
        notes.push(
            "DR-PYARM-KEY: outer runtime key flagged (--outer); the AES key lives in a sibling .pyarmor.rkey / .pyarmor.ikey file rather than embedded in the runtime extension, so static decryption needs that external key file"
                .to_owned(),
        );
    }
    if let Some(flags) = mode_flags.as_ref() {
        if flags.restrict_mode {
            notes.push(
                "DR-PYARM-KEY: restrict mode set; the module rejects import/exec from non-obfuscated callers at runtime but the static code-object recovery is unaffected"
                    .to_owned(),
            );
        }
        if flags.advanced_restrict {
            notes.push(
                "DR-PYARM-KEY: advanced/private restrict set; the module is built as private (--private/--assert-call), still statically recoverable from the encrypted blob"
                    .to_owned(),
            );
        }
        if !flags.obf_module {
            notes.push(
                "DR-PYARM-KEY: obf-module disabled (--obf-module 0); the module-level code object is left in plain marshalled form, only the function bodies are protected"
                    .to_owned(),
            );
        }
    }

    RuntimeKeyClassification {
        serial: serial_class,
        mode_flags,
        runtime_key_class,
        notes,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_trial_v9_leading_marker() {
        let c: SerialClassification = classify_serial("009070");
        assert_eq!(c.kind, SerialKind::DefaultTrial);
        assert_eq!(c.format_version, Some(9u8));
        assert!(c.format_version_high_confidence);
        assert_eq!(c.license_id, None);
    }

    #[test]
    fn default_trial_v8_leading_marker() {
        let c: SerialClassification = classify_serial("008106");
        assert_eq!(c.kind, SerialKind::DefaultTrial);
        assert_eq!(c.format_version, Some(8u8));
        assert!(c.format_version_high_confidence);
    }

    #[test]
    fn license_id_serial_carries_no_version_marker() {
        let c: SerialClassification = classify_serial("015009");
        assert_eq!(c.kind, SerialKind::LicenseId);
        assert_eq!(
            c.format_version, None,
            "the same license-id serial 015009 ships from both pyarmor 8.x and 9.x builds, so it does not encode the format version; that comes from the runtime descriptor"
        );
        assert!(!c.format_version_high_confidence);
        assert_eq!(c.license_id.as_deref(), Some("015"));
    }

    #[test]
    fn license_id_other_serial_is_license_id_kind() {
        let c: SerialClassification = classify_serial("042123");
        assert_eq!(c.kind, SerialKind::LicenseId);
        assert_eq!(c.format_version, None);
        assert!(!c.format_version_high_confidence);
        assert_eq!(c.license_id.as_deref(), Some("042"));
    }

    #[test]
    fn all_zero_serial_is_default_no_version() {
        let c: SerialClassification = classify_serial("000000");
        assert_eq!(c.kind, SerialKind::DefaultTrial);
        assert_eq!(c.format_version, None);
    }

    #[test]
    fn non_numeric_serial_is_unknown() {
        let c: SerialClassification = classify_serial("abc123");
        assert_eq!(c.kind, SerialKind::Unknown);
        assert_eq!(c.format_version, None);
    }

    fn header_with(restrict: u8, protection: u8, m0: u8, m1: u8, m2: u8) -> Vec<u8> {
        let mut h: Vec<u8> = vec![0u8; 64];
        h[..8].copy_from_slice(b"PY015009");
        h[RESTRICT_BYTE_OFFSET] = restrict;
        h[PROTECTION_TYPE_OFFSET] = protection;
        h[MODE_BYTE_0_OFFSET] = m0;
        h[MODE_BYTE_1_OFFSET] = m1;
        h[MODE_BYTE_2_OFFSET] = m2;
        h
    }

    #[test]
    fn decode_default_flags() {
        let h: Vec<u8> = header_with(0x80, 0x08, 0x12, 0x09, 0x06);
        let f: HeaderModeFlags = decode_mode_flags(&h).expect("flags");
        assert!(!f.restrict_mode);
        assert!(!f.advanced_restrict);
        assert!(f.obf_module);
        assert!(f.obf_code);
        assert!(f.wrap_mode);
        assert!(!f.outer_runtime_key);
        assert!(!f.bcc_protection);
    }

    #[test]
    fn decode_restrict_flag() {
        let f: HeaderModeFlags =
            decode_mode_flags(&header_with(0x80, 0x08, 0x1e, 0x09, 0x06)).expect("flags");
        assert!(f.restrict_mode);
    }

    #[test]
    fn decode_outer_key_flag() {
        let f: HeaderModeFlags =
            decode_mode_flags(&header_with(0x80, 0x08, 0x12, 0x09, 0x0a)).expect("flags");
        assert!(f.outer_runtime_key);
        assert!(!f.wrap_mode);
    }

    #[test]
    fn decode_obf_module_disabled() {
        let f: HeaderModeFlags =
            decode_mode_flags(&header_with(0x80, 0x08, 0x12, 0x08, 0x06)).expect("flags");
        assert!(!f.obf_module);
        assert!(f.obf_code);
    }

    #[test]
    fn decode_bcc_protection() {
        let f: HeaderModeFlags =
            decode_mode_flags(&header_with(0x80, 0x09, 0x12, 0x09, 0x06)).expect("flags");
        assert!(f.bcc_protection);
    }

    #[test]
    fn short_header_yields_none() {
        assert!(decode_mode_flags(b"PY015009").is_none());
    }

    #[test]
    fn classify_runtime_key_outer_emits_note() {
        let h: Vec<u8> = header_with(0x80, 0x08, 0x12, 0x09, 0x0a);
        let c: RuntimeKeyClassification = classify_runtime_key("015009", &h);
        assert_eq!(c.runtime_key_class, RuntimeKeyClass::Outer);
        assert!(c.notes.iter().any(|n: &String| n.contains("outer")));
    }

    #[test]
    fn classify_runtime_key_embedded_default() {
        let h: Vec<u8> = header_with(0x80, 0x08, 0x12, 0x09, 0x06);
        let c: RuntimeKeyClassification = classify_runtime_key("015009", &h);
        assert_eq!(c.runtime_key_class, RuntimeKeyClass::Embedded);
        assert_eq!(c.serial.kind, SerialKind::LicenseId);
    }
}
