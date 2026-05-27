#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::detect::PyarmorVersion;
use crate::static_unpack::{
    UnpackOutput as StaticUnpackOutput, WrapperMagic, sniff, unpack_static,
};

pub const PASS_ID: PassId = "pyarmor.unpack";

const TAG_V6: &str = "pyarmor-v6";
const TAG_V7: &str = "pyarmor-v7";
const TAG_V8: &str = "pyarmor-v8";
const TAG_V8_SUPER: &str = "pyarmor-v8-supermode";
const TAG_V9: &str = "pyarmor-v9";
const TAG_V9_BCC: &str = "pyarmor-v9-bcc";
const TAG_LEGACY: &str = "pyarmor-legacy";
const FORMAT_PYC: &str = "pyc";
const FAMILY_PYC: &str = "interpreter-bytecode";

#[derive(Debug)]
pub struct PyarmorDetector;

impl Detector for PyarmorDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Ok(magic) = sniff(bytes) {
            return Some(verdict_for_raw_payload(magic, bytes));
        }
        if let Some(payload_offset) = find_wrapper_text_payload(bytes) {
            let payload: &[u8] = &bytes[payload_offset..];
            if let Ok(magic) = sniff(payload) {
                return Some(verdict_for_raw_payload(magic, payload));
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct PyarmorPass;

impl Pass for PyarmorPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyarmorDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: FORMAT_PYC,
            family: FAMILY_PYC,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let payload: Vec<u8> = if sniff(bytes).is_ok() {
            bytes.to_vec()
        } else if let Some(offset) = find_wrapper_text_payload(bytes) {
            bytes[offset..].to_vec()
        } else {
            return Err(CoreError::PassFailure(
                "DR-PYARM-0901: pyarmor.unpack: input does not match wrapper magic".to_string(),
            ));
        };
        let out: StaticUnpackOutput = unpack_static(&payload)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYARM-0902: {e}")))?;
        if out.plaintext.is_empty() {
            return Err(CoreError::PassFailure(
                "DR-PYARM-0903: pyarmor.unpack: produced empty plaintext".to_string(),
            ));
        }
        Ok(Artifact::new(Rung::Raw, out.plaintext, artifact.root_hash))
    }
}

pub static PYARMOR_PASS: PyarmorPass = PyarmorPass;

fn verdict_for_raw_payload(magic: WrapperMagic, payload: &[u8]) -> DetectVerdict {
    let (format_tag, version_label): (&'static str, &'static str) = match magic {
        WrapperMagic::Py8Or9 => classify_v8v9(payload),
        WrapperMagic::PyArmor6Or7 => classify_v6v7(payload),
        WrapperMagic::LegacyDes | WrapperMagic::LegacyMixed | WrapperMagic::LegacyAesCbc => {
            (TAG_LEGACY, magic.label())
        }
    };
    let confidence: f32 = match magic {
        WrapperMagic::Py8Or9 | WrapperMagic::PyArmor6Or7 => 0.96,
        _ => 0.65,
    };
    DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence,
        10,
        markers_for(magic),
        format!("pyarmor wrapper magic = {version_label}"),
    )
}

fn classify_v8v9(payload: &[u8]) -> (&'static str, &'static str) {
    if payload.len() < 21 {
        return (TAG_V8, "PY 8/9 short-header");
    }
    let serial: &[u8] = &payload[2..8];
    let protection_byte: u8 = payload[20];
    let is_v9: bool = serial.starts_with(b"009");
    match (is_v9, protection_byte) {
        (true, 0x09) => (TAG_V9_BCC, "PY009-bcc"),
        (true, _) => (TAG_V9, "PY009-standard"),
        (false, 0x08) => {
            if detect_super_mode(payload) {
                (TAG_V8_SUPER, "PY008-super-mode")
            } else {
                (TAG_V8, "PY008-standard")
            }
        }
        (false, _) => (TAG_V8, "PY008-unknown-protection"),
    }
}

fn classify_v6v7(payload: &[u8]) -> (&'static str, &'static str) {
    let minor: Option<u8> = payload.get(10).copied();
    match minor {
        Some(m) if m >= 8 => (TAG_V7, "PYARMOR v7 python>=3.8"),
        _ => (TAG_V6, "PYARMOR v6 python<3.8"),
    }
}

fn markers_for(magic: WrapperMagic) -> Vec<&'static str> {
    match magic {
        WrapperMagic::Py8Or9 => vec!["PY-magic"],
        WrapperMagic::PyArmor6Or7 => vec!["PYARMOR-magic"],
        WrapperMagic::LegacyDes => vec!["legacy-mode-0x01"],
        WrapperMagic::LegacyMixed => vec!["legacy-mode-0x02"],
        WrapperMagic::LegacyAesCbc => vec!["legacy-mode-0x05"],
    }
}

fn detect_super_mode(payload: &[u8]) -> bool {
    matches!(payload.get(20), Some(0x08)) && !payload.windows(7).any(|w: &[u8]| w == b"__pyarm")
}

fn find_wrapper_text_payload(bytes: &[u8]) -> Option<usize> {
    let needles: [&[u8]; 2] = [b"b'PY", b"b\"PY"];
    for needle in needles {
        if let Some(pos) = bytes.windows(needle.len()).position(|w: &[u8]| w == needle) {
            return Some(pos + 2);
        }
    }
    let alt: [&[u8]; 2] = [b"b'PYARMOR", b"b\"PYARMOR"];
    for needle in alt {
        if let Some(pos) = bytes.windows(needle.len()).position(|w: &[u8]| w == needle) {
            return Some(pos + 2);
        }
    }
    None
}

#[inline]
#[must_use]
pub const fn version_label(v: PyarmorVersion) -> &'static str {
    match v {
        PyarmorVersion::V3 => "v3",
        PyarmorVersion::V4 => "v4",
        PyarmorVersion::V5 => "v5",
        PyarmorVersion::V6 => "v6",
        PyarmorVersion::V7 => "v7",
        PyarmorVersion::V8 => "v8",
        PyarmorVersion::V9 => "v9",
    }
}

#[inline]
#[must_use]
pub fn metadata_for_unpack(out: &StaticUnpackOutput) -> BTreeMap<String, String> {
    let mut md: BTreeMap<String, String> = BTreeMap::new();
    md.insert(
        "pyarmor_version".to_string(),
        version_label(out.pyarmor_version).to_string(),
    );
    if let Some((maj, min)) = out.python_version {
        md.insert("python_version".to_string(), format!("{maj}.{min}"));
    }
    if let Some(serial) = out.serial.as_deref() {
        md.insert("serial".to_string(), serial.to_string());
    }
    md.insert("status".to_string(), format!("{:?}", out.status));
    md
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_v8_payload() -> Vec<u8> {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[..8].copy_from_slice(b"PY008106");
        payload[9] = 3;
        payload[10] = 12;
        payload[20] = 0x08;
        payload
    }

    #[test]
    fn detector_id_is_stable() {
        let d: PyarmorDetector = PyarmorDetector;
        assert_eq!(d.id(), PASS_ID);
    }

    #[test]
    fn detect_v8_payload() {
        let payload: Vec<u8> = make_v8_payload();
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &payload,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = PyarmorDetector.detect(&ctx).expect("must detect v8");
        assert_eq!(v.pass_id, PASS_ID);
        assert!(v.format_tag.starts_with("pyarmor-v8"));
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn detect_v6_payload() {
        let mut payload: Vec<u8> = vec![0u8; 24];
        payload[..8].copy_from_slice(b"PYARMOR\x00");
        payload[10] = 7;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &payload,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = PyarmorDetector.detect(&ctx).expect("must detect v6");
        assert_eq!(v.format_tag, TAG_V6);
    }

    #[test]
    fn detect_wrapper_text_containing_payload() {
        let payload: Vec<u8> = make_v8_payload();
        let mut wrapper: Vec<u8> = b"__pyarmor__(__name__, __file__, b'".to_vec();
        wrapper.extend_from_slice(&payload);
        wrapper.extend_from_slice(b"')\n");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &wrapper,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: Option<DetectVerdict> = PyarmorDetector.detect(&ctx);
        assert!(v.is_some(), "wrapper-embedded payload must be detected");
    }

    #[test]
    fn detect_misses_garbage() {
        let bytes: &[u8] = b"\xffhello world this is not a pyarmor payload";
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(PyarmorDetector.detect(&ctx).is_none());
    }

    #[test]
    fn pass_output_kind_is_bytes_pyc() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let k: OutputKind = PYARMOR_PASS.output_kind(&a);
        match k {
            OutputKind::Bytes { format_tag, family } => {
                assert_eq!(format_tag, FORMAT_PYC);
                assert_eq!(family, FAMILY_PYC);
            }
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pyarmor() {
        let a: Artifact = Artifact::new(Rung::Raw, b"not pyarmor".to_vec(), [0u8; 32]);
        let r: CoreResult<Artifact> = PYARMOR_PASS.run(&a);
        assert!(r.is_err());
    }
}
