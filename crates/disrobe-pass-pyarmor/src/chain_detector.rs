#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use std::collections::BTreeMap;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_OBFUSCATOR_WRAPPER, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::codec::hex;
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::detect::{
    Detection, DetectionConfidence, ProtectionKind, PyarmorVersion, detect_from_wrapper,
};
use crate::static_unpack::{
    DecryptStatus, HeaderMetadata, UnpackOutput as StaticUnpackOutput, WrapperMagic, parse_header,
    sniff, unpack_static,
};
use crate::unpack::{UnpackOutput as WrapperUnpackOutput, unpack_wrapper_text};

const MANIFEST_CHILD_PATH: &str = "pyarmor-manifest.json";
const PYC_CHILD_PATH: &str = "recovered.pyc";
const CHILD_HINT_PYC: &str = "interpreter-bytecode";
const MANIFEST_SCHEMA: &str = "disrobe.pyarmor.manifest/v0";

pub const PASS_ID: PassId = "pyarmor.unpack";

const TAG_V6: &str = "pyarmor-v6";
const TAG_V7: &str = "pyarmor-v7";
const TAG_V8: &str = "pyarmor-v8";
const TAG_V8_SUPER: &str = "pyarmor-v8-supermode";
const TAG_V9: &str = "pyarmor-v9";
const TAG_V9_BCC: &str = "pyarmor-v9-bcc";
const TAG_LEGACY: &str = "pyarmor-legacy";

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
        if let Ok(text) = core::str::from_utf8(bytes) {
            let decoded: core::result::Result<(Detection, Vec<u8>), crate::error::Error> =
                detect_from_wrapper(text);
            if let Ok((detection, payload)) = decoded {
                return Some(verdict_for_decoded(&detection, &payload));
            }
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
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        self.run_with_path(artifact, None)
    }

    fn run_with_path(&self, artifact: &Artifact, path_hint: Option<&str>) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();

        if let Some(pyc) = path_hint.and_then(|p: &str| recover_pyc_via_runtime(bytes, p)) {
            return Ok(Artifact::new(Rung::Raw, pyc, artifact.root_hash));
        }

        let payload: Vec<u8> = extract_payload(bytes).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-PYARM-0901: pyarmor.unpack: input does not match wrapper magic".to_string(),
            )
        })?;

        let out: StaticUnpackOutput = unpack_static(&payload)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYARM-0902: {e}")))?;
        if out.plaintext.is_empty() {
            let manifest: Vec<u8> = render_manifest(&out, &payload);
            return Ok(Artifact::new(Rung::Disasm, manifest, artifact.root_hash));
        }
        Ok(Artifact::new(Rung::Raw, out.plaintext, artifact.root_hash))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let payload: Vec<u8> = extract_payload(bytes).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-PYARM-0904: pyarmor.unpack: extract_children: input does not match wrapper magic"
                    .to_string(),
            )
        })?;
        let out: StaticUnpackOutput = unpack_static(&payload)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYARM-0905: {e}")))?;

        let mut children: Vec<ChildArtifact> = Vec::with_capacity(2);
        if !out.plaintext.is_empty() {
            children.push(ChildArtifact {
                handle: ChildHandle {
                    artifact_index: 0,
                    relative_path: PYC_CHILD_PATH.to_string(),
                    hint: Some(CHILD_HINT_PYC.to_string()),
                },
                bytes: out.plaintext.clone(),
            });
        }
        let manifest: Vec<u8> = render_manifest(&out, &payload);
        children.push(ChildArtifact {
            handle: ChildHandle {
                artifact_index: u32::try_from(children.len()).unwrap_or(u32::MAX),
                relative_path: MANIFEST_CHILD_PATH.to_string(),
                hint: Some(TERMINAL_HINT.to_string()),
            },
            bytes: manifest,
        });
        Ok(children)
    }
}

fn extract_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    if sniff(bytes).is_ok() {
        Some(bytes.to_vec())
    } else if let Some(decoded) = decode_wrapper_payload(bytes) {
        Some(decoded)
    } else {
        find_wrapper_text_payload(bytes).map(|offset: usize| bytes[offset..].to_vec())
    }
}

const fn confidence_label(c: DetectionConfidence) -> &'static str {
    match c {
        DetectionConfidence::High => "High",
        DetectionConfidence::Medium => "Medium",
        DetectionConfidence::Low => "Low",
    }
}

const fn protection_label(p: ProtectionKind) -> &'static str {
    match p {
        ProtectionKind::Standard => "Standard",
        ProtectionKind::SuperMode => "SuperMode",
        ProtectionKind::Bcc => "Bcc",
        ProtectionKind::Unknown => "Unknown",
    }
}

const fn status_label(s: DecryptStatus) -> &'static str {
    match s {
        DecryptStatus::Functional => "Functional",
        DecryptStatus::BccPartial => "BccPartial",
        DecryptStatus::DetectOnly => "DetectOnly",
        DecryptStatus::Skeleton => "Skeleton",
    }
}

fn compute_limitations(out: &StaticUnpackOutput) -> Vec<String> {
    let mut limits: Vec<String> = Vec::new();
    if matches!(
        out.pyarmor_version,
        PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5
    ) {
        limits.push(
            "PyArmor v3/v4/v5 detected; static decryption is an information-theoretic wall: the \
             code-object AES-128-CTR key is RSA-wrapped in the capsule and absent from the \
             distributed artifact. Recovery needs the original capsule private key or a runtime \
             dump under the matching Python build."
                .to_string(),
        );
    }
    if matches!(out.protection_kind, ProtectionKind::Bcc) {
        limits.push(
            "BCC native body lift requires --allow-bcc; when enabled it is surfaced as recovered \
             pseudo-C via the in-crate x86-64 decompiler."
                .to_string(),
        );
    }
    if matches!(out.pyarmor_version, PyarmorVersion::V9)
        && out
            .header_metadata
            .next_segment_offset
            .is_some_and(|o: u32| o != 0)
    {
        limits.push(
            "9-Pro stage-2 segment(s) detected (header next-segment chain non-zero); stage-2 \
             bodies require runtime bind credentials and stay wrapped under static analysis."
                .to_string(),
        );
    }
    if matches!(out.pyarmor_version, PyarmorVersion::V8 | PyarmorVersion::V9)
        && out.plaintext.is_empty()
    {
        limits.push(
            "v8/v9 AES key lives in the sibling pyarmor_runtime_*/pyarmor_runtime.{pyd,so}; \
             without that runtime binary next to the input the body stays encrypted (detect-only). \
             Run `disrobe pyarmor unpack <wrapper.py>` next to the runtime for full static \
             decryption."
                .to_string(),
        );
    }
    limits
}

fn render_manifest(out: &StaticUnpackOutput, payload: &[u8]) -> Vec<u8> {
    let iv_hex: Option<String> = out
        .header_metadata
        .nonce
        .as_ref()
        .map(|n: &[u8; 12]| hex::encode(n));
    let runtime_key_class: Option<String> = out
        .key_classification
        .as_ref()
        .map(|k| format!("{:?}", k.runtime_key_class));
    let python: Option<String> = out
        .python_version
        .map(|(maj, min): (u8, u8)| format!("{maj}.{min}"));
    let manifest: serde_json::Value = serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "version": version_label(out.pyarmor_version),
        "protection": protection_label(out.protection_kind),
        "confidence": confidence_label(out.confidence),
        "status": status_label(out.status),
        "serial": out.serial,
        "python": python,
        "pyc_magic": out.header_metadata.pyc_magic,
        "key_hex": serde_json::Value::Null,
        "iv_hex": iv_hex,
        "runtime_key_class": runtime_key_class,
        "payload_size": payload.len(),
        "plaintext_size": out.plaintext.len(),
        "encrypted_funcs_recovered": out.encrypted_funcs_recovered,
        "inner_cipher_stats": {
            "recovered_co_count": out.inner_cipher_stats.recovered_co_count,
            "recovered_co_code_bytes": out.inner_cipher_stats.recovered_co_code_bytes,
            "descriptor_cache_hits": out.inner_cipher_stats.descriptor_cache_hits,
            "descriptor_cache_misses": out.inner_cipher_stats.descriptor_cache_misses,
        },
        "limitations": compute_limitations(out),
        "diagnostics": out.diagnostics,
    });
    serde_json::to_vec_pretty(&manifest).unwrap_or_else(|_| b"{}".to_vec())
}

fn recover_pyc_via_runtime(bytes: &[u8], path_hint: &str) -> Option<Vec<u8>> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    if !(text.contains("__pyarmor__") || text.contains("pyarmor_runtime")) {
        return None;
    }
    let wrapper_path: &std::path::Path = std::path::Path::new(path_hint);
    let out: WrapperUnpackOutput = unpack_wrapper_text(text, wrapper_path).ok()?;
    out.pyc.filter(|pyc: &Vec<u8>| !pyc.is_empty())
}

fn decode_wrapper_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    let text: &str = core::str::from_utf8(bytes).ok()?;
    let (_detection, payload): (Detection, Vec<u8>) = detect_from_wrapper(text).ok()?;
    Some(payload)
}

pub static PYARMOR_PASS: PyarmorPass = PyarmorPass;

fn verdict_for_raw_payload(magic: WrapperMagic, payload: &[u8]) -> DetectVerdict {
    let (format_tag, version_label): (&'static str, &'static str) = match magic {
        WrapperMagic::Py8Or9 => classify_v8v9(payload),
        WrapperMagic::PyArmor6Or7 => classify_v6v7(payload),
        WrapperMagic::LegacyV3 | WrapperMagic::LegacyV4 | WrapperMagic::LegacyV5 => {
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

fn verdict_for_decoded(detection: &Detection, decoded: &[u8]) -> DetectVerdict {
    let (format_tag, version_label): (&'static str, &'static str) =
        tag_for_version(detection.version, detection.protection);
    let confidence: f32 = if detection.serial.is_some() {
        0.96
    } else {
        0.9
    };
    let marker: &'static str =
        if matches!(detection.version, PyarmorVersion::V8 | PyarmorVersion::V9) {
            "PY-magic"
        } else if matches!(detection.version, PyarmorVersion::V6 | PyarmorVersion::V7) {
            "PYARMOR-magic"
        } else {
            "legacy-magic"
        };
    DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence,
        10,
        vec![marker],
        format!(
            "pyarmor decoded payload = {version_label} ({} bytes)",
            decoded.len()
        ),
    )
}

const fn tag_for_version(
    version: PyarmorVersion,
    protection: ProtectionKind,
) -> (&'static str, &'static str) {
    match (version, protection) {
        (PyarmorVersion::V9, ProtectionKind::Bcc) => (TAG_V9_BCC, "PY009-bcc"),
        (PyarmorVersion::V9, _) => (TAG_V9, "PY009-standard"),
        (PyarmorVersion::V8, ProtectionKind::SuperMode) => (TAG_V8_SUPER, "PY008-super-mode"),
        (PyarmorVersion::V8, _) => (TAG_V8, "PY008-standard"),
        (PyarmorVersion::V7, _) => (TAG_V7, "PYARMOR v7"),
        (PyarmorVersion::V6, _) => (TAG_V6, "PYARMOR v6"),
        (PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5, _) => {
            (TAG_LEGACY, "PyArmor legacy")
        }
    }
}

fn classify_v8v9(payload: &[u8]) -> (&'static str, &'static str) {
    let Ok(header): Result<HeaderMetadata, crate::error::Error> =
        parse_header(payload, WrapperMagic::Py8Or9)
    else {
        return (TAG_V9, "PY 8/9 short-header");
    };
    let is_v9: bool = !header
        .serial
        .as_deref()
        .is_some_and(|s| s.starts_with("008"));
    match (is_v9, header.protection_type) {
        (true, Some(0x09)) => (TAG_V9_BCC, "PY009-bcc"),
        (true, _) => (TAG_V9, "PY009-standard"),
        (false, _) => {
            if detect_super_mode(payload) {
                (TAG_V8_SUPER, "PY008-super-mode")
            } else {
                (TAG_V8, "PY008-standard")
            }
        }
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
        WrapperMagic::LegacyV3 => vec!["legacy-v3-aes-ctr"],
        WrapperMagic::LegacyV4 => vec!["legacy-v4-aes-ctr"],
        WrapperMagic::LegacyV5 => vec!["legacy-v5-aes-ctr"],
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

#[derive(Debug)]
pub struct PyarmorVersionEntry {
    pub version: PyarmorVersion,
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for PyarmorVersionEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 7;

static CATALOG: [PyarmorVersionEntry; CATALOG_COUNT] = [
    PyarmorVersionEntry {
        version: PyarmorVersion::V3,
        id: "pyarmor-v3",
        display_name: "PyArmor v3 (legacy DES)",
        aliases: &["pyarmor-legacy"],
        quality: SupportQuality::DetectOnly,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V4,
        id: "pyarmor-v4",
        display_name: "PyArmor v4 (legacy mixed)",
        aliases: &[],
        quality: SupportQuality::DetectOnly,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V5,
        id: "pyarmor-v5",
        display_name: "PyArmor v5 (legacy AES)",
        aliases: &[],
        quality: SupportQuality::DetectOnly,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V6,
        id: "pyarmor-v6",
        display_name: "PyArmor v6",
        aliases: &[],
        quality: SupportQuality::Partial,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V7,
        id: "pyarmor-v7",
        display_name: "PyArmor v7",
        aliases: &["pyarmor-supermode"],
        quality: SupportQuality::Partial,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V8,
        id: "pyarmor-v8",
        display_name: "PyArmor v8",
        aliases: &[],
        quality: SupportQuality::Full,
    },
    PyarmorVersionEntry {
        version: PyarmorVersion::V9,
        id: "pyarmor-v9",
        display_name: "PyArmor v9 / 9-Pro",
        aliases: &["pyarmor-9-pro", "pyarmor-bcc"],
        quality: SupportQuality::Full,
    },
];

fn catalog_id_for(version: PyarmorVersion) -> &'static str {
    CATALOG
        .iter()
        .find(|e: &&PyarmorVersionEntry| e.version == version)
        .map_or("pyarmor", |e: &PyarmorVersionEntry| e.id)
}

fn version_of_magic(magic: WrapperMagic, payload: &[u8]) -> PyarmorVersion {
    match magic {
        WrapperMagic::LegacyV3 => PyarmorVersion::V3,
        WrapperMagic::LegacyV4 => PyarmorVersion::V4,
        WrapperMagic::LegacyV5 => PyarmorVersion::V5,
        WrapperMagic::PyArmor6Or7 => {
            if payload.get(10).is_some_and(|b: &u8| *b >= 8) {
                PyarmorVersion::V7
            } else {
                PyarmorVersion::V6
            }
        }
        WrapperMagic::Py8Or9 => {
            if payload.get(2..5) == Some(b"008") {
                PyarmorVersion::V8
            } else {
                PyarmorVersion::V9
            }
        }
    }
}

impl ObfuscatorCatalog for PyarmorDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static PyarmorVersionEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if let Ok(text) = core::str::from_utf8(bytes) {
            let decoded: core::result::Result<(Detection, Vec<u8>), crate::error::Error> =
                detect_from_wrapper(text);
            if let Ok((detection, _payload)) = decoded {
                let confidence: f32 = if detection.serial.is_some() {
                    0.96
                } else {
                    0.9
                };
                let markers: Vec<String> = vec![
                    tag_for_version(detection.version, detection.protection)
                        .1
                        .to_owned(),
                ];
                return Some(DetectorOutput::new(
                    catalog_id_for(detection.version),
                    confidence,
                    markers,
                ));
            }
        }
        let (magic, payload): (WrapperMagic, &[u8]) = if let Ok(m) = sniff(bytes) {
            (m, bytes)
        } else if let Some(offset) = find_wrapper_text_payload(bytes) {
            let payload: &[u8] = &bytes[offset..];
            (sniff(payload).ok()?, payload)
        } else {
            return None;
        };
        let version: PyarmorVersion = version_of_magic(magic, payload);
        let confidence: f32 = match magic {
            WrapperMagic::Py8Or9 | WrapperMagic::PyArmor6Or7 => 0.96,
            _ => 0.65,
        };
        let markers: Vec<String> = markers_for(magic)
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect();
        Some(DetectorOutput::new(
            catalog_id_for(version),
            confidence,
            markers,
        ))
    }
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
        let v: DetectVerdict = Detector::detect(&PyarmorDetector, &ctx).expect("must detect v8");
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
        let v: DetectVerdict = Detector::detect(&PyarmorDetector, &ctx).expect("must detect v6");
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
        let v: Option<DetectVerdict> = Detector::detect(&PyarmorDetector, &ctx);
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
        assert!(Detector::detect(&PyarmorDetector, &ctx).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PYARMOR_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pyarmor() {
        let a: Artifact = Artifact::new(Rung::Raw, b"not pyarmor".to_vec(), [0u8; 32]);
        let r: CoreResult<Artifact> = PYARMOR_PASS.run(&a);
        assert!(r.is_err());
    }

    #[test]
    fn catalog_covers_every_pyarmor_version() {
        let entries: Vec<&'static dyn CatalogEntry> = PyarmorDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn catalog_detects_a_real_v8_payload() {
        let payload: Vec<u8> = make_v8_payload();
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &payload,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let out: DetectorOutput = ObfuscatorCatalog::detect(&PyarmorDetector, &ctx)
            .expect("real v8 wrapper payload must be detected");
        assert_eq!(out.entry_id, "pyarmor-v8");
        assert!(out.confidence > 0.9);
    }

    #[test]
    fn catalog_detect_misses_garbage() {
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"\xffhello world this is not a pyarmor payload",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(ObfuscatorCatalog::detect(&PyarmorDetector, &ctx).is_none());
    }
}
