use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use serde::{Deserialize, Serialize};

use crate::cordova::{WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle};
use crate::flutter::{LibAppLayout, parse_libapp_so};
use crate::hermes::{HermesModule, parse as parse_hermes};
use crate::ios::{IpaExtractionReport, extract_ipa};
use crate::nativescript::{NativeScriptReport, extract_nativescript_bundle};
use crate::react_native::{RnExtractionReport, extract_from_apk_or_ipa};
use crate::xamarin::{XamarinReport, extract_xamarin_bundle};

#[derive(Debug, Default, Clone, Copy)]
pub struct MobilePass;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobilePassOutput {
    pub detected: DetectedKind,
    pub react_native: Option<RnExtractionReport>,
    pub hermes: Option<HermesSummary>,
    pub flutter: Option<LibAppLayout>,
    pub xamarin: Option<XamarinReport>,
    pub cordova: Option<WebviewExtractionReport>,
    pub nativescript: Option<NativeScriptReport>,
    pub ipa: Option<IpaExtractionReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectedKind {
    ReactNativeApk,
    ReactNativeIpa,
    HermesRawBytecode,
    FlutterLibAppSo,
    XamarinApk,
    CordovaApk,
    CapacitorApk,
    NativeScriptApk,
    Ipa,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesSummary {
    pub version: u32,
    pub function_count: usize,
    pub identifier_count: usize,
    pub string_count: usize,
    pub raw_bytecode_size: usize,
}

impl LegacyPass for MobilePass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] = &[];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("mobile.bundle.extracted", 1),
        || Capability::produces("mobile.surface.json", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-mobile"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let payload: &[u8] = artifact.envelope.as_slice();
        let output: MobilePassOutput = run_inner(payload)
            .map_err(|e: crate::error::Error| CoreError::PassFailure(format!("{e}")))?;
        let encoded: Vec<u8> = serde_json::to_vec(&output).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-MOB-PASS: serialise: {e}"))
        })?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, encoded, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

fn run_inner(bytes: &[u8]) -> crate::error::Result<MobilePassOutput> {
    let detected: DetectedKind = detect_kind(bytes);
    let mut output: MobilePassOutput = MobilePassOutput {
        detected,
        react_native: None,
        hermes: None,
        flutter: None,
        xamarin: None,
        cordova: None,
        nativescript: None,
        ipa: None,
    };
    match detected {
        DetectedKind::HermesRawBytecode => {
            let module: HermesModule = parse_hermes(bytes)?;
            output.hermes = Some(HermesSummary {
                version: module.header.version,
                function_count: module.functions.len(),
                identifier_count: module.identifiers.len(),
                string_count: module.strings.len(),
                raw_bytecode_size: module.raw_bytecode_size,
            });
        }
        DetectedKind::FlutterLibAppSo => {
            output.flutter = Some(parse_libapp_so(bytes)?);
        }
        DetectedKind::Ipa => {
            let ipa: IpaExtractionReport = extract_ipa(bytes)?;
            output.ipa = Some(ipa);
            if let Ok(rn) = extract_from_apk_or_ipa(bytes) {
                if !rn.bundles.is_empty() {
                    output.detected = DetectedKind::ReactNativeIpa;
                }
                output.react_native = Some(rn);
            }
        }
        DetectedKind::ReactNativeApk
        | DetectedKind::ReactNativeIpa
        | DetectedKind::XamarinApk
        | DetectedKind::CordovaApk
        | DetectedKind::CapacitorApk
        | DetectedKind::NativeScriptApk => {
            if let Ok(rn) = extract_from_apk_or_ipa(bytes)
                && !rn.bundles.is_empty()
            {
                output.react_native = Some(rn);
                output.detected = DetectedKind::ReactNativeApk;
            }
            if let Ok(xa) = extract_xamarin_bundle(bytes) {
                output.xamarin = Some(xa);
                output.detected = DetectedKind::XamarinApk;
            }
            if let Ok(web) = extract_webview_bundle(bytes) {
                let kind: DetectedKind = match web.kind {
                    WebviewBundleKind::Cordova => DetectedKind::CordovaApk,
                    WebviewBundleKind::Capacitor => DetectedKind::CapacitorApk,
                    WebviewBundleKind::Unknown => DetectedKind::Unknown,
                };
                output.cordova = Some(web);
                output.detected = kind;
            }
            if let Ok(ns) = extract_nativescript_bundle(bytes) {
                output.nativescript = Some(ns);
                output.detected = DetectedKind::NativeScriptApk;
            }
            if matches!(output.detected, DetectedKind::Unknown) {
                return Err(crate::error::Error::Unrecognised);
            }
        }
        DetectedKind::Unknown => return Err(crate::error::Error::Unrecognised),
    }
    Ok(output)
}

#[must_use]
pub fn detect_kind(bytes: &[u8]) -> DetectedKind {
    if bytes.len() >= 8 && bytes[..8] == crate::hermes::HERMES_MAGIC_LE_BYTES {
        return DetectedKind::HermesRawBytecode;
    }
    if bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'] {
        return DetectedKind::FlutterLibAppSo;
    }
    if bytes.len() >= 4 && bytes[..2] == [b'P', b'K'] {
        return DetectedKind::ReactNativeApk;
    }
    DetectedKind::Unknown
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;

    use super::*;

    #[test]
    fn pass_metadata_advertises_capabilities() {
        let p: MobilePass = MobilePass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-mobile");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert!(p.required_capabilities().is_empty());
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn detect_hermes_kind() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&crate::hermes::HERMES_MAGIC_LE_BYTES);
        bytes.extend_from_slice(&[0u8; 128]);
        assert_eq!(detect_kind(&bytes), DetectedKind::HermesRawBytecode);
    }

    #[test]
    fn detect_elf_kind() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        assert_eq!(detect_kind(&bytes), DetectedKind::FlutterLibAppSo);
    }

    #[test]
    fn detect_zip_kind() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
        assert_eq!(detect_kind(&bytes), DetectedKind::ReactNativeApk);
    }

    #[test]
    fn detect_unknown_kind() {
        let bytes: Vec<u8> = vec![0, 0, 0, 0];
        assert_eq!(detect_kind(&bytes), DetectedKind::Unknown);
    }

    #[test]
    fn pass_run_rejects_unrecognised_input() {
        let bytes: Vec<u8> = vec![0u8; 32];
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = MobilePass.run(&artifact).expect_err("must fail");
        let msg: String = format!("{err}");
        assert!(
            msg.contains("DR-MOB-0021")
                || msg.contains("Unrecognised")
                || msg.contains("recognised")
        );
    }
}
