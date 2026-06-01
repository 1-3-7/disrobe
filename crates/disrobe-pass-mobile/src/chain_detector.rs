#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::{Artifact, LegacyPass, Rung};

use crate::pass::{DetectedKind, MobilePass, detect_kind};

pub const PASS_ID: PassId = "mobile.classify";

const TAG_HERMES: &str = "react-native-hermes";
const TAG_FLUTTER_AOT: &str = "flutter-aot";
const TAG_RN_APK: &str = "react-native-apk";
const TAG_RN_IPA: &str = "react-native-ipa";
const TAG_XAMARIN_APK: &str = "xamarin-apk";
const TAG_CORDOVA_APK: &str = "cordova-apk";
const TAG_CAPACITOR_APK: &str = "capacitor-apk";
const TAG_NATIVESCRIPT_APK: &str = "nativescript-apk";
const TAG_IPA: &str = "ipa";

#[derive(Debug)]
pub struct MobileDetector;

impl Detector for MobileDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let kind: DetectedKind = detect_kind(ctx.bytes);
        verdict_for(kind)
    }
}

#[derive(Debug)]
pub struct MobilePassAdapter;

impl Pass for MobilePassAdapter {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &MobileDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let kind: DetectedKind = detect_kind(bytes);
        if matches!(kind, DetectedKind::Unknown) {
            return Err(CoreError::PassFailure(
                "DR-MOB-0902: mobile.classify: input is not a recognized mobile container"
                    .to_string(),
            ));
        }
        let raw: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), artifact.root_hash);
        LegacyPass::run(&MobilePass, &raw)
    }
}

pub static MOBILE_PASS: MobilePassAdapter = MobilePassAdapter;

fn verdict_for(kind: DetectedKind) -> Option<DetectVerdict> {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match kind {
        DetectedKind::HermesRawBytecode => (TAG_HERMES, "hermes-magic", 0.95),
        DetectedKind::FlutterLibAppSo => (TAG_FLUTTER_AOT, "flutter-elf+aot-snapshot", 0.86),
        DetectedKind::ReactNativeApk => (TAG_RN_APK, "apk-zip-rn-bundle", 0.80),
        DetectedKind::ReactNativeIpa => (TAG_RN_IPA, "ipa-rn-bundle", 0.80),
        DetectedKind::XamarinApk => (TAG_XAMARIN_APK, "xamarin-apk", 0.85),
        DetectedKind::CordovaApk => (TAG_CORDOVA_APK, "cordova-apk", 0.85),
        DetectedKind::CapacitorApk => (TAG_CAPACITOR_APK, "capacitor-apk", 0.85),
        DetectedKind::NativeScriptApk => (TAG_NATIVESCRIPT_APK, "nativescript-apk", 0.85),
        DetectedKind::Ipa => (TAG_IPA, "ipa-zip", 0.78),
        DetectedKind::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        confidence,
        28,
        vec![marker],
        format!("mobile kind={tag}"),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(MobileDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_elf_as_flutter() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        let v: DetectVerdict = MobileDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_FLUTTER_AOT);
    }

    #[test]
    fn detect_zip_as_rn_apk() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
        let v: DetectVerdict = MobileDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_RN_APK);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(MobileDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match MOBILE_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_elf_without_libapp_layout() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = MOBILE_PASS
            .run(&a)
            .expect_err("synthetic ELF lacks libapp.so layout");
        let msg: String = format!("{err}");
        assert!(
            msg.contains("DR-MOB")
                || msg.contains("Unrecognised")
                || msg.contains("recognised")
                || msg.contains("Flutter")
                || msg.contains("flutter")
        );
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = MOBILE_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-MOB-0902"));
    }
}
