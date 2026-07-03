#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_PACKER_ARCHIVE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::{Artifact, LegacyPass, Rung};

use crate::pass::{
    BundleFormat, DetectedKind, MobilePass, detect_bundle_format, detect_kind,
    extract_android_bundle_children, extract_android_dex_children,
};

pub const PASS_ID: PassId = "mobile.classify";

const TAG_HERMES: &str = "react-native-hermes";
const TAG_FLUTTER_AOT: &str = "flutter-aot";
const TAG_FLUTTER_KERNEL: &str = "flutter-dart-kernel";
const TAG_RN_APK: &str = "react-native-apk";
const TAG_RN_IPA: &str = "react-native-ipa";
const TAG_XAMARIN_APK: &str = "xamarin-apk";
const TAG_CORDOVA_APK: &str = "cordova-apk";
const TAG_CAPACITOR_APK: &str = "capacitor-apk";
const TAG_NATIVESCRIPT_APK: &str = "nativescript-apk";
const TAG_IPA: &str = "ipa";
const TAG_ANDROID_DEX_APK: &str = "android-apk-dex";
const TAG_ANDROID_BUNDLE: &str = "android-bundle";

#[derive(Debug)]
pub struct MobileDetector;

impl Detector for MobileDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let kind: DetectedKind = detect_kind(ctx.bytes);
        if matches!(kind, DetectedKind::AndroidBundle) {
            let format: BundleFormat =
                detect_bundle_format(ctx.bytes).unwrap_or(BundleFormat::Apkm);
            return Some(DetectVerdict::new(
                PASS_ID,
                TAG_ANDROID_BUNDLE,
                FAMILY_PACKER_ARCHIVE,
                0.93,
                28,
                vec![format.marker()],
                format!(
                    "mobile kind={TAG_ANDROID_BUNDLE} format={}",
                    format.marker()
                ),
            ));
        }
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

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        match detect_kind(bytes) {
            DetectedKind::AndroidDexApk => {
                let dex_children: Vec<(String, Vec<u8>)> = extract_android_dex_children(bytes)
                    .map_err(|e: crate::error::Error| {
                        CoreError::PassFailure(format!("DR-MOB-0905: android dex extract: {e}"))
                    })?;
                Ok(to_children(dex_children, "android-dex"))
            }
            DetectedKind::AndroidBundle => {
                let entries: Vec<(String, Vec<u8>)> = extract_android_bundle_children(bytes)
                    .map_err(|e: crate::error::Error| {
                        CoreError::PassFailure(format!("DR-MOB-0906: android bundle extract: {e}"))
                    })?;
                let children: Vec<ChildArtifact> = entries
                    .into_iter()
                    .enumerate()
                    .map(|(index, (name, data)): (usize, (String, Vec<u8>))| {
                        let hint: &str = if name.ends_with(".apk") {
                            "android-apk"
                        } else {
                            "android-dex"
                        };
                        ChildArtifact {
                            handle: ChildHandle {
                                artifact_index: u32::try_from(index).unwrap_or(u32::MAX),
                                relative_path: name,
                                hint: Some(hint.to_string()),
                            },
                            bytes: data,
                        }
                    })
                    .collect();
                Ok(children)
            }
            _ => Ok(Vec::new()),
        }
    }
}

pub static MOBILE_PASS: MobilePassAdapter = MobilePassAdapter;

fn to_children(entries: Vec<(String, Vec<u8>)>, hint: &str) -> Vec<ChildArtifact> {
    entries
        .into_iter()
        .enumerate()
        .map(
            |(index, (name, data)): (usize, (String, Vec<u8>))| ChildArtifact {
                handle: ChildHandle {
                    artifact_index: u32::try_from(index).unwrap_or(u32::MAX),
                    relative_path: name,
                    hint: Some(hint.to_string()),
                },
                bytes: data,
            },
        )
        .collect()
}

fn verdict_for(kind: DetectedKind) -> Option<DetectVerdict> {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match kind {
        DetectedKind::HermesRawBytecode => (TAG_HERMES, "hermes-magic", 0.95),
        DetectedKind::FlutterLibAppSo => (TAG_FLUTTER_AOT, "flutter-elf+aot-snapshot", 0.86),
        DetectedKind::FlutterDartKernel => (TAG_FLUTTER_KERNEL, "dart-kernel-magic", 0.95),
        DetectedKind::ReactNativeApk => (TAG_RN_APK, "apk-zip-rn-bundle", 0.80),
        DetectedKind::ReactNativeIpa => (TAG_RN_IPA, "ipa-rn-bundle", 0.80),
        DetectedKind::XamarinApk => (TAG_XAMARIN_APK, "xamarin-apk", 0.85),
        DetectedKind::CordovaApk => (TAG_CORDOVA_APK, "cordova-apk", 0.85),
        DetectedKind::CapacitorApk => (TAG_CAPACITOR_APK, "capacitor-apk", 0.85),
        DetectedKind::NativeScriptApk => (TAG_NATIVESCRIPT_APK, "nativescript-apk", 0.85),
        DetectedKind::Ipa => (TAG_IPA, "ipa-zip", 0.78),
        DetectedKind::AndroidDexApk => (TAG_ANDROID_DEX_APK, "apk-zip-classes-dex", 0.91),
        DetectedKind::AndroidBundle => (TAG_ANDROID_BUNDLE, "android-bundle", 0.93),
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

#[derive(Debug)]
pub struct MobileCatalogEntry {
    tag: &'static str,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for MobileCatalogEntry {
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

const CATALOG_COUNT: usize = 11;

static CATALOG: [MobileCatalogEntry; CATALOG_COUNT] = [
    MobileCatalogEntry {
        tag: TAG_HERMES,
        id: "mobile-hermes",
        display_name: "React Native Hermes bytecode",
        aliases: &["hermes", "hbc", "react-native"],
        quality: SupportQuality::Full,
    },
    MobileCatalogEntry {
        tag: TAG_FLUTTER_KERNEL,
        id: "mobile-flutter-kernel",
        display_name: "Flutter Dart kernel",
        aliases: &["dart-kernel", "dill"],
        quality: SupportQuality::Full,
    },
    MobileCatalogEntry {
        tag: TAG_FLUTTER_AOT,
        id: "mobile-flutter-aot",
        display_name: "Flutter AOT snapshot (libapp.so)",
        aliases: &["flutter", "libapp", "aot-snapshot"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_RN_APK,
        id: "mobile-rn-apk",
        display_name: "React Native APK",
        aliases: &["rn-apk"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_RN_IPA,
        id: "mobile-rn-ipa",
        display_name: "React Native IPA",
        aliases: &["rn-ipa"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_XAMARIN_APK,
        id: "mobile-xamarin",
        display_name: "Xamarin / .NET MAUI APK",
        aliases: &["xamarin", "maui"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_CORDOVA_APK,
        id: "mobile-cordova",
        display_name: "Apache Cordova APK",
        aliases: &["cordova", "phonegap"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_CAPACITOR_APK,
        id: "mobile-capacitor",
        display_name: "Capacitor APK",
        aliases: &["capacitor", "ionic"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_NATIVESCRIPT_APK,
        id: "mobile-nativescript",
        display_name: "NativeScript APK",
        aliases: &["nativescript"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_ANDROID_DEX_APK,
        id: "mobile-android-apk",
        display_name: "Android APK (classes.dex)",
        aliases: &["apk", "android"],
        quality: SupportQuality::Partial,
    },
    MobileCatalogEntry {
        tag: TAG_ANDROID_BUNDLE,
        id: "mobile-android-bundle",
        display_name: "Android app bundle (AAB / APKM / XAPK)",
        aliases: &["aab", "apkm", "xapk", "bundle"],
        quality: SupportQuality::Partial,
    },
];

fn catalog_id_for_tag(tag: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&MobileCatalogEntry| e.tag == tag)
        .map(|e: &MobileCatalogEntry| e.id)
}

impl ObfuscatorCatalog for MobileDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static MobileCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let verdict: DetectVerdict = Detector::detect(self, ctx)?;
        let entry_id: &'static str = catalog_id_for_tag(verdict.format_tag)?;
        let markers: Vec<String> = verdict
            .markers
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect();
        Some(DetectorOutput::new(entry_id, verdict.confidence, markers))
    }
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
    fn catalog_lists_mobile_frameworks() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&MobileDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        for want in [
            "mobile-hermes",
            "mobile-flutter-aot",
            "mobile-xamarin",
            "mobile-cordova",
        ] {
            assert!(
                ids.contains(&want),
                "mobile catalog missing {want}: {ids:?}"
            );
        }
        let mut sorted: Vec<&'static str> = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CATALOG_COUNT);
    }

    #[test]
    fn catalog_detect_maps_flutter_elf() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&MobileDetector, &ctx(&bytes)).expect("flutter aot detect");
        assert_eq!(out.entry_id, "mobile-flutter-aot");
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(ObfuscatorCatalog::detect(&MobileDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_elf_as_flutter() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        let v: DetectVerdict =
            Detector::detect(&MobileDetector, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_FLUTTER_AOT);
    }

    #[test]
    fn detect_zip_as_rn_apk() {
        let bytes: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
        let v: DetectVerdict =
            Detector::detect(&MobileDetector, &ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_RN_APK);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(Detector::detect(&MobileDetector, &ctx(&bytes)).is_none());
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
