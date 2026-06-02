use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use serde::{Deserialize, Serialize};

use crate::cordova::{WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle};
use crate::flutter::{LibAppLayout, parse_flutter_apk, parse_libapp_so};
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
            if bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'] {
                output.flutter = Some(parse_libapp_so(bytes)?);
            } else {
                output.flutter = Some(parse_flutter_apk(bytes)?.layout);
            }
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
        DetectedKind::ReactNativeApk | DetectedKind::ReactNativeIpa => {
            let rn: RnExtractionReport = extract_from_apk_or_ipa(bytes)?;
            if rn.bundles.is_empty() {
                return Err(crate::error::Error::Unrecognised);
            }
            output.react_native = Some(rn);
        }
        DetectedKind::XamarinApk => {
            output.xamarin = Some(extract_xamarin_bundle(bytes)?);
        }
        DetectedKind::CordovaApk | DetectedKind::CapacitorApk => {
            let web: WebviewExtractionReport = extract_webview_bundle(bytes)?;
            output.detected = match web.kind {
                WebviewBundleKind::Cordova => DetectedKind::CordovaApk,
                WebviewBundleKind::Capacitor => DetectedKind::CapacitorApk,
                WebviewBundleKind::Unknown => return Err(crate::error::Error::Unrecognised),
            };
            output.cordova = Some(web);
        }
        DetectedKind::NativeScriptApk => {
            output.nativescript = Some(extract_nativescript_bundle(bytes)?);
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
        return classify_zip_container(bytes);
    }
    DetectedKind::Unknown
}

fn classify_zip_container(bytes: &[u8]) -> DetectedKind {
    use std::io::Cursor;

    use zip::ZipArchive;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let Ok(mut archive): zip::result::ZipResult<ZipArchive<Cursor<&[u8]>>> =
        ZipArchive::new(cursor)
    else {
        return DetectedKind::ReactNativeApk;
    };
    let entry_count: usize = archive.len();
    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        if let Ok(f) = archive.by_index(i) {
            names.push(f.name().to_owned());
        }
    }
    classify_apk_entry_names(&names)
}

fn classify_apk_entry_names(names: &[String]) -> DetectedKind {
    let has = |needle: &str| -> bool { names.iter().any(|n: &String| n == needle) };
    let has_prefix =
        |prefix: &str| -> bool { names.iter().any(|n: &String| n.starts_with(prefix)) };
    let has_contains = |needle: &str| -> bool { names.iter().any(|n: &String| n.contains(needle)) };

    let is_ipa: bool = has_prefix("Payload/") && has_contains(".app/");

    let flutter: bool = has_prefix("assets/flutter_assets/")
        || names.iter().any(|n: &String| {
            n.starts_with("lib/") && (n.ends_with("/libapp.so") || n.ends_with("/libflutter.so"))
        });
    if flutter {
        return DetectedKind::FlutterLibAppSo;
    }

    if has("assets/www/cordova.js") || has("assets/www/cordova_plugins.js") {
        return DetectedKind::CordovaApk;
    }
    if has("assets/public/capacitor.config.json")
        || has("assets/capacitor.config.json")
        || has("App/App/public/capacitor.config.json")
    {
        return DetectedKind::CapacitorApk;
    }
    let nativescript: bool = has("assets/app/bundle.js")
        || has("assets/app/runtime.js")
        || has("assets/app/vendor.js")
        || has("assets/app/starter.js")
        || has("App/App/app/bundle.js");
    if nativescript {
        return DetectedKind::NativeScriptApk;
    }
    let xamarin: bool = has("assemblies/assemblies.blob")
        || names.iter().any(|n: &String| {
            n.starts_with("assemblies/") && (n.ends_with(".dll") || n.ends_with(".dll.so"))
        })
        || has_contains("Microsoft.Maui");
    if xamarin {
        return DetectedKind::XamarinApk;
    }
    let react_native: bool = has("assets/index.android.bundle")
        || has("assets/index.android.jsbundle")
        || has("assets/index.bundle")
        || has("Payload/main.jsbundle")
        || has("main.jsbundle")
        || names
            .iter()
            .any(|n: &String| n.ends_with(".hbc") || n.ends_with(".hbcbundle"));
    if react_native {
        return if is_ipa {
            DetectedKind::ReactNativeIpa
        } else {
            DetectedKind::ReactNativeApk
        };
    }
    if is_ipa {
        return DetectedKind::Ipa;
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

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s: &&str| (*s).to_owned()).collect()
    }

    #[test]
    fn classify_flutter_apk() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "lib/arm64-v8a/libapp.so",
            "lib/arm64-v8a/libflutter.so",
            "assets/flutter_assets/AssetManifest.json",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::FlutterLibAppSo);
    }

    #[test]
    fn classify_cordova_over_react_native() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "assets/www/index.html",
            "assets/www/cordova.js",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::CordovaApk);
    }

    #[test]
    fn classify_capacitor_apk() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "assets/public/index.html",
            "assets/public/capacitor.config.json",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::CapacitorApk);
    }

    #[test]
    fn classify_nativescript_apk() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "assets/app/bundle.js",
            "assets/app/runtime.js",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::NativeScriptApk);
    }

    #[test]
    fn classify_xamarin_assembly_store() {
        let n: Vec<String> = names(&["AndroidManifest.xml", "assemblies/assemblies.blob"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::XamarinApk);
    }

    #[test]
    fn classify_xamarin_legacy_dll() {
        let n: Vec<String> = names(&["assemblies/MyApp.dll"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::XamarinApk);
    }

    #[test]
    fn classify_react_native_android() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "assets/index.android.bundle",
            "classes.dex",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::ReactNativeApk);
    }

    #[test]
    fn classify_react_native_ipa() {
        let n: Vec<String> = names(&["Payload/RnApp.app/Demo", "main.jsbundle"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::ReactNativeIpa);
    }

    #[test]
    fn classify_plain_ipa() {
        let n: Vec<String> = names(&["Payload/Demo.app/Demo", "Payload/Demo.app/Info.plist"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::Ipa);
    }

    #[test]
    fn classify_empty_container_unknown() {
        let n: Vec<String> = names(&["AndroidManifest.xml", "classes.dex"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::Unknown);
    }

    #[test]
    fn classify_full_zip_routes_nativescript() {
        use std::io::{Cursor, Write};

        use zip::ZipWriter;
        use zip::write::SimpleFileOptions;

        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (n, c) in [
                ("AndroidManifest.xml", &b"<manifest/>"[..]),
                ("assets/app/bundle.js", &b"// bundle"[..]),
            ] {
                zw.start_file::<&str, ()>(n, opts).expect("start");
                zw.write_all(c).expect("write");
            }
            zw.finish().expect("finish");
        }
        assert_eq!(detect_kind(&buf), DetectedKind::NativeScriptApk);
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
