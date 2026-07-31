use serde::{Deserialize, Serialize};

use crate::apk_recon::{
    ApkReconReport, MAX_PROTECTOR_CARVE_SCAN, analyze as analyze_apk_recon,
    find_embedded_dex_carves, materialize_embedded_dex,
};
use crate::cordova::{WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle};
use crate::debug::{dbg_hex, dbg_kv, dbg_line, dbg_section};
use crate::flutter::{
    AotLiftReport, Arm64Disassembly, DartKernel, DartLibAppRecovery, DartSnapshotStructure,
    LibAppLayout, decompile_libapp_so_recovery, decompile_libapp_so_structured,
    disassemble_libapp_so, is_dart_kernel, lift_libapp_aot, parse_flutter_apk, parse_kernel,
    parse_libapp_so,
};
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
    pub flutter_dart: Option<DartSnapshotStructure>,
    pub flutter_libapp_recovery: Option<DartLibAppRecovery>,
    pub flutter_arm64_disasm: Option<Arm64Disassembly>,
    pub flutter_aot_lift: Option<AotLiftReport>,
    pub flutter_kernel: Option<DartKernel>,
    pub xamarin: Option<XamarinReport>,
    pub cordova: Option<WebviewExtractionReport>,
    pub nativescript: Option<NativeScriptReport>,
    pub ipa: Option<IpaExtractionReport>,
    pub android_dex: Option<AndroidDexReport>,
    pub android_bundle: Option<AndroidBundleReport>,
    pub apk_recon: Option<ApkReconReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidDexReport {
    pub dex_entries: Vec<AndroidDexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidBundleReport {
    pub format: BundleFormat,
    pub apks: Vec<AndroidDexEntry>,
    pub dex_entries: Vec<AndroidDexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidDexEntry {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectedKind {
    ReactNativeApk,
    ReactNativeIpa,
    HermesRawBytecode,
    FlutterLibAppSo,
    FlutterDartKernel,
    XamarinApk,
    CordovaApk,
    CapacitorApk,
    NativeScriptApk,
    Ipa,
    AndroidDexApk,
    AndroidBundle,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleFormat {
    Apkm,
    Xapk,
    Aab,
}

impl BundleFormat {
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Apkm => "apkm",
            Self::Xapk => "xapk",
            Self::Aab => "aab",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesSummary {
    pub version: u32,
    pub function_count: usize,
    pub identifier_count: usize,
    pub string_count: usize,
    pub raw_bytecode_size: usize,
}

pub(crate) fn run_inner(bytes: &[u8]) -> crate::error::Result<MobilePassOutput> {
    dbg_section("mobile analyze");
    dbg_kv("input_len", || bytes.len().to_string());
    dbg_hex("input-magic", bytes, 8);
    let detected: DetectedKind = detect_kind(bytes);
    dbg_kv("classify", || format!("{detected:?}"));
    let mut output: MobilePassOutput = MobilePassOutput {
        detected,
        react_native: None,
        hermes: None,
        flutter: None,
        flutter_dart: None,
        flutter_libapp_recovery: None,
        flutter_arm64_disasm: None,
        flutter_aot_lift: None,
        flutter_kernel: None,
        xamarin: None,
        cordova: None,
        nativescript: None,
        ipa: None,
        android_dex: None,
        android_bundle: None,
        apk_recon: None,
    };
    if bytes.len() >= 2
        && bytes[..2] == [b'P', b'K']
        && let Ok(recon) = analyze_apk_recon(bytes)
    {
        output.apk_recon = Some(recon);
    }
    match detected {
        DetectedKind::HermesRawBytecode => {
            let module: HermesModule = parse_hermes(bytes)?;
            dbg_kv("hermes.version", || module.header.version.to_string());
            dbg_kv("hermes.functions", || module.functions.len().to_string());
            dbg_kv("hermes.strings", || module.strings.len().to_string());
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
                dbg_line(|| "flutter route = libapp.so ELF (AOT snapshot)".to_owned());
                output.flutter = Some(parse_libapp_so(bytes)?);
                let structure: DartSnapshotStructure = decompile_libapp_so_structured(bytes)?;
                dbg_kv("flutter.functions", || {
                    structure.functions.len().to_string()
                });
                output.flutter_dart = Some(structure);
                let recovery: DartLibAppRecovery = decompile_libapp_so_recovery(bytes)?;
                dbg_kv("flutter.cid_match", || {
                    format!("{:?}", recovery.cid_table_match)
                });
                output.flutter_libapp_recovery = Some(recovery);
                let disasm: Arm64Disassembly = disassemble_libapp_so(bytes)?;
                output.flutter_arm64_disasm = Some(disasm);
                let aot_lift: AotLiftReport = lift_libapp_aot(bytes)?;
                dbg_kv("flutter.aot_static_edges", || {
                    aot_lift.named_static_call_edges.to_string()
                });
                output.flutter_aot_lift = Some(aot_lift);
            } else {
                dbg_line(|| "flutter route = apk container (extract libapp.so)".to_owned());
                let apk: crate::flutter::FlutterApkLayout = parse_flutter_apk(bytes)?;
                output.flutter = Some(apk.layout);
            }
        }
        DetectedKind::FlutterDartKernel => {
            let kernel: crate::flutter::DartKernel = parse_kernel(bytes)?;
            dbg_kv("kernel.format_version", || {
                kernel.format_version.to_string()
            });
            dbg_kv("kernel.libraries", || kernel.libraries.len().to_string());
            dbg_kv("kernel.bodies_recovered", || {
                kernel.bodies_recovered.to_string()
            });
            output.flutter_kernel = Some(kernel);
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
                return Err(crate::error::Error::Unrecognized);
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
                WebviewBundleKind::Unknown => return Err(crate::error::Error::Unrecognized),
            };
            output.cordova = Some(web);
        }
        DetectedKind::NativeScriptApk => {
            output.nativescript = Some(extract_nativescript_bundle(bytes)?);
        }
        DetectedKind::AndroidDexApk => {
            let dex_children: Vec<(String, Vec<u8>)> = extract_android_dex_children(bytes)?;
            if dex_children.is_empty() {
                return Err(crate::error::Error::Unrecognized);
            }
            let dex_entries: Vec<AndroidDexEntry> = dex_children
                .into_iter()
                .map(|(name, data): (String, Vec<u8>)| AndroidDexEntry {
                    name,
                    size: data.len() as u64,
                })
                .collect();
            output.android_dex = Some(AndroidDexReport { dex_entries });
        }
        DetectedKind::AndroidBundle => {
            let format: BundleFormat =
                detect_bundle_format(bytes).ok_or(crate::error::Error::Unrecognized)?;
            let children: Vec<(String, Vec<u8>)> = extract_android_bundle_children(bytes)?;
            if children.is_empty() {
                return Err(crate::error::Error::Unrecognized);
            }
            let (apks, dex_entries): (Vec<AndroidDexEntry>, Vec<AndroidDexEntry>) = children
                .iter()
                .map(|(name, data): &(String, Vec<u8>)| AndroidDexEntry {
                    name: name.clone(),
                    size: data.len() as u64,
                })
                .partition(|entry: &AndroidDexEntry| entry.name.ends_with(".apk"));
            output.android_bundle = Some(AndroidBundleReport {
                format,
                apks,
                dex_entries,
            });
        }
        DetectedKind::Unknown => {
            dbg_line(|| "wall: input matched no mobile container or bytecode signature".to_owned());
            return Err(crate::error::Error::Unrecognized);
        }
    }
    Ok(output)
}

pub fn extract_android_dex_children(bytes: &[u8]) -> crate::error::Result<Vec<(String, Vec<u8>)>> {
    use std::io::Cursor;

    use zip::ZipArchive;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut entries: Vec<(usize, String, u64, bool)> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        if let Ok(file) = archive.by_index(i) {
            let name: String = file.name().to_owned();
            let is_top_level_dex: bool = is_top_level_dex_name(name.as_str());
            entries.push((i, name, file.size(), is_top_level_dex));
        }
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for (index, name, size, is_top_level_dex) in entries {
        if is_top_level_dex {
            let file: zip::read::ZipFile<'_> = archive.by_index(index)?;
            let buf: Vec<u8> = crate::read_zip_file_bounded(file, &name)?;
            out.push((name, buf));
            continue;
        }
        if size <= MAX_PROTECTOR_CARVE_SCAN
            && let Ok(file) = archive.by_index(index)
            && let Ok(raw) = crate::read_zip_file_bounded(file, &name)
        {
            for carve in find_embedded_dex_carves(&name, &raw) {
                let bytes: Vec<u8> = materialize_embedded_dex(&raw, &carve);
                let path: String = carve.container_path;
                out.push((path, bytes));
            }
        }
    }
    out.sort_by(|a: &(String, Vec<u8>), b: &(String, Vec<u8>)| a.0.cmp(&b.0));
    Ok(out)
}

#[must_use]
pub fn detect_kind(bytes: &[u8]) -> DetectedKind {
    if bytes.len() >= 8 && bytes[..8] == crate::hermes::HERMES_MAGIC_LE_BYTES {
        return DetectedKind::HermesRawBytecode;
    }
    if is_dart_kernel(bytes) {
        return DetectedKind::FlutterDartKernel;
    }
    if bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'] {
        return if crate::flutter::has_dart_aot_snapshot(bytes) {
            DetectedKind::FlutterLibAppSo
        } else {
            DetectedKind::Unknown
        };
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
    let entry_count: usize = crate::capped_zip_entry_count(archive.len());
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

    if bundle_format_from_names(names).is_some() {
        return DetectedKind::AndroidBundle;
    }

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
    let android_dex: bool = has("AndroidManifest.xml")
        && names
            .iter()
            .any(|n: &String| is_top_level_dex_name(n.as_str()));
    if android_dex {
        return DetectedKind::AndroidDexApk;
    }
    DetectedKind::Unknown
}

#[must_use]
pub fn is_top_level_dex_name(name: &str) -> bool {
    !name.contains('/')
        && name.starts_with("classes")
        && name.ends_with(".dex")
        && name["classes".len()..name.len() - ".dex".len()]
            .chars()
            .all(|c: char| c.is_ascii_digit())
}

fn is_top_level_apk_name(name: &str) -> bool {
    !name.contains('/') && name.ends_with(".apk")
}

fn is_aab_module_dex_name(name: &str) -> bool {
    let mut parts: std::str::Split<'_, char> = name.split('/');
    let (Some(_module), Some(dir), Some(file), None): (
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
    ) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    dir == "dex" && file.ends_with(".dex")
}

fn bundle_format_from_names(names: &[String]) -> Option<BundleFormat> {
    let has = |needle: &str| -> bool { names.iter().any(|n: &String| n == needle) };
    let has_base_apk: bool = has("base.apk");
    let aab_layout: bool = has("BundleConfig.pb")
        && names
            .iter()
            .any(|n: &String| n == "base/manifest/AndroidManifest.xml");
    if aab_layout {
        return Some(BundleFormat::Aab);
    }
    if !has_base_apk {
        return None;
    }
    let has_xapk_meta: bool = names
        .iter()
        .any(|n: &String| n == "info.json" || n == "manifest.json");
    if has_xapk_meta {
        Some(BundleFormat::Xapk)
    } else {
        Some(BundleFormat::Apkm)
    }
}

#[must_use]
pub fn detect_bundle_format(bytes: &[u8]) -> Option<BundleFormat> {
    use std::io::Cursor;

    use zip::ZipArchive;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor).ok()?;
    let entry_count: usize = crate::capped_zip_entry_count(archive.len());
    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        if let Ok(file) = archive.by_index(i) {
            names.push(file.name().to_owned());
        }
    }
    bundle_format_from_names(&names)
}

pub fn extract_android_bundle_children(
    bytes: &[u8],
) -> crate::error::Result<Vec<(String, Vec<u8>)>> {
    use std::io::Cursor;

    use zip::ZipArchive;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        if let Ok(file) = archive.by_index(i) {
            let name: String = file.name().to_owned();
            if is_top_level_apk_name(&name) || is_aab_module_dex_name(&name) {
                names.push(name);
            }
        }
    }
    names.sort_unstable();
    let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(names.len());
    for name in names {
        let file: zip::read::ZipFile<'_> = archive.by_name(name.as_str())?;
        let buf: Vec<u8> = crate::read_zip_file_bounded(file, &name)?;
        out.push((name, buf));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_hermes_kind() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&crate::hermes::HERMES_MAGIC_LE_BYTES);
        bytes.extend_from_slice(&[0u8; 128]);
        assert_eq!(detect_kind(&bytes), DetectedKind::HermesRawBytecode);
    }

    #[test]
    fn a_bare_elf_is_not_a_flutter_snapshot() {
        let bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        assert_eq!(
            detect_kind(&bytes),
            DetectedKind::Unknown,
            "elf magic alone says nothing about Dart; claiming Flutter here reports every linux \
             binary as a Flutter app"
        );
    }

    #[test]
    fn an_elf_without_a_dart_snapshot_is_not_a_flutter_snapshot() {
        let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        bytes.extend_from_slice(&[0u8; 512]);
        assert_eq!(detect_kind(&bytes), DetectedKind::Unknown);
    }

    #[test]
    fn detect_dart_kernel_kind() {
        let bytes: Vec<u8> = vec![0x90, 0xab, 0xcd, 0xef, 0, 0, 0, 130];
        assert_eq!(detect_kind(&bytes), DetectedKind::FlutterDartKernel);
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
    fn zip_entry_count_cap_clamps_directory_counts() {
        assert_eq!(crate::capped_zip_entry_count(17), 17);
        assert_eq!(
            crate::capped_zip_entry_count(crate::ZIP_ENTRY_COUNT_CAP + 1),
            crate::ZIP_ENTRY_COUNT_CAP
        );
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
    fn classify_plain_dex_apk_is_android_dex() {
        let n: Vec<String> = names(&["AndroidManifest.xml", "classes.dex"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::AndroidDexApk);
    }

    #[test]
    fn classify_multidex_apk_is_android_dex() {
        let n: Vec<String> = names(&[
            "AndroidManifest.xml",
            "classes.dex",
            "classes2.dex",
            "resources.arsc",
        ]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::AndroidDexApk);
    }

    #[test]
    fn classify_manifestless_zip_is_unknown() {
        let n: Vec<String> = names(&["classes.dex", "lib/x.so"]);
        assert_eq!(classify_apk_entry_names(&n), DetectedKind::Unknown);
    }

    #[test]
    fn top_level_dex_name_predicate() {
        assert!(is_top_level_dex_name("classes.dex"));
        assert!(is_top_level_dex_name("classes2.dex"));
        assert!(is_top_level_dex_name("classes10.dex"));
        assert!(!is_top_level_dex_name("assets/classes.dex"));
        assert!(!is_top_level_dex_name("classesx.dex"));
        assert!(!is_top_level_dex_name("classes.dex.bak"));
        assert!(!is_top_level_dex_name("notclasses.dex"));
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

    fn forge_central_dir_uncompressed_size(zip_bytes: &mut [u8], entry_name: &str, forged: u32) {
        const CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
        let name: &[u8] = entry_name.as_bytes();
        let mut i: usize = 0;
        while i + 46 <= zip_bytes.len() {
            if zip_bytes[i..i + 4] == CENTRAL_DIR_SIG {
                let name_len: usize =
                    u16::from_le_bytes([zip_bytes[i + 28], zip_bytes[i + 29]]) as usize;
                let name_start: usize = i + 46;
                let name_end: usize = name_start + name_len;
                if name_end <= zip_bytes.len() && &zip_bytes[name_start..name_end] == name {
                    zip_bytes[i + 24..i + 28].copy_from_slice(&forged.to_le_bytes());
                    return;
                }
            }
            i += 1;
        }
        panic!("central-directory header for {entry_name} not found");
    }

    #[test]
    fn dex_extraction_rejects_forged_uncompressed_size() {
        use std::io::{Cursor, Write};

        use zip::ZipWriter;
        use zip::write::SimpleFileOptions;

        let payload: Vec<u8> = b"dex0".iter().copied().cycle().take(4096).collect();
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zw.start_file::<&str, ()>("AndroidManifest.xml", opts)
                .expect("start manifest");
            zw.write_all(b"<manifest/>").expect("write manifest");
            zw.start_file::<&str, ()>("classes.dex", opts)
                .expect("start dex");
            zw.write_all(&payload).expect("write dex");
            zw.finish().expect("finish");
        }
        forge_central_dir_uncompressed_size(&mut buf, "classes.dex", 0xffff_ffff);

        let err: crate::error::Error =
            extract_android_dex_children(&buf).expect_err("forged size must reject");
        let message: String = match err {
            crate::error::Error::Zip(message) => message,
            other => panic!("unexpected error {other}"),
        };
        assert!(message.contains("declared size"));
        assert!(message.contains("decompression cap"));
    }

    #[test]
    fn run_inner_rejects_unrecognized_input() {
        let bytes: Vec<u8> = vec![0u8; 32];
        let err: crate::error::Error = run_inner(&bytes).expect_err("must fail");
        assert!(matches!(err, crate::error::Error::Unrecognized));
    }
}
