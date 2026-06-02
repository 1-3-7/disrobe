#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;

use disrobe_binfmt::asar::{AsarEntry, AsarLayout};
use disrobe_binfmt::container::{ContainerKind, detect_container_with_hint};
use disrobe_binfmt::containers::nsis::detect_nsis;
use disrobe_pass_mobile::hermes::{
    DisassemblyReport, HERMES_MAGIC_LE_BYTES, HERMES_MAX_VERSION, HERMES_MIN_VERSION, HermesModule,
    JsLiftReport, disassemble, lift_to_js_surface, parse, parse_header,
};
use disrobe_pass_mobile::react_native::{
    RnBundleFormat, RnBundlePlatform, RnExtractionReport, extract_from_apk_or_ipa,
};

const ZIP_LOCAL_HEADER: [u8; 4] = [b'P', b'K', 0x03, 0x04];
const ZIP_EOCD: [u8; 4] = [b'P', b'K', 0x05, 0x06];
const PE_DOS_MAGIC: [u8; 2] = [b'M', b'Z'];
const SQUIRREL_MARKER: &[u8] = b"Squirrel";
const UPDATE_EXE_MARKER: &[u8] = b"Update.exe";
const NUPKG_MARKER: &[u8] = b".nupkg";

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn read_fixture(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus(rel);
    if !path.exists() {
        eprintln!("SKIP fixture missing: {path:?}");
        return None;
    }
    std::fs::read(&path).ok()
}

fn first_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let last: usize = haystack.len() - needle.len();
    let mut i: usize = 0;
    while i <= last {
        if haystack[i..i + needle.len()] == *needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[test]
fn electron_installer_is_pe_and_squirrel_packaged() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("electron/discord/DiscordSetup.exe") else {
        return;
    };
    assert!(
        bytes.len() > 10_000_000,
        "Discord installer must be a real multi-MB binary, got {} bytes",
        bytes.len()
    );
    assert_eq!(
        bytes[..2],
        PE_DOS_MAGIC,
        "installer head must be PE DOS MZ magic, got {:?}",
        &bytes[..2]
    );
    let squirrel_off: usize =
        first_occurrence(&bytes, SQUIRREL_MARKER).expect("Squirrel signature must be present");
    let update_off: usize = first_occurrence(&bytes, UPDATE_EXE_MARKER)
        .expect("Squirrel installers embed Update.exe marker");
    assert!(
        squirrel_off < update_off,
        "Squirrel marker must precede Update.exe marker, got {squirrel_off} vs {update_off}"
    );
    assert!(
        detect_nsis(&bytes).is_none(),
        "Discord uses Squirrel.Windows, not NSIS - detect_nsis must NOT match"
    );
    let zip_off: usize = first_occurrence(&bytes, &ZIP_LOCAL_HEADER)
        .expect("Squirrel installers embed a ZIP carrying the nupkg + Update.exe");
    let eocd_off: usize = first_occurrence(&bytes, &ZIP_EOCD)
        .expect("Squirrel ZIP must terminate with PK\\x05\\x06 EOCD record");
    assert!(
        zip_off < eocd_off,
        "ZIP local header at {zip_off} must precede EOCD at {eocd_off}"
    );
    let nupkg_off: usize = first_occurrence(&bytes, NUPKG_MARKER)
        .expect("Squirrel package payload references the .nupkg file inside the ZIP");
    assert!(
        nupkg_off > zip_off && nupkg_off < eocd_off,
        ".nupkg reference at {nupkg_off} must lie inside the embedded ZIP central directory"
    );
    let container_kind: Option<ContainerKind> =
        detect_container_with_hint(&bytes, Some(std::path::Path::new("DiscordSetup.exe")));
    match container_kind {
        Some(ContainerKind::Zip) | None => {}
        other => panic!("unexpected container classification for PE+ZIP: {other:?}"),
    }
    println!(
        "electron-installer: PE+Squirrel verified ({} bytes, ZIP at {zip_off}, EOCD at {eocd_off}, nupkg ref at {nupkg_off})",
        bytes.len()
    );
}

#[test]
fn electron_nsis_baseline_extractor_still_classifies_real_nsis() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("binfmt/nsis/hello.exe") else {
        return;
    };
    let header: disrobe_binfmt::containers::nsis::NsisHeader =
        detect_nsis(&bytes).expect("disrobe-binfmt::nsis must classify a true NSIS installer");
    assert!(
        header.archive_size > 0,
        "NSIS firstheader must declare a non-empty archive"
    );
    println!(
        "nsis-baseline: NullsoftInst detected at offset {} archive_size={} header_size={}",
        header.offset, header.archive_size, header.header_size
    );
}

#[test]
fn electron_asar_parser_roundtrip_proves_app_asar_extraction() {
    let asar_bytes: Vec<u8> = synth_asar(&[
        (
            "index.js",
            b"module.exports = function main() { console.log('hello, electron'); };",
        ),
        (
            "package.json",
            br#"{"name":"demo-electron-app","version":"1.0.0","main":"index.js"}"#,
        ),
    ]);
    let layout: AsarLayout =
        disrobe_binfmt::asar::parse(&asar_bytes).expect("synthesized asar must parse");
    assert_eq!(
        layout.entries.len(),
        2,
        "asar layout must enumerate both files"
    );
    let entry_names: Vec<&str> = layout
        .entries
        .iter()
        .map(|e: &AsarEntry| e.path.as_str())
        .collect();
    assert!(entry_names.contains(&"index.js"));
    assert!(entry_names.contains(&"package.json"));
    let index_entry: &AsarEntry = layout
        .entries
        .iter()
        .find(|e: &&AsarEntry| e.path == "index.js")
        .expect("index.js present");
    let index_bytes: &[u8] =
        disrobe_binfmt::asar::read_entry(&asar_bytes, &layout, index_entry).expect("read index.js");
    let index_text: &str = core::str::from_utf8(index_bytes).expect("index.js is UTF-8");
    assert!(
        index_text.contains("module.exports") && index_text.contains("hello, electron"),
        "asar parser must return JavaScript byte-for-byte: {index_text}"
    );
    let asar_kind: Option<ContainerKind> = detect_container_with_hint(&asar_bytes, None);
    assert_eq!(
        asar_kind,
        Some(ContainerKind::Asar),
        "container sniffer must classify the asar magic shape"
    );
    println!(
        "electron-asar: parsed {} entries, recovered index.js ({} bytes)",
        layout.entries.len(),
        index_bytes.len()
    );
}

#[test]
fn hermes_bundle_from_discord_apk_extracts_via_react_native_pipeline() {
    let Some(apk_bytes): Option<Vec<u8>> =
        read_fixture("mobile/apk/inbox/_unpack_discord/base.apk")
    else {
        return;
    };
    let report: RnExtractionReport =
        extract_from_apk_or_ipa(&apk_bytes).expect("Discord base.apk must yield an RN bundle");
    assert!(
        report.manifest_entries_scanned > 0,
        "must have walked the APK ZIP entries"
    );
    let android_bundles: Vec<&disrobe_pass_mobile::react_native::RnBundleEntry> = report
        .bundles
        .iter()
        .filter(|b: &&disrobe_pass_mobile::react_native::RnBundleEntry| {
            b.platform == RnBundlePlatform::Android
        })
        .collect();
    assert!(
        !android_bundles.is_empty(),
        "Discord base.apk must contain at least one Android RN bundle"
    );
    let hermes_bundle: &disrobe_pass_mobile::react_native::RnBundleEntry = android_bundles
        .iter()
        .find(|b: &&&disrobe_pass_mobile::react_native::RnBundleEntry| {
            b.format == RnBundleFormat::HermesBytecode
        })
        .copied()
        .expect("Discord ships a Hermes-compiled JS bundle");
    assert!(
        hermes_bundle.bytes_len > 1_000_000,
        "Discord's Hermes bundle is multi-MB, got {} bytes",
        hermes_bundle.bytes_len
    );
    assert_eq!(
        hermes_bundle.bytes[..8],
        HERMES_MAGIC_LE_BYTES,
        "RN bundle bytes must start with the Hermes magic"
    );
    println!(
        "hermes-from-apk: extracted {} bytes from {} ({} platform)",
        hermes_bundle.bytes_len,
        hermes_bundle.container_path,
        format_platform(hermes_bundle.platform)
    );
}

#[test]
fn hermes_bytecode_disassembles_to_js_surface() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("mobile/hermes/discord/index.android.bundle")
    else {
        return;
    };
    assert_eq!(
        bytes[..8],
        HERMES_MAGIC_LE_BYTES,
        "fixture must begin with Hermes magic"
    );
    let header: disrobe_pass_mobile::HermesHeader =
        parse_header(&bytes).expect("Hermes header must parse");
    assert!(
        header.version >= HERMES_MIN_VERSION && header.version <= HERMES_MAX_VERSION,
        "Hermes version {} must fall in supported range {}..={}",
        header.version,
        HERMES_MIN_VERSION,
        HERMES_MAX_VERSION
    );
    assert!(
        header.function_count > 1_000,
        "Discord ships tens of thousands of Hermes functions, got {}",
        header.function_count
    );
    let module: HermesModule = parse(&bytes).expect("Hermes module must parse end-to-end");
    assert_eq!(module.header.version, header.version);
    assert_eq!(module.functions.len(), header.function_count as usize);
    assert!(
        !module.identifiers.is_empty(),
        "Hermes module must surface identifier names"
    );
    assert!(
        !module.strings.is_empty(),
        "Hermes module must surface string literals"
    );
    let disasm: DisassemblyReport = disassemble(&module);
    assert_eq!(disasm.function_count, module.functions.len());
    assert!(
        disasm.functions.iter().any(|f| !f.function_name.is_empty()),
        "disasm must surface named functions"
    );
    let lift: JsLiftReport = lift_to_js_surface(&module);
    assert!(
        !lift.function_surface.is_empty(),
        "lift_to_js_surface must produce at least one function declaration"
    );
    let first_surface: &str = lift
        .function_surface
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        first_surface.starts_with("function "),
        "lifted surface must look like JavaScript, got {first_surface:?}"
    );
    println!(
        "hermes-disasm: version={} functions={} identifiers={} strings={} lifted={} surface[0]={first_surface}",
        module.header.version,
        module.functions.len(),
        module.identifiers.len(),
        module.strings.len(),
        lift.function_surface.len()
    );
}

#[test]
fn discord_apk_is_zip_container_classified_by_binfmt() {
    let Some(apk_bytes): Option<Vec<u8>> =
        read_fixture("mobile/apk/inbox/_unpack_discord/base.apk")
    else {
        return;
    };
    assert_eq!(
        apk_bytes[..4],
        ZIP_LOCAL_HEADER,
        "Discord base.apk must start with a ZIP local-file-header"
    );
    let detected: Option<ContainerKind> =
        detect_container_with_hint(&apk_bytes, Some(std::path::Path::new("base.apk")));
    assert_eq!(
        detected,
        Some(ContainerKind::Apk),
        "binfmt container sniffer must promote zip+apk-extension to ContainerKind::Apk"
    );
}

#[test]
fn discord_apkm_unpack_yields_base_apk_via_zip() {
    let Some(apkm_bytes): Option<Vec<u8>> = read_fixture("mobile/apk/inbox/discord.apkm") else {
        return;
    };
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(&apkm_bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("apkm is a zip");
    let mut found_base: bool = false;
    let mut found_split: bool = false;
    let len: usize = archive.len();
    for i in 0..len {
        let entry: zip::read::ZipFile<'_> = archive.by_index(i).expect("zip entry");
        let name: &str = entry.name();
        if name == "base.apk" {
            found_base = true;
        }
        if name.starts_with("split_config.") {
            found_split = true;
        }
    }
    assert!(found_base, "apkm must contain base.apk");
    assert!(
        found_split,
        "apkm must contain at least one split_config.*.apk"
    );
    println!("apkm-unpack: zip with {len} members including base.apk + split_configs");
}

const fn format_platform(p: RnBundlePlatform) -> &'static str {
    match p {
        RnBundlePlatform::Android => "android",
        RnBundlePlatform::Ios => "ios",
        RnBundlePlatform::Unknown => "unknown",
    }
}

fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::fmt::Write as _;
    const ALIGNMENT_PREFIX: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    let mut header: String = String::from(r#"{"files":{"#);
    let mut offset: u64 = 0;
    for (i, (name, body)) in files.iter().enumerate() {
        if i > 0 {
            header.push(',');
        }
        let size: usize = body.len();
        let _: core::fmt::Result =
            write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
        offset += body.len() as u64;
    }
    header.push_str("}}");
    let header_bytes: &[u8] = header.as_bytes();
    let header_size: u32 = u32::try_from(header_bytes.len()).expect("header size fits u32");
    let aligned_size: usize = (header_bytes.len() + 3) & !3;
    let aligned: u32 = u32::try_from(aligned_size).expect("aligned size fits u32");
    let pickle_size: u32 = 8 + aligned;
    let payload_total: usize = usize::try_from(offset).expect("payload total fits usize");
    let mut out: Vec<u8> = Vec::with_capacity(16 + aligned_size + payload_total);
    out.extend_from_slice(&ALIGNMENT_PREFIX);
    out.extend_from_slice(&pickle_size.to_le_bytes());
    out.extend_from_slice(&ALIGNMENT_PREFIX);
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(header_bytes);
    let padding: usize = (aligned - header_size) as usize;
    out.extend(std::iter::repeat_n(0u8, padding));
    for (_, body) in files {
        out.extend_from_slice(body);
    }
    out
}
