#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::error::Error as PassError;
use disrobe_pass_swift_objc::ipa::{self, IpaExtract, IpaInventory};
use disrobe_pass_swift_objc::macho::{
    self, Bitness, CpuKind, FatArchEntry, MachoKind, ParsedSlice,
};
use disrobe_pass_swift_objc::objc::{self as objc_dump, ObjcClassDump};
use disrobe_pass_swift_objc::plist_decode::{self, InfoPlistSummary};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump, looks_like_swift_mangled};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root.join("corpus").join("mobile").join("ipa")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(name);
    fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("missing fixture {}: {e}", path.display()))
}

fn assert_full_ipa_cycle(ipa_name: &str, expected_bundle: &str) {
    let bytes: Vec<u8> = read_fixture(ipa_name);
    let inventory: IpaInventory = ipa::inventory(&bytes)
        .unwrap_or_else(|e: PassError| panic!("inventory({ipa_name}) failed: {e}"));
    assert_eq!(
        inventory.app_dir,
        format!("Payload/{expected_bundle}.app"),
        "{ipa_name} app_dir"
    );
    assert_eq!(
        inventory.bundle_name, expected_bundle,
        "{ipa_name} bundle_name"
    );
    assert_eq!(
        inventory.info_plist_path.as_deref(),
        Some(format!("Payload/{expected_bundle}.app/Info.plist").as_str()),
        "{ipa_name} Info.plist path"
    );
    assert_eq!(
        inventory.main_binary_path.as_deref(),
        Some(format!("Payload/{expected_bundle}.app/{expected_bundle}").as_str()),
        "{ipa_name} main binary path"
    );
    assert!(
        !inventory.entries.is_empty(),
        "{ipa_name} produced zero zip entries"
    );

    let extracted: IpaExtract = ipa::extract(&bytes)
        .unwrap_or_else(|e: PassError| panic!("extract({ipa_name}) failed: {e}"));
    let info: &[u8] = extracted
        .info_plist
        .as_deref()
        .unwrap_or_else(|| panic!("{ipa_name} missing Info.plist bytes"));
    assert!(
        !info.is_empty(),
        "{ipa_name} Info.plist extracted but empty"
    );
    let main: &[u8] = extracted
        .main_binary
        .as_deref()
        .unwrap_or_else(|| panic!("{ipa_name} missing main binary bytes"));
    assert!(
        main.len() > 1024,
        "{ipa_name} main binary suspiciously small ({} bytes)",
        main.len()
    );
    let head: [u8; 4] = [main[0], main[1], main[2], main[3]];
    let be: u32 = u32::from_be_bytes(head);
    let le: u32 = u32::from_le_bytes(head);
    let is_macho: bool = matches!(be, 0xCAFE_BABE | 0xCAFE_BABF | 0xFEED_FACE | 0xFEED_FACF)
        || matches!(le, 0xFEED_FACE | 0xFEED_FACF);
    assert!(
        is_macho,
        "{ipa_name} main binary first 4 bytes {head:?} not a Mach-O / FAT magic"
    );
}

#[test]
fn real_ipa_feather_inventory_and_extract_full_cycle() {
    assert_full_ipa_cycle("Feather-2.8.2.ipa", "Feather");
}

#[test]
fn real_ipa_onion_browser_inventory_and_extract_full_cycle() {
    assert_full_ipa_cycle("OnionBrowser-3.3.8.ipa", "OnionBrowser");
}

#[test]
fn real_ipa_ppsspp_inventory_and_extract_full_cycle() {
    assert_full_ipa_cycle("PPSSPP-v1.20.4.ipa", "PPSSPP");
}

#[test]
fn real_ipa_onion_browser_lists_frameworks_or_plugins() {
    let bytes: Vec<u8> = read_fixture("OnionBrowser-3.3.8.ipa");
    let inventory: IpaInventory = ipa::inventory(&bytes).expect("onion inventory");
    let combined: usize = inventory.frameworks.len() + inventory.plugins.len();
    assert!(
        combined > 0,
        "OnionBrowser should contain at least one framework or plugin entry, got 0"
    );
}

fn pick_arm64_slice(bytes: &[u8]) -> ParsedSlice {
    let detected: Option<MachoKind> = macho::detect_magic(bytes);
    match detected {
        Some(MachoKind::Fat32 | MachoKind::Fat64) => {
            let entries: Vec<FatArchEntry> =
                macho::walk_fat(bytes).expect("walk_fat on FAT main binary");
            assert!(!entries.is_empty(), "FAT main binary has zero arches");
            let chosen: &FatArchEntry = entries
                .iter()
                .find(|e: &&FatArchEntry| {
                    matches!(
                        e.cpu,
                        CpuKind::Arm64 | CpuKind::Arm64_32 | CpuKind::Unknown(0x0100_000C),
                    )
                })
                .or_else(|| {
                    entries
                        .iter()
                        .find(|e: &&FatArchEntry| matches!(e.cpu, CpuKind::X86_64))
                })
                .unwrap_or_else(|| {
                    entries
                        .first()
                        .expect("FAT entries non-empty by earlier assert")
                });
            let inner: &[u8] =
                macho::slice_bytes(bytes, chosen).expect("slice_bytes on chosen FAT arch");
            macho::parse_slice(inner).expect("parse_slice inner")
        }
        Some(MachoKind::Slice64Be | MachoKind::Slice64Le) => {
            macho::parse_slice(bytes).expect("parse_slice thin 64")
        }
        Some(MachoKind::Slice32Be | MachoKind::Slice32Le) => {
            macho::parse_slice(bytes).expect("parse_slice thin 32")
        }
        other => panic!("main binary has unexpected magic kind {other:?}"),
    }
}

fn pick_arm64_slice_bytes(bytes: &[u8]) -> &[u8] {
    let detected: Option<MachoKind> = macho::detect_magic(bytes);
    match detected {
        Some(MachoKind::Fat32 | MachoKind::Fat64) => {
            let entries: Vec<FatArchEntry> =
                macho::walk_fat(bytes).expect("walk_fat on FAT main binary");
            let chosen: &FatArchEntry = entries
                .iter()
                .find(|e: &&FatArchEntry| {
                    matches!(
                        e.cpu,
                        CpuKind::Arm64 | CpuKind::Arm64_32 | CpuKind::Unknown(0x0100_000C),
                    )
                })
                .or_else(|| {
                    entries
                        .iter()
                        .find(|e: &&FatArchEntry| matches!(e.cpu, CpuKind::X86_64))
                })
                .unwrap_or_else(|| entries.first().expect("FAT entries non-empty"));
            macho::slice_bytes(bytes, chosen).expect("slice_bytes")
        }
        _ => bytes,
    }
}

fn full_pipeline_for(ipa_name: &str, expected_bundle: &str) {
    let bytes: Vec<u8> = read_fixture(ipa_name);
    let extracted: IpaExtract =
        ipa::extract(&bytes).unwrap_or_else(|e: PassError| panic!("extract({ipa_name}): {e}"));

    let info_bytes: &[u8] = extracted
        .info_plist
        .as_deref()
        .unwrap_or_else(|| panic!("{ipa_name} missing Info.plist"));
    let info: InfoPlistSummary = plist_decode::parse_info_plist(info_bytes)
        .unwrap_or_else(|e: PassError| panic!("parse_info_plist({ipa_name}): {e}"));
    assert!(
        info.bundle_identifier.is_some()
            || info.bundle_name.is_some()
            || info.bundle_executable.is_some(),
        "{ipa_name} Info.plist has no recognizable bundle keys (got {} raw keys)",
        info.raw_keys.len()
    );
    assert!(
        !info.raw_keys.is_empty(),
        "{ipa_name} Info.plist raw_keys empty"
    );
    let expected_exec: &str = expected_bundle;
    if let Some(exec) = info.bundle_executable.as_deref() {
        assert_eq!(exec, expected_exec, "{ipa_name} CFBundleExecutable");
    }

    let main_bytes: &[u8] = extracted
        .main_binary
        .as_deref()
        .unwrap_or_else(|| panic!("{ipa_name} missing main binary"));
    let slice_bytes: &[u8] = pick_arm64_slice_bytes(main_bytes);
    let parsed: ParsedSlice = pick_arm64_slice(main_bytes);
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    let has_text: bool = parsed
        .segments
        .iter()
        .any(|s: &macho::Segment| s.name == "__TEXT");
    assert!(has_text, "{ipa_name} chosen slice missing __TEXT");

    let objc_dump: ObjcClassDump = objc_dump::class_dump(slice_bytes, &parsed);
    let swift_dump: SwiftClassDump = swift::class_dump(slice_bytes, &parsed);
    let objc_signal: bool = objc_dump.classlist.is_some()
        || objc_dump.protolist.is_some()
        || objc_dump.selectors.is_some()
        || objc_dump.class_names.is_some();
    let swift_signal: bool = swift_dump.types_section.is_some()
        || swift_dump.protos_section.is_some()
        || swift_dump.fieldmd_section.is_some()
        || swift_dump.reflection_strings.is_some();
    assert!(
        objc_signal || swift_signal,
        "{ipa_name} main binary exposed neither objc nor swift reflection sections"
    );

    let reflstr_concat: String = swift_dump
        .reflection_strings
        .as_ref()
        .map(|r: &swift::SwiftReflectionStrings| r.strings.join("\n"))
        .unwrap_or_default();
    if !swift_dump.mangled_symbols.is_empty() {
        let mut demangled_count: usize = 0;
        for sym in &swift_dump.mangled_symbols {
            assert!(
                looks_like_swift_mangled(sym),
                "{ipa_name} mangled symbol {sym} fails prefix detector"
            );
            if swift::demangle(sym).is_ok() {
                demangled_count += 1;
            }
        }
        assert!(
            demangled_count > 0,
            "{ipa_name} produced {} mangled symbols but none demangled",
            swift_dump.mangled_symbols.len()
        );
    } else if swift_signal {
        assert!(
            !reflstr_concat.is_empty(),
            "{ipa_name} swift signal present but reflstr empty"
        );
    }

    if let Some(selectors) = objc_dump.selectors.as_ref() {
        let total: usize = selectors.strings.len();
        let unique: usize = objc_dump.unique_selectors.len();
        assert!(
            unique > 0 && unique <= total,
            "{ipa_name} selector dedupe range invalid"
        );
    }
}

#[test]
fn real_ipa_feather_full_pipeline_plist_macho_objc_swift() {
    full_pipeline_for("Feather-2.8.2.ipa", "Feather");
}

#[test]
fn real_ipa_onion_browser_full_pipeline_plist_macho_objc_swift() {
    full_pipeline_for("OnionBrowser-3.3.8.ipa", "OnionBrowser");
}

#[test]
fn real_ipa_ppsspp_full_pipeline_plist_macho_objc_swift() {
    full_pipeline_for("PPSSPP-v1.20.4.ipa", "PPSSPP");
}

#[test]
fn real_ipa_feather_lists_frameworks_when_present() {
    let bytes: Vec<u8> = read_fixture("Feather-2.8.2.ipa");
    let inventory: IpaInventory = ipa::inventory(&bytes).expect("feather inventory");
    assert!(
        !inventory.entries.is_empty(),
        "Feather IPA inventory had zero entries"
    );
}

#[test]
fn real_ipa_ppsspp_main_binary_is_fat_or_thin_and_walks() {
    let bytes: Vec<u8> = read_fixture("PPSSPP-v1.20.4.ipa");
    let extracted: IpaExtract = ipa::extract(&bytes).expect("ppsspp extract");
    let main: &[u8] = extracted.main_binary.as_deref().expect("ppsspp main");
    let parsed: ParsedSlice = pick_arm64_slice(main);
    assert!(
        !parsed.segments.is_empty(),
        "PPSSPP slice produced zero segments"
    );
}
