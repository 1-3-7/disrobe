#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{
    self, Bitness, CpuKind, FatArchEntry, MachoKind, ParsedSlice,
};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(name);
    fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("missing fixture {}: {e}", path.display()))
}

fn assert_two_slice_fat(name: &str, min_arches: usize) {
    let bytes: Vec<u8> = read_fixture(name);
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Fat32 | MachoKind::Fat64)),
        "{name} should be FAT (got {kind:?})"
    );

    let entries: Vec<FatArchEntry> =
        macho::walk_fat(&bytes).unwrap_or_else(|e: disrobe_pass_swift_objc::error::Error| {
            panic!("walk_fat({name}) failed: {e}")
        });
    assert!(
        entries.len() >= min_arches,
        "{name} should expose >={min_arches} arches, got {}",
        entries.len()
    );

    let mut found_arm64_family: bool = false;
    let mut found_x86_64: bool = false;
    for (idx, entry) in entries.iter().enumerate() {
        assert!(entry.size > 0, "{name}[{idx}] empty slice");
        assert!(
            usize::try_from(entry.offset.saturating_add(entry.size)).unwrap_or(usize::MAX)
                <= bytes.len(),
            "{name}[{idx}] slice {}..{} overruns file len {}",
            entry.offset,
            entry.offset + entry.size,
            bytes.len()
        );
        let inner: &[u8] = macho::slice_bytes(&bytes, entry)
            .unwrap_or_else(|| panic!("{name}[{idx}] slice_bytes returned None"));
        let parsed: ParsedSlice =
            macho::parse_slice(inner).unwrap_or_else(|e: disrobe_pass_swift_objc::error::Error| {
                panic!("{name}[{idx}] parse_slice failed: {e}")
            });
        assert!(
            matches!(parsed.header.bitness, Bitness::Bits64),
            "{name}[{idx}] expected 64-bit slice"
        );
        assert!(
            !parsed.segments.is_empty(),
            "{name}[{idx}] expected at least one segment"
        );
        let has_text: bool = parsed
            .segments
            .iter()
            .any(|s: &macho::Segment| s.name == "__TEXT");
        assert!(has_text, "{name}[{idx}] missing __TEXT segment");
        if matches!(
            entry.cpu,
            CpuKind::Arm64 | CpuKind::Arm64_32 | CpuKind::Unknown(0x0100_000C)
        ) {
            found_arm64_family = true;
        } else if matches!(entry.cpu, CpuKind::X86_64) {
            found_x86_64 = true;
        }
    }
    assert!(
        found_arm64_family || found_x86_64,
        "{name} produced no recognized cputype across {} entries",
        entries.len()
    );
}

#[test]
fn real_macos_ls_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("ls", 2);
}

#[test]
fn real_macos_file_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("file", 3);
}

#[test]
fn real_macos_lipo_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("lipo", 2);
}

#[test]
fn real_macos_libffi_trampolines_dylib_walks_and_parses_all_slices() {
    assert_two_slice_fat("libffi-trampolines.dylib", 2);
}

#[test]
fn real_macos_grep_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("grep", 2);
}

#[test]
fn real_macos_otool_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("otool", 2);
}

#[test]
fn real_macos_dyld_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("dyld", 2);
}

#[test]
fn real_macos_swift_driver_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("swift-driver", 2);
}

#[test]
fn real_macos_python3_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("python3", 2);
}

#[test]
fn real_macos_awk_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("awk", 2);
}

#[test]
fn real_macos_sed_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("sed", 2);
}

#[test]
fn real_macos_codesign_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("codesign", 2);
}

#[test]
fn real_macos_sqlite3_three_slice_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat("sqlite3", 3);
    let bytes: Vec<u8> = read_fixture("sqlite3");
    let entries: Vec<FatArchEntry> = macho::walk_fat(&bytes).expect("walk sqlite3");
    assert_eq!(
        entries.len(),
        3,
        "sqlite3 expected to be a 3-arch FAT (x86_64 / x86_64h / arm64e), got {}",
        entries.len()
    );
}

#[test]
fn real_brew_ripgrep_thin_arm64_slice_parses() {
    let bytes: Vec<u8> = read_fixture("rg");
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "rg should be a thin 64-bit slice, got {kind:?}"
    );
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse rg");
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert!(!parsed.segments.is_empty(), "rg has zero segments");
}

#[test]
fn real_brew_fd_thin_arm64_slice_parses() {
    let bytes: Vec<u8> = read_fixture("fd");
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "fd should be a thin 64-bit slice, got {kind:?}"
    );
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse fd");
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert!(!parsed.segments.is_empty(), "fd has zero segments");
}

#[test]
fn real_brew_bat_thin_arm64_slice_parses() {
    let bytes: Vec<u8> = read_fixture("bat");
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "bat should be a thin 64-bit slice, got {kind:?}"
    );
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse bat");
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert!(!parsed.segments.is_empty(), "bat has zero segments");
}

#[test]
fn real_macos_file_fat_contains_x86_64_and_arm_variant() {
    let bytes: Vec<u8> = read_fixture("file");
    let entries: Vec<FatArchEntry> = macho::walk_fat(&bytes).expect("walk file");
    let mut saw_x86_64: bool = false;
    let mut saw_arm64_family: bool = false;
    for entry in &entries {
        if matches!(entry.cpu, CpuKind::X86_64) {
            saw_x86_64 = true;
        } else if matches!(
            entry.cpu,
            CpuKind::Arm64 | CpuKind::Arm64_32 | CpuKind::Unknown(0x0100_000C)
        ) {
            saw_arm64_family = true;
        }
    }
    assert!(saw_x86_64, "file FAT missing x86_64 slice");
    assert!(saw_arm64_family, "file FAT missing any arm64 slice");
}
