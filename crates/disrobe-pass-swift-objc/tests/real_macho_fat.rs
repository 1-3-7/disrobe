#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{
    self, Bitness, CpuKind, FatArchEntry, MachoKind, ParsedSlice,
};

use macho_corpus::{CorpusFixture, homebrew_binary, macos_system_binary, read_host_sourced};

fn assert_two_slice_fat(fixture: CorpusFixture, min_arches: usize) {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
        return;
    };
    let name: String = fixture.relative();
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

const LS: CorpusFixture = macos_system_binary("ls");
const FILE: CorpusFixture = macos_system_binary("file");
const LIPO: CorpusFixture = macos_system_binary("lipo");
const LIBFFI_TRAMPOLINES: CorpusFixture = macos_system_binary("libffi-trampolines.dylib");
const GREP: CorpusFixture = macos_system_binary("grep");
const OTOOL: CorpusFixture = macos_system_binary("otool");
const DYLD: CorpusFixture = macos_system_binary("dyld");
const SWIFT_DRIVER_FAT: CorpusFixture = macos_system_binary("swift-driver");
const PYTHON3: CorpusFixture = macos_system_binary("python3");
const AWK: CorpusFixture = macos_system_binary("awk");
const SED: CorpusFixture = macos_system_binary("sed");
const CODESIGN: CorpusFixture = macos_system_binary("codesign");
const SQLITE3: CorpusFixture = macos_system_binary("sqlite3");
const RIPGREP: CorpusFixture = homebrew_binary("rg");
const FD: CorpusFixture = homebrew_binary("fd");
const BAT: CorpusFixture = homebrew_binary("bat");

fn assert_thin_arm64(fixture: CorpusFixture) {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
        return;
    };
    let name: String = fixture.relative();
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "{name} should be a thin 64-bit slice, got {kind:?}"
    );
    let parsed: ParsedSlice =
        macho::parse_slice(&bytes).unwrap_or_else(|e: disrobe_pass_swift_objc::error::Error| {
            panic!("parse_slice({name}) failed: {e}")
        });
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert!(!parsed.segments.is_empty(), "{name} has zero segments");
}

#[test]
fn real_macos_ls_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(LS, 2);
}

#[test]
fn real_macos_file_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(FILE, 3);
}

#[test]
fn real_macos_lipo_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(LIPO, 2);
}

#[test]
fn real_macos_libffi_trampolines_dylib_walks_and_parses_all_slices() {
    assert_two_slice_fat(LIBFFI_TRAMPOLINES, 2);
}

#[test]
fn real_macos_grep_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(GREP, 2);
}

#[test]
fn real_macos_otool_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(OTOOL, 2);
}

#[test]
fn real_macos_dyld_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(DYLD, 2);
}

#[test]
fn real_macos_swift_driver_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(SWIFT_DRIVER_FAT, 2);
}

#[test]
fn real_macos_python3_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(PYTHON3, 2);
}

#[test]
fn real_macos_awk_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(AWK, 2);
}

#[test]
fn real_macos_sed_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(SED, 2);
}

#[test]
fn real_macos_codesign_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(CODESIGN, 2);
}

#[test]
fn real_macos_sqlite3_three_slice_fat_walks_and_parses_all_slices() {
    assert_two_slice_fat(SQLITE3, 3);
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(SQLITE3) else {
        return;
    };
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
    assert_thin_arm64(RIPGREP);
}

#[test]
fn real_brew_fd_thin_arm64_slice_parses() {
    assert_thin_arm64(FD);
}

#[test]
fn real_brew_bat_thin_arm64_slice_parses() {
    assert_thin_arm64(BAT);
}

#[test]
fn real_macos_file_fat_contains_x86_64_and_arm_variant() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(FILE) else {
        return;
    };
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
