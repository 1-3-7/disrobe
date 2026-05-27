#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{
    self, Bitness, CpuKind, FatArchEntry, MachoKind, ParsedSlice,
};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root.join("corpus").join("mac").join("megafile")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(name);
    fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "missing fixture {}: {e}; regenerate via corpus/generate.sh (mac slice section)",
            path.display()
        )
    })
}

fn read_fixture_or_skip(name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_root().join(name);
    let bytes: Option<Vec<u8>> = fs::read(&path).ok();
    if bytes.is_none() {
        eprintln!(
            "FIXTURE PENDING: {} missing; regenerate via corpus/generate.sh",
            path.display()
        );
    }
    bytes
}

#[test]
fn edgecases_fat_walks_to_both_x86_64_and_arm64_slices() {
    let bytes: Vec<u8> = read_fixture("EdgeCases.fat");
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Fat32 | MachoKind::Fat64)),
        "EdgeCases.fat should be a FAT image, got {kind:?}"
    );
    let entries: Vec<FatArchEntry> = macho::walk_fat(&bytes).expect("walk fat");
    assert_eq!(
        entries.len(),
        2,
        "expected exactly 2 slices in EdgeCases.fat"
    );

    let mut saw_x86_64: bool = false;
    let mut saw_arm64: bool = false;
    for entry in &entries {
        match entry.cpu {
            CpuKind::X86_64 => saw_x86_64 = true,
            CpuKind::Arm64 | CpuKind::Arm64_32 => saw_arm64 = true,
            _ => {}
        }
        let inner: &[u8] = macho::slice_bytes(&bytes, entry).expect("inner slice bytes");
        let parsed: ParsedSlice = macho::parse_slice(inner).expect("parse inner slice");
        assert!(matches!(parsed.header.bitness, Bitness::Bits64));
        assert!(!parsed.segments.is_empty());
        let has_text: bool = parsed
            .segments
            .iter()
            .any(|s: &macho::Segment| s.name == "__TEXT");
        assert!(has_text, "slice missing __TEXT segment");
    }
    assert!(saw_x86_64, "EdgeCases.fat missing x86_64 slice");
    assert!(saw_arm64, "EdgeCases.fat missing arm64 slice");
}

#[test]
#[ignore = "FIXTURE PENDING: EdgeCases.arm64 is a thin Mach-O slice not redistributed in git; regenerate via corpus/generate.sh on a macOS host"]
fn edgecases_arm64_thin_slice_parses_and_exposes_swift_sections() {
    let Some(bytes): Option<Vec<u8>> = read_fixture_or_skip("EdgeCases.arm64") else {
        return;
    };
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "EdgeCases.arm64 should be a 64-bit thin slice, got {kind:?}"
    );
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse arm64");
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);
    assert!(
        dump.types_section.is_some()
            || dump.protos_section.is_some()
            || dump.fieldmd_section.is_some()
            || dump.reflection_strings.is_some(),
        "arm64 slice produced no swift5_* sections at all"
    );
}

#[test]
#[ignore = "FIXTURE PENDING: EdgeCases.x86_64 is a thin Mach-O slice not redistributed in git; regenerate via corpus/generate.sh on a macOS host"]
fn edgecases_x86_64_thin_slice_parses_and_exposes_swift_sections() {
    let Some(bytes): Option<Vec<u8>> = read_fixture_or_skip("EdgeCases.x86_64") else {
        return;
    };
    let kind: Option<MachoKind> = macho::detect_magic(&bytes);
    assert!(
        matches!(kind, Some(MachoKind::Slice64Le | MachoKind::Slice64Be)),
        "EdgeCases.x86_64 should be a 64-bit thin slice, got {kind:?}"
    );
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse x86_64");
    assert_eq!(parsed.header.cpu, CpuKind::X86_64);
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);
    assert!(
        dump.types_section.is_some()
            || dump.protos_section.is_some()
            || dump.fieldmd_section.is_some()
            || dump.reflection_strings.is_some(),
        "x86_64 slice produced no swift5_* sections at all"
    );
}

#[test]
fn edgecases_fat_swift_class_dump_on_arm64_slice_yields_reflection_data() {
    let bytes: Vec<u8> = read_fixture("EdgeCases.fat");
    let entries: Vec<FatArchEntry> = macho::walk_fat(&bytes).expect("walk fat");
    let arm64_entry: &FatArchEntry = entries
        .iter()
        .find(|e: &&FatArchEntry| matches!(e.cpu, CpuKind::Arm64 | CpuKind::Arm64_32))
        .expect("arm64 slice present in EdgeCases.fat");
    let inner: &[u8] = macho::slice_bytes(&bytes, arm64_entry).expect("slice bytes");
    let parsed: ParsedSlice = macho::parse_slice(inner).expect("parse arm64 slice");
    let dump: SwiftClassDump = swift::class_dump(inner, &parsed);
    let any_swift_section: bool = dump.types_section.is_some()
        || dump.protos_section.is_some()
        || dump.proto_conf_section.is_some()
        || dump.fieldmd_section.is_some()
        || dump.assocty_section.is_some()
        || dump.reflection_strings.is_some();
    assert!(
        any_swift_section,
        "arm64 slice of EdgeCases.fat produced no swift5_* sections"
    );
}
