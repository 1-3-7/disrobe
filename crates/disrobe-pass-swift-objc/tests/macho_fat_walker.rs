#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use disrobe_pass_swift_objc::macho::{
    self, Bitness, CpuKind, FatArchEntry, MachoKind, ParsedSlice,
};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_fat_macho, build_macho64_slice,
    build_swift_reflstr_payload,
};

fn tiny_slice() -> Vec<u8> {
    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![MachoSectionSpec {
                sect_name: "__swift5_reflstr",
                seg_name: "__TEXT",
                data: build_swift_reflstr_payload(&["$s5Hello5WorldC"]),
            }],
        }],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn fat_header_detected_and_walked() {
    let slice: Vec<u8> = tiny_slice();
    let fat: Vec<u8> = build_fat_macho(&slice);
    let kind: Option<MachoKind> = macho::detect_magic(&fat);
    assert_eq!(kind, Some(MachoKind::Fat32));

    let entries: Vec<FatArchEntry> = macho::walk_fat(&fat).expect("walk fat");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cpu, CpuKind::Arm64);

    let inner: &[u8] = macho::slice_bytes(&fat, &entries[0]).expect("inner slice");
    let parsed: ParsedSlice = macho::parse_slice(inner).expect("parse slice");
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert!(!parsed.segments.is_empty());
}

#[test]
fn thin_slice_parses_to_64_bit_parsed_slice() {
    let slice: Vec<u8> = tiny_slice();
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse thin slice");
    assert!(matches!(parsed.header.bitness, Bitness::Bits64));
    assert_eq!(parsed.header.cpu, CpuKind::Arm64);
    assert_eq!(parsed.segments.len(), 1);
    let text: &macho::Segment = &parsed.segments[0];
    assert_eq!(text.name, "__TEXT");
    assert_eq!(text.sections.len(), 1);
    assert_eq!(text.sections[0].name, "__swift5_reflstr");
}

#[test]
fn unknown_bytes_are_not_macho() {
    assert!(macho::detect_magic(b"hello world\0not macho").is_none());
}
