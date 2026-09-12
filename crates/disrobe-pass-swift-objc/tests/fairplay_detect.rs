#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::fairplay::{self, FairPlayStatus};
use disrobe_pass_swift_objc::macho::{self, ParsedSlice};

use crate::fixtures::{MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_macho64_slice};

fn slice_with_cryptid(crypt_id: u32) -> Vec<u8> {
    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![MachoSectionSpec {
                sect_name: "__text",
                seg_name: "__TEXT",
                data: vec![0u8; 16],
            }],
        }],
        encryption_id: crypt_id,
    };
    build_macho64_slice(&builder)
}

#[test]
fn cryptid_zero_means_unencrypted() {
    let slice: Vec<u8> = slice_with_cryptid(0);
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let status: FairPlayStatus = fairplay::detect(&parsed);
    assert!(status.has_encryption_info_lc);
    assert!(!status.is_encrypted);
    assert_eq!(status.crypt_id, 0);
}

#[test]
fn cryptid_one_means_fairplay_encrypted() {
    let slice: Vec<u8> = slice_with_cryptid(1);
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let status: FairPlayStatus = fairplay::detect(&parsed);
    assert!(status.has_encryption_info_lc);
    assert!(status.is_encrypted);
    assert_eq!(status.crypt_id, 1);
}
