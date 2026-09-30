#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use std::path::PathBuf;

use disrobe_core::chain::{DetectContext, Detector};
use disrobe_pass_native::chain_detector::{NativeImageDetector, PackerDetector};
use disrobe_pass_native::packers::{PeImage, PeSection, parse_pe_image};
use disrobe_pass_native::{Packer, PackerDetection, detect_packers};

const BENIGN_HOST: &str = "native/packers/aspack/AccessEnum.original.exe";
const UPX_PACKED: &str = "native/packers/upx/hello.packed.nrv2b.exe";

fn corpus(relative: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} is tracked in git and this grade needs it: {error}",
            path.display()
        )
    })
}

const fn ctx(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

fn packers_of(bytes: &[u8]) -> Vec<Packer> {
    detect_packers(bytes)
        .iter()
        .map(|d: &PackerDetection| d.packer)
        .collect()
}

fn rsrc_raw_range(host: &[u8]) -> (usize, usize) {
    let image: PeImage = parse_pe_image(host).expect("benign host parses as PE");
    let rsrc: &PeSection = image
        .section_by_name(b".rsrc")
        .expect("benign host carries a resource section");
    let start: usize = rsrc.raw_pointer as usize;
    (start, start + rsrc.raw_size as usize)
}

fn assert_left_to_image_classify(label: &str, bytes: &[u8]) {
    let packers: Vec<Packer> = packers_of(bytes);
    assert!(
        packers.is_empty(),
        "{label}: a packer literal outside the headers, section table, entry region and overlay \
         start is at most an indicator, yet detect_packers returned {packers:?}"
    );
    assert!(
        Detector::detect(&PackerDetector, &ctx(bytes)).is_none(),
        "{label}: native.packer-unpack must not claim a host whose only packer evidence is \
         embedded data"
    );
    assert!(
        Detector::detect(&NativeImageDetector, &ctx(bytes)).is_some(),
        "{label}: native.image-classify must still receive the host image"
    );
}

#[test]
fn the_controls_are_what_the_grade_assumes() {
    let host: Vec<u8> = corpus(BENIGN_HOST);
    assert!(
        packers_of(&host).is_empty(),
        "the benign host must carry no packer evidence of its own"
    );
    let upx: Vec<u8> = corpus(UPX_PACKED);
    assert!(
        detect_packers(&upx).iter().any(|d: &PackerDetection| {
            d.packer == Packer::Upx
                && d.confidence == disrobe_pass_native::packers::Confidence::High
        }),
        "the UPX sample itself must keep its High header verdict, or the negative cases below \
         prove nothing"
    );
}

#[test]
fn a_upx_blob_deep_in_the_overlay_is_not_a_upx_verdict() {
    let mut bytes: Vec<u8> = corpus(BENIGN_HOST);
    bytes.extend(std::iter::repeat_n(0x5A_u8, 0x1_0000));
    bytes.extend_from_slice(&corpus(UPX_PACKED));
    assert_left_to_image_classify("upx blob 64 KiB into the overlay", &bytes);
}

#[test]
fn a_upx_blob_inside_a_resource_is_not_a_upx_verdict() {
    let mut bytes: Vec<u8> = corpus(BENIGN_HOST);
    let upx: Vec<u8> = corpus(UPX_PACKED);
    let (start, end): (usize, usize) = rsrc_raw_range(&bytes);
    let at: usize = start + 0x100;
    let len: usize = (end - at).min(upx.len());
    assert!(
        upx[..len].windows(4).any(|w: &[u8]| w == b"UPX!"),
        "the embedded slice must carry the UPX! pack header"
    );
    bytes[at..at + len].copy_from_slice(&upx[..len]);
    assert_left_to_image_classify("upx blob inside .rsrc", &bytes);
}

#[test]
fn vendor_names_in_resource_strings_are_not_verdicts() {
    let mut bytes: Vec<u8> = corpus(BENIGN_HOST);
    let (start, _end): (usize, usize) = rsrc_raw_range(&bytes);
    let mut at: usize = start + 0x40;
    for literal in [
        b"morphine".as_slice(),
        b"WinLicense",
        b"PEC2",
        b"FSG!",
        b"PECompact2",
        b"Obsidium",
        b"ARMADILLO",
        b"Enigma protector",
    ] {
        bytes[at..at + literal.len()].copy_from_slice(literal);
        at += literal.len() + 8;
    }
    assert_left_to_image_classify("vendor names in .rsrc", &bytes);
}
