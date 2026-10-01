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

const ELF_PT_LOAD: u32 = 1;
const ELF_PT_NOTE: u32 = 4;
const ELF_PT_GNU_STACK: u32 = 0x6474_E551;
const ELF_BASE: u64 = 0x40_0000;

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

fn upx_elf64_after_note_bodies(note_sizes: &[usize], note_type: u32) -> Vec<u8> {
    const EHDR: usize = 64;
    const PHDR: usize = 56;
    const FILE_LEN: usize = 0x1000;
    const ENTRY_OFFSET: usize = 0x800;
    let phnum: usize = 2 + note_sizes.len() + 1;
    let table_end: usize = EHDR + phnum * PHDR;
    let mut bytes: Vec<u8> = vec![0xCC; FILE_LEN];
    bytes[..table_end].fill(0);
    put(&mut bytes, 0, b"\x7FELF\x02\x01\x01");
    put(&mut bytes, 16, &2_u16.to_le_bytes());
    put(&mut bytes, 18, &0x3E_u16.to_le_bytes());
    put(&mut bytes, 20, &1_u32.to_le_bytes());
    put(
        &mut bytes,
        24,
        &(ELF_BASE + ENTRY_OFFSET as u64).to_le_bytes(),
    );
    put(&mut bytes, 32, &(EHDR as u64).to_le_bytes());
    put(&mut bytes, 52, &(EHDR as u16).to_le_bytes());
    put(&mut bytes, 54, &(PHDR as u16).to_le_bytes());
    put(&mut bytes, 56, &u16::try_from(phnum).unwrap().to_le_bytes());
    put(&mut bytes, 58, &64_u16.to_le_bytes());
    let mut body: usize = table_end;
    let mut headers: Vec<(u32, usize, usize)> =
        vec![(ELF_PT_LOAD, 0, 0), (ELF_PT_LOAD, 0, FILE_LEN)];
    for size in note_sizes {
        headers.push((note_type, body, *size));
        bytes[body..body + size].fill(0x4E);
        body = (body + size).next_multiple_of(4);
    }
    headers.push((ELF_PT_GNU_STACK, 0, 0));
    headers[0].2 = body;
    for (index, (p_type, offset, filesz)) in headers.into_iter().enumerate() {
        let at: usize = EHDR + index * PHDR;
        put(&mut bytes, at, &p_type.to_le_bytes());
        put(&mut bytes, at + 8, &(offset as u64).to_le_bytes());
        put(
            &mut bytes,
            at + 16,
            &(ELF_BASE + offset as u64).to_le_bytes(),
        );
        put(&mut bytes, at + 32, &(filesz as u64).to_le_bytes());
        put(&mut bytes, at + 40, &(filesz as u64).to_le_bytes());
        put(&mut bytes, at + 48, &0x1000_u64.to_le_bytes());
    }
    put(&mut bytes, body, &[0, 0, 0, 0]);
    put(&mut bytes, body + 4, b"UPX!");
    put(&mut bytes, body + 8, &[0, 0, 14, 22]);
    bytes
}

#[test]
fn upx_l_info_after_the_copied_note_bodies_is_a_upx_verdict() {
    for (label, notes) in [
        ("gcc property and build-id notes", [0x30, 0x44].as_slice()),
        ("go build-id note", [0x64].as_slice()),
    ] {
        let bytes: Vec<u8> = upx_elf64_after_note_bodies(notes, ELF_PT_NOTE);
        assert!(
            packers_of(&bytes).contains(&Packer::Upx),
            "{label}: UPX writes the PT_NOTE bodies between the program headers and its l_info \
             record, so the l_info magic is still header evidence"
        );
        let unnamed: Vec<u8> = upx_elf64_after_note_bodies(notes, 0);
        assert!(
            packers_of(&unnamed).is_empty(),
            "{label}: the same bytes behind PT_NULL headers are not note bodies, so the magic \
             past the header tail stays unanchored"
        );
    }
}
