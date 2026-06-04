#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::cpio::{NEWC_MAGIC, TRAILER_NAME};
use disrobe_binfmt::containers::partition::{
    GPT_SIGNATURE, MBR_PARTITION_TABLE_OFFSET, MBR_SIGNATURE, MBR_SIGNATURE_OFFSET,
    MBR_TYPE_GPT_PROTECTIVE,
};
use disrobe_binfmt::containers::vhd::{VHD_COOKIE, VHD_FOOTER_LEN};
use disrobe_binfmt::containers::wim::WIM_MAGIC;
use disrobe_binfmt::{Error, ExtractionResult, extract_to};

fn temp_dir(name: &str) -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-disk-{}-{name}", std::process::id()));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn newc_header(name: &str, mode: u32, file_size: u32) -> Vec<u8> {
    let name_size: u32 = name.len() as u32 + 1;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(NEWC_MAGIC);
    let fields: [u32; 13] = [0, mode, 0, 0, 1, 0, file_size, 0, 0, 0, 0, name_size, 0];
    for value in fields {
        out.extend_from_slice(format!("{value:08X}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

#[test]
fn cpio_newc_detected_and_extracted_to_disk() {
    let mut archive: Vec<u8> = Vec::new();
    archive.extend_from_slice(&newc_header("docs/readme.txt", 0o100_644, 11));
    archive.extend_from_slice(b"hello world");
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
    archive.extend_from_slice(&newc_header(TRAILER_NAME, 0, 0));

    assert_eq!(detect_container(&archive), Some(ContainerKind::Cpio));

    let out: PathBuf = temp_dir("cpio");
    let result: ExtractionResult =
        extract_to(ContainerKind::Cpio, &archive, &out).expect("extract");
    assert_eq!(result.kind, ContainerKind::Cpio);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "docs/readme.txt");
    let written: Vec<u8> = std::fs::read(out.join("docs/readme.txt")).expect("read extracted");
    assert_eq!(written, b"hello world");
}

#[test]
fn vhd_fixed_footer_detected_via_tail() {
    let mut image: Vec<u8> = vec![0u8; 4096];
    let footer_start: usize = image.len() - VHD_FOOTER_LEN;
    image[footer_start..footer_start + 8].copy_from_slice(VHD_COOKIE);
    image[footer_start + 60..footer_start + 64].copy_from_slice(&2u32.to_be_bytes());
    let mut sum: u32 = 0;
    for (i, &b) in image[footer_start..].iter().enumerate() {
        if (64..68).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b));
    }
    image[footer_start + 64..footer_start + 68].copy_from_slice(&(!sum).to_be_bytes());
    assert_eq!(detect_container(&image), Some(ContainerKind::Vhd));
}

#[test]
fn wim_magic_detected() {
    let mut image: Vec<u8> = vec![0u8; 256];
    image[0..8].copy_from_slice(WIM_MAGIC);
    assert_eq!(detect_container(&image), Some(ContainerKind::Wim));
}

#[test]
fn gpt_detected_before_mbr() {
    let mut disk: Vec<u8> = vec![0u8; 512 * 4];
    disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
    disk[MBR_PARTITION_TABLE_OFFSET + 4] = MBR_TYPE_GPT_PROTECTIVE;
    disk[512..512 + 8].copy_from_slice(GPT_SIGNATURE);
    assert_eq!(detect_container(&disk), Some(ContainerKind::Gpt));
}

#[test]
fn plain_mbr_detected() {
    let mut disk: Vec<u8> = vec![0u8; 512];
    disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
    disk[MBR_PARTITION_TABLE_OFFSET] = 0x80;
    disk[MBR_PARTITION_TABLE_OFFSET + 4] = 0x83;
    disk[MBR_PARTITION_TABLE_OFFSET + 8..MBR_PARTITION_TABLE_OFFSET + 12]
        .copy_from_slice(&2048u32.to_le_bytes());
    assert_eq!(detect_container(&disk), Some(ContainerKind::Mbr));
}

#[test]
fn vhd_summary_extraction_writes_layout_json() {
    let mut image: Vec<u8> = vec![0u8; 2048];
    let footer_start: usize = image.len() - VHD_FOOTER_LEN;
    image[footer_start..footer_start + 8].copy_from_slice(VHD_COOKIE);
    image[footer_start + 60..footer_start + 64].copy_from_slice(&2u32.to_be_bytes());
    let mut sum: u32 = 0;
    for (i, &b) in image[footer_start..].iter().enumerate() {
        if (64..68).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b));
    }
    image[footer_start + 64..footer_start + 68].copy_from_slice(&(!sum).to_be_bytes());

    let out: PathBuf = temp_dir("vhd");
    let err: Error = extract_to(ContainerKind::Vhd, &image, &out).unwrap_err();
    assert!(matches!(err, Error::NoSource { .. }));
    assert!(out.join(".disrobe-vhd-layout.json").is_file());
}
