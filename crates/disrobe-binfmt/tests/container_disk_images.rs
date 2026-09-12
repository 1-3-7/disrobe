#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::cpio::{NEWC_MAGIC, TRAILER_NAME};
use disrobe_binfmt::containers::partition::{
    GPT_SIGNATURE, MBR_PARTITION_TABLE_OFFSET, MBR_SIGNATURE, MBR_SIGNATURE_OFFSET,
    MBR_TYPE_GPT_PROTECTIVE,
};
use disrobe_binfmt::containers::vhd::{VHD_COOKIE, VHD_FOOTER_LEN};
use disrobe_binfmt::containers::wim::{
    RESHDR_FLAG_COMPRESSED, WIM_FLAG_COMPRESS_XPRESS, WIM_FLAG_COMPRESSION, WIM_HEADER_LEN,
    WIM_MAGIC,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-disk-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
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

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("cpio");

    let out: PathBuf = scratch.path().to_path_buf();
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

const SECTOR: usize = 512;

fn write_mbr_signature(disk: &mut [u8]) {
    disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
}

fn write_mbr_entry(disk: &mut [u8], index: usize, ptype: u8, start_lba: u32, sector_count: u32) {
    let off: usize = MBR_PARTITION_TABLE_OFFSET + index * 16;
    disk[off + 4] = ptype;
    disk[off + 8..off + 12].copy_from_slice(&start_lba.to_le_bytes());
    disk[off + 12..off + 16].copy_from_slice(&sector_count.to_le_bytes());
}

fn fixed_vhd_footer(current_size: u64) -> Vec<u8> {
    let mut footer: Vec<u8> = vec![0u8; VHD_FOOTER_LEN];
    footer[0..8].copy_from_slice(VHD_COOKIE);
    footer[48..56].copy_from_slice(&current_size.to_be_bytes());
    footer[60..64].copy_from_slice(&2u32.to_be_bytes());
    let mut sum: u32 = 0;
    for (i, &b) in footer.iter().enumerate() {
        if (64..68).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b));
    }
    footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
    footer
}

#[test]
fn mbr_carves_partition_bytes_and_recovers_known_payload() {
    let total_sectors: usize = 16;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];
    write_mbr_signature(&mut disk);
    write_mbr_entry(&mut disk, 0, 0x83, 2, 3);
    write_mbr_entry(&mut disk, 1, 0x0c, 8, 2);

    let part0_start: usize = 2 * SECTOR;
    let marker0: &[u8] = b"PARTITION-ZERO-PAYLOAD";
    disk[part0_start..part0_start + marker0.len()].copy_from_slice(marker0);
    let part1_start: usize = 8 * SECTOR;
    let marker1: &[u8] = b"second-part-data";
    disk[part1_start..part1_start + marker1.len()].copy_from_slice(marker1);

    assert_eq!(detect_container(&disk), Some(ContainerKind::Mbr));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("mbr-carve");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Mbr, &disk, &out).expect("carve mbr");
    assert_eq!(result.kind, ContainerKind::Mbr);

    let p0: Vec<u8> = std::fs::read(out.join("partition00.83.img")).expect("p0");
    assert_eq!(p0.len(), 3 * SECTOR);
    assert_eq!(&p0[..marker0.len()], marker0);
    let p1: Vec<u8> = std::fs::read(out.join("partition01.0c.img")).expect("p1");
    assert_eq!(p1.len(), 2 * SECTOR);
    assert_eq!(&p1[..marker1.len()], marker1);
    assert!(out.join(".disrobe-mbr-partitions.json").is_file());
}

#[test]
fn vhd_fixed_carves_through_to_partition_payload() {
    let total_sectors: usize = 16;
    let logical_size: u64 = (total_sectors * SECTOR) as u64;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];
    write_mbr_signature(&mut disk);
    write_mbr_entry(&mut disk, 0, 0x83, 4, 2);
    let part_start: usize = 4 * SECTOR;
    let marker: &[u8] = b"VHD-EMBEDDED-PARTITION";
    disk[part_start..part_start + marker.len()].copy_from_slice(marker);

    let mut image: Vec<u8> = disk;
    image.extend_from_slice(&fixed_vhd_footer(logical_size));

    assert_eq!(detect_container(&image), Some(ContainerKind::Vhd));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("vhd-carve");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Vhd, &image, &out).expect("carve vhd");
    assert_eq!(result.kind, ContainerKind::Vhd);
    assert!(out.join(".disrobe-vhd-layout.json").is_file());
    assert!(out.join(".disrobe-mbr-partitions.json").is_file());
    let part: Vec<u8> = std::fs::read(out.join("partition00.83.img")).expect("partition carved");
    assert_eq!(part.len(), 2 * SECTOR);
    assert_eq!(&part[..marker.len()], marker);
}

#[test]
fn vhd_extraction_writes_layout_json() {
    let logical_size: u64 = 2048 - VHD_FOOTER_LEN as u64;
    let mut image: Vec<u8> = vec![0u8; 2048];
    let footer_start: usize = image.len() - VHD_FOOTER_LEN;
    image[footer_start..].copy_from_slice(&fixed_vhd_footer(logical_size));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("vhd");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Vhd, &image, &out).expect("vhd");

    let layout_bytes: Vec<u8> =
        std::fs::read(out.join(".disrobe-vhd-layout.json")).expect("vhd layout json");
    let layout: serde_json::Value =
        serde_json::from_slice(&layout_bytes).expect("layout json parses");
    let footer: &serde_json::Value = &layout["footer"];
    assert_eq!(
        footer["current_size"].as_u64(),
        Some(logical_size),
        "parsed footer must echo the exact logical disk size we wrote"
    );
    assert_eq!(
        footer["disk_type"].as_str(),
        Some("fixed"),
        "the footer disk-type tag must parse back to fixed"
    );
    assert_eq!(
        footer["checksum_valid"].as_bool(),
        Some(true),
        "the footer checksum we computed must verify"
    );

    assert!(
        result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("no in-tree-recognized partition")),
        "empty disk view should report no recognized partition map: {:?}",
        result.integrity_violations
    );
    assert!(
        !result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("vhd") && v.contains("checksum")),
        "a footer with a valid checksum must not raise a checksum violation: {:?}",
        result.integrity_violations
    );
}

fn build_gpt_disk(parts: &[(u64, u64, &[u8])]) -> Vec<u8> {
    let total_sectors: usize = 64;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];
    write_mbr_signature(&mut disk);
    disk[MBR_PARTITION_TABLE_OFFSET + 4] = MBR_TYPE_GPT_PROTECTIVE;

    let header_off: usize = SECTOR;
    disk[header_off..header_off + 8].copy_from_slice(GPT_SIGNATURE);
    disk[header_off + 12..header_off + 16].copy_from_slice(&92u32.to_le_bytes());
    disk[header_off + 24..header_off + 32].copy_from_slice(&1u64.to_le_bytes());
    disk[header_off + 72..header_off + 80].copy_from_slice(&2u64.to_le_bytes());
    disk[header_off + 80..header_off + 84].copy_from_slice(&128u32.to_le_bytes());
    disk[header_off + 84..header_off + 88].copy_from_slice(&128u32.to_le_bytes());

    let linux_type: [u8; 16] = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];
    let array_off: usize = SECTOR * 2;
    for (index, (start_lba, end_lba, payload)) in parts.iter().enumerate() {
        let entry: usize = array_off + index * 128;
        disk[entry..entry + 16].copy_from_slice(&linux_type);
        disk[entry + 16..entry + 24].copy_from_slice(&((index as u64) + 1).to_le_bytes());
        disk[entry + 32..entry + 40].copy_from_slice(&start_lba.to_le_bytes());
        disk[entry + 40..entry + 48].copy_from_slice(&end_lba.to_le_bytes());
        let payload_off: usize = (*start_lba as usize) * SECTOR;
        disk[payload_off..payload_off + payload.len()].copy_from_slice(payload);
    }

    let array_crc: u32 = crc32fast::hash(&disk[array_off..array_off + 128 * 128]);
    disk[header_off + 88..header_off + 92].copy_from_slice(&array_crc.to_le_bytes());
    disk[header_off + 16..header_off + 20].copy_from_slice(&[0u8; 4]);
    let header_crc: u32 = crc32fast::hash(&disk[header_off..header_off + 92]);
    disk[header_off + 16..header_off + 20].copy_from_slice(&header_crc.to_le_bytes());
    disk
}

#[test]
fn gpt_carves_partition_bytes_with_valid_crc() {
    let marker: &[u8] = b"GPT-LINUX-PARTITION-PAYLOAD";
    let disk: Vec<u8> = build_gpt_disk(&[(8, 11, marker)]);
    assert_eq!(detect_container(&disk), Some(ContainerKind::Gpt));

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("gpt-carve");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Gpt, &disk, &out).expect("carve gpt");
    assert_eq!(result.kind, ContainerKind::Gpt);
    assert!(
        !result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("gpt-crc")),
        "spec-correct CRCs must not raise a crc violation: {:?}",
        result.integrity_violations
    );

    let table_bytes: Vec<u8> =
        std::fs::read(out.join(".disrobe-gpt-partitions.json")).expect("gpt table json");
    let table: serde_json::Value =
        serde_json::from_slice(&table_bytes).expect("gpt table json parses");
    assert_eq!(
        table["header"]["header_crc32_valid"].as_bool(),
        Some(true),
        "the header CRC we computed over the 92-byte header must verify"
    );
    assert_eq!(
        table["entries_crc32_valid"].as_bool(),
        Some(true),
        "the partition-array CRC we computed must verify"
    );
    assert_eq!(
        table["header"]["partition_entry_count"].as_u64(),
        Some(128),
        "the parsed entry count must match the 128 we wrote"
    );
    assert_eq!(
        table["header"]["partition_entry_size"].as_u64(),
        Some(128),
        "the parsed entry size must match the 128 we wrote"
    );
    let partitions: &Vec<serde_json::Value> =
        table["partitions"].as_array().expect("partitions array");
    let linux: &serde_json::Value = partitions
        .iter()
        .find(|p: &&serde_json::Value| {
            p["start_lba"].as_u64() == Some(8) && p["end_lba"].as_u64() == Some(11)
        })
        .expect("the populated linux entry must round-trip its exact start/end LBAs");
    assert_eq!(
        linux["end_lba"].as_u64().unwrap() - linux["start_lba"].as_u64().unwrap() + 1,
        4,
        "LBA span 8..=11 covers exactly four sectors"
    );

    let part: Vec<u8> = std::fs::read(out.join("partition00.linux.img")).expect("gpt partition");
    assert_eq!(
        part.len(),
        4 * SECTOR,
        "the carved bytes must span the four-sector LBA range from the parsed entry"
    );
    assert_eq!(&part[..marker.len()], marker);
}

#[test]
fn mbr_partition_holding_nested_mbr_recurses() {
    let inner_sectors: usize = 8;
    let mut inner: Vec<u8> = vec![0u8; inner_sectors * SECTOR];
    write_mbr_signature(&mut inner);
    write_mbr_entry(&mut inner, 0, 0x83, 2, 2);
    let inner_marker: &[u8] = b"DEEP-NESTED-PAYLOAD";
    let inner_part_off: usize = 2 * SECTOR;
    inner[inner_part_off..inner_part_off + inner_marker.len()].copy_from_slice(inner_marker);

    let total_sectors: usize = 16;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];
    write_mbr_signature(&mut disk);
    write_mbr_entry(&mut disk, 0, 0x05, 4, inner_sectors as u32);
    let outer_part_off: usize = 4 * SECTOR;
    disk[outer_part_off..outer_part_off + inner.len()].copy_from_slice(&inner);

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("mbr-nested");

    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Mbr, &disk, &out).expect("nested mbr");
    assert_eq!(result.kind, ContainerKind::Mbr);
    let nested: Vec<u8> = std::fs::read(out.join("partition00.05.img.d/partition00.83.img"))
        .expect("recursed nested partition");
    assert_eq!(&nested[..inner_marker.len()], inner_marker);
}

#[test]
fn wim_carves_uncompressed_resources_and_notes_absent_lookup_table() {
    let header_len: usize = 208;
    let xml: &[u8] = b"<WIM><IMAGE INDEX=\"1\"><NAME>x</NAME></IMAGE></WIM>";
    let mut image: Vec<u8> = vec![0u8; header_len + xml.len()];
    image[0..8].copy_from_slice(WIM_MAGIC);
    image[8..12].copy_from_slice(&(header_len as u32).to_le_bytes());
    image[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    image[16..20].copy_from_slice(&0x0002_0002u32.to_le_bytes());
    image[44..48].copy_from_slice(&1u32.to_le_bytes());
    let xml_size: u64 = xml.len() as u64;
    image[72..79].copy_from_slice(&xml_size.to_le_bytes()[..7]);
    image[79] = 0;
    image[80..88].copy_from_slice(&(header_len as u64).to_le_bytes());
    image[88..96].copy_from_slice(&xml_size.to_le_bytes());
    image[header_len..].copy_from_slice(xml);

    assert_eq!(detect_container(&image), Some(ContainerKind::Wim));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("wim-carve");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(ContainerKind::Wim, &image, &out).expect("wim carve");
    assert_eq!(result.kind, ContainerKind::Wim);
    let carved: Vec<u8> = std::fs::read(out.join(".disrobe-wim-xml.bin")).expect("xml resource");
    assert_eq!(carved, xml);

    let images_bytes: Vec<u8> =
        std::fs::read(out.join(".disrobe-wim-images.json")).expect("wim images json");
    let parsed: serde_json::Value =
        serde_json::from_slice(&images_bytes).expect("wim images json parses");
    let header: &serde_json::Value = &parsed["header"];
    assert_eq!(
        header["header_size"].as_u64(),
        Some(header_len as u64),
        "parsed header size must echo the 208 we wrote"
    );
    assert_eq!(
        header["image_count"].as_u64(),
        Some(1),
        "parsed image count oracle"
    );
    assert_eq!(
        header["xml_data"]["offset"].as_u64(),
        Some(header_len as u64),
        "the XML resource must be located at the byte offset we placed it"
    );
    assert_eq!(
        header["xml_data"]["size"].as_u64(),
        Some(xml_size),
        "the parsed XML resource size must equal the literal XML length"
    );

    assert!(
        result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("wim-image") && v.contains("lookup table")),
        "a wim with no lookup table must report the per-file walk could not proceed: {:?}",
        result.integrity_violations
    );
}

const MS_XCA_ALPHABET_COMPRESSED: [u8; 276] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45, 0x44, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf, 0x8d, 0x04,
    0x00, 0x00, 0x00, 0x00,
];

#[test]
fn wim_xpress_resource_decompresses_end_to_end_through_run_path() {
    let plaintext: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let resource_offset: usize = WIM_HEADER_LEN;
    let mut image: Vec<u8> = vec![0u8; WIM_HEADER_LEN + MS_XCA_ALPHABET_COMPRESSED.len()];
    image[0..8].copy_from_slice(WIM_MAGIC);
    image[8..12].copy_from_slice(&(WIM_HEADER_LEN as u32).to_le_bytes());
    image[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    let flags: u32 = WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_XPRESS;
    image[16..20].copy_from_slice(&flags.to_le_bytes());
    image[20..24].copy_from_slice(&32_768u32.to_le_bytes());
    image[44..48].copy_from_slice(&1u32.to_le_bytes());

    let compressed_size: u64 = MS_XCA_ALPHABET_COMPRESSED.len() as u64;
    let original_size: u64 = plaintext.len() as u64;
    image[96..103].copy_from_slice(&compressed_size.to_le_bytes()[..7]);
    image[103] = RESHDR_FLAG_COMPRESSED;
    image[104..112].copy_from_slice(&(resource_offset as u64).to_le_bytes());
    image[112..120].copy_from_slice(&original_size.to_le_bytes());
    image[resource_offset..].copy_from_slice(&MS_XCA_ALPHABET_COMPRESSED);

    assert_eq!(detect_container(&image), Some(ContainerKind::Wim));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("wim-xpress-e2e");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Wim, &image, &out).expect("wim xpress extract");
    assert_eq!(result.kind, ContainerKind::Wim);

    let decoded: Vec<u8> = std::fs::read(out.join(".disrobe-wim-boot-metadata.dec.bin"))
        .expect("xpress-compressed boot metadata must be decoded to disk through the run path");
    assert_eq!(
        decoded, plaintext,
        "extract_to must recover the MS-XCA plaintext through the offset and chunk-table plumbing"
    );
    assert!(
        result
            .entries
            .iter()
            .any(|e: &disrobe_binfmt::ExtractedEntry| e
                .name
                .ends_with(".disrobe-wim-boot-metadata.dec.bin")),
        "the decoded resource must be reported as an extracted entry: {:?}",
        result.entries
    );
    assert!(
        !result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("wim-decompress")),
        "a real XPRESS resource must not raise a decompression violation: {:?}",
        result.integrity_violations
    );
}
