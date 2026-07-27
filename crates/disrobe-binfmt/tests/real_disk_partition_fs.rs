#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::io::Read as _;
use std::path::{Path, PathBuf};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::partition::{
    GPT_SIGNATURE, MBR_PARTITION_TABLE_OFFSET, MBR_SIGNATURE, MBR_SIGNATURE_OFFSET,
    MBR_TYPE_GPT_PROTECTIVE,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

const SECTOR: usize = 512;
const FAT_FORMAT_DIR: &str = "fat";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-diskfs-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn real_fat12_image() -> Vec<u8> {
    let gz: Vec<u8> = common::load_fixture(FAT_FORMAT_DIR, "fat12.img.gz").unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FAT_FORMAT_DIR}/fat12.img.gz")
    });
    let mut decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(&gz[..]);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut out)
        .expect("inflate fat12 fixture");
    out
}

fn fat_ground_truth(member: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FAT_FORMAT_DIR)
        .join("expected")
        .join(member);
    std::fs::read(&path)
        .unwrap_or_else(|_| panic!("read ground-truth {FAT_FORMAT_DIR}/expected/{member}"))
}

fn find_recovered(out: &Path, leaf: &str) -> Option<Vec<u8>> {
    let mut stack: Vec<PathBuf> = vec![out.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .is_some_and(|n: &str| n.eq_ignore_ascii_case(leaf))
            {
                return std::fs::read(&path).ok();
            }
        }
    }
    None
}

fn write_mbr_entry(disk: &mut [u8], index: usize, ptype: u8, start_lba: u32, sector_count: u32) {
    let off: usize = MBR_PARTITION_TABLE_OFFSET + index * 16;
    disk[off + 4] = ptype;
    disk[off + 8..off + 12].copy_from_slice(&start_lba.to_le_bytes());
    disk[off + 12..off + 16].copy_from_slice(&sector_count.to_le_bytes());
}

fn build_mbr_disk_with_fs(fs: &[u8], start_lba: usize) -> Vec<u8> {
    assert!(
        fs.len().is_multiple_of(SECTOR),
        "fs image must be sector-aligned"
    );
    let fs_sectors: usize = fs.len() / SECTOR;
    let total_sectors: usize = start_lba + fs_sectors + 1;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];
    disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
    write_mbr_entry(&mut disk, 0, 0x0c, start_lba as u32, fs_sectors as u32);
    let off: usize = start_lba * SECTOR;
    disk[off..off + fs.len()].copy_from_slice(fs);
    disk
}

fn build_gpt_disk_with_fs(fs: &[u8], start_lba: u64) -> Vec<u8> {
    assert!(
        fs.len().is_multiple_of(SECTOR),
        "fs image must be sector-aligned"
    );
    let fs_sectors: u64 = (fs.len() / SECTOR) as u64;
    let end_lba: u64 = start_lba + fs_sectors - 1;
    let total_sectors: usize = (end_lba as usize) + 2;
    let mut disk: Vec<u8> = vec![0u8; total_sectors * SECTOR];

    disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
    disk[MBR_PARTITION_TABLE_OFFSET + 4] = MBR_TYPE_GPT_PROTECTIVE;

    let header_off: usize = SECTOR;
    disk[header_off..header_off + 8].copy_from_slice(GPT_SIGNATURE);
    disk[header_off + 12..header_off + 16].copy_from_slice(&92u32.to_le_bytes());
    disk[header_off + 24..header_off + 32].copy_from_slice(&1u64.to_le_bytes());
    disk[header_off + 72..header_off + 80].copy_from_slice(&2u64.to_le_bytes());
    disk[header_off + 80..header_off + 84].copy_from_slice(&128u32.to_le_bytes());
    disk[header_off + 84..header_off + 88].copy_from_slice(&128u32.to_le_bytes());

    let basic_data_type: [u8; 16] = [
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99,
        0xc7,
    ];
    let array_off: usize = SECTOR * 2;
    disk[array_off..array_off + 16].copy_from_slice(&basic_data_type);
    disk[array_off + 16..array_off + 24].copy_from_slice(&1u64.to_le_bytes());
    disk[array_off + 32..array_off + 40].copy_from_slice(&start_lba.to_le_bytes());
    disk[array_off + 40..array_off + 48].copy_from_slice(&end_lba.to_le_bytes());

    let payload_off: usize = (start_lba as usize) * SECTOR;
    disk[payload_off..payload_off + fs.len()].copy_from_slice(fs);

    let array_crc: u32 = crc32fast::hash(&disk[array_off..array_off + 128 * 128]);
    disk[header_off + 88..header_off + 92].copy_from_slice(&array_crc.to_le_bytes());
    disk[header_off + 16..header_off + 20].copy_from_slice(&[0u8; 4]);
    let header_crc: u32 = crc32fast::hash(&disk[header_off..header_off + 92]);
    disk[header_off + 16..header_off + 20].copy_from_slice(&header_crc.to_le_bytes());
    disk
}

fn assert_recovers_fat_members(kind: ContainerKind, disk: &[u8], tag: &str) {
    assert_eq!(
        detect_container(disk),
        Some(kind),
        "{tag} disk must be detected as {kind:?}"
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(tag);
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult = extract_to(kind, disk, &out).expect("extract disk image");
    assert_eq!(result.kind, kind);

    for member in ["HELLO.TXT", "DATA.BIN"] {
        let want: Vec<u8> = fat_ground_truth(member);
        let got: Vec<u8> = find_recovered(&out, member).unwrap_or_else(|| {
            panic!(
                "{member} not recovered from {tag}; entries={:?} violations={:?}",
                result
                    .entries
                    .iter()
                    .map(|e: &disrobe_binfmt::ExtractedEntry| e.name.clone())
                    .collect::<Vec<String>>(),
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from the {tag} partition filesystem must be byte-identical to the real-tool FAT12 ground truth"
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn mbr_partition_holding_real_fat12_recovers_members_byte_exact() {
    let fs: Vec<u8> = real_fat12_image();
    let disk: Vec<u8> = build_mbr_disk_with_fs(&fs, 64);
    assert_recovers_fat_members(ContainerKind::Mbr, &disk, "mbr-fat12");
}

#[test]
fn gpt_partition_holding_real_fat12_recovers_members_byte_exact() {
    let fs: Vec<u8> = real_fat12_image();
    let disk: Vec<u8> = build_gpt_disk_with_fs(&fs, 2048);
    assert_recovers_fat_members(ContainerKind::Gpt, &disk, "gpt-fat12");
}
