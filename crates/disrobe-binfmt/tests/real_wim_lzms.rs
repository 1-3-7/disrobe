#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_binfmt::containers::{
    WimArchive, WimCompression, decompress_named_resource, lzms_decompress, parse_wim,
};
use disrobe_binfmt::extract::{EntryCompression, ExtractionResult};
use disrobe_binfmt::{ContainerKind, ExtractionQuota, extract_to};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("binfmt")
        .join("wim")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn split_raw_fixture(blob: &[u8]) -> (usize, Vec<u8>, Vec<u8>) {
    assert!(blob.len() >= 16, "raw fixture too short");
    assert_eq!(&blob[0..8], b"DRLZMS01", "raw fixture magic");
    let uncompressed_size: usize =
        u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let compressed_size: usize =
        u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let comp_start: usize = 16;
    let comp_end: usize = comp_start + compressed_size;
    let compressed: Vec<u8> = blob[comp_start..comp_end].to_vec();
    let original: Vec<u8> = blob[comp_end..comp_end + uncompressed_size].to_vec();
    (uncompressed_size, compressed, original)
}

fn temp_out(tag: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let dir: PathBuf = std::env::temp_dir().join(format!("disrobe-wim-lzms-{pid}-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn raw_lzms_chunks_from_wimlib_round_trip() {
    for name in ["lzms_raw_40k_l50.bin", "lzms_raw_4k_l25.bin"] {
        let blob: Vec<u8> = read_fixture(name);
        let (out_size, compressed, original): (usize, Vec<u8>, Vec<u8>) = split_raw_fixture(&blob);
        assert!(
            compressed.len() < original.len(),
            "{name}: wimlib must have actually compressed the payload ({} >= {})",
            compressed.len(),
            original.len()
        );
        let decoded: Vec<u8> = lzms_decompress(&compressed, out_size)
            .unwrap_or_else(|e| panic!("{name}: lzms_decompress failed: {e}"));
        assert_eq!(
            decoded, original,
            "{name}: disrobe LZMS decode is not byte-identical to the wimlib-encoded original"
        );
    }
}

fn assert_wim_boot_resource_exact(wim_name: &str) {
    let wim: Vec<u8> = read_fixture(wim_name);
    let expected: Vec<u8> = read_fixture(&format!("{wim_name}.expected"));

    let archive: WimArchive = parse_wim(&wim).expect("parse real lzms wim");
    assert_eq!(
        archive.header.compression,
        WimCompression::Lzms,
        "{wim_name}: header must advertise LZMS"
    );
    assert!(
        archive.header.boot_metadata.is_compressed(),
        "{wim_name}: boot resource must be flagged compressed"
    );
    assert_eq!(
        archive.header.boot_metadata.original_size as usize,
        expected.len(),
        "{wim_name}: declared original size mismatch"
    );

    let decoded: Vec<u8> = decompress_named_resource(
        &wim,
        &archive.header,
        &archive.header.boot_metadata,
        &ExtractionQuota::unrestricted(),
    )
    .unwrap_or_else(|e| panic!("{wim_name}: decompress_named_resource failed: {e}"));
    assert_eq!(
        decoded, expected,
        "{wim_name}: direct resource decode is not byte-identical to the wimlib original"
    );
}

#[test]
fn wim_lzms_resource_decodes_byte_exact() {
    assert_wim_boot_resource_exact("lzms_singlechunk.wim");
    assert_wim_boot_resource_exact("lzms_multichunk.wim");
}

fn assert_extract_to_writes_exact(wim_name: &str, tag: &str) {
    let wim: Vec<u8> = read_fixture(wim_name);
    let expected: Vec<u8> = read_fixture(&format!("{wim_name}.expected"));
    let out_dir: PathBuf = temp_out(tag);

    let kind: ContainerKind = ContainerKind::Wim;
    let result: ExtractionResult = extract_to(kind, &wim, &out_dir).expect("extract_to wim");
    assert_eq!(result.kind, ContainerKind::Wim);

    let decoded_path: PathBuf = out_dir.join(".disrobe-wim-boot-metadata.dec.bin");
    let written: Vec<u8> = std::fs::read(&decoded_path).unwrap_or_else(|e| {
        panic!(
            "{wim_name}: extract_to did not write the decoded boot resource ({}): {e}",
            decoded_path.display()
        )
    });
    assert_eq!(
        written, expected,
        "{wim_name}: on-disk decoded resource from extract_to is not byte-identical"
    );

    let entry_written: bool = result.entries.iter().any(|e| {
        e.name == ".disrobe-wim-boot-metadata.dec.bin"
            && e.uncompressed_size as usize == expected.len()
            && e.compression == EntryCompression::Other
    });
    assert!(
        entry_written,
        "{wim_name}: decoded boot resource must be reported as an extracted entry"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn wim_lzms_extract_to_writes_byte_exact_files() {
    assert_extract_to_writes_exact("lzms_singlechunk.wim", "single");
    assert_extract_to_writes_exact("lzms_multichunk.wim", "multi");
}
