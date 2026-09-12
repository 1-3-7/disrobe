#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_binfmt::containers::{WimArchive, WimCompression, parse_wim};
use disrobe_binfmt::extract::ExtractionResult;
use disrobe_binfmt::{ContainerKind, extract_to};

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

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_dir().join("files_expected").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read expected {}: {e}", path.display()))
}

fn temp_out(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-wim-files-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

const MEMBERS: [&str; 4] = ["hello.txt", "readme.md", "large.txt", "sub/nested.bin"];

fn assert_wim_files_byte_exact(wim_name: &str, expect: WimCompression, tag: &str) {
    let wim: Vec<u8> = read_fixture(wim_name);
    let archive: WimArchive = parse_wim(&wim).expect("parse real wim");
    assert_eq!(
        archive.header.compression, expect,
        "{wim_name}: header compression mismatch"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_out(tag);

    let out_dir: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Wim, &wim, &out_dir).expect("extract_to wim");
    assert_eq!(result.kind, ContainerKind::Wim);

    for member in MEMBERS {
        let want: Vec<u8> = expected_bytes(member);
        let on_disk: PathBuf = out_dir.join(member);
        let got: Vec<u8> = std::fs::read(&on_disk).unwrap_or_else(|_| {
            panic!(
                "{wim_name}: member {member} not recovered to {}; violations: {:?}",
                on_disk.display(),
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{wim_name}: recovered {member} must be byte-identical to the captured source"
        );
        let reported: bool = result
            .entries
            .iter()
            .any(|e| e.name.replace('\\', "/") == member);
        assert!(
            reported,
            "{wim_name}: {member} must be reported as an extracted entry"
        );
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn wim_xpress_per_file_streams_decode_byte_exact() {
    assert_wim_files_byte_exact("files_xpress.wim", WimCompression::Xpress, "xpress");
}

#[test]
fn wim_lzx_per_file_streams_decode_byte_exact() {
    assert_wim_files_byte_exact("files_lzx.wim", WimCompression::Lzx, "lzx");
}
