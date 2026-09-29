#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_binfmt::containers::nsis::{
    NsisArchive, NsisCompression, NsisFileEntry, decode_solid_region, decompress_file,
    parse_nsis_archive, slice_solid_file,
};
use sha2::{Digest, Sha256};

use common::repository_root;
use common::requirement::{MAKENSIS, describe_run, locate, unmeasured};

const SCRIPT: &str = "tide_viewer.nsi";
const INPUTS: [&str; 3] = [
    "payload/readme.txt",
    "payload/stations.csv",
    "payload/docs/changes.txt",
];
const EMPTY_INPUT: &str = "payload/empty.txt";

#[derive(Debug, Clone, Copy)]
struct Build {
    compressor: &'static str,
    method: NsisCompression,
    solid: bool,
    unicode: bool,
}

fn corpus_dir() -> PathBuf {
    repository_root()
        .join("corpus")
        .join("installers")
        .join("nsis")
}

fn stage_build_tree(root: &Path) -> PathBuf {
    for relative in INPUTS.iter().chain(std::iter::once(&SCRIPT)) {
        let from: PathBuf = corpus_dir().join(relative);
        let to: PathBuf = root.join(relative);
        std::fs::create_dir_all(to.parent().expect("staged file has a parent"))
            .expect("create staged directory");
        std::fs::copy(&from, &to).unwrap_or_else(|e: std::io::Error| {
            panic!("stage committed input {}: {e}", from.display())
        });
    }
    std::fs::write(root.join(EMPTY_INPUT), b"").expect("stage the empty input");
    root.join(SCRIPT)
}

fn input_digests() -> BTreeMap<String, [u8; 32]> {
    let mut digests: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    digests.insert("empty.txt".to_owned(), Sha256::digest(b"").into());
    for input in INPUTS {
        let path: PathBuf = corpus_dir().join(input);
        let body: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
            panic!("read committed input {}: {e}", path.display())
        });
        let name: String = path
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .expect("input file name")
            .to_owned();
        digests.insert(name, Sha256::digest(&body).into());
    }
    digests
}

fn build_installer(makensis: &Path, script: &Path, out: &Path, build: Build) -> Vec<u8> {
    let mut arguments: Vec<String> = vec![
        "-V2".to_owned(),
        format!("-DCOMPRESSOR={}", build.compressor),
        format!("-DOUTFILE={}", out.display()),
    ];
    if build.solid {
        arguments.push("-DSOLID".to_owned());
    }
    if build.unicode {
        arguments.push("-DUNICODE_STRINGS".to_owned());
    }
    arguments.push(script.display().to_string());
    let output: Output = Command::new(makensis)
        .args(&arguments)
        .output()
        .expect("start makensis");
    let shown: Vec<&str> = arguments.iter().map(String::as_str).collect();
    assert!(
        output.status.success(),
        "{}",
        describe_run(makensis, &shown, &output)
    );
    std::fs::read(out).expect("read installer")
}

fn round_trip(build: Build) {
    let makensis: PathBuf = match locate(&MAKENSIS) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(
                &MAKENSIS,
                &format!("SHA-256 recovery of every file in an NSIS installer built as {build:?}"),
                &reason,
            );
            return;
        }
    };
    let expected: BTreeMap<String, [u8; 32]> = input_digests();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_nsis_solid")
            .expect("create scratch directory");
    let script: PathBuf = stage_build_tree(&scratch.path().join("tree"));
    let exe: Vec<u8> =
        build_installer(&makensis, &script, &scratch.path().join("setup.exe"), build);

    let archive: NsisArchive = parse_nsis_archive(&exe).expect("parse installer");
    assert_eq!(archive.compression, build.method);
    assert_eq!(archive.solid, build.solid);
    assert_eq!(archive.unicode, build.unicode);
    let solid_stream: Option<Vec<u8>> = build
        .solid
        .then(|| decode_solid_region(&exe, &archive, u64::MAX).expect("decode solid region"));
    let mut recovered: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    for entry in &archive.files {
        let body: Vec<u8> = solid_stream.as_ref().map_or_else(
            || decompress_file(&exe, &archive, entry, u64::MAX).expect("decompress file"),
            |stream: &Vec<u8>| slice_solid_file(stream, entry, u64::MAX).expect("slice solid"),
        );
        let previous: Option<[u8; 32]> =
            recovered.insert(entry.name.clone(), Sha256::digest(&body).into());
        assert!(previous.is_none(), "duplicate entry {entry:?}");
    }
    let names: Vec<&str> = archive
        .files
        .iter()
        .map(|f: &NsisFileEntry| f.name.as_str())
        .collect();
    assert_eq!(recovered, expected, "recovered {names:?} from {build:?}");
}

#[test]
fn makensis_solid_lzma_round_trips() {
    round_trip(Build {
        compressor: "lzma",
        method: NsisCompression::Lzma,
        solid: true,
        unicode: true,
    });
}

#[test]
fn makensis_solid_zlib_round_trips() {
    round_trip(Build {
        compressor: "zlib",
        method: NsisCompression::Deflate,
        solid: true,
        unicode: true,
    });
}

#[test]
fn makensis_solid_bzip2_round_trips() {
    round_trip(Build {
        compressor: "bzip2",
        method: NsisCompression::Bzip2,
        solid: true,
        unicode: true,
    });
}

#[test]
fn makensis_solid_lzma_ansi_round_trips() {
    round_trip(Build {
        compressor: "lzma",
        method: NsisCompression::Lzma,
        solid: true,
        unicode: false,
    });
}

#[test]
fn makensis_non_solid_lzma_round_trips() {
    round_trip(Build {
        compressor: "lzma",
        method: NsisCompression::Lzma,
        solid: false,
        unicode: true,
    });
}

#[test]
fn makensis_non_solid_zlib_round_trips() {
    round_trip(Build {
        compressor: "zlib",
        method: NsisCompression::Deflate,
        solid: false,
        unicode: true,
    });
}

#[test]
fn makensis_non_solid_bzip2_round_trips() {
    round_trip(Build {
        compressor: "bzip2",
        method: NsisCompression::Bzip2,
        solid: false,
        unicode: true,
    });
}
