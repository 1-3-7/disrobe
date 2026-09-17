#![allow(clippy::expect_used)]

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/stuffit/stuffit-method5.sit");
const MANIFEST: &str = include_str!("fixtures/stuffit/MANIFEST_METHOD5.tsv");

#[derive(Debug, Clone)]
struct ManifestRow {
    path: String,
    fork: String,
    method: u8,
    logical_size: usize,
    crc16: u16,
    sha256: String,
}

fn manifest_rows() -> Vec<ManifestRow> {
    MANIFEST
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "manifest row must carry seven fields");
            ManifestRow {
                path: fields[0].to_owned(),
                fork: fields[1].to_owned(),
                method: fields[2].parse::<u8>().expect("manifest method"),
                logical_size: fields[3].parse::<usize>().expect("manifest logical size"),
                crc16: fields[4].parse::<u16>().expect("manifest crc16"),
                sha256: fields[5].to_owned(),
            }
        })
        .collect()
}

#[test]
fn stuffit_method5_forks_match_the_unar_manifest() {
    assert_eq!(FIXTURE.len(), 2838);
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE)),
        "3679e712dd140778e76f7faee1183ed95f9af41a40e7628234b743c7c04053ee"
    );
    assert_eq!(detect_container(FIXTURE), Some(ContainerKind::StuffIt));

    let rows: Vec<ManifestRow> = manifest_rows();
    assert_eq!(rows.len(), 3, "the pinned archive carries three forks");
    assert!(
        rows.iter().all(|row: &ManifestRow| row.method == 5),
        "every pinned fork must be method 5"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-method5")
            .expect("create method 5 scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::StuffIt, FIXTURE, scratch.path())
        .expect("extract StuffIt method 5 fixture");
    assert!(result.integrity_violations.is_empty());

    let expected_paths: std::collections::BTreeSet<String> = rows
        .iter()
        .map(|row: &ManifestRow| match row.fork.as_str() {
            "rsrc" => format!("{}.rsrc", row.path),
            _ => row.path.clone(),
        })
        .collect();
    let recovered_paths: std::collections::BTreeSet<String> = result
        .entries
        .iter()
        .map(|entry: &disrobe_binfmt::ExtractedEntry| entry.name.clone())
        .collect();
    assert_eq!(
        recovered_paths, expected_paths,
        "recovered member set must equal the reference member set"
    );

    for row in &rows {
        let on_disk: String = match row.fork.as_str() {
            "rsrc" => format!("{}.rsrc", row.path),
            _ => row.path.clone(),
        };
        let recovered: Vec<u8> =
            std::fs::read(scratch.path().join(&on_disk)).expect("read recovered fork");
        assert_eq!(
            recovered.len(),
            row.logical_size,
            "{on_disk}: recovered length must equal the reference length"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&recovered)),
            row.sha256,
            "{on_disk}: recovered bytes must equal the unar reference bytes"
        );
        assert_eq!(
            crc16_ibm(&recovered),
            row.crc16,
            "{on_disk}: recovered bytes must satisfy the CRC-16 StuffIt itself stored"
        );
    }
}

fn crc16_ibm(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0u16, |mut crc: u16, byte: &u8| {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
        crc
    })
}
