#![cfg(feature = "chain")]
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract_to;
use disrobe_core::chain::Pass as _;
use disrobe_core::{Artifact, Rung};

const REFERENCE_VECTORS: &str = include_str!("fixtures/stuffit/method8-xadmaster-vectors.txt");
const REFERENCE_ARCHIVE_HEX: &str =
    include_str!("fixtures/stuffit/stuffit-method8-xadmaster.sit.hex");

struct ReferenceVector {
    compressed: Vec<u8>,
    expected: Vec<u8>,
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| {
            let digits: &str = std::str::from_utf8(pair).expect("reference hex is ASCII");
            u8::from_str_radix(digits, 16).expect("reference hex byte is valid")
        })
        .collect()
}

fn decode_compressed(encoded: &str) -> Vec<u8> {
    let Some(specification) = encoded.strip_prefix("codes:") else {
        return decode_hex(encoded);
    };
    let mut bits: Vec<u8> = Vec::new();
    for field in specification.split(',') {
        let (code_and_width, repeat_text): (&str, &str) =
            field.split_once('*').unwrap_or((field, "1"));
        let (code_text, width_text): (&str, &str) = code_and_width
            .split_once('@')
            .expect("code vector names its width");
        let code: usize = code_text.parse().expect("code vector value is valid");
        let width: usize = width_text.parse().expect("code vector width is valid");
        let repeat: usize = repeat_text
            .parse()
            .expect("code vector repetition count is valid");
        for _ in 0..repeat {
            for shift in 0..width {
                bits.push(
                    u8::try_from((code >> shift) & 1).expect("one packed method 8 bit fits in u8"),
                );
            }
        }
    }
    bits.chunks(8)
        .map(|chunk: &[u8]| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |value: u8, (shift, bit): (usize, &u8)| {
                    value | (*bit << shift)
                })
        })
        .collect()
}

fn reference_vector(name: &str) -> ReferenceVector {
    let line: &str = REFERENCE_VECTORS
        .lines()
        .find(|line: &&str| line.split('|').next() == Some(name))
        .expect("named method 8 reference vector exists");
    let fields: Vec<&str> = line.split('|').collect();
    assert_eq!(fields.len(), 4);
    let compressed: Vec<u8> = decode_compressed(fields[1]);
    let unit: Vec<u8> = decode_hex(fields[2]);
    let repeat: usize = fields[3]
        .parse()
        .expect("reference repetition count is valid");
    ReferenceVector {
        compressed,
        expected: unit.repeat(repeat),
    }
}

const fn empty_vector() -> ReferenceVector {
    ReferenceVector {
        compressed: Vec::new(),
        expected: Vec::new(),
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

fn method8_archive(resource: &ReferenceVector, data: &ReferenceVector) -> Vec<u8> {
    let mut record: Vec<u8> = vec![0; 112];
    record[0] = 8;
    record[1] = 8;
    record[2] = 6;
    record[3..9].copy_from_slice(b"mw.bin");
    record[84..88].copy_from_slice(&(resource.expected.len() as u32).to_be_bytes());
    record[88..92].copy_from_slice(&(data.expected.len() as u32).to_be_bytes());
    record[92..96].copy_from_slice(&(resource.compressed.len() as u32).to_be_bytes());
    record[96..100].copy_from_slice(&(data.compressed.len() as u32).to_be_bytes());
    record[100..102].copy_from_slice(&crc16_ibm(&resource.expected).to_be_bytes());
    record[102..104].copy_from_slice(&crc16_ibm(&data.expected).to_be_bytes());
    let header_crc: u16 = crc16_ibm(&record[..110]);
    record[110..112].copy_from_slice(&header_crc.to_be_bytes());
    record.extend_from_slice(&resource.compressed);
    record.extend_from_slice(&data.compressed);

    let mut archive: Vec<u8> = Vec::with_capacity(22 + record.len());
    archive.extend_from_slice(b"SIT!");
    archive.extend_from_slice(&1_u16.to_be_bytes());
    archive.extend_from_slice(&((22 + record.len()) as u32).to_be_bytes());
    archive.extend_from_slice(b"rLau");
    archive.extend_from_slice(&[0; 8]);
    archive.extend_from_slice(&record);
    archive
}

fn automatic_outputs(archive: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let artifact: Artifact = Artifact::new(Rung::Raw, archive.to_vec(), [0; 32]);
    disrobe_binfmt::chain_detector::CONTAINER_PASS
        .extract_children(&artifact)
        .expect("automatic method 8 extraction")
        .into_iter()
        .map(|child: disrobe_core::chain::ChildArtifact| (child.handle.relative_path, child.bytes))
        .collect()
}

#[test]
fn xadmaster_vectors_reach_data_and_resource_forks_through_both_callers() {
    let resource: ReferenceVector = reference_vector("reset");
    let data: ReferenceVector = reference_vector("dictionary");
    let archive: Vec<u8> = decode_hex(REFERENCE_ARCHIVE_HEX.trim());
    assert_eq!(archive.len(), 144);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-method8-reference")
            .expect("create StuffIt method 8 scratch directory");
    let direct: disrobe_binfmt::ExtractionResult =
        extract_to(ContainerKind::StuffIt, &archive, scratch.path())
            .expect("direct method 8 extraction");
    assert!(direct.integrity_violations.is_empty());
    assert_eq!(direct.entries.len(), 2);
    assert_eq!(
        std::fs::read(scratch.path().join("mw.bin")).expect("read direct data fork"),
        data.expected
    );
    assert_eq!(
        std::fs::read(scratch.path().join("mw.bin.rsrc")).expect("read direct resource fork"),
        resource.expected
    );

    let automatic: BTreeMap<String, Vec<u8>> = automatic_outputs(&archive);
    assert_eq!(automatic.len(), 2);
    assert_eq!(automatic.get("mw.bin"), Some(&data.expected));
    assert_eq!(automatic.get("mw.bin.rsrc"), Some(&resource.expected));
}

#[test]
fn width_transition_and_reset_vectors_are_deterministic() {
    let resource: ReferenceVector = reference_vector("initial-reset");
    let data: ReferenceVector = reference_vector("width-9-to-10");
    let archive: Vec<u8> = method8_archive(&resource, &data);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-method8-width")
            .expect("create method 8 width-transition directory");
    let direct: disrobe_binfmt::ExtractionResult =
        extract_to(ContainerKind::StuffIt, &archive, scratch.path())
            .expect("extract method 8 width-transition archive");
    assert!(
        direct.integrity_violations.is_empty(),
        "{:?}",
        direct.integrity_violations
    );
    let first: BTreeMap<String, Vec<u8>> = automatic_outputs(&archive);
    let second: BTreeMap<String, Vec<u8>> = automatic_outputs(&archive);
    assert_eq!(first, second);
    assert_eq!(first.get("mw.bin"), Some(&data.expected));
    assert_eq!(first.get("mw.bin.rsrc"), Some(&resource.expected));

    let repeated: ReferenceVector = reference_vector("repeated-resets");
    let repeated_archive: Vec<u8> = method8_archive(&empty_vector(), &repeated);
    assert_eq!(
        automatic_outputs(&repeated_archive).get("mw.bin"),
        Some(&repeated.expected)
    );
}
