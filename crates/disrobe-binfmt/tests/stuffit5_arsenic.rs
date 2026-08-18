#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{
    Sit5Archive, Sit5Compression, Sit5Entry, Sit5Fork, Sit5Metadata, detect_stuffit, parse_sit5,
    sit5_fork_bytes_bounded,
};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/stuffit/stuffit5-651.sit");
const MANIFEST: &str = include_str!("fixtures/stuffit/MANIFEST_SIT5.tsv");
const MAX_OUTPUT: usize = 1 << 20;

#[derive(Debug, Clone)]
struct Row {
    method: u8,
    logical_size: usize,
    crc16: u16,
    sha256: String,
}

fn manifest() -> BTreeMap<(String, String), Row> {
    MANIFEST
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "manifest row must carry seven fields");
            (
                (fields[0].to_owned(), fields[1].to_owned()),
                Row {
                    method: fields[2].parse::<u8>().expect("manifest method"),
                    logical_size: fields[3].parse::<usize>().expect("manifest size"),
                    crc16: fields[4].parse::<u16>().expect("manifest crc16"),
                    sha256: fields[5].to_owned(),
                },
            )
        })
        .collect()
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

#[test]
fn stuffit5_forks_match_the_unar_manifest() {
    assert_eq!(FIXTURE.len(), 2776);
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE)),
        "238f1e460cd7aa71fa21e31d06e741265df2cafb8151614488baee9af2e4990a"
    );
    assert!(detect_stuffit(FIXTURE).is_some());
    assert_eq!(detect_container(FIXTURE), Some(ContainerKind::StuffIt));

    let expected: BTreeMap<(String, String), Row> = manifest();
    assert_eq!(expected.len(), 9, "the pinned archive carries nine forks");
    assert_eq!(
        expected
            .values()
            .filter(|row: &&Row| row.method == 15)
            .count(),
        5,
        "five of the nine forks are Arsenic"
    );

    let archive: Sit5Archive = parse_sit5(FIXTURE).expect("parse StuffIt 5 fixture");
    let mut seen: BTreeMap<(String, String), Row> = BTreeMap::new();

    for entry in &archive.entries {
        for (label, fork) in [
            ("rsrc", entry.resource.as_ref()),
            ("data", entry.data.as_ref()),
        ] {
            let Some(fork): Option<&Sit5Fork> = fork else {
                continue;
            };
            let key: (String, String) = (entry.path.clone(), label.to_owned());
            let row: &Row = expected.get(&key).expect("recovered an unexpected fork");

            let recovered: Vec<u8> =
                sit5_fork_bytes_bounded(FIXTURE, fork, MAX_OUTPUT).expect("decode StuffIt 5 fork");
            assert_eq!(
                recovered.len(),
                row.logical_size,
                "{key:?}: recovered length must equal the reference length"
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(&recovered)),
                row.sha256,
                "{key:?}: recovered bytes must equal the unar reference bytes"
            );

            match fork.compression {
                Sit5Compression::Stored => {
                    assert_eq!(row.method, 0, "{key:?}: reference calls this stored");
                    assert_eq!(
                        crc16_ibm(&recovered),
                        row.crc16,
                        "{key:?}: a stored fork must satisfy its stored CRC-16"
                    );
                }
                Sit5Compression::Arsenic => {
                    assert_eq!(row.method, 15, "{key:?}: reference calls this Arsenic");
                    assert_eq!(
                        row.crc16, 0,
                        "{key:?}: StuffIt 5 leaves the CRC-16 field zero for Arsenic"
                    );
                }
            }
            seen.insert(key, row.clone());
        }
    }

    let recovered_keys: Vec<&(String, String)> = seen.keys().collect();
    let expected_keys: Vec<&(String, String)> = expected.keys().collect();
    assert_eq!(
        recovered_keys, expected_keys,
        "recovered fork set must equal the reference fork set"
    );
}

#[test]
fn extract_to_publishes_every_stuffit5_fork() {
    let expected: BTreeMap<(String, String), Row> = manifest();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit5-extract-to")
            .expect("create scratch directory");
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(ContainerKind::StuffIt, FIXTURE, scratch.path())
            .expect("extract StuffIt 5 fixture through the container route");
    assert!(result.integrity_violations.is_empty());
    assert_eq!(
        result.entries.len(),
        expected.len(),
        "extract_to must publish one member per reference fork, not a single carved archive"
    );

    for ((path, fork), row) in &expected {
        let on_disk: String = match fork.as_str() {
            "rsrc" => format!("{path}.rsrc"),
            _ => path.clone(),
        };
        let recovered: Vec<u8> =
            std::fs::read(scratch.path().join(&on_disk)).expect("read published fork");
        assert_eq!(
            format!("{:x}", Sha256::digest(&recovered)),
            row.sha256,
            "{on_disk}: published bytes must equal the unar reference bytes"
        );
    }

    assert!(
        !scratch.path().join("archive.sit").exists(),
        "a parsed StuffIt 5 archive must not also be carved verbatim"
    );
}

#[test]
fn stuffit5_entry_metadata_matches_the_unar_reference() {
    const METADATA: &str = include_str!("fixtures/stuffit/MANIFEST_SIT5_METADATA.tsv");

    let expected: BTreeMap<String, Sit5Metadata> = METADATA
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "metadata row must carry six fields");
            (
                fields[0].to_owned(),
                Sit5Metadata {
                    created_mac_epoch: fields[1].parse::<u32>().expect("created"),
                    modified_mac_epoch: fields[2].parse::<u32>().expect("modified"),
                    file_type: fields[3].parse::<u32>().expect("file type"),
                    file_creator: fields[4].parse::<u32>().expect("file creator"),
                    finder_flags: fields[5].parse::<u16>().expect("finder flags"),
                },
            )
        })
        .collect();
    assert_eq!(expected.len(), 6, "the pinned archive carries six members");

    let archive: Sit5Archive = parse_sit5(FIXTURE).expect("parse StuffIt 5 fixture");
    assert_eq!(archive.entries.len(), expected.len());
    for entry in &archive.entries {
        let reference: &Sit5Metadata = expected
            .get(&entry.path)
            .expect("recovered a member the reference does not list");
        assert_eq!(
            entry.metadata, *reference,
            "{}: recovered metadata must equal what unar reports",
            entry.path
        );
    }

    let text: &Sit5Metadata = expected
        .get("testfile.txt")
        .expect("the differing-timestamp member");
    assert_ne!(
        text.created_mac_epoch, text.modified_mac_epoch,
        "this member must keep distinct timestamps, otherwise swapping the two date fields \
         would pass every assertion above"
    );
    assert_eq!(
        u64::from(text.modified_mac_epoch) - u64::from(text.created_mac_epoch),
        697_156_646,
        "the gap between this member's two timestamps must equal the gap unar reports between \
         the same two dates; a gap is invariant under the timezone unar renders through, so it \
         grades the date fields against unar without pinning either side to a machine's zone"
    );
    let image: &Sit5Metadata = expected.get("Test Image").expect("the picture member");
    assert_ne!(
        image.file_type, expected["Test Text"].file_type,
        "two members must differ in file type, otherwise reading a constant would pass"
    );
    assert_ne!(
        image.finder_flags, expected["Test Text"].finder_flags,
        "two members must differ in Finder flags, otherwise reading a constant would pass"
    );
}

#[test]
fn stuffit5_rejects_malformed_containers() {
    assert!(parse_sit5(b"not a stuffit 5 archive at all").is_err());
    assert!(parse_sit5(&FIXTURE[..FIXTURE.len() / 2]).is_err());

    let mut wrong_version: Vec<u8> = FIXTURE.to_vec();
    wrong_version[82] = 4;
    let error: disrobe_binfmt::Error =
        parse_sit5(&wrong_version).expect_err("a non-5 archive version must be refused");
    assert!(
        error.to_string().contains("archive version 4"),
        "expected a version refusal, got {error}"
    );

    let mut broken_entry_crc: Vec<u8> = FIXTURE.to_vec();
    broken_entry_crc[114 + 34] ^= 0xff;
    let error: disrobe_binfmt::Error =
        parse_sit5(&broken_entry_crc).expect_err("a mutated entry header must be refused");
    assert!(
        error.to_string().contains("header CRC mismatch"),
        "expected a header CRC refusal, got {error}"
    );

    let mut broken_marker: Vec<u8> = FIXTURE.to_vec();
    broken_marker[114] ^= 0xff;
    assert!(parse_sit5(&broken_marker).is_err());
}

#[test]
fn stuffit5_arsenic_forks_fail_closed_on_corruption_and_caps() {
    let archive: Sit5Archive = parse_sit5(FIXTURE).expect("parse StuffIt 5 fixture");
    let entry: &Sit5Entry = archive
        .entries
        .iter()
        .find(|entry: &&Sit5Entry| {
            entry
                .data
                .as_ref()
                .is_some_and(|fork: &Sit5Fork| fork.compression == Sit5Compression::Arsenic)
        })
        .expect("an Arsenic data fork");
    let fork: &Sit5Fork = entry.data.as_ref().expect("data fork");
    let expected_len: usize =
        usize::try_from(fork.uncompressed_len).expect("arsenic output length");

    let baseline: Vec<u8> =
        sit5_fork_bytes_bounded(FIXTURE, fork, MAX_OUTPUT).expect("arsenic baseline decode");
    assert_eq!(baseline.len(), expected_len);

    let error: disrobe_binfmt::Error = sit5_fork_bytes_bounded(FIXTURE, fork, expected_len - 1)
        .expect_err("an output cap below the declared length must be refused");
    assert!(
        error.to_string().contains("exceeds cap"),
        "expected an output cap refusal, got {error}"
    );

    let start: usize = fork.data_offset;
    let end: usize = start + fork.compressed_len as usize;
    let mut refused: usize = 0;
    let mut inert: usize = 0;
    for index in start..end {
        let mut corrupted: Vec<u8> = FIXTURE.to_vec();
        corrupted[index] ^= 0x01;
        match sit5_fork_bytes_bounded(&corrupted, fork, MAX_OUTPUT) {
            Ok(decoded) => {
                assert_eq!(
                    decoded, baseline,
                    "byte {index}: an accepted corruption must reproduce the reference bytes"
                );
                inert += 1;
            }
            Err(_) => refused += 1,
        }
    }
    assert_eq!(
        refused + inert,
        end - start,
        "every corruption is either refused or provably inert"
    );
    assert!(
        refused > 0,
        "the Arsenic CRC-32 trailer must refuse corrupted streams"
    );
}
