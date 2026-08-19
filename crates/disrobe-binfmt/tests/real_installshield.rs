#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{
    InstallShieldArchive, InstallShieldCompression, InstallShieldFile, InstallShieldLayout,
    InstallShieldMemberState, walk_installshield,
};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

const USER1: &str = "wireplay-user1.cab";
const SYS1: &str = "wireplay-sys1.cab";
const CVE: &str = "cve-2015-1386.hdr";

const USER1_MANIFEST: &str =
    include_str!("../../../corpus/binfmt/installshield/wireplay-user1.cab.tsv");
const SYS1_MANIFEST: &str =
    include_str!("../../../corpus/binfmt/installshield/wireplay-sys1.cab.tsv");
const CVE_MANIFEST: &str =
    include_str!("../../../corpus/binfmt/installshield/cve-2015-1386.hdr.tsv");

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestRow {
    index: u32,
    disposition: String,
    path: String,
    expanded_size: u64,
    compressed_size: u64,
    sha256: String,
}

fn manifest_rows(text: &str) -> Vec<ManifestRow> {
    let mut rows: Vec<ManifestRow> = Vec::new();
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "manifest row: {line}");
        rows.push(ManifestRow {
            index: fields[0].parse().expect("manifest index"),
            disposition: fields[1].to_owned(),
            path: fields[2].to_owned(),
            expanded_size: fields[3].parse().expect("manifest expanded size"),
            compressed_size: fields[4].parse().expect("manifest compressed size"),
            sha256: fields[5].to_owned(),
        });
    }
    rows
}

fn fixture(name: &str) -> Vec<u8> {
    common::load_fixture("installshield", name)
        .unwrap_or_else(|| panic!("missing corpus/binfmt/installshield/{name}"))
}

const fn generous_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_entries: 4096,
        max_total_uncompressed: 64 * 1024 * 1024,
        max_per_entry_uncompressed: 16 * 1024 * 1024,
        max_per_entry_ratio: 1_000,
        max_aggregate_ratio: 1_000,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const fn disposition(state: InstallShieldMemberState) -> &'static str {
    match state {
        InstallShieldMemberState::Recovered => "recovered",
        InstallShieldMemberState::RefusedInvalidRecord => "invalid-record",
        InstallShieldMemberState::RefusedSplitMember => "split-member",
        InstallShieldMemberState::RefusedAbsentVolume => "absent-volume",
        InstallShieldMemberState::RefusedDataOutOfRange => "data-out-of-range",
        InstallShieldMemberState::RefusedAmbiguousFraming => "ambiguous-framing",
        InstallShieldMemberState::RefusedDecode => "decode-failed",
        InstallShieldMemberState::RefusedIntegrity => "integrity-mismatch",
        InstallShieldMemberState::RefusedQuota => "quota-exceeded",
        InstallShieldMemberState::RefusedDuplicatePath => "duplicate-path",
    }
}

fn grade_against_manifest(name: &str, manifest: &str) -> (usize, usize) {
    let bytes: Vec<u8> = fixture(name);
    let rows: Vec<ManifestRow> = manifest_rows(manifest);
    let archive: InstallShieldArchive =
        walk_installshield(&bytes, generous_quota()).expect("walk real cabinet");
    assert_eq!(
        archive.files.len(),
        rows.len(),
        "{name}: member count must match the reference inventory"
    );
    let mut recovered: usize = 0;
    for row in &rows {
        let file: &InstallShieldFile = archive
            .files
            .iter()
            .find(|candidate: &&InstallShieldFile| candidate.index == row.index)
            .unwrap_or_else(|| panic!("{name}: member {} is missing", row.index));
        assert_eq!(
            disposition(file.state),
            row.disposition,
            "{name}: member {} disposition",
            row.index
        );
        assert_eq!(
            file.expanded_size, row.expanded_size,
            "{name}: member {} declared expanded size",
            row.index
        );
        assert_eq!(
            file.compressed_size, row.compressed_size,
            "{name}: member {} declared compressed size",
            row.index
        );
        assert_eq!(
            file.path, row.path,
            "{name}: member {} carve path",
            row.index
        );
        if row.disposition == "recovered" {
            assert_eq!(
                u64::try_from(file.data.len()).expect("length"),
                row.expanded_size,
                "{name}: member {} recovered length",
                row.index
            );
            assert_eq!(
                hex_sha256(&file.data),
                row.sha256,
                "{name}: member {} recovered content",
                row.index
            );
            recovered += 1;
        } else {
            assert!(
                file.data.is_empty(),
                "{name}: refused member {} must carry no bytes",
                row.index
            );
            assert!(
                !file.detail.is_empty(),
                "{name}: refused member {} must state a reason",
                row.index
            );
        }
    }
    (recovered, rows.len())
}

#[test]
fn wireplay_user_cabinet_matches_the_reference_inventory() {
    let bytes: Vec<u8> = fixture(USER1);
    assert_eq!(bytes.len(), 9_668);
    assert_eq!(
        hex_sha256(&bytes),
        "30ee8b8ad02d6e1a5e1a67de039303236b7f01b4b31cea722b99255240d3834d"
    );
    assert_eq!(detect_container(&bytes), Some(ContainerKind::InstallShield));
    let archive: InstallShieldArchive = walk_installshield(&bytes, generous_quota()).expect("walk");
    assert_eq!(archive.header.version, 0x0100_0004);
    assert_eq!(archive.header.major_version, 0);
    assert_eq!(archive.header.layout, InstallShieldLayout::Legacy);
    assert_eq!(archive.header.directory_count, 1);
    assert_eq!(archive.header.file_count, 8);
    assert_eq!(archive.file_groups.len(), 7);
    assert_eq!(archive.volume.first_file_index, 0);
    assert_eq!(archive.volume.last_file_index, 7);
    let (recovered, total): (usize, usize) = grade_against_manifest(USER1, USER1_MANIFEST);
    assert_eq!((recovered, total), (3, 8));
    for file in archive.recovered() {
        assert_eq!(
            file.compression,
            InstallShieldCompression::FullFlushDeflate,
            "{} framing",
            file.path
        );
    }
}

#[test]
fn wireplay_system_cabinet_matches_the_reference_inventory() {
    let bytes: Vec<u8> = fixture(SYS1);
    assert_eq!(bytes.len(), 386_984);
    assert_eq!(
        hex_sha256(&bytes),
        "6036fe6e7eb763c80a63de3765b0a33e6498cd968ba582d2bd2d7bb1418a7dc2"
    );
    let archive: InstallShieldArchive = walk_installshield(&bytes, generous_quota()).expect("walk");
    assert_eq!(archive.header.file_count, 7);
    assert_eq!(archive.file_groups.len(), 5);
    let (recovered, total): (usize, usize) = grade_against_manifest(SYS1, SYS1_MANIFEST);
    assert_eq!((recovered, total), (7, 7));
    let multi_chunk: usize = archive
        .recovered()
        .filter(|file: &&InstallShieldFile| file.expanded_size > 64 * 1024)
        .count();
    assert_eq!(
        multi_chunk, 4,
        "the system cabinet must exercise the multi-chunk decode loop"
    );
    let case_pair: Vec<&str> = archive
        .recovered()
        .map(|file: &InstallShieldFile| file.path.as_str())
        .filter(|path: &&str| path.to_ascii_lowercase().ends_with("_isres.dll"))
        .collect();
    assert_eq!(case_pair.len(), 2);
    assert_ne!(case_pair[0], case_pair[1]);
}

#[test]
fn cve_2015_1386_header_recovers_nothing_and_names_the_traversal() {
    let bytes: Vec<u8> = fixture(CVE);
    assert_eq!(bytes.len(), 3_113);
    assert_eq!(
        hex_sha256(&bytes),
        "6ed3cc2918dfb2611a112db5c88b40765c8ecdc661df40bc3c5fec0f176810c8"
    );
    let archive: InstallShieldArchive = walk_installshield(&bytes, generous_quota()).expect("walk");
    assert_eq!(archive.header.version, 0x0100_5201);
    assert_eq!(archive.header.major_version, 5);
    assert_eq!(archive.header.layout, InstallShieldLayout::Legacy);
    let (recovered, total): (usize, usize) = grade_against_manifest(CVE, CVE_MANIFEST);
    assert_eq!((recovered, total), (0, 4));
    let traversal: &InstallShieldFile = archive
        .files
        .iter()
        .find(|file: &&InstallShieldFile| file.path.contains("/../"))
        .expect("the traversal member must stay visible in the report");
    assert_eq!(
        traversal.state,
        InstallShieldMemberState::RefusedAbsentVolume
    );
    assert!(traversal.path.ends_with("/tmp/moo"));
    assert!(
        disrobe_binfmt::quota::sanitize_entry_path(&traversal.path).is_err(),
        "the traversal path must also be refused by the shared entry-path sanitiser"
    );
}

#[test]
fn real_cabinets_extract_to_disk_with_exact_bytes() {
    for (name, manifest) in [(USER1, USER1_MANIFEST), (SYS1, SYS1_MANIFEST)] {
        let bytes: Vec<u8> = fixture(name);
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-installshield-real")
                .expect("create scratch directory");
        let result: ExtractionResult =
            extract_to(ContainerKind::InstallShield, &bytes, scratch.path())
                .expect("extract real cabinet");
        assert_eq!(result.kind, ContainerKind::InstallShield);
        let expected: Vec<ManifestRow> = manifest_rows(manifest)
            .into_iter()
            .filter(|row: &ManifestRow| row.disposition == "recovered")
            .collect();
        assert_eq!(result.entries.len(), expected.len(), "{name}: entry count");
        for row in &expected {
            let on_disk: Vec<u8> =
                std::fs::read(scratch.path().join(&row.path)).expect("recovered member on disk");
            assert_eq!(hex_sha256(&on_disk), row.sha256, "{name}: {}", row.path);
            let entry: &disrobe_binfmt::extract::ExtractedEntry = result
                .entries
                .iter()
                .find(|candidate| candidate.name == row.path)
                .unwrap_or_else(|| panic!("{name}: entry {} missing", row.path));
            assert_eq!(entry.uncompressed_size, row.expanded_size);
            assert_eq!(entry.compressed_size, row.compressed_size);
        }
    }
}

#[test]
fn cve_2015_1386_header_writes_nothing_to_disk() {
    let bytes: Vec<u8> = fixture(CVE);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-installshield-cve")
            .expect("create scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::InstallShield, &bytes, scratch.path())
        .expect("extract the CVE header");
    assert!(result.entries.is_empty());
    assert_eq!(result.quota.entries_accepted, 0);
    let written: Vec<std::path::PathBuf> = walk_paths(scratch.path());
    assert!(
        written.is_empty(),
        "the CVE artifact must produce no output files, found {written:?}"
    );
    assert!(
        result
            .integrity_violations
            .iter()
            .any(|line: &String| line.contains("absent-volume") && line.contains("/tmp/moo"))
    );
}

fn walk_paths(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path: std::path::PathBuf = entry.path();
        if path.is_dir() {
            out.extend(walk_paths(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn repeated_walks_are_byte_identical() {
    for name in [USER1, SYS1, CVE] {
        let bytes: Vec<u8> = fixture(name);
        let first: InstallShieldArchive =
            walk_installshield(&bytes, generous_quota()).expect("first walk");
        let second: InstallShieldArchive =
            walk_installshield(&bytes, generous_quota()).expect("second walk");
        assert_eq!(
            first.files, second.files,
            "{name}: walk is not deterministic"
        );
        assert_eq!(first.file_groups, second.file_groups);
        assert_eq!(first.integrity_violations, second.integrity_violations);
    }
}

#[test]
fn every_truncation_of_a_real_cabinet_refuses_without_panicking() {
    let bytes: Vec<u8> = fixture(USER1);
    let mut recovered_any: bool = false;
    for cut in (0..bytes.len()).step_by(97) {
        match walk_installshield(&bytes[..cut], generous_quota()) {
            Ok(archive) => {
                for file in &archive.files {
                    if file.state.is_recovered() {
                        recovered_any = true;
                        assert_eq!(
                            u64::try_from(file.data.len()).expect("length"),
                            file.expanded_size
                        );
                    }
                }
            }
            Err(error) => {
                assert!(!format!("{error}").is_empty());
            }
        }
    }
    assert!(
        recovered_any,
        "at least one prefix must still carry a complete member"
    );
}

#[cfg(feature = "chain")]
mod chain {
    use super::{SYS1, USER1, fixture, manifest_rows};
    use disrobe_core::chain::{
        ChildArtifact, DetectContext, DetectVerdict, Detector as _, Pass as _,
    };
    use disrobe_core::{Artifact, Rung};

    #[test]
    fn container_pass_tags_and_expands_a_real_cabinet() {
        let bytes: Vec<u8> = fixture(USER1);
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let verdict: DetectVerdict = disrobe_binfmt::chain_detector::ContainerDetector
            .detect(&ctx)
            .expect("installshield must be tagged by the container detector");
        assert_eq!(verdict.format_tag, "installshield");
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = disrobe_binfmt::chain_detector::CONTAINER_PASS
            .extract_children(&artifact)
            .expect("installshield children");
        assert_eq!(children.len(), 3);
        let manifest: Vec<String> = manifest_rows(super::USER1_MANIFEST)
            .into_iter()
            .filter(|row| row.disposition == "recovered")
            .map(|row| row.path)
            .collect();
        for child in &children {
            assert!(
                manifest.contains(&child.handle.relative_path),
                "unexpected child {}",
                child.handle.relative_path
            );
        }
        let rendered: Artifact = disrobe_binfmt::chain_detector::CONTAINER_PASS
            .run(&artifact)
            .expect("installshield manifest");
        let text: String =
            String::from_utf8(rendered.envelope.as_slice().to_vec()).expect("utf8 manifest");
        assert!(text.contains("format=installshield"));
        assert!(text.contains("USERSETUP_LANGINDOSIND/license.txt"));
    }

    #[test]
    fn chain_children_carry_the_recovered_bytes_of_the_system_cabinet() {
        let bytes: Vec<u8> = fixture(SYS1);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = disrobe_binfmt::chain_detector::CONTAINER_PASS
            .extract_children(&artifact)
            .expect("installshield children");
        assert_eq!(children.len(), 7);
        let total: usize = children
            .iter()
            .map(|child: &ChildArtifact| child.bytes.len())
            .sum();
        assert_eq!(total, 1_006_350);
    }
}
