#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{
    AppImageFormat, AppImageLayout, IsoEntryKind, IsoImage, parse_appimage, parse_iso,
};
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass as _;

const FIXTURE: &str = "AppImageAssistant.AppImage";

#[test]
fn official_type1_appimage_uses_rock_ridge_apprun_identity() {
    let bytes: Vec<u8> = common::load_fixture("appimage-type1", FIXTURE)
        .unwrap_or_else(|| panic!("missing corpus/binfmt/appimage-type1/{FIXTURE}"));
    assert_eq!(bytes.len(), 1_245_184);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "e78a149c2dd61becc92450bddbb0851c49867c6505330eb5ba8881c13f349c6e"
    );
    assert_eq!(detect_container(&bytes), Some(ContainerKind::AppImage));
    let layout: AppImageLayout = parse_appimage(&bytes).expect("parse official type 1 appimage");
    assert_eq!(layout.format, AppImageFormat::Type1Legacy);
}

#[test]
fn official_type1_regular_files_match_the_libarchive_manifest() {
    let bytes: Vec<u8> = common::load_fixture("appimage-type1", FIXTURE)
        .unwrap_or_else(|| panic!("missing corpus/binfmt/appimage-type1/{FIXTURE}"));
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-appimage-type1-real")
            .expect("create scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::AppImage, &bytes, scratch.path())
        .expect("extract official type 1 appimage");
    let parsed: IsoImage = parse_iso(&bytes).expect("parse official ISO tree");
    let manifest: &str = include_str!("../../../corpus/binfmt/appimage-type1/MANIFEST.tsv");
    let rows: Vec<&str> = manifest.lines().skip(1).collect();
    assert_eq!(rows.len(), 49);
    for row in rows {
        let fields: Vec<&str> = row.split('\t').collect();
        assert_eq!(fields.len(), 6, "manifest row: {row}");
        let path: &str = fields[0];
        let kind: &str = fields[1];
        let mode: u32 = u32::from_str_radix(fields[2], 8).expect("manifest mode");
        let logical_size: u64 = fields[3].parse().expect("manifest logical size");
        let expected_hash: &str = fields[4];
        let parsed_entry: &disrobe_binfmt::containers::IsoEntry = parsed
            .files
            .iter()
            .find(|entry| entry.path == path)
            .unwrap_or_else(|| panic!("parsed entry {path}"));
        assert_eq!(
            parsed_entry.mode.map(|value: u32| value & 0o7777),
            Some(mode)
        );
        if kind == "directory" {
            assert_eq!(parsed_entry.kind, IsoEntryKind::Directory);
            assert!(scratch.path().join(path).is_dir(), "directory for {path}");
            continue;
        }
        assert_eq!(parsed_entry.kind, IsoEntryKind::Regular);
        let recovered: Vec<u8> = std::fs::read(scratch.path().join(path))
            .unwrap_or_else(|error: std::io::Error| panic!("read {path}: {error}"));
        assert_eq!(recovered.len() as u64, logical_size, "size for {path}");
        assert_eq!(
            format!("{:x}", Sha256::digest(&recovered)),
            expected_hash,
            "hash for {path}"
        );
        let entry: &disrobe_binfmt::ExtractedEntry = result
            .entries
            .iter()
            .find(|entry: &&disrobe_binfmt::ExtractedEntry| entry.name == path)
            .unwrap_or_else(|| panic!("result entry {path}"));
        assert_eq!(entry.is_executable, mode & 0o111 != 0, "mode for {path}");
        if kind == "hardlink" {
            let target: &str = fields[5];
            let target_entry: &disrobe_binfmt::containers::IsoEntry = parsed
                .files
                .iter()
                .find(|candidate| candidate.path == target)
                .unwrap_or_else(|| panic!("hardlink target {target}"));
            assert_eq!(parsed_entry.serial, target_entry.serial);
            assert!(parsed_entry.link_count.is_some_and(|count: u32| count > 1));
            assert_eq!(
                recovered,
                std::fs::read(scratch.path().join(target)).expect("target body")
            );
        }
    }
    assert!(result.integrity_violations.is_empty());
}

#[cfg(feature = "chain")]
#[test]
fn official_type1_members_reach_the_registered_container_pass() {
    let bytes: Vec<u8> = common::load_fixture("appimage-type1", FIXTURE)
        .unwrap_or_else(|| panic!("missing corpus/binfmt/appimage-type1/{FIXTURE}"));
    let artifact: disrobe_core::Artifact =
        disrobe_core::Artifact::new(disrobe_core::Rung::Raw, bytes, [0; 32]);
    let children: Vec<disrobe_core::chain::ChildArtifact> =
        disrobe_binfmt::chain_detector::CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract AppImage chain children");
    assert_eq!(children.len(), 43);
    let app_run: &disrobe_core::chain::ChildArtifact = children
        .iter()
        .find(|child: &&disrobe_core::chain::ChildArtifact| child.handle.relative_path == "AppRun")
        .expect("AppRun chain child");
    assert_eq!(app_run.bytes.len(), 222);
    assert_eq!(
        format!("{:x}", Sha256::digest(&app_run.bytes)),
        "4ba7a49ad0828f43b92067ff0948de22503d90f98c32adb76b8729b0708bbc72"
    );
}
