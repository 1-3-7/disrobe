#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write as _;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract_to;
use disrobe_core::chain::Pass as _;
use disrobe_core::{Artifact, Rung};

const RAR_STORED: &[u8] = include_bytes!("../../../corpus/binfmt/rar/store-rar4.rar");
const RAR_REFUSED: &[u8] =
    include_bytes!("../../../corpus/binfmt/rar/hostile-filter-staticdata-rar3.rar");
const ARJ_STORED: &[u8] = include_bytes!("../../../corpus/binfmt/arj/method0.arj");
const ARJ_REFUSED: &[u8] = include_bytes!("../../../corpus/binfmt/arj/garbled.arj");
const LZH_PARTIAL: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/generated_pm1.pma");
const ARC_METHODS: &[u8] = include_bytes!("../../../corpus/binfmt/arc/methods.arc");
const INNOSETUP: &[u8] = include_bytes!("fixtures/innosetup/innosetup-6.3.3.exe");
const EROFS: &[u8] = include_bytes!("fixtures/erofs/lzma-compact-mixed.erofs");
const STUFFIT: &[u8] = include_bytes!("fixtures/stuffit/stuffit45-method13.sit");
const RPM: &[u8] = include_bytes!("fixtures/rpm/hello-v4-gzip.rpm");
const UEFI: &[u8] = include_bytes!("fixtures/uefi_fv/edk2_brotli_guided.fv");
const APPIMAGE: &[u8] =
    include_bytes!("../../../corpus/binfmt/appimage-type1/AppImageAssistant.AppImage");
const DOTNET: &[u8] =
    include_bytes!("../../../corpus/binfmt/dotnet-single-file/probe.v6.win-x64.exe");
const INSTALLSHIELD: &[u8] =
    include_bytes!("../../../corpus/binfmt/installshield/wireplay-user1.cab");

fn rar_with_refused_member() -> Vec<u8> {
    const RAR4_SIGNATURE_LEN: usize = 7;
    const RAR4_MAIN_HEADER_LEN: usize = 13;
    const RAR4_END_HEADER_LEN: usize = 7;

    let mut archive: Vec<u8> = RAR_STORED[..RAR_STORED.len() - RAR4_END_HEADER_LEN].to_vec();
    archive.extend_from_slice(
        &RAR_REFUSED
            [RAR4_SIGNATURE_LEN + RAR4_MAIN_HEADER_LEN..RAR_REFUSED.len() - RAR4_END_HEADER_LEN],
    );
    archive.extend_from_slice(&RAR_STORED[RAR_STORED.len() - RAR4_END_HEADER_LEN..]);
    archive
}

fn arj_local_member_offset(bytes: &[u8]) -> usize {
    let basic_len: usize = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    4 + basic_len + 4 + 2
}

fn arj_with_refused_member() -> Vec<u8> {
    const ARJ_END_MARKER_LEN: usize = 4;

    let mut archive: Vec<u8> = ARJ_STORED[..ARJ_STORED.len() - ARJ_END_MARKER_LEN].to_vec();
    archive.extend_from_slice(&ARJ_REFUSED[arj_local_member_offset(ARJ_REFUSED)..]);
    archive
}

fn zip_with_refused_path() -> Vec<u8> {
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for (name, bytes) in [
        ("first.bin", b"first".as_slice()),
        (".disrobe-user.bin", b"user-controlled".as_slice()),
        ("../refused.bin", b"refused".as_slice()),
        ("last.bin", b"last".as_slice()),
    ] {
        writer.start_file(name, options).expect("start ZIP member");
        writer.write_all(bytes).expect("write ZIP member");
    }
    writer.finish().expect("finish ZIP").into_inner()
}

fn zip_with_refused_quota() -> Vec<u8> {
    const OVER_LIMIT: u32 = 512 * 1024 * 1024 + 1;

    let mut archive: Vec<u8> = zip_with_members(&[
        ("first.bin", b"first"),
        ("quota.bin", b"small"),
        ("last.bin", b"last"),
    ]);
    let mut offset: usize = 0;
    while let Some(relative) = archive[offset..]
        .windows(4)
        .position(|window: &[u8]| window == b"PK\x01\x02")
    {
        let header: usize = offset + relative;
        let name_len: usize = usize::from(u16::from_le_bytes([
            archive[header + 28],
            archive[header + 29],
        ]));
        let name_start: usize = header + 46;
        if &archive[name_start..name_start + name_len] == b"quota.bin" {
            archive[header + 24..header + 28].copy_from_slice(&OVER_LIMIT.to_le_bytes());
            return archive;
        }
        offset = name_start + name_len;
    }
    panic!("quota ZIP central directory member");
}

fn zip_with_refused_duplicate() -> Vec<u8> {
    zip_with_members(&[
        ("duplicate.bin", b"first"),
        ("DUPLICATE.bin", b"second"),
        ("last.bin", b"last"),
    ])
}

fn zip_with_members(files: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for (name, bytes) in files {
        writer.start_file(*name, options).expect("start ZIP member");
        writer.write_all(bytes).expect("write ZIP member");
    }
    writer.finish().expect("finish ZIP").into_inner()
}

fn zip_with_many_members(count: u16) -> Vec<u8> {
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for index in 0..count {
        writer
            .start_file(format!("entry-{index:05}.bin"), options)
            .expect("start large-matrix ZIP member");
        writer
            .write_all(&index.to_le_bytes())
            .expect("write large-matrix ZIP member");
    }
    writer.finish().expect("finish large ZIP").into_inner()
}

fn tar_with_refused_path() -> Vec<u8> {
    let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("first.bin", b"first".as_slice()),
        ("../refused.bin", b"refused".as_slice()),
        ("last.bin", b"last".as_slice()),
    ] {
        let mut header: tar::Header = tar::Header::new_gnu();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).expect("TAR member size"));
        header.set_cksum();
        builder.append(&header, bytes).expect("append TAR member");
    }
    builder.into_inner().expect("finish TAR")
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn assert_archive_parity(kind: ContainerKind, bytes: Vec<u8>, partial: bool) {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("partial-archive-parity")
            .expect("create direct-extraction output directory");
    let direct: disrobe_binfmt::ExtractionResult = extract_to(kind, &bytes, scratch.path())
        .expect("direct extraction must retain recoverable members");
    if partial {
        assert!(
            !direct.integrity_violations.is_empty(),
            "the partial fixture must retain at least one named refusal"
        );
    }

    let expected_members: Vec<(String, [u8; 32])> = direct
        .entries
        .iter()
        .filter_map(|entry: &disrobe_binfmt::ExtractedEntry| {
            if entry.origin == disrobe_binfmt::ExtractedEntryOrigin::GeneratedSidecar {
                return None;
            }
            let path: &std::path::Path = entry.disk_path.as_deref()?;
            let bytes: Vec<u8> = std::fs::read(path).expect("read direct member bytes");
            Some((entry.name.clone(), hash(&bytes)))
        })
        .collect();
    assert!(
        !expected_members.is_empty(),
        "the fixture must retain at least one materialized member"
    );
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0; 32]);
    let children: Vec<disrobe_core::chain::ChildArtifact> =
        disrobe_binfmt::chain_detector::CONTAINER_PASS
            .extract_children(&artifact)
            .expect("automatic extraction must retain recoverable members");
    let actual_members: Vec<(String, [u8; 32])> = children
        .into_iter()
        .map(|child: disrobe_core::chain::ChildArtifact| {
            (child.handle.relative_path, hash(&child.bytes))
        })
        .collect();
    assert_eq!(actual_members, expected_members);

    let automatic_refusals: Vec<String> = disrobe_binfmt::chain_detector::CONTAINER_PASS
        .chain_refusals(&artifact)
        .expect("automatic extraction must retain ordered refusals");
    assert_eq!(automatic_refusals, direct.integrity_violations);
}

#[test]
fn direct_and_automatic_archive_extraction_publish_the_same_partial_recovery() {
    for (kind, bytes, partial) in [
        (ContainerKind::Arc, arc_with_refused_quota(), true),
        (ContainerKind::Rar, rar_with_refused_member(), true),
        (ContainerKind::Arj, arj_with_refused_member(), true),
        (ContainerKind::Lzh, LZH_PARTIAL.to_vec(), true),
        (ContainerKind::InnoSetup, INNOSETUP.to_vec(), false),
        (ContainerKind::InstallShield, INSTALLSHIELD.to_vec(), true),
        (ContainerKind::Zip, zip_with_refused_path(), true),
        (ContainerKind::Zip, zip_with_refused_quota(), true),
        (ContainerKind::Zip, zip_with_refused_duplicate(), true),
        (ContainerKind::Tar, tar_with_refused_path(), true),
        (ContainerKind::DotnetSingleFile, DOTNET.to_vec(), false),
        (ContainerKind::Erofs, EROFS.to_vec(), false),
        (ContainerKind::StuffIt, stuffit_with_refused_fork(), true),
        (ContainerKind::Rpm, RPM.to_vec(), false),
        (ContainerKind::AppImage, APPIMAGE.to_vec(), false),
        (ContainerKind::UefiFv, UEFI.to_vec(), false),
    ] {
        assert_archive_parity(kind, bytes, partial);
    }
}

#[test]
fn large_zip_preserves_linear_accounting_and_ordered_children() {
    const ENTRY_COUNT: u16 = 4_096;
    let archive: Vec<u8> = zip_with_many_members(ENTRY_COUNT);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("large-archive-accounting")
            .expect("create large extraction directory");
    let direct: disrobe_binfmt::ExtractionResult =
        extract_to(ContainerKind::Zip, &archive, scratch.path()).expect("extract large ZIP");
    assert_eq!(direct.entries.len(), usize::from(ENTRY_COUNT));
    assert_eq!(direct.quota.entries_accepted, usize::from(ENTRY_COUNT));
    assert_eq!(
        direct.quota.total_uncompressed_bytes,
        u64::from(ENTRY_COUNT) * 2
    );
    assert_eq!(direct.entries[0].name, "entry-00000.bin");
    assert_eq!(
        direct.entries.last().expect("last entry").name,
        "entry-04095.bin"
    );
    let artifact: Artifact = Artifact::new(Rung::Raw, archive, [0; 32]);
    let children: Vec<disrobe_core::chain::ChildArtifact> =
        disrobe_binfmt::chain_detector::CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract large ZIP through chain policy");
    assert_eq!(children.len(), usize::from(ENTRY_COUNT));
    assert_eq!(children[0].handle.relative_path, "entry-00000.bin");
    assert_eq!(
        children.last().expect("last child").handle.relative_path,
        "entry-04095.bin"
    );
}

fn arc_with_refused_quota() -> Vec<u8> {
    let parsed: disrobe_binfmt::containers::ArcArchive =
        disrobe_binfmt::containers::parse_arc(ARC_METHODS).expect("parse ARC method fixture");
    let entry: &disrobe_binfmt::containers::ArcEntry = parsed
        .entries
        .iter()
        .find(|entry: &&disrobe_binfmt::containers::ArcEntry| entry.method != 1)
        .expect("ARC member with an original-size field");
    assert!(parsed.entries.len() > 1);
    let original_size_offset: usize = entry.data_offset - 4;
    let mut archive: Vec<u8> = ARC_METHODS.to_vec();
    archive[original_size_offset..original_size_offset + 4]
        .copy_from_slice(&(512 * 1024 * 1024 + 1_u32).to_le_bytes());
    archive
}

fn stuffit_with_refused_fork() -> Vec<u8> {
    let parsed: disrobe_binfmt::containers::SitArchive =
        disrobe_binfmt::containers::parse_sit_classic(STUFFIT).expect("parse StuffIt fixture");
    assert!(parsed.entries.len() > 1);
    let fork: &disrobe_binfmt::containers::SitFork = parsed
        .entries
        .iter()
        .map(|entry: &disrobe_binfmt::containers::SitEntry| &entry.data)
        .find(|fork: &&disrobe_binfmt::containers::SitFork| fork.compressed_len > 0)
        .expect("StuffIt data fork");
    let mut archive: Vec<u8> = STUFFIT.to_vec();
    archive[fork.data_offset] ^= 1;
    archive
}
