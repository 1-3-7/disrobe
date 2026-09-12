#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Cursor;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::containers::{RecoveredRpm, RpmCompression, RpmFormat, recover_rpm};
use disrobe_binfmt::extract::{
    ExtractedEntry, ExtractionResult, extract_to, extract_to_with_quota,
};
use disrobe_binfmt::quota::ExtractionQuota;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/rpm/hello-v4-gzip.rpm");
const FIXTURE_SHA256: &str = "f815819b58f7e63273e1afde0140e3a66cb2a2cfe0655b7582f3d925908dd7d5";
const HELLO_PATH: &str = "usr/share/disrobe/hello.txt";
const HELLO_BYTES: &[u8] = b"hello from disrobe rpm fixture\n";
const README_PATH: &str = "usr/share/disrobe/README";
const README_BYTES: &[u8] = b"disrobe binfmt rpm extraction test payload\n";
const SCRIPT_PATH: &str = "usr/bin/disrobe-rpm-fixture";
const SCRIPT_BYTES: &[u8] = b"#!/bin/bash\necho aWQ= | base64 -d | bash\n";
const V3_FIXTURE: &[u8] = include_bytes!("fixtures/rpm/rpm-upstream-hello-v3.rpm");
const V3_FIXTURE_SHA256: &str = "43502376334c05c2263826d558dc0828a4dc8f6bc73da5b0cf32c83d7ef5b7cb";
const V4_UPSTREAM: &[u8] = include_bytes!("fixtures/rpm/rpm-upstream-hello-v4.rpm");
const V4_UPSTREAM_SHA256: &str = "e05a5191e214b1f05ae2448ebe493e55c6313ab68eaf040b83baa80e25f15d54";
const V6_FIXTURE: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-basic.rpm");
const V6_FIXTURE_SHA256: &str = "1aca2bf7a7111f5524f5a3ee492c9cac63d7fda15b8df2b6c264fa523a51ebf5";
const V6_BZIP2: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-bzip2.rpm");
const V6_EMPTY: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-empty.rpm");
const V6_FILE_TYPES: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-file-types.rpm");
const V6_GZIP: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-gzip.rpm");
const V6_HARDLINKS: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-hardlinks.rpm");
const V6_SIGNED: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-signed-rsa.rpm");
const V6_SOURCE: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-source.rpm");
const V6_XZ: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-xz.rpm");
const V6_ZSTD: &[u8] = include_bytes!("fixtures/rpm/rpm-v6-zstd.rpm");
const V4_LZMA: &[u8] = include_bytes!("fixtures/rpm/rpm-opensuse11-lzma.rpm");
const V4_STRIPPED: &[u8] = include_bytes!("fixtures/rpm/rpm-v4-stripped.rpm");
const V4_STRIPPED_SHA256: &str = "852c662ee77e42c9d43fc6a755b2760f01ef41888caf8cbd5f6af91680e8ddfa";
const V6_HARDLINK_MEMBERS: [(&str, u64, &str); 6] = [
    (
        "opt/rpm-hardlinks/alpha-1",
        21,
        "e6e2f3332fd79828ab3508486e5e6bc6e0a9f015e41841195331de406b2eb9c2",
    ),
    (
        "opt/rpm-hardlinks/alpha-2",
        21,
        "e6e2f3332fd79828ab3508486e5e6bc6e0a9f015e41841195331de406b2eb9c2",
    ),
    (
        "opt/rpm-hardlinks/alpha-3",
        21,
        "e6e2f3332fd79828ab3508486e5e6bc6e0a9f015e41841195331de406b2eb9c2",
    ),
    (
        "opt/rpm-hardlinks/beta-1",
        20,
        "ab570b52f4e0a6aea1971275921bc589f8e83539f9f92e0d1e5351095c8da320",
    ),
    (
        "opt/rpm-hardlinks/beta-2",
        20,
        "ab570b52f4e0a6aea1971275921bc589f8e83539f9f92e0d1e5351095c8da320",
    ),
    (
        "opt/rpm-hardlinks/standalone",
        11,
        "b585207374d0563a64277fb7ab1ca2cdfb46080af2a78c7808d66d35bf15cb5f",
    ),
];
type ReferenceFile = (
    String,
    rpm::FileType,
    Vec<u8>,
    bool,
    bool,
    Option<String>,
    u32,
);

#[test]
fn pinned_v4_gzip_rpm_extracts_identical_files() {
    let digest: String = format!("{:x}", Sha256::digest(FIXTURE));
    assert_eq!(digest, FIXTURE_SHA256, "fixture bytes changed");
    assert_eq!(&FIXTURE[..4], &[0xed, 0xab, 0xee, 0xdb]);

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, FIXTURE, tmp.path()).expect("extract rpm");
    assert_eq!(result.kind, ContainerKind::Rpm);
    assert!(
        result.integrity_violations.is_empty(),
        "unexpected integrity violations: {:?}",
        result.integrity_violations
    );

    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    for (name, expected, executable) in [
        (HELLO_PATH, HELLO_BYTES, false),
        (README_PATH, README_BYTES, false),
        (SCRIPT_PATH, SCRIPT_BYTES, true),
    ] {
        let entry: &&ExtractedEntry = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing RPM member `{name}`"));
        let path: &std::path::Path = entry
            .disk_path
            .as_deref()
            .unwrap_or_else(|| panic!("RPM member `{name}` has no disk path"));
        let actual: Vec<u8> = std::fs::read(path)
            .unwrap_or_else(|error: std::io::Error| panic!("read `{name}`: {error}"));
        assert_eq!(actual, expected, "RPM member `{name}` bytes differ");
        assert_eq!(
            entry.is_executable, executable,
            "RPM member `{name}` executable bit differs"
        );
    }
}

#[test]
fn truncated_v4_rpm_fails_before_creating_files() {
    let truncated: &[u8] = &FIXTURE[..FIXTURE.len() - 8];
    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let error: disrobe_binfmt::Error =
        extract_to(ContainerKind::Rpm, truncated, tmp.path()).expect_err("truncated RPM must fail");
    assert!(error.to_string().contains("rpm archive parse failed"));
    assert_eq!(
        std::fs::read_dir(tmp.path()).expect("read output").count(),
        0,
        "RPM validation must finish before materialization"
    );
}

#[test]
fn direct_rpm_quota_failure_precedes_member_writes() {
    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let quota: ExtractionQuota = ExtractionQuota {
        max_total_uncompressed: 1,
        ..ExtractionQuota::default_safe()
    };
    let error: disrobe_binfmt::Error =
        extract_to_with_quota(ContainerKind::Rpm, FIXTURE, tmp.path(), quota)
            .expect_err("RPM expansion must exceed the quota");
    assert!(error.to_string().contains("quota"), "{error}");
    assert_eq!(
        std::fs::read_dir(tmp.path())
            .expect("read output directory")
            .count(),
        0
    );
}

#[test]
fn corrupted_v3_payload_fails_md5_before_creating_files() {
    let mut corrupted: Vec<u8> = V3_FIXTURE.to_vec();
    let last: usize = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Rpm, &corrupted, tmp.path())
        .expect_err("corrupted RPM must fail");
    assert!(
        error
            .to_string()
            .contains("RPM v3 header and payload MD5 mismatch"),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read_dir(tmp.path()).expect("read output").count(),
        0,
        "RPM digest validation must finish before materialization"
    );
}

#[test]
fn corrupted_v6_payload_fails_sha256_before_creating_files() {
    let mut corrupted: Vec<u8> = V6_FIXTURE.to_vec();
    let last: usize = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Rpm, &corrupted, tmp.path())
        .expect_err("corrupted RPM must fail");
    assert!(
        error
            .to_string()
            .contains("compressed payload SHA-256 mismatch"),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read_dir(tmp.path()).expect("read output").count(),
        0,
        "RPM digest validation must finish before materialization"
    );
}

fn normalized_reference_path(path: &std::path::Path) -> String {
    path.components()
        .filter_map(|component: std::path::Component<'_>| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<&str>>()
        .join("/")
}

fn assert_extract_matches_reference(
    bytes: &[u8],
    expected_sha256: &str,
    expected_format: RpmFormat,
    expected_compression: RpmCompression,
) {
    let digest: String = format!("{:x}", Sha256::digest(bytes));
    assert_eq!(digest, expected_sha256, "fixture bytes changed");
    let recovered: RecoveredRpm =
        recover_rpm(bytes, 64 * 1024 * 1024).unwrap_or_else(|error: disrobe_binfmt::Error| {
            panic!("recover `{expected_sha256}`: {error}")
        });
    assert_eq!(recovered.format, expected_format, "format differs");
    assert_eq!(
        recovered.compression, expected_compression,
        "compression differs"
    );

    let mut cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let package: rpm::Package = rpm::Package::parse(&mut cursor).expect("reference parser");
    let reference_files: Vec<ReferenceFile> = package
        .files()
        .expect("reference file iterator")
        .map(|file: Result<rpm::RpmFile<'_>, rpm::Error>| {
            let file: rpm::RpmFile<'_> = file.expect("reference file");
            let path: String = normalized_reference_path(&file.metadata.path());
            let file_type: rpm::FileType = file.metadata.file_type();
            let executable: bool = file.metadata.permissions() & 0o111 != 0;
            let ghost: bool = file.metadata.flags().contains(rpm::FileFlags::GHOST);
            let link_target: Option<String> = file.metadata.linkto().map(str::to_owned);
            let mode: u32 = u32::from(file.metadata.mode().raw_mode());
            (
                path,
                file_type,
                file.content,
                executable,
                ghost,
                link_target,
                mode,
            )
        })
        .collect();

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, bytes, tmp.path()).expect("extract rpm");
    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    let recovered_by_name: BTreeMap<&str, &disrobe_binfmt::containers::RpmEntry> = recovered
        .entries
        .iter()
        .map(|entry: &disrobe_binfmt::containers::RpmEntry| (entry.name.as_str(), entry))
        .collect();
    assert_eq!(by_name.len(), reference_files.len(), "inventory differs");
    for (path, file_type, expected, executable, ghost, link_target, mode) in reference_files {
        let entry: &&ExtractedEntry = by_name
            .get(path.as_str())
            .unwrap_or_else(|| panic!("missing RPM member `{path}`"));
        let recovered_entry: &&disrobe_binfmt::containers::RpmEntry = recovered_by_name
            .get(path.as_str())
            .unwrap_or_else(|| panic!("missing recovered RPM member `{path}`"));
        assert_eq!(recovered_entry.mode, mode, "type or permissions `{path}`");
        assert_eq!(recovered_entry.link_target, link_target, "link `{path}`");
        assert_eq!(
            entry.uncompressed_size,
            expected.len() as u64,
            "size `{path}`"
        );
        assert_eq!(entry.is_executable, executable, "mode `{path}`");
        if file_type == rpm::FileType::Regular && !ghost {
            let disk_path: &std::path::Path = entry
                .disk_path
                .as_deref()
                .unwrap_or_else(|| panic!("regular RPM member `{path}` was not materialized"));
            let actual: Vec<u8> = std::fs::read(disk_path)
                .unwrap_or_else(|error: std::io::Error| panic!("read `{path}`: {error}"));
            assert_eq!(actual, expected, "content `{path}`");
        } else {
            assert!(
                entry.disk_path.is_none(),
                "non-regular RPM member `{path}` was materialized"
            );
        }
    }
}

#[test]
fn upstream_v3_package_extracts_pinned_inventory() {
    let digest: String = format!("{:x}", Sha256::digest(V3_FIXTURE));
    assert_eq!(digest, V3_FIXTURE_SHA256, "fixture bytes changed");
    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, V3_FIXTURE, tmp.path()).expect("extract v3 rpm");
    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    assert_eq!(by_name.len(), 3, "v3 inventory differs");
    for (name, size, executable, sha256) in [
        (
            "usr/local/bin/hello",
            16_824_u64,
            true,
            Some("d1f1b099aa4f285913763facd30d3fe3acee048eab413266b5f0eebd746af97c"),
        ),
        ("usr/share/doc/hello", 0, true, None),
        (
            "usr/share/doc/hello/FAQ",
            36,
            false,
            Some("678b87e217a415f05e43460e2c7b668245b412e2b4f18a75aa7399d9774ed0b4"),
        ),
    ] {
        let entry: &&ExtractedEntry = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing v3 RPM member `{name}`"));
        assert_eq!(entry.uncompressed_size, size, "size `{name}`");
        assert_eq!(entry.is_executable, executable, "mode `{name}`");
        match sha256 {
            Some(expected) => {
                let path: &std::path::Path = entry
                    .disk_path
                    .as_deref()
                    .unwrap_or_else(|| panic!("missing materialized v3 RPM member `{name}`"));
                let bytes: Vec<u8> = std::fs::read(path)
                    .unwrap_or_else(|error: std::io::Error| panic!("read `{name}`: {error}"));
                assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
            }
            None => assert!(
                entry.disk_path.is_none(),
                "directory was reported as a file"
            ),
        }
    }
}

#[test]
fn upstream_v6_package_matches_reference_parser() {
    assert_extract_matches_reference(
        V6_FIXTURE,
        V6_FIXTURE_SHA256,
        RpmFormat::V6,
        RpmCompression::Stored,
    );
}

#[test]
fn upstream_v4_package_matches_reference_parser() {
    assert_extract_matches_reference(
        V4_UPSTREAM,
        V4_UPSTREAM_SHA256,
        RpmFormat::V4,
        RpmCompression::Gzip,
    );
}

#[test]
fn signed_v4_package_preserves_untrusted_signature_blobs() {
    let recovered: RecoveredRpm =
        recover_rpm(V4_LZMA, 64 * 1024 * 1024).expect("recover signed v4 rpm");
    let signatures: Vec<(u32, String)> = recovered
        .signature_blobs
        .iter()
        .map(|signature: &disrobe_binfmt::containers::RpmSignatureBlob| {
            (
                signature.tag,
                format!("{:x}", Sha256::digest(&signature.bytes)),
            )
        })
        .collect();
    assert_eq!(
        signatures,
        [
            (
                268,
                "1bc1f404ec58cee61343d0903ed2157d1ec22b62eb171ab6a44cc0733c9759a6".to_owned(),
            ),
            (
                1002,
                "559b42e2546809eb03f6fe13167a2d4f9797eefc5a839dc1c750b33023ecc812".to_owned(),
            ),
        ]
    );
}

#[test]
fn signed_v6_package_preserves_decoded_openpgp_blob() {
    let recovered: RecoveredRpm =
        recover_rpm(V6_SIGNED, 64 * 1024 * 1024).expect("recover signed v6 rpm");
    let signatures: Vec<(u32, usize, String)> = recovered
        .signature_blobs
        .iter()
        .map(|signature: &disrobe_binfmt::containers::RpmSignatureBlob| {
            (
                signature.tag,
                signature.bytes.len(),
                format!("{:x}", Sha256::digest(&signature.bytes)),
            )
        })
        .collect();
    assert_eq!(
        signatures,
        [(
            278,
            605,
            "c7397fb6f7dc45d368f7f4197c0dee52988d47390186cfbd3887d2a80ba5e758".to_owned(),
        )]
    );
}

#[test]
fn carried_v4_md5_rejects_payload_corruption() {
    let mut bytes: Vec<u8> = V4_LZMA.to_vec();
    let last: usize = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let error: disrobe_binfmt::Error =
        recover_rpm(&bytes, 64 * 1024 * 1024).expect_err("v4 MD5 mismatch must fail");
    assert!(error.to_string().contains("MD5 mismatch"), "{error}");
}

#[test]
fn upstream_v6_matrix_matches_reference_parser() {
    for (bytes, sha256, compression) in [
        (
            V6_BZIP2,
            "bb2855ca71c5e4cdee4a6cc05c897f87cb96ca93aebf10f8b46c7db3dc21f167",
            RpmCompression::Bzip2,
        ),
        (
            V6_EMPTY,
            "17384693825957e86b263798313beb957b84350c92a5537136325d51be2d5ce2",
            RpmCompression::Stored,
        ),
        (
            V6_FILE_TYPES,
            "016b59f487ac84f17718693aa01c4ee12a04d758479f431f635c2978102f5de8",
            RpmCompression::Stored,
        ),
        (
            V6_GZIP,
            "321a2b8ed9ec858dbeaf9ffc87835093cf5016e84e73c593ed2de9c77c7bc4d5",
            RpmCompression::Gzip,
        ),
        (
            V6_SIGNED,
            "ac67d77768620bbb3dea7c9917389668829281eb22540d9bcbe4c8df764a4385",
            RpmCompression::Stored,
        ),
        (
            V6_SOURCE,
            "1882a0a11bea9ab2de54c10f3838ac3000dcb1b8a251490c2af9166a5f5d54a0",
            RpmCompression::Zstd,
        ),
        (
            V6_XZ,
            "1f7abeb2e370fe4e41f551da342e6e4e6bf8e5a3b18d335d1d7f1e2be0d14bc6",
            RpmCompression::Xz,
        ),
        (
            V6_ZSTD,
            "26663c6879aad52ca02e6de039083be3d53c446f5a4785de070515e1b5a0f6c5",
            RpmCompression::Zstd,
        ),
    ] {
        assert_extract_matches_reference(bytes, sha256, RpmFormat::V6, compression);
    }
}

#[test]
fn upstream_v6_hardlinks_share_verified_payload_bytes() {
    let fixture_digest: String = format!("{:x}", Sha256::digest(V6_HARDLINKS));
    assert_eq!(
        fixture_digest,
        "e393089844452972280c097268870cb937374a1159820e19848752e99a4c7df3"
    );
    let recovered: RecoveredRpm =
        recover_rpm(V6_HARDLINKS, 64 * 1024 * 1024).expect("recover hardlink rpm");
    let members: BTreeMap<&str, (u64, String)> = recovered
        .entries
        .iter()
        .map(|entry| {
            let bytes: &[u8] =
                recovered
                    .member_bytes(entry)
                    .unwrap_or_else(|error: disrobe_binfmt::Error| {
                        panic!("member `{}`: {error}", entry.name)
                    });
            (
                entry.name.as_str(),
                (entry.file_size, format!("{:x}", Sha256::digest(bytes))),
            )
        })
        .collect();
    for (name, size, sha256) in V6_HARDLINK_MEMBERS {
        let actual: &(u64, String) = members
            .get(name)
            .unwrap_or_else(|| panic!("missing hardlink member `{name}`"));
        assert_eq!(actual.0, size, "size `{name}`");
        assert_eq!(actual.1, sha256, "content `{name}`");
    }

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, V6_HARDLINKS, tmp.path()).expect("extract hardlink rpm");
    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    for (name, size, sha256) in V6_HARDLINK_MEMBERS {
        let entry: &&ExtractedEntry = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing extracted hardlink member `{name}`"));
        assert_eq!(entry.uncompressed_size, size, "extracted size `{name}`");
        let path: &std::path::Path = entry
            .disk_path
            .as_deref()
            .unwrap_or_else(|| panic!("hardlink member `{name}` has no disk path"));
        let bytes: Vec<u8> = std::fs::read(path)
            .unwrap_or_else(|error: std::io::Error| panic!("read `{name}`: {error}"));
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), sha256, "`{name}`");
    }
}

#[test]
fn opensuse_v4_lzma_package_recovers_in_process() {
    let fixture_digest: String = format!("{:x}", Sha256::digest(V4_LZMA));
    assert_eq!(
        fixture_digest,
        "9919cd7d21940fd66ef9ec50dca0c208f95980d3dca3a6ff3b8412e5da99e737"
    );
    let recovered: RecoveredRpm = recover_rpm(V4_LZMA, 16 * 1024 * 1024).expect("recover lzma rpm");
    assert_eq!(recovered.format, RpmFormat::V4);
    assert_eq!(recovered.compression, RpmCompression::Lzma);
    assert_eq!(recovered.entries.len(), 112);

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, V4_LZMA, tmp.path()).expect("extract lzma rpm");
    assert_eq!(result.entries.len(), 112);
    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    for (name, size, sha256) in [
        (
            "etc/hushlogins",
            1,
            "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        ),
        (
            "usr/bin/filesize",
            68,
            "c50efb99bd84181a7e0ccfc1d5beb7cb6b321c7759dbe40708cdd59eedf8bdc9",
        ),
    ] {
        let entry: &&ExtractedEntry = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing LZMA RPM member `{name}`"));
        assert_eq!(entry.uncompressed_size, size, "size `{name}`");
        let path: &std::path::Path = entry
            .disk_path
            .as_deref()
            .unwrap_or_else(|| panic!("LZMA RPM member `{name}` has no disk path"));
        let bytes: Vec<u8> = std::fs::read(path)
            .unwrap_or_else(|error: std::io::Error| panic!("read `{name}`: {error}"));
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), sha256, "`{name}`");
    }
    let symlink: &&ExtractedEntry = by_name
        .get("etc/init.d/reboot")
        .unwrap_or_else(|| panic!("missing LZMA RPM symlink"));
    assert!(symlink.disk_path.is_none());
    let wildcard: &&ExtractedEntry = by_name
        .get("usr/share/man/man8/*spec.gz")
        .unwrap_or_else(|| panic!("missing LZMA RPM wildcard member"));
    assert_eq!(wildcard.uncompressed_size, 20);
    if cfg!(windows) {
        assert!(wildcard.disk_path.is_none());
        assert!(result.integrity_violations.iter().any(|violation: &String| {
            violation
                == "rpm-host-path `usr/share/man/man8/*spec.gz` cannot be represented by the output filesystem"
        }));
    } else {
        assert!(wildcard.disk_path.is_some());
    }
}

#[test]
fn pinned_v4_stripped_package_extracts_identical_script() {
    assert_eq!(
        format!("{:x}", Sha256::digest(V4_STRIPPED)),
        V4_STRIPPED_SHA256,
        "fixture bytes changed"
    );
    let recovered: RecoveredRpm =
        recover_rpm(V4_STRIPPED, 1024 * 1024).expect("recover v4 stripped rpm");
    assert_eq!(recovered.format, RpmFormat::V4);
    assert_eq!(recovered.compression, RpmCompression::Stored);
    assert!(recovered.cpio.starts_with(b"07070X"));

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, V4_STRIPPED, tmp.path()).expect("extract v4 stripped rpm");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "usr/bin/disrobe-rpm-v4-stripped");
    let path: &std::path::Path = result.entries[0]
        .disk_path
        .as_deref()
        .expect("v4 stripped script disk path");
    assert_eq!(
        std::fs::read(path).expect("read v4 stripped script"),
        SCRIPT_BYTES
    );
}

#[test]
fn reference_rebuilds_pinned_v4_stripped_fixture() {
    fn header(bytes: &[u8], start: usize) -> (usize, Vec<(u32, usize)>) {
        assert_eq!(&bytes[start..start + 4], &[0x8e, 0xad, 0xe8, 0x01]);
        let count: usize = u32::from_be_bytes(
            bytes[start + 8..start + 12]
                .try_into()
                .expect("header count"),
        ) as usize;
        let store_size: usize = u32::from_be_bytes(
            bytes[start + 12..start + 16]
                .try_into()
                .expect("header store size"),
        ) as usize;
        let store_start: usize = start + 16 + count * 16;
        let mut entries: Vec<(u32, usize)> = Vec::with_capacity(count);
        for index in 0..count {
            let entry_start: usize = start + 16 + index * 16;
            let tag: u32 =
                u32::from_be_bytes(bytes[entry_start..entry_start + 4].try_into().expect("tag"));
            let offset: usize = u32::from_be_bytes(
                bytes[entry_start + 8..entry_start + 12]
                    .try_into()
                    .expect("tag offset"),
            ) as usize;
            entries.push((tag, store_start + offset));
        }
        (store_start + store_size, entries)
    }

    fn tag(entries: &[(u32, usize)], expected: u32) -> usize {
        entries
            .iter()
            .find_map(|(tag, offset): &(u32, usize)| (*tag == expected).then_some(*offset))
            .unwrap_or_else(|| panic!("missing tag {expected}"))
    }

    fn replace_hex(bytes: &mut [u8], offset: usize, digest: &[u8]) {
        assert_eq!(bytes[offset + digest.len()], 0);
        bytes[offset..offset + digest.len()].copy_from_slice(digest);
    }

    let package: rpm::Package = rpm::PackageBuilder::new(
        "disrobe-rpm-v4-stripped",
        "1.0.0",
        "MIT",
        "noarch",
        "RPM v4 stripped CPIO fixture",
    )
    .using_config(
        rpm::BuildConfig::v4()
            .compression(rpm::CompressionType::None)
            .source_date(1_700_000_000),
    )
    .with_file_contents(
        SCRIPT_BYTES,
        rpm::FileOptions::new("/usr/bin/disrobe-rpm-v4-stripped")
            .mode(rpm::FileMode::regular(0o755)),
    )
    .expect("add script")
    .build()
    .expect("build package");
    let mut bytes: Vec<u8> = Vec::new();
    package.write(&mut bytes).expect("serialize package");
    let (signature_end, signature_entries): (usize, Vec<(u32, usize)>) = header(&bytes, 96);
    let main_start: usize = (signature_end + 7) & !7;
    let (main_end, main_entries): (usize, Vec<(u32, usize)>) = header(&bytes, main_start);

    let mut stripped: Vec<u8> = b"07070X00000000\0\0".to_vec();
    stripped.extend_from_slice(SCRIPT_BYTES);
    while !stripped.len().is_multiple_of(4) {
        stripped.push(0);
    }
    stripped.extend_from_slice(b"07070Xffffffff\0\0");
    let payload_digest: String = format!("{:x}", Sha256::digest(&stripped));
    replace_hex(
        &mut bytes,
        tag(&main_entries, 5092),
        payload_digest.as_bytes(),
    );
    replace_hex(
        &mut bytes,
        tag(&main_entries, 5097),
        payload_digest.as_bytes(),
    );
    bytes[tag(&signature_entries, 1000)..tag(&signature_entries, 1000) + 4]
        .copy_from_slice(&((main_end - main_start + stripped.len()) as u32).to_be_bytes());
    let header_sha1: String = format!("{:x}", Sha1::digest(&bytes[main_start..main_end]));
    let header_sha256: String = format!("{:x}", Sha256::digest(&bytes[main_start..main_end]));
    replace_hex(
        &mut bytes,
        tag(&signature_entries, 269),
        header_sha1.as_bytes(),
    );
    replace_hex(
        &mut bytes,
        tag(&signature_entries, 273),
        header_sha256.as_bytes(),
    );
    bytes.truncate(main_end);
    bytes.extend_from_slice(&stripped);

    let mut cursor: Cursor<&[u8]> = Cursor::new(&bytes);
    let reference: rpm::Package = rpm::Package::parse(&mut cursor).expect("reference parse");
    let reference_files: Vec<rpm::RpmFile<'_>> = reference
        .files()
        .expect("reference files")
        .collect::<Result<Vec<rpm::RpmFile<'_>>, rpm::Error>>()
        .expect("reference payload");
    assert_eq!(reference_files.len(), 1);
    assert_eq!(reference_files[0].content, SCRIPT_BYTES);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), V4_STRIPPED_SHA256);
    assert_eq!(bytes, V4_STRIPPED);
}
