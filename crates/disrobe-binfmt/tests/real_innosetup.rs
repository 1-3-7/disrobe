#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::innosetup::{
    InnoCompression, InnoFileCompression, InnoMetadata, InnoNamedRecovery, recover_inno_metadata,
    recover_inno_named_files,
};
use disrobe_binfmt::extract::{ExtractedEntry, ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

type HistoricalFixture = (
    &'static str,
    Vec<u8>,
    &'static str,
    usize,
    u64,
    &'static str,
);

static FIXTURE: LazyLock<Vec<u8>> = LazyLock::new(|| load("innosetup-6.3.3.exe", 6));
const FIXTURE_SHA256: &str = "0bcb2a409dea17e305a27a6b09555cabe600e984f88570ab72575cd7e93c95e6";
const ROSTER: &str = include_str!("fixtures/innosetup/innosetup-6.3.3-roster.csv");
const CODEC_ALPHA: &[u8] = include_bytes!("fixtures/innosetup/codec-matrix/alpha.txt");
const CODEC_BETA: &[u8] = include_bytes!("fixtures/innosetup/codec-matrix/beta.txt");
static SOLID_BREAK_FIXTURE: LazyLock<Vec<u8>> =
    LazyLock::new(|| load("codec-matrix/solid-break.exe", 2));
const SOLID_BREAK_SHA256: &str = "fa022f5ce600787da59467b503fed36565e35e57ea6ead42b6f863cbcda92bed";
static STORED_METADATA_FIXTURE: LazyLock<Vec<u8>> =
    LazyLock::new(|| load("codec-matrix/stored-metadata.exe", 5));
const STORED_METADATA_SHA256: &str =
    "bca950b98e26fb1ddbcb016433d0f677c56173735bd70463d21e524967ef4236";
type CodecFixture = (&'static str, Vec<u8>, InnoFileCompression, &'static str);
static CODEC_FIXTURES: LazyLock<[CodecFixture; 5]> = LazyLock::new(|| {
    [
        (
            "none",
            load("codec-matrix/codec-none.exe", 2),
            InnoFileCompression::Stored,
            "abdf89608136af8e6ad4a106d3f8b3ae42aab1965d907c76816fda06cbd6f4f1",
        ),
        (
            "zip",
            load("codec-matrix/codec-zip.exe", 2),
            InnoFileCompression::Zlib,
            "aba105c3015434d47382a729367cae1c0ec416a7501fc4e93e7edcf4db6e66a2",
        ),
        (
            "bzip",
            load("codec-matrix/codec-bzip.exe", 2),
            InnoFileCompression::Bzip2,
            "208b149182f920208dbafc9f05c7b99fac642cee6e5792ddd56760770ff37cdb",
        ),
        (
            "lzma",
            load("codec-matrix/codec-lzma.exe", 2),
            InnoFileCompression::Lzma1,
            "7eb4b471f14c2fcf591db109911f6bf39d3d6ec0a82de032f16880df51a6d1e4",
        ),
        (
            "lzma2",
            load("codec-matrix/codec-lzma2.exe", 2),
            InnoFileCompression::Lzma2,
            "6a3422a2a16cf609b1f32774c418d4adc1ed945abc9571ad2c889f2684b97fc2",
        ),
    ]
});
static HISTORICAL_FIXTURES: LazyLock<[HistoricalFixture; 2]> = LazyLock::new(|| {
    [
        (
            "4.0.9",
            load("isetup-4.0.9.exe", 2),
            "bdc9cdb8e8c80ba494faad054f2ce24938bf3b7f5e53009c94ab3eda9f4758f5",
            37,
            2_278_304,
            "d7c8471c8a0b1f705a6b06cadf67a74468498b85f52b0bde330f04f5ac934d5a",
        ),
        (
            "4.1.6",
            include_bytes!("fixtures/innosetup/isetup-4.1.6.exe").to_vec(),
            "3c737364dd9bcb452f9c615b804183cfdde652bc7f1214e9807c93fda4aa017f",
            40,
            2_820_048,
            "e19235e8d79feacd16034573500d7e5280346e20ffa2bb90a847827d7cdeb82c",
        ),
    ]
});
static INNO7_FIXTURES: LazyLock<[(&str, Vec<u8>, &str); 2]> = LazyLock::new(|| {
    [
        (
            "x86",
            load("innosetup-7.1.0-x86.exe", 13),
            "f9671174e0d15ba9b4f6b56564c6aed32ea8db9c3cb9bf6f2af0850fe7894f60",
        ),
        (
            "x64",
            load("innosetup-7.1.0-x64.exe", 14),
            "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f",
        ),
    ]
});

fn load(path: &str, cap_mib: u64) -> Vec<u8> {
    disrobe_testkit::load_fixture(
        &format!("crates/disrobe-binfmt/tests/fixtures/innosetup/{path}"),
        cap_mib * 1024 * 1024,
    )
    .unwrap_or_else(|error| panic!("load Inno Setup fixture {path}: {error}"))
}

fn expected_roster() -> BTreeMap<String, (u64, String)> {
    ROSTER
        .lines()
        .skip(1)
        .map(|line: &str| {
            let fields: Vec<&str> = line
                .strip_prefix('"')
                .and_then(|value: &str| value.strip_suffix('"'))
                .expect("reference roster row must be quoted")
                .split("\",\"")
                .collect();
            let [path, size, digest]: [&str; 3] = fields
                .try_into()
                .unwrap_or_else(|fields: Vec<&str>| panic!("invalid roster row: {fields:?}"));
            let size: u64 = size.parse().expect("reference size must be decimal");
            (path.to_owned(), (size, digest.to_owned()))
        })
        .collect()
}

#[test]
fn official_633_installer_recovers_the_reference_inventory_byte_exact() {
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE.as_slice())),
        FIXTURE_SHA256
    );
    assert_eq!(
        detect_container(FIXTURE.as_slice()),
        Some(ContainerKind::InnoSetup)
    );
    let metadata: InnoMetadata =
        recover_inno_metadata(FIXTURE.as_slice()).expect("parse official Inno 6.3.3 metadata");
    assert_eq!(metadata.files.len(), 96);
    let external: Vec<_> = metadata
        .files
        .iter()
        .filter(|file| {
            usize::try_from(file.data_entry_index)
                .map_or(true, |index: usize| index >= metadata.data_entries.len())
        })
        .collect();
    assert_eq!(
        external.len(),
        2,
        "unexpected external entries: {external:?}"
    );
    assert!(
        external
            .iter()
            .all(|file| file.data_entry_index == u32::MAX)
    );
    let data_offset: usize = usize::try_from(
        metadata
            .info
            .loader
            .expect("official fixture has loader offsets")
            .data_offset,
    )
    .expect("data offset fits usize");
    assert_eq!(
        FIXTURE.get(data_offset..data_offset + 4),
        Some(b"zlb\x1a".as_slice()),
        "unexpected data area at 0x{data_offset:x}"
    );
    let recovered: InnoNamedRecovery =
        recover_inno_named_files(FIXTURE.as_slice(), &metadata, 64 * 1024 * 1024)
            .expect("recover official Inno 6.3.3 members");
    assert!(
        recovered.refusals.is_empty(),
        "unexpected real Inno refusals: {:?}",
        recovered.refusals
    );
    assert_eq!(recovered.files.len(), 94);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-real-inno-633")
            .expect("create Inno fixture output");
    let result: ExtractionResult =
        extract_to(ContainerKind::InnoSetup, FIXTURE.as_slice(), scratch.path())
            .expect("extract official Inno 6.3.3 fixture");
    let expected: BTreeMap<String, (u64, String)> = expected_roster();
    let actual: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .filter(|entry: &&ExtractedEntry| expected.contains_key(entry.name.as_str()))
        .map(|entry: &ExtractedEntry| (entry.name.as_str(), entry))
        .collect();
    assert_eq!(result.entries.len(), expected.len() + 2);
    assert_eq!(actual.len(), expected.len());
    assert!(result.integrity_violations.is_empty());
    for (name, (size, digest)) in &expected {
        let entry: &&ExtractedEntry = actual
            .get(name.as_str())
            .unwrap_or_else(|| panic!("missing Inno member `{name}`"));
        let disk_path: &Path = entry
            .disk_path
            .as_deref()
            .unwrap_or_else(|| panic!("Inno member `{name}` has no disk path"));
        let bytes: Vec<u8> = std::fs::read(disk_path)
            .unwrap_or_else(|error: std::io::Error| panic!("read `{name}`: {error}"));
        assert_eq!(
            u64::try_from(bytes.len()).expect("member size fits u64"),
            *size
        );
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), *digest);
    }
}

#[test]
fn official_633_compiler_recovers_every_standard_file_codec() {
    for (name, fixture, compression, digest) in &*CODEC_FIXTURES {
        assert_eq!(format!("{:x}", Sha256::digest(fixture)), *digest, "{name}");
        let metadata: InnoMetadata = recover_inno_metadata(fixture)
            .unwrap_or_else(|error| panic!("parse {name} fixture: {error}"));
        assert_eq!(metadata.file_compression, *compression, "{name}");
        let recovered: InnoNamedRecovery =
            recover_inno_named_files(fixture, &metadata, 1024 * 1024)
                .unwrap_or_else(|error| panic!("recover {name} fixture: {error}"));
        assert!(
            recovered.refusals.is_empty(),
            "{name} refusals: {:?}",
            recovered.refusals
        );
        assert_eq!(recovered.files.len(), 2, "{name}");
        let members: BTreeMap<&str, &[u8]> = recovered
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.data.as_slice()))
            .collect();
        assert_eq!(
            members.get("app\\data\\alpha.txt"),
            Some(&CODEC_ALPHA),
            "{name}"
        );
        assert_eq!(
            members.get("app\\data\\beta.txt"),
            Some(&CODEC_BETA),
            "{name}"
        );
    }
}

#[test]
fn official_633_compiler_recovers_explicit_solid_break_groups() {
    assert_eq!(
        format!("{:x}", Sha256::digest(SOLID_BREAK_FIXTURE.as_slice())),
        SOLID_BREAK_SHA256
    );
    let metadata: InnoMetadata =
        recover_inno_metadata(SOLID_BREAK_FIXTURE.as_slice()).expect("parse solid-break fixture");
    assert_eq!(metadata.file_compression, InnoFileCompression::Lzma2);
    assert_eq!(metadata.data_entries.len(), 2);
    assert!(metadata.data_entries[1].solid_break);
    assert_ne!(
        metadata.data_entries[0].chunk_offset,
        metadata.data_entries[1].chunk_offset
    );
    let recovered: InnoNamedRecovery =
        recover_inno_named_files(SOLID_BREAK_FIXTURE.as_slice(), &metadata, 1024 * 1024)
            .expect("recover solid-break fixture");
    assert!(recovered.refusals.is_empty());
    let members: BTreeMap<&str, &[u8]> = recovered
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.data.as_slice()))
        .collect();
    assert_eq!(members.get("app\\data\\alpha.txt"), Some(&CODEC_ALPHA));
    assert_eq!(members.get("app\\data\\beta.txt"), Some(&CODEC_BETA));
}

#[test]
fn official_633_compiler_recovers_stored_setup_metadata() {
    assert_eq!(
        format!("{:x}", Sha256::digest(STORED_METADATA_FIXTURE.as_slice())),
        STORED_METADATA_SHA256
    );
    let metadata: InnoMetadata = recover_inno_metadata(STORED_METADATA_FIXTURE.as_slice())
        .expect("parse stored-metadata fixture");
    assert_eq!(metadata.info.compression, InnoCompression::Stored);
    let recovered: InnoNamedRecovery =
        recover_inno_named_files(STORED_METADATA_FIXTURE.as_slice(), &metadata, 1024 * 1024)
            .expect("recover stored-metadata fixture");
    assert!(recovered.refusals.is_empty());
    assert_eq!(recovered.files.len(), 1);
    assert_eq!(recovered.files[0].path, "app\\alpha.txt");
    assert_eq!(recovered.files[0].data, CODEC_ALPHA);
}

#[test]
fn official_historical_installers_cover_zlib_and_lzma1_metadata() {
    for (version, fixture, digest, expected_count, expected_bytes, compiler_digest) in
        &*HISTORICAL_FIXTURES
    {
        assert_eq!(
            format!("{:x}", Sha256::digest(fixture)),
            *digest,
            "{version}"
        );
        let metadata: InnoMetadata = recover_inno_metadata(fixture)
            .unwrap_or_else(|error| panic!("parse {version} fixture: {error}"));
        assert_eq!(
            metadata.info.version_string,
            format!("Inno Setup Setup Data ({version})")
        );
        let recovered: InnoNamedRecovery =
            recover_inno_named_files(fixture, &metadata, 16 * 1024 * 1024)
                .unwrap_or_else(|error| panic!("recover {version} fixture: {error}"));
        assert!(
            recovered.refusals.is_empty(),
            "{version} refusals: {:?}",
            recovered.refusals
        );
        assert_eq!(
            recovered.files.len(),
            *expected_count,
            "{version} paths: {:?}",
            recovered
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<&str>>()
        );
        let total: u64 = recovered
            .files
            .iter()
            .map(|file| u64::try_from(file.data.len()).expect("member size fits u64"))
            .sum();
        assert_eq!(total, *expected_bytes, "{version}");
        let compiler: &disrobe_binfmt::containers::innosetup::InnoRecoveredFile = recovered
            .files
            .iter()
            .find(|file| file.path.ends_with("Compil32.exe"))
            .unwrap_or_else(|| panic!("{version} compiler member missing"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&compiler.data)),
            *compiler_digest,
            "{version}"
        );
    }
}

#[test]
fn official_inno7_x86_and_x64_installers_recover_current_data_profiles() {
    for (architecture, fixture, digest) in &*INNO7_FIXTURES {
        assert_eq!(
            format!("{:x}", Sha256::digest(fixture)),
            *digest,
            "{architecture}"
        );
        let metadata: InnoMetadata = recover_inno_metadata(fixture)
            .unwrap_or_else(|error| panic!("parse Inno 7 {architecture}: {error}"));
        assert_eq!(
            metadata.info.version_string,
            "Inno Setup Setup Data (7.0.0.3)"
        );
        let recovered: InnoNamedRecovery =
            recover_inno_named_files(fixture, &metadata, 64 * 1024 * 1024)
                .unwrap_or_else(|error| panic!("recover Inno 7 {architecture}: {error}"));
        assert!(
            recovered.refusals.is_empty(),
            "Inno 7 {architecture} refusals: {:?}",
            recovered.refusals
        );
        let recovered_bytes: u64 = recovered
            .files
            .iter()
            .map(|file| u64::try_from(file.data.len()).expect("member size fits u64"))
            .sum();
        let expected: (usize, u64) = if *architecture == "x86" {
            (137, 47_989_387)
        } else {
            (135, 52_674_963)
        };
        assert_eq!(
            (recovered.files.len(), recovered_bytes),
            expected,
            "{architecture}"
        );
        assert!(
            recovered
                .files
                .iter()
                .any(|file| file.path.ends_with("ISCC.exe")),
            "Inno 7 {architecture} compiler member missing"
        );
    }
}
