#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract::{ExtractedEntry, ExtractionResult, extract_to};

const FORMAT_DIR: &str = "rpm";
const FIXTURE_NAME: &str = "hello.rpm";
const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

const HELLO_PATH: &str = "usr/share/disrobe/hello.txt";
const HELLO_BYTES: &[u8] = b"hello from disrobe rpm fixture\n";
const README_PATH: &str = "usr/share/disrobe/README";
const README_BYTES: &[u8] = b"disrobe binfmt rpm extraction test payload\n";

fn build_fixture_rpm() -> Vec<u8> {
    let config: rpm::BuildConfig = rpm::BuildConfig::v4().compression(rpm::CompressionType::Gzip);
    let pkg: rpm::Package = rpm::PackageBuilder::new(
        "disrobe-hello",
        "1.0.0",
        "Elastic-2.0",
        "x86_64",
        "disrobe test",
    )
    .using_config(config)
    .with_file_contents(
        HELLO_BYTES,
        rpm::FileOptions::new("/usr/share/disrobe/hello.txt"),
    )
    .expect("add hello.txt")
    .with_file_contents(
        README_BYTES,
        rpm::FileOptions::new("/usr/share/disrobe/README").mode(rpm::FileMode::regular(0o644)),
    )
    .expect("add README")
    .build()
    .expect("build rpm");
    let mut buf: Vec<u8> = Vec::new();
    pkg.write(&mut buf).expect("serialize rpm");
    buf
}

fn fixture_bytes() -> Vec<u8> {
    common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap_or_else(build_fixture_rpm)
}

#[test]
fn real_rpm_extracts_contained_file_bytes() {
    let bytes: Vec<u8> = fixture_bytes();
    assert_eq!(&bytes[..4], &RPM_LEAD_MAGIC, "not an rpm lead magic");

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: ExtractionResult =
        extract_to(ContainerKind::Rpm, &bytes, tmp.path()).expect("extract rpm");
    assert_eq!(result.kind, ContainerKind::Rpm);
    assert!(
        result.integrity_violations.is_empty(),
        "unexpected integrity violations: {:?}",
        result.integrity_violations
    );

    let by_name: BTreeMap<&str, &ExtractedEntry> = result
        .entries
        .iter()
        .map(|e: &ExtractedEntry| (e.name.as_str(), e))
        .collect();

    let hello: &&ExtractedEntry = by_name.get(HELLO_PATH).expect("hello.txt entry present");
    assert!(
        hello.uncompressed_size > 0,
        "hello.txt extracted as zero bytes (regression)"
    );
    let hello_path: &std::path::Path = hello
        .disk_path
        .as_deref()
        .expect("hello.txt has a disk path");
    let hello_bytes: Vec<u8> = std::fs::read(hello_path).expect("read extracted hello.txt");
    assert_eq!(
        hello_bytes, HELLO_BYTES,
        "extracted hello.txt content mismatch"
    );

    let readme: &&ExtractedEntry = by_name.get(README_PATH).expect("README entry present");
    let readme_bytes: Vec<u8> =
        std::fs::read(readme.disk_path.as_deref().expect("README has a disk path"))
            .expect("read extracted README");
    assert_eq!(
        readme_bytes, README_BYTES,
        "extracted README content mismatch"
    );

    let total: u64 = result
        .entries
        .iter()
        .map(|e: &ExtractedEntry| e.uncompressed_size)
        .sum();
    assert!(total > 0, "no real bytes extracted from rpm payload");
}

#[test]
#[ignore = "writes corpus/binfmt/rpm/hello.rpm (gitignored) for local inspection; run with --ignored"]
fn regenerate_rpm_fixture() {
    let out: std::path::PathBuf = common::fixture_path(FORMAT_DIR, FIXTURE_NAME);
    std::fs::create_dir_all(out.parent().expect("fixture parent")).expect("mkdir corpus");
    std::fs::write(&out, build_fixture_rpm()).expect("write rpm fixture");
}
