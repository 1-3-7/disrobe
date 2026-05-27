#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::io::{Cursor, Read as _};

use disrobe_binfmt::containers::msix::{MsixManifest, parse_appx_manifest};

const FORMAT_DIR: &str = "msix";
const FIXTURE_NAME: &str = "hello.msix";

#[test]
fn real_msix_manifest_identity_recovered() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration (requires MakeAppx)"
        );
    };
    assert!(bytes.len() > 1_000_000);
    let manifest: MsixManifest = parse_appx_manifest(&bytes).expect("parse appx manifest");
    assert_eq!(
        manifest.package_name.as_deref(),
        Some("DisrobeProject.HelloDisrobe")
    );
    assert_eq!(manifest.publisher.as_deref(), Some("CN=DisrobeProject"));
    assert_eq!(manifest.version.as_deref(), Some("1.0.0.0"));
    assert_eq!(manifest.display_name.as_deref(), Some("Hello Disrobe"));
}

#[test]
fn real_msix_contains_payload_files_and_edge_case_names() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let cursor: Cursor<&[u8]> = Cursor::new(bytes.as_slice());
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open msix as zip");
    let mut names: BTreeSet<String> = BTreeSet::new();
    for i in 0..archive.len() {
        let entry: zip::read::ZipFile<'_> = archive.by_index(i).expect("entry");
        names.insert(entry.name().to_owned());
    }
    assert!(names.contains("AppxManifest.xml"));
    assert!(names.contains("hello.txt"));
    assert!(names.contains("README"));
    assert!(names.contains("empty.txt"));
    assert!(names.contains("lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt"));
    assert!(
        names.contains("specials/spaces%20in%20name.txt"),
        "MSIX URI-encodes spaces; expected `specials/spaces%20in%20name.txt`"
    );
    assert!(
        names.contains("specials/parens%281%29.txt"),
        "MSIX URI-encodes parens; expected `specials/parens%281%29.txt`"
    );
    assert!(
        names.contains("specials/amp%26sign.txt"),
        "MSIX URI-encodes &; expected `specials/amp%26sign.txt`"
    );
    assert!(
        names.contains("specials/dash-and_under.txt"),
        "ASCII safe chars stay literal"
    );
    assert!(names.contains("many/small_0000.txt"));
    assert!(names.contains("many/small_0119.txt"));
    assert!(names.contains("bin/large.bin"));
    assert!(names.contains("sparse/sparse.bin"));
    let unicode_count: usize = names
        .iter()
        .filter(|n: &&String| n.starts_with("unicode/"))
        .count();
    assert!(
        unicode_count >= 5,
        "expected 5+ unicode files, got {unicode_count}"
    );
}

#[test]
fn real_msix_hello_txt_content_round_trip() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let cursor: Cursor<&[u8]> = Cursor::new(bytes.as_slice());
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open msix as zip");
    let mut hello: zip::read::ZipFile<'_> = archive.by_name("hello.txt").expect("hello.txt");
    let mut content: String = String::new();
    hello.read_to_string(&mut content).expect("read");
    assert!(content.starts_with("hello disrobe"));
}
