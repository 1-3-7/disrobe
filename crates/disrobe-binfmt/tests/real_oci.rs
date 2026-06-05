#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read as _};

use disrobe_binfmt::containers::oci::{OciIndex, OciManifest, parse_oci_index, parse_oci_manifest};

const FORMAT_DIR: &str = "oci";
const FIXTURE_NAME: &str = "hello.oci.tar";

fn collect_tar_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: tar::Archive<Cursor<&[u8]>> = tar::Archive::new(cursor);
    for entry in archive.entries().expect("tar entries") {
        let mut e: tar::Entry<'_, Cursor<&[u8]>> = entry.expect("entry");
        let path: String = e.path().expect("path").to_string_lossy().replace('\\', "/");
        if e.header().entry_type().is_dir() {
            continue;
        }
        let mut buf: Vec<u8> = Vec::new();
        e.read_to_end(&mut buf).expect("read entry");
        out.insert(path, buf);
    }
    out
}

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/oci/hello.oci.tar (buildah/skopeo, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_oci_layout_contains_index_manifest_config_layer() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} - see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert!(bytes.len() > 1_000_000);
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    assert!(entries.contains_key("oci-layout"), "missing oci-layout");
    assert!(entries.contains_key("index.json"), "missing index.json");
    let blob_count: usize = entries
        .keys()
        .filter(|k: &&String| k.starts_with("blobs/sha256/"))
        .count();
    assert!(
        blob_count >= 3,
        "expected 3+ blobs (manifest+config+layer), got {blob_count}"
    );
}

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/oci/hello.oci.tar (buildah/skopeo, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_oci_index_parses_and_references_manifest_blob() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let index_bytes: &Vec<u8> = entries.get("index.json").expect("index.json");
    let index: OciIndex = parse_oci_index(index_bytes).expect("parse oci index");
    assert_eq!(index.schema_version, 2);
    assert_eq!(index.manifests.len(), 1);
    let manifest_digest: &str = &index.manifests[0].digest;
    assert!(manifest_digest.starts_with("sha256:"));
    let manifest_blob_key: String = format!("blobs/sha256/{}", &manifest_digest["sha256:".len()..]);
    let manifest_bytes: &Vec<u8> = entries.get(&manifest_blob_key).expect("manifest blob");
    let manifest: OciManifest = parse_oci_manifest(manifest_bytes).expect("parse oci manifest");
    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.layers.len(), 1);
    let layer_digest: &str = &manifest.layers[0].digest;
    let layer_blob_key: String = format!("blobs/sha256/{}", &layer_digest["sha256:".len()..]);
    let layer_bytes: &Vec<u8> = entries.get(&layer_blob_key).expect("layer blob");
    assert_eq!(layer_bytes.len() as u64, manifest.layers[0].size);
}

#[test]
#[ignore = "needs gitignored real fixture corpus/binfmt/oci/hello.oci.tar (buildah/skopeo, ~5MB); regen via corpus/binfmt/MANIFEST.toml, run with --ignored"]
fn real_oci_layer_contains_payload_hello_txt() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!("missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}");
    };
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let index_bytes: &Vec<u8> = entries.get("index.json").expect("index.json");
    let index: OciIndex = parse_oci_index(index_bytes).expect("parse oci index");
    let manifest_blob_key: String = format!(
        "blobs/sha256/{}",
        &index.manifests[0].digest["sha256:".len()..]
    );
    let manifest: OciManifest =
        parse_oci_manifest(entries.get(&manifest_blob_key).expect("manifest")).expect("manifest");
    let layer_blob_key: String = format!(
        "blobs/sha256/{}",
        &manifest.layers[0].digest["sha256:".len()..]
    );
    let gz_bytes: &Vec<u8> = entries.get(&layer_blob_key).expect("layer blob");

    let mut decoder: flate2::read::GzDecoder<&[u8]> =
        flate2::read::GzDecoder::new(gz_bytes.as_slice());
    let mut uncompressed: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut uncompressed)
        .expect("gunzip layer");

    let layer_entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&uncompressed);
    let hello: &Vec<u8> = layer_entries.get("hello.txt").expect("hello.txt in layer");
    let text: &str = std::str::from_utf8(hello).expect("utf8");
    assert!(text.starts_with("hello disrobe"));
    assert!(
        layer_entries.contains_key("lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt"),
        "missing deep nested file"
    );
    assert!(layer_entries.contains_key("specials/spaces in name.txt"));
    assert!(layer_entries.contains_key("specials/parens(1).txt"));
    assert!(layer_entries.contains_key("bin/large.bin"));
}
