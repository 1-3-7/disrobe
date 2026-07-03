#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read as _};

use disrobe_binfmt::containers::docker::{DockerManifest, parse_docker_manifest};
use disrobe_binfmt::containers::oci::{OciIndex, OciManifest, parse_oci_index, parse_oci_manifest};
use sha2::{Digest, Sha256};

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

fn read_committed(format_dir: &str, filename: &str) -> Vec<u8> {
    let path: std::path::PathBuf = common::fixture_path(format_dir, filename);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read committed fixture {}: {e}", path.display())
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        push_hex_byte(&mut out, byte);
    }
    out
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
    out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
}

#[test]
fn synthetic_oci_index_resolves_manifest_and_config_blobs_by_digest() {
    let bytes: Vec<u8> = read_committed("oci/synthetic", "hello.oci.tar");
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    assert!(entries.contains_key("oci-layout"), "missing oci-layout");
    assert!(entries.contains_key("index.json"), "missing index.json");

    let index: OciIndex =
        parse_oci_index(entries.get("index.json").expect("index")).expect("index");
    assert_eq!(index.schema_version, 2);
    assert_eq!(index.manifests.len(), 1);

    let manifest_digest: &str = &index.manifests[0].digest;
    assert!(manifest_digest.starts_with("sha256:"));
    let manifest_key: String = format!("blobs/sha256/{}", &manifest_digest["sha256:".len()..]);
    let manifest_bytes: &Vec<u8> = entries.get(&manifest_key).expect("manifest blob");
    assert_eq!(
        sha256_hex(manifest_bytes),
        &manifest_digest["sha256:".len()..],
        "manifest blob content does not match its digest"
    );
    assert_eq!(manifest_bytes.len() as u64, index.manifests[0].size);

    let manifest: OciManifest = parse_oci_manifest(manifest_bytes).expect("manifest");
    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.layers.len(), 1);

    let config_key: String = format!(
        "blobs/sha256/{}",
        &manifest.config.digest["sha256:".len()..]
    );
    let config_bytes: &Vec<u8> = entries.get(&config_key).expect("config blob");
    assert_eq!(
        sha256_hex(config_bytes),
        &manifest.config.digest["sha256:".len()..],
        "config blob content does not match its digest"
    );
    assert_eq!(config_bytes.len() as u64, manifest.config.size);
}

#[test]
fn synthetic_oci_layer_gunzips_to_payload_tree() {
    let bytes: Vec<u8> = read_committed("oci/synthetic", "hello.oci.tar");
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let index: OciIndex =
        parse_oci_index(entries.get("index.json").expect("index")).expect("index");
    let manifest_key: String = format!(
        "blobs/sha256/{}",
        &index.manifests[0].digest["sha256:".len()..]
    );
    let manifest: OciManifest =
        parse_oci_manifest(entries.get(&manifest_key).expect("manifest")).expect("manifest");
    let layer_digest: &str = &manifest.layers[0].digest;
    let layer_key: String = format!("blobs/sha256/{}", &layer_digest["sha256:".len()..]);
    let gz_bytes: &Vec<u8> = entries.get(&layer_key).expect("layer blob");
    assert_eq!(
        sha256_hex(gz_bytes),
        &layer_digest["sha256:".len()..],
        "layer blob content does not match its digest"
    );
    assert_eq!(gz_bytes.len() as u64, manifest.layers[0].size);

    let mut decoder: flate2::read::GzDecoder<&[u8]> =
        flate2::read::GzDecoder::new(gz_bytes.as_slice());
    let mut uncompressed: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut uncompressed)
        .expect("gunzip layer");

    let layer_entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&uncompressed);
    let hello: &Vec<u8> = layer_entries.get("hello.txt").expect("hello.txt in layer");
    assert!(
        std::str::from_utf8(hello)
            .expect("utf8")
            .starts_with("hello disrobe")
    );
    assert!(layer_entries.contains_key("lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt"));
    assert!(layer_entries.contains_key("specials/spaces in name.txt"));
    assert!(layer_entries.contains_key("specials/parens(1).txt"));
    assert!(layer_entries.contains_key("bin/small.bin"));
}

#[test]
fn synthetic_docker_save_manifest_resolves_config_and_layer() {
    let bytes: Vec<u8> = read_committed("docker/synthetic", "hello.docker.tar");
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let manifest_bytes: &Vec<u8> = entries.get("manifest.json").expect("manifest.json");
    let manifests: Vec<DockerManifest> =
        parse_docker_manifest(manifest_bytes).expect("docker manifest");
    assert_eq!(manifests.len(), 1);
    let m: &DockerManifest = &manifests[0];
    assert_eq!(
        m.repo_tags.first().map(String::as_str),
        Some("disrobe/hello:synthetic")
    );
    assert_eq!(m.layers.len(), 1);
    assert!(
        m.layers[0].ends_with("/layer.tar"),
        "layer = {}",
        m.layers[0]
    );
    assert!(
        entries.contains_key(&m.layers[0]),
        "missing layer.tar entry"
    );
    assert!(
        entries.contains_key(&m.config),
        "missing config entry: {}",
        m.config
    );

    let layer_tar: &Vec<u8> = entries.get(&m.layers[0]).expect("layer.tar");
    let layer_entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(layer_tar);
    let hello: &Vec<u8> = layer_entries.get("hello.txt").expect("hello.txt");
    assert!(
        std::str::from_utf8(hello)
            .expect("utf8")
            .starts_with("hello disrobe")
    );
    assert!(layer_entries.contains_key("lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt"));
    assert!(layer_entries.contains_key("specials/amp&sign.txt"));
}
