#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read as _};

use disrobe_binfmt::containers::docker::{DockerManifest, parse_docker_manifest};

const FORMAT_DIR: &str = "docker";
const FIXTURE_NAME: &str = "hello.docker.tar";
const GRADED: &str = "the real docker-save image checks";

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
fn real_docker_save_manifest_and_layer_parse() {
    let Some(bytes): Option<Vec<u8>> =
        common::requirement::regenerable_fixture(FORMAT_DIR, FIXTURE_NAME, GRADED)
    else {
        return;
    };
    assert!(bytes.len() > 1_000_000);
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let manifest_bytes: &Vec<u8> = entries.get("manifest.json").expect("manifest.json");
    let manifests: Vec<DockerManifest> =
        parse_docker_manifest(manifest_bytes).expect("docker manifest parse");
    assert_eq!(manifests.len(), 1);
    let m: &DockerManifest = &manifests[0];
    assert_eq!(
        m.repo_tags.first().map(String::as_str),
        Some("disrobe/hello:latest")
    );
    assert_eq!(m.layers.len(), 1);
    let layer_key: &String = &m.layers[0];
    assert!(layer_key.ends_with("/layer.tar"), "layer key = {layer_key}");
    assert!(entries.contains_key(layer_key), "missing layer.tar entry");
    assert!(
        entries.contains_key(&m.config),
        "missing config entry: {}",
        m.config
    );
}

#[test]
fn real_docker_layer_tar_contains_payload_edge_cases() {
    let Some(bytes): Option<Vec<u8>> =
        common::requirement::regenerable_fixture(FORMAT_DIR, FIXTURE_NAME, GRADED)
    else {
        return;
    };
    let entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(&bytes);
    let manifest_bytes: &Vec<u8> = entries.get("manifest.json").expect("manifest");
    let manifests: Vec<DockerManifest> =
        parse_docker_manifest(manifest_bytes).expect("docker manifest");
    let layer_tar: &Vec<u8> = entries.get(&manifests[0].layers[0]).expect("layer.tar");

    let layer_entries: BTreeMap<String, Vec<u8>> = collect_tar_entries(layer_tar);
    let hello: &Vec<u8> = layer_entries.get("hello.txt").expect("hello.txt");
    let text: &str = std::str::from_utf8(hello).expect("utf8");
    assert!(text.starts_with("hello disrobe"));
    assert!(layer_entries.contains_key("lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt"));
    assert!(layer_entries.contains_key("specials/amp&sign.txt"));
    assert!(layer_entries.contains_key("many/small_0000.txt"));
    assert!(layer_entries.contains_key("many/small_0119.txt"));
    let small_count: usize = layer_entries
        .keys()
        .filter(|k: &&String| k.starts_with("many/small_"))
        .count();
    assert_eq!(
        small_count, 120,
        "expected 120 small files, got {small_count}"
    );
    let large: &Vec<u8> = layer_entries.get("bin/large.bin").expect("bin/large.bin");
    assert!(
        large.len() > 4_000_000,
        "large.bin too small: {}",
        large.len()
    );
}
