#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

pub const LAYER_PAYLOAD: &[(&str, &[u8])] = &[
    ("hello.txt", b"hello disrobe synthetic\n"),
    (
        "lvl1/lvl2/lvl3/lvl4/lvl5/deep.txt",
        b"deeply nested payload\n",
    ),
    ("specials/spaces in name.txt", b"spaced\n"),
    ("specials/parens(1).txt", b"parens\n"),
    ("specials/amp&sign.txt", b"ampersand\n"),
    ("bin/small.bin", b"\x00\x01\x02\x03\x04\x05\x06\x07"),
];

fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
    for (name, body) in files {
        let mut header: tar::Header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, name, *body)
            .expect("tar append");
    }
    builder.into_inner().expect("tar finish")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("gz write");
    encoder.finish().expect("gz finish")
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

pub fn build_synthetic_oci() -> Vec<u8> {
    let layer_tar: Vec<u8> = tar_of(LAYER_PAYLOAD);
    let layer_gz: Vec<u8> = gzip(&layer_tar);
    let layer_digest: String = sha256_hex(&layer_gz);

    let config_json: String = format!(
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"sha256:{}\"]}}}}",
        sha256_hex(&layer_tar)
    );
    let config_bytes: Vec<u8> = config_json.into_bytes();
    let config_digest: String = sha256_hex(&config_bytes);

    let manifest_json: String = format!(
        "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:{config_digest}\",\"size\":{config_size}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"sha256:{layer_digest}\",\"size\":{layer_size}}}]}}",
        config_size = config_bytes.len(),
        layer_size = layer_gz.len(),
    );
    let manifest_bytes: Vec<u8> = manifest_json.into_bytes();
    let manifest_digest: String = sha256_hex(&manifest_bytes);

    let index_json: String = format!(
        "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:{manifest_digest}\",\"size\":{manifest_size},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"disrobe/hello:synthetic\"}}}}]}}",
        manifest_size = manifest_bytes.len(),
    );

    let oci_layout: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";

    tar_of(&[
        ("oci-layout", oci_layout),
        ("index.json", index_json.as_bytes()),
        (&format!("blobs/sha256/{manifest_digest}"), &manifest_bytes),
        (&format!("blobs/sha256/{config_digest}"), &config_bytes),
        (&format!("blobs/sha256/{layer_digest}"), &layer_gz),
    ])
}

pub fn build_synthetic_docker() -> Vec<u8> {
    let layer_tar: Vec<u8> = tar_of(LAYER_PAYLOAD);
    let layer_id: String = sha256_hex(&layer_tar);
    let layer_path: String = format!("{layer_id}/layer.tar");

    let config_json: String = format!(
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"sha256:{layer_id}\"]}}}}"
    );
    let config_bytes: Vec<u8> = config_json.into_bytes();
    let config_id: String = sha256_hex(&config_bytes);
    let config_path: String = format!("{config_id}.json");

    let manifest_json: String = format!(
        "[{{\"Config\":\"{config_path}\",\"RepoTags\":[\"disrobe/hello:synthetic\"],\"Layers\":[\"{layer_path}\"]}}]"
    );

    tar_of(&[
        (&config_path, &config_bytes),
        (&layer_path, &layer_tar),
        ("manifest.json", manifest_json.as_bytes()),
    ])
}

fn main() {
    let oci_dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/binfmt/oci/synthetic");
    let docker_dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/binfmt/docker/synthetic");
    std::fs::create_dir_all(&oci_dir).expect("mkdir oci");
    std::fs::create_dir_all(&docker_dir).expect("mkdir docker");
    std::fs::write(oci_dir.join("hello.oci.tar"), build_synthetic_oci()).expect("write oci");
    std::fs::write(
        docker_dir.join("hello.docker.tar"),
        build_synthetic_docker(),
    )
    .expect("write docker");
    eprintln!("wrote synthetic oci + docker fixtures");
}
