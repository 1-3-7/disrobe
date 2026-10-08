#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/forge_specs.rs"]
mod forge_specs;
#[path = "../common/forge_writer.rs"]
mod forge_writer;
#[path = "../common/oodle_encoder/mod.rs"]
mod oodle_encoder;
#[path = "../common/oodle_fixtures.rs"]
mod oodle_fixtures;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use forge_writer::write_forge;
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn corpus_dir(relative: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join("binfmt").join(relative)
}

fn main() {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map_or_else(|| corpus_dir(forge_specs::FIXTURE_DIR), PathBuf::from);
    std::fs::create_dir_all(&out_dir).expect("create fixture directory");
    let mut manifest: String = String::new();
    manifest.push_str(
        "schema_version = 1\ncrate = \"disrobe-binfmt\"\ngenerated = \"2026-10-08\"\n\
         toolchain = \"cargo run -p disrobe-binfmt --example gen_forge_fixture (the test-tree \
         Forge writer tests/common/forge_writer.rs and Oodle encoder \
         tests/common/oodle_encoder/, over authored content from tests/common/forge_specs.rs)\"\n\
         purpose = \"Authored Scimitar/Anvil Forge archives and depgraphbin sidecars for every \
         header version and codec the reader supports. No game bytes: every payload is generated \
         text, records or zero runs; names, uids and type ids are fixture values. Oodle chunks \
         come from disrobe's own test-tree encoder.\"\n\n",
    );
    for name in forge_specs::FORGE_FIXTURES {
        let bytes: Vec<u8> = write_forge(&forge_specs::spec_for(name));
        record(
            &out_dir,
            name,
            &bytes,
            forge_specs::fixture_role(name),
            None,
            &mut manifest,
        );
    }
    for name in forge_specs::DEPGRAPH_FIXTURES {
        let bytes: Vec<u8> = forge_specs::depgraph_for(name);
        record(
            &out_dir,
            name,
            &bytes,
            forge_specs::fixture_role(name),
            None,
            &mut manifest,
        );
    }
    std::fs::write(out_dir.join("MANIFEST.toml"), manifest).expect("write manifest");

    let oodle_dir: PathBuf = out_dir.join("oodle");
    std::fs::create_dir_all(&oodle_dir).expect("create Oodle fixture directory");
    let mut oodle_manifest: String = String::new();
    oodle_manifest.push_str(
        "schema_version = 1\ncrate = \"disrobe-binfmt\"\ngenerated = \"2026-10-08\"\n\
         toolchain = \"cargo run -p disrobe-binfmt --example gen_forge_fixture (disrobe's \
         test-tree Oodle encoder, tests/common/oodle_encoder/, written from the format \
         description; plans and payload generators in tests/common/oodle_fixtures.rs)\"\n\
         purpose = \"Authored Oodle LZ streams (Kraken, Mermaid, Leviathan and every entropy \
         array form the encoder emits). Each payload is regenerated from its seed by \
         payload_for; payload_sha256 pins it. No proprietary encoder output and no game bytes.\"\n\n",
    );
    for name in oodle_fixtures::OODLE_FIXTURES {
        let bytes: Vec<u8> = oodle_fixtures::stream_for(name);
        let payload: Vec<u8> = oodle_fixtures::payload_for(name);
        record(
            &oodle_dir,
            name,
            &bytes,
            oodle_fixtures::role(name),
            Some(&payload),
            &mut oodle_manifest,
        );
    }
    std::fs::write(oodle_dir.join("MANIFEST.toml"), oodle_manifest).expect("write manifest");
    println!("wrote forge fixtures to {}", out_dir.display());
}

fn record(
    out_dir: &Path,
    name: &str,
    bytes: &[u8],
    role: &str,
    payload: Option<&[u8]>,
    manifest: &mut String,
) {
    std::fs::write(out_dir.join(name), bytes).expect("write fixture");
    writeln!(
        manifest,
        "[[fixture]]\npath = \"{name}\"\nsize_bytes = {}\nsha256 = \"{}\"",
        bytes.len(),
        sha256_hex(bytes),
    )
    .expect("writing to a String cannot fail");
    if let Some(payload) = payload {
        writeln!(
            manifest,
            "payload_bytes = {}\npayload_sha256 = \"{}\"",
            payload.len(),
            sha256_hex(payload)
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(manifest, "role = \"{role}\"\n").expect("writing to a String cannot fail");
}
