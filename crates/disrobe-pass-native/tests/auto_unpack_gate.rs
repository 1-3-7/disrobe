#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{ChildArtifact, Pass};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::chain_detector::PACKER_PASS;

const KNOWN_MARKER: &[u8] = b"disrobe-auto-unpack-known-plaintext-marker-9f3a7c1e";

fn tool_available(name: &str, arg: &str) -> bool {
    Command::new(name)
        .arg(arg)
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn compiler() -> Option<&'static str> {
    ["gcc", "clang", "cc"]
        .into_iter()
        .find(|cc: &&'static str| tool_available(cc, "--version"))
}

fn write_source(dir: &Path) -> PathBuf {
    let src: PathBuf = dir.join("known_plaintext.c");
    let marker: String = String::from_utf8(KNOWN_MARKER.to_vec()).expect("ascii marker");
    let program: String = format!(
        "#include <stdio.h>\nconst char g_marker[] = \"{marker}\";\nint main(void){{ \
         printf(\"%s\\n\", g_marker); return 0; }}\n"
    );
    std::fs::write(&src, program).expect("write source");
    src
}

fn try_run_pass(bytes: &[u8]) -> Option<Vec<ChildArtifact>> {
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    PACKER_PASS.extract_children(&input).ok()
}

fn run_pass(bytes: &[u8]) -> Vec<ChildArtifact> {
    try_run_pass(bytes).expect("packer-unpack children extraction")
}

fn recovered_image(children: &[ChildArtifact]) -> Option<&[u8]> {
    children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "recovered-image.bin")
        .map(|c: &ChildArtifact| c.bytes.as_slice())
}

#[test]
fn auto_surfaces_upx_unpacked_image_matching_upx_d_reference() {
    let Some(cc): Option<&'static str> = compiler() else {
        println!("SKIP: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    if !tool_available("upx", "--version") {
        println!("SKIP: upx CLI not on PATH");
        return;
    }

    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack").expect("create scratch directory");
    let tmp: &Path = scratch.path();

    let src: PathBuf = write_source(&tmp);
    let exe: PathBuf = tmp.join("known_plaintext.exe");
    let compile: std::process::Output = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("invoke compiler");
    if !compile.status.success() {
        println!(
            "SKIP: compiler failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    let packed: PathBuf = tmp.join("packed.exe");
    std::fs::copy(&exe, &packed).expect("copy to packed path");
    let pack: std::process::Output = Command::new("upx")
        .arg("--best")
        .arg(packed.to_str().expect("path utf8"))
        .output()
        .expect("invoke upx pack");
    if !pack.status.success() {
        println!(
            "SKIP: upx pack failed: {}",
            String::from_utf8_lossy(&pack.stderr)
        );
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    let packed_bytes: Vec<u8> = std::fs::read(&packed).expect("read packed");
    let ref_unpacked: PathBuf = tmp.join("ref_unpacked.exe");
    std::fs::copy(&packed, &ref_unpacked).expect("copy for reference");
    let unpack: std::process::Output = Command::new("upx")
        .arg("-d")
        .arg("-o")
        .arg(ref_unpacked.to_str().expect("path utf8"))
        .arg("-f")
        .arg(packed.to_str().expect("path utf8"))
        .output()
        .expect("invoke upx -d");
    assert!(
        unpack.status.success(),
        "upx -d reference must succeed: {}",
        String::from_utf8_lossy(&unpack.stderr)
    );
    let reference: Vec<u8> = std::fs::read(&ref_unpacked).expect("read reference");

    let children: Vec<ChildArtifact> = run_pass(&packed_bytes);
    let manifest: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "packer-unpack.manifest.json")
        .expect("auto must emit the packer-unpack manifest sidecar");
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).expect("manifest is valid json");
    assert_eq!(
        manifest_json["packer"].as_str(),
        Some("upx"),
        "auto must detect UPX on the real packed sample: {manifest_json}"
    );

    let recovered: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "recovered-image.bin")
        .expect("auto must surface a recovered image for the detected UPX packer");
    assert!(
        !recovered.bytes.is_empty(),
        "the recovered image child must carry real bytes"
    );

    assert!(
        contains(&recovered.bytes, KNOWN_MARKER),
        "surfaced unpacked image must contain the original known-plaintext marker"
    );
    assert!(
        contains(&reference, KNOWN_MARKER),
        "the upx -d reference must contain the known-plaintext marker (sanity of oracle)"
    );

    let overlap: usize = longest_common_run(&recovered.bytes, &reference);
    assert!(
        overlap >= KNOWN_MARKER.len() * 4,
        "the surfaced unpacked bytes must share a substantial contiguous run with the upx -d \
         reference (independent oracle); longest common run was {overlap} bytes"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

fn write_go_source(dir: &Path) {
    let marker: String = String::from_utf8(KNOWN_MARKER.to_vec()).expect("ascii marker");
    let program: String = format!(
        "package main\n\nimport \"fmt\"\n\nconst marker = \"{marker}\"\n\nfunc main() {{ \
         fmt.Println(marker) }}\n"
    );
    std::fs::write(dir.join("main.go"), program).expect("write go source");
    std::fs::write(dir.join("go.mod"), "module knownplaintext\n\ngo 1.21\n").expect("write go.mod");
}

fn build_packed_elf(tmp: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    if !tool_available("go", "version") {
        println!("SKIP: go toolchain not on PATH (needed to build an ELF host-independently)");
        return None;
    }
    if !tool_available("upx", "--version") {
        println!("SKIP: upx CLI not on PATH");
        return None;
    }
    write_go_source(tmp);
    let exe: PathBuf = tmp.join("known_plaintext.elf");
    let build: std::process::Output = Command::new("go")
        .current_dir(tmp)
        .args(["build", "-trimpath", "-o"])
        .arg(&exe)
        .arg(".")
        .env("GOOS", "linux")
        .env("GOARCH", "amd64")
        .env("CGO_ENABLED", "0")
        .output()
        .expect("invoke go build");
    if !build.status.success() {
        println!(
            "SKIP: go build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        return None;
    }

    let packed: PathBuf = tmp.join("packed.elf");
    std::fs::copy(&exe, &packed).expect("copy to packed path");
    let pack: std::process::Output = Command::new("upx")
        .arg("--best")
        .arg("-f")
        .arg(packed.to_str().expect("path utf8"))
        .output()
        .expect("invoke upx pack");
    if !pack.status.success() {
        println!(
            "SKIP: upx pack failed: {}",
            String::from_utf8_lossy(&pack.stderr)
        );
        return None;
    }

    let reference: PathBuf = tmp.join("ref_unpacked.elf");
    let unpack: std::process::Output = Command::new("upx")
        .arg("-d")
        .arg("-o")
        .arg(reference.to_str().expect("path utf8"))
        .arg("-f")
        .arg(packed.to_str().expect("path utf8"))
        .output()
        .expect("invoke upx -d");
    assert!(
        unpack.status.success(),
        "upx -d reference must succeed: {}",
        String::from_utf8_lossy(&unpack.stderr)
    );
    Some((
        std::fs::read(&packed).expect("read packed elf"),
        std::fs::read(&reference).expect("read upx -d reference"),
    ))
}

#[test]
fn auto_surfaces_upx_unpacked_elf_byte_identical_to_upx_d_reference() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack-elf").expect("create scratch directory");
    let tmp: &Path = scratch.path();
    let Some((packed_bytes, reference)): Option<(Vec<u8>, Vec<u8>)> = build_packed_elf(tmp) else {
        return;
    };

    let children: Vec<ChildArtifact> = run_pass(&packed_bytes);
    let manifest: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "packer-unpack.manifest.json")
        .expect("auto must emit the packer-unpack manifest sidecar");
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).expect("manifest is valid json");
    assert_eq!(
        manifest_json["packer"].as_str(),
        Some("upx"),
        "auto must detect UPX on the real packed ELF: {manifest_json}"
    );

    let recovered: &[u8] = recovered_image(&children).expect("auto must surface a recovered image");
    assert!(
        contains(recovered, KNOWN_MARKER),
        "surfaced unpacked ELF must contain the original known-plaintext marker"
    );
    assert_eq!(
        recovered.len(),
        reference.len(),
        "recovered ELF length must equal the upx -d reference"
    );
    assert!(
        recovered == reference.as_slice(),
        "recovered ELF must be byte-identical to the upx -d reference; first difference at {:?}",
        recovered
            .iter()
            .zip(reference.iter())
            .position(|(a, b): (&u8, &u8)| a != b)
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn corrupting_one_compressed_byte_stops_the_elf_recovery() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack-elf-mutate").expect("create scratch directory");
    let tmp: &Path = scratch.path();
    let Some((packed_bytes, reference)): Option<(Vec<u8>, Vec<u8>)> = build_packed_elf(tmp) else {
        return;
    };

    let mut mutated: Vec<u8> = packed_bytes.clone();
    let victim: usize = mutated.len() / 2;
    mutated[victim] ^= 0xff;
    let recovered_is_reference: bool = try_run_pass(&mutated)
        .as_deref()
        .and_then(recovered_image)
        .is_some_and(|bytes: &[u8]| bytes == reference.as_slice());
    assert!(
        !recovered_is_reference,
        "a corrupted compressed byte must not still produce the exact upx -d reference image"
    );

    let clean: Vec<ChildArtifact> = run_pass(&packed_bytes);
    assert_eq!(
        recovered_image(&clean),
        Some(reference.as_slice()),
        "the unmutated sample must still recover byte-identically (control)"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn longest_common_run(a: &[u8], b: &[u8]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let (needle, hay): (&[u8], &[u8]) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut window: usize = 4096.min(needle.len());
    while window > 0 {
        let mut start: usize = 0;
        while start + window <= needle.len() {
            let seg: &[u8] = &needle[start..start + window];
            if hay.windows(window).any(|w: &[u8]| w == seg) {
                return window;
            }
            start += 64;
        }
        window = window.saturating_sub(window / 8 + 1);
    }
    0
}
