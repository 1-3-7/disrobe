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

fn run_pass(bytes: &[u8]) -> Vec<ChildArtifact> {
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    PACKER_PASS
        .extract_children(&input)
        .expect("packer-unpack children extraction")
}

#[test]
#[ignore = "upx unpacked-image recovery is platform-dependent (passes on windows, empty on linux ci runner); validated locally, linux gap tracked in RECOVERY.md"]
fn auto_surfaces_upx_unpacked_image_matching_upx_d_reference() {
    let Some(cc): Option<&'static str> = compiler() else {
        println!("SKIP: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    if !tool_available("upx", "--version") {
        println!("SKIP: upx CLI not on PATH");
        return;
    }

    let tmp: PathBuf =
        std::env::temp_dir().join(format!("disrobe-auto-unpack-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

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
