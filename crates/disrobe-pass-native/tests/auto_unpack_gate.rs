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
use disrobe_pass_native::{UpxUnpackOutput, unpack_upx};

const KNOWN_MARKER: &[u8] = b"disrobe-auto-unpack-known-plaintext-marker-9f3a7c1e";
const REQUIRE_GO: &str = "DISROBE_REQUIRE_GO";
const REQUIRE_UPX: &str = "DISROBE_REQUIRE_UPX";

fn tool_available(name: &str, arg: &str) -> bool {
    Command::new(name)
        .arg(arg)
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn required_by_env(variable: &str) -> bool {
    let Some(raw): Option<std::ffi::OsString> = std::env::var_os(variable) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn tool_is_unmeasured(
    available: bool,
    required: bool,
    tool: &str,
    requirement: &str,
    absent: &str,
) -> bool {
    if available {
        return false;
    }
    assert!(
        !required,
        "{requirement} makes {tool} mandatory for this run, so the auto UPX gate would grade nothing"
    );
    println!("SKIP: {absent}; set {requirement}=1 to fail instead of skipping");
    true
}

fn command_is_unmeasured(
    succeeded: bool,
    stderr: &[u8],
    required: bool,
    operation: &str,
    requirement: &str,
) -> bool {
    if succeeded {
        return false;
    }
    let diagnostic: std::borrow::Cow<'_, str> = String::from_utf8_lossy(stderr);
    assert!(
        !required,
        "{requirement} makes {operation} mandatory for this run, so the auto UPX gate would grade nothing: {diagnostic}"
    );
    println!("SKIP: {operation}: {diagnostic}");
    true
}

#[test]
fn required_tool_absence_never_reports_a_successful_unmeasured_gate() {
    let required: std::thread::Result<bool> = std::panic::catch_unwind(|| {
        tool_is_unmeasured(
            false,
            true,
            "upx",
            "DISROBE_REQUIRE_UPX",
            "upx CLI not on PATH",
        )
    });
    assert!(
        required.is_err(),
        "a required missing tool must fail instead of silently skipping the gate"
    );
    assert!(tool_is_unmeasured(
        false,
        false,
        "upx",
        "DISROBE_REQUIRE_UPX",
        "upx CLI not on PATH"
    ));
    assert!(!tool_is_unmeasured(
        true,
        true,
        "upx",
        "DISROBE_REQUIRE_UPX",
        "upx CLI not on PATH"
    ));
}

#[test]
fn required_command_failure_never_reports_a_successful_unmeasured_gate() {
    let stderr: &[u8] = b"reference command failed";
    let required: std::thread::Result<bool> = std::panic::catch_unwind(|| {
        command_is_unmeasured(
            false,
            stderr,
            true,
            "upx pack failed",
            "DISROBE_REQUIRE_UPX",
        )
    });
    assert!(
        required.is_err(),
        "a required command failure must fail instead of silently skipping the gate"
    );
    assert!(command_is_unmeasured(
        false,
        stderr,
        false,
        "upx pack failed",
        "DISROBE_REQUIRE_UPX"
    ));
    assert!(!command_is_unmeasured(
        true,
        stderr,
        true,
        "upx pack failed",
        "DISROBE_REQUIRE_UPX"
    ));
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
        let _: bool = tool_is_unmeasured(
            false,
            required_by_env(REQUIRE_UPX),
            "a C compiler (gcc, clang, or cc)",
            REQUIRE_UPX,
            "no C compiler (gcc/clang/cc) on PATH",
        );
        return;
    };
    if tool_is_unmeasured(
        tool_available("upx", "--version"),
        required_by_env(REQUIRE_UPX),
        "the upx CLI",
        REQUIRE_UPX,
        "upx CLI not on PATH",
    ) {
        return;
    }

    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack").expect("create scratch directory");
    let tmp: &Path = scratch.path();

    let src: PathBuf = write_source(tmp);
    let exe: PathBuf = tmp.join("known_plaintext.exe");
    let compile: std::process::Output = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("invoke compiler");
    if command_is_unmeasured(
        compile.status.success(),
        &compile.stderr,
        required_by_env(REQUIRE_UPX),
        "compiler failed",
        REQUIRE_UPX,
    ) {
        let _ = std::fs::remove_dir_all(tmp);
        return;
    }

    let packed: PathBuf = tmp.join("packed.exe");
    std::fs::copy(&exe, &packed).expect("copy to packed path");
    let pack: std::process::Output = Command::new("upx")
        .arg("--best")
        .arg(packed.to_str().expect("path utf8"))
        .output()
        .expect("invoke upx pack");
    if command_is_unmeasured(
        pack.status.success(),
        &pack.stderr,
        required_by_env(REQUIRE_UPX),
        "upx pack failed",
        REQUIRE_UPX,
    ) {
        let _ = std::fs::remove_dir_all(tmp);
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

    let _ = std::fs::remove_dir_all(tmp);
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
    if tool_is_unmeasured(
        tool_available("go", "version"),
        required_by_env(REQUIRE_GO),
        "the Go toolchain",
        REQUIRE_GO,
        "go toolchain not on PATH (needed to build an ELF host-independently)",
    ) {
        return None;
    }
    if tool_is_unmeasured(
        tool_available("upx", "--version"),
        required_by_env(REQUIRE_UPX),
        "the upx CLI",
        REQUIRE_UPX,
        "upx CLI not on PATH",
    ) {
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
    if command_is_unmeasured(
        build.status.success(),
        &build.stderr,
        required_by_env(REQUIRE_GO),
        "go build failed",
        REQUIRE_GO,
    ) {
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
    if command_is_unmeasured(
        pack.status.success(),
        &pack.stderr,
        required_by_env(REQUIRE_UPX),
        "upx pack failed",
        REQUIRE_UPX,
    ) {
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

struct ElfTailHeader {
    method: u8,
    uncompressed_len: usize,
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: &[u8] = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

fn elf_tail_header(packed: &[u8]) -> Option<ElfTailHeader> {
    let last: usize = packed.len().checked_sub(32)?;
    let first: usize = last.saturating_sub(4096);
    for offset in (first..=last).rev() {
        let header: &[u8] = packed.get(offset..offset.checked_add(32)?)?;
        if header.get(..4)? != b"UPX!" {
            continue;
        }
        let method: u8 = *header.get(6)?;
        if header[4] == 0 || header[4] > 16 || !matches!(method, 2 | 5 | 8 | 14) {
            continue;
        }
        let uncompressed_len: usize = usize::try_from(read_u32_le(header, 16)?).ok()?;
        let compressed_len: usize = usize::try_from(read_u32_le(header, 20)?).ok()?;
        let file_size: usize = usize::try_from(read_u32_le(header, 24)?).ok()?;
        if uncompressed_len == 0
            || compressed_len == 0
            || compressed_len > packed.len()
            || uncompressed_len != file_size
        {
            continue;
        }
        return Some(ElfTailHeader {
            method,
            uncompressed_len,
        });
    }
    None
}

fn elf_first_block(packed: &[u8], uncompressed_len: usize) -> Option<usize> {
    let limit: usize = packed.len().min(64 * 1024);
    packed
        .get(..limit)?
        .windows(4)
        .enumerate()
        .find_map(|(offset, bytes)| {
            (bytes == b"UPX!")
                .then(|| read_u32_le(packed, offset.checked_add(12)?))
                .flatten()
                .is_some_and(|value: u32| value as usize == uncompressed_len)
                .then(|| offset.checked_add(20))
                .flatten()
        })
}

fn compressed_elf_extent(packed: &[u8]) -> Option<std::ops::Range<usize>> {
    if !packed.starts_with(b"\x7fELF") {
        return None;
    }
    let header: ElfTailHeader = elf_tail_header(packed)?;
    let mut remaining: usize = header.uncompressed_len;
    let mut block: usize = elf_first_block(packed, remaining)?;
    while remaining != 0 {
        let info: &[u8] = packed.get(block..block.checked_add(12)?)?;
        let uncompressed_len: usize = usize::try_from(read_u32_le(info, 0)?).ok()?;
        let compressed_len: usize = usize::try_from(read_u32_le(info, 4)?).ok()?;
        if uncompressed_len == 0
            || uncompressed_len > remaining
            || compressed_len == 0
            || compressed_len > uncompressed_len
            || info[11] != 0
        {
            return None;
        }
        let start: usize = block.checked_add(12)?;
        let end: usize = start.checked_add(compressed_len)?;
        packed.get(start..end)?;
        if compressed_len < uncompressed_len {
            if info[8] != header.method {
                return None;
            }
            return Some(start..end);
        }
        block = end;
        remaining = remaining.checked_sub(uncompressed_len)?;
    }
    None
}

fn direct_elf_recovery_matches_reference(packed: &[u8], reference: &[u8]) -> UpxUnpackOutput {
    let direct: UpxUnpackOutput =
        unpack_upx(packed).expect("public UPX decoder must recover the real packed ELF");
    assert!(
        direct.adler_verified,
        "public UPX decoder must verify the recovered ELF against the PackHeader adler"
    );
    assert!(
        contains(&direct.recovered_image, KNOWN_MARKER),
        "public UPX decoder output must contain the original known-plaintext marker"
    );
    assert_eq!(
        direct.recovered_image, reference,
        "public UPX decoder output must be byte-identical to the upx -d reference"
    );
    direct
}

#[test]
fn compressed_elf_extent_identifies_the_first_block_payload() {
    let mut packed: Vec<u8> = vec![0u8; 512];
    packed[..4].copy_from_slice(b"\x7fELF");
    let l_info: usize = 64;
    packed[l_info..l_info + 4].copy_from_slice(b"UPX!");
    packed[l_info + 12..l_info + 16].copy_from_slice(&8u32.to_le_bytes());
    let block: usize = l_info + 20;
    packed[block..block + 4].copy_from_slice(&8u32.to_le_bytes());
    packed[block + 4..block + 8].copy_from_slice(&4u32.to_le_bytes());
    packed[block + 8] = 2;
    packed[block + 12..block + 16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let tail: usize = packed.len() - 32;
    packed[tail..tail + 4].copy_from_slice(b"UPX!");
    packed[tail + 4] = 1;
    packed[tail + 6] = 2;
    packed[tail + 16..tail + 20].copy_from_slice(&8u32.to_le_bytes());
    packed[tail + 20..tail + 24].copy_from_slice(&4u32.to_le_bytes());
    packed[tail + 24..tail + 28].copy_from_slice(&8u32.to_le_bytes());

    assert_eq!(compressed_elf_extent(&packed), Some(block + 12..block + 16));
}

#[test]
fn public_upx_decoder_matches_upx_d_for_a_real_packed_go_elf() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-direct-upx-elf").expect("create scratch directory");
    let tmp: &Path = scratch.path();
    let Some((packed_bytes, reference)): Option<(Vec<u8>, Vec<u8>)> = build_packed_elf(tmp) else {
        return;
    };

    let _: UpxUnpackOutput = direct_elf_recovery_matches_reference(&packed_bytes, &reference);

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn auto_surfaces_upx_unpacked_elf_byte_identical_to_upx_d_reference() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack-elf").expect("create scratch directory");
    let tmp: &Path = scratch.path();
    let Some((packed_bytes, reference)): Option<(Vec<u8>, Vec<u8>)> = build_packed_elf(tmp) else {
        return;
    };

    let direct: UpxUnpackOutput = direct_elf_recovery_matches_reference(&packed_bytes, &reference);

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
    assert_eq!(
        recovered,
        direct.recovered_image.as_slice(),
        "auto extraction must preserve the public UPX decoder output"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn corrupting_one_compressed_byte_rejects_the_elf_in_the_public_decoder() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-auto-unpack-elf-mutate").expect("create scratch directory");
    let tmp: &Path = scratch.path();
    let Some((packed_bytes, reference)): Option<(Vec<u8>, Vec<u8>)> = build_packed_elf(tmp) else {
        return;
    };

    let baseline: UpxUnpackOutput = unpack_upx(&packed_bytes)
        .expect("unmutated packed ELF must decode through the public path");
    assert_eq!(
        baseline.recovered_image, reference,
        "unmutated public decoder output must be byte-identical to the upx -d reference"
    );
    let extent: std::ops::Range<usize> = compressed_elf_extent(&packed_bytes)
        .expect("packed ELF must expose a compressed UPX block");
    assert!(
        !extent.is_empty(),
        "parsed compressed UPX block must contain at least one byte"
    );
    let mut mutated: Vec<u8> = packed_bytes;
    let victim: usize = extent.start + extent.len() / 2;
    mutated[victim] ^= 0xff;
    assert!(
        unpack_upx(&mutated).is_err(),
        "corrupting a byte from a parsed compressed UPX ELF extent must fail the public decoder"
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
