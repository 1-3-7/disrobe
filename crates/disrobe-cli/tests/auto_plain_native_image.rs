#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::chain::{
    ChainDocument, DetectContext, DetectVerdict, Detector, DetectorPick, NodeDoc, PassRegistry,
    VerdictDoc,
};
use disrobe_pass_native::chain_detector::NativeImageDetector;

const NATIVE_IMAGE_PASS_ID: &str = "native.image-classify";

const PLAIN_PE: &str = "native/packers/aspack/AccessEnum.original.exe";
const PLAIN_ELF: &str = "native/discovery/disc.unstripped.elf";
const SWIFT_MACHO: &str = "mobile/macho-mac/SwiftHello.original";
const NIM_ELF: &str = "native/nim/hello.nim.elf";
const GO_PE: &str = "native/compilers/go/hello.go.exe";
const DOTNET_DLL: &str = "dotnet/HelloApp.dll";
const PLAIN_MACHO: &[u8] = include_bytes!("fixtures/native/plain_x86_64.macho");
const OBJC_MACHO: &[u8] = include_bytes!(
    "../../disrobe-pass-swift-objc/tests/fixtures/objc_dispatch/dispatch_sends_x86_64.macho"
);

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn plain_macho_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("native")
        .join("plain_x86_64.macho")
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "{} is tracked in git and this case grades nothing without it, so its absence is a \
             damaged checkout rather than an optional dependency: {e}",
            path.display()
        )
    })
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-native-image-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_auto(input: &Path, out: &Path) -> disrobe_core::subprocess::CapturedOutput {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    let mut command: Command = Command::new(&bin);
    command
        .arg("auto")
        .arg(input)
        .arg("--out")
        .arg(out)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"));
    disrobe_core::subprocess::wait_with_direct_process_output_timeout(
        child,
        Duration::from_secs(30),
        1 << 20,
    )
    .expect("disrobe auto must complete within 30 seconds with bounded output")
}

const fn detect_context(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 1,
    }
}

fn winning_verdict(bytes: &[u8]) -> Option<DetectVerdict> {
    let registry: PassRegistry = disrobe_passes::build_registry();
    let candidates: Vec<DetectVerdict> = registry.run_all(&detect_context(bytes));
    registry.pick(candidates).map(|p: DetectorPick| p.verdict)
}

fn winning_pass_id(bytes: &[u8]) -> Option<String> {
    winning_verdict(bytes).map(|v: DetectVerdict| v.pass_id.to_string())
}

fn candidate_pass_ids(bytes: &[u8]) -> Vec<String> {
    let registry: PassRegistry = disrobe_passes::build_registry();
    let mut ids: Vec<String> = registry
        .run_all(&detect_context(bytes))
        .into_iter()
        .map(|verdict: DetectVerdict| verdict.pass_id.to_owned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn fat_macho(slices: &[&[u8]]) -> Vec<u8> {
    const HEADER_BYTES: usize = 8;
    const ARCH_BYTES: usize = 20;
    const ALIGNMENT: usize = 8;
    let table_bytes: usize = ARCH_BYTES
        .checked_mul(slices.len())
        .expect("bounded test slice count");
    let first_offset: usize = HEADER_BYTES
        .checked_add(table_bytes)
        .and_then(|value: usize| value.checked_add(ALIGNMENT - 1))
        .map(|value: usize| value & !(ALIGNMENT - 1))
        .expect("bounded test header");
    let mut offsets: Vec<usize> = Vec::with_capacity(slices.len());
    let mut cursor: usize = first_offset;
    for slice in slices {
        offsets.push(cursor);
        cursor = cursor
            .checked_add(slice.len())
            .and_then(|value: usize| value.checked_add(ALIGNMENT - 1))
            .map(|value: usize| value & !(ALIGNMENT - 1))
            .expect("bounded test fat image");
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(cursor);
    bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(slices.len())
            .expect("bounded test slice count")
            .to_be_bytes(),
    );
    for (index, (slice, offset)) in slices.iter().zip(&offsets).enumerate() {
        let cpu_type: u32 = if index == 0 { 0x0100_0007 } else { 0x0100_000c };
        bytes.extend_from_slice(&cpu_type.to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(*offset)
                .expect("bounded test slice offset")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(slice.len())
                .expect("bounded test slice length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&3_u32.to_be_bytes());
    }
    bytes.resize(first_offset, 0);
    for (slice, offset) in slices.iter().zip(offsets) {
        bytes.resize(offset, 0);
        bytes.extend_from_slice(slice);
    }
    bytes
}

fn native_image_verdict(bytes: &[u8]) -> Option<DetectVerdict> {
    Detector::detect(&NativeImageDetector, &detect_context(bytes))
}

#[test]
fn the_native_image_pass_is_registered_and_expected() {
    assert!(
        disrobe_passes::expected_pass_ids().contains(&NATIVE_IMAGE_PASS_ID),
        "the one construction site must list the pass id"
    );
    assert!(
        disrobe_passes::registered_pass_ids().contains(&NATIVE_IMAGE_PASS_ID),
        "the built registry must hold the pass, otherwise `disrobe auto` cannot reach it"
    );
    assert!(
        disrobe_passes::build_registry()
            .get(NATIVE_IMAGE_PASS_ID)
            .is_some(),
        "the pass must be resolvable by id so a pinned chain spec can select it"
    );
}

#[test]
fn a_plain_pe_and_elf_route_to_the_native_image_pass() {
    for rel in [PLAIN_PE, PLAIN_ELF] {
        let bytes: Vec<u8> = read_fixture(rel);
        assert_eq!(
            winning_pass_id(&bytes).as_deref(),
            Some(NATIVE_IMAGE_PASS_ID),
            "{rel} is a plain unpacked native image with no ecosystem marker, so the registry \
             must hand it to the native image pass instead of leaving it unclaimed",
        );
    }
}

#[test]
fn a_plain_macho_routes_to_native_while_swift_metadata_keeps_its_owner() {
    assert_eq!(
        winning_pass_id(PLAIN_MACHO).as_deref(),
        Some(NATIVE_IMAGE_PASS_ID),
        "a structurally valid Mach-O object without Swift or Objective-C metadata must use the native fallback",
    );

    let swift: Vec<u8> = read_fixture(SWIFT_MACHO);
    assert_eq!(
        winning_pass_id(&swift).as_deref(),
        Some("swift-objc.classify"),
        "semantic Swift evidence must keep the ecosystem-specific pass above the native fallback",
    );

    for truncated in [&PLAIN_MACHO[..4], &PLAIN_MACHO[..16]] {
        assert_eq!(
            winning_pass_id(truncated),
            None,
            "magic without a complete Mach-O header must not produce a native or Swift claim",
        );
    }
}

#[test]
fn fat_plain_and_semantic_macho_ranking_uses_slice_evidence() {
    let fat_plain: Vec<u8> = fat_macho(&[PLAIN_MACHO]);
    assert_eq!(
        candidate_pass_ids(&fat_plain),
        vec![NATIVE_IMAGE_PASS_ID.to_owned()],
        "a fat container with one plain structural slice must remain a native image",
    );
    assert_eq!(
        winning_pass_id(&fat_plain).as_deref(),
        Some(NATIVE_IMAGE_PASS_ID),
    );

    assert_eq!(
        winning_pass_id(OBJC_MACHO).as_deref(),
        Some("swift-objc.classify"),
        "Objective-C metadata in a thin image must outrank the structural native claim",
    );

    let fat_semantic: Vec<u8> = fat_macho(&[PLAIN_MACHO, OBJC_MACHO]);
    let candidates: Vec<String> = candidate_pass_ids(&fat_semantic);
    assert!(
        candidates.contains(&NATIVE_IMAGE_PASS_ID.to_owned()),
        "the structural native detector must enter the fat-image ranking contest: {candidates:?}",
    );
    assert!(
        candidates.contains(&"swift-objc.classify".to_owned()),
        "the semantic slice must enter the fat-image ranking contest: {candidates:?}",
    );
    assert_eq!(
        winning_pass_id(&fat_semantic).as_deref(),
        Some("swift-objc.classify"),
        "semantic evidence in one bounded fat slice must outrank the container fallback",
    );
}

#[test]
fn an_ecosystem_specific_binary_never_falls_to_the_native_image_pass() {
    for (rel, expected) in [
        (NIM_ELF, "nativelang.classify"),
        (GO_PE, "go.classify"),
        (DOTNET_DLL, "dotnet.classify"),
        (SWIFT_MACHO, "swift-objc.classify"),
    ] {
        let bytes: Vec<u8> = read_fixture(rel);
        let ours: DetectVerdict = native_image_verdict(&bytes).unwrap_or_else(|| {
            panic!(
                "{rel} is a structurally valid native image, so this pass must put a claim on the \
                 table for it. Without a claim the ranking assertion below would pass for the \
                 wrong reason, proving only that we never competed",
            )
        });
        let winner: DetectVerdict = winning_verdict(&bytes)
            .unwrap_or_else(|| panic!("{rel} must be claimed by some pass, not left unclaimed"));
        assert_eq!(
            winner.pass_id, expected,
            "{rel} carries a marker only {expected} knows how to read; the generic native image \
             claim must lose this ranking contest",
        );
        assert_eq!(
            disrobe_core::chain::compare(&winner, &ours),
            std::cmp::Ordering::Greater,
            "{expected} must beat the native image claim through precedence::compare itself, not \
             merely happen to be selected. ours={our_conf}/{our_spec} theirs={won_conf}/{won_spec}",
            our_conf = ours.confidence,
            our_spec = ours.specificity,
            won_conf = winner.confidence,
            won_spec = winner.specificity,
        );
    }
}

fn assert_auto_reaches_the_native_image_pass(rel: &str, scratch_name: &str) {
    let input: PathBuf = corpus_path(rel);
    assert_auto_path_reaches_the_native_image_pass(&input, rel, scratch_name);
}

fn assert_auto_path_reaches_the_native_image_pass(
    input: &Path,
    input_label: &str,
    scratch_name: &str,
) {
    assert!(
        input.exists(),
        "{} is tracked in git and this case grades nothing without it",
        input.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out(scratch_name);
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: disrobe_core::subprocess::CapturedOutput = run_auto(input, &out);
    assert_eq!(
        proc_out.exit_code,
        Some(0),
        "disrobe auto failed for {input_label}: {}",
        String::from_utf8_lossy(&proc_out.stderr),
    );

    let chain_json: PathBuf = out.join("chain.json");
    let raw: String = std::fs::read_to_string(&chain_json).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "cannot read chain.json at {chain_json:?}: {e}; stderr: {}",
            String::from_utf8_lossy(&proc_out.stderr)
        )
    });
    let doc: ChainDocument =
        serde_json::from_str(&raw).expect("chain.json must parse as the published chain document");

    let node: &NodeDoc = doc
        .nodes
        .iter()
        .find(|n: &&NodeDoc| n.pass.as_deref() == Some(NATIVE_IMAGE_PASS_ID))
        .unwrap_or_else(|| {
            panic!(
                "`disrobe auto {input_label}` must route to {NATIVE_IMAGE_PASS_ID}; the plan named these \
                 passes instead: {named:?}",
                named = doc
                    .nodes
                    .iter()
                    .filter_map(|n: &NodeDoc| n.pass.clone())
                    .collect::<Vec<String>>(),
            )
        });
    assert_eq!(
        node.verdict,
        VerdictDoc::FanOut,
        "the native image node must fan out into its report children, not stall or error",
    );
    assert_ne!(
        doc.verdict,
        VerdictDoc::Stalled,
        "`disrobe auto {input_label}` stalled before this item and must not stall now",
    );

    for sidecar in ["native-image.manifest.json", "identity.json"] {
        assert!(
            find_file_named(&out, sidecar).is_some(),
            "`disrobe auto {input_label}` must materialize the {sidecar} report on disk, not only name \
             the pass in the plan",
        );
    }
}

fn find_file_named(dir: &Path, target: &str) -> Option<PathBuf> {
    let read: std::fs::ReadDir = std::fs::read_dir(dir).ok()?;
    for entry in read.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, target) {
                return Some(found);
            }
        } else if entry.file_name().to_string_lossy() == target {
            return Some(path);
        }
    }
    None
}

#[test]
fn auto_reaches_the_native_image_pass_on_a_real_pe() {
    assert_auto_reaches_the_native_image_pass(PLAIN_PE, "pe");
}

#[test]
fn auto_reaches_the_native_image_pass_on_a_real_elf() {
    assert_auto_reaches_the_native_image_pass(PLAIN_ELF, "elf");
}

#[test]
fn auto_reaches_the_native_image_pass_on_a_real_plain_macho() {
    let input: PathBuf = plain_macho_path();
    assert_auto_path_reaches_the_native_image_pass(&input, "plain_x86_64.macho", "macho");
}
