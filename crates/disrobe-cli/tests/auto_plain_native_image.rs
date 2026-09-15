#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::chain::{
    ChainDocument, DetectContext, DetectVerdict, Detector, DetectorPick, NodeDoc, PassRegistry,
    VerdictDoc,
};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::chain_detector::NativeImageDetector;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind};

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
const PE_GUARD_CF_STRIPPED: &[u8] =
    include_bytes!("../../disrobe-pass-native/tests/fixtures/pe_arm64_guard_cf.exe");
const PE_GUARD_CF_REFERENCE: &[u8] =
    include_bytes!("../../disrobe-pass-native/tests/fixtures/pe_arm64_guard_cf.reference.exe");

const ELF_EH_FRAME_HDR_SOURCE: &str = r#"
__attribute__((noinline, visibility("hidden"))) long header_alpha(long value) {
    return value + 3;
}

__attribute__((noinline, visibility("hidden"))) long header_beta(long value) {
    return value * 5;
}

__attribute__((noinline, visibility("hidden"))) long header_gamma(long value) {
    return value ^ 7;
}
"#;

const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

const TOOL_CAPTURE_LIMIT: usize = 1 << 20;

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

fn aarch64_eh_frame_hdr_images(directory: &Path) -> (Vec<u8>, Vec<u8>, PathBuf) {
    let source: PathBuf = directory.join("eh_frame_hdr.c");
    let reference: PathBuf = directory.join("eh_frame_hdr.reference.so");
    let stripped: PathBuf = directory.join("eh_frame_hdr.stripped.so");
    std::fs::write(&source, ELF_EH_FRAME_HDR_SOURCE).expect("write fixture source");
    let arguments: Vec<OsString> = vec![
        OsString::from("--target=aarch64-unknown-linux-gnu"),
        OsString::from("-O1"),
        OsString::from("-fPIC"),
        OsString::from("-fuse-ld=lld"),
        OsString::from("-nostdlib"),
        OsString::from("-shared"),
        OsString::from("-Wl,--eh-frame-hdr"),
        OsString::from("-o"),
        reference.as_os_str().to_os_string(),
        source.as_os_str().to_os_string(),
    ];
    let compiled: CapturedOutput = run_captured(
        Path::new("clang"),
        &arguments,
        TOOL_TIMEOUT,
        TOOL_CAPTURE_LIMIT,
    )
    .expect("start the AArch64 eh-frame-header fixture compiler")
    .expect("the AArch64 eh-frame-header fixture compiler exceeded its timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "clang failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let strip_arguments: Vec<OsString> = vec![
        OsString::from("--strip-all"),
        OsString::from("-o"),
        stripped.as_os_str().to_os_string(),
        reference.as_os_str().to_os_string(),
    ];
    let stripped_output: CapturedOutput = run_captured(
        Path::new("llvm-strip"),
        &strip_arguments,
        TOOL_TIMEOUT,
        TOOL_CAPTURE_LIMIT,
    )
    .expect("start the AArch64 fixture stripper")
    .expect("the AArch64 fixture stripper exceeded its timeout");
    assert_eq!(
        stripped_output.exit_code,
        Some(0),
        "llvm-strip failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stripped_output.stdout),
        String::from_utf8_lossy(&stripped_output.stderr)
    );
    (
        std::fs::read(reference).expect("read unstripped eh-frame-header fixture"),
        std::fs::read(&stripped).expect("read stripped eh-frame-header fixture"),
        stripped,
    )
}

fn eh_frame_header_reference_starts(reference: &[u8]) -> BTreeSet<u64> {
    let file: object::File<'_> =
        object::File::parse(reference).expect("the unstripped reference must parse");
    file.symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| {
            matches!(symbol.kind(), ObjSymbolKind::Text)
                && !symbol.is_undefined()
                && symbol
                    .name()
                    .is_ok_and(|name: &str| name.starts_with("header_"))
        })
        .map(|symbol: object::Symbol<'_, '_>| symbol.address())
        .collect()
}

fn pe_guard_cf_reference_starts(reference: &[u8]) -> BTreeSet<u64> {
    let file: object::File<'_> =
        object::File::parse(reference).expect("the unstripped reference must parse");
    file.symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| {
            matches!(symbol.kind(), ObjSymbolKind::Text)
                && !symbol.is_undefined()
                && symbol
                    .name()
                    .is_ok_and(|name: &str| name.starts_with("guard_"))
        })
        .map(|symbol: object::Symbol<'_, '_>| symbol.address())
        .collect()
}

fn erase_section_contents(bytes: &mut [u8], name: &str) {
    let file: object::File<'_> = object::File::parse(&*bytes).expect("parse linked fixture");
    let section: object::Section<'_, '_> = file
        .section_by_name(name)
        .expect("the linked fixture must contain the requested section");
    let (offset, size): (u64, u64) = section.file_range().expect("section has a file range");
    let start: usize = usize::try_from(offset).expect("section offset fits usize");
    let length: usize = usize::try_from(size).expect("section size fits usize");
    let end: usize = start
        .checked_add(length)
        .expect("section extent fits usize");
    bytes
        .get_mut(start..end)
        .expect("section range lies inside linked fixture")
        .fill(0);
}

fn cargo_bin() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
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
fn auto_presents_aarch64_eh_frame_header_starts_through_production_registry() {
    let directory: tempfile::TempDir = tempfile::tempdir().expect("create fixture directory");
    let (reference, mut stripped, stripped_path): (Vec<u8>, Vec<u8>, PathBuf) =
        aarch64_eh_frame_hdr_images(directory.path());
    let expected: BTreeSet<u64> = eh_frame_header_reference_starts(&reference);
    assert_eq!(
        expected.len(),
        3,
        "compiler reference must expose three starts"
    );

    erase_section_contents(&mut stripped, ".eh_frame");
    std::fs::write(&stripped_path, &stripped).expect("write header-only fixture");
    assert_eq!(
        winning_pass_id(&stripped).as_deref(),
        Some(NATIVE_IMAGE_PASS_ID),
        "the production registry must select the native pass for the header-only image",
    );

    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("aarch64-eh-frame-header");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: CapturedOutput = run_auto(&stripped_path, &out);
    assert_eq!(
        proc_out.exit_code,
        Some(0),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&proc_out.stderr),
    );

    let raw_chain: String =
        std::fs::read_to_string(out.join("chain.json")).expect("read auto chain document");
    let chain: ChainDocument = serde_json::from_str(&raw_chain).expect("parse auto chain document");
    let native: &NodeDoc = chain
        .nodes
        .iter()
        .find(|node: &&NodeDoc| node.pass.as_deref() == Some(NATIVE_IMAGE_PASS_ID))
        .expect("auto chain must contain the native pass");
    assert_eq!(native.verdict, VerdictDoc::FanOut);

    let report_path: PathBuf =
        find_file_named(&out, "pseudo-source.json").expect("auto must write pseudo-source.json");
    let report_bytes: Vec<u8> = std::fs::read(report_path).expect("read pseudo-source report");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse pseudo-source report");
    assert_eq!(report["run"], true);
    let presented: BTreeSet<u64> = ["recovered", "unrecovered"]
        .into_iter()
        .flat_map(|key: &str| {
            report[key]
                .as_array()
                .expect("function result collection must be an array")
        })
        .map(|function: &serde_json::Value| {
            function["address"]
                .as_u64()
                .expect("function result must carry an address")
        })
        .collect();
    assert!(
        expected.is_subset(&presented),
        "auto presented {presented:?}, missing compiler starts {expected:?}",
    );
}

#[test]
fn auto_presents_pe_arm64_guard_cf_starts_through_production_registry() {
    let expected: BTreeSet<u64> = pe_guard_cf_reference_starts(PE_GUARD_CF_REFERENCE);
    assert_eq!(
        expected.len(),
        4,
        "compiler reference must expose four starts"
    );
    assert_eq!(
        winning_pass_id(PE_GUARD_CF_STRIPPED).as_deref(),
        Some(NATIVE_IMAGE_PASS_ID),
        "the production registry must select the native pass for the stripped PE image",
    );
    let input: PathBuf = workspace_root()
        .join("crates")
        .join("disrobe-pass-native")
        .join("tests")
        .join("fixtures")
        .join("pe_arm64_guard_cf.exe");
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("pe-arm64-guard-cf");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: CapturedOutput = run_auto(&input, &out);
    assert_eq!(
        proc_out.exit_code,
        Some(0),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&proc_out.stderr),
    );
    let report_path: PathBuf =
        find_file_named(&out, "pseudo-source.json").expect("auto must write pseudo-source.json");
    let report_bytes: Vec<u8> = std::fs::read(report_path).expect("read pseudo-source report");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse pseudo-source report");
    assert_eq!(report["run"], true);
    let presented: BTreeSet<u64> = ["recovered", "unrecovered"]
        .into_iter()
        .flat_map(|key: &str| {
            report[key]
                .as_array()
                .expect("function result collection must be an array")
        })
        .map(|function: &serde_json::Value| {
            function["address"]
                .as_u64()
                .expect("function result must carry an address")
        })
        .collect();
    assert!(
        expected.is_subset(&presented),
        "auto presented {presented:?}, missing compiler starts {expected:?}",
    );
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
