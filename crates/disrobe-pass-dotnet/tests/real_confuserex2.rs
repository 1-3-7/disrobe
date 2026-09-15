#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{METADATA_SIGNATURE, MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::protectors::{
    ExecuteOptions, ExecutionOutcome, Protector, plan_execution,
};

const HELLOAPP_CONFUSED_REL: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";
const EDGECASES_CONFUSED_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll";
const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn confused_helloapp_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_CONFUSED_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header survives obfuscation");
    let root: MetadataRoot =
        parse_metadata_root(&bytes, &pe, &clr).expect("metadata root survives obfuscation");
    assert!(
        !root.streams.is_empty(),
        "obfuscated DLL still carries metadata streams"
    );
    assert_eq!(root.signature, METADATA_SIGNATURE);
}

#[test]
fn confused_megafile_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(EDGECASES_CONFUSED_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header survives obfuscation");
    let root: MetadataRoot =
        parse_metadata_root(&bytes, &pe, &clr).expect("metadata root survives obfuscation");
    assert_eq!(root.signature, METADATA_SIGNATURE);
    assert!(
        bytes.len() > 16 * 1024,
        "obfuscated megafile must be larger than empty managed PE"
    );
}

#[test]
fn confused_helloapp_detected_by_signature_scanner() {
    let bytes: Vec<u8> = load(HELLOAPP_CONFUSED_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    let any_confuser: bool = summary
        .protectors_detected
        .iter()
        .any(|p: &Protector| matches!(p, Protector::ConfuserEx | Protector::ConfuserEx2));
    assert!(
        any_confuser,
        "ConfuserEx2 watermark string must be detectable in real protector output; got {:?}",
        summary.protectors_detected
    );
}

#[test]
fn confused_megafile_detected_by_signature_scanner() {
    let bytes: Vec<u8> = load(EDGECASES_CONFUSED_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    let any_confuser: bool = summary
        .protectors_detected
        .iter()
        .any(|p: &Protector| matches!(p, Protector::ConfuserEx | Protector::ConfuserEx2));
    assert!(
        any_confuser,
        "ConfuserEx2 watermark must persist after full-megafile protection; got {:?}",
        summary.protectors_detected
    );
}

#[test]
fn confuserex2_planning_yields_de4dot_delegation() {
    let plan: ExecutionOutcome = plan_execution(Protector::ConfuserEx2, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::DelegatedToDe4dot));
}

#[test]
fn confused_megafile_bytes_differ_from_baseline_and_grow() {
    let baseline: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let confused: Vec<u8> = load(EDGECASES_CONFUSED_REL);
    assert_ne!(
        baseline, confused,
        "obfuscated megafile bytes must differ from baseline"
    );
    assert!(
        confused.len() > baseline.len(),
        "ConfuserEx2 normal preset typically grows the PE (cflow + ref-proxy + anti-tamper bloat); got baseline={} confused={}",
        baseline.len(),
        confused.len()
    );
}
