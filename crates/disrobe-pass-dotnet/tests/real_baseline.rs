#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{MetadataRoot, RuntimeLabel, parse_metadata_root};
use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

const HELLOAPP_NET9_REL: &str = "../../corpus/dotnet/HelloApp.dll";
const HELLOAPP_LEGACY_REL: &str = "../../corpus/dotnet/HelloAppLegacy.dll";
const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn helloapp_net9_parses_as_managed_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_NET9_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        pe.clr_directory().is_some(),
        "net9 console DLL must have CLR data directory"
    );
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    assert!(clr.metadata.rva > 0, "metadata rva populated");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
    let label: RuntimeLabel = root.runtime_label();
    assert!(
        matches!(
            label,
            RuntimeLabel::NetFramework4
                | RuntimeLabel::Net5
                | RuntimeLabel::Net6
                | RuntimeLabel::Net7
                | RuntimeLabel::Net8
                | RuntimeLabel::Net9
                | RuntimeLabel::Net10OrLater
                | RuntimeLabel::Unknown
        ),
        "got {label:?} for version {:?}",
        root.version
    );
    assert!(!root.streams.is_empty());
}

#[test]
fn helloapp_legacy_parses_as_netstandard_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_LEGACY_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
    assert!(!root.version.is_empty());
}

#[test]
fn edgecases_megafile_baseline_parses() {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let pe: PeImage = parse(&bytes).expect("parse megafile baseline");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
    assert!(
        !root.streams.is_empty(),
        "megafile must declare metadata streams"
    );
    assert!(
        bytes.len() > 16 * 1024,
        "megafile baseline DLL should be at least 16 KiB"
    );
}

#[test]
fn helloapp_net9_no_obfuscation_detected() {
    let bytes: Vec<u8> = load(HELLOAPP_NET9_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    assert!(
        summary.primary_protector.is_none(),
        "clean managed PE must not flag any protector; got {:?}",
        summary.primary_protector
    );
}

#[test]
fn edgecases_baseline_no_obfuscation_detected() {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let summary: PassSummary = analyze(&bytes).expect("analyze");
    assert!(
        summary.primary_protector.is_none(),
        "unobfuscated megafile must not flag any protector; got {:?}",
        summary.primary_protector
    );
}
