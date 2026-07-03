#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{FileIdReport, IdentityKind, identify_file};

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push(rel);
    fs::read(&p).ok()
}

fn require(rel: &str) -> Vec<u8> {
    corpus(rel).unwrap_or_else(|| panic!("committed corpus sample missing: corpus/{rel}"))
}

fn finding_family<'a>(
    report: &'a FileIdReport,
    family: &str,
) -> Option<&'a disrobe_pass_native::Finding> {
    report
        .findings
        .iter()
        .find(|f: &&disrobe_pass_native::Finding| f.family == family)
}

#[test]
fn upx_packed_pe_detected_by_structure() {
    let bytes: Vec<u8> = require("native/packers/upx/hello.packed.nrv2b.exe");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        report.format.starts_with("pe"),
        "format was {}",
        report.format
    );
    let upx: &disrobe_pass_native::Finding =
        finding_family(&report, "upx").expect("upx must be detected");
    assert_eq!(upx.kind, IdentityKind::Packer);
    assert!(
        upx.confidence >= 90,
        "structural UPX confidence: {}",
        upx.confidence
    );
    assert!(
        upx.evidence
            .iter()
            .any(|e: &disrobe_pass_native::Evidence| e.locus.contains("UPX")),
        "UPX section evidence: {:?}",
        upx.evidence
    );
}

#[test]
fn upx_original_is_not_flagged_as_upx() {
    let bytes: Vec<u8> = require("native/packers/upx/hello.original.exe");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        finding_family(&report, "upx").is_none(),
        "the unpacked original must not be tagged UPX: {:?}",
        report.findings
    );
}

#[test]
fn aspack_packed_pe_detected() {
    let bytes: Vec<u8> = require("native/packers/aspack/AccessEnum.packed.aspack.exe");
    let report: FileIdReport = identify_file(&bytes);
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "aspack").expect("aspack must be detected");
    assert_eq!(hit.kind, IdentityKind::Packer);
    assert!(hit.confidence >= 80);
}

#[test]
fn pecompact_packed_pe_detected() {
    let bytes: Vec<u8> = require("native/packers/pecompact/AccessEnum.packed.pecompact.exe");
    let report: FileIdReport = identify_file(&bytes);
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "pecompact").expect("pecompact must be detected");
    assert_eq!(hit.kind, IdentityKind::Packer);
}

#[test]
fn kkrunchy_packed_pe_detected() {
    let bytes: Vec<u8> = require("native/packers/kkrunchy/hello.packed.kkrunchy.exe");
    let report: FileIdReport = identify_file(&bytes);
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "kkrunchy").expect("kkrunchy must be detected");
    assert_eq!(hit.kind, IdentityKind::Packer);
}

#[test]
fn mew_packed_pe_detected() {
    let bytes: Vec<u8> = require("native/packers/mew/AccessEnum.packed.mew.exe");
    let report: FileIdReport = identify_file(&bytes);
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "mew").expect("mew must be detected");
    assert_eq!(hit.kind, IdentityKind::Packer);
}

#[test]
fn yodas_protector_packed_pe_detected() {
    let bytes: Vec<u8> =
        require("native/packers/yodas_protector/AccessEnum.packed.yodasprotector.exe");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        report.format.starts_with("pe"),
        "format was {}",
        report.format
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f: &disrobe_pass_native::Finding| {
                matches!(f.kind, IdentityKind::Packer | IdentityKind::Protector)
            }),
        "yodas protector must produce a packer/protector finding: {:?}",
        report.findings
    );
}

#[test]
fn managed_dotnet_pe_detected_structurally() {
    let bytes: Vec<u8> = require("dotnet/HelloApp.dll");
    let report: FileIdReport = identify_file(&bytes);
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "dotnet").expect(".NET assembly must be detected");
    assert_eq!(hit.kind, IdentityKind::Compiler);
    assert_eq!(
        hit.support,
        disrobe_pass_native::SupportRoute::DotnetDecompile,
        "managed PE must route to the dotnet decompiler"
    );
    assert!(
        hit.evidence
            .iter()
            .any(|e: &disrobe_pass_native::Evidence| {
                e.kind == disrobe_pass_native::EvidenceKind::DataDirectory
            }),
        "expected CLR data-directory evidence: {:?}",
        hit.evidence
    );
}

#[test]
fn confuserex_obfuscated_dotnet_detected() {
    let bytes: Vec<u8> = require("dotnet/megafile/EdgeCases.confuserex2.dll");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        finding_family(&report, "confuserex").is_some(),
        "ConfuserEx marker must be detected: {:?}",
        report.findings
    );
    assert!(
        finding_family(&report, "dotnet").is_some(),
        "the underlying assembly must still be recognized as .NET"
    );
}

#[test]
fn nim_elf_compiler_detected() {
    let bytes: Vec<u8> = require("native/nim/hello.nim.elf");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        report.format.starts_with("elf"),
        "format was {}",
        report.format
    );
    assert!(
        finding_family(&report, "nim").is_some(),
        "Nim runtime symbol must be detected: {:?}",
        report.findings
    );
}

#[test]
fn swift_macho_detected_by_section() {
    let bytes: Vec<u8> = require("mobile/macho-mac/SwiftHello.original");
    let report: FileIdReport = identify_file(&bytes);
    assert!(
        report.format.starts_with("macho"),
        "format was {}",
        report.format
    );
    let hit: &disrobe_pass_native::Finding =
        finding_family(&report, "swift").expect("Swift must be detected");
    assert_eq!(hit.kind, IdentityKind::Compiler);
    assert!(
        hit.evidence
            .iter()
            .any(|e: &disrobe_pass_native::Evidence| {
                e.kind == disrobe_pass_native::EvidenceKind::SectionName
            }),
        "expected a __swift5 section as evidence: {:?}",
        hit.evidence
    );
}

#[test]
fn macho_fat_universal_recognized() {
    let bytes: Vec<u8> = require("mac/megafile/EdgeCases.fat");
    let report: FileIdReport = identify_file(&bytes);
    assert_eq!(report.format, "macho-fat");
    assert!(
        finding_family(&report, "macho-fat").is_some(),
        "fat container must be flagged: {:?}",
        report.findings
    );
}

#[test]
fn every_finding_has_evidence_and_route() {
    let samples: [&str; 4] = [
        "native/packers/upx/hello.packed.nrv2b.exe",
        "dotnet/HelloApp.dll",
        "native/nim/hello.nim.elf",
        "mobile/macho-mac/SwiftHello.original",
    ];
    for rel in samples {
        let Some(bytes): Option<Vec<u8>> = corpus(rel) else {
            eprintln!("skip {rel}: sample missing");
            continue;
        };
        let report: FileIdReport = identify_file(&bytes);
        for finding in &report.findings {
            assert!(
                !finding.evidence.is_empty(),
                "{rel}: finding {} has no evidence",
                finding.family
            );
            assert!(
                !finding.support.command().is_empty(),
                "{rel}: finding {} has no support route",
                finding.family
            );
            assert!(finding.confidence > 0, "{rel}: zero confidence finding");
        }
    }
}

#[test]
fn sourcing_gaps_are_reported_not_faked() {
    let needed: [(&str, &str); 3] = [
        (
            "go",
            "native/go/hello.go.elf (no committed Go ELF/PE sample)",
        ),
        (
            "rust",
            "native/rust/hello.rs.elf (no committed Rust ELF/PE sample)",
        ),
        (
            "themida",
            "native/packers/themida/*.exe (commercial VM-protector, detect+carve only)",
        ),
    ];
    for (family, note) in needed {
        if corpus(&format!("native/{family}")).is_none() {
            eprintln!("sourcing-needed: {family} -> {note}");
        }
    }
}
