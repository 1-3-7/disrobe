#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::r2r::{R2rHeader, R2rReport, detect as r2r_detect};

const HELLOAPP_R2R_DLL_REL: &str = "../../corpus/dotnet/HelloApp.r2r.dll";
const HELLOAPP_R2R_EXE_REL: &str = "../../corpus/dotnet/HelloApp.r2r.exe";
const EDGECASES_R2R_DLL_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.r2r.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

#[test]
fn r2r_helloapp_dll_parses_as_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        pe.clr_directory().is_some(),
        "R2R DLL keeps CLR data directory"
    );
}

#[test]
fn r2r_helloapp_exe_parses_as_pe() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_EXE_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(
        bytes.len() > 64 * 1024,
        "self-contained R2R executable is at least 64 KiB"
    );
    assert!(pe.number_of_sections >= 1);
}

#[test]
fn r2r_edgecases_dll_parses_as_pe() {
    let bytes: Vec<u8> = load(EDGECASES_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    assert!(pe.clr_directory().is_some());
    assert!(bytes.len() > 16 * 1024);
}

#[test]
fn r2r_edgecases_dll_report_inspectable() {
    let bytes: Vec<u8> = load(EDGECASES_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let report: R2rReport = r2r_detect(&bytes, &pe, &clr);
    let header: R2rHeader = report
        .header
        .expect("R2R header present in EdgeCases.r2r.dll");
    assert_eq!(header.magic, disrobe_pass_dotnet::r2r::R2R_MAGIC);
    assert_eq!(header.major_version, 10);
    assert_eq!(header.minor_version, 1);
    assert_eq!(header.number_of_sections, 15);
    assert!(report.present);
    assert!(!report.composite_image);
}

#[test]
fn r2r_helloapp_dll_header_passes_invariants() {
    let bytes: Vec<u8> = load(HELLOAPP_R2R_DLL_REL);
    let pe: PeImage = parse(&bytes).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let report: R2rReport = r2r_detect(&bytes, &pe, &clr);
    let header: R2rHeader = report
        .header
        .expect("R2R header present in HelloApp.r2r.dll");
    assert_eq!(header.magic, disrobe_pass_dotnet::r2r::R2R_MAGIC);
    assert_eq!(header.major_version, 10);
    assert_eq!(header.number_of_sections, 11);
}
