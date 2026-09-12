#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_dotnet::pe::{ClrHeader, PeBitness, PeImage, parse, parse_clr_header};

use crate::common::synth_minimal_dotnet_pe;

#[test]
fn synth_pe_parses_with_clr_directory() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let pe: PeImage = parse(&img).expect("parse pe");
    assert_eq!(pe.bitness, PeBitness::Pe32);
    assert_eq!(pe.number_of_sections, 1);
    assert!(pe.clr_directory().is_some_and(|d| d.rva == 0x2008));
    assert!(pe.rva_to_offset(0x2008).is_some());
}

#[test]
fn synth_pe_yields_valid_clr_header() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v6.0.0");
    let pe: PeImage = parse(&img).expect("parse pe");
    let clr: ClrHeader = parse_clr_header(&img, &pe).expect("clr");
    assert_eq!(clr.cb, 72);
    assert_eq!(clr.major_runtime_version, 4);
    assert_eq!(clr.metadata.rva, 0x2100);
}

#[test]
fn non_managed_pe_returns_no_clr() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let opt_start: usize = 0x80 + 24;
    let directories_start: usize = opt_start + 96;
    let clr_dir_offset: usize = directories_start + 14 * 8;
    img[clr_dir_offset..clr_dir_offset + 8].copy_from_slice(&[0u8; 8]);
    let pe: PeImage = parse(&img).expect("parse");
    let err: disrobe_pass_dotnet::Error = parse_clr_header(&img, &pe).expect_err("no clr");
    assert!(matches!(err, disrobe_pass_dotnet::Error::NoClrHeader));
}
