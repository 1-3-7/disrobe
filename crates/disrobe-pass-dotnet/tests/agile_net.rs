#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::peel::agile_net_bodies::{
    AgileCodeHeader, CODE_HEADER_SIZE, CliSecureVariant, end_of_metadata, locate_agile_code_header,
};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const NORMAL_CODE_HEADER_SIGNATURE: [u8; 16] = [
    0x08, 0x44, 0x65, 0xE1, 0x8C, 0x82, 0x13, 0x4C, 0x9C, 0x85, 0xB4, 0x17, 0xDA, 0x51, 0xAD, 0x25,
];

#[test]
fn agile_net_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"AgileDotNet");
    let report: DetectionReport = detect_all(&img);
    assert!(
        report.matches.contains_key(&Protector::AgileNet),
        "grading the published Agile.NET watermark vector embedded in a faithful managed PE, \
         not a captured vendor sample; the AgileDotNet signature string must be recognized"
    );
}

#[test]
fn bare_managed_carrier_is_not_flagged_as_agile_net() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let report: DetectionReport = detect_all(&img);
    assert!(
        !report.matches.contains_key(&Protector::AgileNet),
        "the identical synth carrier without the published watermark must not detect Agile.NET, \
         proving the detector keys on the signature vector and not the carrier shape"
    );
}

#[test]
fn agile_net_gates_without_authorization() {
    let plan: ExecutionOutcome = plan_execution(Protector::AgileNet, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::GatedAndBlocked { .. }));
}

#[test]
fn agile_net_code_header_parses_tail_method_table_fields() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let eom: u32 = end_of_metadata(&img).expect("metadata end must parse");
    let start: usize = eom as usize;
    let mut header: [u8; 0x30] = [0u8; 0x30];
    header[..16].copy_from_slice(&NORMAL_CODE_HEADER_SIGNATURE);
    header[0x10..0x20].copy_from_slice(b"AgileNetXORKey16");
    header[0x20..0x24].copy_from_slice(&0x40u32.to_le_bytes());
    header[0x24..0x28].copy_from_slice(&2u32.to_le_bytes());
    header[0x28..0x2C].copy_from_slice(&0x1234u32.to_le_bytes());
    header[0x2C..0x30].copy_from_slice(&0x10u32.to_le_bytes());
    let end: usize = start + header.len();
    if img.len() < end {
        img.resize(end, 0);
    }
    img[start..end].copy_from_slice(&header);

    assert_eq!(CODE_HEADER_SIZE, header.len());
    let parsed: AgileCodeHeader =
        locate_agile_code_header(&img).expect("0x30-byte Agile.NET code header must parse");
    assert_eq!(parsed.variant, CliSecureVariant::Normal);
    assert_eq!(parsed.file_offset, eom);
    assert_eq!(parsed.total_code_size, 0x40);
    assert_eq!(parsed.method_count, 2);
    assert_eq!(parsed.method_table_offset, 0x1234);
    assert_eq!(parsed.method_element_size, 0x10);
}
