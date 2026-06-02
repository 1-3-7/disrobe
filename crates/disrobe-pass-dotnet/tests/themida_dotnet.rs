#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn themida_dotnet_signature_detected() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"Themida");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::ThemidaDotnet));
}

#[test]
fn themida_dotnet_is_detect_only() {
    let plan: ExecutionOutcome =
        plan_execution(Protector::ThemidaDotnet, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::DetectOnly { .. }));
}

#[test]
#[ignore = "FIXTURE PENDING: Themida + WinLicense .NET wrapper sample - detect-only by policy"]
fn themida_dotnet_detect_only_no_unwrap() {
    panic!("FIXTURE PENDING");
}
