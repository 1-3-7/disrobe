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
fn confuserex2_signature_detected_in_synth_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ConfuserEx2 v1.6.0");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::ConfuserEx2));
}

#[test]
fn confuserex2_delegates_to_de4dot() {
    let plan: ExecutionOutcome = plan_execution(Protector::ConfuserEx2, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::DelegatedToDe4dot));
}

#[test]
#[ignore = "FIXTURE PENDING: real ConfuserEx2-protected sample with full CFF + string-decrypt round-trip"]
fn confuserex2_full_round_trip_against_real_sample() {
    panic!("FIXTURE PENDING");
}
