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
fn agile_net_signature_detected() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"AgileDotNet");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::AgileNet));
}

#[test]
fn agile_net_gates_without_authorization() {
    let plan: ExecutionOutcome = plan_execution(Protector::AgileNet, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::GatedAndBlocked { .. }));
}
