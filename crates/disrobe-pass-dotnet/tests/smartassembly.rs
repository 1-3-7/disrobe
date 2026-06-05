#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Handling, Protector, detect_all,
    plan_execution,
};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn smartassembly_signature_detected() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"SmartAssembly.Attributes");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::SmartAssembly));
}

#[test]
fn smartassembly_uses_native_strip() {
    let plan: ExecutionOutcome =
        plan_execution(Protector::SmartAssembly, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}
