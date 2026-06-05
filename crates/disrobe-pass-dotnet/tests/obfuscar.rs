//! Obfuscar detection + handling-policy coverage.

#![allow(clippy::missing_panics_doc)]

mod common;

use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, GreyZone, Handling, Protector, detect_all,
    plan_execution,
};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn obfuscar_signature_detected() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v6.0.0");
    embed_signature(&mut img, b"Obfuscar.Obfuscator");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::Obfuscar));
}

#[test]
fn obfuscar_is_green_zone_foss() {
    assert_eq!(Protector::Obfuscar.grey_zone(), GreyZone::Green);
    let plan: ExecutionOutcome = plan_execution(Protector::Obfuscar, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}
