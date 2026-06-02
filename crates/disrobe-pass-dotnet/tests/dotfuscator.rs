#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, GreyZone, Handling, Protector, detect_all,
    plan_execution,
};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn dotfuscator_signature_detected_in_synth_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"DotfuscatorAttribute");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::Dotfuscator));
}

#[test]
fn dotfuscator_is_green_zone_native_strip() {
    assert_eq!(Protector::Dotfuscator.grey_zone(), GreyZone::Green);
    let plan: ExecutionOutcome = plan_execution(Protector::Dotfuscator, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}

#[test]
#[ignore = "FIXTURE PENDING: PreEmptive Dotfuscator Pro-protected sample for full string-decrypt + name-restore"]
fn dotfuscator_full_round_trip() {
    panic!("FIXTURE PENDING");
}
