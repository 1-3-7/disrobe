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
fn dotfuscator_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"DotfuscatorAttribute");
    let report: DetectionReport = detect_all(&img);
    assert!(
        report.matches.contains_key(&Protector::Dotfuscator),
        "grading the published DotfuscatorAttribute watermark vector embedded in a faithful managed \
         PE, not a captured vendor sample; the signature string must be recognized"
    );
}

#[test]
fn bare_managed_carrier_is_not_flagged_as_dotfuscator() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let report: DetectionReport = detect_all(&img);
    assert!(
        !report.matches.contains_key(&Protector::Dotfuscator),
        "the identical synth carrier without the published watermark must not detect Dotfuscator, \
         proving the detector keys on the signature vector and not the carrier shape"
    );
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
