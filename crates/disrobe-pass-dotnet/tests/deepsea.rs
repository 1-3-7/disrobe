#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::protectors::{DetectionReport, Protector, detect_all};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn deepsea_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"DeepSeaObfuscator");
    let report: DetectionReport = detect_all(&img);
    assert!(
        report.matches.contains_key(&Protector::DeepSea),
        "grading the published DeepSeaObfuscator watermark vector embedded in a faithful managed \
         PE, not a captured vendor sample; the signature string must be recognized"
    );
}

#[test]
fn bare_managed_carrier_is_not_flagged_as_deepsea() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let report: DetectionReport = detect_all(&img);
    assert!(
        !report.matches.contains_key(&Protector::DeepSea),
        "the identical synth carrier without the published watermark must not detect DeepSea, \
         proving the detector keys on the signature vector and not the carrier shape"
    );
}
