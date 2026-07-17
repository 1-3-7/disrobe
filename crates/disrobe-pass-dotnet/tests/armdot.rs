#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};
use disrobe_pass_dotnet::{PeelReport, PeelStrategy, peel_armdot};

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

#[test]
fn armdot_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ArmDot");
    let report: DetectionReport = detect_all(&img);
    assert!(
        report.matches.contains_key(&Protector::ArmDot),
        "grading the published ArmDot watermark vector embedded in a faithful managed PE, \
         not a captured vendor sample; the signature string must be recognized"
    );
}

#[test]
fn bare_managed_carrier_is_not_flagged_as_armdot() {
    let img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    let report: DetectionReport = detect_all(&img);
    assert!(
        !report.matches.contains_key(&Protector::ArmDot),
        "the identical synth carrier without the published watermark must not detect ArmDot, \
         proving the detector keys on the signature vector and not the carrier shape"
    );
}

#[test]
fn armdot_gates_without_authorization() {
    let plan: ExecutionOutcome = plan_execution(Protector::ArmDot, ExecuteOptions::default());
    assert!(matches!(plan, ExecutionOutcome::GatedAndBlocked { .. }));
}

#[test]
fn armdot_detect_only_reports_absent_vm_evidence() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"ArmDot");
    let report: PeelReport = peel_armdot(&img).expect("peel");
    assert_eq!(report.protector, Protector::ArmDot);
    assert_eq!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
    assert!(report.recovered_methods.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("no EazVM-shaped embedded stream")),
        "detect-only ArmDot must cite the failed VM-shape refutation; got {:?}",
        report.notes
    );
}

#[test]
fn armdot_route_lifts_eazvm_shaped_stream_not_a_real_armdot_sample() {
    let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/eazvm/EazSample.eazvm.dll");
    let mut image: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    image.extend_from_slice(b"ArmDot");
    let report: PeelReport = peel_armdot(&image).expect("peel");
    assert_eq!(report.protector, Protector::ArmDot);
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    assert_eq!(report.recovered_methods.len(), 5);
    assert!(
        report
            .recovered_methods
            .iter()
            .any(
                |m: &disrobe_pass_dotnet::RecoveredMethod| m.method_name == "SumTo"
                    && !m.cil.is_empty()
            ),
        "the shared managed-VM lifter must deliver recovered CIL bodies when an EazVM-shaped table \
         and stream are present"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("ArmDot VM-tier") && n.contains("lifted")),
        "the ArmDot route reuses the shared managed-VM lifter; got {:?}",
        report.notes
    );
}
