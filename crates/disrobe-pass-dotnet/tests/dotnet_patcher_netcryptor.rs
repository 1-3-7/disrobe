#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_by};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Protector, detect_all, plan_execution,
};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe};

fn carrier(watermarks: &[&'static str]) -> Vec<u8> {
    build_dotnet_pe(&DotnetPeSpec::new(watermarks))
}

#[test]
fn dotnetpatcher_signature_detected_in_dotnet_pass() {
    let image: Vec<u8> = carrier(&["DNPatcher"]);
    let report: DetectionReport = detect_all(&image);
    assert!(report.matches.contains_key(&Protector::DotNetPatcher));
    assert_eq!(report.primary, Some(Protector::DotNetPatcher));
}

#[test]
fn netcryptor_signature_detected_in_dotnet_pass() {
    let image: Vec<u8> = carrier(&["NETCryptor"]);
    let report: DetectionReport = detect_all(&image);
    assert!(report.matches.contains_key(&Protector::NetCryptor));
    assert_eq!(report.primary, Some(Protector::NetCryptor));
}

#[test]
fn managed_packer_planning_delegates_to_de4dot() {
    let protectors: [Protector; 2] = [Protector::DotNetPatcher, Protector::NetCryptor];
    for protector in protectors {
        let outcome: ExecutionOutcome = plan_execution(protector, ExecuteOptions::default());
        assert!(matches!(outcome, ExecutionOutcome::DelegatedToDe4dot));
    }
}

#[test]
fn managed_packer_peel_reports_are_not_detect_only() {
    let cases: [(Protector, Vec<u8>); 2] = [
        (Protector::DotNetPatcher, carrier(&["DNPatcher"])),
        (Protector::NetCryptor, carrier(&["NETCryptor"])),
    ];
    for (protector, image) in cases {
        let report: PeelReport = peel_by(protector, &image)
            .expect("managed packer peel path must be wired")
            .expect("managed packer peel report must parse");
        assert_eq!(report.protector, protector);
        assert_ne!(report.strategy, PeelStrategy::DetectOnlyNativeOrVm);
        assert!(
            report
                .notes
                .iter()
                .any(|note: &String| note.contains("managed wrapper")),
            "managed packer peel report must explain dotnet ownership"
        );
    }
}
