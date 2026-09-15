#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::peel::peel_babel_net;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use disrobe_pass_dotnet::protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, Handling, Protector, detect_all,
    plan_execution,
};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe};
use crate::common::{embed_signature, synth_minimal_dotnet_pe};

const BABEL_HEADER_SELF_AUTHENTICATING: &[u8] =
    include!("fixtures/babel_header_self_authenticating.rs.inc");

fn babel_image_with_resource(resource: &[u8]) -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["BabelObfuscatorAttribute", "Babel.Module"]);
    spec.resource = Some(("BabelStrings", resource.to_vec()));
    build_dotnet_pe(&spec)
}

#[test]
fn babel_reports_only_for_legacy_decoder_accepted_fixture() {
    let image: Vec<u8> = babel_image_with_resource(BABEL_HEADER_SELF_AUTHENTICATING);
    let report: PeelReport = peel_babel_net(&image).expect("peel");
    assert_eq!(report.protector, Protector::BabelDotnet);
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(
        report.recovered_strings.is_empty(),
        "the legacy decoder accepts this self-authenticating resource, but public Babel peeling \
         must not report its plaintext; got {:?}",
        report.recovered_strings
    );
    assert!(
        report.recovered_resources.is_empty(),
        "the public report-only path must not report resources from this header-selected blob; \
         got {:?}",
        report.recovered_resources
    );
}

#[test]
fn babel_published_signature_vector_detected_in_managed_pe() {
    let mut img: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img, b"BabelObfuscatorAttribute");
    let report: DetectionReport = detect_all(&img);
    assert!(report.matches.contains_key(&Protector::BabelDotnet));
}

#[test]
fn babel_uses_native_strip() {
    let plan: ExecutionOutcome = plan_execution(Protector::BabelDotnet, ExecuteOptions::default());
    assert!(matches!(
        plan,
        ExecutionOutcome::Detected {
            handling: Handling::NativeStrip
        }
    ));
}
