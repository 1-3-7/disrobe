#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::crate_fixture_or_fail;
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::Pass;
use disrobe_pass_nativelang::{
    BodyStatus, NATIVELANG_PASS, NativeImage, NativeLang, RustBody, recover_bodies, recover_dwarf,
    recover_functions,
};

const ZIG_AARCH64_ELF: &str = "zig_modes/arith_releasefast_aarch64_linux.elf";

#[test]
fn automatic_nativelang_recovery_exposes_aarch64_zig_bodies() {
    let bytes: Vec<u8> = crate_fixture_or_fail(ZIG_AARCH64_ELF);
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0_u8; 32]);
    let output: Artifact = NATIVELANG_PASS
        .run(&artifact)
        .expect("the committed aarch64 zig fixture must reach automatic nativelang recovery");
    let report: serde_json::Value =
        serde_json::from_slice(&output.envelope).expect("the automatic nativelang report is json");

    assert_eq!(report["body_arch_supported"].as_bool(), Some(true));
    assert_eq!(report["bodies"]["abi"].as_str(), Some("aapcs64"));
    let bodies: &[serde_json::Value] = report["bodies"]["bodies"]
        .as_array()
        .expect("the automatic nativelang report retains the carved body outcomes");
    assert!(
        bodies.iter().any(|body: &serde_json::Value| {
            body["name"].as_str() == Some("dr_mix")
                && body["status"]["state"].as_str() == Some("recovered")
                && body["status"]["pseudo_c"]
                    .as_str()
                    .is_some_and(|source: &str| source.contains("dr_mix"))
        }),
        "the automatic route must expose the recovered AArch64 dr_mix body"
    );
}

#[test]
fn aarch64_body_route_uses_the_normalized_nativelang_emitted_name() {
    let bytes: Vec<u8> = crate_fixture_or_fail(ZIG_AARCH64_ELF);
    let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse the AArch64 Zig image");
    let dwarf = recover_dwarf(&image);
    let mut function = recover_functions(&image, NativeLang::Zig, &dwarf)
        .functions
        .into_iter()
        .find(|function| function.name == "dr_mix")
        .expect("the compiler-produced fixture retains the dr_mix function symbol");
    function.name = "dr.mix".to_owned();
    let expected: String = format!("dr_mix_{:x}", function.start);
    let bodies = recover_bodies(&image, NativeLang::Zig, &[function]);
    let body = bodies
        .bodies
        .first()
        .expect("the requested AArch64 function receives an outcome");

    assert_eq!(body.emitted_name, expected);
    match &body.status {
        BodyStatus::Recovered {
            pseudo_c,
            pseudo_rust,
        } => {
            assert!(pseudo_c.contains(&format!("{}(", body.emitted_name)));
            if let RustBody::Emitted(source) = pseudo_rust {
                assert!(source.contains(&format!("pub fn {}(", body.emitted_name)));
            }
        }
        status => panic!("the AArch64 normalized-name body must recover, got {status:?}"),
    }
}
