#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_jvm::Error;
use disrobe_pass_jvm::dexguard_protector::{self, CffAnalysis, DexGuardAuthorization};

fn edgecases_dex() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("dex");
    p.push("EdgeCases.dex");
    std::fs::read(p).expect("read dex")
}

#[test]
fn cff_undo_requires_authorization() {
    let bytes: Vec<u8> = edgecases_dex();
    let err: Error = dexguard_protector::undo_cff(&bytes, None).expect_err("auth required");
    assert!(matches!(err, Error::DexGuardRequiresAuthorization));
}

#[test]
fn cff_undo_clean_dex_finds_no_flattening() {
    let bytes: Vec<u8> = edgecases_dex();
    let analysis: CffAnalysis =
        dexguard_protector::undo_cff(&bytes, Some(DexGuardAuthorization::user_attested()))
            .expect("ok");
    assert_eq!(
        analysis.suspected_flattened_methods, 0,
        "EdgeCases.dex carries only ordinary switches whose scrutinee is a method result; the \
         const-purity gate must reject them, so no method is reported as flattened"
    );
    assert_eq!(
        analysis.methods_unflattened, 0,
        "with no switch-on-state dispatcher present, nothing is un-flattened"
    );
    assert_eq!(analysis.residual_dispatcher_edges, 0);
    assert!(
        analysis
            .notes
            .iter()
            .any(|n: &String| n.contains("AUTH-GATED") && n.contains("detect-only")),
        "must disclose the auth-gated detect-only outcome when no flattening is found"
    );
    assert!(
        analysis
            .notes
            .iter()
            .any(|n: &String| n.contains("commercial-sample gap")),
        "must disclose the enterprise-sample sourcing gap honestly"
    );
}

#[test]
fn cff_undo_rejects_non_dex() {
    let err: Error =
        dexguard_protector::undo_cff(b"not a dex", Some(DexGuardAuthorization::user_attested()))
            .expect_err("not dex");
    assert!(matches!(err, Error::DexGuardNotDex));
}
