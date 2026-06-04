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
fn cff_undo_authgated_is_honest_detect_only() {
    let bytes: Vec<u8> = edgecases_dex();
    let analysis: CffAnalysis =
        dexguard_protector::undo_cff(&bytes, Some(DexGuardAuthorization::user_attested()))
            .expect("ok");
    assert_eq!(
        analysis.methods_unflattened, 0,
        "no synthetic un-flatten may be fabricated without a real DexGuard sample"
    );
    assert!(
        analysis
            .notes
            .iter()
            .any(|n: &String| n.contains("AUTH-GATED") && n.contains("detect-only")),
        "must disclose auth-gated detect-only honesty"
    );
}

#[test]
fn cff_undo_rejects_non_dex() {
    let err: Error =
        dexguard_protector::undo_cff(b"not a dex", Some(DexGuardAuthorization::user_attested()))
            .expect_err("not dex");
    assert!(matches!(err, Error::DexGuardNotDex));
}
