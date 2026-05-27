#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::missing_panics_doc
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::dexguard_protector::{self, DexGuardAuthorization};
use disrobe_pass_jvm::{Error, ProtectorFamilyKind, ProtectorPeelReport};

fn real_dex_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("dex");
    p.push("EdgeCases.dex");
    p
}

#[test]
fn dexguard_requires_explicit_authorization_user_action_required() {
    let bytes: Vec<u8> = fs::read(real_dex_path()).expect("read dex");
    let err: Error = dexguard_protector::peel(&bytes, None).expect_err("auth required");
    assert!(matches!(err, Error::DexGuardRequiresAuthorization));
}

#[test]
fn dexguard_real_dex_reports_user_action_required_note() {
    let bytes: Vec<u8> = fs::read(real_dex_path()).expect("read dex");
    let report: ProtectorPeelReport =
        dexguard_protector::peel(&bytes, Some(DexGuardAuthorization::user_attested())).expect("ok");
    assert_eq!(report.family, ProtectorFamilyKind::DexGuard);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("USER-ACTION-REQUIRED"))
    );
}

#[test]
fn dexguard_baseline_dex_residual_strings_is_low_because_not_protected() {
    let bytes: Vec<u8> = fs::read(real_dex_path()).expect("read dex");
    let report: ProtectorPeelReport =
        dexguard_protector::peel(&bytes, Some(DexGuardAuthorization::user_attested())).expect("ok");
    let total_strings: u32 =
        u32::from_le_bytes([bytes[0x38], bytes[0x39], bytes[0x3A], bytes[0x3B]]);
    let residual: usize = report.strings_residual;
    if total_strings > 0 {
        let ratio: f64 = residual as f64 / total_strings as f64;
        assert!(
            ratio < 0.50,
            "baseline (non-DexGuard) dex should have residual ratio < 0.50, got {ratio:.2}"
        );
    }
}
