#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::dalvik_strdec::{self, DexStringRecovery};
use disrobe_pass_jvm::dexguard_protector::{self, DexGuardAuthorization};
use disrobe_pass_jvm::{DexFile, PeelStatus, ProtectorPeelReport, parse_dex};

const AUTHORED_PLAINTEXT: [&str; 6] = [
    "https://api.example.com/v1/auth",
    "X-Api-Key",
    "decryptToken",
    "SELECT * FROM secrets WHERE id = ?",
    "AES/CBC/PKCS5Padding",
    "com.disrobe.sample.Secret",
];

fn sample_dex_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("dexguard");
    p.push("DexGuardReflectStrings.dex");
    p
}

#[test]
fn committed_dex_recovers_authored_plaintext() {
    let bytes: Vec<u8> = fs::read(sample_dex_path()).expect("read committed dexguard sample");
    let dex: DexFile = parse_dex(&bytes).expect("parse committed dex");

    let recoveries: Vec<DexStringRecovery> = dalvik_strdec::recover(&dex, &bytes);
    assert_eq!(recoveries.len(), 1, "exactly one decryptor class expected");
    let recovery: &DexStringRecovery = &recoveries[0];
    assert_eq!(recovery.decrypt_method, "decrypt");
    assert_eq!(recovery.table_size, AUTHORED_PLAINTEXT.len());

    let recovered: Vec<String> = recovery
        .recovered
        .iter()
        .map(|d| d.plaintext.clone())
        .collect();
    for expected in AUTHORED_PLAINTEXT {
        assert!(
            recovered.iter().any(|r: &String| r == expected),
            "authored plaintext {expected:?} not recovered; got {recovered:?}"
        );
    }
    assert_eq!(recovered.len(), AUTHORED_PLAINTEXT.len());

    assert!(
        !recovery.reflective_call_sites.is_empty(),
        "the reflective fetch(int) call site should be resolved"
    );
    assert!(
        recovery
            .reflective_call_sites
            .iter()
            .any(|s| s.resolved_member.ends_with(".decrypt")),
        "reflective site should resolve to the decrypt method"
    );
}

#[test]
fn committed_dex_peels_through_protector_api() {
    let bytes: Vec<u8> = fs::read(sample_dex_path()).expect("read committed dexguard sample");
    let report: ProtectorPeelReport =
        dexguard_protector::peel(&bytes, Some(DexGuardAuthorization::user_attested()))
            .expect("peel ok");
    assert_eq!(report.status, PeelStatus::CipherRecovered);

    let recovered: Vec<&String> = report.strings_recovered.values().collect();
    for expected in AUTHORED_PLAINTEXT {
        assert!(
            recovered.iter().any(|s: &&String| s.as_str() == expected),
            "authored plaintext {expected:?} not in peel report; got {recovered:?}"
        );
    }
}

#[test]
fn peel_without_authorization_is_rejected() {
    let bytes: Vec<u8> = fs::read(sample_dex_path()).expect("read committed dexguard sample");
    assert!(dexguard_protector::peel(&bytes, None).is_err());
}
