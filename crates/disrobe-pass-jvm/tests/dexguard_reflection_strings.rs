#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

pub mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::find_on_path;
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dalvik_strdec::{self, DexStringRecovery};
use disrobe_pass_jvm::dex_builder::dexguard_reflect_sample;
use disrobe_pass_jvm::dexguard_protector::{self, DexGuardAuthorization};
use disrobe_pass_jvm::{DexFile, PeelStatus, ProtectorPeelReport, parse_dex};

const DEX: &[u8] = include_bytes!("../../../corpus/jvm/dexguard/DexGuardReflectStrings.dex");
const JAR: &[u8] = include_bytes!("fixtures/dexguard/DexGuardReflectStrings.jar");

const DEX_BYTES: usize = 1952;
const DEX_SHA256: &str = "ff10daa91aefba5f57aba67a1584cbe4a21679ebc8dcbe39215602c2d2c7d8be";
const MAIN_CLASS: &str = "com.disrobe.sample.DexGuardReflectStrings";
const XOR_KEY: u8 = 0x66;
const DECRYPT_METHOD: &str = "decrypt";

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let mut out: String = String::with_capacity(64);
    for b in hasher.finalize() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn java_binary() -> PathBuf {
    find_on_path("java").unwrap_or_else(|| {
        panic!(
            "java is not on PATH. This gate derives its expected plaintext by running the \
             committed jar under a real JVM; skipping it would leave the recovery graded against \
             nothing. CI provisions Temurin 25 (.github/workflows/ci.yml), so an absent java here \
             is a broken environment, not a reason to report green."
        )
    })
}

fn run_reference_program() -> Vec<String> {
    let java: PathBuf = java_binary();
    let scratch: ScratchDir =
        ScratchDir::create("dexguard-reference").expect("create scratch directory");
    let jar: PathBuf = scratch.path().join("DexGuardReflectStrings.jar");
    std::fs::write(&jar, JAR).expect("materialize the committed jar");
    let run: Output = Command::new(&java)
        .arg("-cp")
        .arg(&jar)
        .arg(MAIN_CLASS)
        .output()
        .expect("launch the reference program");
    assert!(
        run.status.success(),
        "the committed jar must run under a real JVM; stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout: String = String::from_utf8(run.stdout).expect("reference stdout is utf-8");
    let lines: Vec<String> = stdout
        .lines()
        .map(|l: &str| l.trim_end_matches('\r').to_owned())
        .filter(|l: &String| !l.is_empty())
        .collect();
    assert!(
        !lines.is_empty(),
        "the reference program printed nothing, so there is no ground truth to grade against"
    );
    lines
}

fn recover_from(bytes: &[u8]) -> Vec<DexStringRecovery> {
    let dex: DexFile = parse_dex(bytes).expect("parse the committed dex");
    dalvik_strdec::recover(&dex, bytes)
}

fn sole_recovery(bytes: &[u8]) -> DexStringRecovery {
    let mut recoveries: Vec<DexStringRecovery> = recover_from(bytes);
    assert_eq!(
        recoveries.len(),
        1,
        "exactly one decryptor class expected, got {recoveries:#?}"
    );
    recoveries.remove(0)
}

#[test]
fn committed_dex_is_the_pinned_third_party_build() {
    assert_eq!(
        DEX.len(),
        DEX_BYTES,
        "the committed dex changed size; re-pin it only after re-deriving it with the real \
         toolchain recorded in corpus/jvm/dexguard/MANIFEST.toml"
    );
    assert_eq!(
        sha256_hex(DEX),
        DEX_SHA256,
        "the committed dex no longer matches the digest recorded in MANIFEST.toml"
    );
    let ours: Vec<u8> = dexguard_reflect_sample(
        &[
            "https://api.example.com/v1/auth",
            "X-Api-Key",
            "decryptToken",
            "SELECT * FROM secrets WHERE id = ?",
            "AES/CBC/PKCS5Padding",
            "com.disrobe.sample.Secret",
        ],
        XOR_KEY,
    );
    assert_ne!(
        ours.as_slice(),
        DEX,
        "the graded fixture is byte-equal to what this crate's own dex_builder emits. The point \
         of this fixture is that javac and d8 produced it, so grading against input we assembled \
         would compare disrobe to disrobe"
    );
}

#[test]
fn recovered_plaintext_matches_the_real_jvm_stdout() {
    let reference: Vec<String> = run_reference_program();
    let recovery: DexStringRecovery = sole_recovery(DEX);

    assert_eq!(recovery.decrypt_method, DECRYPT_METHOD);
    assert_eq!(
        recovery.table_size,
        reference.len(),
        "recovered table size must equal the number of strings the real program printed"
    );

    let recovered: BTreeSet<String> = recovery
        .recovered
        .iter()
        .map(|d| d.plaintext.clone())
        .collect();
    let expected: BTreeSet<String> = reference.iter().cloned().collect();

    let missing: Vec<&String> = expected.difference(&recovered).collect();
    assert!(
        missing.is_empty(),
        "the real JVM printed {missing:?} but static recovery did not produce them"
    );
    let extra: Vec<&String> = recovered.difference(&expected).collect();
    assert!(
        extra.is_empty(),
        "static recovery produced {extra:?}, which the real JVM never printed"
    );
    assert_eq!(recovered.len(), reference.len());
}

#[test]
fn reflective_call_site_resolves_to_the_decrypt_method() {
    let recovery: DexStringRecovery = sole_recovery(DEX);
    assert!(
        !recovery.reflective_call_sites.is_empty(),
        "the reflective fetch(int) call site should be resolved"
    );
    assert!(
        recovery
            .reflective_call_sites
            .iter()
            .any(|s| s.resolved_member.ends_with(&format!(".{DECRYPT_METHOD}"))),
        "the reflective site should name the method the Class.getDeclaredMethod argument \
         actually holds, got {:?}",
        recovery
            .reflective_call_sites
            .iter()
            .map(|s| s.resolved_member.as_str())
            .collect::<Vec<&str>>()
    );
    assert!(
        recovery
            .reflective_call_sites
            .iter()
            .all(|s| !s.resolved_member.trim().is_empty()),
        "a reflective site must never report an empty member name"
    );
}

#[test]
fn the_jvm_comparison_rejects_a_corrupted_ciphertext() {
    let reference: BTreeSet<String> = run_reference_program().into_iter().collect();
    let target: &str = "X-Api-Key";
    let cipher: Vec<u8> = target.bytes().map(|b: u8| b ^ XOR_KEY).collect();
    let at: usize = DEX
        .windows(cipher.len())
        .position(|w: &[u8]| w == cipher.as_slice())
        .expect("the ciphertext for the probe string must exist in the committed dex");

    let mut corrupted: Vec<u8> = DEX.to_vec();
    corrupted[at] ^= 0x01;

    let recovered: BTreeSet<String> = recover_from(&corrupted)
        .into_iter()
        .flat_map(|r: DexStringRecovery| {
            r.recovered
                .into_iter()
                .map(|d| d.plaintext)
                .collect::<Vec<String>>()
        })
        .collect();
    assert!(
        !recovered.contains(target),
        "flipping a bit inside the ciphertext for {target:?} still produced it, so the recovery \
         is not reading the bytes it claims to decrypt"
    );
    assert_ne!(
        recovered, reference,
        "a corrupted ciphertext still matched the real JVM's output, so this gate would stay \
         green on a recovery that ignores the input"
    );
}

#[test]
fn committed_dex_peels_through_protector_api() {
    let reference: BTreeSet<String> = run_reference_program().into_iter().collect();
    let report: ProtectorPeelReport =
        dexguard_protector::peel(DEX, Some(DexGuardAuthorization::user_attested())).expect("peel");
    assert_eq!(report.status, PeelStatus::CipherRecovered);

    let peeled: BTreeSet<String> = report.strings_recovered.values().cloned().collect();
    let missing: Vec<&String> = reference.difference(&peeled).collect();
    assert!(
        missing.is_empty(),
        "the peel report omits {missing:?}, which the real JVM printed"
    );
}

#[test]
fn peel_without_authorization_is_rejected() {
    assert!(dexguard_protector::peel(DEX, None).is_err());
}

#[test]
fn committed_jar_and_dex_come_from_the_same_recorded_build() {
    let manifest: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/jvm/dexguard/MANIFEST.toml")
        .canonicalize()
        .expect("locate the corpus manifest");
    let text: String = std::fs::read_to_string(&manifest).expect("read the corpus manifest");
    for needle in ["javac", "d8", DEX_SHA256] {
        assert!(
            text.contains(needle),
            "MANIFEST.toml must record {needle:?} so a reader can re-derive the fixture"
        );
    }
    assert!(
        !JAR.is_empty(),
        "the runnable jar is the reference program and must stay committed"
    );
}
