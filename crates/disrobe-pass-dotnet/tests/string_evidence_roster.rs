#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::path::PathBuf;

use disrobe_pass_dotnet::peel::bitmono_strings::{BitMonoStringRecovery, recover_bitmono_strings};
use disrobe_pass_dotnet::peel::obfuscar_strings::{
    ObfuscarStringRecovery, recover_obfuscar_strings,
};
use disrobe_pass_dotnet::peel::{ConfuserConstantsRecovery, peel_confuserex_constants};
use disrobe_pass_dotnet::protectors::{DetectionReport, Protector, StringEvidence, detect_all};

const REPO_ROOT_FROM_CRATE: &str = "../..";

fn repo_path(relative: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(REPO_ROOT_FROM_CRATE);
    path.push(relative);
    path
}

const fn tier(protector: Protector) -> StringEvidence {
    protector.string_evidence()
}

fn families(matching: fn(StringEvidence) -> bool) -> Vec<Protector> {
    Protector::ALL
        .into_iter()
        .filter(|p: &Protector| matching(tier(*p)))
        .collect()
}

fn recovered_string_count(protector: Protector, image: &[u8]) -> usize {
    match protector {
        Protector::ConfuserEx2 => {
            let recovery: ConfuserConstantsRecovery = peel_confuserex_constants(image)
                .expect("the committed ConfuserEx2 sample must parse")
                .expect("the committed ConfuserEx2 sample must peel its constant blob");
            recovery.strings_recovered.len()
        }
        Protector::Obfuscar => {
            let recovery: ObfuscarStringRecovery = recover_obfuscar_strings(image);
            recovery.recovered.len()
        }
        Protector::BitMono => {
            let recovery: BitMonoStringRecovery = recover_bitmono_strings(image)
                .expect("the committed BitMono sample must reach its string decryptor");
            recovery.recovered.len()
        }
        other => panic!(
            "{} is declared with a committed sample but this test knows no string recovery entry \
             point for it, so the claim would go ungraded",
            other.label()
        ),
    }
}

#[test]
fn every_family_carries_exactly_one_string_evidence_tier() {
    assert_eq!(
        Protector::ALL.len(),
        23,
        "the roster length moved; the published protector count and every tier below are derived \
         from this array"
    );
    let claiming: Vec<Protector> = families(StringEvidence::decrypts_strings);
    assert!(
        !claiming.is_empty(),
        "no protector claims string decryption, so this test would grade nothing"
    );
    for protector in claiming {
        let evidence: StringEvidence = tier(protector);
        assert!(
            matches!(
                evidence,
                StringEvidence::RealSample(_) | StringEvidence::ModelledAlgorithm
            ),
            "{} claims string decryption under an unexpected tier {evidence:?}",
            protector.label()
        );
    }
}

#[test]
fn a_real_sample_tier_names_a_committed_artifact_that_recovers_plaintext() {
    let real: Vec<Protector> =
        families(|e: StringEvidence| matches!(e, StringEvidence::RealSample(_)));
    assert!(
        !real.is_empty(),
        "no family declares a committed sample, so this test would assert nothing"
    );
    for protector in real {
        let Some(relative): Option<&str> = tier(protector).committed_sample() else {
            panic!(
                "{} lost its sample path between two reads",
                protector.label()
            );
        };
        let path: PathBuf = repo_path(relative);
        let image: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
            panic!(
                "{} is published as string-decrypting on a committed sample, but {} is unreadable \
                 ({e}); the claim has no artifact behind it",
                protector.label(),
                path.display()
            )
        });
        assert!(
            !image.is_empty(),
            "the committed sample for {} is empty",
            protector.label()
        );
        let report: DetectionReport = detect_all(&image);
        assert!(
            report.matches.contains_key(&protector),
            "{} names {} as its committed sample, but the detector does not recognise that \
             artifact as {}",
            protector.label(),
            path.display(),
            protector.label()
        );
        let recovered: usize = recovered_string_count(protector, &image);
        assert!(
            recovered > 0,
            "{} is published as string-decrypting on {}, but recovery returns no plaintext from it",
            protector.label(),
            path.display()
        );
    }
}

#[test]
fn a_modelled_tier_declares_no_committed_artifact() {
    let modelled: Vec<Protector> =
        families(|e: StringEvidence| matches!(e, StringEvidence::ModelledAlgorithm));
    assert!(
        !modelled.is_empty(),
        "no family sits in the modelled tier, so the documented limit covers nothing"
    );
    for protector in modelled {
        assert_eq!(
            tier(protector).committed_sample(),
            None,
            "{} sits in the modelled tier yet names a committed sample; one of the two is wrong",
            protector.label()
        );
    }
}

#[test]
fn a_runtime_keyed_tier_stops_at_detection() {
    for protector in families(|e: StringEvidence| matches!(e, StringEvidence::RuntimeKeyed)) {
        assert_eq!(
            protector.handling(),
            disrobe_pass_dotnet::protectors::Handling::DetectOnly,
            "{} is published as runtime-keyed for strings but is routed to a recovery handler",
            protector.label()
        );
        assert!(
            !tier(protector).decrypts_strings(),
            "{} cannot both be runtime-keyed and publish string decryption",
            protector.label()
        );
    }
}
