#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_pass_wasm_deob::{
    FingerprintDb, FunctionFingerprint, FunctionMatch, MatchConfig, MatchTier, canonical_label,
    extract_signatures, fingerprint_module, strip_name_section,
};

const ALPHA_V188: &[u8] = include_bytes!("fixtures/fingerprint/alpha_v188.wasm");
const ALPHA_V196: &[u8] = include_bytes!("fixtures/fingerprint/alpha_v196.wasm");
const BETA_V188: &[u8] = include_bytes!("fixtures/fingerprint/beta_v188.wasm");
const BETA_V196: &[u8] = include_bytes!("fixtures/fingerprint/beta_v196.wasm");

fn ground_truth(bytes: &[u8]) -> Vec<Option<String>> {
    let sigs: disrobe_pass_wasm_deob::ModuleSignatures = extract_signatures(bytes).expect("sigs");
    sigs.defined()
        .iter()
        .map(|sig: &disrobe_pass_wasm_deob::FunctionSig| {
            let name: &str = sig.name.as_str();
            if name.starts_with("func_") || name.starts_with("import_") {
                None
            } else {
                Some(canonical_label(name))
            }
        })
        .collect()
}

struct Scored {
    precision: f64,
    recall: f64,
    matched: usize,
    expected: usize,
    produced: usize,
    correct: usize,
    false_positives: usize,
    fuzzy_hits: usize,
    exact_hits: usize,
}

fn score(
    db: &FingerprintDb,
    labeled_bytes: &[u8],
    stripped_bytes: &[u8],
    config: &MatchConfig,
) -> Scored {
    let truth: Vec<Option<String>> = ground_truth(labeled_bytes);
    let db_labels: BTreeSet<String> = db.labels();
    let matches: Vec<Option<FunctionMatch>> =
        db.match_module(stripped_bytes, config).expect("match");
    assert_eq!(matches.len(), truth.len(), "index alignment");

    let mut expected: usize = 0;
    let mut correct: usize = 0;
    let mut produced: usize = 0;
    let mut false_positives: usize = 0;
    let mut fuzzy_hits: usize = 0;
    let mut exact_hits: usize = 0;

    for (label, hit) in truth.iter().zip(matches.iter()) {
        let is_recoverable: bool = label
            .as_ref()
            .is_some_and(|name: &String| db_labels.contains(name));
        if is_recoverable {
            expected += 1;
        }
        let Some(matched): Option<&FunctionMatch> = hit.as_ref() else {
            continue;
        };
        produced += 1;
        match matched.tier {
            MatchTier::Exact => exact_hits += 1,
            MatchTier::Fuzzy => fuzzy_hits += 1,
        }
        let is_correct: bool = label
            .as_ref()
            .is_some_and(|name: &String| *name == matched.label);
        if is_correct {
            correct += 1;
        }
        if !is_recoverable {
            false_positives += 1;
        }
    }

    let precision: f64 = if produced == 0 {
        1.0
    } else {
        correct as f64 / produced as f64
    };
    let recall: f64 = if expected == 0 {
        1.0
    } else {
        correct as f64 / expected as f64
    };
    Scored {
        precision,
        recall,
        matched: correct,
        expected,
        produced,
        correct,
        false_positives,
        fuzzy_hits,
        exact_hits,
    }
}

#[test]
fn exact_tier_matches_shared_functions_across_placement_same_version() {
    let mut db: FingerprintDb = FingerprintDb::new();
    let added: usize = db.add_labeled_module(ALPHA_V196).expect("db");
    assert!(
        added >= 8,
        "alpha corpus should label its helpers, got {added}"
    );

    let stripped: Vec<u8> = strip_name_section(BETA_V196).expect("strip");
    let sigs_stripped: disrobe_pass_wasm_deob::ModuleSignatures =
        extract_signatures(&stripped).expect("sigs");
    assert!(
        sigs_stripped
            .defined()
            .iter()
            .all(|sig: &disrobe_pass_wasm_deob::FunctionSig| !sig.name.starts_with("_ZN")),
        "stripping must remove name-section helper names"
    );

    let config: MatchConfig = MatchConfig {
        fuzzy_threshold: 2.0,
        min_fuzzy_ops: usize::MAX,
    };
    let scored: Scored = score(&db, BETA_V196, &stripped, &config);

    eprintln!(
        "exact-tier same-version cross-module: precision={:.3} recall={:.3} correct={} expected={} produced={} fp={} (exact={}, fuzzy={})",
        scored.precision,
        scored.recall,
        scored.correct,
        scored.expected,
        scored.produced,
        scored.false_positives,
        scored.exact_hits,
        scored.fuzzy_hits
    );

    assert_eq!(scored.fuzzy_hits, 0, "fuzzy disabled for exact-tier run");
    assert!(
        scored.expected >= 4,
        "beta shares several helpers with alpha, got {}",
        scored.expected
    );
    assert!(
        (scored.precision - 1.0).abs() < f64::EPSILON,
        "exact tier must not mislabel, precision={}",
        scored.precision
    );
    assert!(
        scored.recall >= 0.75,
        "exact tier should recover most placement-invariant shared helpers, recall={}",
        scored.recall
    );
    assert_eq!(
        scored.false_positives, 0,
        "module-unique functions must not exact-match"
    );
    assert!(scored.matched >= 4);
}

#[test]
fn fuzzy_tier_generalizes_across_toolchain_versions() {
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(ALPHA_V188).expect("db");

    let stripped: Vec<u8> = strip_name_section(BETA_V196).expect("strip");
    let config: MatchConfig = MatchConfig::default();
    let scored: Scored = score(&db, BETA_V196, &stripped, &config);

    eprintln!(
        "version-disjoint (train=1.88.0, test=1.96.1): precision={:.3} recall={:.3} correct={} expected={} produced={} fp={} (exact={}, fuzzy={})",
        scored.precision,
        scored.recall,
        scored.correct,
        scored.expected,
        scored.produced,
        scored.false_positives,
        scored.exact_hits,
        scored.fuzzy_hits
    );

    assert!(scored.expected >= 4, "shared helpers exist in the DB");
    assert!(
        scored.recall >= 0.75,
        "fuzzy must generalize across the 1.88 -> 1.96 version gap, recall={}",
        scored.recall
    );
    assert!(
        scored.precision >= 0.75,
        "cross-version matches must be mostly correct, precision={}",
        scored.precision
    );
    assert_eq!(
        scored.false_positives, 0,
        "novel functions must stay below the fuzzy threshold"
    );
    assert!(
        scored.fuzzy_hits >= 1,
        "at least one shared helper drifts across versions and needs the fuzzy tier"
    );
}

#[test]
fn fuzzy_tier_generalizes_reverse_direction() {
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(BETA_V188).expect("db");

    let stripped: Vec<u8> = strip_name_section(ALPHA_V196).expect("strip");
    let config: MatchConfig = MatchConfig::default();
    let scored: Scored = score(&db, ALPHA_V196, &stripped, &config);

    eprintln!(
        "version-disjoint reverse (train=beta 1.88.0, test=alpha 1.96.1): precision={:.3} recall={:.3} correct={} expected={} produced={} fp={} (exact={}, fuzzy={})",
        scored.precision,
        scored.recall,
        scored.correct,
        scored.expected,
        scored.produced,
        scored.false_positives,
        scored.exact_hits,
        scored.fuzzy_hits
    );

    assert!(scored.expected >= 4, "shared helpers exist in the beta DB");
    assert!(
        scored.recall >= 0.75,
        "fuzzy generalizes across versions in both directions, recall={}",
        scored.recall
    );
    assert!(scored.precision >= 0.75, "precision={}", scored.precision);
    assert_eq!(
        scored.false_positives, 0,
        "alpha-unique code must not match"
    );
}

#[test]
fn fuzzy_tier_alpha_self_across_versions() {
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(ALPHA_V188).expect("db");

    let stripped: Vec<u8> = strip_name_section(ALPHA_V196).expect("strip");
    let config: MatchConfig = MatchConfig::default();
    let scored: Scored = score(&db, ALPHA_V196, &stripped, &config);

    eprintln!(
        "version-disjoint alpha self (train=1.88.0, test=1.96.1): precision={:.3} recall={:.3} correct={} expected={} produced={} fp={} (exact={}, fuzzy={})",
        scored.precision,
        scored.recall,
        scored.correct,
        scored.expected,
        scored.produced,
        scored.false_positives,
        scored.exact_hits,
        scored.fuzzy_hits
    );

    assert!(scored.expected >= 8, "all alpha helpers are in the DB");
    assert!(
        scored.recall >= 0.75,
        "same source across versions should be highly recoverable, recall={}",
        scored.recall
    );
    assert!(scored.precision >= 0.8, "precision={}", scored.precision);
}

#[test]
fn fuzzy_score_separation_documents_confusability_limit() {
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(ALPHA_V188).expect("db");
    let db_labels: BTreeSet<String> = db.labels();

    let stripped: Vec<u8> = strip_name_section(BETA_V196).expect("strip");
    let truth: Vec<Option<String>> = ground_truth(BETA_V196);
    let reveal: MatchConfig = MatchConfig {
        fuzzy_threshold: 0.0,
        min_fuzzy_ops: 6,
    };
    let matches: Vec<Option<FunctionMatch>> = db.match_module(&stripped, &reveal).expect("m");

    let mut weakest_true: f64 = 1.0;
    let mut strongest_false: f64 = 0.0;
    for (label, hit) in truth.iter().zip(matches.iter()) {
        let Some(matched): Option<&FunctionMatch> = hit.as_ref() else {
            continue;
        };
        let recoverable: bool = label
            .as_ref()
            .is_some_and(|name: &String| db_labels.contains(name));
        let correct: bool = label
            .as_ref()
            .is_some_and(|name: &String| *name == matched.label);
        if recoverable && correct {
            weakest_true = weakest_true.min(matched.confidence);
        } else if !recoverable {
            strongest_false = strongest_false.max(matched.confidence);
        }
    }

    eprintln!(
        "fuzzy separation: weakest true positive={weakest_true:.3}, strongest false positive={strongest_false:.3}, threshold={:.3}",
        disrobe_pass_wasm_deob::DEFAULT_FUZZY_THRESHOLD
    );
    assert!(
        weakest_true > strongest_false,
        "true matches must score above the closest structural confusion"
    );
    assert!(
        weakest_true >= disrobe_pass_wasm_deob::DEFAULT_FUZZY_THRESHOLD,
        "every true cross-version match clears the threshold"
    );
    assert!(
        strongest_false < disrobe_pass_wasm_deob::DEFAULT_FUZZY_THRESHOLD,
        "the closest false positive stays below the threshold"
    );
}

#[test]
fn unrelated_function_does_not_match() {
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(ALPHA_V196).expect("db");

    let wat: &str = r"
        (module
          (func $noise (param i32 i32) (result i64)
            (local i64 f64)
            local.get 0
            i32.const 1337
            i32.rotl
            f64.const 3.14159
            local.set 3
            drop
            i64.const -9000000000
            local.set 2
            local.get 2
            local.get 2
            i64.mul
            local.get 2
            i64.or
            i64.xor))
    ";
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat");
    let fingerprints: Vec<FunctionFingerprint> = fingerprint_module(&bytes).expect("fp");
    let config: MatchConfig = MatchConfig::default();
    for fingerprint in &fingerprints {
        let hit: Option<FunctionMatch> = db.match_fingerprint(fingerprint, &config);
        assert!(
            hit.is_none(),
            "unrelated function matched {:?} at confidence {:?}",
            hit.as_ref().map(|m: &FunctionMatch| &m.label),
            hit.as_ref().map(|m: &FunctionMatch| m.confidence)
        );
    }
}

#[test]
fn corrupted_body_fails_exact_and_distinct_bodies_differ() {
    let fingerprints: Vec<FunctionFingerprint> = fingerprint_module(ALPHA_V196).expect("fp");
    let mut db: FingerprintDb = FingerprintDb::new();
    db.add_labeled_module(ALPHA_V196).expect("db");
    let config: MatchConfig = MatchConfig {
        fuzzy_threshold: 2.0,
        min_fuzzy_ops: usize::MAX,
    };

    let first: &FunctionFingerprint = &fingerprints[0];
    let exact_hit: Option<FunctionMatch> = db.match_fingerprint(first, &config);
    assert!(
        exact_hit.is_some_and(|m: FunctionMatch| m.tier == MatchTier::Exact),
        "an unmodified corpus body exact-matches itself"
    );

    let mut corrupted: FunctionFingerprint = fingerprints[0].clone();
    corrupted.exact_hash[0] ^= 0xff;
    assert!(
        db.match_fingerprint(&corrupted, &config).is_none(),
        "a corrupted body must not exact-match"
    );

    let hashes: BTreeSet<[u8; 32]> = fingerprints
        .iter()
        .map(|fp: &FunctionFingerprint| fp.exact_hash)
        .collect();
    assert_eq!(
        hashes.len(),
        fingerprints.len(),
        "distinct corpus bodies must produce distinct exact hashes"
    );
}
