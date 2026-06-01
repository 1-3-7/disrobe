#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump, SwiftShieldUndoMap};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
}

fn legacy_root() -> PathBuf {
    corpus_root()
}

fn edge_root() -> PathBuf {
    corpus_root().join("swiftshield-edgecases")
}

fn load_at(root: &Path, name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = root.join(name);
    fs::read(&path).ok()
}

fn load_text_at(root: &Path, name: &str) -> Option<String> {
    let path: PathBuf = root.join(name);
    fs::read_to_string(&path).ok()
}

#[test]
fn swiftshield_legacy_mapping_reverses_known_obfuscated_identifiers() {
    let Some(text): Option<String> =
        load_text_at(&legacy_root(), "SwiftHello.swiftshield-mapping.txt")
    else {
        eprintln!("skip: macho-mac/SwiftHello.swiftshield-mapping.txt fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);

    let known: &[(&str, &str)] = &[
        ("A8X9k2QwLp", "LoginViewController"),
        ("Z7q3W1MnPr", "AuthenticationService"),
        ("C5dHj7Tu", "AnalyticsTracker"),
        ("D9eKmRpQ", "PaymentFlowState"),
        ("E2fLpQrS", "HelloRunnerEntry"),
        ("BNm4Lz8a", "HelloGreetable"),
        ("aPq2X9rT", "greetWithBanner"),
        ("bRx4P6mTuv", "recordTrackingEvent"),
        ("cVz7K3xRpq", "describePaymentState"),
        ("kZ3mNqVxBb", "displayedUserName"),
        ("xY9nLkRtCc", "configuredEndpointPath"),
        ("qW8rNm2Yx", "trackerInstanceTag"),
        ("kx7Mn3Az", "awaitingCardEntry"),
        ("ly2Bn9Cp", "validatingPaymentDetails"),
        ("mz5Op8Dr", "chargingMerchantGateway"),
        ("nb1Qr4Es", "paymentFlowCompleted"),
    ];
    assert_eq!(
        undo.mappings.len(),
        known.len(),
        "expected exactly {} mappings, parsed {}",
        known.len(),
        undo.mappings.len()
    );
    for (obfuscated, original) in known {
        let got: Option<&String> = undo.mappings.get(*obfuscated);
        assert_eq!(
            got.map(String::as_str),
            Some(*original),
            "mapping {obfuscated} -> {original} missing or wrong"
        );
    }
}

#[test]
fn swiftshield_legacy_original_binary_contains_unobfuscated_class_names() {
    let Some(bytes): Option<Vec<u8>> = load_at(&legacy_root(), "SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse original");
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);

    let reflstr_concat: String = dump
        .reflection_strings
        .as_ref()
        .map(|r: &swift::SwiftReflectionStrings| r.strings.join("\n"))
        .unwrap_or_default();
    let cstring_concat: String = String::from_utf8_lossy(&bytes).into_owned();

    let original_only_identifiers: &[&str] = &[
        "LoginViewController",
        "AuthenticationService",
        "AnalyticsTracker",
        "HelloGreetable",
        "greetWithBanner",
    ];
    for ident in original_only_identifiers {
        assert!(
            reflstr_concat.contains(ident) || cstring_concat.contains(ident),
            "original SwiftHello binary missing identifier {ident}"
        );
    }
}

#[test]
fn swiftshield_legacy_obfuscated_binary_exposes_renamed_identifiers() {
    let Some(bytes): Option<Vec<u8>> = load_at(&legacy_root(), "SwiftHello.obfuscated") else {
        eprintln!("skip: macho-mac/SwiftHello.obfuscated fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse obfuscated");
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);

    let reflstr_concat: String = dump
        .reflection_strings
        .as_ref()
        .map(|r: &swift::SwiftReflectionStrings| r.strings.join("\n"))
        .unwrap_or_default();
    let cstring_concat: String = String::from_utf8_lossy(&bytes).into_owned();

    let Some(text): Option<String> =
        load_text_at(&legacy_root(), "SwiftHello.swiftshield-mapping.txt")
    else {
        eprintln!("skip: macho-mac/SwiftHello.swiftshield-mapping.txt fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);
    let mut hits: usize = 0;
    for obfuscated_name in undo.mappings.keys() {
        if reflstr_concat.contains(obfuscated_name) || cstring_concat.contains(obfuscated_name) {
            hits += 1;
        }
    }
    assert!(
        hits > 0,
        "obfuscated binary contains none of the {} mapped obfuscated identifiers",
        undo.mappings.len()
    );
}

#[test]
fn swiftshield_legacy_apply_inverse_recovers_originals_from_obfuscated_strings() {
    let Some(text): Option<String> =
        load_text_at(&legacy_root(), "SwiftHello.swiftshield-mapping.txt")
    else {
        eprintln!("skip: macho-mac/SwiftHello.swiftshield-mapping.txt fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);

    let obfuscated_snippet: &str = "A8X9k2QwLp.aPq2X9rT(BNm4Lz8a)";
    let mut recovered: String = obfuscated_snippet.to_owned();
    for (obfuscated_name, original_name) in &undo.mappings {
        recovered = recovered.replace(obfuscated_name, original_name);
    }
    assert_eq!(
        recovered,
        "LoginViewController.greetWithBanner(HelloGreetable)"
    );
}

const EDGE_MAPPING: &str = "SwiftEdgeCases.swiftshield-mapping.txt";
const EDGE_ORIGINAL: &str = "SwiftEdgeCases.original";
const EDGE_OBFUSCATED: &str = "SwiftEdgeCases.obfuscated";
const MIN_EDGE_MAPPING_ENTRIES: usize = 50;

#[test]
fn swiftshield_edge_mapping_parses_at_least_fifty_distinct_substitutions() {
    let Some(text): Option<String> = load_text_at(&edge_root(), EDGE_MAPPING) else {
        eprintln!("skip: swiftshield-edgecases/{EDGE_MAPPING} fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);
    assert!(
        undo.mappings.len() >= MIN_EDGE_MAPPING_ENTRIES,
        "expected >= {MIN_EDGE_MAPPING_ENTRIES} mappings, parsed {}",
        undo.mappings.len()
    );
    let mut unique_originals: BTreeSet<&String> = BTreeSet::new();
    let mut unique_obfuscated: BTreeSet<&String> = BTreeSet::new();
    for (obf, orig) in &undo.mappings {
        unique_obfuscated.insert(obf);
        unique_originals.insert(orig);
    }
    assert_eq!(
        unique_obfuscated.len(),
        undo.mappings.len(),
        "obfuscated identifiers must be unique"
    );
    assert_eq!(
        unique_originals.len(),
        undo.mappings.len(),
        "original identifiers must be unique"
    );
}

#[test]
fn swiftshield_edge_original_binary_carries_unobfuscated_identifier_family() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), EDGE_ORIGINAL) else {
        eprintln!("skip: swiftshield-edgecases/{EDGE_ORIGINAL} fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse edge original");
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);
    let reflstr_concat: String = dump
        .reflection_strings
        .as_ref()
        .map(|r: &swift::SwiftReflectionStrings| r.strings.join("\n"))
        .unwrap_or_default();
    let cstring_concat: String = String::from_utf8_lossy(&bytes).into_owned();

    let expected: &[&str] = &[
        "LoginViewControllerEdgeAlpha",
        "CheckoutCoordinatorEdgeBeta",
        "AnalyticsCollectorEdgeGamma",
        "NetworkClientEdgeDelta",
        "CryptoVaultEdgeEpsilon",
        "SubscriptionReceiptEdgeZeta",
        "AccountAuthenticatorProtocolEdge",
        "SubscriptionLifecyclePhaseEdgeIota",
        "NetworkConnectivityClassEdgeKappa",
    ];
    let mut hits: usize = 0;
    for ident in expected {
        if reflstr_concat.contains(ident) || cstring_concat.contains(ident) {
            hits += 1;
        }
    }
    assert!(
        hits >= expected.len() - 1,
        "edge original missing too many identifiers ({hits}/{} hits)",
        expected.len()
    );
}

#[test]
fn swiftshield_edge_inverse_substitution_recovers_at_least_fifty_originals() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), EDGE_OBFUSCATED) else {
        eprintln!("skip: swiftshield-edgecases/{EDGE_OBFUSCATED} fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse edge obfuscated");
    let dump: SwiftClassDump = swift::class_dump(&bytes, &parsed);
    let reflstr_concat: String = dump
        .reflection_strings
        .as_ref()
        .map(|r: &swift::SwiftReflectionStrings| r.strings.join("\n"))
        .unwrap_or_default();
    let cstring_concat: String = String::from_utf8_lossy(&bytes).into_owned();
    let combined_search_space: String = format!("{reflstr_concat}\n{cstring_concat}");

    let Some(text): Option<String> = load_text_at(&edge_root(), EDGE_MAPPING) else {
        eprintln!("skip: swiftshield-edgecases/{EDGE_MAPPING} fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);

    let mut substitutions_applied: usize = 0;
    let mut recovered_originals: BTreeSet<String> = BTreeSet::new();
    for (obfuscated_name, original_name) in &undo.mappings {
        if combined_search_space.contains(obfuscated_name) {
            substitutions_applied += 1;
            recovered_originals.insert(original_name.clone());
        }
    }
    assert!(
        substitutions_applied >= MIN_EDGE_MAPPING_ENTRIES,
        "expected to apply >= {MIN_EDGE_MAPPING_ENTRIES} inverse substitutions, applied {substitutions_applied} out of {}",
        undo.mappings.len()
    );
    assert!(
        recovered_originals.len() >= MIN_EDGE_MAPPING_ENTRIES,
        "expected >= {MIN_EDGE_MAPPING_ENTRIES} distinct originals recovered, got {}",
        recovered_originals.len()
    );
}

#[test]
fn swiftshield_edge_full_round_trip_substitution_produces_clean_text() {
    let Some(text): Option<String> = load_text_at(&edge_root(), EDGE_MAPPING) else {
        eprintln!("skip: swiftshield-edgecases/{EDGE_MAPPING} fixture absent");
        return;
    };
    let undo: SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(&text);
    let obfuscated_keys: Vec<&String> = undo.mappings.keys().take(5).collect();
    assert!(
        obfuscated_keys.len() >= 5,
        "need at least 5 obfuscated keys for round-trip"
    );

    let synthetic_obfuscated_log: String = format!(
        "[trace] entered {} -> {} -> {} -> {} -> {} (depth=5)",
        obfuscated_keys[0],
        obfuscated_keys[1],
        obfuscated_keys[2],
        obfuscated_keys[3],
        obfuscated_keys[4],
    );
    let mut recovered: String = synthetic_obfuscated_log;
    for (obfuscated_name, original_name) in &undo.mappings {
        recovered = recovered.replace(obfuscated_name, original_name);
    }
    for original in undo.mappings.values().take(5) {
        assert!(
            recovered.contains(original),
            "round-trip substitution missing original {original}"
        );
    }
    for obf in &obfuscated_keys {
        assert!(
            !recovered.contains(obf.as_str()),
            "round-trip still contains obfuscated token {obf}"
        );
    }
}
