#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::uninlined_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::single_char_pattern
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::{Artifact, LegacyPass, Rung};
use disrobe_pass_mobile::{
    DetectedKind, HERMES_MAGIC_LE_BYTES, HermesHeader, HermesModule, HermesStringKind, MobilePass,
    MobilePassOutput, detect_kind, parse_hermes_header, parse_hermes_module,
};

fn fixture_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("discord")
        .join("index.android.bundle")
}

fn load_fixture() -> Option<Vec<u8>> {
    let path: PathBuf = fixture_path();
    if !path.exists() {
        return None;
    }
    std::fs::read(&path).ok()
}

#[test]
fn discord_hermes_bundle_has_correct_magic() {
    let bytes: Vec<u8> = match load_fixture() {
        Some(b) => b,
        None => {
            eprintln!("skip: discord fixture missing at {:?}", fixture_path());
            return;
        }
    };
    assert!(bytes.len() > 1024, "bundle too small: {}", bytes.len());
    let prefix: &[u8] = &bytes[..8];
    assert_eq!(prefix, &HERMES_MAGIC_LE_BYTES, "magic mismatch");
}

#[test]
fn discord_hermes_bundle_dispatch_detects_hermes() {
    let bytes: Vec<u8> = match load_fixture() {
        Some(b) => b,
        None => {
            eprintln!("skip: discord fixture missing");
            return;
        }
    };
    let kind: DetectedKind = detect_kind(&bytes);
    assert_eq!(kind, DetectedKind::HermesRawBytecode);
}

#[test]
fn discord_hermes_header_parses_with_supported_version() {
    let bytes: Vec<u8> = match load_fixture() {
        Some(b) => b,
        None => {
            eprintln!("skip: discord fixture missing");
            return;
        }
    };
    let header: HermesHeader = parse_hermes_header(&bytes).expect("hermes header");
    assert!(
        (60..=96).contains(&header.version),
        "version out of range: {}",
        header.version
    );
    assert!(header.function_count > 0, "expected functions");
    assert!(header.string_count > 0, "expected strings");
    assert!(header.identifier_count > 0, "expected identifiers");
}

#[test]
fn real_hermes_discord_full_module_parse() {
    let bytes: Vec<u8> = match load_fixture() {
        Some(b) => b,
        None => {
            eprintln!("skip: discord fixture missing at {:?}", fixture_path());
            return;
        }
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    assert_eq!(module.header.version, 96);
    assert_eq!(module.header.function_count, 122_633);
    assert_eq!(module.header.identifier_count, 109_076);
    assert_eq!(module.header.string_count, 300_978);
    assert_eq!(module.header.overflow_string_count, 1_038);
    assert_eq!(module.header.string_storage_size, 5_647_272);
    assert_eq!(module.functions.len(), 122_633);
    assert_eq!(module.identifiers.len(), 109_076);
    assert_eq!(module.strings.len(), 191_902);
    assert_eq!(module.identifiers.len() + module.strings.len(), 300_978);
    assert_eq!(module.string_kinds.len(), 300_978);
    let mut kind_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for k in &module.string_kinds {
        let key: &str = match k {
            HermesStringKind::String => "string",
            HermesStringKind::Identifier => "identifier",
        };
        *kind_counts.entry(key).or_insert(0) += 1;
    }
    assert_eq!(kind_counts.get("identifier").copied().unwrap_or(0), 109_076);
    assert_eq!(kind_counts.get("string").copied().unwrap_or(0), 191_902);
    assert!(
        module.overflow_resolved >= 1,
        "expected at least one overflow-resolved string, got {}",
        module.overflow_resolved
    );
    let sample_identifier_hits: usize = module
        .identifiers
        .iter()
        .filter(|s: &&String| {
            matches!(
                s.as_str(),
                "constructor" | "prototype" | "default" | "render"
            )
        })
        .count();
    assert!(
        sample_identifier_hits >= 2,
        "expected to recover well-known JS identifier names, got {sample_identifier_hits}"
    );
}

#[test]
fn discord_hermes_full_module_parse_dispatch() {
    let bytes: Vec<u8> = match load_fixture() {
        Some(b) => b,
        None => {
            eprintln!("skip: discord fixture missing");
            return;
        }
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let out: Artifact = MobilePass.run(&artifact).expect("mobile pass");
    let parsed: MobilePassOutput = serde_json::from_slice(out.envelope.as_slice()).expect("decode");
    assert_eq!(parsed.detected, DetectedKind::HermesRawBytecode);
    let summary = parsed.hermes.expect("hermes summary");
    assert_eq!(summary.version, 96);
    assert_eq!(summary.function_count, 122_633);
    assert_eq!(summary.identifier_count, 109_076);
    assert_eq!(summary.string_count, 191_902);
}
