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

#[path = "support/hermes_production_bundle.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod hermes_production_bundle;

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::panic::UnwindSafe;

use disrobe_pass_mobile::{
    DetectedKind, HERMES_MAGIC_LE_BYTES, HermesHeader, HermesModule, HermesStringKind,
    SmallFunctionHeader, detect_kind, parse_hermes_header, parse_hermes_module,
};
use hermes_production_bundle::{
    BUNDLE_MANIFEST_NAME, BUNDLE_REPO_PATH, BUNDLE_SHA256, BUNDLE_SIZE_BYTES, BundleRequirement,
    PUBLISHED_BAR_HEADING, PUBLISHED_BAR_LABEL, PUBLISHED_FUNCTION_COUNT, REQUIRE_BUNDLE_VAR,
    corpus_manifest_path, corpus_manifest_text, enforce_bundle_requirement, load_bundle,
    manifest_sample_block, published_bar, requirement_from_value,
};

const PINNED_VERSION: u32 = 96;
const PINNED_IDENTIFIER_COUNT: usize = 109_076;
const PINNED_STRING_TABLE_COUNT: usize = 300_978;
const PINNED_NON_IDENTIFIER_STRINGS: usize = 191_902;
const PINNED_OVERFLOW_STRINGS: usize = 1_038;
const PINNED_STRING_STORAGE_SIZE: usize = 5_647_272;
const PINNED_UTF16_STRINGS: usize = 88_423;
const PINNED_RAW_BYTECODE_SIZE: usize = 66_978_037;
const PINNED_BIG_INT_ENTRIES: usize = 25;
const PINNED_REG_EXP_ENTRIES: usize = 2_337;
const PINNED_NAMED_FUNCTIONS: usize = 65_988;

const PINNED_METRO_FUNCTION_NAMES: [&str; 8] = [
    "global",
    "metroRequire",
    "metroImportDefault",
    "metroImportAll",
    "packModuleId",
    "unpackModuleId",
    "loadModuleImplementation",
    "guardedLoadModule",
];

const PINNED_IDENTIFIERS: [&str; 23] = [
    "constructor",
    "prototype",
    "default",
    "render",
    "props",
    "children",
    "require",
    "module",
    "exports",
    "length",
    "toString",
    "valueOf",
    "hasOwnProperty",
    "Object",
    "Array",
    "Promise",
    "then",
    "catch",
    "createElement",
    "useState",
    "useEffect",
    "componentDidMount",
    "displayName",
];

#[test]
fn discord_hermes_bundle_has_correct_magic() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle magic check") else {
        return;
    };
    assert_eq!(
        bytes.len(),
        BUNDLE_SIZE_BYTES,
        "the loader must only hand back the declared bundle bytes"
    );
    let prefix: &[u8] = &bytes[..8];
    assert_eq!(prefix, &HERMES_MAGIC_LE_BYTES, "magic mismatch");
}

#[test]
fn discord_hermes_bundle_dispatch_detects_hermes() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle dispatch check") else {
        return;
    };
    let kind: DetectedKind = detect_kind(&bytes);
    assert_eq!(kind, DetectedKind::HermesRawBytecode);
}

#[test]
fn discord_hermes_header_parses_with_pinned_table_sizes() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle header parse") else {
        return;
    };
    let header: HermesHeader = parse_hermes_header(&bytes).expect("hermes header");
    assert_eq!(header.version, PINNED_VERSION);
    assert_eq!(header.function_count as usize, PUBLISHED_FUNCTION_COUNT);
    assert_eq!(header.identifier_count as usize, PINNED_IDENTIFIER_COUNT);
    assert_eq!(header.string_count as usize, PINNED_STRING_TABLE_COUNT);
    assert_eq!(
        header.overflow_string_count as usize,
        PINNED_OVERFLOW_STRINGS
    );
    assert_eq!(
        header.string_storage_size as usize,
        PINNED_STRING_STORAGE_SIZE
    );
}

#[test]
fn real_hermes_discord_full_module_parse() {
    let Some(bytes): Option<Vec<u8>> =
        load_bundle("the published production-bundle functions parsed figure")
    else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    assert_eq!(module.header.version, PINNED_VERSION);
    assert_eq!(
        module.functions.len(),
        PUBLISHED_FUNCTION_COUNT,
        "the published `{PUBLISHED_BAR_LABEL}` figure is {PUBLISHED_FUNCTION_COUNT}; a module parse \
         that yields any other number of function headers does not support that row"
    );
    assert_eq!(
        module.header.function_count as usize,
        module.functions.len(),
        "the header count and the parsed table must agree, otherwise the published figure is a \
         header field nobody parsed"
    );
    assert_eq!(module.identifiers.len(), PINNED_IDENTIFIER_COUNT);
    assert_eq!(module.strings.len(), PINNED_NON_IDENTIFIER_STRINGS);
    assert_eq!(
        module.identifiers.len() + module.strings.len(),
        PINNED_STRING_TABLE_COUNT,
        "the split tables must cover the whole declared string table, so a run that reads fewer \
         strings scores worse instead of shrinking what it is measured against"
    );
    assert_eq!(module.string_kinds.len(), PINNED_STRING_TABLE_COUNT);
    assert_eq!(
        module.overflow_resolved, PINNED_OVERFLOW_STRINGS,
        "every declared overflow string entry must resolve, not merely one of them"
    );
    assert_eq!(module.utf16_strings, PINNED_UTF16_STRINGS);
    assert_eq!(module.raw_bytecode_size, PINNED_RAW_BYTECODE_SIZE);
    assert_eq!(module.big_int_table.len(), PINNED_BIG_INT_ENTRIES);
    assert_eq!(module.reg_exp_table.len(), PINNED_REG_EXP_ENTRIES);

    let mut kind_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for k in &module.string_kinds {
        let key: &str = match k {
            HermesStringKind::String => "string",
            HermesStringKind::Identifier => "identifier",
        };
        *kind_counts.entry(key).or_insert(0) += 1;
    }
    assert_eq!(
        kind_counts.get("identifier").copied().unwrap_or(0),
        PINNED_IDENTIFIER_COUNT
    );
    assert_eq!(
        kind_counts.get("string").copied().unwrap_or(0),
        PINNED_NON_IDENTIFIER_STRINGS
    );
}

#[test]
fn real_hermes_discord_recovers_the_named_metro_runtime_functions() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("production-bundle function-name recovery")
    else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    let recovered: BTreeSet<&str> = module
        .functions
        .iter()
        .filter_map(|f: &SmallFunctionHeader| module.string_by_global_id(f.function_name_id))
        .filter(|name: &&str| !name.is_empty())
        .collect();
    let missing: Vec<&str> = PINNED_METRO_FUNCTION_NAMES
        .iter()
        .copied()
        .filter(|name: &&str| !recovered.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "the React Native Metro runtime function names must all come back from the production \
         bundle, {} of {} did: missing {missing:?}",
        PINNED_METRO_FUNCTION_NAMES.len() - missing.len(),
        PINNED_METRO_FUNCTION_NAMES.len()
    );

    let identifiers: BTreeSet<&str> = module.identifiers.iter().map(String::as_str).collect();
    let absent: Vec<&str> = PINNED_IDENTIFIERS
        .iter()
        .copied()
        .filter(|name: &&str| !identifiers.contains(name))
        .collect();
    assert!(
        absent.is_empty(),
        "every pinned JavaScript identifier must be recovered from the identifier table, {} of {} \
         were: missing {absent:?}",
        PINNED_IDENTIFIERS.len() - absent.len(),
        PINNED_IDENTIFIERS.len()
    );

    let named: usize = module
        .functions
        .iter()
        .filter(|f: &&SmallFunctionHeader| {
            module
                .string_by_global_id(f.function_name_id)
                .is_some_and(|name: &str| !name.is_empty())
        })
        .count();
    assert_eq!(
        named, PINNED_NAMED_FUNCTIONS,
        "{PINNED_NAMED_FUNCTIONS} of the {PUBLISHED_FUNCTION_COUNT} function headers carry a \
         non-empty name in this bundle; the rest are anonymous in the bytecode itself and no name \
         may be invented for them"
    );
    assert!(
        module
            .strings
            .iter()
            .any(|s: &String| s == "https://discord.com"),
        "the string table of this production bundle holds the app's own endpoint, so a parse that \
         loses it is decoding the wrong storage region"
    );
}

#[test]
fn real_hermes_discord_function_spans_and_name_ids_stay_in_range() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("production-bundle function-header resolution")
    else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("full Hermes module parse");
    let overflowed: usize = module
        .functions
        .iter()
        .filter(|f: &&SmallFunctionHeader| f.overflowed)
        .count();
    assert_eq!(
        overflowed, PUBLISHED_FUNCTION_COUNT,
        "every small function header in this bundle delegates to a large header, so the published \
         figure rests entirely on large-header resolution working"
    );
    let out_of_range: Vec<usize> = module
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f): &(usize, &SmallFunctionHeader)| {
            let end: usize = f.offset as usize + f.bytecode_size_bytes as usize;
            end > bytes.len() || f.bytecode_size_bytes == 0
        })
        .map(|(i, _): (usize, &SmallFunctionHeader)| i)
        .take(8)
        .collect();
    assert!(
        out_of_range.is_empty(),
        "every resolved function must own a non-empty bytecode span inside the file, otherwise the \
         large-header offsets are being read from the wrong place; first offenders: {out_of_range:?}"
    );
    let unresolvable: Vec<u32> = module
        .functions
        .iter()
        .map(|f: &SmallFunctionHeader| f.function_name_id)
        .filter(|id: &u32| module.string_by_global_id(*id).is_none())
        .take(8)
        .collect();
    assert!(
        unresolvable.is_empty(),
        "every resolved function name id must index the string table; first offenders: \
         {unresolvable:?}"
    );
}

#[test]
#[cfg(feature = "chain")]
fn discord_hermes_full_module_parse_dispatch() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;
    use disrobe_pass_mobile::{HermesSummary, MobilePassOutput};

    let Some(bytes): Option<Vec<u8>> = load_bundle("the production-bundle chain dispatch parse")
    else {
        return;
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let out: Artifact = MOBILE_PASS.run(&artifact).expect("mobile pass");
    let parsed: MobilePassOutput = serde_json::from_slice(out.envelope.as_slice()).expect("decode");
    assert_eq!(parsed.detected, DetectedKind::HermesRawBytecode);
    let summary: HermesSummary = parsed.hermes.expect("hermes summary");
    assert_eq!(summary.version, PINNED_VERSION);
    assert_eq!(summary.function_count, PUBLISHED_FUNCTION_COUNT);
    assert_eq!(summary.identifier_count, PINNED_IDENTIFIER_COUNT);
    assert_eq!(summary.string_count, PINNED_NON_IDENTIFIER_STRINGS);
}

#[test]
fn published_functions_parsed_bar_matches_the_figure_this_file_asserts() {
    let bar: serde_json::Value = published_bar(PUBLISHED_BAR_HEADING, PUBLISHED_BAR_LABEL);
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the published bar must carry a numeric value");
    let published: f64 = f64::from(
        u32::try_from(PUBLISHED_FUNCTION_COUNT).expect("the published function count fits u32"),
    );
    assert!(
        (value - published).abs() < 0.5,
        "xtask/data/recovery.json publishes {value} functions parsed while this file grades \
         {PUBLISHED_FUNCTION_COUNT}; the figure in the README, the docs and the chart all come from \
         that file, so a change there must move the graded assertion in the same commit"
    );
}

#[test]
fn corpus_manifest_declares_the_exact_bundle_this_file_grades() {
    let manifest: String = corpus_manifest_text();
    let block: &str = manifest_sample_block(&manifest, BUNDLE_MANIFEST_NAME).unwrap_or_else(|| {
        panic!(
            "{} must declare the sample `{BUNDLE_MANIFEST_NAME}`, because that declaration is the \
             only tracked record of the bytes the published figure was measured against",
            corpus_manifest_path().display()
        )
    });
    let size_line: String = format!("size_bytes = {BUNDLE_SIZE_BYTES}");
    assert!(
        block.contains(&size_line),
        "the manifest entry for `{BUNDLE_MANIFEST_NAME}` must declare `{size_line}`, matching the \
         size this file pins; entry was:\n{block}"
    );
    let digest_line: String = format!("sha256 = \"{BUNDLE_SHA256}\"");
    assert!(
        block.contains(&digest_line),
        "the manifest entry for `{BUNDLE_MANIFEST_NAME}` must declare `{digest_line}`, matching the \
         digest this file pins; entry was:\n{block}"
    );
    assert!(
        block.contains("proprietary"),
        "the manifest entry for `{BUNDLE_MANIFEST_NAME}` must keep recording that the sample is \
         proprietary, which is the reason it is not tracked and the reason the published figure is \
         local only; entry was:\n{block}"
    );
}

#[test]
fn an_absent_bundle_fails_instead_of_skipping_when_the_run_demands_it() {
    let message: String = message_from_seeded_defect("an absent production bundle", || {
        enforce_bundle_requirement("a probe case", BundleRequirement::Mandatory);
    });
    assert!(
        message.contains(REQUIRE_BUNDLE_VAR),
        "the failure must name the variable that made the bundle mandatory: {message}"
    );
    assert!(
        message.contains(BUNDLE_REPO_PATH),
        "the failure must name the path the bundle was expected at: {message}"
    );
    assert!(
        message.contains(BUNDLE_SHA256),
        "the failure must name the digest of the sample that would satisfy it: {message}"
    );
}

#[test]
fn the_requirement_variable_reads_every_documented_spelling() {
    assert_eq!(requirement_from_value(None), BundleRequirement::Optional);
    for off in ["", "0", "false", "no", "off", "optional", "  OFF  "] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(off))),
            BundleRequirement::Optional,
            "`{off}` must leave the bundle optional"
        );
    }
    for on in ["1", "true", "yes", "all", "local", "1 "] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(on))),
            BundleRequirement::Mandatory,
            "`{on}` must make an absent bundle fatal"
        );
    }
}

fn message_from_seeded_defect(what: &str, check: impl FnOnce() + UnwindSafe) -> String {
    eprintln!("seeding a defect ({what}); the failure below is the expected outcome");
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(check);
    let payload: Box<dyn Any + Send> = outcome.expect_err(
        "a seeded defect must make this gate fail; a check that accepts the seeded state pins \
         nothing",
    );
    let owned: Option<String> = payload.downcast_ref::<String>().cloned();
    owned
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message: &&str| (*message).to_owned())
        })
        .unwrap_or_else(|| panic!("the failure must carry a message naming what regressed"))
}
