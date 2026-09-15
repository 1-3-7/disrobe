#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[path = "common/published.rs"]
mod published;

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{
    WasmDetection, WasmFamilySupport, WasmObfuscator, WasmPipelineSupport, WasmTransformSupport,
    detect,
};
use published::{published_bar, published_count};

const PUBLISHED_HEADING: &str = "Obfuscator and bundler family coverage";
const PUBLISHED_BAR: &str = "WASM direct transformation helper families";

const NAMED_FAMILY_POPULATION: usize = 5;

const EXPECTED_DIRECT_HELPERS: [WasmObfuscator; 4] = [
    WasmObfuscator::JscramblerWasm,
    WasmObfuscator::Wobfuscator,
    WasmObfuscator::TigressEmscripten,
    WasmObfuscator::WasmMixer,
];

const EXPECTED_PIPELINE_DELIVERED: [WasmObfuscator; 3] = [
    WasmObfuscator::JscramblerWasm,
    WasmObfuscator::Wobfuscator,
    WasmObfuscator::WasmMixer,
];

const EXCLUDED_FROM_HELPER_AND_PIPELINE: [WasmObfuscator; 1] = [WasmObfuscator::WasmNameObfuscator];

const PUBLISHED_FAMILY_TOKENS: [(WasmObfuscator, &str); NAMED_FAMILY_POPULATION] = [
    (WasmObfuscator::JscramblerWasm, "Jscrambler"),
    (WasmObfuscator::Wobfuscator, "Wobfuscator"),
    (WasmObfuscator::TigressEmscripten, "Tigress"),
    (WasmObfuscator::WasmMixer, "Wasmixer"),
    (WasmObfuscator::WasmNameObfuscator, "wasm-name-obfuscator"),
];

const EXCLUSION_MARKERS: [&str; 2] = ["excluded", "detect+classify only"];

const EVIDENCE_FILE: &str = "obfuscators_e2e.rs";
const TEST_ATTRIBUTE: &str = "#[test]";
const IGNORE_ATTRIBUTE: &str = "#[ignore";
const ATTRIBUTE_LOOKBACK_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
struct FamilyEvidence {
    family: WasmObfuscator,
    test_fn: &'static str,
    exercised_symbol: &'static str,
}

const FAMILY_EVIDENCE: [FamilyEvidence; NAMED_FAMILY_POPULATION] = [
    FamilyEvidence {
        family: WasmObfuscator::JscramblerWasm,
        test_fn: "jscrambler_detect_then_strip_and_fold_opaque",
        exercised_symbol: "strip_integrity_imports",
    },
    FamilyEvidence {
        family: WasmObfuscator::Wobfuscator,
        test_fn: "wobfuscator_extract_optable_and_lift_each_eval",
        exercised_symbol: "extract_optable",
    },
    FamilyEvidence {
        family: WasmObfuscator::TigressEmscripten,
        test_fn: "tigress_detect_emscripten_then_unflatten_dispatcher",
        exercised_symbol: "unflatten",
    },
    FamilyEvidence {
        family: WasmObfuscator::WasmMixer,
        test_fn: "wasmixer_detect_decrypt_stub_via_direct_api",
        exercised_symbol: "detect_decrypt_stubs",
    },
    FamilyEvidence {
        family: WasmObfuscator::WasmNameObfuscator,
        test_fn: "name_obfuscator_detect_and_classify_strategy",
        exercised_symbol: "classify_export_strategy",
    },
];

type RosterEntry = (WasmObfuscator, WasmFamilySupport);

fn crate_roster() -> Vec<RosterEntry> {
    WasmObfuscator::NAMED_FAMILIES
        .into_iter()
        .map(|family: WasmObfuscator| {
            let Some(support): Option<WasmFamilySupport> = family.support() else {
                panic!("{family:?} is named but carries no catalog support declaration")
            };
            (family, support)
        })
        .collect()
}

fn transform_helper_families(roster: &[RosterEntry]) -> Vec<WasmObfuscator> {
    roster
        .iter()
        .copied()
        .filter(|entry: &RosterEntry| entry.1.transform == WasmTransformSupport::DirectHelper)
        .map(|entry: RosterEntry| entry.0)
        .collect()
}

fn pipeline_delivered_families(roster: &[RosterEntry]) -> Vec<WasmObfuscator> {
    roster
        .iter()
        .copied()
        .filter(|entry: &RosterEntry| entry.1.pipeline == WasmPipelineSupport::Delivered)
        .map(|entry: RosterEntry| entry.0)
        .collect()
}

fn same_members(left: &[WasmObfuscator], right: &[WasmObfuscator]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|family: &WasmObfuscator| right.contains(family))
        && right
            .iter()
            .all(|family: &WasmObfuscator| left.contains(family))
}

fn published_token(family: WasmObfuscator) -> &'static str {
    let found: Option<(WasmObfuscator, &'static str)> = PUBLISHED_FAMILY_TOKENS
        .into_iter()
        .find(|entry: &(WasmObfuscator, &str)| entry.0 == family);
    let Some(entry): Option<(WasmObfuscator, &'static str)> = found else {
        panic!(
            "{family:?} is on the roster but PUBLISHED_FAMILY_TOKENS does not say how the \
             published bar spells it, so nothing ties this family to the number the README renders"
        )
    };
    entry.1
}

fn evidence_for(family: WasmObfuscator) -> FamilyEvidence {
    let found: Option<FamilyEvidence> = FAMILY_EVIDENCE
        .into_iter()
        .find(|row: &FamilyEvidence| row.family == family);
    let Some(row): Option<FamilyEvidence> = found else {
        panic!(
            "{family:?} is on the roster the `{PUBLISHED_BAR}` count is cut from, but \
             FAMILY_EVIDENCE names no test that exercises it, so the published number would count \
             a family nothing demonstrates"
        )
    };
    row
}

fn evidence_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(EVIDENCE_FILE);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the `{PUBLISHED_BAR}` figure is cut from the per-family evidence in {}, so a run that \
             cannot read that file must fail rather than measure nothing: {error}",
            path.display()
        )
    })
}

fn evidence_region<'a>(source: &'a str, test_fn: &str) -> &'a str {
    let needle: String = format!("fn {test_fn}(");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{EVIDENCE_FILE} no longer declares `{test_fn}`, which FAMILY_EVIDENCE names as the \
             evidence for a family the `{PUBLISHED_BAR}` count depends on; the test was renamed or \
             deleted while the published number stayed"
        )
    };
    let Some(tail): Option<&str> = source.get(at..) else {
        panic!("`{test_fn}` starts mid-character in {EVIDENCE_FILE}, so its body cannot be read")
    };
    let next: Option<usize> = tail
        .get(1..)
        .and_then(|rest: &str| rest.find(TEST_ATTRIBUTE));
    let end: usize = next.map_or(tail.len(), |offset: usize| offset.saturating_add(1));
    let Some(region): Option<&str> = tail.get(..end) else {
        panic!("the body of `{test_fn}` could not be delimited in {EVIDENCE_FILE}")
    };
    region
}

fn attribute_window<'a>(source: &'a str, test_fn: &str) -> &'a str {
    let needle: String = format!("fn {test_fn}(");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!("{EVIDENCE_FILE} no longer declares `{test_fn}`")
    };
    let mut start: usize = at.saturating_sub(ATTRIBUTE_LOOKBACK_BYTES);
    while start < at && !source.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    let Some(window): Option<&str> = source.get(start..at) else {
        panic!("the attributes above `{test_fn}` could not be read from {EVIDENCE_FILE}")
    };
    window
}

fn calls(region: &str, symbol: &str) -> bool {
    region.contains(&format!("{symbol}("))
}

fn bar_source() -> String {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    bar["source"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "the `{PUBLISHED_BAR}` bar must record where its number comes from; recovery.json \
                 carries no source string for it"
            )
        })
        .to_owned()
}

#[test]
fn published_wasm_direct_helper_count_matches_this_crate_roster() {
    let published: u64 = published_count(PUBLISHED_HEADING, PUBLISHED_BAR);
    let roster: Vec<RosterEntry> = crate_roster();

    assert_eq!(
        roster.len(),
        NAMED_FAMILY_POPULATION,
        "the named-family population is the denominator both published wasm figures are cut from, \
         the catalog entry count and the helper count, so it is pinned by equality: this crate \
         now carries {} families",
        roster.len()
    );

    let direct_helpers: Vec<WasmObfuscator> = transform_helper_families(&roster);
    let pipeline_delivered: Vec<WasmObfuscator> = pipeline_delivered_families(&roster);
    let excluded: Vec<WasmObfuscator> = roster
        .iter()
        .copied()
        .filter(|entry: &RosterEntry| {
            entry.1.transform == WasmTransformSupport::Unavailable
                && entry.1.pipeline == WasmPipelineSupport::NotDelivered
        })
        .map(|entry: RosterEntry| entry.0)
        .collect();

    assert!(
        same_members(&direct_helpers, &EXPECTED_DIRECT_HELPERS),
        "xtask/data/recovery.json publishes {published} `{PUBLISHED_BAR}` and the README and the \
         pass table render that number, but this crate's direct helper catalog is {direct_helpers:?} \
         where the published roster is {EXPECTED_DIRECT_HELPERS:?}; a swap that keeps the count would leave the number green \
         while the families changed"
    );
    assert!(
        same_members(&pipeline_delivered, &EXPECTED_PIPELINE_DELIVERED),
        "the wasm deob pipeline must deliver exactly {EXPECTED_PIPELINE_DELIVERED:?}, but the \
         catalog marks {pipeline_delivered:?}; Tigress helpers are standalone and must not count \
         as runtime delivery"
    );
    assert_eq!(
        pipeline_delivered.len(),
        3,
        "the runtime-delivered count is derived from the same family support declarations as the \
         published helper count"
    );
    assert!(
        same_members(&excluded, &EXCLUDED_FROM_HELPER_AND_PIPELINE),
        "the direct-helper and pipeline exclusions must be declared together, but the catalog has \
         {excluded:?}"
    );
    assert_eq!(
        published,
        direct_helpers.len() as u64,
        "xtask/data/recovery.json publishes {published} `{PUBLISHED_BAR}` and metrics.rs renders \
         that value into README.md and docs/src/passes.md, but this crate catalogs direct helpers for {} of the {} \
         named families",
        direct_helpers.len(),
        NAMED_FAMILY_POPULATION
    );

    let source: String = bar_source();
    for family in direct_helpers {
        let token: &str = published_token(family);
        assert!(
            source.contains(token),
            "the published bar counts {family:?} but its provenance never names it; searched for \
             `{token}` in {source}"
        );
    }
    for family in excluded {
        let token: &str = published_token(family);
        assert!(
            source.contains(token),
            "the published bar excludes {family:?} but its provenance never names it; searched for \
             `{token}` in {source}"
        );
        assert!(
            EXCLUSION_MARKERS
                .into_iter()
                .any(|marker: &str| source.contains(marker)),
            "the published bar must state that {family:?} is left out of the count, otherwise a \
             reader cannot tell {published} from {NAMED_FAMILY_POPULATION}; none of \
             {EXCLUSION_MARKERS:?} appear in {source}"
        );
    }
}

#[test]
fn the_excluded_family_is_still_detected_and_classified() {
    const SHORT_EXPORT_MODULE: &str = r#"
        (module
          (func (export "aa") (result i32) i32.const 1)
          (func (export "bb") (result i32) i32.const 2)
          (func (export "cc") (result i32) i32.const 3)
          (func (export "dd") (result i32) i32.const 4))
    "#;

    let bytes: Vec<u8> = wat::parse_str(SHORT_EXPORT_MODULE).expect("assemble wat");
    let detection: WasmDetection = detect(&bytes).expect("detect must parse the module");
    assert_eq!(
        detection.obfuscator,
        WasmObfuscator::WasmNameObfuscator,
        "a stripped short-export module must still fingerprint as the name obfuscator, or the \
         family excluded from the `{PUBLISHED_BAR}` count is not covered at all"
    );
    assert_eq!(
        detection.obfuscator.support(),
        Some(WasmFamilySupport {
            transform: WasmTransformSupport::Unavailable,
            pipeline: WasmPipelineSupport::NotDelivered,
        }),
        "the excluded family must declare neither a direct helper nor pipeline delivery"
    );
    assert!(
        !EXPECTED_DIRECT_HELPERS.contains(&detection.obfuscator),
        "{:?} is excluded from the published direct helper count and must never appear in the \
         direct helper roster",
        detection.obfuscator
    );
}

#[test]
fn moving_the_excluded_family_into_the_direct_helper_set_breaks_the_pin() {
    let published: u64 = published_count(PUBLISHED_HEADING, PUBLISHED_BAR);
    let mutated: Vec<RosterEntry> = crate_roster()
        .into_iter()
        .map(|(family, mut support): RosterEntry| {
            if support.transform == WasmTransformSupport::Unavailable {
                support.transform = WasmTransformSupport::DirectHelper;
            }
            (family, support)
        })
        .collect();

    let direct_helpers: Vec<WasmObfuscator> = transform_helper_families(&mutated);
    assert_eq!(
        direct_helpers.len(),
        NAMED_FAMILY_POPULATION,
        "the control must promote every named family into the direct helper set"
    );
    assert_ne!(
        published,
        direct_helpers.len() as u64,
        "the published `{PUBLISHED_BAR}` figure must disagree with a roster that claims a direct helper \
         for the detect-only family, otherwise the equality assertion above proves nothing"
    );
    assert!(
        !same_members(&direct_helpers, &EXPECTED_DIRECT_HELPERS),
        "the membership assertion above must reject a padded roster, but {direct_helpers:?} compared \
         equal to {EXPECTED_DIRECT_HELPERS:?}"
    );
    assert!(
        mutated
            .iter()
            .all(|entry: &RosterEntry| entry.1.transform == WasmTransformSupport::DirectHelper),
        "the control roster must leave no family outside the direct-helper set"
    );
}

#[test]
fn every_named_family_has_a_live_evidence_test_that_calls_its_declared_entry_point() {
    let published: u64 = published_count(PUBLISHED_HEADING, PUBLISHED_BAR);
    let roster: Vec<RosterEntry> = crate_roster();
    let source: String = evidence_source();

    assert_eq!(
        FAMILY_EVIDENCE.len(),
        roster.len(),
        "FAMILY_EVIDENCE is the evidence side of the same population the `{PUBLISHED_BAR}` figure \
         is cut from, so it is pinned by equality against the roster: {} evidence rows against {} \
         families",
        FAMILY_EVIDENCE.len(),
        roster.len()
    );
    for entry in &roster {
        let row: FamilyEvidence = evidence_for(entry.0);
        assert_eq!(
            row.family, entry.0,
            "evidence lookup returned the wrong family for {:?}",
            entry.0
        );
    }
    for row in FAMILY_EVIDENCE {
        assert!(
            roster
                .iter()
                .any(|entry: &RosterEntry| entry.0 == row.family),
            "FAMILY_EVIDENCE names {:?}, which is not on the roster the published \
             `{PUBLISHED_BAR}` count is cut from",
            row.family
        );
    }

    assert!(
        bar_source().contains(EVIDENCE_FILE),
        "the published bar must name {EVIDENCE_FILE} as its provenance, otherwise the file this \
         check scans and the file the {published} is attributed to can drift apart"
    );

    for row in FAMILY_EVIDENCE {
        let window: &str = attribute_window(&source, row.test_fn);
        assert!(
            window.contains(TEST_ATTRIBUTE),
            "`{}` is named as the evidence for {:?} but carries no {TEST_ATTRIBUTE}, so it never \
             runs and cannot fail",
            row.test_fn,
            row.family
        );
        assert!(
            !window.contains(IGNORE_ATTRIBUTE),
            "`{}` is named as the evidence for {:?} but is marked {IGNORE_ATTRIBUTE}, so the \
             published {published} would survive a declared support path that stopped working",
            row.test_fn,
            row.family
        );

        let region: &str = evidence_region(&source, row.test_fn);
        assert!(
            calls(region, row.exercised_symbol),
            "`{}` is the evidence that {:?} has its declared support, but its body never calls \
             `{}`; a test gutted to a no-op would leave the published {published} green while the \
             declared support path was gone",
            row.test_fn,
            row.family,
            row.exercised_symbol
        );
    }
}

#[test]
fn the_evidence_scan_delimits_one_test_and_cannot_pass_by_reading_the_whole_file() {
    let source: String = evidence_source();

    let symbols: Vec<&'static str> = FAMILY_EVIDENCE
        .into_iter()
        .map(|row: FamilyEvidence| row.exercised_symbol)
        .collect();
    for symbol in &symbols {
        assert_eq!(
            symbols
                .iter()
                .filter(|other: &&&str| *other == symbol)
                .count(),
            1,
            "`{symbol}` is named as the exercised entry point for more than one family, so one \
             family could vouch for another and the per-family check would prove less than it reads"
        );
    }

    for row in FAMILY_EVIDENCE {
        let region: &str = evidence_region(&source, row.test_fn);
        assert!(
            region.len() < source.len(),
            "the region extracted for `{}` is the whole of {EVIDENCE_FILE}, so every containment \
             check above would pass no matter which test was deleted",
            row.test_fn
        );

        let matched: Vec<&&str> = symbols
            .iter()
            .filter(|symbol: &&&str| calls(region, symbol))
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "the region extracted for `{}` must contain exactly one of the {} exercised entry \
             points, otherwise the scan is not delimited to a single test; it matched {matched:?}",
            row.test_fn,
            symbols.len()
        );

        for other in FAMILY_EVIDENCE {
            assert!(
                other.test_fn == row.test_fn || !region.contains(other.test_fn),
                "the region extracted for `{}` also spans `{}`, so the two families share one body \
                 and neither is checked on its own",
                row.test_fn,
                other.test_fn
            );
        }
    }
}
