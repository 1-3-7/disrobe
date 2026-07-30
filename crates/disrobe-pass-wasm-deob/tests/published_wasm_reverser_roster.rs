#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[path = "common/published.rs"]
mod published;

use disrobe_pass_wasm_deob::{WasmDetection, WasmObfuscator, WasmRecovery, detect};
use published::{published_bar, published_count};

const PUBLISHED_HEADING: &str = "Obfuscator and bundler family coverage";
const PUBLISHED_BAR: &str = "WASM obfuscator reversers";

const NAMED_FAMILY_POPULATION: usize = 5;

const EXPECTED_REVERSED: [WasmObfuscator; 4] = [
    WasmObfuscator::JscramblerWasm,
    WasmObfuscator::Wobfuscator,
    WasmObfuscator::TigressEmscripten,
    WasmObfuscator::WasmMixer,
];

const EXCLUDED_DETECT_AND_CLASSIFY_ONLY: [WasmObfuscator; 1] = [WasmObfuscator::WasmNameObfuscator];

const PUBLISHED_FAMILY_TOKENS: [(WasmObfuscator, &str); NAMED_FAMILY_POPULATION] = [
    (WasmObfuscator::JscramblerWasm, "Jscrambler"),
    (WasmObfuscator::Wobfuscator, "Wobfuscator"),
    (WasmObfuscator::TigressEmscripten, "Tigress"),
    (WasmObfuscator::WasmMixer, "Wasmixer"),
    (WasmObfuscator::WasmNameObfuscator, "wasm-name-obfuscator"),
];

const EXCLUSION_MARKERS: [&str; 2] = ["excluded", "detect+classify only"];

type RosterEntry = (WasmObfuscator, Option<WasmRecovery>);

fn crate_roster() -> Vec<RosterEntry> {
    WasmObfuscator::NAMED_FAMILIES
        .into_iter()
        .map(|family: WasmObfuscator| (family, family.recovery()))
        .collect()
}

fn families_at(roster: &[RosterEntry], depth: WasmRecovery) -> Vec<WasmObfuscator> {
    roster
        .iter()
        .copied()
        .filter(|entry: &RosterEntry| entry.1 == Some(depth))
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
fn published_wasm_reverser_count_matches_this_crate_roster() {
    let published: u64 = published_count(PUBLISHED_HEADING, PUBLISHED_BAR);
    let roster: Vec<RosterEntry> = crate_roster();

    assert_eq!(
        roster.len(),
        NAMED_FAMILY_POPULATION,
        "the named-family population is the denominator both published wasm figures are cut from, \
         the catalog entry count and the reverser count, so it is pinned by equality: this crate \
         now carries {} families",
        roster.len()
    );

    let reversed: Vec<WasmObfuscator> = families_at(&roster, WasmRecovery::Reversed);
    let detect_only: Vec<WasmObfuscator> =
        families_at(&roster, WasmRecovery::DetectAndClassifyOnly);

    assert!(
        same_members(&reversed, &EXPECTED_REVERSED),
        "xtask/data/recovery.json publishes {published} `{PUBLISHED_BAR}` and the README and the \
         pass table render that number, but this crate reverses {reversed:?} where the published \
         roster is {EXPECTED_REVERSED:?}; a swap that keeps the count would leave the number green \
         while the families changed"
    );
    assert!(
        same_members(&detect_only, &EXCLUDED_DETECT_AND_CLASSIFY_ONLY),
        "the published count excludes {EXCLUDED_DETECT_AND_CLASSIFY_ONLY:?} because hex renames \
         destroy the original names, but this crate now treats {detect_only:?} as detect and \
         classify only"
    );
    assert_eq!(
        reversed.len() + detect_only.len(),
        NAMED_FAMILY_POPULATION,
        "every named family is either reversed or detect and classify only; {} reversed plus {} \
         detect-only does not account for the whole roster",
        reversed.len(),
        detect_only.len()
    );
    assert_eq!(
        published,
        reversed.len() as u64,
        "xtask/data/recovery.json publishes {published} `{PUBLISHED_BAR}` and metrics.rs renders \
         that value into README.md and docs/src/passes.md, but this crate reverses {} of the {} \
         named families",
        reversed.len(),
        NAMED_FAMILY_POPULATION
    );

    let source: String = bar_source();
    for family in reversed {
        let token: &str = published_token(family);
        assert!(
            source.contains(token),
            "the published bar counts {family:?} but its provenance never names it; searched for \
             `{token}` in {source}"
        );
    }
    for family in detect_only {
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
        detection.obfuscator.recovery(),
        Some(WasmRecovery::DetectAndClassifyOnly),
        "the excluded family must be classified as detect and classify only"
    );
    assert!(
        !EXPECTED_REVERSED.contains(&detection.obfuscator),
        "{:?} is excluded from the published reverser count and must never appear in the reversed \
         roster",
        detection.obfuscator
    );
}

#[test]
fn moving_the_excluded_family_into_the_reversed_set_breaks_the_pin() {
    let published: u64 = published_count(PUBLISHED_HEADING, PUBLISHED_BAR);
    let mutated: Vec<RosterEntry> = crate_roster()
        .into_iter()
        .map(|entry: RosterEntry| match entry.1 {
            Some(WasmRecovery::DetectAndClassifyOnly) => (entry.0, Some(WasmRecovery::Reversed)),
            other => (entry.0, other),
        })
        .collect();

    let reversed: Vec<WasmObfuscator> = families_at(&mutated, WasmRecovery::Reversed);
    assert_eq!(
        reversed.len(),
        NAMED_FAMILY_POPULATION,
        "the control must promote every named family to reversed"
    );
    assert_ne!(
        published,
        reversed.len() as u64,
        "the published `{PUBLISHED_BAR}` figure must disagree with a roster that claims a reverser \
         for the detect-only family, otherwise the equality assertion above proves nothing"
    );
    assert!(
        !same_members(&reversed, &EXPECTED_REVERSED),
        "the membership assertion above must reject a padded roster, but {reversed:?} compared \
         equal to {EXPECTED_REVERSED:?}"
    );
    assert!(
        families_at(&mutated, WasmRecovery::DetectAndClassifyOnly).is_empty(),
        "the control roster must leave nothing behind in the excluded set"
    );
}
