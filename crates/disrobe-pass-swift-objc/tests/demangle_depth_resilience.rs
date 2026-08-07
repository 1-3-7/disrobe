#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_swift_objc::demangle;
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const CASES_PER_INPUT: usize = 256;
const BATCH_SIZE: usize = 128;
const CASE_BUDGET: Duration = Duration::from_millis(400);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const NESTING_DOMAIN: u64 = 0x0F3A_11C3_D3E9_0001;
const MIN_NESTING_LEVELS: usize = 1_100;
const MAX_EXTRA_NESTING_LEVELS: usize = 200;

fn nested_array_of_int(levels: usize) -> String {
    let mut body: String = "Say".repeat(levels);
    body.push_str("Si");
    body.push_str(&"G".repeat(levels));
    format!("$s{body}")
}

fn nested_optional_of_int(levels: usize) -> String {
    let mut body: String = String::from("Si");
    for _ in 0..levels {
        body.push_str("Sg");
    }
    format!("$s{body}")
}

fn nested_tuple_of_int(levels: usize) -> String {
    let mut body: String = String::new();
    for _ in 0..levels {
        body.push_str("Si_Si");
    }
    for _ in 0..levels {
        body.push('t');
    }
    format!("$s{body}")
}

fn deeply_nested_from_seed(case_seed: u64) -> String {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ NESTING_DOMAIN);
    let levels: usize = MIN_NESTING_LEVELS + rng.below_usize(MAX_EXTRA_NESTING_LEVELS);
    match rng.below_usize(3) {
        0 => nested_array_of_int(levels),
        1 => nested_optional_of_int(levels),
        _ => nested_tuple_of_int(levels),
    }
}

fn oversized_from_seed(case_seed: u64) -> String {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ NESTING_DOMAIN.wrapping_add(1));
    let extra: usize = rng.below_usize(1 << 15);
    format!("$s4Arms{}P", "A".repeat((1 << 17) + extra))
}

fn probe_symbol(text: &str) {
    let _: Result<String, _> = demangle::demangle(text);
    let _: Option<String> = demangle::demangle_type(text);
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("nested-array-seed", nested_array_of_int(48).into_bytes()),
        CorpusEntry::new(
            "nested-optional-seed",
            nested_optional_of_int(48).into_bytes(),
        ),
        CorpusEntry::new("nested-tuple-seed", nested_tuple_of_int(48).into_bytes()),
        CorpusEntry::new("empty", Vec::<u8>::new()),
    ]
}

fn check(case: &StressCase<'_>) {
    probe_symbol(&String::from_utf8_lossy(case.bytes()));
    let mut rng: XorShift64 = XorShift64::new(case.case_seed() ^ NESTING_DOMAIN.wrapping_add(3));
    match rng.below_usize(3) {
        0 => probe_symbol(&deeply_nested_from_seed(case.case_seed())),
        1 => probe_symbol(&oversized_from_seed(case.case_seed())),
        _ => {
            let truncated_at: usize = rng.below_usize(4_096);
            let deep: String = deeply_nested_from_seed(case.case_seed());
            let boundary: usize = deep
                .char_indices()
                .map(|(i, _)| i)
                .find(|i| *i >= truncated_at)
                .unwrap_or(deep.len());
            probe_symbol(&deep[..boundary]);
        }
    }
}

fn config() -> StressConfig {
    StressConfig {
        cases_per_input: CASES_PER_INPUT,
        batch_size: BATCH_SIZE,
        case_budget: CASE_BUDGET,
        suite_budget: SUITE_BUDGET,
        ..StressConfig::default()
    }
}

mod depth_resilience {
    disrobe_testkit::stress_suite!(
        check: super::check,
        corpus: super::corpus,
        config: super::config
    );
}

#[test]
fn a_deeply_nested_array_type_is_rejected_not_crashed() {
    let mangled: String = nested_array_of_int(MIN_NESTING_LEVELS);
    assert!(
        mangled.len() > MIN_NESTING_LEVELS,
        "the nesting must actually be present"
    );
    let rendered: Option<String> = demangle::demangle_type(&mangled[2..]);
    assert!(
        rendered.is_none(),
        "a nesting depth far past MAX_DEPTH must abstain rather than recurse unbounded"
    );
}

#[test]
fn a_deeply_nested_optional_type_is_rejected_not_crashed() {
    let mangled: String = nested_optional_of_int(MIN_NESTING_LEVELS);
    let rendered: Option<String> = demangle::demangle_type(&mangled[2..]);
    assert!(
        rendered.is_none(),
        "a nesting depth far past MAX_DEPTH must abstain rather than recurse unbounded"
    );
}

#[test]
fn a_deeply_nested_tuple_type_is_rejected_not_crashed() {
    let mangled: String = nested_tuple_of_int(MIN_NESTING_LEVELS);
    let rendered: Option<String> = demangle::demangle_type(&mangled[2..]);
    assert!(
        rendered.is_none(),
        "a nesting depth far past MAX_DEPTH must abstain rather than recurse unbounded"
    );
}

#[test]
fn a_shallow_nesting_under_the_bound_still_recovers() {
    let mangled: String = nested_optional_of_int(3);
    let rendered: Option<String> = demangle::demangle_type(&mangled[2..]);
    assert_eq!(rendered.as_deref(), Some("Swift.Int???"));
}

fn assert_abstains_quickly(label: &str, mangled: &str) {
    let start: std::time::Instant = std::time::Instant::now();
    let rendered: Option<String> = demangle::demangle_type(&mangled[2..]);
    let elapsed: Duration = start.elapsed();
    assert!(rendered.is_none(), "{label} unexpectedly recovered a type");
    assert!(
        elapsed < Duration::from_secs(1),
        "{label} took {elapsed:?} to abstain; a depth-bounded parser must reject far sooner"
    );
}

#[test]
fn a_deeply_nested_array_abstains_in_bounded_wall_clock_time() {
    assert_abstains_quickly("nested array", &nested_array_of_int(MIN_NESTING_LEVELS));
}

#[test]
fn a_deeply_nested_optional_abstains_in_bounded_wall_clock_time() {
    assert_abstains_quickly(
        "nested optional",
        &nested_optional_of_int(MIN_NESTING_LEVELS),
    );
}

#[test]
fn a_deeply_nested_tuple_abstains_in_bounded_wall_clock_time() {
    assert_abstains_quickly("nested tuple", &nested_tuple_of_int(MIN_NESTING_LEVELS));
}
