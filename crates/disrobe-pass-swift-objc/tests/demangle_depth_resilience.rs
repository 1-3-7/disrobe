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
const MAX_THUNK_WIDTH: usize = 64;

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

fn reabstraction_thunk_of_width(width: usize) -> String {
    let types: String = "Si".repeat(width);
    let conventions: String = "y".repeat(width);
    format!("$s{types}Ig{conventions}_{types}Ig{conventions}_TR")
}

fn reabstraction_thunk_with_mangled_ctype_length(length: u64) -> String {
    format!("$sIgzB{length}abc_Ig_TR")
}

fn reabstraction_thunk_from_seed(case_seed: u64) -> String {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ NESTING_DOMAIN.wrapping_add(5));
    if rng.below(2) == 0 {
        reabstraction_thunk_of_width(rng.below_usize(MAX_THUNK_WIDTH))
    } else {
        reabstraction_thunk_with_mangled_ctype_length(rng.below(u64::MAX))
    }
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
    match rng.below_usize(4) {
        0 => probe_symbol(&deeply_nested_from_seed(case.case_seed())),
        1 => probe_symbol(&oversized_from_seed(case.case_seed())),
        2 => probe_symbol(&reabstraction_thunk_from_seed(case.case_seed())),
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

fn assert_symbol_abstains_within(label: &str, mangled: &str, ceiling: Duration) {
    let start: std::time::Instant = std::time::Instant::now();
    let rendered: Result<String, _> = demangle::demangle(mangled);
    let elapsed: Duration = start.elapsed();
    assert!(
        rendered.is_err(),
        "{label} unexpectedly recovered {rendered:?}"
    );
    assert!(
        elapsed < ceiling,
        "{label} took {elapsed:?} to abstain, past the {ceiling:?} ceiling; the parser is no \
         longer bounded in the width of its input"
    );
}

#[test]
fn a_reabstraction_thunk_wider_than_the_depth_bound_abstains() {
    let mangled: String = reabstraction_thunk_of_width(MIN_NESTING_LEVELS);
    let rendered: Result<String, _> = demangle::demangle(&mangled);
    assert!(
        rendered.is_err(),
        "a reabstraction thunk carrying more implementation-type operands than MAX_DEPTH must \
         abstain, got {rendered:?}"
    );
}

#[test]
fn an_oversized_mangled_ctype_length_abstains_in_bounded_wall_clock_time() {
    assert_symbol_abstains_within(
        "mangled C type length at the natural-number ceiling",
        &reabstraction_thunk_with_mangled_ctype_length(u64::from(u32::MAX)),
        Duration::from_secs(1),
    );
    assert_symbol_abstains_within(
        "mangled C type length past the natural-number ceiling",
        &reabstraction_thunk_with_mangled_ctype_length(u64::MAX),
        Duration::from_secs(1),
    );
    assert_symbol_abstains_within(
        "mangled C type past the symbol end",
        &reabstraction_thunk_with_mangled_ctype_length(1 << 20),
        Duration::from_secs(1),
    );
}

#[test]
fn a_narrow_reabstraction_thunk_under_the_bound_still_recovers() {
    let mangled: String = reabstraction_thunk_of_width(4);
    let rendered: String = demangle::demangle(&mangled)
        .expect("a reabstraction thunk well under the parser bounds must still recover");
    assert_eq!(
        rendered,
        "reabstraction thunk helper from @callee_guaranteed (@unowned Swift.Int, @unowned \
         Swift.Int, @unowned Swift.Int, @unowned Swift.Int) -> () to @callee_guaranteed (@unowned \
         Swift.Int, @unowned Swift.Int, @unowned Swift.Int, @unowned Swift.Int) -> ()"
    );
}
