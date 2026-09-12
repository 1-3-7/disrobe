#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use disrobe_testkit::{
    CorpusEntry, MutationKind, StressCase, StressConfig, StressError, XorShift64, mutate, run_cases,
};

const FINGERPRINT_ENTRIES: usize = 4;
const FINGERPRINT_SEEDS: u64 = 256;
const EXPECTED_FINGERPRINT: u64 = 0x8D7A_A5B4_AE82_D5B7;

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::new()),
        CorpusEntry::new(
            "ascii",
            b"the quick brown fox jumps over the lazy dog".to_vec(),
        ),
        CorpusEntry::new("binary", (0u8..=255u8).collect::<Vec<u8>>()),
        CorpusEntry::new("newlines", b"a\nb\r\nc\n\n".to_vec()),
    ]
}

fn fold(accumulator: u64, bytes: &[u8]) -> u64 {
    let mut state: u64 = accumulator;
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
    state
}

fn fingerprint() -> u64 {
    let entries: Vec<CorpusEntry> = corpus();
    assert_eq!(entries.len(), FINGERPRINT_ENTRIES);
    let mut state: u64 = 0xCBF2_9CE4_8422_2325;
    for entry in &entries {
        state = fold(state, entry.name().as_bytes());
        for seed in 0..FINGERPRINT_SEEDS {
            let (bytes, kind): (Vec<u8>, MutationKind) = mutate(entry.bytes(), seed);
            state = fold(state, &bytes);
            state = fold(state, kind.as_str().as_bytes());
            state = fold(state, &bytes.len().to_le_bytes());
        }
    }
    state
}

#[test]
fn the_mutation_matrix_fingerprint_is_pinned_across_runs() {
    let observed: u64 = fingerprint();
    println!("determinism fingerprint {observed:#018x}");
    assert_eq!(
        observed, EXPECTED_FINGERPRINT,
        "the mutation matrix changed; a printed (corpus entry, case seed) pair no longer replays older reports"
    );
}

#[test]
fn a_second_pass_over_the_matrix_is_byte_identical() {
    assert_eq!(fingerprint(), fingerprint());
}

#[test]
fn a_single_reported_pair_replays_the_same_bytes() {
    let entries: Vec<CorpusEntry> = corpus();
    let entry: &CorpusEntry = entries
        .iter()
        .find(|entry: &&CorpusEntry| entry.name() == "binary")
        .expect("the binary entry exists");
    let config: StressConfig = StressConfig {
        cases_per_input: 8,
        master_seed: 0x0BAD_C0DE_0BAD_C0DE,
        ..StressConfig::default()
    };
    let reported_seed: u64 = config.case_seed(5);
    let (first, first_kind): (Vec<u8>, MutationKind) = mutate(entry.bytes(), reported_seed);
    let (second, second_kind): (Vec<u8>, MutationKind) = mutate(entry.bytes(), reported_seed);
    assert_eq!(first, second);
    assert_eq!(first_kind, second_kind);
    println!(
        "replayed entry `{}` seed {reported_seed:#018x} mutation {first_kind} into {} byte(s)",
        entry.name(),
        first.len()
    );
}

#[test]
fn a_stream_is_reproducible_from_its_seed_alone() {
    let mut left: XorShift64 = XorShift64::new(0);
    let mut right: XorShift64 = XorShift64::new(0);
    for _ in 0..4096 {
        assert_eq!(left.next_u64(), right.next_u64());
        assert_eq!(left.below(97), right.below(97));
    }
}

fn record(case: &StressCase<'_>) {
    let (replayed, kind): (Vec<u8>, MutationKind) = mutate(
        corpus()
            .iter()
            .find(|entry: &&CorpusEntry| entry.name() == case.entry())
            .expect("every case names a corpus entry")
            .bytes(),
        case.case_seed(),
    );
    assert_eq!(replayed, case.bytes());
    assert_eq!(kind, case.mutation());
}

#[test]
fn the_in_process_runner_hands_the_check_replayable_cases() {
    let config: StressConfig = StressConfig {
        cases_per_input: 16,
        master_seed: 0x1234_5678_9ABC_DEF0,
        batch_size: 4,
        case_budget: Duration::from_millis(500),
        suite_budget: Duration::from_secs(30),
    };
    let executed: usize = run_cases(&corpus(), &config, record).expect("no case panics");
    assert_eq!(executed, corpus().len() * 16);
}

#[test]
fn the_in_process_runner_refuses_an_empty_plan() {
    let outcome: Result<usize, StressError> =
        run_cases(&[], &StressConfig::default(), |_case: &StressCase<'_>| {});
    assert!(matches!(outcome, Err(StressError::EmptyRun { .. })));
}
