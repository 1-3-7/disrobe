#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    clippy::unwrap_used
)]

use std::time::Duration;

use disrobe_testkit::{
    BatchFailure, BatchFailureReason, CorpusEntry, CulpritCase, MutationKind, StressConfig,
    StressError, WorkerTest, mutate, run_isolated,
};

const CASES_PER_INPUT: usize = 3;
const BATCH_SIZE: usize = 8;
const MASTER_SEED: u64 = 0x5445_5354_4B49_5401;
const TOTAL_CASES: usize = 6;
const PATIENT_CASE_BUDGET: Duration = Duration::from_secs(4);
const IMPATIENT_CASE_BUDGET: Duration = Duration::from_millis(250);
const SUITE_BUDGET: Duration = Duration::from_mins(2);
const CLAMPING_SUITE_BUDGET: Duration = Duration::from_secs(2);

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("alpha", b"alpha structured seed bytes\n".to_vec()),
        CorpusEntry::new("beta", vec![0xA5u8; 48]),
    ]
}

const fn config(case_budget: Duration) -> StressConfig {
    StressConfig {
        cases_per_input: CASES_PER_INPUT,
        master_seed: MASTER_SEED,
        batch_size: BATCH_SIZE,
        case_budget,
        suite_budget: SUITE_BUDGET,
    }
}

fn expect_batch_failure(worker: &WorkerTest, case_budget: Duration) -> Box<BatchFailure> {
    expect_batch_failure_with(worker, &config(case_budget))
}

fn expect_batch_failure_with(worker: &WorkerTest, config: &StressConfig) -> Box<BatchFailure> {
    match run_isolated(&corpus(), config, worker) {
        Err(StressError::Batch(failure)) => failure,
        Err(other) => panic!("expected a batch failure, got {other}"),
        Ok(sealed) => panic!("the planted fault went undetected: {sealed} case(s) reported sealed"),
    }
}

fn discard_retained_workspace(failure: &BatchFailure) {
    assert!(
        failure.retained_workspace.is_dir(),
        "the harness did not retain {} for inspection",
        failure.retained_workspace.display()
    );
    std::fs::remove_dir_all(&failure.retained_workspace)
        .expect("the retained workspace is removable once the assertions are done");
}

fn checksum_only(case: &disrobe_testkit::StressCase<'_>) {
    let checksum: u64 = case.bytes().iter().map(|byte: &u8| u64::from(*byte)).sum();
    core::hint::black_box(checksum);
}

disrobe_testkit::stress_suite!(
    check: checksum_only,
    driven_by: a_parent_aimed_at_a_foreign_modules_worker_is_refused_rather_than_passed
);

mod nested {
    disrobe_testkit::stress_suite!(
        check: super::checksum_only,
        driven_by: super::a_correctly_aimed_nested_worker_still_seals_every_case
    );
}

mod completes_every_case {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        let checksum: u64 = case.bytes().iter().map(|byte: &u8| u64::from(*byte)).sum();
        core::hint::black_box(checksum);
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::a_worker_that_seals_every_case_is_the_only_way_to_pass
    );
}

mod aborts_after_sealing_every_case {
    #[test]
    #[ignore = "planted fault: seals every case and then aborts while the process tears down"]
    fn stress_worker() -> std::io::Result<()> {
        disrobe_testkit::worker_main(module_path!(), super::checksum_only)?;
        std::process::abort();
    }

    pub(crate) fn stress_worker_test() -> disrobe_testkit::WorkerTest {
        disrobe_testkit::WorkerTest::from_module_path(module_path!())
    }
}

mod aborts_at_case_two {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        if case.case_index() == 2 {
            std::process::abort();
        }
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::a_process_abort_is_detected_and_localized
    );
}

mod hangs_at_case_one {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        if case.case_index() == 1 {
            loop {
                core::hint::spin_loop();
            }
        }
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::an_infinite_loop_is_killed_and_localized
    );
}

mod panics_at_case_three {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        assert!(
            case.case_index() != 3,
            "planted panic while checking case {}",
            case.case_index()
        );
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::a_panic_partway_through_a_batch_is_detected_and_localized
    );
}

mod panics_at_case_four {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        assert!(
            case.case_index() != 4,
            "planted panic while checking case {}",
            case.case_index()
        );
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::the_reported_seed_replays_the_dumped_culprit_bytes
    );
}

mod replays_its_own_bytes {
    fn check(case: &disrobe_testkit::StressCase<'_>) {
        let entries: Vec<disrobe_testkit::CorpusEntry> = super::corpus();
        let entry: &disrobe_testkit::CorpusEntry = entries
            .iter()
            .find(|entry: &&disrobe_testkit::CorpusEntry| entry.name() == case.entry())
            .expect("every case names a corpus entry");
        let (replayed, kind): (Vec<u8>, disrobe_testkit::MutationKind) =
            disrobe_testkit::mutate(entry.bytes(), case.case_seed());
        assert_eq!(
            replayed,
            case.bytes(),
            "the batch did not carry the bytes the reported seed replays"
        );
        assert_eq!(kind, case.mutation());
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::the_worker_process_receives_exactly_the_bytes_its_seed_replays
    );
}

mod refuses_a_nested_run {
    fn check(_case: &disrobe_testkit::StressCase<'_>) {
        let unmatched: disrobe_testkit::WorkerTest =
            disrobe_testkit::WorkerTest::from_module_path("probe::no_such_module");
        let outcome: Result<usize, disrobe_testkit::StressError> = disrobe_testkit::run_isolated(
            &super::corpus(),
            &super::config(super::PATIENT_CASE_BUDGET),
            &unmatched,
        );
        assert!(
            matches!(outcome, Err(disrobe_testkit::StressError::Nested { .. })),
            "a worker must refuse a nested run before it reaches preflight"
        );
    }

    disrobe_testkit::stress_suite!(
        check: check,
        driven_by: super::a_worker_refuses_to_start_a_nested_run
    );
}

mod exits_without_sealing {
    #[test]
    #[ignore = "planted fault: reports success without recording a single case"]
    fn stress_worker() {}

    pub(crate) fn stress_worker_test() -> disrobe_testkit::WorkerTest {
        disrobe_testkit::WorkerTest::from_module_path(module_path!())
    }
}

mod forges_a_seal_with_a_stale_token {
    use std::io::Write as _;
    use std::path::PathBuf;

    #[test]
    #[ignore = "planted fault: plants a seal carrying a token from another run"]
    fn stress_worker() -> std::io::Result<()> {
        let raw: std::ffi::OsString = std::env::var_os(disrobe_testkit::BATCH_ENV)
            .expect("the harness always sets the batch path");
        let batch_path: PathBuf = PathBuf::from(raw);
        let batch: Vec<u8> = std::fs::read(&batch_path)?;
        let token: u64 = u64::from_le_bytes(
            batch
                .get(8..16)
                .and_then(|slice: &[u8]| slice.try_into().ok())
                .expect("the batch header carries a token"),
        );
        let declared: u32 = u32::from_le_bytes(
            batch
                .get(16..20)
                .and_then(|slice: &[u8]| slice.try_into().ok())
                .expect("the batch header carries a case count"),
        );
        let count: usize = usize::try_from(declared).expect("the case count fits usize");
        let progress_path: PathBuf =
            PathBuf::from(format!("{}.progress", batch_path.to_string_lossy()));
        let mut progress: std::fs::File = std::fs::File::create(progress_path)?;
        for offset in 0..count {
            writeln!(progress, "case {offset}")?;
        }
        writeln!(progress, "seal {:016x} {count}", token ^ 1)?;
        Ok(())
    }

    pub(crate) fn stress_worker_test() -> disrobe_testkit::WorkerTest {
        disrobe_testkit::WorkerTest::from_module_path(module_path!())
    }
}

#[test]
fn a_worker_that_seals_every_case_is_the_only_way_to_pass() {
    let sealed: usize = run_isolated(
        &corpus(),
        &config(PATIENT_CASE_BUDGET),
        &completes_every_case::stress_worker_test(),
    )
    .expect("a worker that completes and seals every case must pass");
    assert_eq!(sealed, TOTAL_CASES);
}

#[test]
fn a_process_abort_is_detected_and_localized() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &aborts_at_case_two::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealMissing);
    assert!(!failure.timed_out, "an abort is not a timeout: {failure}");
    assert!(!failure.child_success, "an aborted worker cannot exit zero");
    assert_eq!(failure.completed_cases, 2);
    let culprit: &CulpritCase = failure.culprit.as_ref().expect("an abort blames one case");
    assert_eq!(culprit.case_index, 2);
    assert_eq!(culprit.batch_offset, 2);
    assert!(
        culprit
            .bytes_path
            .as_ref()
            .is_some_and(|path| path.is_file())
    );
    discard_retained_workspace(&failure);
}

#[test]
fn an_infinite_loop_is_killed_and_localized() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &hangs_at_case_one::stress_worker_test(),
        IMPATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealMissing);
    assert!(failure.timed_out, "the watchdog did not fire: {failure}");
    assert!(!failure.child_success, "a killed worker cannot exit zero");
    assert_eq!(failure.completed_cases, 1);
    let culprit: &CulpritCase = failure.culprit.as_ref().expect("a hang blames one case");
    assert_eq!(culprit.case_index, 1);
    assert!(
        culprit
            .bytes_path
            .as_ref()
            .is_some_and(|path| path.is_file())
    );
    discard_retained_workspace(&failure);
}

#[test]
fn a_panic_partway_through_a_batch_is_detected_and_localized() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &panics_at_case_three::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealMissing);
    assert!(!failure.timed_out, "a panic is not a timeout: {failure}");
    assert!(
        !failure.child_success,
        "a panicking worker cannot exit zero"
    );
    assert_eq!(failure.completed_cases, 3);
    let culprit: &CulpritCase = failure.culprit.as_ref().expect("a panic blames one case");
    assert_eq!(culprit.case_index, 3);
    assert!(
        failure
            .stderr_tail
            .contains("planted panic while checking case 3"),
        "the worker stderr was not carried back: {failure}"
    );
    discard_retained_workspace(&failure);
}

#[test]
fn a_worker_that_exits_zero_without_sealing_is_still_a_failure() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &exits_without_sealing::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealMissing);
    assert!(
        failure.child_success,
        "this planted fault exits zero on purpose: {failure}"
    );
    assert!(!failure.timed_out);
    assert_eq!(failure.completed_cases, 0);
    assert_eq!(failure.sealed_cases, None);
    let culprit: &CulpritCase = failure
        .culprit
        .as_ref()
        .expect("the first case is blamed when nothing was recorded");
    assert_eq!(culprit.case_index, 0);
    discard_retained_workspace(&failure);
}

#[test]
fn a_seal_carrying_another_runs_token_is_rejected() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &forges_a_seal_with_a_stale_token::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealTokenMismatch);
    assert!(
        failure.child_success,
        "this planted fault exits zero on purpose: {failure}"
    );
    assert_eq!(failure.completed_cases, TOTAL_CASES);
    assert_eq!(failure.sealed_cases, Some(TOTAL_CASES));
    assert!(
        failure.culprit.is_none(),
        "a stale seal cannot blame a single case"
    );
    discard_retained_workspace(&failure);
}

#[test]
fn a_filter_matching_no_test_fails_before_any_batch_runs() {
    let worker: WorkerTest =
        WorkerTest::from_module_path("planted_faults::renamed_since_the_filter_was_written");
    let error: StressError = run_isolated(&corpus(), &config(PATIENT_CASE_BUDGET), &worker)
        .expect_err("a filter matching no test must fail loudly");
    println!("disrobe-testkit: {error}");
    match error {
        StressError::WorkerNotFound { filter, .. } => {
            assert_eq!(
                filter,
                "renamed_since_the_filter_was_written::stress_worker"
            );
        }
        other => panic!("expected a zero-match preflight failure, got {other}"),
    }
}

#[test]
fn the_reported_seed_replays_the_dumped_culprit_bytes() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &panics_at_case_four::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    let culprit: &CulpritCase = failure.culprit.as_ref().expect("a panic blames one case");
    assert_eq!(culprit.case_index, 4);
    let bytes_path: &std::path::Path = culprit
        .bytes_path
        .as_deref()
        .expect("the harness dumps the offending bytes");
    let dumped: Vec<u8> = std::fs::read(bytes_path).expect("the dumped bytes are readable");
    let entry: CorpusEntry = corpus()
        .into_iter()
        .find(|entry: &CorpusEntry| entry.name() == culprit.entry)
        .expect("the blamed entry is a corpus entry");
    let (replayed, kind): (Vec<u8>, MutationKind) = mutate(entry.bytes(), culprit.case_seed);
    assert_eq!(
        replayed, dumped,
        "the reported (entry, seed) pair did not reproduce the failing bytes"
    );
    assert_eq!(kind, culprit.mutation);
    assert_eq!(dumped.len(), culprit.byte_len);
    discard_retained_workspace(&failure);
}

#[test]
fn the_worker_process_receives_exactly_the_bytes_its_seed_replays() {
    let sealed: usize = run_isolated(
        &corpus(),
        &config(PATIENT_CASE_BUDGET),
        &replays_its_own_bytes::stress_worker_test(),
    )
    .expect("a separate process must rebuild every case from its seed alone");
    assert_eq!(sealed, TOTAL_CASES);
}

#[test]
fn a_worker_refuses_to_start_a_nested_run() {
    let sealed: usize = run_isolated(
        &corpus(),
        &config(PATIENT_CASE_BUDGET),
        &refuses_a_nested_run::stress_worker_test(),
    )
    .expect("the nested-run probe runs inside the worker and must seal every case");
    assert_eq!(sealed, TOTAL_CASES);
}

#[test]
fn an_empty_plan_is_refused_rather_than_reported_green() {
    let empty_corpus: Result<usize, StressError> = run_isolated(
        &[],
        &config(PATIENT_CASE_BUDGET),
        &completes_every_case::stress_worker_test(),
    );
    assert!(matches!(
        empty_corpus,
        Err(StressError::EmptyRun {
            corpus_entries: 0,
            ..
        })
    ));
    let zero_cases: Result<usize, StressError> = run_isolated(
        &corpus(),
        &StressConfig {
            cases_per_input: 0,
            ..config(PATIENT_CASE_BUDGET)
        },
        &completes_every_case::stress_worker_test(),
    );
    assert!(matches!(
        zero_cases,
        Err(StressError::EmptyRun {
            cases_per_input: 0,
            ..
        })
    ));
}

#[test]
fn a_worker_that_seals_every_case_and_then_aborts_is_not_reported_green() {
    let failure: Box<BatchFailure> = expect_batch_failure(
        &aborts_after_sealing_every_case::stress_worker_test(),
        PATIENT_CASE_BUDGET,
    );
    assert_eq!(failure.reason, BatchFailureReason::SealedThenFailed);
    assert!(
        !failure.child_success,
        "an aborted worker cannot exit zero: {failure}"
    );
    assert!(!failure.timed_out, "an abort is not a timeout: {failure}");
    assert_eq!(failure.completed_cases, TOTAL_CASES);
    assert_eq!(failure.sealed_cases, Some(TOTAL_CASES));
    assert!(
        failure.culprit.is_none(),
        "a fault after the last seal cannot be pinned on one case: {failure}"
    );
    discard_retained_workspace(&failure);
}

#[test]
fn a_parent_aimed_at_a_foreign_modules_worker_is_refused_rather_than_passed() {
    assert_eq!(
        nested::stress_worker_test().filter(),
        "nested::stress_worker"
    );
    let mistargeted: WorkerTest = WorkerTest::from_module_path("nested");
    assert_eq!(
        mistargeted.filter(),
        stress_worker_test().filter(),
        "a bare module name must collapse onto the crate-root worker for this probe to mean anything"
    );

    let failure: Box<BatchFailure> = expect_batch_failure(&mistargeted, PATIENT_CASE_BUDGET);
    assert_eq!(failure.reason, BatchFailureReason::WorkerIdentityMismatch);
    assert!(
        failure.child_success,
        "the foreign worker itself ran cleanly: {failure}"
    );
    assert_eq!(failure.completed_cases, TOTAL_CASES);
    assert_eq!(failure.sealed_cases, Some(TOTAL_CASES));
    assert!(
        failure.culprit.is_none(),
        "a mistargeted parent cannot blame a single case: {failure}"
    );
    assert!(
        failure.detail.contains("planted_faults"),
        "the module the worker recorded is not reported: {failure}"
    );
    discard_retained_workspace(&failure);
}

#[test]
fn a_correctly_aimed_nested_worker_still_seals_every_case() {
    let sealed: usize = run_isolated(
        &corpus(),
        &config(PATIENT_CASE_BUDGET),
        &nested::stress_worker_test(),
    )
    .expect("a worker aimed at its own module must pass");
    assert_eq!(sealed, TOTAL_CASES);
}

#[test]
fn an_exhausted_suite_budget_stops_the_run_before_a_batch_starts() {
    let starved: StressConfig = StressConfig {
        suite_budget: Duration::ZERO,
        ..config(PATIENT_CASE_BUDGET)
    };
    match run_isolated(
        &corpus(),
        &starved,
        &completes_every_case::stress_worker_test(),
    ) {
        Err(StressError::SuiteBudgetExhausted {
            budget,
            batches_completed,
            sealed_cases,
            total_cases,
            ..
        }) => {
            assert_eq!(budget, Duration::ZERO);
            assert_eq!(batches_completed, 0);
            assert_eq!(sealed_cases, 0);
            assert_eq!(total_cases, TOTAL_CASES);
        }
        other => panic!("a zero suite budget must refuse the run, got {other:?}"),
    }
}

#[test]
fn a_batch_killed_by_the_suite_deadline_names_the_suite_budget() {
    let clamped: StressConfig = StressConfig {
        suite_budget: CLAMPING_SUITE_BUDGET,
        ..config(PATIENT_CASE_BUDGET)
    };
    assert!(
        clamped.batch_timeout() > CLAMPING_SUITE_BUDGET,
        "this probe needs the suite budget to be the tighter of the two limits"
    );
    match run_isolated(
        &corpus(),
        &clamped,
        &hangs_at_case_one::stress_worker_test(),
    ) {
        Err(StressError::SuiteBudgetExhausted {
            budget, elapsed, ..
        }) => {
            assert_eq!(budget, CLAMPING_SUITE_BUDGET);
            assert!(
                elapsed >= CLAMPING_SUITE_BUDGET,
                "the run stopped after {elapsed:?}, before its {CLAMPING_SUITE_BUDGET:?} budget"
            );
        }
        other => {
            panic!(
                "a batch killed by the suite deadline must not read as a per-case hang: {other:?}"
            )
        }
    }
}

#[test]
fn a_duplicate_corpus_name_is_refused_before_any_case_runs() {
    let ambiguous: Vec<CorpusEntry> = vec![
        CorpusEntry::new("same", b"first".to_vec()),
        CorpusEntry::new("same", b"second".to_vec()),
    ];
    match run_isolated(
        &ambiguous,
        &config(PATIENT_CASE_BUDGET),
        &completes_every_case::stress_worker_test(),
    ) {
        Err(StressError::DuplicateCorpusEntry { name, .. }) => assert_eq!(name, "same"),
        other => panic!("a duplicate corpus name must be refused, got {other:?}"),
    }
}
