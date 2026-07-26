use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use crate::config::{StressConfig, print_banner};
use crate::corpus::{
    CheckFn, CorpusEntry, StressCase, entry_for_case, ordered_indices, validate_corpus,
};
use crate::error::{BatchFailure, BatchFailureReason, CulpritCase, StressError, io_error};
use crate::mutate::{MutationKind, mutate};
use crate::wire::{
    Batch, BatchRecord, Progress, case_line, module_line, parse_progress, progress_path,
    read_batch, seal_line, write_batch,
};
use crate::workspace::Workspace;

pub const WORKER_FN_NAME: &str = "stress_worker";
pub const BATCH_ENV: &str = "DISROBE_STRESS_BATCH";

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const STDERR_TAIL_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTest {
    module_path: String,
    filter: String,
}

impl WorkerTest {
    #[must_use]
    pub fn from_module_path(module_path: &str) -> Self {
        let suffix: &str = module_path
            .split_once("::")
            .map_or("", |(_, rest): (&str, &str)| rest);
        let filter: String = if suffix.is_empty() {
            WORKER_FN_NAME.to_owned()
        } else {
            format!("{suffix}::{WORKER_FN_NAME}")
        };
        Self {
            module_path: module_path.to_owned(),
            filter,
        }
    }

    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    #[must_use]
    pub fn module_path(&self) -> &str {
        &self.module_path
    }
}

impl fmt::Display for WorkerTest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.filter)
    }
}

#[derive(Debug)]
struct BatchOutcome {
    status: ExitStatus,
    timed_out: bool,
}

#[derive(Debug)]
struct BatchContext<'a> {
    batch_index: usize,
    token: u64,
    expected_module: &'a str,
    records: &'a [BatchRecord],
    batch_path: &'a Path,
    stderr_path: &'a Path,
    workspace_path: &'a Path,
    batch_timeout: Duration,
}

pub fn run_isolated(
    corpus: &[CorpusEntry],
    config: &StressConfig,
    worker: &WorkerTest,
) -> Result<usize, StressError> {
    if std::env::var_os(BATCH_ENV).is_some() {
        return Err(StressError::Nested {
            variable: BATCH_ENV,
        });
    }
    let config: StressConfig = config.with_seed_from_env()?;
    validate_corpus(corpus)?;
    let order: Vec<usize> = ordered_indices(corpus);
    let total: usize = config.total_cases(order.len());
    if total == 0 || config.batch_size == 0 {
        return Err(StressError::EmptyRun {
            corpus_entries: order.len(),
            cases_per_input: config.cases_per_input,
            batch_size: config.batch_size,
        });
    }
    print_banner(&config, order.len(), total, Some(worker.filter()));
    let executable: PathBuf = std::env::current_exe()
        .map_err(|error: std::io::Error| io_error("locating the running test binary", error))?;
    preflight(&executable, worker)?;
    let mut workspace: Workspace = Workspace::create()?;
    let outcome: Result<usize, StressError> = run_batches(
        &workspace,
        &executable,
        worker,
        corpus,
        &order,
        &config,
        total,
    );
    if let Err(StressError::Batch(failure)) = &outcome {
        eprintln!("disrobe-testkit: {failure}");
        workspace.retain();
    }
    outcome
}

fn run_batches(
    workspace: &Workspace,
    executable: &Path,
    worker: &WorkerTest,
    corpus: &[CorpusEntry],
    order: &[usize],
    config: &StressConfig,
    total: usize,
) -> Result<usize, StressError> {
    let suite_started: Instant = Instant::now();
    let configured_timeout: Duration = config.batch_timeout();
    let mut sealed_total: usize = 0;
    let mut batch_index: usize = 0;
    let mut next_case: usize = 0;
    while next_case < total {
        let remaining: Duration = config.suite_budget.saturating_sub(suite_started.elapsed());
        if remaining.is_zero() {
            return Err(suite_budget_exhausted(
                config,
                suite_started,
                batch_index,
                sealed_total,
                total,
            ));
        }
        let batch_timeout: Duration = configured_timeout.min(remaining);
        let batch_end: usize = next_case.saturating_add(config.batch_size).min(total);
        let records: Vec<BatchRecord> = build_records(corpus, order, config, next_case, batch_end)?;
        let batch_path: PathBuf = workspace.path.join(format!("batch-{batch_index}.bin"));
        let stderr_path: PathBuf = workspace.path.join(format!("stderr-{batch_index}.log"));
        write_batch(&batch_path, workspace.token, &records)?;
        let outcome: BatchOutcome =
            execute_batch(executable, worker, &batch_path, &stderr_path, batch_timeout)?;
        if outcome.timed_out && batch_timeout < configured_timeout {
            return Err(suite_budget_exhausted(
                config,
                suite_started,
                batch_index,
                sealed_total,
                total,
            ));
        }
        let context: BatchContext<'_> = BatchContext {
            batch_index,
            token: workspace.token,
            expected_module: worker.module_path(),
            records: &records,
            batch_path: &batch_path,
            stderr_path: &stderr_path,
            workspace_path: &workspace.path,
            batch_timeout,
        };
        sealed_total = sealed_total
            .saturating_add(evaluate_batch(&context, &outcome).map_err(StressError::Batch)?);
        next_case = batch_end;
        batch_index = batch_index.saturating_add(1);
    }
    Ok(sealed_total)
}

fn suite_budget_exhausted(
    config: &StressConfig,
    suite_started: Instant,
    batches_completed: usize,
    sealed_cases: usize,
    total_cases: usize,
) -> StressError {
    StressError::SuiteBudgetExhausted {
        budget: config.suite_budget,
        elapsed: suite_started.elapsed(),
        batches_completed,
        sealed_cases,
        total_cases,
    }
}

fn build_records(
    corpus: &[CorpusEntry],
    order: &[usize],
    config: &StressConfig,
    from_case: usize,
    to_case: usize,
) -> Result<Vec<BatchRecord>, StressError> {
    let mut records: Vec<BatchRecord> = Vec::with_capacity(to_case.saturating_sub(from_case));
    for case_index in from_case..to_case {
        let entry: &CorpusEntry =
            entry_for_case(corpus, order, config.cases_per_input, case_index)?;
        let case_seed: u64 = config.case_seed(case_index);
        let (bytes, mutation): (Vec<u8>, MutationKind) = mutate(entry.bytes(), case_seed);
        records.push(BatchRecord {
            case_index,
            case_seed,
            mutation,
            entry: entry.name().to_owned(),
            bytes,
        });
    }
    Ok(records)
}

fn preflight(executable: &Path, worker: &WorkerTest) -> Result<(), StressError> {
    let output: Output = Command::new(executable)
        .args(["--list", "--ignored", "--exact", worker.filter()])
        .env_remove(BATCH_ENV)
        .stdin(Stdio::null())
        .output()
        .map_err(|error: std::io::Error| {
            io_error(
                format!("listing tests of {} for preflight", executable.display()),
                error,
            )
        })?;
    let listing: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let expected: String = format!("{}: test", worker.filter());
    if listing
        .lines()
        .any(|line: &str| line.trim() == expected.as_str())
    {
        return Ok(());
    }
    Err(StressError::WorkerNotFound {
        filter: worker.filter().to_owned(),
        executable: executable.to_path_buf(),
        listing,
    })
}

fn execute_batch(
    executable: &Path,
    worker: &WorkerTest,
    batch_path: &Path,
    stderr_path: &Path,
    batch_timeout: Duration,
) -> Result<BatchOutcome, StressError> {
    let stderr_file: File = File::create(stderr_path).map_err(|error: std::io::Error| {
        io_error(
            format!("creating worker stderr log {}", stderr_path.display()),
            error,
        )
    })?;
    let mut child: Child = Command::new(executable)
        .args(["--ignored", "--exact", worker.filter(), "--nocapture"])
        .env(BATCH_ENV, batch_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|error: std::io::Error| {
            io_error(format!("spawning stress worker {}", worker.filter()), error)
        })?;
    let started: Instant = Instant::now();
    loop {
        let waited: Option<ExitStatus> = child
            .try_wait()
            .map_err(|error: std::io::Error| io_error("polling the stress worker", error))?;
        if let Some(status) = waited {
            return Ok(BatchOutcome {
                status,
                timed_out: false,
            });
        }
        if started.elapsed() > batch_timeout {
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(io_error("killing the stress worker", error)),
            }
            let status: ExitStatus = child
                .wait()
                .map_err(|error: std::io::Error| io_error("reaping the stress worker", error))?;
            return Ok(BatchOutcome {
                status,
                timed_out: true,
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn evaluate_batch(
    context: &BatchContext<'_>,
    outcome: &BatchOutcome,
) -> Result<usize, Box<BatchFailure>> {
    let record: String = std::fs::read_to_string(progress_path(context.batch_path))
        .unwrap_or_else(|_| String::new());
    let progress: Progress = parse_progress(&record);
    let (reason, completed, sealed_cases, detail): (
        BatchFailureReason,
        usize,
        Option<usize>,
        String,
    ) = match progress {
        Progress::Sealed {
            module,
            token,
            sealed_cases,
            completed,
        } => {
            if token != context.token {
                (
                    BatchFailureReason::SealTokenMismatch,
                    completed,
                    Some(sealed_cases),
                    format!(
                        "seal token {token:016x} does not match this run's {:016x}",
                        context.token
                    ),
                )
            } else if sealed_cases != context.records.len() || completed != context.records.len() {
                (
                    BatchFailureReason::SealCountMismatch,
                    completed,
                    Some(sealed_cases),
                    String::new(),
                )
            } else if let Some(mismatch) =
                module_mismatch(context.expected_module, module.as_deref())
            {
                (
                    BatchFailureReason::WorkerIdentityMismatch,
                    completed,
                    Some(sealed_cases),
                    mismatch,
                )
            } else if !outcome.status.success() || outcome.timed_out {
                (
                    BatchFailureReason::SealedThenFailed,
                    completed,
                    Some(sealed_cases),
                    "the record is complete, so the fault landed after the last case: process teardown, a detached thread, an exit handler, or the watchdog".to_owned(),
                )
            } else {
                return Ok(context.records.len());
            }
        }
        Progress::Unsealed { module, completed } => module
            .as_deref()
            .and_then(|recorded: &str| module_mismatch(context.expected_module, Some(recorded)))
            .map_or_else(
                || {
                    (
                        BatchFailureReason::SealMissing,
                        completed,
                        None,
                        String::new(),
                    )
                },
                |mismatch: String| {
                    (
                        BatchFailureReason::WorkerIdentityMismatch,
                        completed,
                        None,
                        mismatch,
                    )
                },
            ),
        Progress::Malformed { detail, completed } => (
            BatchFailureReason::ProgressMalformed,
            completed,
            None,
            detail,
        ),
    };
    Err(Box::new(BatchFailure {
        reason,
        batch_index: context.batch_index,
        batch_cases: context.records.len(),
        completed_cases: completed,
        sealed_cases,
        timed_out: outcome.timed_out,
        batch_timeout: context.batch_timeout,
        child_status: outcome.status.to_string(),
        child_success: outcome.status.success(),
        culprit: blame_case(context, reason, completed),
        retained_workspace: context.workspace_path.to_path_buf(),
        stderr_tail: read_stderr_tail(context.stderr_path),
        detail,
    }))
}

fn module_mismatch(expected: &str, recorded: Option<&str>) -> Option<String> {
    if recorded == Some(expected) {
        return None;
    }
    Some(format!(
        "the worker recorded module `{}` where the parent aimed at `{expected}`, so the test filter drove a different suite",
        recorded.unwrap_or("<none>")
    ))
}

fn blame_case(
    context: &BatchContext<'_>,
    reason: BatchFailureReason,
    completed: usize,
) -> Option<CulpritCase> {
    if !reason.blames_a_single_case() {
        return None;
    }
    let record: &BatchRecord = context.records.get(completed)?;
    let bytes_path: PathBuf = context.workspace_path.join(format!(
        "culprit-batch{}-case{}.bin",
        context.batch_index, record.case_index
    ));
    let dumped: Option<PathBuf> = match std::fs::write(&bytes_path, &record.bytes) {
        Ok(()) => Some(bytes_path),
        Err(_) => None,
    };
    Some(CulpritCase {
        case_index: record.case_index,
        batch_offset: completed,
        entry: record.entry.clone(),
        case_seed: record.case_seed,
        mutation: record.mutation,
        byte_len: record.bytes.len(),
        bytes_path: dumped,
    })
}

fn read_stderr_tail(path: &Path) -> String {
    let Ok(mut file): std::io::Result<File> = File::open(path) else {
        return String::new();
    };
    let mut raw: Vec<u8> = Vec::new();
    if file.read_to_end(&mut raw).is_err() {
        return String::new();
    }
    let start: usize = raw.len().saturating_sub(STDERR_TAIL_BYTES);
    let tail: &[u8] = raw.get(start..).unwrap_or(&raw);
    String::from_utf8_lossy(tail)
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .collect::<Vec<&str>>()
        .join(" | ")
}

pub fn worker_main(module_path: &str, check: CheckFn) -> std::io::Result<()> {
    if module_path.split_ascii_whitespace().count() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("`{module_path}` is not a single-token module path and cannot be recorded"),
        ));
    }
    let Some(raw): Option<std::ffi::OsString> = std::env::var_os(BATCH_ENV) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{BATCH_ENV} is unset, so this worker was not started by the stress harness and has nothing to run"
            ),
        ));
    };
    let batch_path: PathBuf = PathBuf::from(raw);
    let batch: Batch = read_batch(&batch_path)?;
    let mut progress: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(progress_path(&batch_path))?;
    progress.write_all(module_line(module_path).as_bytes())?;
    progress.flush()?;
    for (batch_offset, record) in batch.records.iter().enumerate() {
        let case: StressCase<'_> = StressCase::new(
            record.entry.as_str(),
            record.case_index,
            record.case_seed,
            record.mutation,
            &record.bytes,
        );
        check(&case);
        progress.write_all(case_line(batch_offset).as_bytes())?;
        progress.flush()?;
    }
    progress.write_all(seal_line(batch.token, batch.records.len()).as_bytes())?;
    progress.flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{WORKER_FN_NAME, WorkerTest, module_mismatch, worker_main};
    use crate::corpus::StressCase;

    fn ignores_every_case(_case: &StressCase<'_>) {}

    #[test]
    fn a_module_path_carrying_whitespace_is_refused_before_anything_is_recorded() {
        for path in ["", " ", "suite::worker extra"] {
            let refusal: std::io::Error = worker_main(path, ignores_every_case)
                .expect_err("a module path that would corrupt the record must be refused");
            assert_eq!(refusal.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                refusal.to_string().contains("single-token module path"),
                "unexpected refusal: {refusal}"
            );
        }
    }

    #[test]
    fn a_root_module_path_yields_the_bare_worker_name() {
        assert_eq!(
            WorkerTest::from_module_path("planted_faults").filter(),
            WORKER_FN_NAME
        );
    }

    #[test]
    fn a_worker_test_keeps_the_module_it_aims_at_alongside_its_filter() {
        let worker: WorkerTest = WorkerTest::from_module_path("planted_faults::nested");
        assert_eq!(worker.module_path(), "planted_faults::nested");
        assert_eq!(worker.filter(), "nested::stress_worker");
    }

    #[test]
    fn a_bare_module_name_collapses_the_filter_but_keeps_its_own_identity() {
        let worker: WorkerTest = WorkerTest::from_module_path("nested");
        assert_eq!(worker.filter(), WORKER_FN_NAME);
        assert_eq!(worker.module_path(), "nested");
    }

    #[test]
    fn a_recorded_module_only_matches_the_module_it_equals() {
        assert!(module_mismatch("suite::worker", Some("suite::worker")).is_none());
        assert!(module_mismatch("suite::worker", Some("suite::other")).is_some());
        assert!(module_mismatch("suite::worker", None).is_some());
    }

    #[test]
    fn a_nested_module_path_keeps_every_segment_below_the_crate() {
        assert_eq!(
            WorkerTest::from_module_path("planted_faults::aborts::deeper").filter(),
            "aborts::deeper::stress_worker"
        );
    }

    #[test]
    fn an_empty_module_path_still_yields_a_usable_filter() {
        assert_eq!(WorkerTest::from_module_path("").filter(), WORKER_FN_NAME);
    }

    #[test]
    fn the_emitted_filter_matches_this_modules_worker_name() {
        assert_eq!(
            WorkerTest::from_module_path(module_path!()).filter(),
            "isolate::tests::stress_worker"
        );
    }
}
