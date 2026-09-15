use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::mutate::MutationKind;

#[derive(Debug)]
pub enum StressError {
    Io {
        context: String,
        source: std::io::Error,
    },
    SeedEnv {
        variable: &'static str,
        value: String,
    },
    Nested {
        variable: &'static str,
    },
    EmptyRun {
        corpus_entries: usize,
        cases_per_input: usize,
        batch_size: usize,
    },
    DuplicateCorpusEntry {
        name: String,
        first_index: usize,
        second_index: usize,
    },
    CorpusEntryTooLarge {
        entry: String,
        bytes: usize,
        limit: usize,
    },
    MutatedCaseTooLarge {
        entry: String,
        case_index: usize,
        case_seed: u64,
        bytes: usize,
        limit: usize,
    },
    SuiteBudgetExhausted {
        budget: Duration,
        elapsed: Duration,
        batches_completed: usize,
        sealed_cases: usize,
        total_cases: usize,
    },
    WorkerNotFound {
        filter: String,
        executable: PathBuf,
        listing: String,
    },
    Inconsistent {
        detail: String,
    },
    Batch(Box<BatchFailure>),
}

#[derive(Debug)]
pub struct BatchFailure {
    pub reason: BatchFailureReason,
    pub batch_index: usize,
    pub batch_cases: usize,
    pub completed_cases: usize,
    pub sealed_cases: Option<usize>,
    pub timed_out: bool,
    pub batch_timeout: Duration,
    pub child_status: String,
    pub child_success: bool,
    pub culprit: Option<CulpritCase>,
    pub retained_workspace: PathBuf,
    pub stderr_tail: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct CulpritCase {
    pub case_index: usize,
    pub batch_offset: usize,
    pub entry: String,
    pub case_seed: u64,
    pub mutation: MutationKind,
    pub byte_len: usize,
    pub bytes_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchFailureReason {
    SealMissing,
    SealTokenMismatch,
    SealCountMismatch,
    SealedThenFailed,
    WorkerIdentityMismatch,
    ProgressMalformed,
}

impl BatchFailureReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealMissing => "no seal was written",
            Self::SealTokenMismatch => "the seal carried a token from another run",
            Self::SealCountMismatch => "the seal counted a different number of cases",
            Self::SealedThenFailed => "every case sealed but the worker did not then exit cleanly",
            Self::WorkerIdentityMismatch => {
                "the worker that ran is not the one the parent aimed at"
            }
            Self::ProgressMalformed => "the progress record did not parse",
        }
    }

    #[must_use]
    pub const fn blames_a_single_case(self) -> bool {
        matches!(self, Self::SealMissing | Self::SealCountMismatch)
    }
}

impl fmt::Display for BatchFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for CulpritCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "case {} (batch offset {}) entry `{}` seed {:#018x} mutation {} len {}",
            self.case_index,
            self.batch_offset,
            self.entry,
            self.case_seed,
            self.mutation,
            self.byte_len
        )?;
        if let Some(path) = self.bytes_path.as_ref() {
            write!(formatter, ", bytes at {}", path.display())?;
        }
        Ok(())
    }
}

impl fmt::Display for BatchFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "batch {} of {} case(s) failed: {}",
            self.batch_index, self.batch_cases, self.reason
        )?;
        write!(
            formatter,
            "; {} case(s) completed before the record stopped",
            self.completed_cases
        )?;
        if let Some(sealed) = self.sealed_cases {
            write!(formatter, "; seal claimed {sealed} case(s)")?;
        }
        if self.timed_out {
            write!(
                formatter,
                "; the worker was killed after exceeding {:?}",
                self.batch_timeout
            )?;
        }
        write!(
            formatter,
            "; worker status {} (success {}, required for a pass but never sufficient on its own)",
            self.child_status, self.child_success
        )?;
        match self.culprit.as_ref() {
            Some(culprit) => write!(formatter, "; culprit {culprit}")?,
            None => formatter.write_str("; no single case could be blamed")?,
        }
        if !self.detail.is_empty() {
            write!(formatter, "; {}", self.detail)?;
        }
        write!(
            formatter,
            "; workspace retained at {}",
            self.retained_workspace.display()
        )?;
        if !self.stderr_tail.is_empty() {
            write!(formatter, "; worker stderr tail: {}", self.stderr_tail)?;
        }
        Ok(())
    }
}

impl fmt::Display for StressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::SeedEnv { variable, value } => write!(
                formatter,
                "{variable} must be a decimal or 0x-prefixed u64, got `{value}`"
            ),
            Self::Nested { variable } => write!(
                formatter,
                "{variable} is already set, so this process is a stress worker and must not start a nested run"
            ),
            Self::EmptyRun {
                corpus_entries,
                cases_per_input,
                batch_size,
            } => write!(
                formatter,
                "nothing would run: {corpus_entries} corpus entr(ies) x {cases_per_input} case(s) with batch size {batch_size}"
            ),
            Self::DuplicateCorpusEntry {
                name,
                first_index,
                second_index,
            } => write!(
                formatter,
                "corpus entries {first_index} and {second_index} are both named `{name}`, so a reported (entry, seed) pair would not identify one case"
            ),
            Self::CorpusEntryTooLarge {
                entry,
                bytes,
                limit,
            } => write!(
                formatter,
                "corpus entry `{entry}` is {bytes} bytes, over the {limit} byte corpus-entry limit that leaves a mutated case room to grow"
            ),
            Self::MutatedCaseTooLarge {
                entry,
                case_index,
                case_seed,
                bytes,
                limit,
            } => write!(
                formatter,
                "case {case_index} mutated from corpus entry `{entry}` with seed {case_seed:#018x} is {bytes} bytes, over the {limit} byte batch-wire limit"
            ),
            Self::SuiteBudgetExhausted {
                budget,
                elapsed,
                batches_completed,
                sealed_cases,
                total_cases,
            } => write!(
                formatter,
                "the whole-suite budget of {budget:?} ran out after {elapsed:?}: {batches_completed} batch(es) done, {sealed_cases} of {total_cases} case(s) sealed; raise suite_budget or lower cases_per_input"
            ),
            Self::WorkerNotFound {
                filter,
                executable,
                listing,
            } => write!(
                formatter,
                "no ignored test named `{filter}` exists in {}, so a run would have exercised nothing; listing was: {}",
                executable.display(),
                if listing.trim().is_empty() {
                    "<empty>"
                } else {
                    listing.trim()
                }
            ),
            Self::Inconsistent { detail } => {
                write!(formatter, "internal stress-plan inconsistency: {detail}")
            }
            Self::Batch(failure) => write!(formatter, "{failure}"),
        }
    }
}

impl std::error::Error for StressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<StressError> for std::io::Error {
    fn from(error: StressError) -> Self {
        Self::other(error.to_string())
    }
}

pub(crate) fn io_error(context: impl Into<String>, source: std::io::Error) -> StressError {
    StressError::Io {
        context: context.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::BatchFailureReason;

    #[test]
    fn only_a_record_that_stopped_partway_blames_a_single_case() {
        assert!(BatchFailureReason::SealMissing.blames_a_single_case());
        assert!(BatchFailureReason::SealCountMismatch.blames_a_single_case());
        assert!(!BatchFailureReason::SealTokenMismatch.blames_a_single_case());
        assert!(!BatchFailureReason::SealedThenFailed.blames_a_single_case());
        assert!(!BatchFailureReason::WorkerIdentityMismatch.blames_a_single_case());
        assert!(!BatchFailureReason::ProgressMalformed.blames_a_single_case());
    }

    #[test]
    fn every_reason_reads_as_a_distinct_sentence() {
        let reasons: [BatchFailureReason; 6] = [
            BatchFailureReason::SealMissing,
            BatchFailureReason::SealTokenMismatch,
            BatchFailureReason::SealCountMismatch,
            BatchFailureReason::SealedThenFailed,
            BatchFailureReason::WorkerIdentityMismatch,
            BatchFailureReason::ProgressMalformed,
        ];
        let mut seen: Vec<&str> = Vec::with_capacity(reasons.len());
        for reason in reasons {
            let text: &str = reason.as_str();
            assert!(!text.is_empty());
            assert!(!seen.contains(&text), "`{text}` is reported twice");
            seen.push(text);
        }
    }
}
