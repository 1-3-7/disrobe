use std::panic::AssertUnwindSafe;

use crate::config::{StressConfig, print_banner};
use crate::corpus::{
    CheckFn, CorpusEntry, StressCase, entry_for_case, ordered_indices, validate_corpus,
};
use crate::error::StressError;
use crate::mutate::{MutationKind, mutate};

pub fn run_cases(
    corpus: &[CorpusEntry],
    config: &StressConfig,
    check: CheckFn,
) -> Result<usize, StressError> {
    let config: StressConfig = config.with_seed_from_env()?;
    validate_corpus(corpus)?;
    let order: Vec<usize> = ordered_indices(corpus);
    let total: usize = config.total_cases(order.len());
    if total == 0 {
        return Err(StressError::EmptyRun {
            corpus_entries: order.len(),
            cases_per_input: config.cases_per_input,
            batch_size: config.batch_size,
        });
    }
    print_banner(&config, order.len(), total, None);
    for case_index in 0..total {
        let entry: &CorpusEntry =
            entry_for_case(corpus, &order, config.cases_per_input, case_index)?;
        let case_seed: u64 = config.case_seed(case_index);
        let (bytes, mutation): (Vec<u8>, MutationKind) = mutate(entry.bytes(), case_seed);
        let case: StressCase<'_> =
            StressCase::new(entry.name(), case_index, case_seed, mutation, &bytes);
        let outcome: std::thread::Result<()> =
            std::panic::catch_unwind(AssertUnwindSafe(|| check(&case)));
        if let Err(payload) = outcome {
            eprintln!(
                "disrobe-testkit: case {case_index} panicked; replay with {}",
                case.replay_hint()
            );
            std::panic::resume_unwind(payload);
        }
    }
    Ok(total)
}
