#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]

mod config;
mod corpus;
mod error;
mod isolate;
mod macros;
mod mutate;
mod reach;
mod rng;
mod run;
mod wire;
mod workspace;

pub use config::{
    BATCH_STARTUP_OVERHEAD, DEFAULT_BATCH_SIZE, DEFAULT_CASE_BUDGET, DEFAULT_CASES_PER_INPUT,
    DEFAULT_MASTER_SEED, DEFAULT_SUITE_BUDGET, SEED_ENV, StressConfig,
};
pub use corpus::{CheckFn, CorpusEntry, CorpusSource, StressCase};
pub use error::{BatchFailure, BatchFailureReason, CulpritCase, StressError};
pub use isolate::{BATCH_ENV, WorkerTest, run_isolated, worker_main};
pub use mutate::{MutationKind, mutate};
pub use reach::{ReachTally, SeedReach, ShapelessSeed};
pub use rng::XorShift64;
pub use run::run_cases;
