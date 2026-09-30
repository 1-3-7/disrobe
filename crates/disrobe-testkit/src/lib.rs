#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]

mod config;
mod corpus;
mod error;
mod isolate;
mod macros;
mod mutate;
mod prerequisite;
mod reach;
mod rng;
mod run;
mod tool;
mod wire;
mod workspace;

pub use config::{
    DEFAULT_BATCH_SIZE, DEFAULT_CASES_PER_INPUT, DEFAULT_MASTER_SEED, DEFAULT_STALL_BACKSTOP,
    SEED_ENV, StressConfig,
};
pub use corpus::{CheckFn, CorpusEntry, CorpusSource, StressCase};
pub use disrobe_tool_process::CommandSpec;
pub use error::{BatchFailure, BatchFailureReason, CulpritCase, StressError};
pub use isolate::{BATCH_ENV, WorkerTest, run_isolated, worker_main};
pub use mutate::{MutationKind, mutate};
pub use prerequisite::{Available, NOT_MEASURED_DIR, OPTIONAL_LIST, PrerequisiteError, require};
pub use reach::{ReachTally, SeedReach, ShapelessSeed};
pub use rng::XorShift64;
pub use run::run_cases;
pub use tool::{ToolError, ToolOutput, tool_output};
