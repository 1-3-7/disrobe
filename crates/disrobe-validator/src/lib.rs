#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
pub mod corpus;
pub mod metrics;
pub mod report;
pub mod runner;

pub use corpus::{CorpusEntry, CorpusKind, walk_corpus};
pub use metrics::{PassMetrics, SampleMetrics, aggregate};
pub use report::{ValidationReport, build_report};
pub use runner::{RunOutcome, run_sample};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
