#![forbid(unsafe_code)]

mod config;
mod engine;
mod report;

pub use config::TaintConfig;
pub use engine::analyze;
pub use report::{TaintFinding, TaintReport, TaintStep};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
