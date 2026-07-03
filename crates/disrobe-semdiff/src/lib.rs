#![forbid(unsafe_code)]

mod diff;

pub use diff::{ChangeKind, FunctionChange, SemanticDiff, diff};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
