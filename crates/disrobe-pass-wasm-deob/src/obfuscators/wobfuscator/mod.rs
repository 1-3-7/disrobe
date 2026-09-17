mod optable;
mod reinline;

pub use optable::{WobfuscatorTable, extract_optable, lift_op_to_rust_fn};
pub use reinline::{ReinlineStats, reinline_imported_ops};
