mod optable;
pub(crate) mod reinline;

pub use optable::{WobfuscatorTable, extract_optable, lift_op_to_rust_fn};
pub(crate) use reinline::op_for_import_name;
pub use reinline::{ReinlineStats, reinline_imported_ops};
