mod host_table;
mod optable;
pub(crate) mod reinline;

pub use host_table::{
    HostBinding, HostOpTable, HostOperator, HostTableReinline, MAX_HOST_ENTRIES,
    MAX_HOST_SCRIPT_BYTES, parse_host_table, reinline_host_table,
};
pub use optable::{WobfuscatorTable, extract_optable, lift_op_to_rust_fn};
pub(crate) use reinline::op_for_import_name;
pub use reinline::{ReinlineStats, reinline_imported_ops};
