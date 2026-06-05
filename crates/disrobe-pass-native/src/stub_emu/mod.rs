#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unnecessary_cast,
    clippy::useless_conversion,
    clippy::int_plus_one,
    clippy::no_effect_underscore_binding,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::items_after_statements,
    clippy::if_not_else,
    clippy::if_same_then_else,
    clippy::option_if_let_else,
    clippy::naive_bytecount,
    clippy::ptr_arg,
    clippy::unused_self,
    clippy::redundant_closure_for_method_calls,
    clippy::redundant_else,
    clippy::manual_range_contains,
    clippy::neg_cmp_op_on_partial_ord,
    clippy::useless_let_if_seq,
    clippy::module_name_repetitions,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::comparison_chain,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::trivially_copy_pass_by_ref,
    clippy::redundant_field_names,
    clippy::manual_let_else,
    clippy::cast_precision_loss,
    clippy::range_plus_one,
    clippy::manual_clamp,
    clippy::needless_collect,
    clippy::missing_const_for_fn,
    clippy::redundant_clone,
    clippy::needless_type_cast
)]

//! Pure-Rust minimal x86 / x86-64 interpreter for emulating packer-stub code.

pub mod cpu;
pub mod mem;
pub mod regs;

pub use cpu::{Cpu, ExitReason, HostCall};
pub use mem::{Memory, PAGE_BITS, PAGE_SIZE, Perm};
pub use regs::{CpuMode, Reg, Regs};
