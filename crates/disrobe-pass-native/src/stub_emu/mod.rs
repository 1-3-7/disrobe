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
//!
//! Used by the Petite/MPRESS/kkrunchy phase-2 unpackers to execute compressed
//! decompressor stubs that statically-only decoders cannot recover. The module
//! is intentionally narrow: it implements just the ~60 instruction forms that
//! real-world packer stubs use, plus a tiny Win32 import shim (VirtualAlloc /
//! VirtualFree / VirtualProtect / LoadLibraryA / GetProcAddress / ExitProcess)
//! so the emulated stub can perform its allocations and self-bootstrap.
//!
//! Design constraints:
//!
//! - No unsafe, no FFI, no third-party emulator dependency. Disassembly is
//!   delegated to `iced-x86` (Apache-2/MIT, already in the workspace).
//! - Virtual memory is a `BTreeMap<u64, [u8; PAGE_SIZE]>`-backed paged address
//!   space with per-page R/W/X permission bits.
//! - Halts cleanly on JMP/CALL/RET targets that fall outside any mapped page,
//!   surfacing the final EIP/RIP and a snapshot of the dirty pages so the
//!   caller can reconstruct the unpacked image.

pub mod cpu;
pub mod mem;
pub mod regs;

pub use cpu::{Cpu, ExitReason, HostCall};
pub use mem::{Memory, PAGE_BITS, PAGE_SIZE, Perm};
pub use regs::{CpuMode, Reg, Regs};
