#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::unused_self,
    clippy::option_if_let_else,
    clippy::branches_sharing_code,
    clippy::useless_let_if_seq,
    clippy::unnested_or_patterns,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::missing_const_for_fn
)]

pub mod cfg;
pub mod detect;
pub mod emit;
pub mod eval;
pub mod fingerprint;
pub mod layout;
pub mod lift;
pub mod microop;
pub mod structure;

mod guardian;

use serde::{Deserialize, Serialize};

pub use cfg::{VmBlock, VmCfg};
pub use detect::{
    DispatchKind, HandlerEntry, VmDetection, VmStructure, detect_vm, recover_structure,
};
pub use emit::{emit_pseudocode, emit_recovered_listing};
pub use eval::{EvalError, EvalOutcome, evaluate};
pub use fingerprint::{FingerprintError, HandlerSemantics, fingerprint_handlers};
pub use lift::{LiftError, LiftedProgram, VmInsn, lift_bytecode};
pub use microop::{BinKind, CmpKind, MicroOp, UnKind, VmOperand};
pub use structure::{StructuredNode, structure_program};

pub const MAX_HANDLERS: usize = 4096;

pub const MAX_BYTECODE_INSNS: usize = 1 << 20;

pub const MAX_VM_REGS: usize = 256;

pub const MAX_VM_STACK: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevirtReport {
    pub detection: VmDetection,
    pub handler_count: usize,
    pub fingerprinted_count: usize,
    pub bytecode_insn_count: usize,
    pub block_count: usize,
    pub pseudocode: String,
    pub recovered_listing: String,
    pub residual: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevirtError {
    NoVmDetected,
    StructureRecoveryFailed,
    FingerprintFailed,
    LiftFailed,
}

pub fn devirtualize(
    bytes: &[u8],
    bitness: detect::Bitness,
) -> Result<(DevirtReport, LiftedProgram, VmCfg, Vec<HandlerSemantics>), DevirtError> {
    if let Some(result) = guardian::devirtualize_guardian_rs(bytes, bitness) {
        return Ok(result);
    }
    let detection: VmDetection = detect_vm(bytes, bitness).ok_or(DevirtError::NoVmDetected)?;
    let structure: VmStructure = recover_structure(bytes, bitness, &detection)
        .ok_or(DevirtError::StructureRecoveryFailed)?;
    let semantics: Vec<HandlerSemantics> = fingerprint_handlers(bytes, bitness, &structure)
        .map_err(|_| DevirtError::FingerprintFailed)?;
    let lifted: LiftedProgram =
        lift_bytecode(bytes, &structure, &semantics).map_err(|_| DevirtError::LiftFailed)?;
    let cfg: VmCfg = cfg::build_cfg(&lifted);
    let structured: Vec<StructuredNode> = structure_program(&cfg);
    let pseudocode: String = emit_pseudocode(&lifted, &structured);
    let recovered_listing: String = emit_recovered_listing(&lifted);
    let fingerprinted_count: usize = semantics
        .iter()
        .filter(|s: &&HandlerSemantics| !matches!(s.micro_op, MicroOp::Unknown))
        .count();
    let report: DevirtReport = DevirtReport {
        detection: detection.clone(),
        handler_count: structure.handlers.len(),
        fingerprinted_count,
        bytecode_insn_count: lifted.insns.len(),
        block_count: cfg.blocks.len(),
        pseudocode,
        recovered_listing,
        residual: residual_note(&detection, &semantics),
    };
    Ok((report, lifted, cfg, semantics))
}

fn residual_note(detection: &VmDetection, semantics: &[HandlerSemantics]) -> String {
    let unknown: usize = semantics
        .iter()
        .filter(|s: &&HandlerSemantics| matches!(s.micro_op, MicroOp::Unknown))
        .count();
    if unknown == 0 {
        format!(
            "generic VM lifter: dispatch={:?}, all {} handlers fingerprinted to a micro-op and the \
bytecode lifted to a re-executable IR. residual only if the handler stream is generated at \
runtime or fetched remotely.",
            detection.dispatch_kind,
            semantics.len()
        )
    } else {
        format!(
            "generic VM lifter: dispatch={:?}, {} of {} handlers fingerprinted; {} handlers could \
not be reduced to a single micro-op by behavioral probing (likely super-operators or \
opaque-predicate-split handlers needing a wider probe set).",
            detection.dispatch_kind,
            semantics.len() - unknown,
            semantics.len(),
            unknown
        )
    }
}
