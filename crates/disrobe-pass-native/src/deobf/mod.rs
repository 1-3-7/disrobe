pub mod abi;
pub mod bcf;
#[cfg(feature = "smt-solver")]
pub mod bcf_dse;
pub mod branchfold;
pub mod cff;
pub mod copyprop;
pub mod deadflags;
pub mod jumptable;
pub mod mba_lift;
pub mod pathsense;
pub mod substitution;
pub mod summary;

use serde::{Deserialize, Serialize};

pub use abi::{AbiInference, ArgCount, CallingConvention, ReturnKind, infer as infer_function_abi};
pub use bcf::{BogusBranch, OpaqueResult, analyze_block as analyze_bogus_branch};
#[cfg(feature = "smt-solver")]
pub use bcf_dse::{
    BackwardBudget, analyze_branch_backward as analyze_bogus_branch_deep,
    analyze_branch_backward_bounded as analyze_bogus_branch_deep_bounded, locate_containing_block,
};
pub use branchfold::{
    BranchFoldFinding, BranchFoldOutcome, FoldKind, FoldVerdict, fold_block as fold_branch_block,
};
pub use cff::{
    BlockSpan, CffOutcome, CffRecovery, DispatcherCover, StateCoverGap, StateEdge, StateLoc,
    StateRegion, UncoveredState, unflatten as unflatten_cff,
};
pub use copyprop::{
    CopyPropOutcome, CopyPropReport, clean_block as copy_propagate_block,
    clean_block_with_live_out as copy_propagate_block_live_out,
};
pub use deadflags::{
    DeadFlagOutcome, DeadFlagReport, clean_block as eliminate_dead_flags,
    clean_block_with_live_out as eliminate_dead_flags_live_out,
};
pub use jumptable::{
    JumpTableCase, JumpTableResolution, TableBaseForm, resolve_block as resolve_jump_table_block,
};
pub use pathsense::{
    DeadEdge, PathSenseReport, WallReason as PathSenseWall, analyze as analyze_path_constraints,
};
pub use substitution::{SubstitutionResult, simplify_sequence};
pub use summary::{FunctionSummary, summarize as summarize_function};

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    Bits32,
    Bits64,
}

impl Bits {
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCopyProp {
    pub block_address: u64,
    pub report: CopyPropReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDeadFlags {
    pub block_address: u64,
    pub report: DeadFlagReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaquePredicateSimplification {
    pub branch_address: u64,
    pub result: OpaqueResult,
    pub simplification: SubstitutionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEffect {
    pub address: u64,
    pub outputs: BTreeMap<String, String>,
}

impl FunctionEffect {
    #[must_use]
    pub fn from_summary(address: u64, summary: &FunctionSummary) -> Self {
        Self {
            address,
            outputs: summary.simplified_effects(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeobfReport {
    pub cff: Option<CffRecovery>,
    pub bogus_branches: Vec<BogusBranch>,
    pub substitutions: Vec<SubstitutionResult>,
    pub copyprop_report: Vec<BlockCopyProp>,
    pub dead_flag_report: Vec<BlockDeadFlags>,
    pub pathsense_report: Option<PathSenseReport>,
    pub mba_simplifications: Vec<OpaquePredicateSimplification>,
    pub branch_folds: Vec<BranchFoldFinding>,
    pub jump_tables: Vec<JumpTableResolution>,
    pub function_effects: Vec<FunctionEffect>,
    pub abi_inferences: Vec<AbiInference>,
    pub api_hashes: Vec<crate::api_hash::ApiHashHit>,
    pub stack_strings: Vec<crate::stack_string::ReassembledStackString>,
    pub cleaned_listing: Option<String>,
    pub notes: Vec<String>,
}

#[must_use]
pub fn defeat_cff(bits: Bits, base: u64, code: &[u8], entry: u64) -> CffOutcome {
    cff::unflatten(bits.value(), base, code, entry)
}

#[must_use]
pub fn defeat_bogus_control_flow(bits: Bits, base: u64, block: &[u8]) -> Option<BogusBranch> {
    bcf::analyze_block(bits.value(), base, block)
}

#[cfg(feature = "smt-solver")]
#[must_use]
pub fn defeat_bogus_control_flow_deep(
    bits: Bits,
    base: u64,
    code: &[u8],
    branch_address: u64,
) -> Option<BogusBranch> {
    let fast: Option<BogusBranch> =
        bcf_dse::locate_containing_block(bits.value(), base, code, branch_address).and_then(
            |(block_addr, range): (u64, std::ops::Range<usize>)| {
                bcf::analyze_block(bits.value(), block_addr, &code[range])
            },
        );
    if let Some(found) = &fast
        && matches!(
            found.result,
            OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
        )
    {
        return fast;
    }
    bcf_dse::analyze_branch_backward(bits.value(), base, code, branch_address).or(fast)
}

#[must_use]
pub fn undo_substitution(bits: Bits, base: u64, sequence: &[u8]) -> Option<SubstitutionResult> {
    substitution::simplify_sequence(bits.value(), base, sequence)
}

#[must_use]
pub fn prove_dead_paths(bits: Bits, base: u64, code: &[u8], entry: u64) -> PathSenseReport {
    pathsense::analyze(bits.value(), base, code, entry)
}

#[must_use]
pub fn clean_register_copies(bits: Bits, base: u64, block: &[u8]) -> Option<CopyPropOutcome> {
    copyprop::clean_block(bits.value(), base, block)
}

#[must_use]
pub fn clean_dead_flags(bits: Bits, base: u64, block: &[u8]) -> Option<DeadFlagOutcome> {
    deadflags::clean_block(bits.value(), base, block)
}

#[must_use]
pub fn clean_register_copies_live_out(
    bits: Bits,
    base: u64,
    block: &[u8],
    live_out: Option<&[iced_x86::Register]>,
) -> Option<CopyPropOutcome> {
    copyprop::clean_block_with_live_out(bits.value(), base, block, live_out)
}

#[must_use]
pub fn fold_constant_branch(bits: Bits, base: u64, block: &[u8]) -> Option<BranchFoldOutcome> {
    branchfold::fold_block(bits.value(), base, block)
}

#[must_use]
pub fn resolve_jump_table(
    bits: Bits,
    base: u64,
    block: &[u8],
    image_base: u64,
    image: &[u8],
) -> Option<JumpTableResolution> {
    jumptable::resolve_block(bits.value(), base, block, image_base, image)
}
