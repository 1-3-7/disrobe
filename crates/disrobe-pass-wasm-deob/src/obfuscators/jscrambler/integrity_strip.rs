use walrus::ir::Visitor;
use walrus::{FunctionId, Module, ModuleConfig, ValType};

use crate::cfg::BlockId;
use crate::error::{Error, Result};
use crate::ssa::{BlockTarget, SsaFunction, SsaTerm};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityStripStats {
    pub imports_removed: usize,
    pub call_sites_rewritten: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityCfgStats {
    pub guards_eliminated: usize,
    pub trap_blocks_isolated: usize,
}

/// Eliminates CFG-level integrity re-entry guard blocks left behind after the
/// integrity-check imports are stubbed out.
///
/// A jscrambler integrity guard is a `br_if` block where one arm reaches a trap
/// (`Unreachable`) handler — the tamper response — and the other continues normal
/// flow. Once the checksum import is neutralized the guard is a no-op re-entry: this
/// rewrites every such block to branch unconditionally to its continue arm, then
/// reports the trap blocks that became unreachable for downstream DCE.
pub fn eliminate_integrity_guards(ssa: &mut SsaFunction) -> IntegrityCfgStats {
    let mut stats: IntegrityCfgStats = IntegrityCfgStats::default();
    let mut isolated_traps: Vec<BlockId> = Vec::new();
    for bidx in 0..ssa.blocks.len() {
        let Some((continue_arm, trap_arm)): Option<(BlockTarget, BlockId)> =
            classify_guard(ssa, bidx)
        else {
            continue;
        };
        if let Some(block) = ssa.blocks.get_mut(bidx) {
            block.terminator = SsaTerm::Br(continue_arm);
            stats.guards_eliminated += 1;
            isolated_traps.push(trap_arm);
        }
    }
    isolated_traps.sort_unstable_by_key(|b| b.0);
    isolated_traps.dedup();
    stats.trap_blocks_isolated = isolated_traps
        .into_iter()
        .filter(|trap| !block_has_live_predecessor(ssa, *trap))
        .count();
    stats
}

/// A guard block branches to a trap (`Unreachable`) handler on one arm and continues
/// on the other. Returns `(continue_arm, trap_block_id)` so the caller can bypass it.
fn classify_guard(ssa: &SsaFunction, bidx: usize) -> Option<(BlockTarget, BlockId)> {
    let block: &crate::ssa::SsaBlock = ssa.blocks.get(bidx)?;
    let SsaTerm::BrIf { then_t, else_t, .. } = &block.terminator else {
        return None;
    };
    let then_traps: bool = block_is_trap(ssa, then_t.block);
    let else_traps: bool = block_is_trap(ssa, else_t.block);
    match (then_traps, else_traps) {
        (true, false) => Some((else_t.clone(), then_t.block)),
        (false, true) => Some((then_t.clone(), else_t.block)),
        _ => None,
    }
}

fn block_is_trap(ssa: &SsaFunction, id: BlockId) -> bool {
    ssa.blocks
        .get(id.0 as usize)
        .is_some_and(|b| matches!(b.terminator, SsaTerm::Unreachable) && b.stores.is_empty())
}

fn block_has_live_predecessor(ssa: &SsaFunction, target: BlockId) -> bool {
    ssa.blocks
        .iter()
        .any(|block| block.id != target && terminator_reaches(&block.terminator, target))
}

fn terminator_reaches(term: &SsaTerm, target: BlockId) -> bool {
    match term {
        SsaTerm::Br(t) | SsaTerm::Fallthrough(t) => t.block == target,
        SsaTerm::BrIf { then_t, else_t, .. } => then_t.block == target || else_t.block == target,
        SsaTerm::BrTable {
            targets, default, ..
        } => default.block == target || targets.iter().any(|t| t.block == target),
        SsaTerm::Return(_) | SsaTerm::Unreachable => false,
    }
}

pub fn strip_integrity_imports(
    wasm: &[u8],
    prefixes: &[&str],
) -> Result<(Vec<u8>, IntegrityStripStats)> {
    let mut module: Module = Module::from_buffer_with_config(wasm, &lenient_config())
        .map_err(|e| Error::Parse(format!("walrus parse: {e}")))?;
    let targets: Vec<FunctionId> = collect_target_funcs(&module, prefixes);
    let call_sites: usize = count_call_sites(&module, &targets);
    let stats: IntegrityStripStats = IntegrityStripStats {
        imports_removed: targets.len(),
        call_sites_rewritten: call_sites,
    };
    for fid in targets {
        let result_tys: Vec<ValType> = {
            let ty_id: walrus::TypeId = module.funcs.get(fid).ty();
            module.types.get(ty_id).results().to_vec()
        };
        module
            .replace_imported_func(fid, move |(body, _args)| {
                for ty in &result_tys {
                    push_zero(body, *ty);
                }
            })
            .map_err(|e| Error::Parse(format!("replace_imported_func: {e}")))?;
    }
    let bytes: Vec<u8> = module.emit_wasm();
    Ok((bytes, stats))
}

fn lenient_config() -> ModuleConfig {
    let mut cfg: ModuleConfig = ModuleConfig::new();
    cfg.generate_producers_section(false);
    cfg
}

fn push_zero(body: &mut walrus::InstrSeqBuilder<'_>, ty: ValType) {
    match ty {
        ValType::I32 => {
            body.i32_const(0);
        }
        ValType::I64 => {
            body.i64_const(0);
        }
        ValType::F32 => {
            body.f32_const(0.0);
        }
        ValType::F64 => {
            body.f64_const(0.0);
        }
        _ => {
            body.unreachable();
        }
    }
}

fn collect_target_funcs(module: &Module, prefixes: &[&str]) -> Vec<FunctionId> {
    let mut out: Vec<FunctionId> = Vec::new();
    for import in module.imports.iter() {
        if !prefixes.iter().any(|p| import.name.starts_with(p)) {
            continue;
        }
        if let walrus::ImportKind::Function(fid) = import.kind {
            out.push(fid);
        }
    }
    out
}

fn count_call_sites(module: &Module, targets: &[FunctionId]) -> usize {
    if targets.is_empty() {
        return 0;
    }
    let mut counter: CallCounter<'_> = CallCounter { targets, count: 0 };
    for (_id, func) in module.funcs.iter_local() {
        walrus::ir::dfs_in_order(&mut counter, func, func.entry_block());
    }
    counter.count
}

struct CallCounter<'a> {
    targets: &'a [FunctionId],
    count: usize,
}

impl<'a> Visitor<'a> for CallCounter<'a> {
    fn visit_call(&mut self, instr: &walrus::ir::Call) {
        if self.targets.contains(&instr.func) {
            self.count += 1;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ssa::{SsaBlock, ValueDef, ValueId};
    use smallvec::SmallVec;

    fn target(b: u32) -> BlockTarget {
        BlockTarget {
            block: BlockId(b),
            args: SmallVec::new(),
        }
    }

    fn empty_block(id: u32, term: SsaTerm) -> SsaBlock {
        SsaBlock {
            id: BlockId(id),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: term,
            preds: Vec::new(),
        }
    }

    #[test]
    fn guard_branching_to_trap_is_bypassed() {
        let values: Vec<ValueDef> = vec![ValueDef::Param(BlockId(0), 0)];
        let blocks: Vec<SsaBlock> = vec![
            empty_block(
                0,
                SsaTerm::BrIf {
                    cond: ValueId(0),
                    then_t: target(2),
                    else_t: target(1),
                },
            ),
            empty_block(1, SsaTerm::Return(SmallVec::new())),
            empty_block(2, SsaTerm::Unreachable),
        ];
        let mut ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        let stats: IntegrityCfgStats = eliminate_integrity_guards(&mut ssa);
        assert_eq!(stats.guards_eliminated, 1);
        assert_eq!(
            stats.trap_blocks_isolated, 1,
            "trap has no other predecessor"
        );
        match &ssa.blocks[0].terminator {
            SsaTerm::Br(t) => assert_eq!(t.block, BlockId(1), "bypass to continue arm"),
            other => panic!("expected unconditional Br, got {other:?}"),
        }
    }

    #[test]
    fn non_guard_brif_is_left_alone() {
        let values: Vec<ValueDef> = vec![ValueDef::Param(BlockId(0), 0)];
        let blocks: Vec<SsaBlock> = vec![
            empty_block(
                0,
                SsaTerm::BrIf {
                    cond: ValueId(0),
                    then_t: target(1),
                    else_t: target(2),
                },
            ),
            empty_block(1, SsaTerm::Return(SmallVec::new())),
            empty_block(2, SsaTerm::Return(SmallVec::new())),
        ];
        let mut ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        let stats: IntegrityCfgStats = eliminate_integrity_guards(&mut ssa);
        assert_eq!(stats.guards_eliminated, 0, "no trap arm -> not a guard");
        assert!(matches!(ssa.blocks[0].terminator, SsaTerm::BrIf { .. }));
    }

    #[test]
    fn trap_with_live_predecessor_not_counted_isolated() {
        let values: Vec<ValueDef> = vec![ValueDef::Param(BlockId(0), 0)];
        let blocks: Vec<SsaBlock> = vec![
            empty_block(
                0,
                SsaTerm::BrIf {
                    cond: ValueId(0),
                    then_t: target(2),
                    else_t: target(1),
                },
            ),
            empty_block(1, SsaTerm::Br(target(2))),
            empty_block(2, SsaTerm::Unreachable),
        ];
        let mut ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        let stats: IntegrityCfgStats = eliminate_integrity_guards(&mut ssa);
        assert_eq!(stats.guards_eliminated, 1);
        assert_eq!(
            stats.trap_blocks_isolated, 0,
            "trap still reached from block 1 -> not isolated"
        );
    }
}
