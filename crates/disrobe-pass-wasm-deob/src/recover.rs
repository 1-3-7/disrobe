use serde::Serialize;
use walrus::ir::{BinaryOp, Instr, InstrSeqId, Value};
use walrus::{FunctionId, FunctionKind, LocalFunction, Module, ModuleConfig};

use disrobe_mba::{
    BinOp as MbaBinOp, Expr as MbaExpr, Simplification, Width, equivalent_exhaustive, simplify,
};

use crate::error::{Error, Result};

mod cff;
mod opaque;
mod pure_eval;
mod reloop;

pub use cff::CffRecovery;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub mba_expressions_folded: usize,
    pub mba_nodes_removed: usize,
    pub opaque_predicates_removed: usize,
    pub call_indirect_resolved: usize,
    pub flattened_functions_restructured: usize,
    pub flattened_conditional_restructured: usize,
    pub flattened_dispatchers_walled: usize,
    pub wobfuscator_ops_reinlined: usize,
    pub wobfuscator_imports_dropped: usize,
    pub jscrambler_imports_stripped: usize,
    pub wasmixer_fragments_inlined: usize,
    pub wasmixer_functions_dropped: usize,
    pub wasmixer_elements_pruned: usize,
    pub intra_function_folding_skipped: bool,
    pub guard_folding_budget_exhausted: bool,
}

impl RecoveryReport {
    #[must_use]
    pub const fn any_change(&self) -> bool {
        self.mba_expressions_folded > 0
            || self.opaque_predicates_removed > 0
            || self.call_indirect_resolved > 0
            || self.flattened_functions_restructured > 0
            || self.wobfuscator_ops_reinlined > 0
            || self.jscrambler_imports_stripped > 0
            || self.wasmixer_fragments_inlined > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredModule {
    pub bytes: Vec<u8>,
    pub report: RecoveryReport,
}

const MAX_EXPR_NODES: usize = 96;
const MBA_DOUBLE_CHECK_VARS: u32 = 2;
const MBA_PROOF_WIDTH: Width = Width::W8;
const MAX_FOLD_INSTRUCTIONS: usize = 1 << 21;

const JSCRAMBLER_INTEGRITY_PREFIXES: &[&str] = &["__jscrambler_", "jscrambler", "jsc_"];

pub fn recover_module(wasm: &[u8]) -> Result<RecoveredModule> {
    crate::debug::dbg_section("recover");
    let mut report: RecoveryReport = RecoveryReport::default();
    let staged: Vec<u8> = recover_obfuscator_families(wasm, &mut report)?;

    let mut module: Module = parse_module(&staged)?;

    let resolved: usize = call_indirect::resolve_aliases(&mut module);
    report.call_indirect_resolved = resolved;
    crate::debug::dbg_kv("call-indirect", || format!("resolved_to_direct={resolved}"));

    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    crate::debug::dbg_kv("local-functions", || local_ids.len().to_string());
    let total_instructions: usize = count_local_instructions(&module, &local_ids);
    if exceeds_fold_budget(total_instructions) {
        report.intra_function_folding_skipped = true;
        crate::debug::dbg_kv("fold-skip", || {
            format!("instructions={total_instructions} cap={MAX_FOLD_INSTRUCTIONS}")
        });
    } else {
        for fid in &local_ids {
            let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(*fid).kind
            else {
                continue;
            };
            fold_function_mba(func, &mut report);
            opaque::fold_constant_branches(func, &mut report);
        }

        opaque::fold_interprocedural(&mut module, &mut report);
        crate::debug::dbg_kv("mba-fold", || {
            format!(
                "expressions_folded={} nodes_removed={} opaque_removed={}",
                report.mba_expressions_folded,
                report.mba_nodes_removed,
                report.opaque_predicates_removed
            )
        });

        let cff: CffRecovery = cff::restructure_flattened(&mut module);
        report.flattened_functions_restructured = cff.functions_restructured;
        report.flattened_conditional_restructured = cff.conditional_restructured;
        report.flattened_dispatchers_walled = cff.walled_branching_dispatchers;
        crate::debug::dbg_kv("unflatten", || {
            format!(
                "flattened_functions_restructured={} conditional={} walled={}",
                report.flattened_functions_restructured,
                report.flattened_conditional_restructured,
                report.flattened_dispatchers_walled
            )
        });
    }

    let bytes: Vec<u8> = module.emit_wasm();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::WASM2)
        .validate_all(&bytes)
        .map_err(|e| Error::InvalidRecovery(e.to_string()))?;
    Ok(RecoveredModule { bytes, report })
}

fn recover_obfuscator_families(wasm: &[u8], report: &mut RecoveryReport) -> Result<Vec<u8>> {
    let (after_wobf, wobf): (Vec<u8>, crate::obfuscators::ReinlineStats) =
        crate::obfuscators::reinline_imported_ops(wasm)?;
    report.wobfuscator_ops_reinlined = wobf.ops_reinlined;
    report.wobfuscator_imports_dropped = wobf.imports_dropped;
    crate::debug::dbg_kv("wobfuscator", || {
        format!(
            "ops_reinlined={} imports_dropped={}",
            wobf.ops_reinlined, wobf.imports_dropped
        )
    });

    let (after_jsc, jsc): (Vec<u8>, crate::obfuscators::IntegrityStripStats) =
        crate::obfuscators::strip_integrity_imports(&after_wobf, JSCRAMBLER_INTEGRITY_PREFIXES)?;
    report.jscrambler_imports_stripped = jsc.imports_removed;
    crate::debug::dbg_kv("jscrambler-integrity", || {
        format!("imports_removed={}", jsc.imports_removed)
    });

    let (after_mixer, mixer): (Vec<u8>, crate::obfuscators::DefragStats) =
        crate::obfuscators::defragment(&after_jsc)?;
    report.wasmixer_fragments_inlined = mixer.fragments_inlined;
    report.wasmixer_functions_dropped = mixer.functions_dropped;
    report.wasmixer_elements_pruned = mixer.elements_pruned;
    crate::debug::dbg_kv("wasmixer-defrag", || {
        format!(
            "fragments_inlined={} functions_dropped={} elements_pruned={}",
            mixer.fragments_inlined, mixer.functions_dropped, mixer.elements_pruned
        )
    });

    Ok(after_mixer)
}

pub(crate) fn parse_walrus_module(wasm: &[u8], config: &ModuleConfig) -> Result<Module> {
    let mut validator: wasmparser::Validator =
        wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::WASM2);
    validator.validate_all(wasm).map_err(|e| {
        Error::Parse(format!(
            "DR-WASMDEOB: wasm outside supported feature set: {e}"
        ))
    })?;
    Module::from_buffer_with_config(wasm, config)
        .map_err(|e| Error::Parse(format!("DR-WASMDEOB: walrus parse: {e}")))
}

fn parse_module(wasm: &[u8]) -> Result<Module> {
    let mut config: ModuleConfig = ModuleConfig::new();
    config.generate_producers_section(false);
    parse_walrus_module(wasm, &config)
}

const fn exceeds_fold_budget(total_instructions: usize) -> bool {
    total_instructions > MAX_FOLD_INSTRUCTIONS
}

fn count_local_instructions(module: &Module, local_ids: &[FunctionId]) -> usize {
    let mut total: usize = 0;
    for fid in local_ids {
        let FunctionKind::Local(func): &FunctionKind = &module.funcs.get(*fid).kind else {
            continue;
        };
        for seq_id in collect_seq_ids(func) {
            total = total.saturating_add(func.block(seq_id).instrs.len());
        }
    }
    total
}

fn fold_function_mba(func: &mut LocalFunction, report: &mut RecoveryReport) {
    let seq_ids: Vec<InstrSeqId> = collect_seq_ids(func);
    for seq_id in seq_ids {
        fold_seq_mba(func, seq_id, ExprWidth::W32, report);
        fold_seq_mba(func, seq_id, ExprWidth::W64, report);
    }
}

fn collect_seq_ids(func: &LocalFunction) -> Vec<InstrSeqId> {
    let mut out: Vec<InstrSeqId> = Vec::new();
    let mut stack: Vec<InstrSeqId> = vec![func.entry_block()];
    while let Some(id) = stack.pop() {
        out.push(id);
        let seq: &walrus::ir::InstrSeq = func.block(id);
        for (instr, _) in &seq.instrs {
            match instr {
                Instr::Block(b) => stack.push(b.seq),
                Instr::Loop(l) => stack.push(l.seq),
                Instr::IfElse(ie) => {
                    stack.push(ie.consequent);
                    stack.push(ie.alternative);
                }
                _ => {}
            }
        }
    }
    out
}

fn fold_seq_mba(
    func: &mut LocalFunction,
    seq_id: InstrSeqId,
    width: ExprWidth,
    report: &mut RecoveryReport,
) {
    let instrs: Vec<Instr> = func
        .block(seq_id)
        .instrs
        .iter()
        .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let mut end: usize = instrs.len();
    let mut rewrites: Vec<(usize, usize, Vec<Instr>, usize)> = Vec::new();
    while end > 0 {
        let Some(extract): Option<Extracted> = extract_expr(&instrs, end, width) else {
            end -= 1;
            continue;
        };
        if extract.start >= end {
            end -= 1;
            continue;
        }
        let folded: Option<FoldedExpr> = try_simplify(&extract, width);
        if let Some(folded) = folded {
            rewrites.push((extract.start, end, folded.instrs, folded.nodes_removed));
            end = extract.start;
        } else {
            end -= 1;
        }
    }
    if rewrites.is_empty() {
        return;
    }
    rewrites.sort_by_key(|(start, _, _, _): &(usize, usize, Vec<Instr>, usize)| {
        std::cmp::Reverse(*start)
    });
    let seq: &mut walrus::ir::InstrSeq = func.block_mut(seq_id);
    for (start, stop, replacement, nodes_removed) in rewrites {
        if stop > seq.instrs.len() || start > stop {
            continue;
        }
        let loc: walrus::ir::InstrLocId = seq
            .instrs
            .get(start)
            .map_or_else(walrus::ir::InstrLocId::default, |(_, l)| *l);
        let tail: Vec<(Instr, walrus::ir::InstrLocId)> = seq.instrs.split_off(stop);
        seq.instrs.truncate(start);
        for instr in replacement {
            seq.instrs.push((instr, loc));
        }
        seq.instrs.extend(tail);
        report.mba_expressions_folded += 1;
        report.mba_nodes_removed += nodes_removed;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprWidth {
    W32,
    W64,
}

#[derive(Debug, Clone)]
struct Extracted {
    expr: MbaExpr,
    leaves: Vec<Instr>,
    start: usize,
    consumed: usize,
}

#[derive(Debug, Clone)]
struct FoldedExpr {
    instrs: Vec<Instr>,
    nodes_removed: usize,
}

fn extract_expr(instrs: &[Instr], end: usize, width: ExprWidth) -> Option<Extracted> {
    let mut leaves: Vec<Instr> = Vec::new();
    let mut cursor: usize = end;
    let mut budget: usize = MAX_EXPR_NODES;
    let expr: MbaExpr = parse_value(instrs, &mut cursor, &mut leaves, &mut budget, width)?;
    Some(Extracted {
        expr,
        leaves,
        start: cursor,
        consumed: end - cursor,
    })
}

fn parse_value(
    instrs: &[Instr],
    cursor: &mut usize,
    leaves: &mut Vec<Instr>,
    budget: &mut usize,
    width: ExprWidth,
) -> Option<MbaExpr> {
    if *cursor == 0 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let idx: usize = *cursor - 1;
    let instr: &Instr = instrs.get(idx)?;
    match instr {
        Instr::Binop(b) => {
            let shift_scale: Option<u64> = const_shift_scale(instrs, idx, width);
            if let Some(scale) = shift_scale {
                *cursor -= 1;
                let _shift_amount: MbaExpr = parse_value(instrs, cursor, leaves, budget, width)?;
                let lhs: MbaExpr = parse_value(instrs, cursor, leaves, budget, width)?;
                return Some(MbaExpr::mul(lhs, MbaExpr::konst(scale)));
            }
            let op: MbaBinOp = arithmetic_binop(b.op, width)?;
            *cursor -= 1;
            let rhs: MbaExpr = parse_value(instrs, cursor, leaves, budget, width)?;
            let lhs: MbaExpr = parse_value(instrs, cursor, leaves, budget, width)?;
            Some(MbaExpr::Binary(op, Box::new(lhs), Box::new(rhs)))
        }
        Instr::Const(c) => match (c.value, width) {
            (Value::I32(v), ExprWidth::W32) => {
                *cursor -= 1;
                Some(MbaExpr::konst(u64::from(v.cast_unsigned())))
            }
            (Value::I64(v), ExprWidth::W64) => {
                *cursor -= 1;
                Some(MbaExpr::konst(v.cast_unsigned()))
            }
            _ => None,
        },
        Instr::LocalGet(_) => Some(leaf(instrs, cursor, leaves)),
        _ => None,
    }
}

fn const_shift_scale(instrs: &[Instr], binop_idx: usize, width: ExprWidth) -> Option<u64> {
    let is_shl: bool = match instrs.get(binop_idx) {
        Some(Instr::Binop(b)) => matches!(
            (b.op, width),
            (BinaryOp::I32Shl, ExprWidth::W32) | (BinaryOp::I64Shl, ExprWidth::W64)
        ),
        _ => false,
    };
    if !is_shl {
        return None;
    }
    let shift_amount: i64 = match instrs.get(binop_idx.checked_sub(1)?)? {
        Instr::Const(c) => match (c.value, width) {
            (Value::I32(v), ExprWidth::W32) => i64::from(v),
            (Value::I64(v), ExprWidth::W64) => v,
            _ => return None,
        },
        _ => return None,
    };
    let bit_width: i64 = match width {
        ExprWidth::W32 => 32,
        ExprWidth::W64 => 64,
    };
    if shift_amount <= 0 || shift_amount >= bit_width {
        return None;
    }
    let shift: u32 = u32::try_from(shift_amount).ok()?;
    1u64.checked_shl(shift)
}

fn leaf(instrs: &[Instr], cursor: &mut usize, leaves: &mut Vec<Instr>) -> MbaExpr {
    let idx: usize = *cursor - 1;
    let instr: Instr = instrs[idx].clone();
    *cursor -= 1;
    if let Instr::LocalGet(lg) = &instr {
        if let Some(pos) = leaves.iter().position(|existing: &Instr| {
            matches!(existing, Instr::LocalGet(other) if other.local == lg.local)
        }) {
            return MbaExpr::var(pos as u32);
        }
    }
    let index: u32 = leaves.len() as u32;
    leaves.push(instr);
    MbaExpr::var(index)
}

const fn arithmetic_binop(op: BinaryOp, width: ExprWidth) -> Option<MbaBinOp> {
    match (op, width) {
        (BinaryOp::I32Add, ExprWidth::W32) | (BinaryOp::I64Add, ExprWidth::W64) => {
            Some(MbaBinOp::Add)
        }
        (BinaryOp::I32Sub, ExprWidth::W32) | (BinaryOp::I64Sub, ExprWidth::W64) => {
            Some(MbaBinOp::Sub)
        }
        (BinaryOp::I32Mul, ExprWidth::W32) | (BinaryOp::I64Mul, ExprWidth::W64) => {
            Some(MbaBinOp::Mul)
        }
        (BinaryOp::I32And, ExprWidth::W32) | (BinaryOp::I64And, ExprWidth::W64) => {
            Some(MbaBinOp::And)
        }
        (BinaryOp::I32Or, ExprWidth::W32) | (BinaryOp::I64Or, ExprWidth::W64) => Some(MbaBinOp::Or),
        (BinaryOp::I32Xor, ExprWidth::W32) | (BinaryOp::I64Xor, ExprWidth::W64) => {
            Some(MbaBinOp::Xor)
        }
        _ => None,
    }
}

fn try_simplify(extract: &Extracted, width: ExprWidth) -> Option<FoldedExpr> {
    if !extract.expr.is_linear_mba() || extract.leaves.is_empty() {
        return None;
    }
    let var_count: u32 = extract.leaves.len() as u32;
    if var_count == 0 {
        return None;
    }
    let domain_width: Width = match width {
        ExprWidth::W32 => Width::W32,
        ExprWidth::W64 => Width::W64,
    };
    let result: Simplification = simplify(&extract.expr, domain_width);
    if !result.changed() || !result.verification.is_proven() {
        return None;
    }
    if result.simplified_nodes >= result.original_nodes {
        return None;
    }
    let distinct_vars: u32 = extract.expr.max_var().map_or(0, |m| m + 1);
    if distinct_vars <= MBA_DOUBLE_CHECK_VARS
        && !equivalent_exhaustive(
            &result.simplified,
            &extract.expr,
            MBA_PROOF_WIDTH,
            var_count,
        )
    {
        return None;
    }
    let instrs: Vec<Instr> = materialize(&result.simplified, &extract.leaves, width)?;
    let original: usize = extract.consumed;
    let removed: usize = original.saturating_sub(instrs.len());
    Some(FoldedExpr {
        instrs,
        nodes_removed: removed,
    })
}

fn materialize(expr: &MbaExpr, leaves: &[Instr], width: ExprWidth) -> Option<Vec<Instr>> {
    let mut out: Vec<Instr> = Vec::new();
    emit_expr(expr, leaves, width, &mut out)?;
    Some(out)
}

fn emit_expr(
    expr: &MbaExpr,
    leaves: &[Instr],
    width: ExprWidth,
    out: &mut Vec<Instr>,
) -> Option<()> {
    match expr {
        MbaExpr::Var(index) => {
            let instr: Instr = leaves.get(*index as usize)?.clone();
            out.push(instr);
            Some(())
        }
        MbaExpr::Const(value) => {
            out.push(const_instr(*value, width));
            Some(())
        }
        MbaExpr::Unary(op, inner) => {
            match op {
                disrobe_mba::UnOp::Neg => {
                    out.push(const_instr(0, width));
                    emit_expr(inner, leaves, width, out)?;
                    out.push(binop_instr(MbaBinOp::Sub, width)?);
                }
                disrobe_mba::UnOp::Not => {
                    emit_expr(inner, leaves, width, out)?;
                    out.push(const_instr(all_ones(width), width));
                    out.push(binop_instr(MbaBinOp::Xor, width)?);
                }
            }
            Some(())
        }
        MbaExpr::Binary(op, left, right) => {
            emit_expr(left, leaves, width, out)?;
            emit_expr(right, leaves, width, out)?;
            out.push(binop_instr(*op, width)?);
            Some(())
        }
        MbaExpr::Ite(_, _, _)
        | MbaExpr::Slice(_, _, _)
        | MbaExpr::Compose(_, _, _)
        | MbaExpr::Mem(_, _) => None,
    }
}

const fn const_instr(value: u64, width: ExprWidth) -> Instr {
    let value: Value = match width {
        ExprWidth::W32 => Value::I32((value as u32).cast_signed()),
        ExprWidth::W64 => Value::I64(value.cast_signed()),
    };
    Instr::Const(walrus::ir::Const { value })
}

const fn all_ones(width: ExprWidth) -> u64 {
    match width {
        ExprWidth::W32 => u32::MAX as u64,
        ExprWidth::W64 => u64::MAX,
    }
}

const fn binop_instr(op: MbaBinOp, width: ExprWidth) -> Option<Instr> {
    let bop: BinaryOp = match (op, width) {
        (MbaBinOp::Add, ExprWidth::W32) => BinaryOp::I32Add,
        (MbaBinOp::Add, ExprWidth::W64) => BinaryOp::I64Add,
        (MbaBinOp::Sub, ExprWidth::W32) => BinaryOp::I32Sub,
        (MbaBinOp::Sub, ExprWidth::W64) => BinaryOp::I64Sub,
        (MbaBinOp::Mul, ExprWidth::W32) => BinaryOp::I32Mul,
        (MbaBinOp::Mul, ExprWidth::W64) => BinaryOp::I64Mul,
        (MbaBinOp::And, ExprWidth::W32) => BinaryOp::I32And,
        (MbaBinOp::And, ExprWidth::W64) => BinaryOp::I64And,
        (MbaBinOp::Or, ExprWidth::W32) => BinaryOp::I32Or,
        (MbaBinOp::Or, ExprWidth::W64) => BinaryOp::I64Or,
        (MbaBinOp::Xor, ExprWidth::W32) => BinaryOp::I32Xor,
        (MbaBinOp::Xor, ExprWidth::W64) => BinaryOp::I64Xor,
        (MbaBinOp::Shl | MbaBinOp::Shr, _) => return None,
    };
    Some(Instr::Binop(walrus::ir::Binop { op: bop }))
}

pub(crate) mod call_indirect {
    use std::collections::{BTreeMap, BTreeSet};

    use walrus::ir::{Instr, InstrSeqId, Value};
    use walrus::{
        ElementId, ElementItems, ExportItem, FunctionId, FunctionKind, Module, TableId, TypeId,
    };

    pub(super) fn resolve_aliases(module: &mut Module) -> usize {
        let frozen: BTreeSet<TableId> = frozen_tables(module);
        let table_map: BTreeMap<TableId, Vec<Option<FunctionId>>> = build_table_index(module)
            .into_iter()
            .filter(|(table, _): &(TableId, Vec<Option<FunctionId>>)| frozen.contains(table))
            .collect();
        let types: BTreeMap<FunctionId, TypeId> = module
            .funcs
            .iter()
            .map(|func: &walrus::Function| (func.id(), func.ty()))
            .collect();
        let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
        let mut resolved: usize = 0;
        for fid in local_ids {
            let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(fid).kind
            else {
                continue;
            };
            let seq_ids: Vec<InstrSeqId> = super::collect_seq_ids(func);
            for seq_id in seq_ids {
                resolved += resolve_seq(func.block_mut(seq_id), &table_map, &types);
            }
        }
        resolved
    }

    pub(crate) fn frozen_tables(module: &Module) -> BTreeSet<TableId> {
        let mut excluded: BTreeSet<TableId> = module
            .exports
            .iter()
            .filter_map(|export: &walrus::Export| match export.item {
                ExportItem::Table(table) => Some(table),
                _ => None,
            })
            .collect();
        for table in module.tables.iter() {
            if table.import.is_some() {
                excluded.insert(table.id());
            }
        }
        for element in module.elements.iter() {
            if let walrus::ElementKind::Active { table, offset } = &element.kind
                && !matches!(offset, walrus::ConstExpr::Value(Value::I32(_)))
            {
                excluded.insert(*table);
            }
        }
        for (_, func) in module.funcs.iter_local() {
            for seq_id in super::collect_seq_ids(func) {
                for (instr, _) in &func.block(seq_id).instrs {
                    match instr {
                        Instr::TableSet(i) => {
                            excluded.insert(i.table);
                        }
                        Instr::TableGrow(i) => {
                            excluded.insert(i.table);
                        }
                        Instr::TableFill(i) => {
                            excluded.insert(i.table);
                        }
                        Instr::TableCopy(i) => {
                            excluded.insert(i.dst);
                        }
                        Instr::TableInit(i) => {
                            excluded.insert(i.table);
                        }
                        _ => {}
                    }
                }
            }
        }
        module
            .tables
            .iter()
            .map(walrus::Table::id)
            .filter(|table: &TableId| !excluded.contains(table))
            .collect()
    }

    fn resolve_seq(
        seq: &mut walrus::ir::InstrSeq,
        table_map: &BTreeMap<TableId, Vec<Option<FunctionId>>>,
        types: &BTreeMap<FunctionId, TypeId>,
    ) -> usize {
        let mut resolved: usize = 0;
        let mut idx: usize = 0;
        while idx + 1 < seq.instrs.len() {
            let slot: Option<i32> = match &seq.instrs[idx].0 {
                Instr::Const(c) => match c.value {
                    Value::I32(v) => Some(v),
                    _ => None,
                },
                _ => None,
            };
            let target: Option<FunctionId> = match &seq.instrs[idx + 1].0 {
                Instr::CallIndirect(ci) => slot.and_then(|table_index: i32| {
                    let entries: &Vec<Option<FunctionId>> = table_map.get(&ci.table)?;
                    let slot: usize = usize::try_from(table_index).ok()?;
                    let target: FunctionId = (*entries.get(slot)?)?;
                    (types.get(&target) == Some(&ci.ty)).then_some(target)
                }),
                _ => None,
            };
            if let Some(target) = target {
                let loc: walrus::ir::InstrLocId = seq.instrs[idx].1;
                seq.instrs.remove(idx + 1);
                seq.instrs[idx] = (Instr::Call(walrus::ir::Call { func: target }), loc);
                resolved += 1;
            }
            idx += 1;
        }
        resolved
    }

    const MAX_TABLE_SLOTS: usize = 10_000_000;

    pub(super) fn build_table_index(module: &Module) -> BTreeMap<TableId, Vec<Option<FunctionId>>> {
        let table_caps: BTreeMap<TableId, usize> = module
            .tables
            .iter()
            .map(|table: &walrus::Table| {
                let declared: usize = usize::try_from(table.initial).unwrap_or(usize::MAX);
                (table.id(), declared.min(MAX_TABLE_SLOTS))
            })
            .collect();
        let mut out: BTreeMap<TableId, Vec<Option<FunctionId>>> = BTreeMap::new();
        let mut budget: usize = MAX_TABLE_SLOTS;
        let element_ids: Vec<ElementId> = module.elements.iter().map(walrus::Element::id).collect();
        for eid in element_ids {
            let element: &walrus::Element = module.elements.get(eid);
            let walrus::ElementKind::Active { table, offset } = &element.kind else {
                continue;
            };
            let Some(&cap): Option<&usize> = table_caps.get(table) else {
                continue;
            };
            let base: usize = match offset {
                walrus::ConstExpr::Value(Value::I32(v)) => match usize::try_from(*v) {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                _ => continue,
            };
            if base >= cap {
                continue;
            }
            let functions: Vec<Option<FunctionId>> = match &element.items {
                ElementItems::Functions(ids) => ids.iter().copied().map(Some).collect(),
                ElementItems::Expressions(_, exprs) => exprs
                    .iter()
                    .map(|expr| match expr {
                        walrus::ConstExpr::RefFunc(fid) => Some(*fid),
                        _ => None,
                    })
                    .collect(),
            };
            let needed: usize = base.saturating_add(functions.len()).min(cap);
            let slots: &mut Vec<Option<FunctionId>> = out.entry(*table).or_default();
            if slots.len() < needed {
                let growth: usize = needed - slots.len();
                if growth > budget {
                    continue;
                }
                budget -= growth;
                slots.resize(needed, None);
            }
            for (offset_idx, fid) in functions.into_iter().enumerate() {
                let Some(slot_index): Option<usize> = base.checked_add(offset_idx) else {
                    break;
                };
                if slot_index >= needed {
                    break;
                }
                if let Some(slot) = slots.get_mut(slot_index) {
                    *slot = fid;
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn assemble(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("assemble wat")
    }

    #[test]
    fn folds_xor_carry_mba_into_addition() {
        let wat: &str = r#"
            (module
              (func (export "f") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.xor
                i32.const 2
                local.get 0
                local.get 1
                i32.and
                i32.mul
                i32.add))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert!(
            recovered.report.mba_expressions_folded >= 1,
            "expected MBA fold, report={:?}",
            recovered.report
        );
        assert!(walrus::Module::from_buffer(&recovered.bytes).is_ok());
    }

    #[test]
    fn leaves_clean_arithmetic_untouched() {
        let wat: &str = r#"
            (module
              (func (export "f") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert_eq!(recovered.report.mba_expressions_folded, 0);
    }

    fn recover_real(name: &str) -> RecoveryReport {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/wasm/obf/real")
            .join(name);
        let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read {name}: {e}; run corpus/wasm/obf/build.sh to produce the real wat")
        });
        let bytes: Vec<u8> = assemble(&text);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert!(
            walrus::Module::from_buffer(&recovered.bytes).is_ok(),
            "recovered {name} must round-trip"
        );
        recovered.report
    }

    #[test]
    fn real_mba_checksum_recovers() {
        let report: RecoveryReport = recover_real("mba_checksum.obf.wat");
        assert!(report.mba_expressions_folded >= 2, "report={report:?}");
    }

    #[test]
    fn folds_constant_opaque_predicates_when_present() {
        let wat: &str = r#"
            (module
              (func (export "constant") (param i32) (result i32)
                i32.const 9
                i32.const 3
                i32.rem_s
                i32.eqz
                if (result i32) local.get 0 i32.const 7 i32.mul
                else local.get 0 i32.const 13 i32.mul end))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert!(
            recovered.report.opaque_predicates_removed >= 1,
            "report={:?}",
            recovered.report
        );
        assert!(walrus::Module::from_buffer(&recovered.bytes).is_ok());
    }

    #[test]
    fn real_callind_dispatch_leaves_memory_loaded_indices_indirect() {
        let report: RecoveryReport = recover_real("callind_dispatch.obf.wat");
        assert_eq!(report.call_indirect_resolved, 0, "report={report:?}");
    }

    fn resolved_calls(wat: &str) -> usize {
        recover_module(&assemble(wat))
            .expect("recover")
            .report
            .call_indirect_resolved
    }

    #[test]
    fn a_constant_slot_on_a_frozen_table_becomes_a_direct_call() {
        let wat: &str = r#"
            (module
              (type $t (func (result i32)))
              (table 2 funcref)
              (elem (i32.const 0) $a $b)
              (func $a (type $t) i32.const 1)
              (func $b (type $t) i32.const 2)
              (func (export "f") (result i32) i32.const 1 call_indirect (type $t))
              (func (export "g") (result i32) i32.const 1 call_indirect (type $t)))
        "#;
        assert_eq!(resolved_calls(wat), 2);
    }

    #[test]
    fn an_exported_table_keeps_the_indirect_call() {
        let wat: &str = r#"
            (module
              (type $t (func (result i32)))
              (table (export "tbl") 2 funcref)
              (elem (i32.const 0) $a $a)
              (func $a (type $t) i32.const 1)
              (func (export "f") (result i32) i32.const 1 call_indirect (type $t)))
        "#;
        assert_eq!(indirect_calls_left(wat), 1);
    }

    #[test]
    fn a_table_grown_at_run_time_keeps_the_indirect_call() {
        let wat: &str = r#"
            (module
              (type $t (func (result i32)))
              (table 2 funcref)
              (elem (i32.const 0) $a $a)
              (func $a (type $t) i32.const 1)
              (func (export "grow") (result i32) ref.null func i32.const 1 table.grow 0)
              (func (export "f") (result i32) i32.const 1 call_indirect (type $t)))
        "#;
        assert_eq!(indirect_calls_left(wat), 1);
    }

    #[test]
    fn a_slot_whose_function_has_another_type_keeps_the_indirect_call() {
        let wat: &str = r#"
            (module
              (type $t (func (result i32)))
              (type $u (func (param i32) (result i32)))
              (table 2 funcref)
              (elem (i32.const 0) $a $c)
              (func $a (type $t) i32.const 1)
              (func $c (type $u) local.get 0)
              (func (export "f") (result i32) i32.const 1 call_indirect (type $t)))
        "#;
        assert_eq!(indirect_calls_left(wat), 1);
    }

    fn indirect_calls_left(wat: &str) -> usize {
        let recovered: RecoveredModule = recover_module(&assemble(wat)).expect("recover");
        let module: walrus::Module =
            walrus::Module::from_buffer(&recovered.bytes).expect("reparse");
        module
            .funcs
            .iter_local()
            .map(|(_, func): (FunctionId, &LocalFunction)| {
                collect_seq_ids(func)
                    .into_iter()
                    .map(|seq: walrus::ir::InstrSeqId| {
                        func.block(seq)
                            .instrs
                            .iter()
                            .filter(|(instr, _): &&(Instr, walrus::ir::InstrLocId)| {
                                matches!(instr, Instr::CallIndirect(_))
                            })
                            .count()
                    })
                    .sum::<usize>()
            })
            .sum()
    }

    #[test]
    fn real_cff_pipeline_relinearizes_br_table_dispatcher() {
        let report: RecoveryReport = recover_real("cff_pipeline.obf.wat");
        assert!(
            report.flattened_functions_restructured >= 1,
            "report={report:?}"
        );
    }

    #[test]
    fn real_cff_loop_restructures_cyclic_dispatcher() {
        let report: RecoveryReport = recover_real("cff_loop.obf.wat");
        assert!(
            report.flattened_functions_restructured >= 1,
            "report={report:?}"
        );
    }

    #[test]
    fn real_decrypt_stub_keeps_its_ciphertext_for_the_stub_to_decrypt() {
        fn segments(wasm: &[u8]) -> Vec<Vec<u8>> {
            walrus::Module::from_buffer(wasm)
                .expect("parse")
                .data
                .iter()
                .map(|data: &walrus::Data| data.value.clone())
                .collect()
        }
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/wasm/obf/real/decrypt_stub.obf.wat");
        let text: String = std::fs::read_to_string(&path).expect("read decrypt_stub.obf.wat");
        let bytes: Vec<u8> = assemble(&text);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert_eq!(segments(&recovered.bytes), segments(&bytes));
    }

    #[test]
    fn fold_budget_threshold_caps_oversized_modules() {
        assert!(!exceeds_fold_budget(0));
        assert!(!exceeds_fold_budget(MAX_FOLD_INSTRUCTIONS));
        assert!(exceeds_fold_budget(MAX_FOLD_INSTRUCTIONS + 1));
        assert!(exceeds_fold_budget(usize::MAX));
    }

    #[test]
    fn small_module_runs_folding_under_budget() {
        let wat: &str = r#"
            (module
              (func (export "f") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.xor
                i32.const 2
                local.get 0
                local.get 1
                i32.and
                i32.mul
                i32.add))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
        assert!(
            !recovered.report.intra_function_folding_skipped,
            "small module must not trip the fold budget cap, report={:?}",
            recovered.report
        );
        assert!(recovered.report.mba_expressions_folded >= 1);
    }

    #[test]
    fn out_of_bounds_element_segment_does_not_inflate_table_index() {
        let wat: &str = r"
            (module
              (table 1 funcref)
              (func $f)
              (elem (i32.const 9999999) $f))
        ";
        let bytes: Vec<u8> = assemble(wat);
        let module: walrus::Module =
            walrus::Module::from_buffer(&bytes).expect("parse crafted module");
        let index: std::collections::BTreeMap<walrus::TableId, Vec<Option<FunctionId>>> =
            call_indirect::build_table_index(&module);
        for slots in index.values() {
            assert!(
                slots.len() <= 1,
                "an out-of-bounds element segment inflated the table index to {} slots",
                slots.len()
            );
        }
        let recovered: RecoveredModule = recover_module(&bytes).expect("recover crafted module");
        assert_eq!(recovered.report.call_indirect_resolved, 0);
    }

    #[test]
    fn in_bounds_element_segment_is_indexed() {
        let wat: &str = r"
            (module
              (table 4 funcref)
              (func $a)
              (func $b)
              (elem (i32.const 1) $a $b))
        ";
        let bytes: Vec<u8> = assemble(wat);
        let module: walrus::Module = walrus::Module::from_buffer(&bytes).expect("parse module");
        let index: std::collections::BTreeMap<walrus::TableId, Vec<Option<FunctionId>>> =
            call_indirect::build_table_index(&module);
        let slots: &Vec<Option<FunctionId>> = index.values().next().expect("one table indexed");
        assert_eq!(slots.len(), 3);
        assert!(slots[1].is_some());
        assert!(slots[2].is_some());
        assert!(slots[0].is_none());
    }
}
