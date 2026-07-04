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
pub use opaque::CollatzWitness;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub mba_expressions_folded: usize,
    pub mba_nodes_removed: usize,
    pub opaque_predicates_removed: usize,
    pub collatz_predicates_removed: usize,
    pub call_indirect_resolved: usize,
    pub flattened_functions_restructured: usize,
    pub flattened_conditional_restructured: usize,
    pub flattened_dispatchers_walled: usize,
    pub decrypt_stub_bytes_recovered: usize,
    pub wobfuscator_ops_reinlined: usize,
    pub wobfuscator_imports_dropped: usize,
    pub jscrambler_imports_stripped: usize,
    pub wasmixer_fragments_inlined: usize,
    pub wasmixer_functions_dropped: usize,
    pub wasmixer_elements_pruned: usize,
    pub intra_function_folding_skipped: bool,
    pub collatz_witnesses: Vec<CollatzWitness>,
}

impl RecoveryReport {
    #[must_use]
    pub const fn any_change(&self) -> bool {
        self.mba_expressions_folded > 0
            || self.opaque_predicates_removed > 0
            || self.collatz_predicates_removed > 0
            || self.call_indirect_resolved > 0
            || self.flattened_functions_restructured > 0
            || self.decrypt_stub_bytes_recovered > 0
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
                "expressions_folded={} nodes_removed={} opaque_removed={} collatz_removed={}",
                report.mba_expressions_folded,
                report.mba_nodes_removed,
                report.opaque_predicates_removed,
                report.collatz_predicates_removed
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

    let decrypted: usize = decrypt::recover_pure_decrypt_data(&mut module);
    report.decrypt_stub_bytes_recovered = decrypted;
    crate::debug::dbg_kv("decrypt-stub", || {
        format!("data_bytes_recovered={decrypted}")
    });

    Ok(RecoveredModule {
        bytes: module.emit_wasm(),
        report,
    })
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

mod call_indirect {
    use std::collections::BTreeMap;

    use walrus::ir::{Instr, InstrSeqId, LoadKind, LocalId, Value};
    use walrus::{DataKind, ElementId, ElementItems, FunctionId, FunctionKind, Module, TableId};

    pub(super) fn resolve_aliases(module: &mut Module) -> usize {
        let table_map: BTreeMap<TableId, Vec<Option<FunctionId>>> = build_table_index(module);
        let memory: BTreeMap<u64, u8> = build_data_index(module);
        let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
        let mut resolved: usize = 0;
        for fid in local_ids {
            let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(fid).kind
            else {
                continue;
            };
            let seq_ids: Vec<InstrSeqId> = super::collect_seq_ids(func);
            for seq_id in seq_ids {
                resolved += resolve_seq(func.block_mut(seq_id), &table_map, &memory);
            }
        }
        resolved
    }

    fn resolve_seq(
        seq: &mut walrus::ir::InstrSeq,
        table_map: &BTreeMap<TableId, Vec<Option<FunctionId>>>,
        memory: &BTreeMap<u64, u8>,
    ) -> usize {
        let constant_slots: BTreeMap<LocalId, i32> = track_constant_slots(&seq.instrs, memory);
        let mut resolved: usize = 0;
        let mut idx: usize = 0;
        while idx + 1 < seq.instrs.len() {
            let slot: Option<i32> = match &seq.instrs[idx].0 {
                Instr::Const(c) => match c.value {
                    Value::I32(v) => Some(v),
                    _ => None,
                },
                Instr::LocalGet(lg) => constant_slots.get(&lg.local).copied(),
                _ => None,
            };
            let target: Option<FunctionId> = match &seq.instrs[idx + 1].0 {
                Instr::CallIndirect(ci) => slot.and_then(|table_index: i32| {
                    let entries: &Vec<Option<FunctionId>> = table_map.get(&ci.table)?;
                    let slot: usize = usize::try_from(table_index).ok()?;
                    *entries.get(slot)?
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

    fn track_constant_slots(
        instrs: &[(Instr, walrus::ir::InstrLocId)],
        memory: &BTreeMap<u64, u8>,
    ) -> BTreeMap<LocalId, i32> {
        let mut slots: BTreeMap<LocalId, i32> = BTreeMap::new();
        for window in instrs.windows(3) {
            let base: i32 = match &window[0].0 {
                Instr::Const(c) => match c.value {
                    Value::I32(v) => v,
                    _ => continue,
                },
                _ => continue,
            };
            let load_offset: u64 = match &window[1].0 {
                Instr::Load(load) => match load.kind {
                    LoadKind::I32 { .. } => u64::from(load.arg.offset),
                    _ => continue,
                },
                _ => continue,
            };
            let Instr::LocalSet(set) = &window[2].0 else {
                continue;
            };
            let address: u64 = match u64::try_from(base) {
                Ok(b) => b.wrapping_add(load_offset),
                Err(_) => continue,
            };
            if let Some(value) = read_i32(memory, address) {
                slots.insert(set.local, value);
            }
        }
        for window in instrs.windows(2) {
            let value: i32 = match &window[0].0 {
                Instr::Const(c) => match c.value {
                    Value::I32(v) => v,
                    _ => continue,
                },
                _ => continue,
            };
            if let Instr::LocalSet(set) = &window[1].0 {
                slots.insert(set.local, value);
            }
        }
        slots
    }

    fn read_i32(memory: &BTreeMap<u64, u8>, address: u64) -> Option<i32> {
        let mut bytes: [u8; 4] = [0; 4];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = *memory.get(&address.wrapping_add(i as u64))?;
        }
        Some(i32::from_le_bytes(bytes))
    }

    fn build_data_index(module: &Module) -> BTreeMap<u64, u8> {
        let mut out: BTreeMap<u64, u8> = BTreeMap::new();
        for data in module.data.iter() {
            let DataKind::Active { offset, .. } = &data.kind else {
                continue;
            };
            let base: u64 = match offset {
                walrus::ConstExpr::Value(Value::I32(v)) => match u64::try_from(*v) {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                walrus::ConstExpr::Value(Value::I64(v)) => match u64::try_from(*v) {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                _ => continue,
            };
            for (i, byte) in data.value.iter().enumerate() {
                out.insert(base.wrapping_add(i as u64), *byte);
            }
        }
        out
    }

    const MAX_TABLE_SLOTS: usize = 10_000_000;

    fn build_table_index(module: &Module) -> BTreeMap<TableId, Vec<Option<FunctionId>>> {
        let mut out: BTreeMap<TableId, Vec<Option<FunctionId>>> = BTreeMap::new();
        let element_ids: Vec<ElementId> = module.elements.iter().map(walrus::Element::id).collect();
        for eid in element_ids {
            let element: &walrus::Element = module.elements.get(eid);
            let walrus::ElementKind::Active { table, offset } = &element.kind else {
                continue;
            };
            let base: usize = match offset {
                walrus::ConstExpr::Value(Value::I32(v)) => match usize::try_from(*v) {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                _ => continue,
            };
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
            let needed: usize = base.saturating_add(functions.len());
            if needed > MAX_TABLE_SLOTS {
                continue;
            }
            let slots: &mut Vec<Option<FunctionId>> = out.entry(*table).or_default();
            if slots.len() < needed {
                slots.resize(needed, None);
            }
            for (offset_idx, fid) in functions.into_iter().enumerate() {
                if let Some(slot) = slots.get_mut(base + offset_idx) {
                    *slot = fid;
                }
            }
        }
        out
    }
}

mod decrypt {
    use walrus::ir::{BinaryOp, Instr, Value};
    use walrus::{DataId, DataKind, FunctionId, LocalFunction, Module};

    #[derive(Debug, Clone, Copy)]
    enum ByteOp {
        Xor(u8),
        Add(u8),
        Sub(u8),
    }

    pub(super) fn recover_pure_decrypt_data(module: &mut Module) -> usize {
        let Some((data_id, op)): Option<(DataId, ByteOp)> = find_decrypt_target(module) else {
            return 0;
        };
        let data: &mut walrus::Data = module.data.get_mut(data_id);
        if !matches!(data.kind, DataKind::Active { .. }) || data.value.is_empty() {
            return 0;
        }
        let mut count: usize = 0;
        for byte in &mut data.value {
            *byte = apply(op, *byte);
            count += 1;
        }
        count
    }

    const fn apply(op: ByteOp, byte: u8) -> u8 {
        match op {
            ByteOp::Xor(k) => byte ^ k,
            ByteOp::Add(k) => byte.wrapping_add(k),
            ByteOp::Sub(k) => byte.wrapping_sub(k),
        }
    }

    fn find_decrypt_target(module: &Module) -> Option<(DataId, ByteOp)> {
        let op: ByteOp = module
            .funcs
            .iter_local()
            .find_map(|(_, func): (FunctionId, &LocalFunction)| byte_walk_transform(func))?;
        let active: DataId = module
            .data
            .iter()
            .find(|d| matches!(d.kind, DataKind::Active { .. }) && !d.value.is_empty())
            .map(walrus::Data::id)?;
        Some((active, op))
    }

    #[derive(Debug, Default)]
    struct Walk {
        loads8: u32,
        stores8: u32,
        keyed_op: Option<ByteOp>,
        keyed_count: u32,
        calls: u32,
    }

    fn byte_walk_transform(func: &LocalFunction) -> Option<ByteOp> {
        let mut walk: Walk = Walk::default();
        let mut stack: Vec<walrus::ir::InstrSeqId> = vec![func.entry_block()];
        let mut has_loop: bool = false;
        while let Some(id) = stack.pop() {
            let instrs: &[(Instr, walrus::ir::InstrLocId)] = &func.block(id).instrs;
            scan_block(instrs, &mut walk);
            for (instr, _) in instrs {
                match instr {
                    Instr::Loop(l) => {
                        has_loop = true;
                        stack.push(l.seq);
                    }
                    Instr::Block(b) => stack.push(b.seq),
                    Instr::IfElse(ie) => {
                        stack.push(ie.consequent);
                        stack.push(ie.alternative);
                    }
                    _ => {}
                }
            }
        }
        let single_keyed: bool = walk.keyed_count == 1 && walk.keyed_op.is_some();
        if has_loop && walk.loads8 >= 1 && walk.stores8 >= 1 && walk.calls == 0 && single_keyed {
            return walk.keyed_op;
        }
        None
    }

    fn scan_block(instrs: &[(Instr, walrus::ir::InstrLocId)], walk: &mut Walk) {
        let mut last_const: Option<i32> = None;
        let mut in_byte_transform: bool = false;
        for (instr, _) in instrs {
            match instr {
                Instr::Const(c) => {
                    if let Value::I32(v) = c.value {
                        last_const = Some(v);
                    }
                }
                Instr::Load(l) => {
                    if matches!(l.kind, walrus::ir::LoadKind::I32_8 { .. }) {
                        walk.loads8 += 1;
                        in_byte_transform = true;
                    }
                    last_const = None;
                }
                Instr::Store(s) => {
                    if matches!(s.kind, walrus::ir::StoreKind::I32_8 { .. }) {
                        walk.stores8 += 1;
                    }
                    in_byte_transform = false;
                    last_const = None;
                }
                Instr::Binop(b) => {
                    let key: Option<u8> = last_const.and_then(|v| u8::try_from(v & 0xff).ok());
                    if let Some(op) = keyed_byte_op(b.op, key) {
                        if in_byte_transform {
                            walk.keyed_op = Some(op);
                            walk.keyed_count += 1;
                        }
                    }
                    last_const = None;
                }
                Instr::Call(_) | Instr::CallIndirect(_) => {
                    walk.calls += 1;
                    last_const = None;
                }
                _ => last_const = None,
            }
        }
    }

    const fn keyed_byte_op(op: BinaryOp, key: Option<u8>) -> Option<ByteOp> {
        match (op, key) {
            (BinaryOp::I32Xor, Some(k)) => Some(ByteOp::Xor(k)),
            (BinaryOp::I32Add, Some(k)) => Some(ByteOp::Add(k)),
            (BinaryOp::I32Sub, Some(k)) => Some(ByteOp::Sub(k)),
            _ => None,
        }
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
    fn folds_constant_and_collatz_opaque_predicates_when_present() {
        let wat: &str = r#"
            (module
              (func (export "constant") (param i32) (result i32)
                i32.const 9
                i32.const 3
                i32.rem_s
                i32.eqz
                if (result i32) local.get 0 i32.const 7 i32.mul
                else local.get 0 i32.const 13 i32.mul end)
              (func (export "collatz") (param i32) (result i32)
                i32.const 27
                i32.const 1
                i32.eq
                if (result i32) local.get 0 i32.const 3 i32.mul
                else local.get 0 i32.const 5 i32.mul end))
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
    fn real_callind_dispatch_resolves_memory_loaded_table_index() {
        let report: RecoveryReport = recover_real("callind_dispatch.obf.wat");
        assert!(report.call_indirect_resolved >= 3, "report={report:?}");
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
    fn real_decrypt_stub_recovers_plaintext() {
        let report: RecoveryReport = recover_real("decrypt_stub.obf.wat");
        assert!(
            report.decrypt_stub_bytes_recovered >= 10,
            "report={report:?}"
        );
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
}
