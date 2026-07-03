use std::collections::{BTreeMap, BTreeSet};

use disrobe_mba::verify::classify_predicate;
use disrobe_mba::{CmpOp, Expr, OpaqueVerdict, Predicate, Width};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::mba_lift::RegFile;

const MAX_DECODE_INSNS: usize = 8192;
const MAX_PATH_BLOCKS: usize = 256;
const MAX_CONSTRAINTS: usize = 64;
const MAX_FEASIBILITY_VARS: u32 = 3;
const FEASIBILITY_LIFT_WIDTH: Width = Width::W16;
const MAX_FEASIBILITY_EVALS: u128 = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WallReason {
    ConstraintBudgetExceeded,
    VariableBudgetExceeded,
    NonExhaustibleDomain,
    SymbolicStateCapped,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeadEdge {
    pub branch_address: u64,
    pub dead_target: u64,
    pub edge_taken: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathSenseReport {
    pub dead_edges: Vec<DeadEdge>,
    pub walls: Vec<String>,
}

#[derive(Debug, Clone)]
struct Constraint {
    predicate: Predicate,
    expect: bool,
    width: Width,
}

#[derive(Debug, Clone)]
struct PathState {
    regs: RegFile,
    constraints: Vec<Constraint>,
}

#[must_use]
pub fn analyze(bitness: u32, base: u64, code: &[u8], entry: u64) -> PathSenseReport {
    let insns: Vec<Instruction> = decode_all(bitness, base, code);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    let mut report: PathSenseReport = PathSenseReport {
        dead_edges: Vec::new(),
        walls: Vec::new(),
    };
    let Some(&start): Option<&usize> = index.get(&entry) else {
        return report;
    };
    let initial: PathState = PathState {
        regs: RegFile::new(),
        constraints: Vec::new(),
    };
    walk(&insns, &index, start, initial, &mut report);
    dedup(&mut report);
    report
}

fn walk(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    mut cursor: usize,
    mut state: PathState,
    report: &mut PathSenseReport,
) {
    let mut visited_branches: BTreeSet<u64> = BTreeSet::new();
    let mut block_budget: usize = MAX_PATH_BLOCKS;
    loop {
        let Some(insn): Option<&Instruction> = insns.get(cursor) else {
            return;
        };
        match insn.flow_control() {
            FlowControl::ConditionalBranch => {
                if !visited_branches.insert(insn.ip()) {
                    return;
                }
                if block_budget == 0 {
                    return;
                }
                block_budget -= 1;
                let cmp_index: Option<usize> = cursor.checked_sub(1);
                let predicate: Option<(Predicate, Width)> = cmp_index
                    .and_then(|ci: usize| insns.get(ci))
                    .and_then(|cmp: &Instruction| {
                        build_branch_predicate(&mut state.regs, cmp, insn.mnemonic())
                    });
                let taken_ip: u64 = insn.near_branch_target();
                let fallthrough_ip: u64 = insn.ip().saturating_add(insn.len() as u64);
                let Some((predicate, width)): Option<(Predicate, Width)> = predicate else {
                    if let Some(&next) = index.get(&taken_ip) {
                        walk(insns, index, next, state.clone(), report);
                    }
                    cursor = match index.get(&fallthrough_ip) {
                        Some(&next) => next,
                        None => return,
                    };
                    continue;
                };
                evaluate_edges(
                    insn.ip(),
                    &predicate,
                    width,
                    taken_ip,
                    fallthrough_ip,
                    &state,
                    report,
                );
                let taken_state: PathState =
                    push_constraint(state.clone(), predicate.clone(), true, width);
                if let Some(&next) = index.get(&taken_ip)
                    && feasible(&taken_state, report)
                {
                    walk(insns, index, next, taken_state, report);
                }
                state = push_constraint(state, predicate, false, width);
                if !feasible(&state, report) {
                    return;
                }
                match index.get(&fallthrough_ip) {
                    Some(&next) => cursor = next,
                    None => return,
                }
            }
            FlowControl::UnconditionalBranch => {
                let target: u64 = insn.near_branch_target();
                match index.get(&target) {
                    Some(&next) if next > cursor => cursor = next,
                    _ => return,
                }
            }
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
            | FlowControl::Exception => return,
            _ => {
                if !state.regs.apply_insn(insn) || state.regs.is_capped() {
                    return;
                }
                cursor += 1;
            }
        }
    }
}

fn evaluate_edges(
    branch_address: u64,
    predicate: &Predicate,
    width: Width,
    taken_ip: u64,
    fallthrough_ip: u64,
    state: &PathState,
    report: &mut PathSenseReport,
) {
    let taken_state: PathState = push_constraint(state.clone(), predicate.clone(), true, width);
    match feasibility(&taken_state) {
        Feasibility::Unsatisfiable => report.dead_edges.push(DeadEdge {
            branch_address,
            dead_target: taken_ip,
            edge_taken: true,
            reason: "branch taken-edge contradicts an earlier correlated branch".to_owned(),
        }),
        Feasibility::Satisfiable => {}
        Feasibility::Walled(reason) => record_wall(report, reason),
    }
    let fall_state: PathState = push_constraint(state.clone(), predicate.clone(), false, width);
    match feasibility(&fall_state) {
        Feasibility::Unsatisfiable => report.dead_edges.push(DeadEdge {
            branch_address,
            dead_target: fallthrough_ip,
            edge_taken: false,
            reason: "branch fallthrough-edge contradicts an earlier correlated branch".to_owned(),
        }),
        Feasibility::Satisfiable => {}
        Feasibility::Walled(reason) => record_wall(report, reason),
    }
}

fn push_constraint(
    mut state: PathState,
    predicate: Predicate,
    expect: bool,
    width: Width,
) -> PathState {
    if state.constraints.len() < MAX_CONSTRAINTS {
        state.constraints.push(Constraint {
            predicate,
            expect,
            width,
        });
    }
    state
}

fn feasible(state: &PathState, report: &mut PathSenseReport) -> bool {
    match feasibility(state) {
        Feasibility::Unsatisfiable => false,
        Feasibility::Satisfiable => true,
        Feasibility::Walled(reason) => {
            record_wall(report, reason);
            true
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Feasibility {
    Satisfiable,
    Unsatisfiable,
    Walled(WallReason),
}

fn feasibility(state: &PathState) -> Feasibility {
    if state.constraints.is_empty() {
        return Feasibility::Satisfiable;
    }
    if state.constraints.len() > MAX_CONSTRAINTS {
        return Feasibility::Walled(WallReason::ConstraintBudgetExceeded);
    }
    if state.regs.is_capped() {
        return Feasibility::Walled(WallReason::SymbolicStateCapped);
    }
    let mut vars: BTreeSet<u32> = BTreeSet::new();
    let mut max_width: Width = Width::W1;
    for constraint in &state.constraints {
        collect_predicate_vars(&constraint.predicate, &mut vars);
        if constraint.width.bits() > max_width.bits() {
            max_width = constraint.width;
        }
    }
    let var_count: u32 = match u32::try_from(vars.len()) {
        Ok(count) => count,
        Err(_) => return Feasibility::Walled(WallReason::VariableBudgetExceeded),
    };
    let eval_width: Width = if max_width.is_exhaustible() {
        max_width
    } else {
        FEASIBILITY_LIFT_WIDTH
    };
    let mut remap: BTreeMap<u32, u32> = BTreeMap::new();
    for pair in vars.into_iter().enumerate() {
        let (dense, original): (usize, u32) = pair;
        let Ok(dense): Result<u32, _> = u32::try_from(dense) else {
            return Feasibility::Walled(WallReason::VariableBudgetExceeded);
        };
        remap.insert(original, dense);
    }
    let compacted: Vec<Constraint> = state
        .constraints
        .iter()
        .map(|constraint: &Constraint| Constraint {
            predicate: remap_predicate(&constraint.predicate, &remap),
            expect: constraint.expect,
            width: constraint.width,
        })
        .collect();
    if (!max_width.is_exhaustible() || var_count > MAX_FEASIBILITY_VARS)
        && let Some(result) = solver_feasibility(&compacted, max_width)
    {
        return result;
    }
    if var_count > MAX_FEASIBILITY_VARS {
        return Feasibility::Walled(WallReason::VariableBudgetExceeded);
    }
    let total: u128 = domain_size(eval_width, var_count);
    if total > MAX_FEASIBILITY_EVALS {
        if let Some(result) = solver_feasibility(&compacted, max_width) {
            return result;
        }
        return Feasibility::Walled(WallReason::NonExhaustibleDomain);
    }
    let mut env: Vec<u64> = vec![0; var_count as usize];
    for assignment in 0..total {
        decode_assignment(assignment, eval_width, &mut env);
        if compacted
            .iter()
            .all(|c: &Constraint| c.predicate.evaluate(&env, eval_width) == c.expect)
        {
            return Feasibility::Satisfiable;
        }
    }
    Feasibility::Unsatisfiable
}

fn solver_feasibility(compacted: &[Constraint], width: Width) -> Option<Feasibility> {
    let predicate: Predicate = combined_expected_predicate(compacted)?;
    match classify_predicate(&predicate, width) {
        OpaqueVerdict::AlwaysFalse { .. } => Some(Feasibility::Unsatisfiable),
        OpaqueVerdict::AlwaysTrue { .. } | OpaqueVerdict::DataDependent => {
            Some(Feasibility::Satisfiable)
        }
        OpaqueVerdict::OutOfBudget => None,
    }
}

fn combined_expected_predicate(compacted: &[Constraint]) -> Option<Predicate> {
    let mut iter: std::slice::Iter<'_, Constraint> = compacted.iter();
    let first: &Constraint = iter.next()?;
    let mut acc: Predicate = expected_predicate(first);
    for constraint in iter {
        let constraint: &Constraint = constraint;
        acc = Predicate::and(acc, expected_predicate(constraint));
    }
    Some(acc)
}

fn expected_predicate(constraint: &Constraint) -> Predicate {
    if constraint.expect {
        constraint.predicate.clone()
    } else {
        negate_predicate(&constraint.predicate)
    }
}

fn negate_predicate(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::Nonzero(inner) => Predicate::eq(inner.clone(), Expr::konst(0)),
        Predicate::Compare { op, left, right } => Predicate::Compare {
            op: invert_cmp(*op),
            left: left.clone(),
            right: right.clone(),
        },
        Predicate::Or(left, right) => {
            Predicate::and(negate_predicate(left), negate_predicate(right))
        }
        Predicate::And(left, right) => {
            Predicate::or(negate_predicate(left), negate_predicate(right))
        }
    }
}

const fn invert_cmp(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Eq => CmpOp::Ne,
        CmpOp::Ne => CmpOp::Eq,
        CmpOp::UnsignedLt => CmpOp::UnsignedGe,
        CmpOp::UnsignedLe => CmpOp::UnsignedGt,
        CmpOp::UnsignedGt => CmpOp::UnsignedLe,
        CmpOp::UnsignedGe => CmpOp::UnsignedLt,
        CmpOp::SignedLt => CmpOp::SignedGe,
        CmpOp::SignedLe => CmpOp::SignedGt,
        CmpOp::SignedGt => CmpOp::SignedLe,
        CmpOp::SignedGe => CmpOp::SignedLt,
    }
}

fn domain_size(width: Width, var_count: u32) -> u128 {
    let modulus: u128 = width.modulus();
    let mut acc: u128 = 1;
    for _ in 0..var_count {
        acc = acc.saturating_mul(modulus);
    }
    acc
}

fn decode_assignment(mut index: u128, width: Width, env: &mut [u64]) {
    let modulus: u128 = width.modulus();
    for slot in env.iter_mut() {
        *slot = (index % modulus) as u64;
        index /= modulus;
    }
}

fn collect_predicate_vars(predicate: &Predicate, into: &mut BTreeSet<u32>) {
    match predicate {
        Predicate::Nonzero(inner) => inner.collect_vars(into),
        Predicate::Compare { left, right, .. } => {
            left.collect_vars(into);
            right.collect_vars(into);
        }
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            collect_predicate_vars(left, into);
            collect_predicate_vars(right, into);
        }
    }
}

fn remap_predicate(predicate: &Predicate, remap: &BTreeMap<u32, u32>) -> Predicate {
    match predicate {
        Predicate::Nonzero(inner) => Predicate::Nonzero(inner.remap_vars(remap)),
        Predicate::Compare { op, left, right } => Predicate::Compare {
            op: *op,
            left: left.remap_vars(remap),
            right: right.remap_vars(remap),
        },
        Predicate::Or(left, right) => {
            Predicate::or(remap_predicate(left, remap), remap_predicate(right, remap))
        }
        Predicate::And(left, right) => {
            Predicate::and(remap_predicate(left, remap), remap_predicate(right, remap))
        }
    }
}

fn build_branch_predicate(
    regs: &mut RegFile,
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    match cmp.mnemonic() {
        Mnemonic::Cmp => {
            if cmp.op0_kind() != OpKind::Register {
                return None;
            }
            let width: Width = register_width(cmp.op0_register());
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let op: CmpOp = branch_to_cmp(branch)?;
            Some((Predicate::Compare { op, left, right }, width))
        }
        Mnemonic::Test => {
            if cmp.op0_kind() != OpKind::Register {
                return None;
            }
            let width: Width = register_width(cmp.op0_register());
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let masked: Expr = Expr::and(left, right);
            let predicate: Predicate = match branch {
                Mnemonic::Je => Predicate::eq(masked, Expr::konst(0)),
                Mnemonic::Jne => Predicate::nonzero(masked),
                _ => return None,
            };
            Some((predicate, width))
        }
        _ => None,
    }
}

fn operand_expr(regs: &mut RegFile, cmp: &Instruction, operand: u32) -> Option<Expr> {
    match cmp.op_kind(operand) {
        OpKind::Register => Some(regs.current(cmp.op_register(operand))),
        OpKind::Immediate8 => Some(Expr::konst(u64::from(cmp.immediate8()))),
        OpKind::Immediate16 => Some(Expr::konst(u64::from(cmp.immediate16()))),
        OpKind::Immediate32 => Some(Expr::konst(u64::from(cmp.immediate32()))),
        OpKind::Immediate64 => Some(Expr::konst(cmp.immediate64())),
        OpKind::Immediate8to16 => Some(Expr::konst(cmp.immediate8to16().cast_unsigned().into())),
        OpKind::Immediate8to32 => Some(Expr::konst(cmp.immediate8to32().cast_unsigned().into())),
        OpKind::Immediate8to64 => Some(Expr::konst(cmp.immediate8to64().cast_unsigned())),
        OpKind::Immediate32to64 => Some(Expr::konst(cmp.immediate32to64().cast_unsigned())),
        _ => None,
    }
}

fn register_width(reg: Register) -> Width {
    match reg.size() {
        1 => Width::W8,
        2 => Width::W16,
        4 => Width::W32,
        _ => Width::W64,
    }
}

const fn branch_to_cmp(branch: Mnemonic) -> Option<CmpOp> {
    match branch {
        Mnemonic::Je => Some(CmpOp::Eq),
        Mnemonic::Jne => Some(CmpOp::Ne),
        Mnemonic::Jb => Some(CmpOp::UnsignedLt),
        Mnemonic::Jbe => Some(CmpOp::UnsignedLe),
        Mnemonic::Ja => Some(CmpOp::UnsignedGt),
        Mnemonic::Jae => Some(CmpOp::UnsignedGe),
        Mnemonic::Jl => Some(CmpOp::SignedLt),
        Mnemonic::Jle => Some(CmpOp::SignedLe),
        Mnemonic::Jg => Some(CmpOp::SignedGt),
        Mnemonic::Jge => Some(CmpOp::SignedGe),
        _ => None,
    }
}

fn record_wall(report: &mut PathSenseReport, reason: WallReason) {
    let label: String = wall_label(reason).to_owned();
    if !report.walls.contains(&label) {
        report.walls.push(label);
    }
}

const fn wall_label(reason: WallReason) -> &'static str {
    match reason {
        WallReason::ConstraintBudgetExceeded => "path constraint count exceeded exhaustive budget",
        WallReason::VariableBudgetExceeded => {
            "correlated free-variable count exceeds the bounded solver input budget"
        }
        WallReason::NonExhaustibleDomain => {
            "joint variable domain exceeds exhaustive fallback and bounded solver budget"
        }
        WallReason::SymbolicStateCapped => {
            "symbolic state hit the expression-node cap before the branch"
        }
    }
}

fn dedup(report: &mut PathSenseReport) {
    let mut seen: BTreeSet<(u64, u64, bool)> = BTreeSet::new();
    report.dead_edges.retain(|edge: &DeadEdge| {
        seen.insert((edge.branch_address, edge.dead_target, edge.edge_taken))
    });
    report
        .dead_edges
        .sort_by_key(|edge: &DeadEdge| (edge.branch_address, edge.dead_target));
}

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_DECODE_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
