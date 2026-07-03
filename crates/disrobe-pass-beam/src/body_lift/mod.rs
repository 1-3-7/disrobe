mod bin_clauses;
pub mod binmatch;
pub mod clause;
mod codegen;
pub mod comprehension;
mod control_flow;
pub mod expr;
pub mod render;
pub mod resugar;
pub mod simplify;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::body_lift::expr::{
    AfterClause, BifKind, BinSegment, CaseArm, CatchArm, Expr, IfArm, MAX_EXPR_NODES, Stmt,
    bif_operator, expr_node_count_capped, is_guard_bif,
};
use crate::chunks::Chunks;
use crate::disasm::{Instruction, Operand};
use crate::etf::Term;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedBody {
    pub stmts: Vec<Stmt>,

    pub lift_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reg {
    X(u32),
    Y(u32),
    F(u32),
}

#[derive(Debug, Clone, Copy)]
struct Block {
    start: usize,
    end: usize,
}

#[must_use]
pub fn build_label_index(chunks: &Chunks) -> BTreeMap<u32, (String, u32)> {
    let mut map: BTreeMap<u32, (String, u32)> = BTreeMap::new();
    for e in &chunks.exports {
        if let Some(n) = chunks.atoms.get(e.function_atom_index) {
            map.insert(e.label, (n.to_owned(), e.arity));
        }
    }
    for l in &chunks.locals {
        if let Some(n) = chunks.atoms.get(l.function_atom_index) {
            map.insert(l.label, (n.to_owned(), l.arity));
        }
    }
    for f in &chunks.funs {
        if let Some(n) = chunks.atoms.get(f.function_atom_index) {
            map.insert(f.label, (n.to_owned(), f.arity));
        }
    }
    map
}

#[derive(Debug, Default, Clone)]
struct Env {
    regs: BTreeMap<Reg, Expr>,
    bin_ctx: BTreeMap<Reg, BinMatchState>,
}

#[derive(Debug, Clone)]
struct BinMatchState {
    source: Reg,
    segments: Vec<BinSegment>,
}

impl Env {
    fn get(&self, reg: Reg) -> Expr {
        self.regs.get(&reg).cloned().unwrap_or_else(|| reg.var())
    }

    fn set(&mut self, reg: Reg, value: Expr) {
        self.regs.insert(reg, value);
    }
}

impl Reg {
    fn var(self) -> Expr {
        match self {
            Self::X(r) => Expr::Var(format!("X{r}")),
            Self::Y(r) => Expr::Var(format!("Y{r}")),
            Self::F(r) => Expr::Var(format!("Fr{r}")),
        }
    }
}

#[derive(Debug)]
struct Lifter<'a> {
    chunks: &'a Chunks,
    instrs: &'a [Instruction],
    blocks: BTreeMap<u32, Block>,
    label_to_fun: &'a BTreeMap<u32, (String, u32)>,
    literals: &'a [Term],
    arity: u32,
}

#[must_use]
pub fn lift_body(
    instrs: &[Instruction],
    arity: u32,
    chunks: &Chunks,
    label_to_fun: &BTreeMap<u32, (String, u32)>,
) -> LiftedBody {
    let empty: Vec<Term> = Vec::new();
    let literals: &[Term] = chunks
        .literals
        .as_ref()
        .map_or(empty.as_slice(), |l| l.literals.as_slice());
    let lifter: Lifter<'_> = Lifter {
        chunks,
        instrs,
        blocks: index_blocks(instrs),
        label_to_fun,
        literals,
        arity,
    };
    let entry: Option<u32> = lifter.blocks.keys().next().copied();
    let Some(entry) = entry else {
        return LiftedBody {
            stmts: vec![Stmt::Return(Expr::Atom("ok".to_owned()))],
            lift_complete: false,
        };
    };
    let mut env: Env = Env::default();
    for i in 0..arity {
        env.set(Reg::X(i), Reg::X(i).var());
    }
    let mut flags: Flags = Flags::default();
    let stmts: Vec<Stmt> = lifter.walk(entry, &mut env.clone(), &mut flags, 0);
    let stmts: Vec<Stmt> = if stmts.is_empty() {
        flags.degraded = true;
        vec![Stmt::Return(Expr::Atom("ok".to_owned()))]
    } else {
        resugar::resugar_body(simplify::simplify_body(stmts))
    };
    let unresolved: bool = stmts.iter().any(has_unrecovered_marker);
    LiftedBody {
        stmts,
        lift_complete: !flags.degraded && !unresolved,
    }
}

#[must_use]
pub fn lift_function(
    instrs: &[Instruction],
    arity: u32,
    chunks: &Chunks,
    label_to_fun: &BTreeMap<u32, (String, u32)>,
) -> (Vec<expr::FnClause>, bool) {
    let empty: Vec<Term> = Vec::new();
    let literals: &[Term] = chunks
        .literals
        .as_ref()
        .map_or(empty.as_slice(), |l| l.literals.as_slice());
    let lifter: Lifter<'_> = Lifter {
        chunks,
        instrs,
        blocks: index_blocks(instrs),
        label_to_fun,
        literals,
        arity,
    };
    let Some(entry): Option<u32> = lifter.blocks.keys().next().copied() else {
        return (
            vec![expr::FnClause {
                patterns: var_params(arity),
                guard: None,
                body: vec![Stmt::Return(Expr::Atom("ok".to_owned()))],
            }],
            false,
        );
    };
    if let Some((clauses, ok)) = lifter.reconstruct_binary_clauses(entry) {
        return (clauses, ok);
    }
    let body: LiftedBody = lift_body(instrs, arity, chunks, label_to_fun);
    let clauses: Vec<expr::FnClause> = clause::reconstruct_clauses(arity, &body.stmts)
        .unwrap_or_else(|| {
            vec![expr::FnClause {
                patterns: var_params(arity),
                guard: None,
                body: body.stmts.clone(),
            }]
        });
    (clauses, body.lift_complete)
}

fn var_params(arity: u32) -> Vec<Expr> {
    (0..arity)
        .map(|i: u32| Expr::Var(format!("X{i}")))
        .collect()
}

fn has_unrecovered_marker(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Comment(_) => true,
        Stmt::Return(e) | Stmt::Expr(e) => expr_has_marker(e),
        Stmt::Bind { value, .. } | Stmt::Match { value, .. } => expr_has_marker(value),
        Stmt::Send { dest, msg } => expr_has_marker(dest) || expr_has_marker(msg),
    }
}

fn expr_has_marker(expr: &Expr) -> bool {
    match expr {
        Expr::Case { subject, arms } => {
            expr_has_marker(subject)
                || arms
                    .iter()
                    .any(|a: &CaseArm| a.body.iter().any(has_unrecovered_marker))
        }
        Expr::If { arms } => arms.iter().any(|a: &IfArm| {
            expr_has_marker(&a.guard) || a.body.iter().any(has_unrecovered_marker)
        }),
        Expr::Receive { arms, after } => {
            arms.iter()
                .any(|a: &CaseArm| a.body.iter().any(has_unrecovered_marker))
                || after
                    .as_deref()
                    .is_some_and(|a: &AfterClause| a.body.iter().any(has_unrecovered_marker))
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            body.iter().any(has_unrecovered_marker)
                || of_arms
                    .iter()
                    .any(|a: &CaseArm| a.body.iter().any(has_unrecovered_marker))
                || catch_arms
                    .iter()
                    .any(|a: &CatchArm| a.body.iter().any(has_unrecovered_marker))
                || after.iter().any(has_unrecovered_marker)
        }
        Expr::Catch(inner) => expr_has_marker(inner),
        Expr::Block(stmts) => stmts.iter().any(has_unrecovered_marker),
        _ => false,
    }
}

#[derive(Debug, Default)]
struct Flags {
    degraded: bool,
    var_counter: u32,
    pat_counter: u32,
    in_progress: std::collections::BTreeSet<u32>,
    visit_counts: std::collections::BTreeMap<u32, u32>,
    walk_calls: u32,
}

const SYNTH_LABEL_FLOOR: u32 = u32::MAX - 1;
const MAX_LABEL_VISITS: u32 = 8;
const MAX_WALK_CALLS: u32 = 20_000;

impl Flags {
    fn fresh_var(&mut self) -> String {
        let n: u32 = self.var_counter;
        self.var_counter += 1;
        format!("V{n}")
    }

    fn fresh_pat(&mut self) -> String {
        let n: u32 = self.pat_counter;
        self.pat_counter += 1;
        format!("B{n}")
    }

    fn over_walk_budget(&mut self) -> bool {
        self.walk_calls = self.walk_calls.saturating_add(1);
        self.walk_calls > MAX_WALK_CALLS
    }

    fn enter_label(&mut self, label: u32) -> WalkEntry {
        if label >= SYNTH_LABEL_FLOOR {
            return WalkEntry::Ok;
        }
        if !self.in_progress.insert(label) {
            return WalkEntry::Cyclic;
        }
        let count: &mut u32 = self.visit_counts.entry(label).or_insert(0);
        *count = count.saturating_add(1);
        if *count > MAX_LABEL_VISITS {
            self.in_progress.remove(&label);
            return WalkEntry::Saturated;
        }
        WalkEntry::Ok
    }

    fn leave_label(&mut self, label: u32) {
        if label < SYNTH_LABEL_FLOOR {
            self.in_progress.remove(&label);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkEntry {
    Ok,
    Cyclic,
    Saturated,
}

fn index_blocks(instrs: &[Instruction]) -> BTreeMap<u32, Block> {
    let mut blocks: BTreeMap<u32, Block> = BTreeMap::new();
    let mut current: Option<(u32, usize)> = None;
    for (i, ins) in instrs.iter().enumerate() {
        if ins.name == "label"
            && let Some(Operand::Literal(v)) = ins.operands.first()
        {
            if let Some((label, start)) = current.take() {
                blocks.insert(label, Block { start, end: i });
            }
            current = Some((u32::try_from(*v).unwrap_or(0), i + 1));
        }
    }
    if let Some((label, start)) = current.take() {
        blocks.insert(
            label,
            Block {
                start,
                end: instrs.len(),
            },
        );
    }
    blocks
}

const TEST_OPS: &[&str] = &[
    "is_lt",
    "is_ge",
    "is_eq",
    "is_ne",
    "is_eq_exact",
    "is_ne_exact",
    "is_integer",
    "is_float",
    "is_number",
    "is_atom",
    "is_pid",
    "is_reference",
    "is_port",
    "is_nil",
    "is_binary",
    "is_list",
    "is_nonempty_list",
    "is_tuple",
    "is_map",
    "is_boolean",
    "is_bitstr",
    "is_function",
    "is_function2",
    "test_arity",
    "is_tagged_tuple",
    "has_map_fields",
];

impl Lifter<'_> {
    #[allow(clippy::too_many_lines)]
    fn walk(&self, label: u32, env: &mut Env, flags: &mut Flags, depth: u32) -> Vec<Stmt> {
        if depth > 400 || flags.over_walk_budget() {
            flags.degraded = true;
            return Vec::new();
        }
        match flags.enter_label(label) {
            WalkEntry::Ok => {}
            WalkEntry::Cyclic => {
                flags.degraded = true;
                return vec![Stmt::Comment(format!("cyclic block L{label}"))];
            }
            WalkEntry::Saturated => {
                flags.degraded = true;
                return vec![Stmt::Comment(format!(
                    "shared block L{label} fan-in capped"
                ))];
            }
        }
        let out: Vec<Stmt> = self.walk_block(label, env, flags, depth);
        flags.leave_label(label);
        out
    }

    fn walk_block(&self, label: u32, env: &mut Env, flags: &mut Flags, depth: u32) -> Vec<Stmt> {
        let mut out: Vec<Stmt> = Vec::new();
        let Some(block) = self.blocks.get(&label).copied() else {
            return out;
        };
        let mut idx: usize = block.start;
        while idx < block.end {
            let ins: &Instruction = &self.instrs[idx];
            let name: &str = ins.name;
            if TEST_OPS.contains(&name) {
                if let Some(stmt) = self.reconstruct_branch(&block, idx, env, flags, depth) {
                    out.push(stmt);
                    return out;
                }
                idx += 1;
                continue;
            }
            match name {
                "line"
                | "func_info"
                | "label"
                | "allocate"
                | "allocate_zero"
                | "allocate_heap"
                | "allocate_heap_zero"
                | "test_heap"
                | "init"
                | "init_yregs"
                | "deallocate"
                | "fclearerror"
                | "fcheckerror"
                | "recv_mark"
                | "recv_set"
                | "recv_marker_bind"
                | "recv_marker_clear"
                | "recv_marker_reserve"
                | "recv_marker_use"
                | "nif_start"
                | "timeout"
                | "remove_message" => {}
                "bs_init_writable" => env.set(Reg::X(0), Expr::BinaryLit(Vec::new())),
                "trim" => Self::exec_trim(ins, env),
                "move" | "swap" | "fmove" | "fconv" => self.exec_move(ins, env),
                "fadd" | "fsub" | "fmul" | "fdiv" | "fnegate" => {
                    self.exec_float_arith(ins, env);
                }
                "put_list" => self.exec_put_list(ins, env, flags),
                "put_tuple2" => self.exec_put_tuple2(ins, env, flags),
                "put_tuple" => {
                    idx = self.exec_put_tuple_old(ins, idx, block.end, env, flags);
                    idx += 1;
                    continue;
                }
                "get_list" => self.exec_get_list(ins, env),
                "get_hd" => self.exec_unary_dest(ins, "hd", env),
                "get_tl" => self.exec_unary_dest(ins, "tl", env),
                "get_tuple_element" => self.exec_get_tuple_element(ins, env),
                "put_map_assoc" | "put_map_exact" => self.exec_put_map(ins, env),
                "update_record" => self.exec_update_record(ins, env),
                "get_map_elements" => {
                    let fail: u32 = label_of(&ins.operands[0]);
                    if self.fail_leads_to_clause(fail) {
                        out.push(Stmt::Return(
                            self.build_map_match_branch(&block, idx, fail, env, flags, depth),
                        ));
                        return out;
                    }
                    if let Some(stmt) = self.exec_get_map_elements(ins, env, flags) {
                        out.push(stmt);
                    }
                }
                "bif0" | "bif1" | "bif2" => self.exec_bif(ins, env, flags),
                "gc_bif1" | "gc_bif2" | "gc_bif3" => self.exec_gc_bif(ins, env, flags),
                "call" | "call_only" | "call_last" => {
                    if self.exec_call_local(ins, env, &mut out, flags) {
                        return out;
                    }
                }
                "call_ext" | "call_ext_only" | "call_ext_last" => {
                    if self.exec_call_ext(ins, env, &mut out, flags) {
                        return out;
                    }
                }
                "call_fun" | "call_fun2" => {
                    if self.exec_call_fun(ins, env, &mut out, flags) {
                        return out;
                    }
                }
                "apply" | "apply_last" => {
                    if exec_apply(ins, env, &mut out, flags) {
                        return out;
                    }
                }
                "make_fun2" | "make_fun3" | "make_fun" => self.exec_make_fun(ins, env),
                "bs_create_bin" => self.exec_bs_create_bin(ins, env, flags),
                "bs_start_match" | "bs_start_match2" | "bs_start_match3" | "bs_start_match4" => {
                    Self::exec_bs_start_match(ins, env);
                }
                "bs_match" => {
                    let fail: u32 = label_of(&ins.operands[0]);
                    if self.fail_leads_to_clause(fail)
                        && let Some(items) = bs_match_commands(ins)
                        && !is_ensure_exactly_zero(items, self.chunks)
                    {
                        out.push(Stmt::Return(
                            self.build_bin_match_branch(&block, idx, fail, env, flags, depth),
                        ));
                        return out;
                    }
                    if let Some(stmt) = self.exec_bs_match(ins, env, flags) {
                        out.push(stmt);
                    }
                }
                "bs_get_tail" => Self::exec_bs_get_tail(ins, env, flags),
                "bs_get_position" | "bs_set_position" => {}
                "send" => out.push(exec_send(env)),
                "select_val" => {
                    out.push(Stmt::Return(self.build_select_val(ins, env, flags, depth)));
                    return out;
                }
                "select_tuple_arity" => {
                    out.push(Stmt::Return(
                        self.build_select_tuple_arity(ins, env, flags, depth),
                    ));
                    return out;
                }
                "jump" => {
                    if let Some(Operand::Label(l)) = ins.operands.first() {
                        out.extend(self.walk(*l, env, flags, depth + 1));
                    }
                    return out;
                }
                "loop_rec" => {
                    out.push(Stmt::Return(self.build_receive(label, env, flags, depth)));
                    return out;
                }
                "wait" | "wait_timeout" | "loop_rec_end" => return out,
                "return" => {
                    out.push(Stmt::Return(env.get(Reg::X(0))));
                    return out;
                }
                "catch" => {
                    let catch_end: usize =
                        self.region_end(idx + 1, self.instrs.len(), &["catch_end"]);
                    let value: Expr = self.build_catch(idx, catch_end, env, flags, depth);
                    let var: String = flags.fresh_var();
                    out.push(Stmt::Bind {
                        pattern: Expr::Var(var.clone()),
                        value,
                    });
                    env.set(Reg::X(0), Expr::Var(var));
                    idx = catch_end + 1;
                    continue;
                }
                "try" => {
                    out.push(Stmt::Return(self.build_try(idx, env, flags, depth)));
                    return out;
                }
                "badmatch" | "case_end" | "if_end" | "badrecord" | "try_case_end" => {
                    out.push(Stmt::Comment(format!("match failure ({name})")));
                    return out;
                }
                "catch_end" | "try_end" | "try_case" => {}
                "build_stacktrace" => {}
                "raise" | "raw_raise" => {
                    out.push(self.build_raise(ins, env));
                    return out;
                }
                _ => flags.degraded = true,
            }
            idx += 1;
        }
        if let Some(next) = self.fall_through_label(block.end) {
            out.extend(self.walk(next, env, flags, depth + 1));
        }
        out
    }

    fn fall_through_label(&self, end: usize) -> Option<u32> {
        let ins: &Instruction = self.instrs.get(end)?;
        if ins.name != "label" {
            return None;
        }
        match ins.operands.first() {
            Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
            _ => None,
        }
    }
}

fn is_reraise(body: &[Stmt]) -> bool {
    matches!(
        body,
        [Stmt::Return(Expr::Call { target, .. })] if target == "erlang:raise"
    )
}

fn class_from_guard(guard: &Expr) -> (String, Option<Expr>) {
    let conds: Vec<Expr> = split_andalso(guard.clone());
    let mut class: Option<String> = None;
    let mut rest: Vec<Expr> = Vec::new();
    for cond in conds {
        match &cond {
            Expr::BinOp { op, lhs, rhs }
                if op == "=:=" && matches!(&**lhs, Expr::Var(v) if v == "Class") =>
            {
                if let Expr::Atom(a) = &**rhs {
                    class = Some(a.clone());
                    continue;
                }
                rest.push(cond);
            }
            _ => rest.push(cond),
        }
    }
    let combined: Option<Expr> = (!rest.is_empty()).then(|| combine_guard(rest));
    (class.unwrap_or_else(|| "Class".to_owned()), combined)
}

fn split_andalso(expr: Expr) -> Vec<Expr> {
    match expr {
        Expr::BinOp { op, lhs, rhs } if op == "andalso" => {
            let mut out: Vec<Expr> = split_andalso(*lhs);
            out.extend(split_andalso(*rhs));
            out
        }
        other => vec![other],
    }
}

#[must_use]
pub fn stmts_reference_var(body: &[Stmt], name: &str) -> bool {
    body_uses_var(body, name)
}

fn body_uses_var(body: &[Stmt], name: &str) -> bool {
    body.iter().any(|s: &Stmt| stmt_uses_var(s, name))
}

fn stmt_uses_var(stmt: &Stmt, name: &str) -> bool {
    match stmt {
        Stmt::Return(e) | Stmt::Expr(e) => expr_uses_var(e, name),
        Stmt::Bind { value, .. } | Stmt::Match { value, .. } => expr_uses_var(value, name),
        Stmt::Send { dest, msg } => expr_uses_var(dest, name) || expr_uses_var(msg, name),
        Stmt::Comment(_) => false,
    }
}

fn expr_uses_var(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Var(v) => v == name,
        Expr::Tuple(items) => items.iter().any(|e: &Expr| expr_uses_var(e, name)),
        Expr::List { elements, tail } => {
            elements.iter().any(|e: &Expr| expr_uses_var(e, name)) || expr_uses_var(tail, name)
        }
        Expr::Cons { head, tail } => expr_uses_var(head, name) || expr_uses_var(tail, name),
        Expr::Map { pairs } | Expr::MapPattern { pairs } | Expr::MapUpdate { pairs, .. } => pairs
            .iter()
            .any(|(k, v): &(Expr, Expr)| expr_uses_var(k, name) || expr_uses_var(v, name)),
        Expr::TupleElement { tuple, .. } => expr_uses_var(tuple, name),
        Expr::RecordUpdate { base, updates } => {
            expr_uses_var(base, name)
                || updates
                    .iter()
                    .any(|(_, v): &(u32, Expr)| expr_uses_var(v, name))
        }
        Expr::Call { args, .. } | Expr::Guard { args, .. } => {
            args.iter().any(|e: &Expr| expr_uses_var(e, name))
        }
        Expr::BinOp { lhs, rhs, .. } => expr_uses_var(lhs, name) || expr_uses_var(rhs, name),
        Expr::UnOp { operand, .. } => expr_uses_var(operand, name),
        Expr::CallFun { fun, args } => {
            expr_uses_var(fun, name) || args.iter().any(|e: &Expr| expr_uses_var(e, name))
        }
        Expr::BinaryConstruct(segs) => segs.iter().any(|s: &BinSegment| {
            expr_uses_var(&s.value, name)
                || s.size
                    .as_deref()
                    .is_some_and(|sz: &Expr| expr_uses_var(sz, name))
        }),
        Expr::Catch(inner) => expr_uses_var(inner, name),
        Expr::Case { subject, arms } => {
            expr_uses_var(subject, name)
                || arms.iter().any(|a: &CaseArm| body_uses_var(&a.body, name))
        }
        Expr::If { arms } => arms
            .iter()
            .any(|a: &IfArm| expr_uses_var(&a.guard, name) || body_uses_var(&a.body, name)),
        Expr::Receive { arms, after } => {
            arms.iter().any(|a: &CaseArm| body_uses_var(&a.body, name))
                || after
                    .as_deref()
                    .is_some_and(|a: &AfterClause| body_uses_var(&a.body, name))
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            body_uses_var(body, name)
                || of_arms
                    .iter()
                    .any(|a: &CaseArm| body_uses_var(&a.body, name))
                || catch_arms
                    .iter()
                    .any(|a: &CatchArm| body_uses_var(&a.body, name))
                || body_uses_var(after, name)
        }
        Expr::Block(stmts) => body_uses_var(stmts, name),
        _ => false,
    }
}

#[derive(Debug)]
struct BinaryClause {
    segments: Vec<BinSegment>,
    body: Vec<Stmt>,
    fails: Vec<u32>,
    degraded: bool,
    wildcard: bool,
}

#[derive(Debug)]
struct BinShared {
    all_segments: Vec<BinSegment>,
    pos_len: BTreeMap<Reg, usize>,
    seg_vars: Vec<String>,
    seg_dsts: Vec<Option<Reg>>,
}

fn close_pattern(
    prefix: &[BinSegment],
    exact: bool,
    ctx: Option<Reg>,
    env: &mut Env,
    flags: &mut Flags,
) -> Vec<BinSegment> {
    let mut segments: Vec<BinSegment> = prefix.to_vec();
    let already_tail: bool = segments
        .last()
        .is_some_and(|s: &BinSegment| s.kind == "binary" && s.size.is_none());
    if exact || already_tail {
        return segments;
    }
    let var: String = flags.fresh_pat();
    if let Some(reg) = ctx {
        env.set(reg, Expr::Var(var.clone()));
    }
    segments.push(BinSegment {
        value: Box::new(Expr::Var(var)),
        size: None,
        unit: 8,
        kind: "binary".to_owned(),
        flags: Vec::new(),
    });
    segments
}

fn rebind_prefix(shared: &BinShared, len: usize, env: &mut Env) {
    for i in 0..len.min(shared.seg_vars.len()) {
        if let Some(dst) = shared.seg_dsts.get(i).copied().flatten() {
            env.set(dst, Expr::Var(shared.seg_vars[i].clone()));
        }
    }
}

fn bs_match_commands(ins: &Instruction) -> Option<&[Operand]> {
    match ins.operands.get(2) {
        Some(Operand::List(items)) => Some(items.as_slice()),
        _ => None,
    }
}

fn is_ensure_exactly_zero(items: &[Operand], chunks: &Chunks) -> bool {
    matches!(items.first(), Some(Operand::Atom(a)) if chunks.atoms.get(*a) == Some("ensure_exactly"))
        && matches!(items.get(1), Some(Operand::Literal(0)))
}

fn class_of_trace(_trace: &Expr) -> Expr {
    Expr::Var("Class".to_owned())
}

fn catch_value(body: Vec<Stmt>, env: &Env) -> Expr {
    match body.as_slice() {
        [] => env.get(Reg::X(0)),
        [Stmt::Return(e) | Stmt::Expr(e)] => e.clone(),
        [Stmt::Bind { value, .. }] => value.clone(),
        _ => Expr::Block(body),
    }
}

fn guard(name: &str, args: Vec<Expr>) -> Expr {
    Expr::Guard {
        name: name.to_owned(),
        args,
    }
}

fn build_bif_expr(module: &str, name: &str, arity: u32, args: &[Expr]) -> Expr {
    if module == "erlang"
        && let Some(kind) = bif_operator(name, arity)
    {
        return match (kind, args) {
            (BifKind::Binary(op), [lhs, rhs]) => Expr::BinOp {
                op: op.to_owned(),
                lhs: Box::new(lhs.clone()),
                rhs: Box::new(rhs.clone()),
            },
            (BifKind::Unary(op), [operand]) => Expr::UnOp {
                op: op.to_owned(),
                operand: Box::new(operand.clone()),
            },
            _ => plain_call(module, name, args),
        };
    }
    if module == "erlang" && is_guard_bif(name) {
        return guard(name, args.to_vec());
    }
    plain_call(module, name, args)
}

pub(super) fn call_ext_expr(module: &str, name: &str, arity: u32, args: &[Expr]) -> Expr {
    if module == "erlang"
        && let Some(kind) = bif_operator(name, arity)
    {
        match (kind, args) {
            (BifKind::Binary(op), [lhs, rhs]) => {
                return Expr::BinOp {
                    op: op.to_owned(),
                    lhs: Box::new(lhs.clone()),
                    rhs: Box::new(rhs.clone()),
                };
            }
            (BifKind::Unary(op), [operand]) => {
                return Expr::UnOp {
                    op: op.to_owned(),
                    operand: Box::new(operand.clone()),
                };
            }
            _ => {}
        }
    }
    plain_call(module, name, args)
}

fn plain_call(module: &str, name: &str, args: &[Expr]) -> Expr {
    let target: String = if module == "erlang" && is_auto_imported(name, args.len()) {
        render::render_atom(name)
    } else {
        format!(
            "{}:{}",
            render::render_atom(module),
            render::render_atom(name)
        )
    };
    Expr::Call {
        target,
        args: args.to_vec(),
    }
}

fn is_auto_imported(name: &str, arity: usize) -> bool {
    !matches!(
        (name, arity),
        ("raise", 2 | 3)
            | ("raw_raise", 3)
            | ("apply", 2)
            | ("get_module_info", 1 | 2)
            | ("dt_get_tag", 0)
            | ("dt_spread_tag", 1)
    )
}

fn finish_call(
    name: &str,
    call: Expr,
    env: &mut Env,
    out: &mut Vec<Stmt>,
    flags: &mut Flags,
) -> bool {
    if name.ends_with("only") || name.ends_with("last") {
        out.push(Stmt::Return(call));
        true
    } else {
        let var: String = flags.fresh_var();
        out.push(Stmt::Bind {
            pattern: Expr::Var(var.clone()),
            value: call,
        });
        env.set(Reg::X(0), Expr::Var(var));
        false
    }
}

fn exec_apply(ins: &Instruction, env: &mut Env, out: &mut Vec<Stmt>, flags: &mut Flags) -> bool {
    let arity: u32 = literal_u32(&ins.operands[0]);
    let mut args: Vec<Expr> = vec![env.get(Reg::X(arity)), env.get(Reg::X(arity + 1))];
    args.extend((0..arity).map(|i: u32| env.get(Reg::X(i))));
    finish_call(
        ins.name,
        Expr::Call {
            target: "apply".to_owned(),
            args,
        },
        env,
        out,
        flags,
    )
}

fn exec_send(env: &mut Env) -> Stmt {
    let dest: Expr = env.get(Reg::X(0));
    let msg: Expr = env.get(Reg::X(1));
    env.set(Reg::X(0), msg.clone());
    Stmt::Send { dest, msg }
}

fn combine_guard(conds: Vec<Expr>) -> Expr {
    let mut iter: std::vec::IntoIter<Expr> = conds.into_iter();
    let first: Expr = iter.next().unwrap_or(Expr::Atom("true".to_owned()));
    iter.fold(first, |acc: Expr, next: Expr| Expr::BinOp {
        op: "andalso".to_owned(),
        lhs: Box::new(acc),
        rhs: Box::new(next),
    })
}

fn make_cons(head: Expr, tail: Expr) -> Expr {
    match tail {
        Expr::Nil => Expr::List {
            elements: vec![head],
            tail: Box::new(Expr::Nil),
        },
        Expr::List { mut elements, tail } => {
            elements.insert(0, head);
            Expr::List { elements, tail }
        }
        other => Expr::Cons {
            head: Box::new(head),
            tail: Box::new(other),
        },
    }
}

fn bounded_set(env: &mut Env, reg: Reg, value: Expr, flags: &mut Flags) {
    if expr_node_count_capped(&value, MAX_EXPR_NODES) >= MAX_EXPR_NODES {
        flags.degraded = true;
        env.set(reg, Expr::Raw("'-disrobe-oversized-'".to_owned()));
    } else {
        env.set(reg, value);
    }
}

fn as_reg(op: &Operand) -> Option<Reg> {
    match op {
        Operand::XReg(r) => Some(Reg::X(*r)),
        Operand::YReg(r) => Some(Reg::Y(*r)),
        Operand::FpReg(r) => Some(Reg::F(*r)),
        Operand::TypedReg { reg, .. } => as_reg(reg),
        _ => None,
    }
}

fn literal_u32(op: &Operand) -> u32 {
    match op {
        Operand::Literal(v) => u32::try_from(*v).unwrap_or(0),
        Operand::SignedInteger(v) => u32::try_from(*v).unwrap_or(0),
        Operand::Character(c) => *c,
        _ => 0,
    }
}

fn label_of(op: &Operand) -> u32 {
    match op {
        Operand::Label(l) => *l,
        _ => 0,
    }
}
