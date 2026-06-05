pub mod binmatch;
pub mod clause;
pub mod comprehension;
pub mod expr;
pub mod render;
pub mod resugar;
pub mod simplify;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::body_lift::expr::{
    AfterClause, BifKind, BinSegment, CaseArm, CatchArm, Expr, IfArm, Stmt, bif_operator,
    is_guard_bif,
};
use crate::chunks::Chunks;
use crate::disasm::{Instruction, Operand};
use crate::etf::Term;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedBody {
    pub stmts: Vec<Stmt>,
    /// Self-reported lift coverage, not source fidelity.
    pub lift_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reg {
    X(u32),
    Y(u32),
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

/// Lifts one `func_info`-bracketed function body into Erlang statements.
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

/// Lifts a function body into reconstructed Erlang clauses.
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
}

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
        let mut out: Vec<Stmt> = Vec::new();
        if depth > 400 {
            flags.degraded = true;
            return out;
        }
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
                "put_list" => self.exec_put_list(ins, env),
                "put_tuple2" => self.exec_put_tuple2(ins, env),
                "put_tuple" => {
                    idx = self.exec_put_tuple_old(ins, idx, block.end, env);
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

    /// Models `trim N Remaining`: shifts the Y-register environment to renumber survivors.
    fn exec_trim(ins: &Instruction, env: &mut Env) {
        let n: u32 = literal_u32(&ins.operands[0]);
        if n == 0 {
            return;
        }
        let shifted: BTreeMap<Reg, Expr> = env
            .regs
            .iter()
            .filter_map(|(reg, value): (&Reg, &Expr)| match reg {
                Reg::Y(i) if *i >= n => Some((Reg::Y(i - n), value.clone())),
                Reg::Y(_) => None,
                Reg::X(_) => Some((*reg, value.clone())),
            })
            .collect();
        env.regs = shifted;
    }

    fn exec_move(&self, ins: &Instruction, env: &mut Env) {
        let (Some(src), Some(dst)): (Option<&Operand>, Option<&Operand>) =
            (ins.operands.first(), ins.operands.get(1))
        else {
            return;
        };
        if ins.name == "swap" {
            let a: Expr = self.value(src, env);
            let b: Expr = self.value(dst, env);
            if let Some(ra) = as_reg(src) {
                env.set(ra, b);
            }
            if let Some(rb) = as_reg(dst) {
                env.set(rb, a);
            }
            return;
        }
        let value: Expr = self.value(src, env);
        if let Some(reg) = as_reg(dst) {
            env.set(reg, value);
        }
    }

    fn exec_put_list(&self, ins: &Instruction, env: &mut Env) {
        let head: Expr = self.value(&ins.operands[0], env);
        let tail: Expr = self.value(&ins.operands[1], env);
        if let Some(reg) = as_reg(&ins.operands[2]) {
            env.set(reg, make_cons(head, tail));
        }
    }

    fn exec_put_tuple2(&self, ins: &Instruction, env: &mut Env) {
        let Operand::List(items) = &ins.operands[1] else {
            return;
        };
        let elements: Vec<Expr> = items.iter().map(|o: &Operand| self.value(o, env)).collect();
        if let Some(reg) = as_reg(&ins.operands[0]) {
            env.set(reg, Expr::Tuple(elements));
        }
    }

    fn exec_put_tuple_old(
        &self,
        ins: &Instruction,
        start: usize,
        end: usize,
        env: &mut Env,
    ) -> usize {
        let size: u32 = literal_u32(&ins.operands[0]);
        let dst: &Operand = &ins.operands[1];
        let mut elements: Vec<Expr> = Vec::with_capacity(size as usize);
        let mut cursor: usize = start + 1;
        while cursor < end && elements.len() < size as usize && self.instrs[cursor].name == "put" {
            elements.push(self.value(&self.instrs[cursor].operands[0], env));
            cursor += 1;
        }
        if let Some(reg) = as_reg(dst) {
            env.set(reg, Expr::Tuple(elements));
        }
        cursor - 1
    }

    fn exec_get_list(&self, ins: &Instruction, env: &mut Env) {
        let src: Expr = self.value(&ins.operands[0], env);
        if let Some(hd) = as_reg(&ins.operands[1]) {
            env.set(hd, guard("hd", vec![src.clone()]));
        }
        if let Some(tl) = as_reg(&ins.operands[2]) {
            env.set(tl, guard("tl", vec![src]));
        }
    }

    fn exec_unary_dest(&self, ins: &Instruction, op: &str, env: &mut Env) {
        let src: Expr = self.value(&ins.operands[0], env);
        if let Some(dst) = as_reg(&ins.operands[1]) {
            env.set(dst, guard(op, vec![src]));
        }
    }

    fn exec_get_tuple_element(&self, ins: &Instruction, env: &mut Env) {
        let tuple: Expr = self.value(&ins.operands[0], env);
        let index: u32 = literal_u32(&ins.operands[1]);
        let Some(dst): Option<Reg> = as_reg(&ins.operands[2]) else {
            return;
        };
        if let Expr::Tuple(elements) = &tuple
            && let Some(elem) = elements.get(index as usize)
        {
            env.set(dst, elem.clone());
            return;
        }
        env.set(
            dst,
            Expr::TupleElement {
                tuple: Box::new(tuple),
                index,
            },
        );
    }

    fn exec_put_map(&self, ins: &Instruction, env: &mut Env) {
        let exact: bool = ins.name == "put_map_exact";
        let base: Expr = self.value(&ins.operands[1], env);
        let dst: &Operand = &ins.operands[2];
        let Some(Operand::List(items)) = ins.operands.get(4) else {
            return;
        };
        let pairs: Vec<(Expr, Expr)> = self.pair_list(items, env);
        if let Some(reg) = as_reg(dst) {
            env.set(
                reg,
                Expr::MapUpdate {
                    base: Box::new(base),
                    exact,
                    pairs,
                },
            );
        }
    }

    fn exec_update_record(&self, ins: &Instruction, env: &mut Env) {
        let base: Expr = self.value(&ins.operands[2], env);
        let dst: &Operand = &ins.operands[3];
        let Some(Operand::List(items)) = ins.operands.get(4) else {
            if let Some(reg) = as_reg(dst) {
                env.set(reg, base);
            }
            return;
        };
        let mut updates: Vec<(u32, Expr)> = Vec::with_capacity(items.len() / 2);
        for pair in items.chunks_exact(2) {
            updates.push((literal_u32(&pair[0]), self.value(&pair[1], env)));
        }
        if let Some(reg) = as_reg(dst) {
            env.set(
                reg,
                Expr::RecordUpdate {
                    base: Box::new(base),
                    updates,
                },
            );
        }
    }

    fn fail_leads_to_clause(&self, fail: u32) -> bool {
        fail != 0 && self.blocks.contains_key(&fail) && !self.is_pure_failure(fail)
    }

    /// Builds the `case` conditional for an in-body `bs_match` whose fail branch is a real clause.
    fn build_bin_match_branch(
        &self,
        block: &Block,
        idx: usize,
        fail: u32,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
        let ins: &Instruction = &self.instrs[idx];
        let ctx: Option<Reg> = as_reg(&ins.operands[1]);
        let subject: Expr = ctx
            .and_then(|c: Reg| {
                env.bin_ctx
                    .get(&c)
                    .map(|s: &BinMatchState| env.get(s.source))
            })
            .or_else(|| ctx.map(|c: Reg| env.get(c)))
            .unwrap_or(Expr::Nil);
        let mut then_env: Env = env.clone();
        let mut segments: Vec<BinSegment> = Vec::new();
        if let Some(Operand::List(items)) = ins.operands.get(2) {
            for mut seg in binmatch::decode_match_commands(items, self.chunks) {
                let var: String = flags.fresh_pat();
                seg.segment.value = Box::new(Expr::Var(var.clone()));
                if let Some(dst) = seg.dst.as_ref().and_then(as_reg) {
                    then_env.set(dst, Expr::Var(var));
                }
                segments.push(seg.segment);
            }
        }
        let rest: String = flags.fresh_pat();
        segments.push(BinSegment {
            value: Box::new(Expr::Var(rest.clone())),
            size: None,
            unit: 8,
            kind: "binary".to_owned(),
            flags: Vec::new(),
        });
        if let Some(c) = ctx {
            then_env.set(c, Expr::Var(rest));
        }
        let then_body: Vec<Stmt> = self.walk_inline(block, idx + 1, &mut then_env, flags, depth);
        let else_body: Vec<Stmt> = self.walk(fail, &mut env.clone(), flags, depth + 1);
        Expr::Case {
            subject: Box::new(subject),
            arms: vec![
                CaseArm {
                    pattern: Expr::BinaryConstruct(segments),
                    guard: None,
                    body: then_body,
                },
                CaseArm {
                    pattern: Expr::Var("_".to_owned()),
                    guard: None,
                    body: else_body,
                },
            ],
        }
    }

    /// Builds the conditional for a `get_map_elements` whose fail branch is a real clause.
    fn build_map_match_branch(
        &self,
        block: &Block,
        idx: usize,
        fail: u32,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
        let ins: &Instruction = &self.instrs[idx];
        let src: Expr = self.value(&ins.operands[1], env);
        let keys: Vec<Expr> = match ins.operands.get(2) {
            Some(Operand::List(items)) => items
                .chunks_exact(2)
                .map(|p: &[Operand]| self.value(&p[0], env))
                .collect(),
            _ => Vec::new(),
        };
        let guard: Expr = combine_guard(
            keys.into_iter()
                .map(|k: Expr| guard("is_map_key", vec![k, src.clone()]))
                .collect(),
        );
        let mut then_env: Env = env.clone();
        let mut then_body: Vec<Stmt> = Vec::new();
        if let Some(stmt) = self.exec_get_map_elements(ins, &mut then_env, flags) {
            then_body.push(stmt);
        }
        then_body.extend(self.walk_inline(block, idx + 1, &mut then_env, flags, depth));
        let else_body: Vec<Stmt> = self.walk(fail, &mut env.clone(), flags, depth + 1);
        Expr::If {
            arms: vec![
                IfArm {
                    guard,
                    body: then_body,
                },
                IfArm {
                    guard: Expr::Atom("true".to_owned()),
                    body: else_body,
                },
            ],
        }
    }

    /// Lifts `get_map_elements` as a map-pattern match `#{K := Var, ...} = Src`.
    fn exec_get_map_elements(
        &self,
        ins: &Instruction,
        env: &mut Env,
        flags: &mut Flags,
    ) -> Option<Stmt> {
        let src: Expr = self.value(&ins.operands[1], env);
        let Some(Operand::List(items)) = ins.operands.get(2) else {
            return None;
        };
        let mut pairs: Vec<(Expr, Expr)> = Vec::with_capacity(items.len() / 2);
        for pair in items.chunks_exact(2) {
            let key: Expr = self.value(&pair[0], env);
            if let Some(reg) = as_reg(&pair[1]) {
                let var: String = flags.fresh_pat();
                env.set(reg, Expr::Var(var.clone()));
                pairs.push((key, Expr::Var(var)));
            }
        }
        if pairs.is_empty() {
            return None;
        }
        Some(Stmt::Match {
            pattern: Expr::MapPattern { pairs },
            value: src,
        })
    }

    fn pair_list(&self, items: &[Operand], env: &Env) -> Vec<(Expr, Expr)> {
        let mut pairs: Vec<(Expr, Expr)> = Vec::with_capacity(items.len() / 2);
        for pair in items.chunks_exact(2) {
            pairs.push((self.value(&pair[0], env), self.value(&pair[1], env)));
        }
        pairs
    }

    fn exec_bif(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let (import_op, dst, args): (&Operand, &Operand, Vec<Expr>) = match ins.name {
            "bif0" => (&ins.operands[0], &ins.operands[1], Vec::new()),
            "bif1" => (
                &ins.operands[1],
                &ins.operands[3],
                vec![self.value(&ins.operands[2], env)],
            ),
            "bif2" => (
                &ins.operands[1],
                &ins.operands[4],
                vec![
                    self.value(&ins.operands[2], env),
                    self.value(&ins.operands[3], env),
                ],
            ),
            _ => return,
        };
        self.apply_bif(import_op, &args, dst, env, flags);
    }

    fn exec_gc_bif(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let (import_op, args, dst): (&Operand, Vec<Expr>, &Operand) = match ins.name {
            "gc_bif1" => (
                &ins.operands[2],
                vec![self.value(&ins.operands[3], env)],
                &ins.operands[4],
            ),
            "gc_bif2" => (
                &ins.operands[2],
                vec![
                    self.value(&ins.operands[3], env),
                    self.value(&ins.operands[4], env),
                ],
                &ins.operands[5],
            ),
            "gc_bif3" => (
                &ins.operands[2],
                vec![
                    self.value(&ins.operands[3], env),
                    self.value(&ins.operands[4], env),
                    self.value(&ins.operands[5], env),
                ],
                &ins.operands[6],
            ),
            _ => return,
        };
        self.apply_bif(import_op, &args, dst, env, flags);
    }

    fn apply_bif(
        &self,
        import_op: &Operand,
        args: &[Expr],
        dst: &Operand,
        env: &mut Env,
        flags: &mut Flags,
    ) {
        let Some((module, name, arity)): Option<(String, String, u32)> =
            self.resolve_import(import_op)
        else {
            flags.degraded = true;
            return;
        };
        let expr: Expr = build_bif_expr(&module, &name, arity, args);
        if let Some(reg) = as_reg(dst) {
            env.set(reg, expr);
        }
    }

    fn exec_call_local(
        &self,
        ins: &Instruction,
        env: &mut Env,
        out: &mut Vec<Stmt>,
        flags: &mut Flags,
    ) -> bool {
        let arity: u32 = literal_u32(&ins.operands[0]);
        let label: u32 = match &ins.operands[1] {
            Operand::Label(l) => *l,
            _ => 0,
        };
        let args: Vec<Expr> = (0..arity).map(|i: u32| env.get(Reg::X(i))).collect();
        let target: String = self.label_to_fun.get(&label).map_or_else(
            || format!("'-local-L{label}-'"),
            |(n, _): &(String, u32)| render::render_atom(n),
        );
        finish_call(ins.name, Expr::Call { target, args }, env, out, flags)
    }

    fn exec_call_ext(
        &self,
        ins: &Instruction,
        env: &mut Env,
        out: &mut Vec<Stmt>,
        flags: &mut Flags,
    ) -> bool {
        let arity: u32 = literal_u32(&ins.operands[0]);
        let args: Vec<Expr> = (0..arity).map(|i: u32| env.get(Reg::X(i))).collect();
        let call: Expr = match self.resolve_import(&ins.operands[1]) {
            Some((module, name, _)) => plain_call(&module, &name, &args),
            None => Expr::Call {
                target: "erlang:apply".to_owned(),
                args,
            },
        };
        finish_call(ins.name, call, env, out, flags)
    }

    fn exec_call_fun(
        &self,
        ins: &Instruction,
        env: &mut Env,
        out: &mut Vec<Stmt>,
        flags: &mut Flags,
    ) -> bool {
        let (arity, fun): (u32, Expr) = if ins.name == "call_fun2" {
            (
                literal_u32(&ins.operands[1]),
                self.value(&ins.operands[2], env),
            )
        } else {
            let a: u32 = literal_u32(&ins.operands[0]);
            (a, env.get(Reg::X(a)))
        };
        let args: Vec<Expr> = (0..arity).map(|i: u32| env.get(Reg::X(i))).collect();
        finish_call(
            "call",
            Expr::CallFun {
                fun: Box::new(fun),
                args,
            },
            env,
            out,
            flags,
        )
    }

    fn exec_make_fun(&self, ins: &Instruction, env: &mut Env) {
        let (fun_index, dst, env_ops): (u32, Option<&Operand>, &[Operand]) = match ins.name {
            "make_fun3" => (
                literal_u32(&ins.operands[0]),
                ins.operands.get(1),
                match ins.operands.get(2) {
                    Some(Operand::List(items)) => items.as_slice(),
                    _ => &[],
                },
            ),
            _ => (literal_u32(&ins.operands[0]), None, &[]),
        };
        let captured: Vec<Expr> = env_ops
            .iter()
            .map(|o: &Operand| self.value(o, env))
            .collect();
        let (name, arity): (String, u32) = self.chunks.funs.get(fun_index as usize).map_or_else(
            || (format!("'-fun-{fun_index}-'"), 0),
            |f: &crate::chunks::FunEntry| {
                let n: String = self
                    .chunks
                    .atoms
                    .get(f.function_atom_index)
                    .map_or_else(|| format!("'-fun-{fun_index}-'"), render::render_atom);
                (n, f.arity)
            },
        );
        let make: Expr = Expr::MakeFun {
            name,
            arity,
            env: captured,
        };
        env.set(dst.and_then(as_reg).unwrap_or(Reg::X(0)), make);
    }

    /// Reconstructs binary-matching function clauses when the entry block opens a match context.
    fn reconstruct_binary_clauses(&self, entry: u32) -> Option<(Vec<expr::FnClause>, bool)> {
        let block: Block = self.blocks.get(&entry).copied()?;
        if self.arity != 1
            || !(block.start..block.end)
                .any(|i: usize| self.instrs[i].name.starts_with("bs_start_match"))
        {
            return None;
        }
        let mut flags: Flags = Flags::default();
        let mut ok: bool = true;
        let mut shared: BinShared = BinShared {
            all_segments: Vec::new(),
            pos_len: BTreeMap::new(),
            seg_vars: Vec::new(),
            seg_dsts: Vec::new(),
        };
        let mut clauses: Vec<expr::FnClause> = Vec::new();
        let mut queue: Vec<u32> = vec![entry];
        let mut visited: Vec<u32> = Vec::new();
        while let Some(label) = (!queue.is_empty()).then(|| queue.remove(0)) {
            if visited.contains(&label)
                || self.is_pure_failure(label)
                || self.is_gc_retry(label, &visited)
            {
                continue;
            }
            visited.push(label);
            let Some(walked): Option<BinaryClause> =
                self.walk_binary_clause(label, &mut flags, &mut shared)
            else {
                continue;
            };
            ok = ok && !walked.degraded;
            clauses.push(expr::FnClause {
                patterns: vec![Expr::BinaryConstruct(walked.segments)],
                guard: None,
                body: resugar::resugar_body(simplify::simplify_body(walked.body)),
            });
            for fail in walked.fails {
                if !visited.contains(&fail) && !queue.contains(&fail) {
                    queue.push(fail);
                }
            }
        }
        if clauses.is_empty() {
            return None;
        }
        let unresolved: bool = clauses
            .iter()
            .any(|c: &expr::FnClause| c.body.iter().any(has_unrecovered_marker));
        Some((clauses, ok && !unresolved))
    }

    /// Walks one binary-match clause starting at `label`.
    fn walk_binary_clause(
        &self,
        label: u32,
        flags: &mut Flags,
        shared: &mut BinShared,
    ) -> Option<BinaryClause> {
        let mut env: Env = Env::default();
        env.set(Reg::X(0), Reg::X(0).var());
        let mut fails: Vec<u32> = Vec::new();
        let mut idx: usize = self.blocks.get(&label)?.start;
        let limit: usize = self.instrs.len();
        let mut exact: bool = false;
        let mut ctx: Option<Reg> = None;
        let mut cursor: usize = shared.all_segments.len();
        let mut local_max: usize = cursor;
        loop {
            if idx >= limit {
                return Some(BinaryClause {
                    segments: close_pattern(
                        &shared.all_segments[..local_max],
                        exact,
                        ctx,
                        &mut env,
                        flags,
                    ),
                    body: Vec::new(),
                    fails,
                    degraded: true,
                });
            }
            let ins: &Instruction = &self.instrs[idx];
            match ins.name {
                name if name.starts_with("bs_start_match") => {
                    ctx = ins.operands.last().and_then(as_reg);
                }
                "bs_get_position" => {
                    if let Some(reg) = as_reg(&ins.operands[1]) {
                        shared.pos_len.insert(reg, cursor);
                    }
                }
                "bs_set_position" => {
                    if let Some(reg) = as_reg(&ins.operands[1])
                        && let Some(&len) = shared.pos_len.get(&reg)
                    {
                        cursor = len;
                        local_max = len;
                        rebind_prefix(shared, len, &mut env);
                    }
                }
                "bs_match" => {
                    let fail: u32 = label_of(&ins.operands[0]);
                    if fail != 0 {
                        fails.push(fail);
                    }
                    if let Some(Operand::List(items)) = ins.operands.get(2) {
                        if is_ensure_exactly_zero(items, self.chunks) {
                            exact = true;
                        }
                        for seg in binmatch::decode_match_commands(items, self.chunks) {
                            let var: String = Self::segment_var(shared, cursor, flags);
                            let dst: Option<Reg> = seg.dst.as_ref().and_then(as_reg);
                            let mut s: BinSegment = seg.segment;
                            s.value = Box::new(Expr::Var(var.clone()));
                            if cursor == shared.all_segments.len() {
                                shared.all_segments.push(s);
                                shared.seg_vars.push(var.clone());
                                shared.seg_dsts.push(dst);
                            }
                            if let Some(dst) = dst {
                                env.set(dst, Expr::Var(var));
                            }
                            cursor += 1;
                            local_max = local_max.max(cursor);
                        }
                    }
                }
                "bs_get_tail" => {
                    let var: String = Self::segment_var(shared, cursor, flags);
                    let dst: Option<Reg> = as_reg(&ins.operands[1]);
                    if let Some(dst) = dst {
                        env.set(dst, Expr::Var(var.clone()));
                    }
                    if cursor == shared.all_segments.len() {
                        shared.all_segments.push(BinSegment {
                            value: Box::new(Expr::Var(var.clone())),
                            size: None,
                            unit: 8,
                            kind: "binary".to_owned(),
                            flags: Vec::new(),
                        });
                        shared.seg_vars.push(var);
                        shared.seg_dsts.push(dst);
                    }
                    cursor += 1;
                    local_max = local_max.max(cursor);
                    exact = true;
                }
                "jump" => {
                    if let Some(Operand::Label(l)) = ins.operands.first() {
                        idx = self.blocks.get(l).map_or(limit, |b: &Block| b.start);
                        continue;
                    }
                }
                "line" | "label" | "test_heap" | "allocate" | "allocate_heap"
                | "allocate_heap_zero" | "deallocate" | "trim" | "init_yregs"
                | "bs_init_writable" => {}
                "return" => {
                    return Some(BinaryClause {
                        segments: close_pattern(
                            &shared.all_segments[..local_max],
                            exact,
                            ctx,
                            &mut env,
                            flags,
                        ),
                        body: vec![Stmt::Return(env.get(Reg::X(0)))],
                        fails,
                        degraded: false,
                    });
                }
                _ => {
                    let segments: Vec<BinSegment> = close_pattern(
                        &shared.all_segments[..local_max],
                        exact,
                        ctx,
                        &mut env,
                        flags,
                    );
                    let mut sub_flags: Flags = Flags {
                        pat_counter: flags.pat_counter,
                        ..Flags::default()
                    };
                    let region: Block = Block {
                        start: idx,
                        end: limit,
                    };
                    let mut body_env: Env = env.clone();
                    let body: Vec<Stmt> = self.walk_synth(region, &mut body_env, &mut sub_flags, 1);
                    flags.pat_counter = sub_flags.pat_counter;
                    return Some(BinaryClause {
                        segments,
                        body,
                        fails,
                        degraded: sub_flags.degraded,
                    });
                }
            }
            idx += 1;
        }
    }

    fn segment_var(shared: &BinShared, cursor: usize, flags: &mut Flags) -> String {
        shared
            .seg_vars
            .get(cursor)
            .cloned()
            .unwrap_or_else(|| flags.fresh_pat())
    }

    /// Recognizes a heap-GC retry stub that jumps back to an already-emitted clause.
    fn is_gc_retry(&self, label: u32, visited: &[u32]) -> bool {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return false;
        };
        for i in block.start..block.end {
            match self.instrs[i].name {
                "bs_get_tail" | "bs_get_position" | "bs_set_position" | "line" | "label"
                | "move" | "test_heap" | "allocate" | "deallocate" => {}
                "jump" => {
                    let Some(Operand::Label(l)): Option<&Operand> = self.instrs[i].operands.first()
                    else {
                        return true;
                    };
                    return visited.contains(l)
                        || self.block_opens_match(*l)
                        || !self.blocks.contains_key(l);
                }
                _ => return false,
            }
        }
        false
    }

    fn block_opens_match(&self, label: u32) -> bool {
        self.blocks.get(&label).copied().is_some_and(|b: Block| {
            (b.start..b.end).any(|i: usize| self.instrs[i].name.starts_with("bs_start_match"))
        })
    }

    fn is_pure_failure(&self, label: u32) -> bool {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return false;
        };
        (block.start..block.end).all(|i: usize| {
            matches!(
                self.instrs[i].name,
                "line" | "label" | "func_clause" | "badmatch" | "case_end" | "if_end"
            )
        }) && (block.start..block.end)
            .any(|i: usize| matches!(self.instrs[i].name, "func_clause" | "badmatch"))
    }

    fn exec_bs_start_match(ins: &Instruction, env: &mut Env) {
        let (src, ctx): (Option<Reg>, Option<Reg>) = match ins.name {
            "bs_start_match4" => (as_reg(&ins.operands[2]), as_reg(&ins.operands[3])),
            _ => (
                as_reg(&ins.operands[1]),
                ins.operands.last().and_then(as_reg),
            ),
        };
        let (Some(src), Some(ctx)): (Option<Reg>, Option<Reg>) = (src, ctx) else {
            return;
        };
        env.bin_ctx.insert(
            ctx,
            BinMatchState {
                source: src,
                segments: Vec::new(),
            },
        );
    }

    /// Lifts an in-body `bs_match` into a `Pattern = Subject` binding.
    fn exec_bs_match(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) -> Option<Stmt> {
        let ctx: Reg = as_reg(&ins.operands[1])?;
        let Some(Operand::List(items)) = ins.operands.get(2) else {
            flags.degraded = true;
            return None;
        };
        if is_ensure_exactly_zero(items, self.chunks) {
            return None;
        }
        let subject: Expr = env
            .bin_ctx
            .get(&ctx)
            .map_or_else(|| ctx.var(), |s: &BinMatchState| env.get(s.source));
        let mut segments: Vec<BinSegment> = Vec::new();
        let mut produced: bool = false;
        for mut seg in binmatch::decode_match_commands(items, self.chunks) {
            let var: String = flags.fresh_pat();
            seg.segment.value = Box::new(Expr::Var(var.clone()));
            if let Some(dst) = seg.dst.as_ref().and_then(as_reg) {
                env.set(dst, Expr::Var(var));
            }
            segments.push(seg.segment);
            produced = true;
        }
        if !produced {
            return None;
        }
        let rest: String = flags.fresh_pat();
        segments.push(BinSegment {
            value: Box::new(Expr::Var(rest.clone())),
            size: None,
            unit: 8,
            kind: "binary".to_owned(),
            flags: Vec::new(),
        });
        env.set(ctx, Expr::Var(rest));
        Some(Stmt::Match {
            pattern: Expr::BinaryConstruct(segments),
            value: subject,
        })
    }

    fn exec_bs_get_tail(ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let Some(ctx): Option<Reg> = as_reg(&ins.operands[0]) else {
            return;
        };
        let Some(dst): Option<Reg> = as_reg(&ins.operands[1]) else {
            return;
        };
        let var: String = flags.fresh_pat();
        env.set(dst, Expr::Var(var.clone()));
        if let Some(state) = env.bin_ctx.get_mut(&ctx) {
            state.segments.push(BinSegment {
                value: Box::new(Expr::Var(var)),
                size: None,
                unit: 8,
                kind: "binary".to_owned(),
                flags: Vec::new(),
            });
        }
    }

    fn exec_bs_create_bin(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let dst: Option<&Operand> = ins.operands.get(4);
        let Some(Operand::List(items)) = ins.operands.get(5) else {
            flags.degraded = true;
            return;
        };
        let segments: Vec<BinSegment> = self.parse_bin_segments(items, env);
        if let Some(reg) = dst.and_then(as_reg) {
            env.set(reg, Expr::BinaryConstruct(segments));
        }
    }

    fn parse_bin_segments(&self, items: &[Operand], env: &Env) -> Vec<BinSegment> {
        let mut segments: Vec<BinSegment> = Vec::new();
        let mut i: usize = 0;
        while i + 5 < items.len() {
            let kind: &str = match &items[i] {
                Operand::Atom(a) => self.chunks.atoms.get(*a).unwrap_or("integer"),
                _ => "integer",
            };
            let unit: u32 = literal_u32(&items[i + 2]);
            let flag_names: Vec<String> =
                binmatch::decode_construct_flags(&items[i + 3], self.chunks);
            if kind == "string" {
                let offset: usize = literal_u32(&items[i + 4]) as usize;
                let len: usize = literal_u32(&items[i + 5]) as usize;
                segments.extend(self.strt_string_segments(offset, len));
                i += 6;
                continue;
            }
            let value: Expr = self.value(&items[i + 4], env);
            let size: Option<Box<Expr>> = match &items[i + 5] {
                Operand::Atom(a) if self.chunks.atoms.get(*a) == Some("all") => None,
                Operand::Atom(0) => None,
                other => Some(Box::new(self.value(other, env))),
            };
            if matches!(kind, "append" | "private_append") {
                segments.push(BinSegment {
                    value: Box::new(value),
                    size,
                    unit: 8,
                    kind: "binary".to_owned(),
                    flags: Vec::new(),
                });
                i += 6;
                continue;
            }
            let normalized: String = match kind {
                "binary" => "binary".to_owned(),
                "utf8" | "utf16" | "utf32" | "float" => kind.to_owned(),
                _ => "integer".to_owned(),
            };
            segments.push(BinSegment {
                value: Box::new(value),
                size,
                unit,
                kind: normalized,
                flags: flag_names,
            });
            i += 6;
        }
        segments
    }

    /// Expands a compile-time `string` segment into individual `Byte:8` integer segments.
    fn strt_string_segments(&self, offset: usize, len: usize) -> Vec<BinSegment> {
        let bytes: &[u8] = self
            .chunks
            .strings
            .as_ref()
            .and_then(|s: &crate::chunks::StringTable| s.slice(offset, len))
            .unwrap_or(&[]);
        bytes
            .iter()
            .map(|b: &u8| BinSegment {
                value: Box::new(Expr::Int(i64::from(*b))),
                size: Some(Box::new(Expr::Int(8))),
                unit: 1,
                kind: "integer".to_owned(),
                flags: Vec::new(),
            })
            .collect()
    }

    fn build_select_val(
        &self,
        ins: &Instruction,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
        let subject: Expr = self.value(&ins.operands[0], env);
        let default_label: u32 = label_of(&ins.operands[1]);
        let Operand::List(pairs) = &ins.operands[2] else {
            flags.degraded = true;
            return Expr::Atom("ok".to_owned());
        };
        let mut arms: Vec<CaseArm> = Vec::new();
        for pair in pairs.chunks_exact(2) {
            arms.push(CaseArm {
                pattern: self.value(&pair[0], env),
                guard: None,
                body: self.walk(label_of(&pair[1]), &mut env.clone(), flags, depth + 1),
            });
        }
        arms.push(CaseArm {
            pattern: Expr::Var("_".to_owned()),
            guard: None,
            body: self.walk(default_label, &mut env.clone(), flags, depth + 1),
        });
        Expr::Case {
            subject: Box::new(subject),
            arms,
        }
    }

    fn build_select_tuple_arity(
        &self,
        ins: &Instruction,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
        let subject: Expr = self.value(&ins.operands[0], env);
        let default_label: u32 = label_of(&ins.operands[1]);
        let Operand::List(pairs) = &ins.operands[2] else {
            flags.degraded = true;
            return Expr::Atom("ok".to_owned());
        };
        let mut arms: Vec<CaseArm> = Vec::new();
        let subject_reg: Option<Reg> = as_reg(&ins.operands[0]);
        for pair in pairs.chunks_exact(2) {
            let arity: u32 = literal_u32(&pair[0]);
            let vars: Vec<Expr> = (0..arity)
                .map(|i: u32| Expr::Var(format!("E{i}")))
                .collect();
            let pattern: Expr = Expr::Tuple(vars.clone());
            let mut sub: Env = env.clone();
            if let Some(reg) = subject_reg {
                sub.set(reg, Expr::Tuple(vars));
            }
            arms.push(CaseArm {
                pattern,
                guard: None,
                body: self.walk(label_of(&pair[1]), &mut sub, flags, depth + 1),
            });
        }
        arms.push(CaseArm {
            pattern: Expr::Var("_".to_owned()),
            guard: None,
            body: self.walk(default_label, &mut env.clone(), flags, depth + 1),
        });
        Expr::Case {
            subject: Box::new(subject),
            arms,
        }
    }

    fn build_receive(&self, label: u32, env: &Env, flags: &mut Flags, depth: u32) -> Expr {
        let Some(block) = self.blocks.get(&label).copied() else {
            flags.degraded = true;
            return Expr::Atom("ok".to_owned());
        };
        let mut msg_reg: Reg = Reg::X(0);
        let mut loop_rec_at: usize = block.start;
        let mut after_label: Option<u32> = None;
        let mut timeout: Option<Expr> = None;
        for slot in block.start..block.end {
            let ins: &Instruction = &self.instrs[slot];
            match ins.name {
                "loop_rec" => {
                    loop_rec_at = slot;
                    if let Some(reg) = as_reg(&ins.operands[1]) {
                        msg_reg = reg;
                    }
                }
                "wait_timeout" => {
                    after_label = Some(label_of(&ins.operands[0]));
                    timeout = Some(self.value(&ins.operands[1], env));
                }
                _ => {}
            }
        }
        let mut body_env: Env = env.clone();
        body_env.set(msg_reg, Expr::Var("Msg".to_owned()));
        let body_region: Block = Block {
            start: loop_rec_at + 1,
            end: block.end,
        };
        let body: Vec<Stmt> = self.walk_synth(body_region, &mut body_env, flags, depth + 1);
        let arms: Vec<CaseArm> = vec![CaseArm {
            pattern: Expr::Var("Msg".to_owned()),
            guard: None,
            body,
        }];
        let after: Option<Box<AfterClause>> = after_label.and_then(|al: u32| {
            self.blocks.get(&al).copied().and_then(|_| {
                let after_body: Vec<Stmt> = self.walk(al, &mut env.clone(), flags, depth + 1);
                (!after_body.is_empty()).then(|| {
                    Box::new(AfterClause {
                        timeout: timeout.clone().unwrap_or(Expr::Atom("infinity".to_owned())),
                        body: after_body,
                    })
                })
            })
        });
        Expr::Receive { arms, after }
    }

    fn build_raise(&self, ins: &Instruction, env: &Env) -> Stmt {
        let args: Vec<Expr> = if ins.name == "raw_raise" {
            vec![env.get(Reg::X(0)), env.get(Reg::X(1)), env.get(Reg::X(2))]
        } else {
            let trace: Expr = self.value(&ins.operands[0], env);
            let value: Expr = self.value(&ins.operands[1], env);
            vec![class_of_trace(&trace), value, trace]
        };
        Stmt::Return(Expr::Call {
            target: "erlang:raise".to_owned(),
            args,
        })
    }

    fn build_catch(
        &self,
        idx: usize,
        catch_end: usize,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
        let region: Block = Block {
            start: idx + 1,
            end: catch_end,
        };
        let mut body_env: Env = env.clone();
        let body: Vec<Stmt> = self.walk_synth(region, &mut body_env, flags, depth + 1);
        let inner: Expr = catch_value(body, &body_env);
        Expr::Catch(Box::new(inner))
    }

    fn build_try(&self, idx: usize, env: &Env, flags: &mut Flags, depth: u32) -> Expr {
        let catch_label: u32 = label_of(&self.instrs[idx].operands[1]);
        let try_case: usize = self.region_end(idx + 1, self.instrs.len(), &["try_case"]);
        let region: Block = Block {
            start: idx + 1,
            end: try_case,
        };
        let mut body_env: Env = env.clone();
        let body: Vec<Stmt> = self.walk_synth(region, &mut body_env, flags, depth + 1);
        let (of_arms, catch_arms): (Vec<CaseArm>, Vec<CatchArm>) =
            self.build_try_handlers(catch_label, env, flags, depth);
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after: Vec::new(),
        }
    }

    fn region_end(&self, start: usize, limit: usize, stop_at: &[&str]) -> usize {
        let mut cursor: usize = start;
        while cursor < limit {
            if stop_at.contains(&self.instrs[cursor].name) {
                return cursor;
            }
            cursor += 1;
        }
        limit
    }

    fn build_try_handlers(
        &self,
        label: u32,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> (Vec<CaseArm>, Vec<CatchArm>) {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return (Vec::new(), Vec::new());
        };
        let mut cursor: usize = block.start;
        while cursor < block.end && self.instrs[cursor].name != "try_case" {
            cursor += 1;
        }
        let mut catch_env: Env = env.clone();
        catch_env.set(Reg::X(0), Expr::Var("Class".to_owned()));
        catch_env.set(Reg::X(1), Expr::Var("Reason".to_owned()));
        catch_env.set(Reg::X(2), Expr::Var("Stack".to_owned()));
        let synth: Block = Block {
            start: cursor + 1,
            end: block.end,
        };
        let stmts: Vec<Stmt> = self.walk_synth(synth, &mut catch_env, flags, depth + 1);
        (Vec::new(), Self::to_catch_arms(stmts))
    }

    /// Converts the lifted handler dispatch into idiomatic `Class:Reason[:Stack]` catch clauses.
    fn to_catch_arms(stmts: Vec<Stmt>) -> Vec<CatchArm> {
        if let [Stmt::Return(Expr::If { arms })] = stmts.as_slice() {
            let mut out: Vec<CatchArm> = Vec::with_capacity(arms.len());
            for arm in arms {
                if is_reraise(&arm.body) {
                    continue;
                }
                let (class, extra): (String, Option<Expr>) = class_from_guard(&arm.guard);
                let stacktrace: Option<String> =
                    body_uses_var(&arm.body, "Stack").then(|| "Stack".to_owned());
                let guarded_body: Vec<Stmt> = match extra {
                    Some(rest) => vec![Stmt::Return(Expr::If {
                        arms: vec![IfArm {
                            guard: rest,
                            body: arm.body.clone(),
                        }],
                    })],
                    None => arm.body.clone(),
                };
                out.push(CatchArm {
                    class,
                    pattern: Expr::Var("Reason".to_owned()),
                    stacktrace,
                    body: guarded_body,
                });
            }
            if !out.is_empty() {
                return out;
            }
        }
        vec![CatchArm {
            class: "Class".to_owned(),
            pattern: Expr::Var("Reason".to_owned()),
            stacktrace: Some("Stack".to_owned()),
            body: stmts,
        }]
    }

    fn walk_synth(&self, synth: Block, env: &mut Env, flags: &mut Flags, depth: u32) -> Vec<Stmt> {
        let synth_label: u32 = u32::MAX - 1;
        let mut sub: Lifter<'_> = Lifter {
            chunks: self.chunks,
            instrs: self.instrs,
            blocks: self.blocks.clone(),
            label_to_fun: self.label_to_fun,
            literals: self.literals,
            arity: self.arity,
        };
        sub.blocks.insert(synth_label, synth);
        sub.walk(synth_label, env, flags, depth + 1)
    }

    fn reconstruct_branch(
        &self,
        block: &Block,
        idx: usize,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Option<Stmt> {
        let arms: Vec<IfArm> = self.collect_if_arms(block, idx, env, flags, depth)?;
        Some(Stmt::Return(Expr::If { arms }))
    }

    fn collect_if_arms(
        &self,
        block: &Block,
        start: usize,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Option<Vec<IfArm>> {
        let mut idx: usize = start;
        let mut conds: Vec<Expr> = Vec::new();
        let mut fail: Option<u32> = None;
        let mut local_env: Env = env.clone();
        while idx < block.end && TEST_OPS.contains(&self.instrs[idx].name) {
            let ins: &Instruction = &self.instrs[idx];
            let this_fail: u32 = label_of(&ins.operands[0]);
            match fail {
                Some(f) if f != this_fail => break,
                _ => fail = Some(this_fail),
            }
            let Some(cond): Option<Expr> = self.test_condition(ins, &local_env) else {
                flags.degraded = true;
                return None;
            };
            conds.push(cond);
            idx += 1;
        }
        if conds.is_empty() {
            flags.degraded = true;
            return None;
        }
        let guard: Expr = combine_guard(conds);
        let body: Vec<Stmt> = self.walk_inline(block, idx, &mut local_env, flags, depth);
        let mut arms: Vec<IfArm> = vec![IfArm { guard, body }];
        if let Some(fail_label) = fail
            && self.blocks.contains_key(&fail_label)
        {
            arms.extend(self.continue_if_chain(fail_label, env, flags, depth));
        }
        Some(arms)
    }

    fn continue_if_chain(
        &self,
        label: u32,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Vec<IfArm> {
        if depth > 400 {
            flags.degraded = true;
            return Vec::new();
        }
        if let Some(block) = self.blocks.get(&label).copied()
            && self
                .instrs
                .get(block.start)
                .is_some_and(|i: &Instruction| TEST_OPS.contains(&i.name))
            && let Some(rest) = self.collect_if_arms(&block, block.start, env, flags, depth + 1)
        {
            return rest;
        }
        vec![IfArm {
            guard: Expr::Atom("true".to_owned()),
            body: self.walk(label, &mut env.clone(), flags, depth + 1),
        }]
    }

    fn walk_inline(
        &self,
        block: &Block,
        from: usize,
        env: &mut Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Vec<Stmt> {
        let synth: Block = Block {
            start: from,
            end: block.end,
        };
        let synth_label: u32 = u32::MAX;
        let mut sub: Lifter<'_> = Lifter {
            chunks: self.chunks,
            instrs: self.instrs,
            blocks: self.blocks.clone(),
            label_to_fun: self.label_to_fun,
            literals: self.literals,
            arity: self.arity,
        };
        sub.blocks.insert(synth_label, synth);
        sub.walk(synth_label, env, flags, depth + 1)
    }

    fn test_condition(&self, ins: &Instruction, env: &Env) -> Option<Expr> {
        let ops: &[Operand] = &ins.operands;
        let unary = |g: &str| -> Option<Expr> { Some(guard(g, vec![self.value(&ops[1], env)])) };
        let cmp = |op: &str| -> Option<Expr> {
            Some(Expr::BinOp {
                op: op.to_owned(),
                lhs: Box::new(self.value(&ops[1], env)),
                rhs: Box::new(self.value(&ops[2], env)),
            })
        };
        match ins.name {
            "is_integer" => unary("is_integer"),
            "is_float" => unary("is_float"),
            "is_number" => unary("is_number"),
            "is_atom" => unary("is_atom"),
            "is_pid" => unary("is_pid"),
            "is_reference" => unary("is_reference"),
            "is_port" => unary("is_port"),
            "is_nil" => Some(Expr::BinOp {
                op: "=:=".to_owned(),
                lhs: Box::new(self.value(&ops[1], env)),
                rhs: Box::new(Expr::Nil),
            }),
            "is_binary" => unary("is_binary"),
            "is_bitstr" => unary("is_bitstring"),
            "is_list" => unary("is_list"),
            "is_nonempty_list" => {
                let subject: Expr = self.value(&ops[1], env);
                Some(Expr::BinOp {
                    op: "andalso".to_owned(),
                    lhs: Box::new(guard("is_list", vec![subject.clone()])),
                    rhs: Box::new(Expr::BinOp {
                        op: "=/=".to_owned(),
                        lhs: Box::new(subject),
                        rhs: Box::new(Expr::Nil),
                    }),
                })
            }
            "is_tuple" => unary("is_tuple"),
            "is_map" => unary("is_map"),
            "is_boolean" => unary("is_boolean"),
            "is_function" => unary("is_function"),
            "is_function2" => Some(guard(
                "is_function",
                vec![self.value(&ops[1], env), self.value(&ops[2], env)],
            )),
            "is_lt" => cmp("<"),
            "is_ge" => cmp(">="),
            "is_eq" => cmp("=="),
            "is_ne" => cmp("/="),
            "is_eq_exact" => cmp("=:="),
            "is_ne_exact" => cmp("=/="),
            "test_arity" => {
                let subject: Expr = self.value(&ops[1], env);
                let arity: u32 = literal_u32(&ops[2]);
                Some(Expr::BinOp {
                    op: "=:=".to_owned(),
                    lhs: Box::new(guard("tuple_size", vec![subject])),
                    rhs: Box::new(Expr::Int(i64::from(arity))),
                })
            }
            "is_tagged_tuple" => {
                let subject: Expr = self.value(&ops[1], env);
                let arity: u32 = literal_u32(&ops[2]);
                let tag: Expr = self.value(&ops[3], env);
                let is_tuple: Expr = guard("is_tuple", vec![subject.clone()]);
                let arity_eq: Expr = Expr::BinOp {
                    op: "=:=".to_owned(),
                    lhs: Box::new(guard("tuple_size", vec![subject.clone()])),
                    rhs: Box::new(Expr::Int(i64::from(arity))),
                };
                let tag_eq: Expr = Expr::BinOp {
                    op: "=:=".to_owned(),
                    lhs: Box::new(guard("element", vec![Expr::Int(1), subject])),
                    rhs: Box::new(tag),
                };
                Some(combine_guard(vec![is_tuple, arity_eq, tag_eq]))
            }
            "has_map_fields" => {
                let subject: Expr = self.value(&ops[1], env);
                let Some(Operand::List(keys)) = ops.get(2) else {
                    return None;
                };
                let checks: Vec<Expr> = keys
                    .iter()
                    .map(|k: &Operand| {
                        guard("is_map_key", vec![self.value(k, env), subject.clone()])
                    })
                    .collect();
                (!checks.is_empty()).then(|| combine_guard(checks))
            }
            _ => None,
        }
    }

    fn resolve_import(&self, op: &Operand) -> Option<(String, String, u32)> {
        let index: u32 = match op {
            Operand::Literal(v) => u32::try_from(*v).ok()?,
            Operand::LiteralIndex(v) => *v,
            _ => return None,
        };
        let import: &crate::chunks::ImportEntry = self.chunks.imports.get(index as usize)?;
        let module: &str = self.chunks.atoms.get(import.module_atom_index)?;
        let name: &str = self.chunks.atoms.get(import.function_atom_index)?;
        Some((module.to_owned(), name.to_owned(), import.arity))
    }

    fn value(&self, op: &Operand, env: &Env) -> Expr {
        match op {
            Operand::Literal(v) => Expr::Int(i64::try_from(*v).unwrap_or(0)),
            Operand::SignedInteger(v) => Expr::Int(*v),
            Operand::Atom(0) => Expr::Nil,
            Operand::Atom(a) => self
                .chunks
                .atoms
                .get(*a)
                .map_or(Expr::Nil, |n: &str| Expr::Atom(n.to_owned())),
            Operand::XReg(r) => env.get(Reg::X(*r)),
            Operand::YReg(r) => env.get(Reg::Y(*r)),
            Operand::Character(c) => Expr::CharLit(*c),
            Operand::LiteralIndex(i) => self
                .literals
                .get(*i as usize)
                .map_or_else(|| Expr::Raw(format!("literal[{i}]")), Expr::from_term),
            Operand::Label(l) => Expr::Raw(format!("label_{l}")),
            Operand::FpReg(r) => Expr::Var(format!("Fr{r}")),
            Operand::TypedReg { reg, .. } => self.value(reg, env),
            Operand::BigInteger { sign, magnitude_be } => {
                let mut le: Vec<u8> = magnitude_be.clone();
                le.reverse();
                Expr::BigInt {
                    sign: *sign,
                    magnitude_le: le,
                }
            }
            Operand::List(_) | Operand::AllocList(_) => Expr::Raw("[...]".to_owned()),
        }
    }
}

fn is_reraise(body: &[Stmt]) -> bool {
    matches!(
        body,
        [Stmt::Return(Expr::Call { target, .. })] if target == "erlang:raise"
    )
}

/// Splits a catch-handler guard into the matched class atom and any residual guard.
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

/// Whether any statement in `body` references the variable `name`.
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

/// Finalizes a binary-match clause's segment list.
#[derive(Debug)]
struct BinaryClause {
    segments: Vec<BinSegment>,
    body: Vec<Stmt>,
    fails: Vec<u32>,
    degraded: bool,
}

/// Shared binary-match ledger across the clauses of one function.
#[derive(Debug)]
struct BinShared {
    all_segments: Vec<BinSegment>,
    pos_len: BTreeMap<Reg, usize>,
    seg_vars: Vec<String>,
    seg_dsts: Vec<Option<Reg>>,
}

/// Closes a binary clause pattern, appending a `Rest/binary` segment when the subject is not exhausted.
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

/// Re-establishes the destination-register bindings for a retained match prefix after a position rewind.
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

/// The exception class for a re-raise.
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

/// Whether an `erlang:` function may be called unqualified.
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

fn as_reg(op: &Operand) -> Option<Reg> {
    match op {
        Operand::XReg(r) => Some(Reg::X(*r)),
        Operand::YReg(r) => Some(Reg::Y(*r)),
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
