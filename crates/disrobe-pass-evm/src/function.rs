use std::collections::{BTreeMap, BTreeSet};

use crate::dispatch::Entry;
use crate::exec::{
    CallKind, CallValueCheck, Evidence, Halt, Jumps, Machine, Sink, State, Stmt, Stop,
    callvalue_check, record_jump, split_branch,
};
use crate::expr::{BinOp, CdLoc, Expr, UnOp, Val, affine, as_const};
use crate::u256::U256;

const MAX_EVIDENCE: usize = 4096;
const PRECOMPILE_LAST: u64 = 0x11;

#[derive(Debug, Clone)]
pub(crate) enum End {
    Open,
    Next(usize),
    Branch {
        cond: Val,
        taken: usize,
        fall: usize,
    },
    Goto(usize),
    Halt(Halt),
    Cut,
}

#[derive(Debug, Clone)]
pub(crate) struct TreeNode {
    pub(crate) pc: usize,
    pub(crate) stmts: Vec<Stmt>,
    pub(crate) end: End,
}

#[derive(Debug, Clone)]
pub(crate) struct Trace {
    pub(crate) nodes: Vec<TreeNode>,
    pub(crate) ops: [u64; 4],
    pub(crate) evidence: Vec<(CdLoc, Evidence)>,
    pub(crate) head_bytes: Option<u64>,
    pub(crate) guarded: bool,
    pub(crate) external_static_call: bool,
    pub(crate) complete: bool,
    pub(crate) jumps: Jumps,
}

impl Trace {
    pub(crate) const fn executed(&self, opcode: u8) -> bool {
        (self.ops[(opcode / 64) as usize] >> (opcode % 64)) & 1 == 1
    }
}

struct FunctionSink {
    ops: [u64; 4],
    evidence: Vec<(CdLoc, Evidence)>,
    seen: BTreeSet<(CdLoc, Evidence)>,
    stmts: Vec<Stmt>,
    external_static_call: bool,
    jumps: Jumps,
}

impl Sink for FunctionSink {
    fn jump(&mut self, pc: usize, target: usize) {
        record_jump(&mut self.jumps, pc, target);
    }

    fn op(&mut self, _pc: usize, opcode: u8) {
        self.ops[(opcode / 64) as usize] |= 1 << (opcode % 64);
    }

    fn evidence(&mut self, loc: CdLoc, evidence: Evidence) {
        if self.evidence.len() < MAX_EVIDENCE && self.seen.insert((loc, evidence)) {
            self.evidence.push((loc, evidence));
        }
    }

    fn stmt(&mut self, stmt: Stmt) {
        if let Stmt::Call {
            kind: CallKind::StaticCall,
            address,
            ..
        } = &stmt
        {
            let precompile: bool = as_const(address)
                .and_then(U256::to_u64)
                .is_some_and(|value: u64| (1..=PRECOMPILE_LAST).contains(&value));
            if !precompile {
                self.external_static_call = true;
            }
        }
        self.stmts.push(stmt);
    }
}

fn head_size(cond: &Val, depth: u8) -> Option<u64> {
    if depth > 4 {
        return None;
    }
    match &cond.expr {
        Expr::Un(UnOp::IsZero, inner) => head_size(inner, depth + 1),
        Expr::Bin(BinOp::Or | BinOp::And, a, b) => {
            match (head_size(a, depth + 1), head_size(b, depth + 1)) {
                (Some(x), Some(y)) => Some(x.max(y)),
                (x, y) => x.or(y),
            }
        }
        Expr::Bin(BinOp::Lt | BinOp::Slt | BinOp::Gt | BinOp::Sgt, a, b) => {
            let (constant, other): (U256, &Val) = match (as_const(a), as_const(b)) {
                (Some(constant), None) => (constant, b),
                (None, Some(constant)) => (constant, a),
                _ => return None,
            };
            let form = affine(other);
            if form.terms.len() != 1 || !matches!(form.terms[0].expr, Expr::CdSize) {
                return None;
            }
            let bytes: U256 = if form.constant == U256::from_u64(4).wrapping_neg() {
                constant
            } else if form.constant.is_zero() && constant >= U256::from_u64(4) {
                constant.wrapping_sub(U256::from_u64(4))
            } else {
                return None;
            };
            bytes
                .to_u64()
                .filter(|bytes: &u64| bytes.is_multiple_of(32) && *bytes <= 32 * 1024)
        }
        _ => None,
    }
}

fn push_node(nodes: &mut Vec<TreeNode>, pc: usize) -> usize {
    nodes.push(TreeNode {
        pc,
        stmts: Vec::new(),
        end: End::Open,
    });
    nodes.len() - 1
}

pub(crate) fn explore(
    machine: &Machine<'_>,
    entry: &Entry,
    budget: &mut u64,
    max_nodes: usize,
) -> Trace {
    let mut nodes: Vec<TreeNode> = Vec::new();
    let root: usize = push_node(&mut nodes, entry.pc);
    let mut sink: FunctionSink = FunctionSink {
        ops: [0; 4],
        evidence: Vec::new(),
        seen: BTreeSet::new(),
        stmts: Vec::new(),
        external_static_call: false,
        jumps: Jumps::new(),
    };
    let mut memo: BTreeMap<u64, usize> = BTreeMap::new();
    let mut work: Vec<(usize, State)> = vec![(root, entry.state.clone())];
    let mut guarded: bool = entry.state.guarded;
    let mut complete: bool = true;
    let mut head_bytes: Option<u64> = None;
    if entry.state.guarded {
        nodes[root].stmts.push(Stmt::CallValueGuard);
    }
    while let Some((start, mut state)) = work.pop() {
        let mut current: usize = start;
        loop {
            let stop: Stop = machine.run(&mut state, &mut sink, budget, true);
            nodes[current].stmts.append(&mut sink.stmts);
            match stop {
                Stop::JumpDest => {
                    let key: u64 = state.fingerprint();
                    if let Some(existing) = memo.get(&key) {
                        nodes[current].end = End::Goto(*existing);
                        break;
                    }
                    if nodes.len() >= max_nodes {
                        nodes[current].end = End::Cut;
                        complete = false;
                        break;
                    }
                    let next: usize = push_node(&mut nodes, state.pc);
                    memo.insert(key, next);
                    nodes[current].end = End::Next(next);
                    current = next;
                }
                Stop::Bucket(_) => {
                    nodes[current].end = End::Cut;
                    complete = false;
                    break;
                }
                Stop::Halt(halt) => {
                    if matches!(
                        halt,
                        Halt::StepLimit | Halt::LoopLimit | Halt::UnresolvedJump
                    ) {
                        complete = false;
                    }
                    nodes[current].end = End::Halt(halt);
                    break;
                }
                Stop::Branch {
                    cond,
                    target,
                    fallthrough,
                } => {
                    if let Some(bytes) = head_size(&cond, 0) {
                        head_bytes = Some(head_bytes.map_or(bytes, |seen: u64| seen.max(bytes)));
                    }
                    let Some(target) = target else {
                        continue;
                    };
                    if let Some(check) = callvalue_check(&cond) {
                        let (taken, fall) = split_branch(&state, target, fallthrough);
                        let (zero, nonzero) = match check {
                            CallValueCheck::JumpWhenNonZero => (fall, taken),
                            CallValueCheck::JumpWhenZero => (taken, fall),
                        };
                        if machine.guard_reverts(&nonzero, budget) {
                            guarded = true;
                            nodes[current].stmts.push(Stmt::CallValueGuard);
                            state = zero;
                            state.guarded = true;
                            continue;
                        }
                    }
                    if !state.note_fork(fallthrough - 1, machine.dests)
                        || nodes.len() + 2 > max_nodes
                    {
                        nodes[current].end = End::Cut;
                        complete = false;
                        break;
                    }
                    let (taken, fall) = split_branch(&state, target, fallthrough);
                    let taken_node: usize = push_node(&mut nodes, target);
                    let fall_node: usize = push_node(&mut nodes, fallthrough);
                    nodes[current].end = End::Branch {
                        cond,
                        taken: taken_node,
                        fall: fall_node,
                    };
                    work.push((taken_node, taken));
                    work.push((fall_node, fall));
                    break;
                }
            }
        }
    }
    Trace {
        nodes,
        ops: sink.ops,
        evidence: sink.evidence,
        head_bytes,
        guarded,
        external_static_call: sink.external_static_call,
        complete,
        jumps: sink.jumps,
    }
}
