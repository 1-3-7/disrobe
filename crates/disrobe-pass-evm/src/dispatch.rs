use std::collections::BTreeMap;

use crate::exec::{
    CallValueCheck, Halt, Jumps, Machine, Sink, State, Stop, callvalue_check, record_jump,
    split_branch,
};
use crate::expr::{BinOp, CdLoc, Expr, UnOp, Val, as_const, is_selector, konst, mentions};
use crate::u256::U256;

const WORLD_EMPTY: u8 = 1;
const WORLD_LONG: u8 = 2;
const LONG_CALLDATA: u64 = 4 + 32 * 32;

#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) pc: usize,
    pub(crate) state: State,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Dispatch {
    pub(crate) entries: BTreeMap<u32, Entry>,
    pub(crate) receive: bool,
    pub(crate) fallback: bool,
    pub(crate) default_reverts: bool,
    pub(crate) delegate_targets: Vec<Val>,
    pub(crate) complete: bool,
    pub(crate) truncated_functions: bool,
    pub(crate) jumps: Jumps,
}

struct JumpSink {
    jumps: Jumps,
}

impl Sink for JumpSink {
    fn op(&mut self, _pc: usize, _opcode: u8) {}
    fn evidence(&mut self, _loc: CdLoc, _evidence: crate::exec::Evidence) {}
    fn stmt(&mut self, _stmt: crate::exec::Stmt) {}
    fn jump(&mut self, pc: usize, target: usize) {
        record_jump(&mut self.jumps, pc, target);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compare {
    JumpIfEqual(u32),
    JumpIfNotEqual(u32),
}

fn selector_const(a: &Val, b: &Val) -> Option<u32> {
    let constant: U256 = if is_selector(a) {
        as_const(b)?
    } else if is_selector(b) {
        as_const(a)?
    } else {
        return None;
    };
    constant
        .to_u64()
        .and_then(|value: u64| u32::try_from(value).ok())
}

fn selector_compare(cond: &Val) -> Option<Compare> {
    match &cond.expr {
        Expr::Bin(BinOp::Eq, a, b) => selector_const(a, b).map(Compare::JumpIfEqual),
        Expr::Bin(BinOp::And, a, b) => match (selector_compare(a), selector_compare(b)) {
            (Some(Compare::JumpIfEqual(selector)), None)
            | (None, Some(Compare::JumpIfEqual(selector))) => Some(Compare::JumpIfEqual(selector)),
            _ => None,
        },
        Expr::Bin(BinOp::Xor | BinOp::Sub, a, b) => {
            selector_const(a, b).map(Compare::JumpIfNotEqual)
        }
        Expr::Un(UnOp::IsZero, inner) => {
            if is_selector(inner) {
                return Some(Compare::JumpIfEqual(0));
            }
            match selector_compare(inner)? {
                Compare::JumpIfEqual(selector) => Some(Compare::JumpIfNotEqual(selector)),
                Compare::JumpIfNotEqual(selector) => Some(Compare::JumpIfEqual(selector)),
            }
        }
        _ if is_selector(cond) => Some(Compare::JumpIfNotEqual(0)),
        _ => None,
    }
}

fn substitute_size(value: &Val, size: U256, budget: &mut u32) -> Option<U256> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    match &value.expr {
        Expr::Const(constant) => Some(*constant),
        Expr::CdSize => Some(size),
        Expr::Un(UnOp::IsZero, a) => {
            Some(U256::from_bool(substitute_size(a, size, budget)?.is_zero()))
        }
        Expr::Un(UnOp::Not, a) => Some(!substitute_size(a, size, budget)?),
        Expr::Bin(op, a, b) => {
            let x: U256 = substitute_size(a, size, budget)?;
            let y: U256 = substitute_size(b, size, budget)?;
            Some(match op {
                BinOp::Add => x.wrapping_add(y),
                BinOp::Sub => x.wrapping_sub(y),
                BinOp::Lt => U256::from_bool(x < y),
                BinOp::Gt => U256::from_bool(x > y),
                BinOp::Slt => U256::from_bool(x.signed_cmp(y).is_lt()),
                BinOp::Sgt => U256::from_bool(x.signed_cmp(y).is_gt()),
                BinOp::Eq => U256::from_bool(x == y),
                BinOp::And => x & y,
                BinOp::Or => x | y,
                BinOp::Xor => x ^ y,
                BinOp::Shr => y.shift_right(x.shift_amount()),
                BinOp::Shl => y.shift_left(x.shift_amount()),
                _ => return None,
            })
        }
        _ => None,
    }
}

fn size_truth(cond: &Val, size: u64) -> Option<bool> {
    let mut budget: u32 = 256;
    substitute_size(cond, U256::from_u64(size), &mut budget).map(|value: U256| !value.is_zero())
}

struct Path {
    state: State,
    worlds: u8,
    tested_empty: bool,
}

pub(crate) fn discover(machine: &Machine<'_>, budget: &mut u64, max_functions: usize) -> Dispatch {
    let mut out: Dispatch = Dispatch {
        complete: true,
        ..Dispatch::default()
    };
    let mut work: Vec<Path> = vec![Path {
        state: State::default(),
        worlds: WORLD_EMPTY | WORLD_LONG,
        tested_empty: false,
    }];
    let mut sink: JumpSink = JumpSink {
        jumps: Jumps::new(),
    };
    let mut paths: usize = 0;
    while let Some(mut path) = work.pop() {
        paths += 1;
        if paths > 1 << 16 {
            out.complete = false;
            break;
        }
        let stop: Stop = machine.run(&mut path.state, &mut sink, budget, false);
        match stop {
            Stop::JumpDest => {
                work.push(path);
            }
            Stop::Bucket(modulus) => {
                for bucket in (0..modulus).rev() {
                    let mut state: State = path.state.clone();
                    state.stack.push(konst(U256::from_u64(u64::from(bucket))));
                    work.push(Path {
                        state,
                        worlds: path.worlds,
                        tested_empty: path.tested_empty,
                    });
                }
            }
            Stop::Halt(halt) => {
                if matches!(halt, Halt::StepLimit) {
                    out.complete = false;
                    break;
                }
                if matches!(halt, Halt::LoopLimit | Halt::UnresolvedJump) {
                    out.complete = false;
                }
                if path.worlds & WORLD_LONG != 0 {
                    if halt.succeeds() || path.state.delegate_target.is_some() {
                        out.fallback = true;
                    } else if matches!(halt, Halt::Revert(_) | Halt::Invalid) {
                        out.default_reverts = true;
                    }
                }
                if path.worlds & WORLD_EMPTY != 0 && path.tested_empty && halt.succeeds() {
                    out.receive = true;
                }
                if let Some(target) = path.state.delegate_target.take() {
                    out.delegate_targets.push(target);
                }
            }
            Stop::Branch {
                cond,
                target,
                fallthrough,
            } => {
                let Some(target) = target else {
                    let mut fall: Path = path;
                    fall.state.pc = fallthrough;
                    work.push(fall);
                    continue;
                };
                if let Some(compare) = selector_compare(&cond) {
                    let (selector, entry_pc, rest_pc): (u32, usize, usize) = match compare {
                        Compare::JumpIfEqual(selector) => (selector, target, fallthrough),
                        Compare::JumpIfNotEqual(selector) => (selector, fallthrough, target),
                    };
                    if path.worlds & WORLD_LONG != 0 {
                        if out.entries.len() < max_functions {
                            out.entries.entry(selector).or_insert_with(|| {
                                let mut state: State = path.state.clone();
                                state.pc = entry_pc;
                                Entry {
                                    pc: entry_pc,
                                    state,
                                }
                            });
                        } else {
                            out.truncated_functions = true;
                        }
                    }
                    let mut rest: Path = path;
                    rest.state.pc = rest_pc;
                    work.push(rest);
                    continue;
                }
                if let Some(check) = callvalue_check(&cond) {
                    let (taken, fall) = split_branch(&path.state, target, fallthrough);
                    let (zero, nonzero) = match check {
                        CallValueCheck::JumpWhenNonZero => (fall, taken),
                        CallValueCheck::JumpWhenZero => (taken, fall),
                    };
                    if machine.guard_reverts(&nonzero, budget) {
                        let mut guarded: Path = Path {
                            state: zero,
                            worlds: path.worlds,
                            tested_empty: path.tested_empty,
                        };
                        guarded.state.guarded = true;
                        work.push(guarded);
                        continue;
                    }
                    work.push(Path {
                        state: nonzero,
                        worlds: path.worlds,
                        tested_empty: path.tested_empty,
                    });
                    work.push(Path {
                        state: zero,
                        worlds: path.worlds,
                        tested_empty: path.tested_empty,
                    });
                    continue;
                }
                let mut size_budget: u32 = 64;
                let size_dependent: bool = mentions(
                    &cond,
                    &|expr: &Expr| matches!(expr, Expr::CdSize),
                    &mut size_budget,
                );
                let (taken, fall) = split_branch(&path.state, target, fallthrough);
                if size_dependent {
                    let empty: Option<bool> = size_truth(&cond, 0);
                    let short: Option<bool> = size_truth(&cond, 1);
                    let long: Option<bool> = size_truth(&cond, LONG_CALLDATA);
                    let tests_empty: bool = empty.is_some() && short.is_some() && empty != short;
                    for (state, branch) in [(fall, false), (taken, true)] {
                        let mut worlds: u8 = 0;
                        if path.worlds & WORLD_EMPTY != 0 && empty.is_none_or(|v: bool| v == branch)
                        {
                            worlds |= WORLD_EMPTY;
                        }
                        if path.worlds & WORLD_LONG != 0 && long.is_none_or(|v: bool| v == branch) {
                            worlds |= WORLD_LONG;
                        }
                        if worlds != 0 {
                            work.push(Path {
                                state,
                                worlds,
                                tested_empty: path.tested_empty || tests_empty,
                            });
                        }
                    }
                    continue;
                }
                if !path.state.note_fork(fallthrough - 1, machine.dests) {
                    out.complete = false;
                    continue;
                }
                let mut fall_state: State = fall;
                let mut taken_state: State = taken;
                fall_state.forks = path.state.forks.clone();
                taken_state.forks = path.state.forks.clone();
                work.push(Path {
                    state: fall_state,
                    worlds: path.worlds,
                    tested_empty: path.tested_empty,
                });
                work.push(Path {
                    state: taken_state,
                    worlds: path.worlds,
                    tested_empty: path.tested_empty,
                });
            }
        }
    }
    out.jumps = sink.jumps;
    out
}
