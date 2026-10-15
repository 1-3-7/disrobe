use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::{
    AggregatePlan, Block, Cond, CondKind, Flags, LoopCond, Node, RegRef, Stmt, SwitchCase,
    VARIABLE_COLLECTION_MAX_DEPTH, loop_cond_var, node_never_returns, reg_var, rs_cond_expr,
    rs_emit_stmt, rs_if_cond_expr, rs_signed_operand,
};

const MAX_DISPATCH_BLOCKS: usize = 4096;

enum Op<'a> {
    Stmt(&'a Stmt),
    Snapshot {
        var: u32,
        cond: CondKind,
        flags: &'a Flags,
    },
}

enum Exit<'a> {
    Open,
    Jump(usize),
    If {
        cond: &'a Cond,
        taken: usize,
        otherwise: usize,
    },
    Loop {
        cond: &'a LoopCond,
        taken: usize,
        otherwise: usize,
    },
    Switch {
        disc: RegRef,
        arms: Vec<(&'a [i64], usize)>,
        default: usize,
    },
    Return,
}

struct DispatchBlock<'a> {
    ops: Vec<Op<'a>>,
    exit: Exit<'a>,
}

#[derive(Clone, Copy)]
struct Targets {
    exit: usize,
    resume: Option<usize>,
}

struct Lowering<'a> {
    blocks: Vec<DispatchBlock<'a>>,
    labels: BTreeMap<u32, usize>,
    placed: BTreeSet<u32>,
    current: usize,
}

fn nested(targets: &[Targets], innermost: Targets) -> Vec<Targets> {
    targets
        .iter()
        .copied()
        .chain(std::iter::once(innermost))
        .collect()
}

impl<'a> Lowering<'a> {
    fn open(&mut self) -> Option<usize> {
        if self.blocks.len() >= MAX_DISPATCH_BLOCKS {
            return None;
        }
        self.blocks.push(DispatchBlock {
            ops: Vec::new(),
            exit: Exit::Open,
        });
        Some(self.blocks.len() - 1)
    }

    fn close(&mut self, exit: Exit<'a>) -> Option<()> {
        let block: &mut DispatchBlock<'a> = self.blocks.get_mut(self.current)?;
        if matches!(block.exit, Exit::Open) {
            block.exit = exit;
        }
        Some(())
    }

    fn terminate(&mut self, exit: Exit<'a>) -> Option<()> {
        self.close(exit)?;
        self.current = self.open()?;
        Some(())
    }

    fn push(&mut self, op: Op<'a>) -> Option<()> {
        self.blocks.get_mut(self.current)?.ops.push(op);
        Some(())
    }

    fn label(&mut self, label: u32) -> Option<usize> {
        if let Some(&block) = self.labels.get(&label) {
            return Some(block);
        }
        let block: usize = self.open()?;
        self.labels.insert(label, block);
        Some(block)
    }

    fn lower(&mut self, nodes: &'a [Node], targets: &[Targets], depth: usize) -> Option<()> {
        if depth > VARIABLE_COLLECTION_MAX_DEPTH {
            return None;
        }
        let next: usize = depth + 1;
        for (index, node) in nodes.iter().enumerate() {
            match node {
                Node::Stmt(stmt) => self.push(Op::Stmt(stmt))?,
                Node::CondSnapshot { var, cond, flags } => self.push(Op::Snapshot {
                    var: *var,
                    cond: *cond,
                    flags,
                })?,
                Node::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    let taken: usize = self.open()?;
                    let otherwise: Option<usize> = match else_body {
                        Some(_) => Some(self.open()?),
                        None => None,
                    };
                    let join: usize = self.open()?;
                    self.close(Exit::If {
                        cond,
                        taken,
                        otherwise: otherwise.unwrap_or(join),
                    })?;
                    self.current = taken;
                    self.lower(then_body, targets, next)?;
                    self.close(Exit::Jump(join))?;
                    if let (Some(body), Some(entry)) = (else_body, otherwise) {
                        self.current = entry;
                        self.lower(body, targets, next)?;
                        self.close(Exit::Jump(join))?;
                    }
                    self.current = join;
                }
                Node::DoWhile { body, cond } => {
                    let entry: usize = self.open()?;
                    let check: usize = self.open()?;
                    let exit: usize = self.open()?;
                    self.close(Exit::Jump(entry))?;
                    self.current = entry;
                    let inner: Vec<Targets> = nested(
                        targets,
                        Targets {
                            exit,
                            resume: Some(check),
                        },
                    );
                    self.lower(body, &inner, next)?;
                    self.close(Exit::Jump(check))?;
                    self.current = check;
                    self.close(Exit::Loop {
                        cond,
                        taken: entry,
                        otherwise: exit,
                    })?;
                    self.current = exit;
                }
                Node::While { body, cond } => {
                    let header: usize = self.open()?;
                    let entry: usize = self.open()?;
                    let exit: usize = self.open()?;
                    self.close(Exit::Jump(header))?;
                    self.current = header;
                    match cond {
                        Some(cond) => self.close(Exit::Loop {
                            cond,
                            taken: entry,
                            otherwise: exit,
                        })?,
                        None => self.close(Exit::Jump(entry))?,
                    }
                    self.current = entry;
                    let inner: Vec<Targets> = nested(
                        targets,
                        Targets {
                            exit,
                            resume: Some(header),
                        },
                    );
                    self.lower(body, &inner, next)?;
                    self.close(Exit::Jump(header))?;
                    self.current = exit;
                }
                Node::Switch {
                    disc,
                    cases,
                    default,
                } => {
                    let mut entries: Vec<usize> = Vec::with_capacity(cases.len());
                    for _ in cases {
                        entries.push(self.open()?);
                    }
                    let default_entry: usize = self.open()?;
                    let exit: usize = self.open()?;
                    self.close(Exit::Switch {
                        disc: *disc,
                        arms: cases
                            .iter()
                            .map(|case: &SwitchCase| case.values.as_slice())
                            .zip(entries.iter().copied())
                            .collect(),
                        default: default_entry,
                    })?;
                    let inner: Vec<Targets> = nested(targets, Targets { exit, resume: None });
                    for (position, (case, entry)) in cases.iter().zip(&entries).enumerate() {
                        self.current = *entry;
                        self.lower(&case.body, &inner, next)?;
                        let after: usize = if case.fallthrough {
                            entries.get(position + 1).copied().unwrap_or(default_entry)
                        } else {
                            exit
                        };
                        self.close(Exit::Jump(after))?;
                    }
                    self.current = default_entry;
                    self.lower(default, &inner, next)?;
                    self.close(Exit::Jump(exit))?;
                    self.current = exit;
                }
                Node::Break => {
                    let target: usize = targets.last()?.exit;
                    self.terminate(Exit::Jump(target))?;
                }
                Node::Continue => {
                    let target: usize = targets
                        .iter()
                        .rev()
                        .find_map(|enclosing: &Targets| enclosing.resume)?;
                    self.terminate(Exit::Jump(target))?;
                }
                Node::Return => {
                    if index
                        .checked_sub(1)
                        .and_then(|previous: usize| nodes.get(previous))
                        .is_some_and(node_never_returns)
                    {
                        continue;
                    }
                    self.terminate(Exit::Return)?;
                }
                Node::Label(label) => {
                    if !self.placed.insert(*label) {
                        return None;
                    }
                    let block: usize = self.label(*label)?;
                    self.close(Exit::Jump(block))?;
                    self.current = block;
                }
                Node::Goto(label) => {
                    let block: usize = self.label(*label)?;
                    self.terminate(Exit::Jump(block))?;
                }
                Node::BreakLoop(_)
                | Node::ContinueLoop(_)
                | Node::ResumeAt(_)
                | Node::OuterResume(_) => return None,
            }
        }
        Some(())
    }

    fn forward(&self, mut block: usize) -> usize {
        for _ in 0..self.blocks.len() {
            match self.blocks.get(block) {
                Some(DispatchBlock {
                    ops,
                    exit: Exit::Jump(next),
                }) if ops.is_empty() && *next != block => block = *next,
                _ => break,
            }
        }
        block
    }

    fn successors(&self, block: usize) -> Vec<usize> {
        match self
            .blocks
            .get(block)
            .map(|block: &DispatchBlock<'a>| &block.exit)
        {
            Some(Exit::Jump(next)) => vec![*next],
            Some(
                Exit::If {
                    taken, otherwise, ..
                }
                | Exit::Loop {
                    taken, otherwise, ..
                },
            ) => vec![*taken, *otherwise],
            Some(Exit::Switch { arms, default, .. }) => arms
                .iter()
                .map(|(_, target): &(&[i64], usize)| *target)
                .chain(std::iter::once(*default))
                .collect(),
            Some(Exit::Return | Exit::Open) | None => Vec::new(),
        }
        .into_iter()
        .map(|target: usize| self.forward(target))
        .collect()
    }
}

pub(super) fn rs_emit_dispatch(
    out: &mut String,
    body: &Block,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> Option<()> {
    let mut lowering: Lowering<'_> = Lowering {
        blocks: Vec::new(),
        labels: BTreeMap::new(),
        placed: BTreeSet::new(),
        current: 0,
    };
    lowering.current = lowering.open()?;
    lowering.lower(body, &[], 0)?;
    lowering.close(Exit::Return)?;
    if lowering
        .blocks
        .iter()
        .any(|block: &DispatchBlock<'_>| matches!(block.exit, Exit::Open))
    {
        return None;
    }
    let entry: usize = lowering.forward(0);
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut pending: Vec<usize> = vec![entry];
    while let Some(block) = pending.pop() {
        if reachable.insert(block) {
            pending.extend(lowering.successors(block));
        }
    }
    let arm: &str = "            ";
    let inner: &str = "                ";
    let _ = writeln!(out, "    let mut recover_state: usize = {entry};");
    let _ = writeln!(out, "    loop {{");
    let _ = writeln!(out, "        match recover_state {{");
    for id in &reachable {
        let block: &DispatchBlock<'_> = lowering.blocks.get(*id)?;
        let _ = writeln!(out, "{arm}{id} => {{");
        for op in &block.ops {
            match op {
                Op::Stmt(stmt) => rs_emit_stmt(out, stmt, inner, aggregates)?,
                Op::Snapshot { var, cond, flags } => {
                    let cond_text: String = rs_cond_expr(*cond, flags, aggregates)?;
                    let _ = writeln!(
                        out,
                        "{inner}{} = ({cond_text}) as u64;",
                        loop_cond_var(*var)
                    );
                }
            }
        }
        let forward = |target: usize| lowering.forward(target);
        match &block.exit {
            Exit::Jump(next) => {
                let _ = writeln!(out, "{inner}recover_state = {};", forward(*next));
            }
            Exit::If {
                cond,
                taken,
                otherwise,
            } => {
                let cond_text: String = rs_if_cond_expr(cond, aggregates)?;
                let _ = writeln!(
                    out,
                    "{inner}recover_state = if {cond_text} {{ {} }} else {{ {} }};",
                    forward(*taken),
                    forward(*otherwise)
                );
            }
            Exit::Loop {
                cond,
                taken,
                otherwise,
            } => {
                let cond_text: String = match cond {
                    LoopCond::Direct { cond, flags } => rs_cond_expr(*cond, flags, aggregates)?,
                    LoopCond::Snapshot { var } => format!("{} != 0", loop_cond_var(*var)),
                };
                let _ = writeln!(
                    out,
                    "{inner}recover_state = if {cond_text} {{ {} }} else {{ {} }};",
                    forward(*taken),
                    forward(*otherwise)
                );
            }
            Exit::Switch {
                disc,
                arms,
                default,
            } => {
                let key: String = rs_signed_operand(reg_var(disc.reg), disc.width);
                let _ = writeln!(out, "{inner}recover_state = match {key} {{");
                for (values, target) in arms {
                    if values.is_empty() {
                        continue;
                    }
                    let pattern: String = values
                        .iter()
                        .map(|value: &i64| format!("{value}i64"))
                        .collect::<Vec<String>>()
                        .join(" | ");
                    let _ = writeln!(out, "{inner}    {pattern} => {},", forward(*target));
                }
                let _ = writeln!(out, "{inner}    _ => {},", forward(*default));
                let _ = writeln!(out, "{inner}}};");
            }
            Exit::Return => {
                let _ = writeln!(out, "{inner}return {ret_expr};");
            }
            Exit::Open => return None,
        }
        let _ = writeln!(out, "{arm}}}");
    }
    let _ = writeln!(out, "{arm}_ => std::process::abort(),");
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    Some(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::{Reg, Source, Width, rs_emit_block};
    use super::*;

    fn rax() -> RegRef {
        RegRef {
            reg: Reg::Rax,
            width: Width::W64,
        }
    }

    fn rax_is_zero() -> Cond {
        Cond::leaf(
            CondKind::E,
            Flags::Cmp {
                lhs: rax(),
                rhs: Source::Imm(0),
            },
        )
    }

    fn set_rax(value: i64) -> Node {
        Node::Stmt(Stmt::Assign {
            dest: rax(),
            src: Source::Imm(value),
        })
    }

    fn dispatch(body: &Block) -> Option<String> {
        let mut out: String = String::new();
        rs_emit_dispatch(&mut out, body, "r_rax", &AggregatePlan::default()).map(|()| out)
    }

    #[test]
    fn a_goto_into_a_sibling_arm_lowers_to_a_dispatch_loop() {
        let body: Block = vec![
            Node::If {
                cond: rax_is_zero(),
                then_body: vec![Node::If {
                    cond: rax_is_zero(),
                    then_body: vec![Node::Label(8), set_rax(87)],
                    else_body: None,
                }],
                else_body: Some(vec![Node::Goto(8)]),
            },
            Node::Return,
        ];
        let mut structured: String = String::new();
        assert!(
            rs_emit_block(
                &mut structured,
                &body,
                1,
                "r_rax",
                &AggregatePlan::default()
            )
            .is_none(),
            "the structured emitter cannot express a jump into a sibling arm: {structured}"
        );
        let source: String = dispatch(&body).expect("the dispatch loop expresses any forward goto");
        assert!(
            source.contains("let mut recover_state: usize = 0;"),
            "{source}"
        );
        assert_eq!(source.matches("return r_rax;").count(), 1, "{source}");
        assert_eq!(
            source.matches("r_rax = 87i64 as u64;").count(),
            1,
            "{source}"
        );
        assert!(source.contains("_ => std::process::abort(),"), "{source}");
    }

    #[test]
    fn labels_that_are_missing_or_placed_twice_are_refused() {
        for body in [
            vec![Node::Goto(3), Node::Return],
            vec![Node::Label(3), set_rax(1), Node::Label(3), Node::Return],
            vec![Node::Break],
            vec![Node::Continue],
        ] {
            assert_eq!(dispatch(&body), None, "{body:?}");
        }
    }

    #[test]
    fn a_continue_in_a_do_while_reaches_the_loop_condition() {
        let body: Block = vec![
            Node::DoWhile {
                body: vec![
                    set_rax(2),
                    Node::If {
                        cond: rax_is_zero(),
                        then_body: vec![Node::Continue],
                        else_body: None,
                    },
                    set_rax(3),
                ],
                cond: LoopCond::Direct {
                    cond: CondKind::Ne,
                    flags: Flags::Cmp {
                        lhs: rax(),
                        rhs: Source::Imm(0),
                    },
                },
            },
            Node::Return,
        ];
        let source: String = dispatch(&body).expect("a do-while lowers");
        let arms: Vec<&str> = source.lines().map(str::trim).collect();
        let continue_arm: usize = arms
            .iter()
            .position(|line: &&str| line.contains("== 0i64 as u64 as i64 as i64 { 2 } else { 5 };"))
            .unwrap_or_else(|| panic!("the continue must jump to the condition arm: {source}"));
        let check_arm: usize = arms
            .iter()
            .position(|line: &&str| *line == "2 => {")
            .unwrap_or_else(|| panic!("the loop condition has its own arm: {source}"));
        assert!(continue_arm < check_arm, "{source}");
        assert!(
            arms.get(check_arm + 1).is_some_and(
                |line: &&str| line.contains("!= 0i64 as u64 as i64 as i64 { 1 } else { 3 };")
            ),
            "{source}"
        );
    }
}
