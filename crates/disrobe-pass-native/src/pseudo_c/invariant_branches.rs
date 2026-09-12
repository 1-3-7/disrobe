use std::collections::BTreeSet;

use disrobe_mba::{CmpOp, Expr, OpaqueVerdict, Predicate};

use super::{
    BinOp, BlockTerm, CfgBlock, CondKind, Flags, Reg, RegRef, Source, Stmt, Width,
    block_predecessors, cfg_from_leaf_blocks, enumerable_gpr_writes, reachable_blocks,
};

const MAX_BLOCKS: usize = 256;
const MAX_STATEMENTS: usize = 2048;
const MAX_VALUES: usize = 4;
const MAX_EXPR_NODES: usize = 128;
const MAX_READ_STEPS: usize = 16384;
const MAX_FOLDS: usize = 16;
const MAX_PROOFS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Point {
    block: usize,
    before: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Definition {
    Input,
    Write(Point),
}

struct Values<'a> {
    blocks: &'a [CfgBlock],
    reachable: &'a BTreeSet<usize>,
    preds: Vec<Vec<usize>>,
    remaining: usize,
}

fn push_value(values: &mut Vec<Expr>, value: Expr) -> Option<()> {
    if value.node_count() > MAX_EXPR_NODES {
        return None;
    }
    if !values.contains(&value) {
        values.push(value);
    }
    (values.len() <= MAX_VALUES).then_some(())
}

impl Values<'_> {
    fn definitions(&mut self, point: Point, register: Reg) -> Option<BTreeSet<Definition>> {
        if !self.reachable.contains(&point.block) {
            return None;
        }
        let mut pending: Vec<Point> = vec![point];
        let mut visited: BTreeSet<Point> = BTreeSet::new();
        let mut definitions: BTreeSet<Definition> = BTreeSet::new();
        while let Some(point) = pending.pop() {
            if !visited.insert(point) {
                continue;
            }
            self.remaining = self.remaining.checked_sub(1)?;
            let block: &CfgBlock = self.blocks.get(point.block)?;
            let statements: &[Stmt] = block.stmts.get(..point.before)?;
            let mut writer: Option<Point> = None;
            for (position, statement) in statements.iter().enumerate().rev() {
                self.remaining = self.remaining.checked_sub(1)?;
                let writes: Vec<RegRef> = enumerable_gpr_writes(statement)?;
                if writes
                    .iter()
                    .any(|written: &RegRef| written.reg == register)
                {
                    writer = Some(Point {
                        block: point.block,
                        before: position,
                    });
                    break;
                }
            }
            match writer {
                Some(writer) => {
                    definitions.insert(Definition::Write(writer));
                }
                None => {
                    if point.block == 0 {
                        definitions.insert(Definition::Input);
                    }
                    let incoming: &[usize] = self.preds.get(point.block)?;
                    if incoming.is_empty() && point.block != 0 {
                        return None;
                    }
                    for predecessor in incoming {
                        if !self.reachable.contains(predecessor) {
                            continue;
                        }
                        pending.push(Point {
                            block: *predecessor,
                            before: self.blocks.get(*predecessor)?.stmts.len(),
                        });
                    }
                }
            }
            if definitions.len() > MAX_VALUES {
                return None;
            }
        }
        (!definitions.is_empty()).then_some(definitions)
    }

    fn register(
        &mut self,
        point: Point,
        register: RegRef,
        active: &mut BTreeSet<(Point, Reg)>,
    ) -> Option<Vec<Expr>> {
        if active.len() >= 16 {
            return None;
        }
        let definitions: BTreeSet<Definition> = self.definitions(point, register.reg)?;
        let mut values: Vec<Expr> = Vec::new();
        for definition in definitions {
            let alternatives: Vec<Expr> = match definition {
                Definition::Input => vec![Expr::Var(register.reg as u32)],
                Definition::Write(writer) => {
                    if !active.insert((writer, register.reg)) {
                        return None;
                    }
                    let statement: &Stmt =
                        self.blocks.get(writer.block)?.stmts.get(writer.before)?;
                    if !matches!(statement, Stmt::Assign { .. } | Stmt::BinAssign { .. }) {
                        return None;
                    }
                    let statement: Stmt = statement.clone();
                    let (destination, alternatives): (RegRef, Vec<Expr>) = match statement {
                        Stmt::Assign { dest, src } => (dest, self.source(writer, &src, active)?),
                        Stmt::BinAssign { dest, op, src } => {
                            let left: Vec<Expr> = self.register(writer, dest, active)?;
                            let right: Vec<Expr> = self.source(writer, &src, active)?;
                            let mut alternatives: Vec<Expr> = Vec::new();
                            for left in left {
                                for right in &right {
                                    let value: Expr = match op {
                                        BinOp::Add => Expr::add(left.clone(), right.clone()),
                                        BinOp::Sub => Expr::sub(left.clone(), right.clone()),
                                        BinOp::And => Expr::and(left.clone(), right.clone()),
                                        _ => return None,
                                    };
                                    push_value(&mut alternatives, value)?;
                                }
                            }
                            (dest, alternatives)
                        }
                        _ => return None,
                    };
                    active.remove(&(writer, register.reg));
                    alternatives
                        .into_iter()
                        .map(|value: Expr| match destination.width {
                            Width::W64 => Some(value),
                            Width::W32 => Some(Expr::and(value, Expr::Const(u64::from(u32::MAX)))),
                            Width::W16 | Width::W8 => None,
                        })
                        .collect::<Option<Vec<_>>>()?
                }
            };
            for value in alternatives {
                let value: Expr = match register.width {
                    Width::W64 => value,
                    Width::W32 => Expr::and(value, Expr::Const(u64::from(u32::MAX))),
                    Width::W16 | Width::W8 => return None,
                };
                push_value(&mut values, value)?;
            }
        }
        Some(values)
    }

    fn source(
        &mut self,
        point: Point,
        source: &Source,
        active: &mut BTreeSet<(Point, Reg)>,
    ) -> Option<Vec<Expr>> {
        match source {
            Source::Imm(value) => Some(vec![Expr::Const(*value as u64)]),
            Source::Reg(register) => self.register(point, *register, active),
            Source::Lea {
                base,
                index: None,
                disp,
            } => {
                let bases: Vec<Expr> = match base {
                    Some(register) => self.register(
                        point,
                        RegRef {
                            reg: *register,
                            width: Width::W64,
                        },
                        active,
                    )?,
                    None => vec![Expr::Const(0)],
                };
                Some(
                    bases
                        .into_iter()
                        .map(|base: Expr| Expr::add(base, Expr::Const(*disp as u64)))
                        .collect(),
                )
            }
            Source::Lea { index: Some(_), .. } | Source::Mem(_) => None,
        }
    }

    fn predicate(&mut self, block: usize, negate: bool) -> Option<Predicate> {
        let term: BlockTerm = self.blocks.get(block)?.term.clone();
        let BlockTerm::Branch {
            mut kind, flags, ..
        } = term
        else {
            return None;
        };
        if negate {
            kind = kind.negate();
        }
        let op: CmpOp = match kind {
            CondKind::E => CmpOp::Eq,
            CondKind::Ne => CmpOp::Ne,
            CondKind::G => CmpOp::SignedGt,
            CondKind::Ge => CmpOp::SignedGe,
            CondKind::L => CmpOp::SignedLt,
            CondKind::Le => CmpOp::SignedLe,
            CondKind::A => CmpOp::UnsignedGt,
            CondKind::Ae => CmpOp::UnsignedGe,
            CondKind::B => CmpOp::UnsignedLt,
            CondKind::Be => CmpOp::UnsignedLe,
            _ => return None,
        };
        let (left, right): (RegRef, Source) = match flags {
            Flags::Cmp { lhs, rhs } => (lhs, rhs),
            Flags::Test { operand } => (operand, Source::Imm(0)),
            _ => return None,
        };
        if left.width != Width::W64 {
            return None;
        }
        let point: Point = Point {
            block,
            before: self.blocks[block].stmts.len(),
        };
        let left: Vec<Expr> = self.register(point, left, &mut BTreeSet::new())?;
        let right: Vec<Expr> = self.source(point, &right, &mut BTreeSet::new())?;
        let mut predicate: Option<Predicate> = None;
        for left in left {
            for right in &right {
                let next: Predicate = Predicate::Compare {
                    op,
                    left: left.clone(),
                    right: right.clone(),
                };
                predicate = Some(match predicate {
                    None => next,
                    Some(previous) => Predicate::or(previous, next),
                });
            }
        }
        predicate.filter(|predicate: &Predicate| predicate.node_count() <= 512)
    }
}

struct ProvedBranch {
    block: usize,
    target: usize,
}

fn edge_negation(block: &CfgBlock, target: usize) -> Option<bool> {
    let BlockTerm::Branch {
        taken, fallthrough, ..
    } = block.term
    else {
        return None;
    };
    if taken == fallthrough {
        return None;
    }
    if taken == target {
        Some(false)
    } else if fallthrough == target {
        Some(true)
    } else {
        None
    }
}

fn prove_one(blocks: &[CfgBlock], proofs: &mut usize) -> Option<ProvedBranch> {
    let cfg: super::structuring::Cfg = cfg_from_leaf_blocks(blocks)?;
    let reachable: BTreeSet<usize> = reachable_blocks(blocks);
    let mut values: Values<'_> = Values {
        blocks,
        reachable: &reachable,
        preds: block_predecessors(blocks),
        remaining: MAX_READ_STEPS,
    };
    for component in super::structuring::strongly_connected_components(&cfg) {
        let members: BTreeSet<usize> = component
            .into_iter()
            .map(|node: u32| node as usize)
            .collect();
        if members.contains(&0)
            || (members.len() == 1
                && !blocks[*members.first()?]
                    .successors()
                    .contains(members.first()?))
        {
            continue;
        }
        let entries: BTreeSet<(usize, usize)> = members
            .iter()
            .flat_map(|target: &usize| {
                values.preds[*target]
                    .iter()
                    .filter(|source: &&usize| {
                        reachable.contains(source) && !members.contains(source)
                    })
                    .map(move |source: &usize| (*source, *target))
            })
            .collect();
        if entries.len() != 1 {
            continue;
        }
        let (controller, entry): (usize, usize) = *entries.first()?;
        let Some(negate): Option<bool> = edge_negation(&blocks[controller], entry) else {
            continue;
        };
        let Some(context): Option<Predicate> = values.predicate(controller, negate) else {
            continue;
        };
        let BlockTerm::Branch {
            flags: entry_flags, ..
        } = &blocks[controller].term
        else {
            continue;
        };
        let mut candidates: Vec<usize> = members.iter().copied().collect();
        candidates.sort_by_key(|candidate: &usize| match &blocks[*candidate].term {
            BlockTerm::Branch { flags, .. } => flags != entry_flags,
            BlockTerm::Ret | BlockTerm::Jump(_) | BlockTerm::Fall(_) => true,
        });
        for candidate in &candidates {
            let BlockTerm::Branch {
                taken, fallthrough, ..
            } = blocks[*candidate].term
            else {
                continue;
            };
            let mut context: Predicate = context.clone();
            let mut current: usize = *candidate;
            let mut visited: BTreeSet<usize> = BTreeSet::new();
            for _ in 0..8 {
                if !visited.insert(current) {
                    break;
                }
                let incoming: Vec<usize> = values.preds[current]
                    .iter()
                    .copied()
                    .filter(|pred: &usize| reachable.contains(pred))
                    .collect();
                let [predecessor]: [usize; 1] = match incoming.as_slice().try_into() {
                    Ok(single) => single,
                    Err(_) => break,
                };
                if let Some(negate) = edge_negation(&blocks[predecessor], current)
                    && let Some(guard) = values.predicate(predecessor, negate)
                {
                    context = Predicate::and(context, guard);
                }
                current = predecessor;
            }
            for (negate, target) in [(false, fallthrough), (true, taken)] {
                let Some(condition): Option<Predicate> = values.predicate(*candidate, negate)
                else {
                    continue;
                };
                let query: Predicate = Predicate::and(context.clone(), condition);
                if query.node_count() > 1024 {
                    continue;
                }
                *proofs = proofs.checked_sub(1)?;
                if matches!(
                    disrobe_mba::verify::classify_predicate_budgeted(
                        &query,
                        disrobe_mba::Width::W64,
                        1 << 16
                    ),
                    OpaqueVerdict::AlwaysFalse {
                        verified_width: disrobe_mba::Width::W64,
                        lifted: false
                    }
                ) {
                    return Some(ProvedBranch {
                        block: *candidate,
                        target,
                    });
                }
            }
        }
    }
    None
}

pub(super) fn specialize(blocks: &[CfgBlock]) -> Option<Vec<CfgBlock>> {
    if blocks.len() > MAX_BLOCKS
        || blocks
            .iter()
            .map(|block: &CfgBlock| block.stmts.len())
            .sum::<usize>()
            > MAX_STATEMENTS
    {
        return None;
    }
    let mut rewritten: Vec<CfgBlock> = blocks.to_vec();
    let mut proofs: usize = MAX_PROOFS;
    let mut changed: bool = false;
    for _ in 0..MAX_FOLDS {
        let Some(proof): Option<ProvedBranch> = prove_one(&rewritten, &mut proofs) else {
            break;
        };
        rewritten[proof.block].term = BlockTerm::Jump(proof.target);
        changed = true;
    }
    changed.then_some(rewritten)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn register(reg: Reg) -> RegRef {
        RegRef {
            reg,
            width: Width::W64,
        }
    }

    fn branch(
        reg: Reg,
        kind: CondKind,
        immediate: i64,
        taken: usize,
        fallthrough: usize,
    ) -> BlockTerm {
        BlockTerm::Branch {
            kind,
            flags: Flags::Cmp {
                lhs: register(reg),
                rhs: Source::Imm(immediate),
            },
            taken,
            fallthrough,
        }
    }

    fn producer(displacement: i64) -> Stmt {
        Stmt::Assign {
            dest: register(Reg::Rbx),
            src: Source::Lea {
                base: Some(Reg::Rcx),
                index: None,
                disp: displacement,
            },
        }
    }

    fn invariant_loop() -> Vec<CfgBlock> {
        vec![
            CfgBlock {
                stmts: vec![producer(-1)],
                term: branch(Reg::Rbx, CondKind::Be, 10, 1, 3),
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rbx, CondKind::A, 10, 3, 2),
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rdx, CondKind::G, 0, 1, 3),
            },
            CfgBlock {
                stmts: vec![],
                term: BlockTerm::Ret,
            },
        ]
    }

    #[test]
    fn invariant_branch_follows_actual_producers_and_preserves_statements() {
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        let specialized: Vec<CfgBlock> = specialize(&blocks).expect("invariant branch proof");
        assert!(matches!(specialized[1].term, BlockTerm::Jump(2)));
        assert_eq!(specialized[0].stmts, blocks[0].stmts);
        assert_eq!(specialized[2].term, blocks[2].term);
        blocks[2].stmts.push(producer(-1));
        let specialized: Vec<CfgBlock> = specialize(&blocks).expect("equal reaching definitions");
        assert!(matches!(specialized[1].term, BlockTerm::Jump(2)));
        blocks[1].stmts.push(producer(1));
        assert!(
            specialize(&blocks).is_none(),
            "changed producer admits the other edge"
        );
    }

    #[test]
    fn disagreeing_or_cyclic_backedge_definitions_refuse_folding() {
        for statement in [
            Stmt::Assign {
                dest: register(Reg::Rbx),
                src: Source::Imm(20),
            },
            Stmt::BinAssign {
                dest: register(Reg::Rbx),
                op: BinOp::Add,
                src: Source::Imm(1),
            },
        ] {
            let mut blocks: Vec<CfgBlock> = invariant_loop();
            blocks[2].stmts.push(statement);
            assert!(specialize(&blocks).is_none());
        }
    }

    #[test]
    fn unreachable_predecessors_do_not_supply_reaching_definitions() {
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks.push(CfgBlock {
            stmts: vec![Stmt::Assign {
                dest: register(Reg::Rbx),
                src: Source::Imm(20),
            }],
            term: BlockTerm::Jump(1),
        });
        let specialized: Vec<CfgBlock> =
            specialize(&blocks).expect("dead predecessor cannot change the invariant");
        assert!(matches!(specialized[1].term, BlockTerm::Jump(2)));
        assert_eq!(specialized[4], blocks[4]);
        blocks[0].term = branch(Reg::Rbx, CondKind::Be, 10, 1, 4);
        assert!(
            specialize(&blocks).is_none(),
            "making the predecessor reachable preserves the conflicting definition"
        );
    }

    #[test]
    fn partial_writes_unknown_writers_and_narrow_flags_refuse_folding() {
        for width in [Width::W8, Width::W16] {
            let mut blocks: Vec<CfgBlock> = invariant_loop();
            blocks[1].stmts.push(Stmt::Assign {
                dest: RegRef {
                    reg: Reg::Rbx,
                    width,
                },
                src: Source::Imm(0),
            });
            assert!(specialize(&blocks).is_none());
        }
        for statement in [
            Stmt::BlockFill { elem: Width::W8 },
            Stmt::Call {
                target: super::super::CallTarget::Address(0x1000),
                args: vec![Reg::Rcx],
                name: None,
            },
        ] {
            let mut blocks: Vec<CfgBlock> = invariant_loop();
            blocks[1].stmts.push(statement);
            assert!(specialize(&blocks).is_none());
        }
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        if let BlockTerm::Branch {
            flags: Flags::Cmp { lhs, .. },
            ..
        } = &mut blocks[0].term
        {
            lhs.width = Width::W32;
        }
        assert!(specialize(&blocks).is_none());
    }

    #[test]
    fn multiple_entry_edges_and_wrapping_arithmetic_keep_live_branches() {
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks[0].term = branch(Reg::Rbx, CondKind::Be, 10, 1, 2);
        assert!(specialize(&blocks).is_none());
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks[0].stmts.clear();
        blocks[0].term = branch(Reg::Rcx, CondKind::G, 0, 1, 3);
        blocks[1].stmts.push(producer(1));
        blocks[1].term = branch(Reg::Rbx, CondKind::Le, 0, 3, 2);
        assert!(
            specialize(&blocks).is_none(),
            "signed MAX plus one must retain its wrapping edge"
        );
    }

    #[test]
    fn word_writes_zero_extend_and_input_redefinitions_are_not_invariant() {
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks[1].stmts.push(Stmt::Assign {
            dest: RegRef {
                reg: Reg::Rbx,
                width: Width::W32,
            },
            src: Source::Imm(-1),
        });
        blocks[1].term = branch(Reg::Rbx, CondKind::L, 0, 3, 2);
        assert!(matches!(
            specialize(&blocks).expect("zero-extended word")[1].term,
            BlockTerm::Jump(2)
        ));
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks[2].stmts.push(Stmt::Assign {
            dest: register(Reg::Rcx),
            src: Source::Imm(100),
        });
        blocks[2].stmts.push(producer(-1));
        assert!(specialize(&blocks).is_none());
    }

    #[test]
    fn specialization_respects_graph_and_statement_caps() {
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks.resize(
            MAX_BLOCKS + 1,
            CfgBlock {
                stmts: vec![],
                term: BlockTerm::Ret,
            },
        );
        assert!(specialize(&blocks).is_none());
        let mut blocks: Vec<CfgBlock> = invariant_loop();
        blocks[0].stmts.resize(MAX_STATEMENTS + 1, producer(-1));
        assert!(specialize(&blocks).is_none());
        let mut proofs: usize = 0;
        assert!(prove_one(&invariant_loop(), &mut proofs).is_none());
    }

    #[test]
    fn entry_condition_candidates_use_the_existing_proof_budget_first() {
        let blocks: Vec<CfgBlock> = vec![
            CfgBlock {
                stmts: vec![producer(-1)],
                term: branch(Reg::Rbx, CondKind::Be, 10, 1, 4),
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rdx, CondKind::E, 0, 2, 3),
            },
            CfgBlock {
                stmts: vec![],
                term: BlockTerm::Jump(3),
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rbx, CondKind::A, 10, 4, 1),
            },
            CfgBlock {
                stmts: vec![],
                term: BlockTerm::Ret,
            },
        ];
        let mut proofs: usize = 1;
        let proof: ProvedBranch = prove_one(&blocks, &mut proofs)
            .expect("entry-conditioned candidate uses the available proof");
        assert_eq!((proof.block, proof.target, proofs), (3, 1, 0));
    }

    #[test]
    fn predecessor_guard_uses_its_actual_arithmetic_and_survives_renumbering() {
        let mut blocks: Vec<CfgBlock> = vec![
            CfgBlock {
                stmts: vec![producer(-1)],
                term: branch(Reg::Rbx, CondKind::Be, 10, 1, 4),
            },
            CfgBlock {
                stmts: vec![
                    Stmt::Assign {
                        dest: register(Reg::Rax),
                        src: Source::Imm(0),
                    },
                    Stmt::BinAssign {
                        dest: register(Reg::Rax),
                        op: BinOp::Add,
                        src: Source::Imm(10),
                    },
                ],
                term: BlockTerm::Branch {
                    kind: CondKind::G,
                    flags: Flags::Cmp {
                        lhs: register(Reg::Rcx),
                        rhs: Source::Reg(register(Reg::Rax)),
                    },
                    taken: 2,
                    fallthrough: 4,
                },
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rbx, CondKind::Ne, 10, 4, 3),
            },
            CfgBlock {
                stmts: vec![],
                term: branch(Reg::Rdx, CondKind::G, 0, 1, 4),
            },
            CfgBlock {
                stmts: vec![],
                term: BlockTerm::Ret,
            },
        ];
        assert!(matches!(
            specialize(&blocks).expect("mandatory path guard")[2].term,
            BlockTerm::Jump(3)
        ));
        let permutation: [usize; 5] = [0, 3, 2, 1, 4];
        let mut permuted: Vec<CfgBlock> = permutation
            .iter()
            .map(|old: &usize| blocks[*old].clone())
            .collect();
        for block in &mut permuted {
            match &mut block.term {
                BlockTerm::Branch {
                    taken, fallthrough, ..
                } => {
                    *taken = permutation[*taken];
                    *fallthrough = permutation[*fallthrough];
                }
                BlockTerm::Jump(target) | BlockTerm::Fall(target) => *target = permutation[*target],
                BlockTerm::Ret => {}
            }
        }
        assert!(matches!(
            specialize(&permuted).expect("permuted guard")[2].term,
            BlockTerm::Jump(1)
        ));
        if let Stmt::BinAssign { src, .. } = &mut blocks[1].stmts[1] {
            *src = Source::Imm(9);
        }
        assert!(
            specialize(&blocks).is_none(),
            "mutated guard permits both candidate edges"
        );
    }
}
