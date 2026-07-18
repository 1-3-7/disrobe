use crate::disasm::{Instruction, Operand};

use super::expr::{AfterClause, BinSegment, CaseArm, CatchArm, Expr, IfArm, Stmt};
use super::{
    BinMatchState, Block, Env, Flags, Lifter, Reg, TEST_OPS, as_reg, binmatch, body_uses_var,
    catch_value, class_from_guard, class_of_trace, combine_guard, guard, is_reraise, label_of,
    literal_u32,
};

impl Lifter<'_> {
    pub(super) fn fail_leads_to_clause(&self, fail: u32) -> bool {
        fail != 0 && self.blocks.contains_key(&fail) && !self.is_pure_failure(fail)
    }

    pub(super) fn build_bin_match_branch(
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

    pub(super) fn build_map_match_branch(
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

    pub(super) fn build_select_val(
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

    pub(super) fn build_select_tuple_arity(
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
            let arity: u32 = literal_u32(&pair[0]).min(crate::chunks::MAX_FUN_ARITY);
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

    pub(super) fn build_receive(
        &self,
        label: u32,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Expr {
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

    pub(super) fn build_raise(&self, ins: &Instruction, env: &Env) -> Stmt {
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

    pub(super) fn build_catch(
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

    pub(super) fn build_try(&self, idx: usize, env: &Env, flags: &mut Flags, depth: u32) -> Expr {
        let catch_label: u32 = label_of(&self.instrs[idx].operands[1]);
        let try_case: usize = self.region_end(idx + 1, self.instrs.len(), &["try_case"]);
        let region: Block = Block {
            start: idx + 1,
            end: try_case,
        };
        let mut body_env: Env = env.clone();
        let body: Vec<Stmt> = self.walk_synth(region, &mut body_env, flags, depth + 1);
        let (cls, rsn, stk): (String, String, String) = choose_exc_names(&body);
        let (of_arms, catch_arms): (Vec<CaseArm>, Vec<CatchArm>) =
            self.build_try_handlers(catch_label, env, flags, depth, &cls, &rsn, &stk);
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after: Vec::new(),
        }
    }

    pub(super) fn region_end(&self, start: usize, limit: usize, stop_at: &[&str]) -> usize {
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
        cls: &str,
        rsn: &str,
        stk: &str,
    ) -> (Vec<CaseArm>, Vec<CatchArm>) {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return (Vec::new(), Vec::new());
        };
        let mut cursor: usize = block.start;
        while cursor < block.end && self.instrs[cursor].name != "try_case" {
            cursor += 1;
        }
        let mut catch_env: Env = env.clone();
        catch_env.set(Reg::X(0), Expr::Var(cls.to_owned()));
        catch_env.set(Reg::X(1), Expr::Var(rsn.to_owned()));
        catch_env.set(Reg::X(2), Expr::Var(stk.to_owned()));
        let synth: Block = Block {
            start: cursor + 1,
            end: block.end,
        };
        let stmts: Vec<Stmt> = self.walk_synth(synth, &mut catch_env, flags, depth + 1);
        (Vec::new(), to_catch_arms(stmts, cls, rsn, stk))
    }

    pub(super) fn walk_synth(
        &self,
        synth: Block,
        env: &mut Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Vec<Stmt> {
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

    pub(super) fn reconstruct_branch(
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
}

fn choose_exc_names(body: &[Stmt]) -> (String, String, String) {
    for suffix_n in 0u32..64 {
        let suffix: String = if suffix_n == 0 {
            String::new()
        } else {
            suffix_n.to_string()
        };
        let cls: String = format!("Class{suffix}");
        let rsn: String = format!("Reason{suffix}");
        let stk: String = format!("Stack{suffix}");
        if !body_uses_var(body, &cls) && !body_uses_var(body, &rsn) && !body_uses_var(body, &stk) {
            return (cls, rsn, stk);
        }
    }
    ("Class".to_owned(), "Reason".to_owned(), "Stack".to_owned())
}

fn to_catch_arms(stmts: Vec<Stmt>, cls: &str, rsn: &str, stk: &str) -> Vec<CatchArm> {
    if let [Stmt::Return(Expr::If { arms })] = stmts.as_slice() {
        let mut out: Vec<CatchArm> = Vec::with_capacity(arms.len());
        for arm in arms {
            if is_reraise(&arm.body) {
                continue;
            }
            let (class, extra): (String, Option<Expr>) = class_from_guard(&arm.guard, cls);
            let stacktrace: Option<String> = body_uses_var(&arm.body, stk).then(|| stk.to_owned());
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
                pattern: Expr::Var(rsn.to_owned()),
                stacktrace,
                body: guarded_body,
            });
        }
        if !out.is_empty() {
            return out;
        }
    }
    vec![CatchArm {
        class: cls.to_owned(),
        pattern: Expr::Var(rsn.to_owned()),
        stacktrace: Some(stk.to_owned()),
        body: stmts,
    }]
}
