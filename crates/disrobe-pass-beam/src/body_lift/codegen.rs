use std::collections::BTreeMap;

use crate::disasm::{Instruction, Operand};

use super::expr::{Expr, Stmt};
use super::{
    Env, Flags, Lifter, Reg, as_reg, bounded_set, build_bif_expr, call_ext_expr, finish_call,
    guard, literal_u32, make_cons, render,
};

impl Lifter<'_> {
    pub(super) fn exec_trim(ins: &Instruction, env: &mut Env) {
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
                Reg::X(_) | Reg::F(_) => Some((*reg, value.clone())),
            })
            .collect();
        env.regs = shifted;
    }

    pub(super) fn exec_move(&self, ins: &Instruction, env: &mut Env) {
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

    pub(super) fn exec_float_arith(&self, ins: &Instruction, env: &mut Env) {
        let (expr, dst): (Expr, &Operand) = if ins.name == "fnegate" {
            let (Some(operand), Some(dst)): (Option<&Operand>, Option<&Operand>) =
                (ins.operands.get(1), ins.operands.get(2))
            else {
                return;
            };
            (
                Expr::UnOp {
                    op: "-".to_owned(),
                    operand: Box::new(self.value(operand, env)),
                },
                dst,
            )
        } else {
            let op: &str = match ins.name {
                "fadd" => "+",
                "fsub" => "-",
                "fmul" => "*",
                "fdiv" => "/",
                _ => return,
            };
            let (Some(lhs), Some(rhs), Some(dst)): (
                Option<&Operand>,
                Option<&Operand>,
                Option<&Operand>,
            ) = (
                ins.operands.get(1),
                ins.operands.get(2),
                ins.operands.get(3),
            ) else {
                return;
            };
            (
                Expr::BinOp {
                    op: op.to_owned(),
                    lhs: Box::new(self.value(lhs, env)),
                    rhs: Box::new(self.value(rhs, env)),
                },
                dst,
            )
        };
        if let Some(reg) = as_reg(dst) {
            env.set(reg, expr);
        }
    }

    pub(super) fn exec_put_list(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let head: Expr = self.value(&ins.operands[0], env);
        let tail: Expr = self.value(&ins.operands[1], env);
        if let Some(reg) = as_reg(&ins.operands[2]) {
            bounded_set(env, reg, make_cons(head, tail), flags);
        }
    }

    pub(super) fn exec_put_tuple2(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let Operand::List(items) = &ins.operands[1] else {
            return;
        };
        let elements: Vec<Expr> = items.iter().map(|o: &Operand| self.value(o, env)).collect();
        if let Some(reg) = as_reg(&ins.operands[0]) {
            bounded_set(env, reg, Expr::Tuple(elements), flags);
        }
    }

    pub(super) fn exec_put_tuple_old(
        &self,
        ins: &Instruction,
        start: usize,
        end: usize,
        env: &mut Env,
        flags: &mut Flags,
    ) -> usize {
        let size: usize = literal_u32(&ins.operands[0]) as usize;
        let dst: &Operand = &ins.operands[1];
        let remaining: usize = end.saturating_sub(start + 1);
        let mut elements: Vec<Expr> = Vec::with_capacity(size.min(remaining));
        let mut cursor: usize = start + 1;
        while cursor < end && elements.len() < size && self.instrs[cursor].name == "put" {
            elements.push(self.value(&self.instrs[cursor].operands[0], env));
            cursor += 1;
        }
        if let Some(reg) = as_reg(dst) {
            bounded_set(env, reg, Expr::Tuple(elements), flags);
        }
        cursor - 1
    }

    pub(super) fn exec_get_list(&self, ins: &Instruction, env: &mut Env) {
        let src: Expr = self.value(&ins.operands[0], env);
        if let Some(hd) = as_reg(&ins.operands[1]) {
            env.set(hd, guard("hd", vec![src.clone()]));
        }
        if let Some(tl) = as_reg(&ins.operands[2]) {
            env.set(tl, guard("tl", vec![src]));
        }
    }

    pub(super) fn exec_unary_dest(&self, ins: &Instruction, op: &str, env: &mut Env) {
        let src: Expr = self.value(&ins.operands[0], env);
        if let Some(dst) = as_reg(&ins.operands[1]) {
            env.set(dst, guard(op, vec![src]));
        }
    }

    pub(super) fn exec_get_tuple_element(&self, ins: &Instruction, env: &mut Env) {
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

    pub(super) fn exec_put_map(&self, ins: &Instruction, env: &mut Env) {
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

    pub(super) fn exec_update_record(&self, ins: &Instruction, env: &mut Env) {
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

    pub(super) fn exec_get_map_elements(
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

    pub(super) fn exec_bif(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
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

    pub(super) fn exec_gc_bif(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
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

    pub(super) fn exec_call_local(
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

    pub(super) fn exec_call_ext(
        &self,
        ins: &Instruction,
        env: &mut Env,
        out: &mut Vec<Stmt>,
        flags: &mut Flags,
    ) -> bool {
        let arity: u32 = literal_u32(&ins.operands[0]);
        let args: Vec<Expr> = (0..arity).map(|i: u32| env.get(Reg::X(i))).collect();
        let call: Expr = match self.resolve_import(&ins.operands[1]) {
            Some((module, name, arity)) => call_ext_expr(&module, &name, arity, &args),
            None => Expr::Call {
                target: "erlang:apply".to_owned(),
                args,
            },
        };
        finish_call(ins.name, call, env, out, flags)
    }

    pub(super) fn exec_call_fun(
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

    pub(super) fn exec_make_fun(&self, ins: &Instruction, env: &mut Env) {
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

    pub(super) fn value(&self, op: &Operand, env: &Env) -> Expr {
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
            Operand::FpReg(r) => env.get(Reg::F(*r)),
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
