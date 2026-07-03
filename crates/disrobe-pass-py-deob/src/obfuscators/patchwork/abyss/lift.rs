use serde_json::Value as Json;

use super::emit::render_stmt;
use super::{AbyssDoc, AbyssFunction, Const, Instruction, Op};

#[derive(Debug, Clone)]
pub(super) enum PyExpr {
    Name(String),
    ConstLit(Const),
    Bin(Box<Self>, String, Box<Self>),
    Unary(String, Box<Self>),
    Compare(Box<Self>, Vec<(String, Self)>),
    BoolOp(String, Vec<Self>),
    Call(Box<Self>, Vec<Self>, Vec<(String, Self)>),
    Attr(Box<Self>, String),
    Subscript(Box<Self>, Box<Self>),
    Slice(Box<Self>, Box<Self>, Box<Self>),
    List(Vec<Self>),
    Tuple(Vec<Self>),
    Set(Vec<Self>),
    Dict(Vec<(Self, Self)>),
    JoinedStr(Vec<Self>),
    FormatValue(Box<Self>, i64, Option<Box<Self>>),
    Walrus(String, Box<Self>),
    ListComp(Box<Self>, AssignTarget, Box<Self>, Vec<Self>),
}

#[derive(Debug, Clone)]
pub(super) enum PyStmt {
    Assign(Vec<AssignTarget>, PyExpr),
    ExprStmt(PyExpr),
    Return(Option<PyExpr>),
    If(PyExpr, Vec<Self>, Vec<Self>),
    While(PyExpr, Vec<Self>),
    For(AssignTarget, PyExpr, Vec<Self>),
    Global(Vec<String>),
    Break,
    Continue,
    Pass,
}

#[derive(Debug, Clone)]
pub(super) enum AssignTarget {
    Name(String),
    Tuple(Vec<Self>),
}

#[derive(Debug)]
pub(super) struct LiftError;

type LiftResult<T> = std::result::Result<T, LiftError>;

struct Lifter<'a> {
    code: &'a [Instruction],
    func: &'a AbyssFunction,
    loop_stack: Vec<LoopContext>,
}

#[derive(Debug, Clone, Copy)]
struct LoopContext {
    header: usize,
    exit: usize,
}

pub(super) fn lift_function(doc: &AbyssDoc, func: &AbyssFunction) -> LiftResult<Vec<PyStmt>> {
    let end: usize = function_end(&doc.code, func.entry)?;
    let mut lifter: Lifter<'_> = Lifter {
        code: &doc.code,
        func,
        loop_stack: Vec::new(),
    };
    let mut body: Vec<PyStmt> = lifter.region(func.entry, end)?;
    strip_trailing_none_return(&mut body);
    if !func.globals.is_empty() {
        let names: Vec<String> = func.globals.iter().cloned().collect();
        body.insert(0, PyStmt::Global(names));
    }
    if body.is_empty() {
        body.push(PyStmt::Pass);
    }
    Ok(body)
}

fn function_end(code: &[Instruction], entry: usize) -> LiftResult<usize> {
    let mut i: usize = entry;
    let mut max_target: usize = entry;
    while i < code.len() {
        let inst: &Instruction = code.get(i).ok_or(LiftError)?;
        if let Some(target) = jump_arg(inst) {
            max_target = max_target.max(target);
        }
        if matches!(inst.op, Op::Return) && i + 1 > max_target {
            return Ok(i + 1);
        }
        i += 1;
    }
    Ok(code.len())
}

fn jump_arg(inst: &Instruction) -> Option<usize> {
    if !matches!(
        inst.op,
        Op::Jump | Op::JumpIfFalse | Op::JumpIfTrueKeep | Op::JumpIfFalseKeep | Op::ForIter
    ) {
        return None;
    }
    inst.args
        .first()
        .and_then(Json::as_u64)
        .map(|v: u64| usize::try_from(v).unwrap_or(usize::MAX))
}

impl Lifter<'_> {
    fn region(&mut self, start: usize, end: usize) -> LiftResult<Vec<PyStmt>> {
        let mut stmts: Vec<PyStmt> = Vec::new();
        let mut stack: Vec<PyExpr> = Vec::new();
        let mut ip: usize = start;
        while ip < end {
            let inst: &Instruction = self.code.get(ip).ok_or(LiftError)?;
            match inst.op {
                Op::Jump => {
                    let target: usize = jump_arg(inst).ok_or(LiftError)?;
                    if !stack.is_empty() {
                        return Err(LiftError);
                    }
                    let loop_ctx: Option<LoopContext> = self.loop_stack.last().copied();
                    match loop_ctx {
                        Some(ctx) if target == ctx.header => {
                            stmts.push(PyStmt::Continue);
                            ip += 1;
                        }
                        Some(ctx) if target == ctx.exit => {
                            stmts.push(PyStmt::Break);
                            ip += 1;
                        }
                        _ => return Err(LiftError),
                    }
                }
                Op::JumpIfFalse => {
                    let target: usize = jump_arg(inst).ok_or(LiftError)?;
                    let test: PyExpr = stack.pop().ok_or(LiftError)?;
                    if !stack.is_empty() {
                        return Err(LiftError);
                    }
                    ip = self.lift_if(ip, target, end, test, &mut stmts)?;
                }
                Op::GetIter => {
                    if !stack.is_empty()
                        && let Some(next) = self.code.get(ip + 1)
                        && matches!(next.op, Op::ForIter)
                    {
                        let iter_expr: PyExpr = stack.pop().ok_or(LiftError)?;
                        if !stack.is_empty() {
                            return Err(LiftError);
                        }
                        ip = self.lift_for(ip + 1, iter_expr, &mut stmts)?;
                    } else {
                        return Err(LiftError);
                    }
                }
                Op::Return => {
                    let value: Option<PyExpr> = stack.pop();
                    if !stack.is_empty() {
                        return Err(LiftError);
                    }
                    stmts.push(PyStmt::Return(value));
                    ip += 1;
                }
                Op::BuildList if is_comprehension_start(self.code, ip) => {
                    ip = self.lift_comprehension(ip, &mut stmts)?;
                }
                Op::Dup
                    if matches!(
                        self.code.get(ip + 1).map(|i: &Instruction| i.op),
                        Some(Op::Store)
                    ) =>
                {
                    ip += 1;
                }
                Op::Store if is_walrus(self.code, ip) => {
                    let name: String = arg_str(inst, 0)?;
                    let value: PyExpr = stack.pop().ok_or(LiftError)?;
                    stack.push(PyExpr::Walrus(name, Box::new(value)));
                    ip += 1;
                }
                Op::Store => {
                    ip = self.lift_store(ip, &mut stack, &mut stmts)?;
                }
                Op::Pop if self.is_break_cleanup(ip, &stack) => {
                    stmts.push(PyStmt::Break);
                    ip += 2;
                }
                Op::Pop => {
                    let value: PyExpr = stack.pop().ok_or(LiftError)?;
                    stmts.push(PyStmt::ExprStmt(value));
                    ip += 1;
                }
                Op::JumpIfTrueKeep | Op::JumpIfFalseKeep => {
                    let target: usize = jump_arg(inst).ok_or(LiftError)?;
                    let op: &str = if matches!(inst.op, Op::JumpIfTrueKeep) {
                        "or"
                    } else {
                        "and"
                    };
                    self.short_circuit(ip, target, op, &mut stack)?;
                    ip = target;
                }
                _ => {
                    self.eval(inst, ip, &mut stack)?;
                    ip += 1;
                }
            }
        }
        if !stack.is_empty() {
            return Err(LiftError);
        }
        Ok(stmts)
    }

    fn lift_if(
        &mut self,
        cond_ip: usize,
        else_target: usize,
        end: usize,
        test: PyExpr,
        stmts: &mut Vec<PyStmt>,
    ) -> LiftResult<usize> {
        if let Some(ctx) = self.loop_stack.last().copied()
            && (else_target == ctx.header || else_target == ctx.exit)
        {
            let body: Vec<PyStmt> = self.region(cond_ip + 1, else_target)?;
            stmts.push(PyStmt::If(test, body, Vec::new()));
            return Ok(else_target);
        }
        let before_else: usize = else_target.saturating_sub(1);
        if before_else > cond_ip
            && let Some(jump) = self.code.get(before_else)
            && matches!(jump.op, Op::Jump)
            && let Some(join) = jump_arg(jump)
        {
            if join <= cond_ip {
                return self.lift_while(join, cond_ip, else_target, test, stmts);
            }
            if self.is_loop_back(join) {
                let body: Vec<PyStmt> = self.region(cond_ip + 1, before_else)?;
                stmts.push(PyStmt::If(test, body, Vec::new()));
                return Ok(else_target);
            }
            if join > else_target && join <= end {
                let then_body: Vec<PyStmt> = self.region(cond_ip + 1, before_else)?;
                let else_body: Vec<PyStmt> = self.region(else_target, join)?;
                stmts.push(PyStmt::If(test, then_body, else_body));
                return Ok(join);
            }
            if join == else_target {
                let then_body: Vec<PyStmt> = self.region(cond_ip + 1, before_else)?;
                stmts.push(PyStmt::If(test, then_body, Vec::new()));
                return Ok(else_target);
            }
        }
        let body: Vec<PyStmt> = self.region(cond_ip + 1, else_target.min(end))?;
        stmts.push(PyStmt::If(test, body, Vec::new()));
        Ok(else_target.min(end))
    }

    fn lift_while(
        &mut self,
        header: usize,
        cond_ip: usize,
        exit: usize,
        test: PyExpr,
        stmts: &mut Vec<PyStmt>,
    ) -> LiftResult<usize> {
        let back_jump: usize = exit.saturating_sub(1);
        self.loop_stack.push(LoopContext { header, exit });
        let body: Vec<PyStmt> = self.region(cond_ip + 1, back_jump)?;
        self.loop_stack.pop();
        stmts.push(PyStmt::While(test, body));
        Ok(exit)
    }

    fn lift_for(
        &mut self,
        for_iter_ip: usize,
        iter_expr: PyExpr,
        stmts: &mut Vec<PyStmt>,
    ) -> LiftResult<usize> {
        let for_inst: &Instruction = self.code.get(for_iter_ip).ok_or(LiftError)?;
        let exit: usize = jump_arg(for_inst).ok_or(LiftError)?;
        let target: AssignTarget = self.read_store_target(for_iter_ip + 1)?;
        let store_len: usize = self.store_len(for_iter_ip + 1)?;
        let body_start: usize = for_iter_ip + 1 + store_len;
        let back_jump: usize = exit.saturating_sub(1);
        let jump_inst: &Instruction = self.code.get(back_jump).ok_or(LiftError)?;
        if !matches!(jump_inst.op, Op::Jump) || jump_arg(jump_inst) != Some(for_iter_ip) {
            return Err(LiftError);
        }
        self.loop_stack.push(LoopContext {
            header: for_iter_ip,
            exit,
        });
        let body: Vec<PyStmt> = self.region(body_start, back_jump)?;
        self.loop_stack.pop();
        stmts.push(PyStmt::For(target, iter_expr, body));
        Ok(exit)
    }

    fn lift_comprehension(&self, start: usize, stmts: &mut Vec<PyStmt>) -> LiftResult<usize> {
        let store_tmp: &Instruction = self.code.get(start + 1).ok_or(LiftError)?;
        if !matches!(store_tmp.op, Op::Store) {
            return Err(LiftError);
        }
        let result_name: String = arg_str(store_tmp, 0)?;
        let mut ip: usize = start + 2;
        let mut iter_stack: Vec<PyExpr> = Vec::new();
        while ip < self.code.len() {
            let inst: &Instruction = self.code.get(ip).ok_or(LiftError)?;
            if matches!(inst.op, Op::GetIter) {
                break;
            }
            self.eval(inst, ip, &mut iter_stack)?;
            ip += 1;
        }
        let iter_expr: PyExpr = iter_stack.pop().ok_or(LiftError)?;
        if !iter_stack.is_empty() {
            return Err(LiftError);
        }
        let for_iter_ip: usize = ip + 1;
        let for_inst: &Instruction = self.code.get(for_iter_ip).ok_or(LiftError)?;
        if !matches!(for_inst.op, Op::ForIter) {
            return Err(LiftError);
        }
        let exit: usize = jump_arg(for_inst).ok_or(LiftError)?;
        let target: AssignTarget = self.read_store_target(for_iter_ip + 1)?;
        let store_len: usize = self.store_len(for_iter_ip + 1)?;
        let mut cursor: usize = for_iter_ip + 1 + store_len;
        let mut conditions: Vec<PyExpr> = Vec::new();
        let mut cond_stack: Vec<PyExpr> = Vec::new();
        while cursor < self.code.len() {
            let inst: &Instruction = self.code.get(cursor).ok_or(LiftError)?;
            if matches!(inst.op, Op::JumpIfFalse) {
                if jump_arg(inst) != Some(for_iter_ip) {
                    return Err(LiftError);
                }
                let cond: PyExpr = cond_stack.pop().ok_or(LiftError)?;
                if !cond_stack.is_empty() {
                    return Err(LiftError);
                }
                conditions.push(cond);
                cursor += 1;
                continue;
            }
            if matches!(inst.op, Op::Load)
                && cond_stack.is_empty()
                && arg_str(inst, 0)? == result_name
            {
                break;
            }
            self.eval(inst, cursor, &mut cond_stack)?;
            cursor += 1;
        }
        if !cond_stack.is_empty() {
            return Err(LiftError);
        }
        let load_inst: &Instruction = self.code.get(cursor).ok_or(LiftError)?;
        if !matches!(load_inst.op, Op::Load) || arg_str(load_inst, 0)? != result_name {
            return Err(LiftError);
        }
        let attr_inst: &Instruction = self.code.get(cursor + 1).ok_or(LiftError)?;
        if !matches!(attr_inst.op, Op::GetAttr) || arg_str(attr_inst, 0)? != "append" {
            return Err(LiftError);
        }
        let back_jump: usize = exit.saturating_sub(1);
        let call_ip: usize = back_jump.saturating_sub(2);
        let mut elt_stack: Vec<PyExpr> = Vec::new();
        for j in cursor + 2..call_ip {
            let einst: &Instruction = self.code.get(j).ok_or(LiftError)?;
            self.eval(einst, j, &mut elt_stack)?;
        }
        let elt: PyExpr = elt_stack.pop().ok_or(LiftError)?;
        if !elt_stack.is_empty() {
            return Err(LiftError);
        }
        let final_load: &Instruction = self.code.get(exit).ok_or(LiftError)?;
        if !matches!(final_load.op, Op::Load) || arg_str(final_load, 0)? != result_name {
            return Err(LiftError);
        }
        let comp: PyExpr = PyExpr::ListComp(Box::new(elt), target, Box::new(iter_expr), conditions);
        let assign_target: AssignTarget = self.read_store_target(exit + 1)?;
        let store_len_final: usize = self.store_len(exit + 1)?;
        stmts.push(PyStmt::Assign(vec![assign_target], comp));
        Ok(exit + 1 + store_len_final)
    }

    fn lift_store(
        &self,
        ip: usize,
        stack: &mut Vec<PyExpr>,
        stmts: &mut Vec<PyStmt>,
    ) -> LiftResult<usize> {
        let target: AssignTarget = self.read_store_target(ip)?;
        let store_len: usize = self.store_len(ip)?;
        let value: PyExpr = stack.pop().ok_or(LiftError)?;
        if !stack.is_empty() {
            return Err(LiftError);
        }
        stmts.push(PyStmt::Assign(vec![target], value));
        Ok(ip + store_len)
    }

    fn read_store_target(&self, ip: usize) -> LiftResult<AssignTarget> {
        let inst: &Instruction = self.code.get(ip).ok_or(LiftError)?;
        match inst.op {
            Op::Store => Ok(AssignTarget::Name(arg_str(inst, 0)?)),
            Op::Unpack => {
                let count: usize = arg_usize(inst, 0)?;
                let mut elts: Vec<AssignTarget> = Vec::with_capacity(count);
                let mut cursor: usize = ip + 1;
                for _ in 0..count {
                    elts.push(self.read_store_target(cursor)?);
                    cursor += self.store_len(cursor)?;
                }
                Ok(AssignTarget::Tuple(elts))
            }
            _ => Err(LiftError),
        }
    }

    fn store_len(&self, ip: usize) -> LiftResult<usize> {
        let inst: &Instruction = self.code.get(ip).ok_or(LiftError)?;
        match inst.op {
            Op::Store => Ok(1),
            Op::Unpack => {
                let count: usize = arg_usize(inst, 0)?;
                let mut total: usize = 1;
                let mut cursor: usize = ip + 1;
                for _ in 0..count {
                    let len: usize = self.store_len(cursor)?;
                    cursor += len;
                    total += len;
                }
                Ok(total)
            }
            _ => Err(LiftError),
        }
    }

    fn is_loop_back(&self, target: usize) -> bool {
        self.loop_stack
            .iter()
            .any(|ctx: &LoopContext| ctx.header == target)
    }

    fn is_break_cleanup(&self, pop_ip: usize, stack: &[PyExpr]) -> bool {
        if !stack.is_empty() {
            return false;
        }
        let Some(ctx): Option<&LoopContext> = self.loop_stack.last() else {
            return false;
        };
        let Some(next): Option<&Instruction> = self.code.get(pop_ip + 1) else {
            return false;
        };
        matches!(next.op, Op::Jump) && jump_arg(next) == Some(ctx.exit)
    }

    fn eval(&self, inst: &Instruction, ip: usize, stack: &mut Vec<PyExpr>) -> LiftResult<()> {
        match inst.op {
            Op::Const => {
                let idx: usize = arg_usize(inst, 0)?;
                let konst: &Const = self.func.consts.get(idx).ok_or(LiftError)?;
                stack.push(PyExpr::ConstLit(konst.clone()));
            }
            Op::Load => stack.push(PyExpr::Name(arg_str(inst, 0)?)),
            Op::Dup
                if matches!(
                    self.code.get(ip + 1).map(|i: &Instruction| i.op),
                    Some(Op::Store)
                ) => {}
            Op::Dup => {
                let top: PyExpr = stack.last().ok_or(LiftError)?.clone();
                stack.push(top);
            }
            Op::Bin => {
                let op_name: String = arg_str(inst, 0)?;
                let b: PyExpr = stack.pop().ok_or(LiftError)?;
                let a: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Bin(Box::new(a), bin_symbol(&op_name)?, Box::new(b)));
            }
            Op::Unary => {
                let op_name: String = arg_str(inst, 0)?;
                let a: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Unary(unary_symbol(&op_name)?, Box::new(a)));
            }
            Op::CompareChain => {
                let ops: Vec<String> = inst
                    .args
                    .first()
                    .and_then(Json::as_array)
                    .ok_or(LiftError)?
                    .iter()
                    .map(|v: &Json| v.as_str().map(str::to_owned).ok_or(LiftError))
                    .collect::<LiftResult<Vec<String>>>()?;
                let total: usize = ops.len() + 1;
                let mut values: Vec<PyExpr> = Vec::with_capacity(total);
                for _ in 0..total {
                    values.push(stack.pop().ok_or(LiftError)?);
                }
                values.reverse();
                let mut iter: std::vec::IntoIter<PyExpr> = values.into_iter();
                let left: PyExpr = iter.next().ok_or(LiftError)?;
                let mut comps: Vec<(String, PyExpr)> = Vec::with_capacity(ops.len());
                for op_name in &ops {
                    comps.push((compare_symbol(op_name)?, iter.next().ok_or(LiftError)?));
                }
                stack.push(PyExpr::Compare(Box::new(left), comps));
            }
            Op::Call => {
                let argc: usize = arg_usize(inst, 0)?;
                let kw_names: Vec<String> = inst
                    .args
                    .get(1)
                    .and_then(Json::as_array)
                    .map(|arr: &Vec<Json>| {
                        arr.iter()
                            .filter_map(|v: &Json| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut kwargs: Vec<(String, PyExpr)> = Vec::with_capacity(kw_names.len());
                for name in kw_names.iter().rev() {
                    kwargs.push((name.clone(), stack.pop().ok_or(LiftError)?));
                }
                kwargs.reverse();
                let mut args: Vec<PyExpr> = Vec::with_capacity(argc);
                for _ in 0..argc {
                    args.push(stack.pop().ok_or(LiftError)?);
                }
                args.reverse();
                let func: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Call(Box::new(func), args, kwargs));
            }
            Op::GetAttr => {
                let attr: String = arg_str(inst, 0)?;
                let value: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Attr(Box::new(value), attr));
            }
            Op::Subscr => {
                let key: PyExpr = stack.pop().ok_or(LiftError)?;
                let obj: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Subscript(Box::new(obj), Box::new(key)));
            }
            Op::BuildSlice => {
                let step: PyExpr = stack.pop().ok_or(LiftError)?;
                let upper: PyExpr = stack.pop().ok_or(LiftError)?;
                let lower: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Slice(
                    Box::new(lower),
                    Box::new(upper),
                    Box::new(step),
                ));
            }
            Op::BuildList => {
                let count: usize = arg_usize(inst, 0)?;
                let items: Vec<PyExpr> = pop_n(stack, count)?;
                stack.push(PyExpr::List(items));
            }
            Op::BuildTuple => {
                let count: usize = arg_usize(inst, 0)?;
                let items: Vec<PyExpr> = pop_n(stack, count)?;
                stack.push(PyExpr::Tuple(items));
            }
            Op::BuildSet => {
                let count: usize = arg_usize(inst, 0)?;
                let items: Vec<PyExpr> = pop_n(stack, count)?;
                stack.push(PyExpr::Set(items));
            }
            Op::BuildDict => {
                let count: usize = arg_usize(inst, 0)?;
                let mut pairs: Vec<(PyExpr, PyExpr)> = Vec::with_capacity(count);
                for _ in 0..count {
                    let value: PyExpr = stack.pop().ok_or(LiftError)?;
                    let key: PyExpr = stack.pop().ok_or(LiftError)?;
                    pairs.push((key, value));
                }
                pairs.reverse();
                stack.push(PyExpr::Dict(pairs));
            }
            Op::BuildString => {
                let count: usize = arg_usize(inst, 0)?;
                let items: Vec<PyExpr> = pop_n(stack, count)?;
                stack.push(PyExpr::JoinedStr(items));
            }
            Op::FormatValue => {
                let conversion: i64 = inst.args.first().and_then(Json::as_i64).unwrap_or(-1);
                let has_spec: bool = inst.args.get(1).and_then(Json::as_bool).unwrap_or(false);
                let spec: Option<Box<PyExpr>> = if has_spec {
                    Some(Box::new(stack.pop().ok_or(LiftError)?))
                } else {
                    None
                };
                let value: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::FormatValue(Box::new(value), conversion, spec));
            }
            Op::Store if is_walrus(self.code, ip) => {
                let name: String = arg_str(inst, 0)?;
                let value: PyExpr = stack.pop().ok_or(LiftError)?;
                stack.push(PyExpr::Walrus(name, Box::new(value)));
            }
            _ => return Err(LiftError),
        }
        Ok(())
    }

    fn short_circuit(
        &mut self,
        keep_ip: usize,
        target: usize,
        op: &str,
        stack: &mut Vec<PyExpr>,
    ) -> LiftResult<()> {
        let first: PyExpr = stack.pop().ok_or(LiftError)?;
        let second: PyExpr = self.eval_expr_range(keep_ip + 1, target)?;
        match first {
            PyExpr::BoolOp(existing, mut vals) if existing == op => {
                vals.push(second);
                stack.push(PyExpr::BoolOp(op.to_owned(), vals));
            }
            other => stack.push(PyExpr::BoolOp(op.to_owned(), vec![other, second])),
        }
        Ok(())
    }

    fn eval_expr_range(&mut self, start: usize, end: usize) -> LiftResult<PyExpr> {
        let mut stack: Vec<PyExpr> = Vec::new();
        let mut ip: usize = start;
        while ip < end {
            let inst: &Instruction = self.code.get(ip).ok_or(LiftError)?;
            match inst.op {
                Op::JumpIfTrueKeep | Op::JumpIfFalseKeep => {
                    let target: usize = jump_arg(inst).ok_or(LiftError)?;
                    let op: &str = if matches!(inst.op, Op::JumpIfTrueKeep) {
                        "or"
                    } else {
                        "and"
                    };
                    self.short_circuit(ip, target, op, &mut stack)?;
                    ip = target;
                }
                _ => {
                    self.eval(inst, ip, &mut stack)?;
                    ip += 1;
                }
            }
        }
        let value: PyExpr = stack.pop().ok_or(LiftError)?;
        if !stack.is_empty() {
            return Err(LiftError);
        }
        Ok(value)
    }
}

fn pop_n(stack: &mut Vec<PyExpr>, count: usize) -> LiftResult<Vec<PyExpr>> {
    let mut items: Vec<PyExpr> = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(stack.pop().ok_or(LiftError)?);
    }
    items.reverse();
    Ok(items)
}

fn is_comprehension_start(code: &[Instruction], ip: usize) -> bool {
    let Some(build): Option<&Instruction> = code.get(ip) else {
        return false;
    };
    if !matches!(build.op, Op::BuildList) || build.args.first().and_then(Json::as_u64) != Some(0) {
        return false;
    }
    matches!(
        code.get(ip + 1).map(|i: &Instruction| i.op),
        Some(Op::Store)
    ) && code
        .get(ip + 1)
        .and_then(|i: &Instruction| i.args.first())
        .and_then(Json::as_str)
        .is_some_and(|name: &str| name.starts_with("_pw_ab_tmp_"))
}

fn is_walrus(code: &[Instruction], ip: usize) -> bool {
    ip > 0 && matches!(code.get(ip - 1).map(|i: &Instruction| i.op), Some(Op::Dup))
}

fn strip_trailing_none_return(body: &mut Vec<PyStmt>) {
    if matches!(
        body.last(),
        Some(PyStmt::Return(Some(PyExpr::ConstLit(Const::None)) | None))
    ) {
        body.pop();
    }
}

fn arg_str(inst: &Instruction, idx: usize) -> LiftResult<String> {
    inst.args
        .get(idx)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or(LiftError)
}

fn arg_usize(inst: &Instruction, idx: usize) -> LiftResult<usize> {
    inst.args
        .get(idx)
        .and_then(Json::as_u64)
        .map(|v: u64| usize::try_from(v).unwrap_or(usize::MAX))
        .ok_or(LiftError)
}

fn bin_symbol(name: &str) -> LiftResult<String> {
    let symbol: &str = match name {
        "add" => "+",
        "sub" => "-",
        "mul" => "*",
        "matmul" => "@",
        "truediv" => "/",
        "floordiv" => "//",
        "mod" => "%",
        "pow" => "**",
        "lshift" => "<<",
        "rshift" => ">>",
        "or" => "|",
        "xor" => "^",
        "and" => "&",
        _ => return Err(LiftError),
    };
    Ok(symbol.to_owned())
}

fn unary_symbol(name: &str) -> LiftResult<String> {
    let symbol: &str = match name {
        "invert" => "~",
        "not" => "not ",
        "pos" => "+",
        "neg" => "-",
        _ => return Err(LiftError),
    };
    Ok(symbol.to_owned())
}

fn compare_symbol(name: &str) -> LiftResult<String> {
    let symbol: &str = match name {
        "eq" => "==",
        "ne" => "!=",
        "lt" => "<",
        "le" => "<=",
        "gt" => ">",
        "ge" => ">=",
        "is" => "is",
        "is_not" => "is not",
        "in" => "in",
        "not_in" => "not in",
        _ => return Err(LiftError),
    };
    Ok(symbol.to_owned())
}

pub(super) fn render_indented(body: &[PyStmt], indent: usize) -> String {
    let mut out: String = String::new();
    for stmt in body {
        render_stmt(stmt, indent, &mut out);
    }
    if out.is_empty() {
        let pad: String = "    ".repeat(indent);
        out.push_str(&pad);
        out.push_str("pass\n");
    }
    out
}
