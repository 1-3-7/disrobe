use std::collections::BTreeMap;
use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{ConstValue as AstConst, Expr, ExprCtx, Stmt};
use crate::bytecode::opcode::{BinOp, CmpOp, UnaryOp};
use crate::roundtrip::normalize::canonicalize_relowered;
use crate::roundtrip::{ConstValue, NameValue, NormToken, NormalizedOp};

const CO_OPTIMIZED: i32 = 0x0001;
const KIND_CELL: u8 = 0x40;
const KIND_FREE: u8 = 0x80;
const NB_SUBSCR: u32 = 26;
const MAX_DEPTH: u32 = 96;

#[derive(Debug)]
pub(crate) enum Relowered {
    Ops(Vec<NormalizedOp>),
    Uncovered,
}

#[derive(Debug)]
pub(crate) struct ScopeCtx {
    fast: BTreeSet<String>,
    deref: BTreeSet<String>,
    function_scope: bool,
}

impl ScopeCtx {
    #[must_use]
    pub(crate) fn from_code(code: &CodeObject) -> Self {
        let function_scope: bool = (code.flags & CO_OPTIMIZED) != 0;
        let mut fast: BTreeSet<String> = BTreeSet::new();
        let mut deref: BTreeSet<String> = BTreeSet::new();
        if code.localsplusnames.is_empty() {
            for obj in &code.varnames {
                if let Some(name) = object_str(obj) {
                    fast.insert(name);
                }
            }
            for obj in code.cellvars.iter().chain(code.freevars.iter()) {
                if let Some(name) = object_str(obj) {
                    deref.insert(name);
                }
            }
        } else {
            for (idx, obj) in code.localsplusnames.iter().enumerate() {
                let Some(name): Option<String> = object_str(obj) else {
                    continue;
                };
                let kind: u8 = code.localspluskinds.get(idx).copied().unwrap_or(0);
                if kind & (KIND_CELL | KIND_FREE) != 0 {
                    deref.insert(name);
                } else {
                    fast.insert(name);
                }
            }
        }
        Self {
            fast,
            deref,
            function_scope,
        }
    }

    #[must_use]
    pub(crate) fn is_function_scope(&self) -> bool {
        self.function_scope
    }

    #[must_use]
    fn load_op_for(&self, name: &str) -> Option<&'static str> {
        if self.deref.contains(name) {
            Some("LOAD_DEREF")
        } else if self.fast.contains(name) {
            Some("LOAD_FAST")
        } else if self.function_scope {
            Some("LOAD_GLOBAL")
        } else {
            None
        }
    }

    #[must_use]
    fn store_op_for(&self, name: &str) -> Option<&'static str> {
        if self.deref.contains(name) {
            Some("STORE_DEREF")
        } else if self.fast.contains(name) {
            Some("STORE_FAST")
        } else if self.function_scope {
            Some("STORE_GLOBAL")
        } else {
            None
        }
    }
}

#[cfg(test)]
impl ScopeCtx {
    #[must_use]
    pub(crate) fn from_parts(fast: &[&str], deref: &[&str], function_scope: bool) -> Self {
        Self {
            fast: fast.iter().map(|s: &&str| (*s).to_owned()).collect(),
            deref: deref.iter().map(|s: &&str| (*s).to_owned()).collect(),
            function_scope,
        }
    }
}

#[must_use]
fn object_str(obj: &Object) -> Option<String> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum Tail {
    Return,
    Goto(u32),
}

#[derive(Debug)]
enum Item {
    Op(NormalizedOp),
    Label(u32),
    Jump(u32),
    CondJump(&'static str, u32),
}

#[derive(Debug)]
struct Emitter {
    items: Vec<Item>,
    next_label: u32,
}

impl Emitter {
    #[must_use]
    fn new() -> Self {
        Self {
            items: Vec::new(),
            next_label: 0,
        }
    }

    fn new_label(&mut self) -> u32 {
        let label: u32 = self.next_label;
        self.next_label += 1;
        label
    }

    fn place(&mut self, label: u32) {
        self.items.push(Item::Label(label));
    }

    fn op(&mut self, op: NormalizedOp) {
        self.items.push(Item::Op(op));
    }

    fn push_ops(&mut self, ops: Vec<NormalizedOp>) {
        for op in ops {
            self.items.push(Item::Op(op));
        }
    }

    fn jump(&mut self, label: u32) {
        self.items.push(Item::Jump(label));
    }

    fn cond_jump(&mut self, name: &'static str, label: u32) {
        self.items.push(Item::CondJump(name, label));
    }

    #[must_use]
    fn finish(self) -> Option<Vec<NormalizedOp>> {
        let items: Vec<Item> = elide_noop_jumps(self.items);
        let mut label_index: BTreeMap<u32, u32> = BTreeMap::new();
        let mut idx: u32 = 0;
        for item in &items {
            match item {
                Item::Label(label) => {
                    label_index.insert(*label, idx);
                }
                _ => idx = idx.checked_add(1)?,
            }
        }
        let mut out: Vec<NormalizedOp> = Vec::with_capacity(items.len());
        for item in items {
            match item {
                Item::Label(_) => {}
                Item::Op(op) => out.push(op),
                Item::Jump(label) => out.push(jump_op("JUMP", label_index.get(&label).copied())),
                Item::CondJump(name, label) => {
                    out.push(jump_op(name, label_index.get(&label).copied()));
                }
            }
        }
        Some(out)
    }
}

#[must_use]
fn elide_noop_jumps(items: Vec<Item>) -> Vec<Item> {
    let mut remove: Vec<bool> = vec![false; items.len()];
    for (pos, item) in items.iter().enumerate() {
        let Item::Jump(target) = item else {
            continue;
        };
        let mut cursor: usize = pos + 1;
        let mut lands_on_next: bool = false;
        while let Some(next) = items.get(cursor) {
            match next {
                Item::Label(label) if label == target => {
                    lands_on_next = true;
                    break;
                }
                Item::Label(_) => cursor += 1,
                _ => break,
            }
        }
        if lands_on_next {
            remove[pos] = true;
        }
    }
    items
        .into_iter()
        .enumerate()
        .filter_map(|(idx, item): (usize, Item)| (!remove[idx]).then_some(item))
        .collect()
}

#[must_use]
pub(crate) fn relower_function_body(body: &[Stmt], ctx: &ScopeCtx) -> Relowered {
    if !ctx.is_function_scope() {
        return Relowered::Uncovered;
    }
    let mut em: Emitter = Emitter::new();
    if lower_seq(body, ctx, &mut em, Tail::Return, 0).is_none() {
        return Relowered::Uncovered;
    }
    em.finish()
        .map_or(Relowered::Uncovered, |ops: Vec<NormalizedOp>| {
            Relowered::Ops(canonicalize_relowered(ops))
        })
}

#[must_use]
fn lower_seq(
    stmts: &[Stmt],
    ctx: &ScopeCtx,
    em: &mut Emitter,
    tail: Tail,
    depth: u32,
) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    let Some((first, rest)): Option<(&Stmt, &[Stmt])> = stmts.split_first() else {
        return apply_tail(em, tail);
    };
    match first {
        Stmt::If {
            test, body, orelse, ..
        } => lower_if(test, body, orelse, rest, ctx, em, tail, depth),
        Stmt::While {
            test, body, orelse, ..
        } => lower_while(test, body, orelse, rest, ctx, em, tail, depth),
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            is_async,
            ..
        } => {
            if *is_async {
                return None;
            }
            lower_for(target, iter, body, orelse, rest, ctx, em, tail, depth)
        }
        Stmt::Return(value) => {
            if !rest.is_empty() {
                return None;
            }
            lower_return(value.as_ref(), ctx, em)
        }
        Stmt::Pass | Stmt::Assign { .. } | Stmt::Expr(_) => {
            lower_simple(first, ctx, em)?;
            lower_seq(rest, ctx, em, tail, depth)
        }
        _ => None,
    }
}

#[must_use]
fn apply_tail(em: &mut Emitter, tail: Tail) -> Option<()> {
    match tail {
        Tail::Return => {
            em.op(op_const(ConstValue::None));
            em.op(op_bare("RETURN_VALUE"));
            Some(())
        }
        Tail::Goto(label) => {
            em.jump(label);
            Some(())
        }
    }
}

#[must_use]
#[allow(clippy::too_many_arguments)]
fn lower_if(
    test: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    rest: &[Stmt],
    ctx: &ScopeCtx,
    em: &mut Emitter,
    tail: Tail,
    depth: u32,
) -> Option<()> {
    if orelse.is_empty() {
        let join: u32 = em.new_label();
        emit_condition(test, join, ctx, em)?;
        let body_tail: Tail = if rest.is_empty() {
            tail
        } else {
            Tail::Goto(join)
        };
        lower_seq(body, ctx, em, body_tail, depth + 1)?;
        em.place(join);
        return lower_seq(rest, ctx, em, tail, depth + 1);
    }
    let elselbl: u32 = em.new_label();
    emit_condition(test, elselbl, ctx, em)?;
    if rest.is_empty() {
        lower_seq(body, ctx, em, tail, depth + 1)?;
        em.place(elselbl);
        return lower_seq(orelse, ctx, em, tail, depth + 1);
    }
    let join: u32 = em.new_label();
    lower_seq(body, ctx, em, Tail::Goto(join), depth + 1)?;
    em.place(elselbl);
    lower_seq(orelse, ctx, em, Tail::Goto(join), depth + 1)?;
    em.place(join);
    lower_seq(rest, ctx, em, tail, depth + 1)
}

#[must_use]
#[allow(clippy::too_many_arguments)]
fn lower_while(
    test: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    rest: &[Stmt],
    ctx: &ScopeCtx,
    em: &mut Emitter,
    tail: Tail,
    depth: u32,
) -> Option<()> {
    if !body_is_straight_line(body) || is_constant_test(test) {
        return None;
    }
    let header: u32 = em.new_label();
    let exit: u32 = em.new_label();
    em.place(header);
    emit_condition(test, exit, ctx, em)?;
    lower_seq(body, ctx, em, Tail::Goto(header), depth + 1)?;
    em.place(exit);
    let cont: Vec<Stmt> = concat_stmts(orelse, rest);
    lower_seq(&cont, ctx, em, tail, depth + 1)
}

#[must_use]
#[allow(clippy::too_many_arguments)]
fn lower_for(
    target: &Expr,
    iter: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    rest: &[Stmt],
    ctx: &ScopeCtx,
    em: &mut Emitter,
    tail: Tail,
    depth: u32,
) -> Option<()> {
    if !body_is_straight_line(body) {
        return None;
    }
    let Expr::Name {
        id,
        ctx: ExprCtx::Store,
        ..
    } = target
    else {
        return None;
    };
    let store_op: &'static str = ctx.store_op_for(id)?;
    emit_expr(iter, ctx, em)?;
    em.op(op_bare("GET_ITER"));
    let header: u32 = em.new_label();
    let end: u32 = em.new_label();
    em.place(header);
    em.cond_jump("FOR_ITER", end);
    em.op(op_name(store_op, id));
    lower_seq(body, ctx, em, Tail::Goto(header), depth + 1)?;
    em.place(end);
    em.op(op_bare("END_FOR"));
    em.op(op_bare("POP_ITER"));
    let cont: Vec<Stmt> = concat_stmts(orelse, rest);
    lower_seq(&cont, ctx, em, tail, depth + 1)
}

#[must_use]
fn concat_stmts(head: &[Stmt], tail: &[Stmt]) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(head.len() + tail.len());
    out.extend_from_slice(head);
    out.extend_from_slice(tail);
    out
}

#[must_use]
fn body_is_straight_line(body: &[Stmt]) -> bool {
    !body.is_empty()
        && body
            .iter()
            .all(|s: &Stmt| matches!(s, Stmt::Pass | Stmt::Assign { .. } | Stmt::Expr(_)))
}

#[must_use]
fn is_constant_test(test: &Expr) -> bool {
    matches!(test, Expr::Constant { .. })
}

#[must_use]
fn lower_return(value: Option<&Expr>, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    let mut ops: Vec<NormalizedOp> = Vec::new();
    match value {
        None => {
            ops.push(op_const(ConstValue::None));
            ops.push(op_bare("RETURN_VALUE"));
        }
        Some(expr) => {
            lower_expr(expr, ctx, &mut ops)?;
            ops.push(op_bare("RETURN_VALUE"));
        }
    }
    em.push_ops(ops);
    Some(())
}

#[must_use]
fn lower_simple(stmt: &Stmt, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    let mut ops: Vec<NormalizedOp> = Vec::new();
    lower_simple_ops(stmt, ctx, &mut ops)?;
    em.push_ops(ops);
    Some(())
}

#[must_use]
fn lower_simple_ops(stmt: &Stmt, ctx: &ScopeCtx, out: &mut Vec<NormalizedOp>) -> Option<()> {
    match stmt {
        Stmt::Pass => Some(()),
        Stmt::Expr(call @ Expr::Call { .. }) => {
            lower_expr(call, ctx, out)?;
            out.push(op_bare("POP_TOP"));
            Some(())
        }
        Stmt::Assign { targets, value, .. } if targets.len() == 1 => {
            lower_assign(&targets[0], value, ctx, out)
        }
        _ => None,
    }
}

#[must_use]
fn emit_expr(expr: &Expr, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    let mut ops: Vec<NormalizedOp> = Vec::new();
    lower_expr(expr, ctx, &mut ops)?;
    em.push_ops(ops);
    Some(())
}

#[must_use]
fn emit_condition(test: &Expr, target: u32, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    emit_branch(test, target, ctx, em)?;
    em.op(op_bare("NOT_TAKEN"));
    Some(())
}

#[must_use]
fn emit_branch(test: &Expr, target: u32, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    match test {
        Expr::UnaryOp {
            op: UnaryOp::Not,
            operand,
        } => {
            emit_expr(operand, ctx, em)?;
            em.op(op_bare("TO_BOOL"));
            em.cond_jump("JUMP_IF_TRUE", target);
            Some(())
        }
        Expr::Compare {
            left,
            ops,
            comparators,
        } if ops.len() == 1 && comparators.len() == 1 => {
            emit_compare_condition(left, ops[0], &comparators[0], target, ctx, em)
        }
        Expr::BoolOp { .. }
        | Expr::IfExp { .. }
        | Expr::NamedExpr { .. }
        | Expr::Constant { .. }
        | Expr::Compare { .. } => None,
        other => {
            emit_expr(other, ctx, em)?;
            em.op(op_bare("TO_BOOL"));
            em.cond_jump("JUMP_IF_FALSE", target);
            Some(())
        }
    }
}

#[must_use]
fn emit_compare_condition(
    left: &Expr,
    op: CmpOp,
    right: &Expr,
    target: u32,
    ctx: &ScopeCtx,
    em: &mut Emitter,
) -> Option<()> {
    if matches!(op, CmpOp::Is | CmpOp::IsNot) && is_none_const(right) {
        emit_expr(left, ctx, em)?;
        let name: &'static str = if matches!(op, CmpOp::Is) {
            "JUMP_IF_NOT_NONE"
        } else {
            "JUMP_IF_NONE"
        };
        em.cond_jump(name, target);
        return Some(());
    }
    if !matches!(
        op,
        CmpOp::Lt
            | CmpOp::Le
            | CmpOp::Eq
            | CmpOp::Ne
            | CmpOp::Gt
            | CmpOp::Ge
            | CmpOp::In
            | CmpOp::NotIn
            | CmpOp::Is
            | CmpOp::IsNot
    ) {
        return None;
    }
    emit_expr(left, ctx, em)?;
    emit_expr(right, ctx, em)?;
    em.op(compare_op(op)?);
    em.cond_jump("JUMP_IF_FALSE", target);
    Some(())
}

#[must_use]
fn is_none_const(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Constant {
            value: AstConst::None,
            ..
        }
    )
}

#[must_use]
fn lower_assign(
    target: &Expr,
    value: &Expr,
    ctx: &ScopeCtx,
    out: &mut Vec<NormalizedOp>,
) -> Option<()> {
    match target {
        Expr::Name {
            id,
            ctx: ExprCtx::Store,
            ..
        } => {
            lower_expr(value, ctx, out)?;
            let op: &'static str = ctx.store_op_for(id)?;
            out.push(op_name(op, id));
            Some(())
        }
        Expr::Attribute {
            value: obj,
            attr,
            ctx: ExprCtx::Store,
        } => {
            lower_expr(value, ctx, out)?;
            lower_expr(obj, ctx, out)?;
            out.push(op_name("STORE_ATTR", attr));
            Some(())
        }
        Expr::Subscript {
            value: obj,
            slice,
            ctx: ExprCtx::Store,
        } => {
            if matches!(slice.as_ref(), Expr::Slice { .. }) {
                return None;
            }
            lower_expr(value, ctx, out)?;
            lower_expr(obj, ctx, out)?;
            lower_expr(slice, ctx, out)?;
            out.push(op_bare("STORE_SUBSCR"));
            Some(())
        }
        _ => None,
    }
}

#[must_use]
fn lower_expr(expr: &Expr, ctx: &ScopeCtx, out: &mut Vec<NormalizedOp>) -> Option<()> {
    match expr {
        Expr::Constant { value, .. } => {
            out.push(op_const(map_const(value)?));
            Some(())
        }
        Expr::Name {
            id,
            ctx: ExprCtx::Load,
            ..
        } => {
            let op: &'static str = ctx.load_op_for(id)?;
            out.push(op_name(op, id));
            Some(())
        }
        Expr::Attribute {
            value,
            attr,
            ctx: ExprCtx::Load,
        } => {
            lower_expr(value, ctx, out)?;
            out.push(op_name("LOAD_ATTR", attr));
            Some(())
        }
        Expr::Subscript {
            value,
            slice,
            ctx: ExprCtx::Load,
        } => {
            if matches!(slice.as_ref(), Expr::Slice { .. }) {
                return None;
            }
            lower_expr(value, ctx, out)?;
            lower_expr(slice, ctx, out)?;
            out.push(op_operator("BINARY_OP", NB_SUBSCR));
            Some(())
        }
        Expr::BinOp { left, op, right } => {
            let code: u32 = binop_code(*op)?;
            lower_expr(left, ctx, out)?;
            lower_expr(right, ctx, out)?;
            out.push(op_operator("BINARY_OP", code));
            Some(())
        }
        Expr::UnaryOp { op, operand } => {
            let name: &'static str = unary_name(*op)?;
            lower_expr(operand, ctx, out)?;
            out.push(op_bare(name));
            Some(())
        }
        Expr::Compare {
            left,
            ops,
            comparators,
        } if ops.len() == 1 && comparators.len() == 1 => {
            lower_expr(left, ctx, out)?;
            lower_expr(&comparators[0], ctx, out)?;
            out.push(compare_op(ops[0])?);
            Some(())
        }
        Expr::Call {
            func,
            args,
            keywords,
        } if keywords.is_empty() => lower_call(func, args, ctx, out),
        _ => None,
    }
}

#[must_use]
fn lower_call(
    func: &Expr,
    args: &[Expr],
    ctx: &ScopeCtx,
    out: &mut Vec<NormalizedOp>,
) -> Option<()> {
    if args
        .iter()
        .any(|a: &Expr| matches!(a, Expr::Starred { .. }))
    {
        return None;
    }
    match func {
        Expr::Name {
            id,
            ctx: ExprCtx::Load,
            ..
        } => {
            let op: &'static str = ctx.load_op_for(id)?;
            out.push(op_name(op, id));
            if op != "LOAD_GLOBAL" {
                out.push(op_bare("PUSH_NULL"));
            }
        }
        Expr::Attribute {
            value,
            attr,
            ctx: ExprCtx::Load,
        } => {
            lower_expr(value, ctx, out)?;
            out.push(op_name("LOAD_ATTR", attr));
        }
        _ => return None,
    }
    for arg in args {
        lower_expr(arg, ctx, out)?;
    }
    let argc: u32 = u32::try_from(args.len()).ok()?;
    out.push(op_operator("CALL", argc));
    Some(())
}

#[must_use]
fn map_const(value: &AstConst) -> Option<ConstValue> {
    match value {
        AstConst::None => Some(ConstValue::None),
        AstConst::True => Some(ConstValue::Bool(true)),
        AstConst::False => Some(ConstValue::Bool(false)),
        AstConst::Int(i) => i32::try_from(*i).ok().map(ConstValue::SmallInt),
        AstConst::Str(s) | AstConst::Unicode(s) => Some(ConstValue::Str(s.clone())),
        AstConst::Bytes(b) => Some(ConstValue::Bytes(b.clone())),
        AstConst::Float(f) => Some(ConstValue::Float(canonical_float_bits(*f))),
        _ => None,
    }
}

#[must_use]
fn canonical_float_bits(f: f64) -> u64 {
    if f.is_nan() {
        f64::NAN.to_bits()
    } else {
        f.to_bits()
    }
}

#[must_use]
const fn binop_code(op: BinOp) -> Option<u32> {
    let code: u32 = match op {
        BinOp::Add => 0,
        BinOp::BitAnd => 1,
        BinOp::FloorDiv => 2,
        BinOp::Lshift => 3,
        BinOp::MatMul => 4,
        BinOp::Mul => 5,
        BinOp::Mod => 6,
        BinOp::BitOr => 7,
        BinOp::Pow => 8,
        BinOp::Rshift => 9,
        BinOp::Sub => 10,
        BinOp::TrueDiv => 11,
        BinOp::BitXor => 12,
        _ => return None,
    };
    Some(code)
}

#[must_use]
const fn unary_name(op: UnaryOp) -> Option<&'static str> {
    match op {
        UnaryOp::Negative => Some("UNARY_NEGATIVE"),
        UnaryOp::Invert => Some("UNARY_INVERT"),
        _ => None,
    }
}

#[must_use]
fn compare_op(op: CmpOp) -> Option<NormalizedOp> {
    let (name, operator_id): (&'static str, u32) = match op {
        CmpOp::Lt => ("COMPARE_OP", 0),
        CmpOp::Le => ("COMPARE_OP", 2),
        CmpOp::Eq => ("COMPARE_OP", 4),
        CmpOp::Ne => ("COMPARE_OP", 6),
        CmpOp::Gt => ("COMPARE_OP", 8),
        CmpOp::Ge => ("COMPARE_OP", 10),
        CmpOp::Is => ("IS_OP", 0),
        CmpOp::IsNot => ("IS_OP", 1),
        CmpOp::In => ("CONTAINS_OP", 0),
        CmpOp::NotIn => ("CONTAINS_OP", 1),
        _ => return None,
    };
    Some(op_operator(name, operator_id))
}

#[must_use]
fn op_bare(name: &'static str) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(name.into()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_const(value: ConstValue) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op("LOAD_CONST".into()),
        const_value: Some(value),
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_name(op: &'static str, name: &str) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(op.into()),
        const_value: None,
        name_value: Some(NameValue(name.to_owned())),
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_operator(op: &'static str, operator_id: u32) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(op.into()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: Some(operator_id),
        raw_arg: None,
    }
}

#[must_use]
fn jump_op(name: &str, target: Option<u32>) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(name.into()),
        const_value: None,
        name_value: None,
        jump_target_index: target,
        operator_id: None,
        raw_arg: None,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::ast::node::{BoolOpKind, ConstValue as AstConst};

    fn load(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }
    }

    fn store(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Store,
            line: None,
        }
    }

    fn assign(target: Expr, value: Expr) -> Stmt {
        Stmt::Assign {
            targets: vec![target],
            value,
            type_comment: None,
            line: None,
        }
    }

    fn attr_load(obj: Expr, attr: &str) -> Expr {
        Expr::Attribute {
            value: Box::new(obj),
            attr: attr.to_owned(),
            ctx: ExprCtx::Load,
        }
    }

    fn call(func: Expr, args: Vec<Expr>) -> Expr {
        Expr::Call {
            func: Box::new(func),
            args,
            keywords: Vec::new(),
        }
    }

    fn call_stmt(func: Expr, args: Vec<Expr>) -> Stmt {
        Stmt::Expr(call(func, args))
    }

    fn if_stmt(test: Expr, body: Vec<Stmt>, orelse: Vec<Stmt>) -> Stmt {
        Stmt::If {
            test,
            body,
            orelse,
            line: None,
        }
    }

    fn ops(body: &[Stmt], ctx: &ScopeCtx) -> Vec<NormalizedOp> {
        match relower_function_body(body, ctx) {
            Relowered::Ops(o) => o,
            Relowered::Uncovered => panic!("expected covered body, got Uncovered"),
        }
    }

    fn names(seq: &[NormalizedOp]) -> Vec<String> {
        seq.iter()
            .map(|op: &NormalizedOp| match &op.token {
                NormToken::Op(n) => n.clone(),
                NormToken::JRetLeaf => "JRET".to_owned(),
                NormToken::RetBlock => "RETBLK".to_owned(),
            })
            .collect()
    }

    fn jret_none() -> NormalizedOp {
        NormalizedOp {
            token: NormToken::JRetLeaf,
            const_value: Some(ConstValue::None),
            name_value: None,
            jump_target_index: None,
            operator_id: None,
            raw_arg: None,
        }
    }

    #[test]
    fn assign_binop_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "x"], &[], true);
        let body: Vec<Stmt> = vec![
            assign(
                store("x"),
                Expr::BinOp {
                    left: Box::new(load("a")),
                    op: BinOp::Add,
                    right: Box::new(load("b")),
                },
            ),
            Stmt::Return(Some(load("x"))),
        ];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "a"),
            op_name("LOAD_FAST", "b"),
            op_operator("BINARY_OP", 0),
            op_name("STORE_FAST", "x"),
            op_name("LOAD_FAST", "x"),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn method_call_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["self", "x"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(call(
            attr_load(load("self"), "g"),
            vec![load("x")],
        )))];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "self"),
            op_name("LOAD_ATTR", "g"),
            op_name("LOAD_FAST", "x"),
            op_operator("CALL", 1),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn local_callable_emits_push_null() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["b"], &[], true);
        let body: Vec<Stmt> = vec![call_stmt(load("b"), Vec::new())];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "b"),
            op_bare("PUSH_NULL"),
            op_operator("CALL", 0),
            op_bare("POP_TOP"),
            jret_none(),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn global_call_and_attr_store_and_implicit_return() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["self", "x"], &[], true);
        let body: Vec<Stmt> = vec![
            assign(
                Expr::Attribute {
                    value: Box::new(load("self")),
                    attr: "y".to_owned(),
                    ctx: ExprCtx::Store,
                },
                load("x"),
            ),
            call_stmt(load("log"), Vec::new()),
        ];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "x"),
            op_name("LOAD_FAST", "self"),
            op_name("STORE_ATTR", "y"),
            op_name("LOAD_GLOBAL", "log"),
            op_operator("CALL", 0),
            op_bare("POP_TOP"),
            jret_none(),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn compare_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(Expr::Compare {
            left: Box::new(load("a")),
            ops: vec![CmpOp::Lt],
            comparators: vec![load("b")],
        }))];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "a"),
            op_name("LOAD_FAST", "b"),
            op_operator("COMPARE_OP", 0),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn if_without_else_tail_duplicates_return_none() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let body: Vec<Stmt> = vec![if_stmt(
            load("a"),
            vec![call_stmt(load("b"), Vec::new())],
            Vec::new(),
        )];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_FAST",
                "TO_BOOL",
                "JUMP_IF_FALSE",
                "NOT_TAKEN",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "JRET",
            ]
        );
        assert_eq!(seq[2].jump_target_index, Some(10));
    }

    #[test]
    fn if_followed_by_return_shares_join() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "c"], &[], true);
        let body: Vec<Stmt> = vec![
            if_stmt(load("a"), vec![Stmt::Return(Some(load("b")))], Vec::new()),
            Stmt::Return(Some(load("c"))),
        ];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_FAST",
                "TO_BOOL",
                "JUMP_IF_FALSE",
                "NOT_TAKEN",
                "LOAD_FAST",
                "RETURN_VALUE",
                "LOAD_FAST",
                "RETURN_VALUE",
            ]
        );
        assert_eq!(seq[2].jump_target_index, Some(6));
    }

    #[test]
    fn if_else_continuation_jumps_over_else() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "c", "d"], &[], true);
        let body: Vec<Stmt> = vec![
            if_stmt(
                load("a"),
                vec![call_stmt(load("b"), Vec::new())],
                vec![call_stmt(load("c"), Vec::new())],
            ),
            call_stmt(load("d"), Vec::new()),
        ];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_FAST",
                "TO_BOOL",
                "JUMP_IF_FALSE",
                "NOT_TAKEN",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "JUMP",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "JRET",
            ]
        );
        assert_eq!(seq[2].jump_target_index, Some(9));
        assert_eq!(seq[8].jump_target_index, Some(13));
    }

    #[test]
    fn for_loop_straight_body_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "x"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::For {
            target: store("x"),
            iter: load("a"),
            body: vec![call_stmt(load("x"), Vec::new())],
            orelse: Vec::new(),
            is_async: false,
            line: None,
        }];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_FAST",
                "GET_ITER",
                "FOR_ITER",
                "STORE_FAST",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "JUMP",
                "END_FOR",
                "POP_ITER",
                "JRET",
            ]
        );
        assert_eq!(seq[2].jump_target_index, Some(9));
        assert_eq!(seq[8].jump_target_index, Some(2));
    }

    #[test]
    fn while_loop_straight_body_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::While {
            test: load("a"),
            body: vec![call_stmt(load("a"), Vec::new())],
            orelse: Vec::new(),
            line: None,
        }];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_FAST",
                "TO_BOOL",
                "JUMP_IF_FALSE",
                "NOT_TAKEN",
                "LOAD_FAST",
                "PUSH_NULL",
                "CALL",
                "POP_TOP",
                "JUMP",
                "JRET",
            ]
        );
        assert_eq!(seq[2].jump_target_index, Some(9));
        assert_eq!(seq[8].jump_target_index, Some(0));
    }

    #[test]
    fn not_condition_flips_polarity() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let body: Vec<Stmt> = vec![if_stmt(
            Expr::UnaryOp {
                op: UnaryOp::Not,
                operand: Box::new(load("a")),
            },
            vec![call_stmt(load("b"), Vec::new())],
            Vec::new(),
        )];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq)[0..4],
            ["LOAD_FAST", "TO_BOOL", "JUMP_IF_TRUE", "NOT_TAKEN"]
        );
    }

    #[test]
    fn is_none_condition_uses_none_branch() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let body: Vec<Stmt> = vec![if_stmt(
            Expr::Compare {
                left: Box::new(load("a")),
                ops: vec![CmpOp::Is],
                comparators: vec![Expr::Constant {
                    value: AstConst::None,
                    line: None,
                }],
            },
            vec![call_stmt(load("b"), Vec::new())],
            Vec::new(),
        )];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(names(&seq)[0..2], ["LOAD_FAST", "JUMP_IF_NOT_NONE"]);
    }

    #[test]
    fn deref_and_global_resolution() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &["cell"], true);
        let body: Vec<Stmt> = vec![
            assign(store("a"), load("cell")),
            assign(store("a"), load("glob")),
        ];
        let out: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(out[0], op_name("LOAD_DEREF", "cell"));
        assert_eq!(out[2], op_name("LOAD_GLOBAL", "glob"));
    }

    #[test]
    fn non_function_scope_abstains() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &[], false);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(load("a")))];
        assert!(matches!(
            relower_function_body(&body, &ctx),
            Relowered::Uncovered
        ));
    }

    #[test]
    fn boolop_and_while_true_and_nested_loop_if_abstain() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let with_boolop: Vec<Stmt> = vec![Stmt::Return(Some(Expr::BoolOp {
            op: BoolOpKind::And,
            values: vec![load("a"), load("b")],
        }))];
        assert!(matches!(
            relower_function_body(&with_boolop, &ctx),
            Relowered::Uncovered
        ));
        let while_true: Vec<Stmt> = vec![Stmt::While {
            test: Expr::Constant {
                value: AstConst::True,
                line: None,
            },
            body: vec![call_stmt(load("a"), Vec::new())],
            orelse: Vec::new(),
            line: None,
        }];
        assert!(matches!(
            relower_function_body(&while_true, &ctx),
            Relowered::Uncovered
        ));
        let loop_with_if: Vec<Stmt> = vec![Stmt::While {
            test: load("a"),
            body: vec![if_stmt(load("b"), vec![Stmt::Pass], Vec::new())],
            orelse: Vec::new(),
            line: None,
        }];
        assert!(matches!(
            relower_function_body(&loop_with_if, &ctx),
            Relowered::Uncovered
        ));
    }

    #[test]
    fn small_int_and_none_consts() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["x"], &[], true);
        let body: Vec<Stmt> = vec![assign(
            store("x"),
            Expr::Constant {
                value: AstConst::Int(5),
                line: None,
            },
        )];
        let out: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(out[0], op_const(ConstValue::SmallInt(5)));
        assert_eq!(out[1], op_name("STORE_FAST", "x"));
        assert_eq!(out[2], jret_none());
    }
}
