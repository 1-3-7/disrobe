use std::collections::BTreeMap;
use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{ConstValue as AstConst, ExceptHandler, Expr, ExprCtx, Keyword, Stmt};
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
    module_imports: BTreeSet<String>,
    function_scope: bool,
}

impl ScopeCtx {
    #[must_use]
    pub(crate) fn from_code(code: &CodeObject, module_imports: &BTreeSet<String>) -> Self {
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
            module_imports: module_imports.clone(),
            function_scope,
        }
    }

    #[must_use]
    pub(crate) fn is_function_scope(&self) -> bool {
        self.function_scope
    }

    #[must_use]
    fn is_module_import(&self, name: &str) -> bool {
        self.module_imports.contains(name)
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
        Self::from_parts_with_imports(fast, deref, &[], function_scope)
    }

    #[must_use]
    pub(crate) fn from_parts_with_imports(
        fast: &[&str],
        deref: &[&str],
        module_imports: &[&str],
        function_scope: bool,
    ) -> Self {
        Self {
            fast: fast.iter().map(|s: &&str| (*s).to_owned()).collect(),
            deref: deref.iter().map(|s: &&str| (*s).to_owned()).collect(),
            module_imports: module_imports
                .iter()
                .map(|s: &&str| (*s).to_owned())
                .collect(),
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
    FallThrough,
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
    cold: Vec<Item>,
    emitting_cold: bool,
    next_label: u32,
}

impl Emitter {
    #[must_use]
    fn new() -> Self {
        Self {
            items: Vec::new(),
            cold: Vec::new(),
            emitting_cold: false,
            next_label: 0,
        }
    }

    fn sink(&mut self) -> &mut Vec<Item> {
        if self.emitting_cold {
            &mut self.cold
        } else {
            &mut self.items
        }
    }

    fn new_label(&mut self) -> u32 {
        let label: u32 = self.next_label;
        self.next_label += 1;
        label
    }

    fn place(&mut self, label: u32) {
        self.sink().push(Item::Label(label));
    }

    fn op(&mut self, op: NormalizedOp) {
        self.sink().push(Item::Op(op));
    }

    fn push_ops(&mut self, ops: Vec<NormalizedOp>) {
        let sink: &mut Vec<Item> = self.sink();
        for op in ops {
            sink.push(Item::Op(op));
        }
    }

    fn jump(&mut self, label: u32) {
        self.sink().push(Item::Jump(label));
    }

    fn cond_jump(&mut self, name: &'static str, label: u32) {
        self.sink().push(Item::CondJump(name, label));
    }

    #[must_use]
    fn finish(mut self) -> Option<Vec<NormalizedOp>> {
        self.items.append(&mut self.cold);
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
        Stmt::Raise { exc, cause, .. } => {
            if !rest.is_empty() {
                return None;
            }
            lower_raise(exc.as_ref(), cause.as_ref(), ctx, em)
        }
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => lower_try(
            body, handlers, orelse, finalbody, rest, ctx, em, tail, depth,
        ),
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
        Tail::FallThrough => Some(()),
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

#[derive(Debug, Clone, Copy)]
enum Cont<'a> {
    DupReturn(Option<&'a Expr>),
    JumpBack,
}

#[must_use]
#[allow(clippy::too_many_arguments)]
fn lower_try<'a>(
    body: &'a [Stmt],
    handlers: &'a [ExceptHandler],
    orelse: &'a [Stmt],
    finalbody: &'a [Stmt],
    rest: &'a [Stmt],
    ctx: &ScopeCtx,
    em: &mut Emitter,
    tail: Tail,
    depth: u32,
) -> Option<()> {
    if depth > MAX_DEPTH || em.emitting_cold {
        return None;
    }
    if !finalbody.is_empty() || handlers.is_empty() || !handlers_covered(handlers) {
        return None;
    }
    let needs_cont: bool = handlers
        .iter()
        .any(|h: &ExceptHandler| handler_falls_through(&h.body));
    let cont: Option<Cont<'a>> = if needs_cont {
        Some(classify_cont(rest, tail)?)
    } else {
        None
    };
    lower_seq(body, ctx, em, Tail::FallThrough, depth + 1)?;
    if !orelse.is_empty() {
        lower_seq(orelse, ctx, em, Tail::FallThrough, depth + 1)?;
    }
    emit_handlers(handlers, cont, ctx, em, depth)?;
    match cont {
        Some(Cont::DupReturn(value)) => lower_return(value, ctx, em),
        Some(Cont::JumpBack) | None => lower_seq(rest, ctx, em, tail, depth + 1),
    }
}

#[must_use]
fn handlers_covered(handlers: &[ExceptHandler]) -> bool {
    handlers
        .iter()
        .enumerate()
        .all(|(idx, h): (usize, &ExceptHandler)| {
            h.name.is_none()
                && !stmts_contain_region(&h.body)
                && (h.typ.is_some() || idx + 1 == handlers.len())
        })
}

#[must_use]
fn handler_falls_through(body: &[Stmt]) -> bool {
    !matches!(body.last(), Some(Stmt::Return(_) | Stmt::Raise { .. }))
}

#[must_use]
fn stmts_contain_region(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s: &Stmt| match s {
        Stmt::Try { .. } | Stmt::TryStar { .. } | Stmt::With { .. } | Stmt::Match { .. } => true,
        Stmt::If { body, orelse, .. }
        | Stmt::For { body, orelse, .. }
        | Stmt::While { body, orelse, .. } => {
            stmts_contain_region(body) || stmts_contain_region(orelse)
        }
        _ => false,
    })
}

#[must_use]
fn classify_cont(rest: &[Stmt], tail: Tail) -> Option<Cont<'_>> {
    if rest.is_empty() {
        return match tail {
            Tail::Return => Some(Cont::DupReturn(None)),
            _ => None,
        };
    }
    if let [Stmt::Return(value)] = rest {
        return Some(Cont::DupReturn(value.as_ref()));
    }
    Some(Cont::JumpBack)
}

#[must_use]
fn emit_handlers(
    handlers: &[ExceptHandler],
    cont: Option<Cont<'_>>,
    ctx: &ScopeCtx,
    em: &mut Emitter,
    depth: u32,
) -> Option<()> {
    em.emitting_cold = true;
    let result: Option<()> = emit_handlers_inner(handlers, cont, ctx, em, depth);
    em.emitting_cold = false;
    result
}

#[must_use]
fn emit_handlers_inner(
    handlers: &[ExceptHandler],
    cont: Option<Cont<'_>>,
    ctx: &ScopeCtx,
    em: &mut Emitter,
    depth: u32,
) -> Option<()> {
    em.op(op_bare("PUSH_EXC_INFO"));
    let mut pending_false: Option<u32> = None;
    let mut last_typed: bool = false;
    for handler in handlers {
        if let Some(label) = pending_false.take() {
            em.place(label);
        }
        if let Some(typ) = &handler.typ {
            emit_handler_type(typ, ctx, em)?;
            em.op(op_bare("CHECK_EXC_MATCH"));
            let next: u32 = em.new_label();
            em.cond_jump("JUMP_IF_FALSE", next);
            em.op(op_bare("NOT_TAKEN"));
            pending_false = Some(next);
            last_typed = true;
        } else {
            last_typed = false;
        }
        em.op(op_bare("POP_TOP"));
        emit_handler_body(&handler.body, cont, ctx, em, depth)?;
    }
    if last_typed {
        if let Some(label) = pending_false.take() {
            em.place(label);
        }
        em.op(op_raw("RERAISE", 0));
    }
    em.op(op_raw("COPY", 3));
    em.op(op_bare("POP_EXCEPT"));
    em.op(op_raw("RERAISE", 1));
    Some(())
}

#[must_use]
fn emit_handler_type(typ: &Expr, ctx: &ScopeCtx, em: &mut Emitter) -> Option<()> {
    if let Expr::Tuple { elts, .. } = typ {
        for elt in elts {
            emit_expr(elt, ctx, em)?;
        }
        let count: u32 = u32::try_from(elts.len()).ok()?;
        em.op(op_operator("BUILD_TUPLE", count));
        return Some(());
    }
    emit_expr(typ, ctx, em)
}

#[must_use]
fn emit_handler_body(
    body: &[Stmt],
    cont: Option<Cont<'_>>,
    ctx: &ScopeCtx,
    em: &mut Emitter,
    depth: u32,
) -> Option<()> {
    let (last, prefix): (&Stmt, &[Stmt]) = body.split_last()?;
    match last {
        Stmt::Return(value) => {
            lower_seq(prefix, ctx, em, Tail::FallThrough, depth + 1)?;
            em.op(op_bare("POP_EXCEPT"));
            lower_return(value.as_ref(), ctx, em)
        }
        Stmt::Raise { exc, cause, .. } => {
            lower_seq(prefix, ctx, em, Tail::FallThrough, depth + 1)?;
            lower_raise(exc.as_ref(), cause.as_ref(), ctx, em)
        }
        _ => {
            lower_seq(body, ctx, em, Tail::FallThrough, depth + 1)?;
            em.op(op_bare("POP_EXCEPT"));
            match cont? {
                Cont::DupReturn(value) => lower_return(value, ctx, em),
                Cont::JumpBack => {
                    em.op(op_bare("JUMP"));
                    Some(())
                }
            }
        }
    }
}

#[must_use]
fn lower_raise(
    exc: Option<&Expr>,
    cause: Option<&Expr>,
    ctx: &ScopeCtx,
    em: &mut Emitter,
) -> Option<()> {
    if cause.is_some() {
        return None;
    }
    match exc {
        None => em.op(op_raw("RAISE_VARARGS", 0)),
        Some(expr) => {
            emit_expr(expr, ctx, em)?;
            em.op(op_raw("RAISE_VARARGS", 1));
        }
    }
    Some(())
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
        } => lower_call(func, args, keywords, ctx, out),
        _ => None,
    }
}

#[must_use]
fn lower_call(
    func: &Expr,
    args: &[Expr],
    keywords: &[Keyword],
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
            let plain: bool = calls_module_attr(value, ctx);
            lower_expr(value, ctx, out)?;
            out.push(op_name("LOAD_ATTR", attr));
            if plain {
                out.push(op_bare("PUSH_NULL"));
            }
        }
        _ => return None,
    }
    for arg in args {
        lower_expr(arg, ctx, out)?;
    }
    if keywords.is_empty() {
        let argc: u32 = u32::try_from(args.len()).ok()?;
        out.push(op_operator("CALL", argc));
        return Some(());
    }
    let mut names: Vec<ConstValue> = Vec::with_capacity(keywords.len());
    for kw in keywords {
        let name: &String = kw.arg.as_ref()?;
        lower_expr(&kw.value, ctx, out)?;
        names.push(ConstValue::Str(name.clone()));
    }
    out.push(op_const(ConstValue::Tuple(names)));
    let total: usize = args.len().checked_add(keywords.len())?;
    let argc: u32 = u32::try_from(total).ok()?;
    out.push(op_operator("CALL_KW", argc));
    Some(())
}

#[must_use]
fn calls_module_attr(value: &Expr, ctx: &ScopeCtx) -> bool {
    matches!(
        value,
        Expr::Name { id, ctx: ExprCtx::Load, .. }
            if ctx.load_op_for(id) == Some("LOAD_GLOBAL") && ctx.is_module_import(id)
    )
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
fn op_raw(name: &'static str, arg: u32) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(name.into()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: Some(arg),
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

    fn handler(typ: Option<Expr>, body: Vec<Stmt>) -> ExceptHandler {
        ExceptHandler {
            typ,
            name: None,
            body,
            line: None,
        }
    }

    fn try_stmt(body: Vec<Stmt>, handlers: Vec<ExceptHandler>, orelse: Vec<Stmt>) -> Stmt {
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody: Vec::new(),
            line: None,
        }
    }

    fn tuple_load(ids: &[&str]) -> Expr {
        Expr::Tuple {
            elts: ids.iter().map(|id: &&str| load(id)).collect(),
            ctx: ExprCtx::Load,
        }
    }

    fn const_none() -> Expr {
        Expr::Constant {
            value: AstConst::None,
            line: None,
        }
    }

    fn attr_store(obj: Expr, attr: &str) -> Expr {
        Expr::Attribute {
            value: Box::new(obj),
            attr: attr.to_owned(),
            ctx: ExprCtx::Store,
        }
    }

    fn open_kw_call() -> Expr {
        Expr::Call {
            func: Box::new(load("open")),
            args: vec![load("fd")],
            keywords: vec![
                Keyword {
                    arg: Some("encoding".to_owned()),
                    value: Expr::Constant {
                        value: AstConst::Str("utf-8".to_owned()),
                        line: None,
                    },
                },
                Keyword {
                    arg: Some("closefd".to_owned()),
                    value: Expr::Constant {
                        value: AstConst::False,
                        line: None,
                    },
                },
            ],
        }
    }

    fn close_stdin_correct() -> Vec<Stmt> {
        let inner: Stmt = try_stmt(
            vec![assign(attr_store(load("sys"), "stdin"), open_kw_call())],
            vec![handler(
                None,
                vec![
                    call_stmt(attr_load(load("os"), "close"), vec![load("fd")]),
                    Stmt::Raise {
                        exc: None,
                        cause: None,
                        line: None,
                    },
                ],
            )],
            Vec::new(),
        );
        let open_call: Expr = call(
            attr_load(load("os"), "open"),
            vec![
                attr_load(load("os"), "devnull"),
                attr_load(load("os"), "O_RDONLY"),
            ],
        );
        let try2: Stmt = try_stmt(
            vec![assign(store("fd"), open_call), inner],
            vec![handler(
                Some(tuple_load(&["OSError", "ValueError"])),
                vec![Stmt::Pass],
            )],
            Vec::new(),
        );
        let try1: Stmt = try_stmt(
            vec![call_stmt(
                attr_load(attr_load(load("sys"), "stdin"), "close"),
                Vec::new(),
            )],
            vec![handler(
                Some(tuple_load(&["OSError", "ValueError"])),
                vec![Stmt::Pass],
            )],
            Vec::new(),
        );
        let guard: Stmt = if_stmt(
            Expr::Compare {
                left: Box::new(attr_load(load("sys"), "stdin")),
                ops: vec![CmpOp::Is],
                comparators: vec![const_none()],
            },
            vec![Stmt::Return(Some(const_none()))],
            Vec::new(),
        );
        vec![guard, try1, try2]
    }

    #[test]
    fn close_stdin_correct_structure_is_covered() {
        let ctx: ScopeCtx = ScopeCtx::from_parts_with_imports(&["fd"], &[], &["os", "sys"], true);
        assert!(matches!(
            relower_function_body(&close_stdin_correct(), &ctx),
            Relowered::Ops(_)
        ));
    }

    #[test]
    fn module_import_call_uses_plain_load_push_null() {
        let ctx: ScopeCtx = ScopeCtx::from_parts_with_imports(&["fd"], &[], &["os"], true);
        let body: Vec<Stmt> = vec![call_stmt(attr_load(load("os"), "close"), vec![load("fd")])];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq)[0..5],
            ["LOAD_GLOBAL", "LOAD_ATTR", "PUSH_NULL", "LOAD_FAST", "CALL"]
        );
    }

    #[test]
    fn non_import_method_call_omits_push_null() {
        let ctx: ScopeCtx = ScopeCtx::from_parts_with_imports(&["fd"], &[], &[], true);
        let body: Vec<Stmt> = vec![call_stmt(attr_load(load("os"), "close"), vec![load("fd")])];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq)[0..4],
            ["LOAD_GLOBAL", "LOAD_ATTR", "LOAD_FAST", "CALL"]
        );
    }

    #[test]
    fn keyword_call_emits_names_tuple_and_call_kw() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["fd"], &[], true);
        let call_kw: Expr = Expr::Call {
            func: Box::new(load("open")),
            args: vec![load("fd")],
            keywords: vec![
                Keyword {
                    arg: Some("encoding".to_owned()),
                    value: Expr::Constant {
                        value: AstConst::Str("utf-8".to_owned()),
                        line: None,
                    },
                },
                Keyword {
                    arg: Some("closefd".to_owned()),
                    value: Expr::Constant {
                        value: AstConst::False,
                        line: None,
                    },
                },
            ],
        };
        let body: Vec<Stmt> = vec![Stmt::Return(Some(call_kw))];
        let seq: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_GLOBAL",
                "LOAD_FAST",
                "LOAD_CONST",
                "LOAD_CONST",
                "LOAD_CONST",
                "CALL_KW",
                "RETURN_VALUE",
            ]
        );
        assert_eq!(seq[5].operator_id, Some(3));
    }

    #[test]
    fn nested_tail_try_relowers_to_expected_3_14_stream() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["x", "a"], &[], true);
        let inner: Stmt = try_stmt(
            vec![call_stmt(load("u"), vec![load("a")])],
            vec![handler(
                None,
                vec![
                    call_stmt(load("c"), vec![load("a")]),
                    Stmt::Raise {
                        exc: None,
                        cause: None,
                        line: None,
                    },
                ],
            )],
            Vec::new(),
        );
        let outer: Stmt = try_stmt(
            vec![assign(store("a"), call(load("g"), vec![load("x")])), inner],
            vec![handler(
                Some(tuple_load(&["OSError", "ValueError"])),
                vec![Stmt::Pass],
            )],
            Vec::new(),
        );
        let seq: Vec<NormalizedOp> = ops(&[outer], &ctx);
        assert_eq!(
            names(&seq),
            vec![
                "LOAD_GLOBAL",
                "LOAD_FAST",
                "CALL",
                "STORE_FAST",
                "LOAD_GLOBAL",
                "LOAD_FAST",
                "CALL",
                "POP_TOP",
                "JRET",
                "PUSH_EXC_INFO",
                "POP_TOP",
                "LOAD_GLOBAL",
                "LOAD_FAST",
                "CALL",
                "POP_TOP",
                "RAISE_VARARGS",
                "COPY",
                "POP_EXCEPT",
                "RERAISE",
                "PUSH_EXC_INFO",
                "LOAD_GLOBAL",
                "LOAD_GLOBAL",
                "BUILD_TUPLE",
                "CHECK_EXC_MATCH",
                "JUMP_IF_FALSE",
                "NOT_TAKEN",
                "POP_TOP",
                "POP_EXCEPT",
                "JRET",
                "RERAISE",
                "COPY",
                "POP_EXCEPT",
                "RERAISE",
            ]
        );
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
