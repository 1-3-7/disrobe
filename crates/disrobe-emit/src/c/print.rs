use std::borrow::Cow;

use pretty::{Arena, DocAllocator, DocBuilder};

use crate::c::ast::{
    AggregateKind, AssignOp, BinaryOp, CBaseType, CDecl, CExpr, CField, CFile, CInit, CItem,
    CParam, CQuals, CStmt, CTypeSpec, DeclaratorChain, IntSuffix, LongSuffix, PostfixOp, Radix,
    Storage, TypeName, UnaryOp,
};
use crate::intern::{Interner, Symbol};
use crate::precedence::{Assoc, Precedence, Side, parenthesize_operand};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParenMode {
    Minimal,
    Full,
}

type Doc<'a> = DocBuilder<'a, Arena<'a>>;

struct Ctx<'a> {
    arena: &'a Arena<'a>,
    interner: &'a Interner,
    mode: ParenMode,
}

const P_COMMA: Precedence = Precedence(0);
const P_ASSIGN: Precedence = Precedence(1);
const P_TERNARY: Precedence = Precedence(2);
const P_LOGOR: Precedence = Precedence(3);
const P_LOGAND: Precedence = Precedence(4);
const P_BITOR: Precedence = Precedence(5);
const P_BITXOR: Precedence = Precedence(6);
const P_BITAND: Precedence = Precedence(7);
const P_EQUALITY: Precedence = Precedence(8);
const P_RELATIONAL: Precedence = Precedence(9);
const P_SHIFT: Precedence = Precedence(10);
const P_ADDITIVE: Precedence = Precedence(11);
const P_MULTIPLICATIVE: Precedence = Precedence(12);
const P_UNARY: Precedence = Precedence(13);
const P_POSTFIX: Precedence = Precedence(14);

const DEFAULT_WIDTH: usize = 100;

#[must_use]
pub fn render_expr(expr: &CExpr, interner: &Interner, width: usize) -> String {
    render_expr_mode(expr, interner, width, ParenMode::Minimal)
}

#[must_use]
pub fn render_expr_mode(
    expr: &CExpr,
    interner: &Interner,
    width: usize,
    mode: ParenMode,
) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode,
    };
    finish(expr_doc(&ctx, expr), width)
}

#[must_use]
pub fn render_stmt(stmt: &CStmt, interner: &Interner, width: usize) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode: ParenMode::Minimal,
    };
    finish(stmt_doc(&ctx, stmt), width)
}

#[must_use]
pub fn render_declaration(decl: &CDecl, interner: &Interner, width: usize) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode: ParenMode::Minimal,
    };
    finish(decl_doc(&ctx, decl).append(arena.text(";")), width)
}

#[must_use]
pub fn render_type_name(ty: &TypeName, interner: &Interner, width: usize) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode: ParenMode::Minimal,
    };
    finish(type_name_doc(&ctx, ty), width)
}

#[must_use]
pub fn render_item(item: &CItem, interner: &Interner, width: usize) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode: ParenMode::Minimal,
    };
    finish(item_doc(&ctx, item), width)
}

#[must_use]
pub fn render_file(file: &CFile, interner: &Interner, width: usize) -> String {
    let arena: Arena<'_> = Arena::new();
    let ctx: Ctx<'_> = Ctx {
        arena: &arena,
        interner,
        mode: ParenMode::Minimal,
    };
    finish(file_doc(&ctx, file), width)
}

#[must_use]
pub const fn default_width() -> usize {
    DEFAULT_WIDTH
}

fn finish(doc: Doc<'_>, width: usize) -> String {
    let mut out: String = String::new();
    doc.into_doc().render_fmt(width, &mut out).ok();
    out
}

fn ident_text(interner: &Interner, symbol: Symbol) -> Cow<'_, str> {
    interner.resolve(symbol).map_or_else(
        || Cow::Owned(format!("__sym{}", symbol.index())),
        Cow::Borrowed,
    )
}

const fn binary_precedence(op: BinaryOp) -> (Precedence, Assoc) {
    let prec: Precedence = match op {
        BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => P_MULTIPLICATIVE,
        BinaryOp::Add | BinaryOp::Sub => P_ADDITIVE,
        BinaryOp::Shl | BinaryOp::Shr => P_SHIFT,
        BinaryOp::Lt | BinaryOp::Gt | BinaryOp::Le | BinaryOp::Ge => P_RELATIONAL,
        BinaryOp::Eq | BinaryOp::Ne => P_EQUALITY,
        BinaryOp::BitAnd => P_BITAND,
        BinaryOp::BitXor => P_BITXOR,
        BinaryOp::BitOr => P_BITOR,
        BinaryOp::LogAnd => P_LOGAND,
        BinaryOp::LogOr => P_LOGOR,
    };
    (prec, Assoc::Left)
}

const fn expr_precedence(expr: &CExpr) -> Precedence {
    match expr {
        CExpr::Int { .. } | CExpr::Float(_) | CExpr::Char(_) | CExpr::Str(_) | CExpr::Ident(_) => {
            Precedence::ATOM
        }
        CExpr::Unary { .. } | CExpr::Cast { .. } | CExpr::SizeofExpr(_) | CExpr::SizeofType(_) => {
            P_UNARY
        }
        CExpr::Postfix { .. } | CExpr::Call { .. } | CExpr::Index { .. } | CExpr::Member { .. } => {
            P_POSTFIX
        }
        CExpr::Binary { op, .. } => binary_precedence(*op).0,
        CExpr::Assign { .. } => P_ASSIGN,
        CExpr::Ternary { .. } => P_TERNARY,
        CExpr::Comma { .. } => P_COMMA,
    }
}

const fn is_atom(expr: &CExpr) -> bool {
    matches!(
        expr,
        CExpr::Int { .. } | CExpr::Float(_) | CExpr::Char(_) | CExpr::Str(_) | CExpr::Ident(_)
    )
}

const fn needs_parens_operand(
    child: &CExpr,
    parent: Precedence,
    assoc: Assoc,
    side: Side,
    mode: ParenMode,
) -> bool {
    match mode {
        ParenMode::Minimal => parenthesize_operand(expr_precedence(child), parent, assoc, side),
        ParenMode::Full => !is_atom(child),
    }
}

const fn needs_parens_min(child: &CExpr, min: Precedence, mode: ParenMode) -> bool {
    match mode {
        ParenMode::Minimal => expr_precedence(child).0 < min.0,
        ParenMode::Full => !is_atom(child),
    }
}

fn operand_doc<'a>(
    ctx: &Ctx<'a>,
    child: &'a CExpr,
    parent: Precedence,
    assoc: Assoc,
    side: Side,
) -> Doc<'a> {
    let doc: Doc<'a> = expr_doc(ctx, child);
    if needs_parens_operand(child, parent, assoc, side, ctx.mode) {
        doc.parens()
    } else {
        doc
    }
}

fn operand_min_doc<'a>(ctx: &Ctx<'a>, child: &'a CExpr, min: Precedence) -> Doc<'a> {
    let doc: Doc<'a> = expr_doc(ctx, child);
    if needs_parens_min(child, min, ctx.mode) {
        doc.parens()
    } else {
        doc
    }
}

fn expr_doc<'a>(ctx: &Ctx<'a>, expr: &'a CExpr) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match expr {
        CExpr::Int {
            value,
            radix,
            suffix,
        } => arena.text(format_int(*value, *radix, *suffix)),
        CExpr::Float(text) => arena.text(text.as_ref()),
        CExpr::Char(value) => arena.text(char_literal(*value)),
        CExpr::Str(value) => arena.text(string_literal(value)),
        CExpr::Ident(symbol) => arena.text(ident_text(ctx.interner, *symbol)),
        CExpr::Unary { op, operand } => unary_doc(ctx, *op, operand),
        CExpr::Postfix { op, operand } => {
            operand_doc(ctx, operand, P_POSTFIX, Assoc::Left, Side::Left)
                .append(arena.text(postfix_symbol(*op)))
        }
        CExpr::Binary { op, lhs, rhs } => {
            let (prec, assoc): (Precedence, Assoc) = binary_precedence(*op);
            let left: Doc<'a> = operand_doc(ctx, lhs, prec, assoc, Side::Left);
            let right: Doc<'a> = operand_doc(ctx, rhs, prec, assoc, Side::Right);
            left.append(arena.space())
                .append(arena.text(binary_symbol(*op)))
                .append(arena.line())
                .append(right)
                .nest(4)
                .group()
        }
        CExpr::Assign { op, lhs, rhs } => {
            let left: Doc<'a> = operand_doc(ctx, lhs, P_ASSIGN, Assoc::Right, Side::Left);
            let right: Doc<'a> = operand_doc(ctx, rhs, P_ASSIGN, Assoc::Right, Side::Right);
            left.append(arena.space())
                .append(arena.text(assign_symbol(*op)))
                .append(arena.space())
                .append(right)
        }
        CExpr::Ternary { cond, then, els } => {
            let cond_doc: Doc<'a> = operand_doc(ctx, cond, P_TERNARY, Assoc::Right, Side::Left);
            let then_doc: Doc<'a> = operand_min_doc(ctx, then, P_COMMA);
            let else_doc: Doc<'a> = operand_doc(ctx, els, P_TERNARY, Assoc::Right, Side::Right);
            cond_doc
                .append(arena.text(" ? "))
                .append(then_doc)
                .append(arena.text(" : "))
                .append(else_doc)
        }
        CExpr::Comma { lhs, rhs } => {
            let left: Doc<'a> = operand_doc(ctx, lhs, P_COMMA, Assoc::Left, Side::Left);
            let right: Doc<'a> = operand_doc(ctx, rhs, P_COMMA, Assoc::Left, Side::Right);
            left.append(arena.text(","))
                .append(arena.space())
                .append(right)
        }
        CExpr::Call { callee, args } => {
            let head: Doc<'a> = operand_doc(ctx, callee, P_POSTFIX, Assoc::Left, Side::Left);
            let arg_docs = args
                .iter()
                .map(|arg: &'a CExpr| operand_min_doc(ctx, arg, P_ASSIGN));
            let list: Doc<'a> = arena.intersperse(arg_docs, arena.text(", "));
            head.append(list.parens())
        }
        CExpr::Index { base, index } => {
            let head: Doc<'a> = operand_doc(ctx, base, P_POSTFIX, Assoc::Left, Side::Left);
            let idx: Doc<'a> = operand_min_doc(ctx, index, P_COMMA);
            head.append(idx.brackets())
        }
        CExpr::Member { base, arrow, field } => {
            let head: Doc<'a> = operand_doc(ctx, base, P_POSTFIX, Assoc::Left, Side::Left);
            let sep: &str = if *arrow { "->" } else { "." };
            head.append(arena.text(sep))
                .append(arena.text(ident_text(ctx.interner, *field)))
        }
        CExpr::Cast { ty, operand } => {
            let inner: Doc<'a> = operand_doc(ctx, operand, P_UNARY, Assoc::Right, Side::Right);
            type_name_doc(ctx, ty).parens().append(inner)
        }
        CExpr::SizeofExpr(operand) => {
            let inner: Doc<'a> = operand_doc(ctx, operand, P_UNARY, Assoc::Right, Side::Right);
            arena.text("sizeof").append(arena.space()).append(inner)
        }
        CExpr::SizeofType(ty) => arena.text("sizeof").append(type_name_doc(ctx, ty).parens()),
    }
}

fn unary_doc<'a>(ctx: &Ctx<'a>, op: UnaryOp, operand: &'a CExpr) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let symbol: &str = unary_symbol(op);
    let child_parens: bool =
        needs_parens_operand(operand, P_UNARY, Assoc::Right, Side::Right, ctx.mode);
    let inner: Doc<'a> = expr_doc(ctx, operand);
    let inner: Doc<'a> = if child_parens { inner.parens() } else { inner };
    let first: char = if child_parens {
        '('
    } else {
        leading_char(ctx.interner, operand)
    };
    let op_last: Option<char> = symbol.chars().next_back();
    let need_space: bool = matches!(op_last, Some('+' | '-' | '&')) && op_last == Some(first);
    if need_space {
        arena.text(symbol).append(arena.space()).append(inner)
    } else {
        arena.text(symbol).append(inner)
    }
}

fn leading_char(interner: &Interner, expr: &CExpr) -> char {
    match expr {
        CExpr::Int { value, radix, .. } => match radix {
            Radix::Dec => first_char_of(&value.to_string()),
            Radix::Hex | Radix::Oct => '0',
        },
        CExpr::Float(text) => first_char_of(text),
        CExpr::Char(value) => {
            if (*value as u32) > WIDE_CHAR_THRESHOLD {
                'U'
            } else {
                '\''
            }
        }
        CExpr::Str(_) => '"',
        CExpr::Ident(symbol) => first_char_of(&ident_text(interner, *symbol)),
        CExpr::Unary { op, .. } => first_char_of(unary_symbol(*op)),
        CExpr::Postfix { operand, .. }
        | CExpr::Call {
            callee: operand, ..
        }
        | CExpr::Index { base: operand, .. }
        | CExpr::Member { base: operand, .. } => leading_char(interner, operand),
        CExpr::Binary { lhs, .. } | CExpr::Assign { lhs, .. } | CExpr::Comma { lhs, .. } => {
            leading_char(interner, lhs)
        }
        CExpr::Ternary { cond, .. } => leading_char(interner, cond),
        CExpr::Cast { .. } => '(',
        CExpr::SizeofExpr(_) | CExpr::SizeofType(_) => 's',
    }
}

fn first_char_of(text: &str) -> char {
    text.chars().next().unwrap_or('_')
}

fn type_name_doc<'a>(ctx: &Ctx<'a>, ty: &'a TypeName) -> Doc<'a> {
    decl_core_doc(ctx, &ty.base, None, &ty.declarator)
}

fn decl_doc<'a>(ctx: &Ctx<'a>, decl: &'a CDecl) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let core: Doc<'a> = decl_core_doc(ctx, &decl.base, decl.name, &decl.declarator);
    let with_storage: Doc<'a> = match decl.storage {
        Some(storage) => arena
            .text(storage_keyword(storage))
            .append(arena.space())
            .append(core),
        None => core,
    };
    match &decl.init {
        Some(init) => with_storage
            .append(arena.text(" = "))
            .append(init_doc(ctx, init)),
        None => with_storage,
    }
}

fn decl_core_doc<'a>(
    ctx: &Ctx<'a>,
    base: &'a CBaseType,
    name: Option<Symbol>,
    chain: &'a DeclaratorChain,
) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let name_doc: Doc<'a> = name.map_or_else(
        || arena.nil(),
        |symbol: Symbol| arena.text(ident_text(ctx.interner, symbol)),
    );
    let declared: Doc<'a> = declarator_doc(ctx, chain, name_doc);
    let base_doc: Doc<'a> = base_type_doc(ctx, base);
    if matches!(chain, DeclaratorChain::Terminal) && name.is_none() {
        base_doc
    } else {
        base_doc.append(arena.space()).append(declared)
    }
}

fn declarator_doc<'a>(ctx: &Ctx<'a>, chain: &'a DeclaratorChain, acc: Doc<'a>) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match chain {
        DeclaratorChain::Terminal => acc,
        DeclaratorChain::Pointer { quals, to } => {
            let mut head: Doc<'a> = arena.text("*");
            if !quals.is_empty() {
                head = head
                    .append(qualifier_suffix_doc(ctx, *quals))
                    .append(arena.space());
            }
            let inner: Doc<'a> = head.append(acc);
            let wrapped: Doc<'a> = if matches!(
                to.as_ref(),
                DeclaratorChain::Array { .. } | DeclaratorChain::Function { .. }
            ) {
                inner.parens()
            } else {
                inner
            };
            declarator_doc(ctx, to, wrapped)
        }
        DeclaratorChain::Array { of, size } => {
            let bracket: Doc<'a> = size.as_deref().map_or_else(
                || arena.text("[]"),
                |expr: &CExpr| operand_min_doc(ctx, expr, P_ASSIGN).brackets(),
            );
            declarator_doc(ctx, of, acc.append(bracket))
        }
        DeclaratorChain::Function {
            returns,
            params,
            variadic,
        } => {
            let list: Doc<'a> = params_doc(ctx, params, *variadic);
            declarator_doc(ctx, returns, acc.append(list.parens()))
        }
    }
}

fn qualifier_suffix_doc<'a>(ctx: &Ctx<'a>, quals: CQuals) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let mut parts: Vec<&'static str> = Vec::new();
    if quals.is_const {
        parts.push("const");
    }
    if quals.is_volatile {
        parts.push("volatile");
    }
    if quals.is_restrict {
        parts.push("restrict");
    }
    arena.intersperse(
        parts.into_iter().map(|p: &str| arena.text(p)),
        arena.space(),
    )
}

fn params_doc<'a>(ctx: &Ctx<'a>, params: &'a [CParam], variadic: bool) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    if params.is_empty() {
        return if variadic {
            arena.text("...")
        } else {
            arena.text("void")
        };
    }
    let docs = params.iter().map(|param: &'a CParam| param_doc(ctx, param));
    let list: Doc<'a> = arena.intersperse(docs, arena.text(", "));
    if variadic {
        list.append(arena.text(", ..."))
    } else {
        list
    }
}

fn param_doc<'a>(ctx: &Ctx<'a>, param: &'a CParam) -> Doc<'a> {
    decl_core_doc(ctx, &param.base, param.name, &param.declarator)
}

fn base_type_doc<'a>(ctx: &Ctx<'a>, base: &'a CBaseType) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let mut doc: Doc<'a> = arena.nil();
    if base.quals.is_const {
        doc = doc.append(arena.text("const "));
    }
    if base.quals.is_volatile {
        doc = doc.append(arena.text("volatile "));
    }
    doc.append(spec_doc(ctx, &base.spec))
}

fn spec_doc<'a>(ctx: &Ctx<'a>, spec: &'a CTypeSpec) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match spec {
        CTypeSpec::Void => arena.text("void"),
        CTypeSpec::Bool => arena.text("_Bool"),
        CTypeSpec::Char => arena.text("char"),
        CTypeSpec::SignedChar => arena.text("signed char"),
        CTypeSpec::UnsignedChar => arena.text("unsigned char"),
        CTypeSpec::Short => arena.text("short"),
        CTypeSpec::UnsignedShort => arena.text("unsigned short"),
        CTypeSpec::Int => arena.text("int"),
        CTypeSpec::UnsignedInt => arena.text("unsigned int"),
        CTypeSpec::Long => arena.text("long"),
        CTypeSpec::UnsignedLong => arena.text("unsigned long"),
        CTypeSpec::LongLong => arena.text("long long"),
        CTypeSpec::UnsignedLongLong => arena.text("unsigned long long"),
        CTypeSpec::Float => arena.text("float"),
        CTypeSpec::Double => arena.text("double"),
        CTypeSpec::LongDouble => arena.text("long double"),
        CTypeSpec::Named(symbol) => arena.text(ident_text(ctx.interner, *symbol)),
        CTypeSpec::Struct(tag) => tagged_doc(ctx, "struct", *tag),
        CTypeSpec::Union(tag) => tagged_doc(ctx, "union", *tag),
        CTypeSpec::Enum(tag) => tagged_doc(ctx, "enum", *tag),
    }
}

fn tagged_doc<'a>(ctx: &Ctx<'a>, keyword: &'static str, tag: Option<Symbol>) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    tag.map_or_else(
        || arena.text(keyword),
        |symbol: Symbol| {
            arena
                .text(keyword)
                .append(arena.space())
                .append(arena.text(ident_text(ctx.interner, symbol)))
        },
    )
}

fn init_doc<'a>(ctx: &Ctx<'a>, init: &'a CInit) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match init {
        CInit::Expr(expr) => operand_min_doc(ctx, expr, P_ASSIGN),
        CInit::List(items) => {
            let docs = items.iter().map(|item: &'a CInit| init_doc(ctx, item));
            arena
                .intersperse(docs, arena.text(", "))
                .enclose(arena.text("{ "), arena.text(" }"))
        }
    }
}

fn stmt_doc<'a>(ctx: &Ctx<'a>, stmt: &'a CStmt) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match stmt {
        CStmt::Empty => arena.text(";"),
        CStmt::Expr(expr) => expr_doc(ctx, expr).append(arena.text(";")),
        CStmt::Decl(decl) => decl_doc(ctx, decl).append(arena.text(";")),
        CStmt::Block(stmts) => block_doc(ctx, stmts),
        CStmt::If { cond, then, els } => {
            let head: Doc<'a> = arena
                .text("if (")
                .append(expr_doc(ctx, cond))
                .append(arena.text(") "))
                .append(braced_doc(ctx, then));
            match els {
                Some(else_stmt) => head
                    .append(arena.text(" else "))
                    .append(braced_doc(ctx, else_stmt)),
                None => head,
            }
        }
        CStmt::While { cond, body } => arena
            .text("while (")
            .append(expr_doc(ctx, cond))
            .append(arena.text(") "))
            .append(braced_doc(ctx, body)),
        CStmt::DoWhile { body, cond } => arena
            .text("do ")
            .append(braced_doc(ctx, body))
            .append(arena.text(" while ("))
            .append(expr_doc(ctx, cond))
            .append(arena.text(");")),
        CStmt::For {
            init,
            cond,
            step,
            body,
        } => {
            let init_doc: Doc<'a> = init
                .as_deref()
                .map_or_else(|| arena.nil(), |stmt: &CStmt| for_init_doc(ctx, stmt));
            let cond_doc: Doc<'a> = cond
                .as_ref()
                .map_or_else(|| arena.nil(), |expr: &CExpr| expr_doc(ctx, expr));
            let step_doc: Doc<'a> = step
                .as_ref()
                .map_or_else(|| arena.nil(), |expr: &CExpr| expr_doc(ctx, expr));
            arena
                .text("for (")
                .append(init_doc)
                .append(arena.text("; "))
                .append(cond_doc)
                .append(arena.text("; "))
                .append(step_doc)
                .append(arena.text(") "))
                .append(braced_doc(ctx, body))
        }
        CStmt::Switch { value, body } => arena
            .text("switch (")
            .append(expr_doc(ctx, value))
            .append(arena.text(") "))
            .append(braced_doc(ctx, body)),
        CStmt::Case { value, body } => {
            let separator: Doc<'a> = if matches!(body.as_ref(), CStmt::Case { .. }) {
                arena.text(":").append(arena.hardline())
            } else {
                arena.text(": ")
            };
            arena
                .text("case ")
                .append(expr_doc(ctx, value))
                .append(separator)
                .append(stmt_doc(ctx, body))
        }
        CStmt::Default { body } => arena.text("default: ").append(stmt_doc(ctx, body)),
        CStmt::Return(value) => value.as_ref().map_or_else(
            || arena.text("return;"),
            |expr: &CExpr| {
                arena
                    .text("return ")
                    .append(expr_doc(ctx, expr))
                    .append(arena.text(";"))
            },
        ),
        CStmt::Break => arena.text("break;"),
        CStmt::Continue => arena.text("continue;"),
        CStmt::Goto(label) => arena
            .text("goto ")
            .append(arena.text(ident_text(ctx.interner, *label)))
            .append(arena.text(";")),
        CStmt::Label { name, body } => arena
            .text(ident_text(ctx.interner, *name))
            .append(arena.text(": "))
            .append(stmt_doc(ctx, body)),
    }
}

fn for_init_doc<'a>(ctx: &Ctx<'a>, stmt: &'a CStmt) -> Doc<'a> {
    match stmt {
        CStmt::Decl(decl) => decl_doc(ctx, decl),
        CStmt::Expr(expr) => expr_doc(ctx, expr),
        other => stmt_doc(ctx, other),
    }
}

fn braced_doc<'a>(ctx: &Ctx<'a>, stmt: &'a CStmt) -> Doc<'a> {
    match stmt {
        CStmt::Block(stmts) => block_doc(ctx, stmts),
        single => {
            let body: Doc<'a> = stmt_doc(ctx, single);
            wrap_block(ctx.arena, body)
        }
    }
}

fn block_doc<'a>(ctx: &Ctx<'a>, stmts: &'a [CStmt]) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    if stmts.is_empty() {
        return arena.text("{}");
    }
    let docs = stmts.iter().map(|stmt: &'a CStmt| stmt_doc(ctx, stmt));
    let body: Doc<'a> = arena.intersperse(docs, arena.hardline());
    wrap_block(arena, body)
}

fn wrap_block<'a>(arena: &'a Arena<'a>, body: Doc<'a>) -> Doc<'a> {
    arena
        .text("{")
        .append(arena.hardline().append(body).nest(4))
        .append(arena.hardline())
        .append(arena.text("}"))
}

fn item_doc<'a>(ctx: &Ctx<'a>, item: &'a CItem) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match item {
        CItem::Function { decl, body } => {
            let header: Doc<'a> = decl_doc(ctx, decl);
            header.append(arena.space()).append(block_doc(ctx, body))
        }
        CItem::Decl(decl) => decl_doc(ctx, decl).append(arena.text(";")),
        CItem::Typedef(decl) => arena
            .text("typedef ")
            .append(decl_core_doc(ctx, &decl.base, decl.name, &decl.declarator))
            .append(arena.text(";")),
        CItem::Aggregate { kind, tag, fields } => aggregate_doc(ctx, *kind, *tag, fields),
    }
}

fn aggregate_doc<'a>(
    ctx: &Ctx<'a>,
    kind: AggregateKind,
    tag: Option<Symbol>,
    fields: &'a [CField],
) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let keyword: &str = match kind {
        AggregateKind::Struct => "struct",
        AggregateKind::Union => "union",
    };
    let header: Doc<'a> = tag.map_or_else(
        || arena.text(keyword),
        |symbol: Symbol| {
            arena
                .text(keyword)
                .append(arena.space())
                .append(arena.text(ident_text(ctx.interner, symbol)))
        },
    );
    let field_docs = fields.iter().map(|field: &'a CField| field_doc(ctx, field));
    let body: Doc<'a> = arena.intersperse(field_docs, arena.hardline());
    header
        .append(arena.space())
        .append(wrap_block(arena, body))
        .append(arena.text(";"))
}

fn field_doc<'a>(ctx: &Ctx<'a>, field: &'a CField) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let core: Doc<'a> = decl_core_doc(ctx, &field.base, field.name, &field.declarator);
    let with_bits: Doc<'a> = match &field.bitfield {
        Some(width) => core
            .append(arena.text(" : "))
            .append(operand_min_doc(ctx, width, P_ASSIGN)),
        None => core,
    };
    with_bits.append(arena.text(";"))
}

fn file_doc<'a>(ctx: &Ctx<'a>, file: &'a CFile) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    let docs = file.items.iter().map(|item: &'a CItem| item_doc(ctx, item));
    arena.intersperse(docs, arena.hardline().append(arena.hardline()))
}

const fn unary_symbol(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Neg => "-",
        UnaryOp::Pos => "+",
        UnaryOp::Not => "!",
        UnaryOp::BitNot => "~",
        UnaryOp::Deref => "*",
        UnaryOp::AddrOf => "&",
        UnaryOp::PreInc => "++",
        UnaryOp::PreDec => "--",
    }
}

const fn postfix_symbol(op: PostfixOp) -> &'static str {
    match op {
        PostfixOp::PostInc => "++",
        PostfixOp::PostDec => "--",
    }
}

const fn binary_symbol(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Rem => "%",
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Lt => "<",
        BinaryOp::Gt => ">",
        BinaryOp::Le => "<=",
        BinaryOp::Ge => ">=",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitXor => "^",
        BinaryOp::BitOr => "|",
        BinaryOp::LogAnd => "&&",
        BinaryOp::LogOr => "||",
    }
}

const fn assign_symbol(op: AssignOp) -> &'static str {
    match op {
        AssignOp::Assign => "=",
        AssignOp::Add => "+=",
        AssignOp::Sub => "-=",
        AssignOp::Mul => "*=",
        AssignOp::Div => "/=",
        AssignOp::Rem => "%=",
        AssignOp::Shl => "<<=",
        AssignOp::Shr => ">>=",
        AssignOp::And => "&=",
        AssignOp::Xor => "^=",
        AssignOp::Or => "|=",
    }
}

const fn storage_keyword(storage: Storage) -> &'static str {
    match storage {
        Storage::Extern => "extern",
        Storage::Static => "static",
        Storage::Register => "register",
        Storage::Auto => "auto",
        Storage::ThreadLocal => "_Thread_local",
        Storage::Inline => "inline",
    }
}

fn format_int(value: u64, radix: Radix, suffix: IntSuffix) -> String {
    let mut text: String = match radix {
        Radix::Dec => value.to_string(),
        Radix::Hex => format!("0x{value:x}"),
        Radix::Oct => {
            if value == 0 {
                "0".to_owned()
            } else {
                format!("0{value:o}")
            }
        }
    };
    if suffix.unsigned {
        text.push('U');
    }
    match suffix.long {
        LongSuffix::None => {}
        LongSuffix::Long => text.push('L'),
        LongSuffix::LongLong => text.push_str("LL"),
    }
    text
}

const QUESTION: u8 = b'?';
const PRINTABLE_LOW: u8 = 0x20;
const PRINTABLE_HIGH: u8 = 0x7e;
const WIDE_CHAR_THRESHOLD: u32 = 0xff;

const fn simple_escape(byte: u8, delimiter: u8) -> Option<&'static str> {
    match byte {
        b'\\' => Some("\\\\"),
        b'\n' => Some("\\n"),
        b'\t' => Some("\\t"),
        b'\r' => Some("\\r"),
        b'"' if delimiter == b'"' => Some("\\\""),
        b'\'' if delimiter == b'\'' => Some("\\'"),
        _ => None,
    }
}

fn push_octal_escape(out: &mut String, byte: u8) {
    out.push('\\');
    out.push(char::from(b'0' + (byte >> 6)));
    out.push(char::from(b'0' + ((byte >> 3) & 0b111)));
    out.push(char::from(b'0' + (byte & 0b111)));
}

fn push_escaped_byte(out: &mut String, byte: u8, delimiter: u8, next: Option<u8>) {
    if let Some(escape) = simple_escape(byte, delimiter) {
        out.push_str(escape);
        return;
    }
    let starts_trigraph: bool = byte == QUESTION && next == Some(QUESTION);
    if starts_trigraph || !(PRINTABLE_LOW..=PRINTABLE_HIGH).contains(&byte) {
        push_octal_escape(out, byte);
        return;
    }
    out.push(char::from(byte));
}

fn char_literal(value: char) -> String {
    let point: u32 = value as u32;
    if point > WIDE_CHAR_THRESHOLD {
        return format!("U'\\U{point:08X}'");
    }
    let mut out: String = String::with_capacity(6);
    out.push('\'');
    push_escaped_byte(&mut out, point as u8, b'\'', None);
    out.push('\'');
    out
}

fn string_literal(value: &str) -> String {
    let bytes: &[u8] = value.as_bytes();
    let mut out: String = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for (index, byte) in bytes.iter().enumerate() {
        push_escaped_byte(&mut out, *byte, b'"', bytes.get(index + 1).copied());
    }
    out.push('"');
    out
}
