use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{
    Alias, Arguments, AstModule, Comprehension, ConstValue, ExceptHandler, Expr, ExprCtx,
    FormatConversion, MatchCase, Pattern, Stmt, TStrItem, WithItem,
};
use crate::bytecode::opcode::{
    CanonicalOp, CmpOp, OpcodeMap, deref_local_payload, is_deref_local, map_for,
};
use crate::bytecode::version::PyVersion;
use crate::error::{DecompileError, Result};
use crate::frame_tree::{Frame, FrameKind, FrameTree};

pub trait AstBuilder: Send + Sync + core::fmt::Debug {
    fn build_module(
        &self,
        code: &CodeObject,
        frame_tree: &FrameTree,
        version: &PyVersion,
    ) -> Result<AstModule>;
}

#[derive(Debug, Default)]
pub struct DefaultAstBuilder;

impl DefaultAstBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AstBuilder for DefaultAstBuilder {
    fn build_module(
        &self,
        code: &CodeObject,
        frame_tree: &FrameTree,
        version: &PyVersion,
    ) -> Result<AstModule> {
        set_active_version(version);
        set_future_annotations(code.flags);
        let opmap: Box<dyn OpcodeMap> = map_for(version.clone());
        let stream: DecodedStream = decode_stream_with_offsets(code, opmap.as_ref(), version);
        let module_docstring: Option<String> = class_docstring(code, &stream.ops);
        let route_via_sim: bool = matches!(frame_tree.root.kind, FrameKind::Module)
            && (frame_tree.root.children.is_empty()
                || legacy_loop_module_route(version, &frame_tree.root)
                || module_loop_flatten_route(&frame_tree.root));
        let raw_body: Vec<Stmt> = if route_via_sim {
            structure_stmts(code, &stream, 0, stream.ops.len())?
        } else {
            build_frame(code, &frame_tree.root, &stream.ops)?
        };
        let stripped: Vec<Stmt> =
            strip_module_implicit_return(strip_module_docstring_stmt(raw_body, code));
        let body: Vec<Stmt> = prepend_global_decls(
            code,
            &stream.ops,
            thread_module_annotations(postprocess_body(stripped, BodyKind::Module)),
        );
        Ok(AstModule {
            docstring: module_docstring,
            body,
            blank_lines: std::collections::BTreeMap::new(),
        })
    }
}

/// Pre-3.2 (`major < 3 || minor < 2`) `SETUP_LOOP` block frames mis-nest legacy `for`/`while` loops:
/// the cleanup `SETUP_LOOP` opens a `WhileLoop` frame that physically wraps the inner `FOR_ITER`
/// `ForLoop` frame, and `FrameDispatch::Module` flattens the lot. The SIM structurer (`structure_stmts`
/// with `find_loop`) recovers these from `FOR_ITER`/back-edge shape directly with `SETUP_LOOP` and
/// `POP_BLOCK` already lowered to `Nop`, so route the whole legacy module through it. Gated strictly to
/// `minor <= 1` so 3.2-3.14 (the live floor) keep the existing frame path; the 3.0-3.1 overlap
/// (`while_loops2.3.1`) is included because its `SETUP_LOOP` layout matches the 2.x shape.
fn legacy_loop_module_route(version: &PyVersion, root: &Frame) -> bool {
    let is_legacy: bool = version.major() < 3 || version.minor() < 2;
    is_legacy
        && !root.children.is_empty()
        && root.children.iter().all(|c: &Frame| {
            matches!(
                c.kind,
                FrameKind::WhileLoop
                    | FrameKind::ForLoop
                    | FrameKind::AsyncForLoop
                    | FrameKind::Try
            )
        })
}

/// `FrameDispatch::Module` lowers a module body via `build_linear_stmts`, which is a flat stack
/// simulator with no loop/guard recovery: any module-level `for`/`while`/`async for` frame is
/// silently flattened into its first-iteration ops (the back-edge and `FOR_ITER` exit are lost, and
/// an enclosing `if` constant-guard collapses with them). Functions and classes already recurse via
/// `build_children_or_body`, so the gap is module-scope loops only. Route such modules through the
/// SIM structurer (`structure_stmts`), which recovers the loop from `FOR_ITER`/back-edge shape and
/// re-nests the body and guards correctly across every version.
fn module_loop_flatten_route(root: &Frame) -> bool {
    root.children.iter().any(|c: &Frame| {
        matches!(
            c.kind,
            FrameKind::ForLoop | FrameKind::AsyncForLoop | FrameKind::WhileLoop
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Module,
    Function,
    Class,
}

fn postprocess_body(body: Vec<Stmt>, kind: BodyKind) -> Vec<Stmt> {
    let asserts: Vec<Stmt> = body
        .into_iter()
        .map(recover_aug_assign)
        .map(recover_assert_idiom)
        .collect();
    let merged: Vec<Stmt> = merge_annotations(asserts);
    let pruned: Vec<Stmt> = match kind {
        BodyKind::Function => prune_after_first_terminator(merged),
        _ => merged,
    };
    fix_nested_bodies(pruned, kind)
}

fn is_assert_raise(stmts: &[Stmt]) -> bool {
    matches!(
        stmts,
        [Stmt::Raise { exc: Some(exc), cause: None, .. }]
            if matches!(exc, Expr::Name { id, .. } if id == "AssertionError")
    ) || matches!(stmts, [Stmt::Assert { .. }])
}

fn inplace_base_op(op: crate::bytecode::opcode::BinOp) -> Option<crate::bytecode::opcode::BinOp> {
    use crate::bytecode::opcode::BinOp;
    match op {
        BinOp::InplaceAdd => Some(BinOp::Add),
        BinOp::InplaceSub => Some(BinOp::Sub),
        BinOp::InplaceMul => Some(BinOp::Mul),
        BinOp::InplaceMatMul => Some(BinOp::MatMul),
        BinOp::InplaceTrueDiv => Some(BinOp::TrueDiv),
        BinOp::InplaceFloorDiv => Some(BinOp::FloorDiv),
        BinOp::InplaceMod => Some(BinOp::Mod),
        BinOp::InplacePow => Some(BinOp::Pow),
        BinOp::InplaceLshift => Some(BinOp::Lshift),
        BinOp::InplaceRshift => Some(BinOp::Rshift),
        BinOp::InplaceBitAnd => Some(BinOp::BitAnd),
        BinOp::InplaceBitOr => Some(BinOp::BitOr),
        BinOp::InplaceBitXor => Some(BinOp::BitXor),
        BinOp::InplaceOldDivide => Some(BinOp::OldDivide),
        _ => None,
    }
}

fn aug_targets_match(target: &Expr, left: &Expr) -> bool {
    match (target, left) {
        (Expr::Name { id: a, .. }, Expr::Name { id: b, .. }) => a == b,
        (
            Expr::Attribute {
                value: av,
                attr: aa,
                ..
            },
            Expr::Attribute {
                value: bv,
                attr: ba,
                ..
            },
        ) => aa == ba && aug_targets_match(av, bv),
        (
            Expr::Subscript {
                value: av,
                slice: asl,
                ..
            },
            Expr::Subscript {
                value: bv,
                slice: bsl,
                ..
            },
        ) => aug_targets_match(av, bv) && aug_targets_match(asl, bsl),
        (Expr::Constant { value: a, .. }, Expr::Constant { value: b, .. }) => a == b,
        _ => false,
    }
}

fn recover_aug_assign(stmt: Stmt) -> Stmt {
    let Stmt::Assign {
        targets,
        value,
        type_comment,
        line,
    } = stmt
    else {
        return stmt;
    };
    let [target]: &[Expr] = targets.as_slice() else {
        return Stmt::Assign {
            targets,
            value,
            type_comment,
            line,
        };
    };
    if let Expr::BinOp { left, op, right } = &value
        && inplace_base_op(*op).is_some()
        && aug_targets_match(target, left)
    {
        let target_owned: Expr = target.clone();
        let right_owned: Expr = (**right).clone();
        return Stmt::AugAssign {
            target: target_owned,
            op: *op,
            value: right_owned,
            line,
        };
    }
    Stmt::Assign {
        targets,
        value,
        type_comment,
        line,
    }
}

fn recover_assert_idiom(stmt: Stmt) -> Stmt {
    let Stmt::If {
        test,
        body,
        orelse,
        line,
    } = stmt
    else {
        return stmt;
    };
    let body_pass: bool = matches!(body.as_slice(), [Stmt::Pass]) || body.is_empty();
    if body_pass && is_assert_raise(&orelse) {
        return Stmt::Assert {
            test,
            msg: None,
            line,
        };
    }
    Stmt::If {
        test,
        body,
        orelse,
        line,
    }
}

fn fix_nested_bodies(body: Vec<Stmt>, parent_kind: BodyKind) -> Vec<Stmt> {
    let recovered: Vec<Stmt> = body
        .into_iter()
        .map(recover_aug_assign)
        .map(recover_assert_idiom)
        .collect();
    merge_annotations(recovered)
        .into_iter()
        .map(|s: Stmt| recurse_postprocess(s, parent_kind))
        .collect()
}

fn recurse_postprocess(stmt: Stmt, _parent_kind: BodyKind) -> Stmt {
    match stmt {
        Stmt::FunctionDef {
            name,
            type_params,
            args,
            body,
            decorators,
            returns,
            is_async,
            docstring,
            line,
        } => Stmt::FunctionDef {
            name,
            type_params,
            args,
            body: postprocess_body(body, BodyKind::Function),
            decorators,
            returns,
            is_async,
            docstring,
            line,
        },
        Stmt::ClassDef {
            name,
            type_params,
            bases,
            keywords,
            body,
            decorators,
            docstring,
            line,
        } => Stmt::ClassDef {
            name,
            type_params,
            bases,
            keywords,
            body: postprocess_body(body, BodyKind::Class),
            decorators,
            docstring,
            line,
        },
        Stmt::If {
            test,
            body,
            orelse,
            line,
        } => Stmt::If {
            test,
            body: fix_nested_bodies(body, BodyKind::Function),
            orelse: fix_nested_bodies(orelse, BodyKind::Function),
            line,
        },
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            is_async,
            line,
        } => Stmt::For {
            target,
            iter,
            body: fix_nested_bodies(body, BodyKind::Function),
            orelse: fix_nested_bodies(orelse, BodyKind::Function),
            is_async,
            line,
        },
        Stmt::While {
            test,
            body,
            orelse,
            line,
        } => Stmt::While {
            test,
            body: fix_nested_bodies(body, BodyKind::Function),
            orelse: fix_nested_bodies(orelse, BodyKind::Function),
            line,
        },
        Stmt::With {
            items,
            body,
            is_async,
            line,
        } => Stmt::With {
            items,
            body: fix_nested_bodies(body, BodyKind::Function),
            is_async,
            line,
        },
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            line,
        } => Stmt::Try {
            body: fix_nested_bodies(body, BodyKind::Function),
            handlers: handlers.into_iter().map(fix_handler).collect(),
            orelse: fix_nested_bodies(orelse, BodyKind::Function),
            finalbody: fix_nested_bodies(finalbody, BodyKind::Function),
            line,
        },
        Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            line,
        } => Stmt::TryStar {
            body: fix_nested_bodies(body, BodyKind::Function),
            handlers: handlers.into_iter().map(fix_handler).collect(),
            orelse: fix_nested_bodies(orelse, BodyKind::Function),
            finalbody: fix_nested_bodies(finalbody, BodyKind::Function),
            line,
        },
        Stmt::Match {
            subject,
            cases,
            line,
        } => Stmt::Match {
            subject,
            cases: cases
                .into_iter()
                .map(|c: MatchCase| MatchCase {
                    pattern: c.pattern,
                    guard: c.guard,
                    body: fix_nested_bodies(c.body, BodyKind::Function),
                })
                .collect(),
            line,
        },
        other => other,
    }
}

fn fix_handler(h: ExceptHandler) -> ExceptHandler {
    ExceptHandler {
        typ: h.typ,
        name: h.name,
        body: fix_nested_bodies(h.body, BodyKind::Function),
        line: h.line,
    }
}

fn prune_after_first_terminator(body: Vec<Stmt>) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len());
    let mut terminated: bool = false;
    for stmt in body {
        if terminated {
            if matches!(stmt, Stmt::FunctionDef { .. } | Stmt::ClassDef { .. }) {
                out.push(stmt);
            }
            continue;
        }
        let is_term: bool = matches!(
            &stmt,
            Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Continue | Stmt::Break
        );
        out.push(stmt);
        if is_term {
            terminated = true;
        }
    }
    out
}

fn merge_annotations(body: Vec<Stmt>) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len());
    for stmt in body {
        if let Stmt::Assign { targets, value, .. } = &stmt
            && let [
                Expr::Subscript {
                    value: container,
                    slice,
                    ..
                },
            ] = targets.as_slice()
            && let Expr::Name { id: cname, .. } = container.as_ref()
            && cname == "__annotations__"
            && let Expr::Constant {
                value: ConstValue::Str(slot_name),
                ..
            } = slice.as_ref()
        {
            let annotation_expr: Expr = match value {
                Expr::Constant {
                    value: ConstValue::Str(annotation_str),
                    ..
                } if future_annotations_active() => parse_annotation_string(annotation_str),
                other => other.clone(),
            };
            if try_attach_annotation(&mut out, slot_name, &annotation_expr) {
                continue;
            }
            out.push(Stmt::AnnAssign {
                target: Expr::Name {
                    id: slot_name.clone(),
                    ctx: ExprCtx::Store,
                    line: None,
                },
                annotation: annotation_expr,
                value: None,
                simple: true,
                line: None,
            });
            continue;
        }
        if let Stmt::AnnAssign {
            target,
            annotation,
            value: None,
            ..
        } = &stmt
            && let Expr::Name { id: slot_name, .. } = target
            && try_attach_annotation(&mut out, slot_name, annotation)
        {
            continue;
        }
        out.push(stmt);
    }
    out
}

fn try_attach_annotation(out: &mut [Stmt], slot_name: &str, annotation: &Expr) -> bool {
    let Some(last) = out.last_mut() else {
        return false;
    };
    let Stmt::Assign { targets, value, .. } = last else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    if id != slot_name {
        return false;
    }
    let new_target: Expr = Expr::Name {
        id: slot_name.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    };
    let new_value: Expr = std::mem::replace(
        value,
        Expr::Constant {
            value: ConstValue::None,
            line: None,
        },
    );
    *last = Stmt::AnnAssign {
        target: new_target,
        annotation: annotation.clone(),
        value: Some(new_value),
        simple: true,
        line: None,
    };
    true
}

fn parse_annotation_string(s: &str) -> Expr {
    let trimmed: &str = s.trim();
    if let Ok(i) = trimmed.parse::<i128>() {
        return Expr::Constant {
            value: ConstValue::Int(i),
            line: None,
        };
    }
    if trimmed == "None" {
        return Expr::Constant {
            value: ConstValue::None,
            line: None,
        };
    }
    if trimmed == "True" {
        return Expr::Constant {
            value: ConstValue::True,
            line: None,
        };
    }
    if trimmed == "False" {
        return Expr::Constant {
            value: ConstValue::False,
            line: None,
        };
    }
    if is_simple_identifier(trimmed) {
        return Expr::Name {
            id: trimmed.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        };
    }
    if let Some(parsed) = parse_annotation_expr(trimmed) {
        return parsed;
    }
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
    }
}

/// A `PEP 563` stringified annotation (`from __future__ import annotations`) stores the source
/// annotation expression as a plain `str` const. Recovering it as a string literal recompiles to a
/// DOUBLE-stringified const under the same future import, so the annotation grammar subset Python
/// actually emits (`names`, dotted access, `[...]` subscripts, `(...)`/`[...]` groups, `*`/`**`
/// stars, `|` unions, and bare literals) is parsed back into a real `Expr`. Returns `None` for
/// anything outside that subset so the caller keeps the safe string-literal fallback.
fn parse_annotation_expr(s: &str) -> Option<Expr> {
    let tokens: Vec<AnnTok> = tokenize_annotation(s)?;
    let mut parser: AnnParser<'_> = AnnParser {
        toks: &tokens,
        pos: 0,
    };
    let expr: Expr = parser.parse_union()?;
    if parser.pos == tokens.len() {
        Some(expr)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
enum AnnTok {
    Ident(String),
    Int(i128),
    Str(String),
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Dot,
    Pipe,
    Star,
    DoubleStar,
    Ellipsis,
}

fn tokenize_annotation(s: &str) -> Option<Vec<AnnTok>> {
    let mut toks: Vec<AnnTok> = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '[' => {
                toks.push(AnnTok::LBracket);
                i += 1;
            }
            ']' => {
                toks.push(AnnTok::RBracket);
                i += 1;
            }
            '(' => {
                toks.push(AnnTok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(AnnTok::RParen);
                i += 1;
            }
            ',' => {
                toks.push(AnnTok::Comma);
                i += 1;
            }
            '|' => {
                toks.push(AnnTok::Pipe);
                i += 1;
            }
            '.' => {
                if i + 2 < chars.len() && chars[i + 1] == '.' && chars[i + 2] == '.' {
                    toks.push(AnnTok::Ellipsis);
                    i += 3;
                } else {
                    toks.push(AnnTok::Dot);
                    i += 1;
                }
            }
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    toks.push(AnnTok::DoubleStar);
                    i += 2;
                } else {
                    toks.push(AnnTok::Star);
                    i += 1;
                }
            }
            '\'' | '"' => {
                let quote: char = c;
                i += 1;
                let start: usize = i;
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' {
                        return None;
                    }
                    i += 1;
                }
                if i >= chars.len() {
                    return None;
                }
                let lit: String = chars[start..i].iter().collect();
                toks.push(AnnTok::Str(lit));
                i += 1;
            }
            d if d.is_ascii_digit() => {
                let start: usize = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let num: String = chars[start..i].iter().collect();
                toks.push(AnnTok::Int(num.parse::<i128>().ok()?));
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let start: usize = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                toks.push(AnnTok::Ident(chars[start..i].iter().collect()));
            }
            _ => return None,
        }
    }
    Some(toks)
}

struct AnnParser<'a> {
    toks: &'a [AnnTok],
    pos: usize,
}

impl AnnParser<'_> {
    fn peek(&self) -> Option<&AnnTok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&AnnTok> {
        let t: Option<&AnnTok> = self.toks.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_union(&mut self) -> Option<Expr> {
        let mut left: Expr = self.parse_postfix()?;
        while matches!(self.peek(), Some(AnnTok::Pipe)) {
            self.pos += 1;
            let right: Expr = self.parse_postfix()?;
            left = Expr::BinOp {
                left: Box::new(left),
                op: crate::bytecode::opcode::BinOp::BitOr,
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_postfix(&mut self) -> Option<Expr> {
        let mut base: Expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Some(AnnTok::Dot) => {
                    self.pos += 1;
                    let attr: String = match self.bump() {
                        Some(AnnTok::Ident(a)) => a.clone(),
                        _ => return None,
                    };
                    base = Expr::Attribute {
                        value: Box::new(base),
                        attr,
                        ctx: ExprCtx::Load,
                    };
                }
                Some(AnnTok::LBracket) => {
                    self.pos += 1;
                    let slice: Expr = self.parse_subscript_slice()?;
                    if !matches!(self.bump(), Some(AnnTok::RBracket)) {
                        return None;
                    }
                    base = Expr::Subscript {
                        value: Box::new(base),
                        slice: Box::new(slice),
                        ctx: ExprCtx::Load,
                    };
                }
                _ => break,
            }
        }
        Some(base)
    }

    fn parse_subscript_slice(&mut self) -> Option<Expr> {
        let first: Expr = self.parse_union()?;
        if !matches!(self.peek(), Some(AnnTok::Comma)) {
            return Some(first);
        }
        let mut elts: Vec<Expr> = vec![first];
        while matches!(self.peek(), Some(AnnTok::Comma)) {
            self.pos += 1;
            if matches!(self.peek(), Some(AnnTok::RBracket)) {
                break;
            }
            elts.push(self.parse_union()?);
        }
        Some(Expr::Tuple {
            elts,
            ctx: ExprCtx::Load,
        })
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        match self.bump()? {
            AnnTok::Ident(id) => {
                let expr: Expr = match id.as_str() {
                    "None" => Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    },
                    "True" => Expr::Constant {
                        value: ConstValue::True,
                        line: None,
                    },
                    "False" => Expr::Constant {
                        value: ConstValue::False,
                        line: None,
                    },
                    other => Expr::Name {
                        id: other.to_owned(),
                        ctx: ExprCtx::Load,
                        line: None,
                    },
                };
                Some(expr)
            }
            AnnTok::Int(n) => Some(Expr::Constant {
                value: ConstValue::Int(*n),
                line: None,
            }),
            AnnTok::Str(lit) => Some(Expr::Constant {
                value: ConstValue::Str(lit.clone()),
                line: None,
            }),
            AnnTok::Ellipsis => Some(Expr::Constant {
                value: ConstValue::Ellipsis,
                line: None,
            }),
            AnnTok::Star => Some(Expr::Starred {
                value: Box::new(self.parse_postfix()?),
                ctx: ExprCtx::Load,
            }),
            AnnTok::LBracket => {
                let mut elts: Vec<Expr> = Vec::new();
                if !matches!(self.peek(), Some(AnnTok::RBracket)) {
                    elts.push(self.parse_union()?);
                    while matches!(self.peek(), Some(AnnTok::Comma)) {
                        self.pos += 1;
                        if matches!(self.peek(), Some(AnnTok::RBracket)) {
                            break;
                        }
                        elts.push(self.parse_union()?);
                    }
                }
                if !matches!(self.bump(), Some(AnnTok::RBracket)) {
                    return None;
                }
                Some(Expr::List {
                    elts,
                    ctx: ExprCtx::Load,
                })
            }
            AnnTok::LParen => {
                let inner: Expr = self.parse_union()?;
                if !matches!(self.bump(), Some(AnnTok::RParen)) {
                    return None;
                }
                Some(inner)
            }
            _ => None,
        }
    }
}

fn is_simple_identifier(s: &str) -> bool {
    let mut chars: std::str::Chars<'_> = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn is_implicit_none_return(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Return(
            None | Some(Expr::Constant {
                value: ConstValue::None,
                ..
            })
        )
    )
}

fn strip_trailing_implicit_return(body: &mut Vec<Stmt>) {
    while body.last().is_some_and(is_implicit_none_return) {
        body.pop();
    }
    match body.last_mut() {
        Some(Stmt::If {
            body: b, orelse, ..
        }) => {
            if orelse.is_empty() {
                strip_trailing_implicit_return(b);
            } else {
                strip_trailing_implicit_return(orelse);
            }
        }
        Some(
            Stmt::For { body: b, .. } | Stmt::While { body: b, .. } | Stmt::With { body: b, .. },
        ) => strip_trailing_implicit_return(b),
        Some(Stmt::Try {
            body: b,
            orelse,
            finalbody,
            ..
        }) => {
            if !finalbody.is_empty() {
                strip_trailing_implicit_return(finalbody);
            } else if !orelse.is_empty() {
                strip_trailing_implicit_return(orelse);
            } else {
                strip_trailing_implicit_return(b);
            }
        }
        _ => {}
    }
}

fn strip_module_implicit_return(mut body: Vec<Stmt>) -> Vec<Stmt> {
    strip_trailing_implicit_return(&mut body);
    body
}

fn strip_module_docstring_stmt(mut body: Vec<Stmt>, code: &CodeObject) -> Vec<Stmt> {
    if let Some(doc) = extract_docstring(code) {
        if let Some(Stmt::Expr(Expr::Constant {
            value: ConstValue::Str(s),
            ..
        })) = body.first()
            && s == &doc
        {
            body.remove(0);
        }
        body.retain(|s: &Stmt| !is_doc_assign(s, &doc));
    }
    body.retain(|s: &Stmt| !is_conditional_annotations_seed(s));
    body
}

fn is_doc_assign(s: &Stmt, doc: &str) -> bool {
    let Stmt::Assign { targets, value, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    if id != "__doc__" {
        return false;
    }
    matches!(value, Expr::Constant { value: ConstValue::Str(v), .. } if v == doc)
}

fn is_conditional_annotations_seed(s: &Stmt) -> bool {
    let Stmt::Assign { targets, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    id == "__conditional_annotations__"
}

#[derive(Debug, Clone, Copy)]
pub enum FrameDispatch {
    Module,
    FunctionDef,
    ClassDef,
    Try,
    With,
    AsyncWith,
    For,
    AsyncFor,
    While,
    IfChain,
    Match,
    Lambda,
    Comprehension,
    ExceptHandler,
    FinallyClause,
    ExceptGroup,
}

impl FrameDispatch {
    #[must_use]
    pub const fn from_kind(kind: FrameKind) -> Self {
        match kind {
            FrameKind::Module => Self::Module,
            FrameKind::FunctionDef => Self::FunctionDef,
            FrameKind::ClassDef => Self::ClassDef,
            FrameKind::Try => Self::Try,
            FrameKind::With => Self::With,
            FrameKind::AsyncWith => Self::AsyncWith,
            FrameKind::ForLoop => Self::For,
            FrameKind::AsyncForLoop => Self::AsyncFor,
            FrameKind::WhileLoop => Self::While,
            FrameKind::IfChain => Self::IfChain,
            FrameKind::MatchStmt => Self::Match,
            FrameKind::Lambda => Self::Lambda,
            FrameKind::Comprehension => Self::Comprehension,
            FrameKind::ExceptHandler => Self::ExceptHandler,
            FrameKind::FinallyClause => Self::FinallyClause,
            FrameKind::ExceptGroup => Self::ExceptGroup,
        }
    }
}

/// `CO_HAS_DOCSTRING` (3.14+). On a FUNCTION code object the compiler sets this flag exactly when
/// `co_consts[0]` is the real docstring. From 3.14 a function whose first statement is a t-string /
/// f-string with a leading literal interns that literal as `co_consts[0]` WITHOUT setting the flag,
/// so trusting `consts[0]` unconditionally fabricates a spurious leading bare-string statement. The
/// flag is meaningful ONLY for functions: module and class code objects never set it (their
/// docstring is materialized via an explicit `STORE_NAME __doc__` prologue, with `consts[0]` holding
/// the docstring for modules and the qualname for classes), so the gate must be scoped to functions.
const PY_CO_FLAG_HAS_DOCSTRING: i32 = 0x4_000_000;

/// `CO_OPTIMIZED | CO_NEWLOCALS` - set together on function code objects, clear on module/class
/// bodies. Used to scope the [`PY_CO_FLAG_HAS_DOCSTRING`] gate to functions only.
const PY_CO_FLAG_FUNCTION_SCOPE: i32 = 0x0001 | 0x0002;

fn version_uses_docstring_flag() -> bool {
    active_version().is_some_and(|v: PyVersion| {
        let (maj, min): (u8, u8) = (v.major(), v.minor());
        maj > 3 || (maj == 3 && min >= 14)
    })
}

fn extract_docstring(code: &CodeObject) -> Option<String> {
    let is_function: bool = (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) == PY_CO_FLAG_FUNCTION_SCOPE;
    if is_function && version_uses_docstring_flag() && (code.flags & PY_CO_FLAG_HAS_DOCSTRING) == 0
    {
        return None;
    }
    match code.consts.first()? {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn const_str_at(code: &CodeObject, idx: u32) -> Option<String> {
    match code.consts.get(idx as usize)? {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

/// A class (or module) body carries a docstring only when its prologue executes
/// `LOAD_CONST <str>; STORE_NAME __doc__`. The first const is the qualname, never the docstring,
/// so [`extract_docstring`] (which trusts `consts[0]`) is wrong for class bodies.
fn class_docstring(code: &CodeObject, ops: &[CanonicalOp]) -> Option<String> {
    for window in ops.windows(2) {
        if let [CanonicalOp::LoadConst(k), CanonicalOp::StoreName(n)] = window
            && name_at(&code.names, *n, 0, "name").is_ok_and(|s: String| s == "__doc__")
        {
            return const_str_at(code, *k);
        }
    }
    None
}

fn decode_stream(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> Vec<CanonicalOp> {
    let mut out: Vec<CanonicalOp> = Vec::new();
    if version.supports_word_code() {
        decode_wordcode(code, opmap, version, &mut out);
    } else {
        decode_legacy(code, opmap, &mut out);
    }
    out
}

/// Polarity of a 3.9+ fused None-comparison conditional jump. `CPython` lowers `x is None` /
/// `x is not None` tests into `POP_JUMP_IF_NOT_NONE` / `POP_JUMP_IF_NONE` (no `COMPARE_OP`, no
/// `TO_BOOL`). The normalizer collapses both into plain `PopJumpIf{False,True}` so every existing
/// control-flow classifier keeps working unchanged; this side-table records, per op index, that the
/// jump's TEST expression must be reconstructed as `val is None` / `val is not None` so the recovered
/// source recompiles to the bare None-jump (no spurious `TO_BOOL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoneJumpKind {
    /// `POP_JUMP_IF_NONE`: control falls through when the value `is not None`.
    IsNotNone,
    /// `POP_JUMP_IF_NOT_NONE`: control falls through when the value `is None`.
    IsNone,
}

#[derive(Debug, Clone)]
struct DecodedStream {
    ops: Vec<CanonicalOp>,
    offsets: Vec<u32>,
    lines: Vec<Option<u32>>,
    wordcode: bool,
    instr_unit_jumps: bool,
    relative_cond_jumps: bool,
    exception_table: Vec<crate::bytecode::flow::ExceptionTableEntry>,
    pre311_end_finally_idx: std::collections::BTreeSet<usize>,
    pre311_pop_block_idx: std::collections::BTreeSet<usize>,
    pre311_break_loop_idx: std::collections::BTreeSet<usize>,
    setup_loop_end: std::collections::BTreeMap<usize, usize>,
    none_jump_kind: std::collections::BTreeMap<usize, NoneJumpKind>,
    version: PyVersion,
}

impl DecodedStream {
    fn index_for_offset(&self, byte_offset: u32) -> Option<usize> {
        self.offsets.binary_search(&byte_offset).ok()
    }

    /// Map a byte offset to an op index, rounding UP to the first op at or after the offset when the
    /// offset does not land on an exact op boundary. Exception-table range ends (`entry.end()`) fall
    /// between ops (the protected region stops mid-statement before the inline finally/else copy), so
    /// the exact `index_for_offset` lookup fails and the body would over-extend to the handler. The
    /// ceiling maps such an end to the next op - the true start of the inline copy / else region.
    fn index_for_offset_ceil(&self, byte_offset: u32) -> Option<usize> {
        let idx: usize = self.offsets.partition_point(|&o: &u32| o < byte_offset);
        if idx < self.offsets.len() {
            Some(idx)
        } else {
            None
        }
    }

    fn supports_match(&self) -> bool {
        let (maj, min): (u8, u8) = (self.version.major(), self.version.minor());
        maj > 3 || (maj == 3 && min >= 10)
    }

    /// The source line of the op at `idx`, when the line table resolved it. Used to distinguish a
    /// multi-item `with a, b:` (all setups share one line) from a nested `with a:\n with b:` (each
    /// setup on its own line) when both compile to back-to-back context-manager setups.
    fn line_at(&self, idx: usize) -> Option<u32> {
        self.lines.get(idx).copied().flatten()
    }

    fn is_pre_311(&self) -> bool {
        self.version.is_pre_311()
    }
}

fn decode_stream_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> DecodedStream {
    let mut ops: Vec<CanonicalOp> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    let wordcode: bool = version.supports_word_code();
    if wordcode {
        decode_wordcode_with_offsets(code, opmap, version, &mut ops, &mut offsets);
    } else {
        decode_legacy_with_offsets(code, opmap, &mut ops, &mut offsets);
    }
    let instr_unit_jumps: bool =
        version.major() > 3 || (version.major() == 3 && version.minor() >= 10);
    let relative_cond_jumps: bool = !version.is_pre_311();
    let exception_table: Vec<crate::bytecode::flow::ExceptionTableEntry> =
        if version.supports_pep_657_exception_table() && !code.exceptiontable.is_empty() {
            crate::bytecode::flow::parse_exception_table(&code.exceptiontable).unwrap_or_default()
        } else if version.is_pre_311() {
            synthesize_pre_311_exception_table(code, opmap, version)
        } else {
            Vec::new()
        };
    let pre311_end_finally_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(
            code,
            opmap,
            version,
            &offsets,
            &["END_FINALLY", "END_ASYNC_FOR"],
        )
    } else {
        std::collections::BTreeSet::new()
    };
    let pre311_pop_block_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(code, opmap, version, &offsets, &["POP_BLOCK"])
    } else {
        std::collections::BTreeSet::new()
    };
    let pre311_break_loop_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(code, opmap, version, &offsets, &["BREAK_LOOP"])
    } else {
        std::collections::BTreeSet::new()
    };
    let setup_loop_end: std::collections::BTreeMap<usize, usize> =
        if version.major() < 3 || version.minor() < 2 {
            collect_setup_loop_ends(code, opmap, &offsets)
        } else if version.major() == 3 && version.minor() < 8 {
            collect_setup_loop_ends_wordcode(code, opmap, &offsets)
        } else {
            std::collections::BTreeMap::new()
        };
    let lines: Vec<Option<u32>> = decode_lines_for_offsets(code, version, &offsets);
    let none_jump_kind: std::collections::BTreeMap<usize, NoneJumpKind> =
        collect_none_jump_kinds(code, opmap, version, &offsets);
    DecodedStream {
        ops,
        offsets,
        lines,
        wordcode,
        instr_unit_jumps,
        relative_cond_jumps,
        exception_table,
        pre311_end_finally_idx,
        pre311_pop_block_idx,
        pre311_break_loop_idx,
        setup_loop_end,
        none_jump_kind,
        version: version.clone(),
    }
}

/// Resolve the source line for every decoded op (parallel to `offsets`). Used only to discriminate
/// multi-item from nested `with` (see `DecodedStream::line_at`); missing or unparsable line tables
/// yield `None` per op, in which case the structurer falls back to the multi-item shape.
fn decode_lines_for_offsets(
    code: &CodeObject,
    version: &PyVersion,
    offsets: &[u32],
) -> Vec<Option<u32>> {
    let marshal_version: disrobe_py_marshal::PyVersion = disrobe_py_marshal::PyVersion {
        major: version.major(),
        minor: version.minor(),
    };
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    let table_bytes: &[u8] = if maj > 3 || (maj == 3 && min >= 10) {
        &code.linetable
    } else {
        &code.lnotab
    };
    let table: Vec<crate::bytecode::flow::LineTableEntry> =
        crate::bytecode::flow::parse_line_table(table_bytes, marshal_version).unwrap_or_default();
    offsets
        .iter()
        .map(|&off: &u32| crate::bytecode::flow::line_for_offset(&table, off))
        .collect()
}

/// Scan the raw bytecode for the fused None-comparison jumps (3.9+) and record, per decoded op
/// index, whether the jump is the `is None` (`POP_JUMP_IF_NOT_NONE`) or `is not None`
/// (`POP_JUMP_IF_NONE`) form. The canonical op stream collapses both into `PopJumpIf{False,True}`,
/// so this side-table is the only surviving record of the None semantics - consulted purely at
/// test-expression construction sites, never by control-flow classification. Mirrors
/// `collect_pre_311_opcode_indices`'s raw-name walk; applies to every version (pre-3.9 maps stay
/// empty since the opcodes do not exist).
fn collect_none_jump_kinds(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, NoneJumpKind> {
    let classify = |name: &str| -> Option<NoneJumpKind> {
        match name {
            "POP_JUMP_IF_NONE" | "POP_JUMP_FORWARD_IF_NONE" | "POP_JUMP_BACKWARD_IF_NONE" => {
                Some(NoneJumpKind::IsNotNone)
            }
            "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_FORWARD_IF_NOT_NONE"
            | "POP_JUMP_BACKWARD_IF_NOT_NONE" => Some(NoneJumpKind::IsNone),
            _ => None,
        }
    };
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut byte_kind: std::collections::BTreeMap<u32, NoneJumpKind> =
        std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    if wordcode {
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            if is_extended_arg(opmap, raw) {
                cursor += WIDE_STEP;
                continue;
            }
            if let Some(kind) = classify(opmap.opname(raw)) {
                byte_kind.insert(u32::try_from(cursor).unwrap_or(u32::MAX), kind);
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            if let Some(kind) = classify(opmap.opname(raw)) {
                byte_kind.insert(u32::try_from(cursor).unwrap_or(u32::MAX), kind);
            }
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            cursor += 3;
        }
    }
    let mut out: std::collections::BTreeMap<usize, NoneJumpKind> =
        std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(kind) = byte_kind.get(off) {
            out.insert(idx, *kind);
        }
    }
    out
}

/// Build the `is None` / `is not None` test expression for a None-comparison jump at `jump_idx`,
/// given the raw condition value `val` already popped from the sim. Returns `None` when `jump_idx`
/// is an ordinary truthiness jump (caller keeps its existing test). The returned `Compare` encodes
/// the full polarity, so callers must NOT additionally wrap it in `UnaryOp::Not`.
fn none_jump_test(stream: &DecodedStream, jump_idx: usize, val: Expr) -> Option<Expr> {
    let op: CmpOp = match stream.none_jump_kind.get(&jump_idx)? {
        NoneJumpKind::IsNotNone => CmpOp::IsNot,
        NoneJumpKind::IsNone => CmpOp::Is,
    };
    Some(Expr::Compare {
        left: Box::new(val),
        ops: vec![op],
        comparators: vec![Expr::Constant {
            value: ConstValue::None,
            line: None,
        }],
    })
}

fn collect_pre_311_opcode_indices(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    offsets: &[u32],
    names: &[&str],
) -> std::collections::BTreeSet<usize> {
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut byte_set: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut cursor: usize = 0;
    if wordcode {
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            if is_extended_arg(opmap, raw) {
                cursor += WIDE_STEP;
                continue;
            }
            let name: &str = opmap.opname(raw);
            if names.contains(&name) {
                byte_set.insert(u32::try_from(cursor).unwrap_or(u32::MAX));
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            let name: &str = opmap.opname(raw);
            if names.contains(&name) {
                byte_set.insert(u32::try_from(cursor).unwrap_or(u32::MAX));
            }
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            cursor += 3;
        }
    }
    let mut out: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (idx, off) in offsets.iter().enumerate() {
        if byte_set.contains(off) {
            out.insert(idx);
        }
    }
    out
}

/// Map each pre-3.2 `SETUP_LOOP`'s op index to the op index of its loop end (the instruction the block
/// cleanup jumps past). The arg is a forward byte delta from the instruction following `SETUP_LOOP`;
/// `SETUP_LOOP` itself decodes to `Nop`, so this side table is the only surviving record of the loop
/// span. The legacy `for`/`while` structurer uses it to bound a trailing `else:` clause: the region
/// between the loop body's `POP_BLOCK` exit and this end is the loop `orelse`, and code at or beyond
/// the end belongs to the enclosing scope. Only populated for `major < 3 || minor < 2`.
fn collect_setup_loop_ends(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, usize> {
    let bytes: &[u8] = &code.code;
    let mut byte_ends: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        let name: &str = opmap.opname(raw);
        if raw < LEGACY_HAVE_ARGUMENT {
            cursor += NARROW_STEP;
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        if name == "SETUP_LOOP" {
            let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
            let after: u32 = u32::try_from(cursor + 3).unwrap_or(u32::MAX);
            let end_byte: u32 = after.saturating_add(arg);
            byte_ends.insert(u32::try_from(cursor).unwrap_or(u32::MAX), end_byte);
        }
        cursor += 3;
    }
    let mut out: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(end_byte) = byte_ends.get(off) {
            let end_idx: usize = offsets.partition_point(|&o: &u32| o < *end_byte);
            out.insert(idx, end_idx);
        }
    }
    out
}

/// Word-code (3.6-3.7) analogue of `collect_setup_loop_ends`: `SETUP_LOOP` survives in these versions
/// (removed in 3.8) but the stream is 2-byte word-code, so the legacy 3-byte reader misses it. Walk the
/// 2-byte instructions, fold `EXTENDED_ARG`, and for each `SETUP_LOOP` record its loop-end byte (the
/// forward arg delta from the next instruction). Used by `legacy_loop_orelse_end` to bound a break-less
/// `for`/`while` `else:` clause, whose `POP_BLOCK`-exit-to-end span is otherwise indistinguishable from
/// plain post-loop code on 3.6/3.7.
fn collect_setup_loop_ends_wordcode(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, usize> {
    let bytes: &[u8] = &code.code;
    let mut byte_ends: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    let mut extended: u32 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            extended = (extended | u32::from(arg_byte)) << 8;
            cursor += 2;
            continue;
        }
        let arg: u32 = extended | u32::from(arg_byte);
        extended = 0;
        if opmap.opname(raw) == "SETUP_LOOP" {
            let after: u32 = u32::try_from(cursor + 2).unwrap_or(u32::MAX);
            let end_byte: u32 = after.saturating_add(arg);
            byte_ends.insert(u32::try_from(cursor).unwrap_or(u32::MAX), end_byte);
        }
        cursor += 2;
    }
    let mut out: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(end_byte) = byte_ends.get(off) {
            let end_idx: usize = offsets.partition_point(|&o: &u32| o < *end_byte);
            out.insert(idx, end_idx);
        }
    }
    out
}

fn synthesize_pre_311_exception_table(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> Vec<crate::bytecode::flow::ExceptionTableEntry> {
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut entries: Vec<crate::bytecode::flow::ExceptionTableEntry> = Vec::new();
    let mut cursor: usize = 0;
    if wordcode {
        let mut extended: u32 = 0;
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            let arg_byte: u8 = bytes[cursor + 1];
            if is_extended_arg(opmap, raw) {
                extended = (extended | u32::from(arg_byte)) << 8;
                cursor += WIDE_STEP;
                continue;
            }
            let arg: u32 = extended | u32::from(arg_byte);
            extended = 0;
            let name: &str = opmap.opname(raw);
            if matches!(name, "SETUP_FINALLY" | "SETUP_EXCEPT") {
                let after: u32 = u32::try_from(cursor + WIDE_STEP).unwrap_or(u32::MAX);
                let delta_bytes: u32 = if version.major() == 3 && version.minor() >= 10 {
                    arg.saturating_mul(2)
                } else {
                    arg
                };
                let target: u32 = after.saturating_add(delta_bytes);
                let start: u32 = after;
                let length: u32 = target.saturating_sub(start);
                entries.push(crate::bytecode::flow::ExceptionTableEntry {
                    start,
                    length,
                    target,
                    depth: 0,
                    lasti: false,
                });
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
            let name: &str = opmap.opname(raw);
            if matches!(name, "SETUP_FINALLY" | "SETUP_EXCEPT") {
                let after: u32 = u32::try_from(cursor + 3).unwrap_or(u32::MAX);
                let target: u32 = after.saturating_add(arg);
                entries.push(crate::bytecode::flow::ExceptionTableEntry {
                    start: after,
                    length: target.saturating_sub(after),
                    target,
                    depth: 0,
                    lasti: false,
                });
            }
            cursor += 3;
        }
    }
    entries
}

fn decode_wordcode_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    ops: &mut Vec<CanonicalOp>,
    offsets: &mut Vec<u32>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    let mut extended: u32 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            extended = (extended | u32::from(arg_byte)) << 8;
            cursor += WIDE_STEP;
            continue;
        }
        let arg: u32 = extended | u32::from(arg_byte);
        extended = 0;
        let here: u32 = u32::try_from(cursor).unwrap_or(u32::MAX);
        if crate::bytecode::opcode::shared_pushes_self_slot(version, raw, arg) {
            offsets.push(here);
            ops.push(CanonicalOp::Push(0));
        }
        offsets.push(here);
        ops.push(opmap.decode(raw, arg));
        if crate::bytecode::opcode::shared_method_form_load_attr(version, raw, arg) {
            offsets.push(here);
            ops.push(CanonicalOp::Push(0));
        }
        cursor += WIDE_STEP;
        let caches: usize = usize::from(opmap.cache_size(raw));
        if caches > 0 {
            cursor += caches * WIDE_STEP;
        }
    }
}

fn decode_legacy_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    ops: &mut Vec<CanonicalOp>,
    offsets: &mut Vec<u32>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        if raw < LEGACY_HAVE_ARGUMENT {
            offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
            ops.push(opmap.decode(raw, 0));
            cursor += NARROW_STEP;
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
        offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
        ops.push(opmap.decode(raw, arg));
        cursor += 3;
    }
}

const LEGACY_HAVE_ARGUMENT: u8 = 90;
const WIDE_STEP: usize = 2;
const NARROW_STEP: usize = 1;

#[inline]
fn is_extended_arg(opmap: &dyn OpcodeMap, raw: u8) -> bool {
    opmap.opname(raw) == "EXTENDED_ARG"
}

fn decode_wordcode(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    out: &mut Vec<CanonicalOp>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    let mut extended: u32 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            extended = (extended | u32::from(arg_byte)) << 8;
            cursor += WIDE_STEP;
            continue;
        }
        let arg: u32 = extended | u32::from(arg_byte);
        extended = 0;
        if crate::bytecode::opcode::shared_pushes_self_slot(version, raw, arg) {
            out.push(CanonicalOp::Push(0));
        }
        out.push(opmap.decode(raw, arg));
        if crate::bytecode::opcode::shared_method_form_load_attr(version, raw, arg) {
            out.push(CanonicalOp::Push(0));
        }
        cursor += WIDE_STEP;
        let caches: usize = usize::from(opmap.cache_size(raw));
        if caches > 0 {
            cursor += caches * WIDE_STEP;
        }
    }
}

fn decode_legacy(code: &CodeObject, opmap: &dyn OpcodeMap, out: &mut Vec<CanonicalOp>) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        if raw < LEGACY_HAVE_ARGUMENT {
            out.push(opmap.decode(raw, 0));
            cursor += NARROW_STEP;
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
        out.push(opmap.decode(raw, arg));
        cursor += 3;
    }
}

fn build_frame(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    let dispatch: FrameDispatch = FrameDispatch::from_kind(frame.kind);
    match dispatch {
        FrameDispatch::Module => build_linear_stmts(code, ops),
        FrameDispatch::FunctionDef => build_function_def(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Lambda => build_lambda(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::ClassDef => build_class_def(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Try => build_try(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::With => build_with(code, frame, ops, false).map(|s: Stmt| vec![s]),
        FrameDispatch::AsyncWith => build_with(code, frame, ops, true).map(|s: Stmt| vec![s]),
        FrameDispatch::For => build_for(code, frame, ops, false).map(|s: Stmt| vec![s]),
        FrameDispatch::AsyncFor => build_for(code, frame, ops, true).map(|s: Stmt| vec![s]),
        FrameDispatch::While => build_while(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::IfChain => build_if_chain(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Match => build_match(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::ExceptHandler => build_except_handler_body(code, frame, ops),
        FrameDispatch::FinallyClause => build_finally_body(code, frame, ops),
        FrameDispatch::ExceptGroup => build_try(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Comprehension => {
            build_comprehension(code, frame, ops).map(|s: Stmt| vec![s])
        }
    }
}

fn slice_ops<'a>(frame: &Frame, ops: &'a [CanonicalOp]) -> &'a [CanonicalOp] {
    let lo: usize = frame.body_range.start as usize;
    let hi: usize = frame.body_range.end as usize;
    let cap: usize = ops.len();
    let lo: usize = lo.min(cap);
    let hi: usize = hi.min(cap).max(lo);
    &ops[lo..hi]
}

fn build_function_def(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    let body: Vec<Stmt> = prepend_nonlocal_decls(code, ops, body);
    let name: String = code_name(code);
    let is_async: bool = (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    Ok(Stmt::FunctionDef {
        name,
        type_params: Vec::new(),
        args: function_args_from_code(code),
        body,
        decorators: Vec::new(),
        returns: None,
        is_async,
        docstring: extract_docstring(code),
        line: frame.line,
    })
}

fn build_lambda(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_stmts: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let value: Expr = body_stmts
        .into_iter()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let args: Arguments = function_args_from_code(code);
    Ok(Stmt::Expr(Expr::Lambda {
        args: Box::new(args),
        body: Box::new(value),
    }))
}

fn build_class_def(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    let name: String = code_name(code);
    let bases: Vec<Expr> = collect_class_bases(code, ops, frame);
    Ok(Stmt::ClassDef {
        name,
        type_params: Vec::new(),
        bases,
        keywords: Vec::new(),
        body,
        decorators: Vec::new(),
        docstring: class_docstring(code, ops),
        line: frame.line,
    })
}

fn build_try(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let mut handlers: Vec<ExceptHandler> = Vec::with_capacity(frame.handlers.len());
    for child in &frame.children {
        if child.kind == FrameKind::ExceptHandler {
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: build_frame(code, child, ops)?,
                line: child.line,
            });
        }
    }
    let mut finalbody: Vec<Stmt> = Vec::new();
    for child in &frame.children {
        if child.kind == FrameKind::FinallyClause {
            finalbody = build_frame(code, child, ops)?;
            break;
        }
    }
    let is_star: bool = frame
        .children
        .iter()
        .any(|c: &Frame| c.kind == FrameKind::ExceptGroup);
    if is_star {
        Ok(Stmt::TryStar {
            body,
            handlers,
            orelse: Vec::new(),
            finalbody,
            line: frame.line,
        })
    } else {
        Ok(Stmt::Try {
            body,
            handlers,
            orelse: Vec::new(),
            finalbody,
            line: frame.line,
        })
    }
}

fn build_with(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
    is_async: bool,
) -> Result<Stmt> {
    let items: Vec<WithItem> = collect_with_items(code, ops, frame);
    let body: Vec<Stmt> = if frame.children.is_empty() {
        build_legacy_with_body(code, frame, ops)?
    } else {
        build_children_or_body(code, frame, ops)?
    };
    Ok(Stmt::With {
        items,
        body,
        is_async,
        line: frame.line,
    })
}

/// Pre-3.11 with-body builder. The body slice starts at the `StoreFast(target)` and ends with the
/// implicit `__exit__(None, None, None)` cleanup. The `Rot/Swap + LoadConst-None-triple + Call + Pop`
/// idiom returns the body's last value, so when the swap-stash + Call + Pop + Return tail is
/// detected the residual becomes a `Stmt::Return`; otherwise the body is the linear prefix up to
/// the cleanup. Handles both the 3.8/3.10 `LoadConst+Dup+Dup` and 3.11+ `LoadConst x3` triples.
fn build_legacy_with_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let start: usize = usize::from(matches!(
        body_ops.first(),
        Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::Pop)
    ));
    let triple_idx: Option<usize> = legacy_with_exit_triple_start(body_ops, start);
    let Some(triple_idx): Option<usize> = triple_idx else {
        return build_linear_stmts(code, &body_ops[start..]);
    };
    let swap_idx: Option<usize> = (start..triple_idx).rev().find(|&k: &usize| {
        !matches!(
            body_ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    });
    let (body_end, has_return_idiom): (usize, bool) = match swap_idx {
        Some(swap) if matches!(body_ops[swap], CanonicalOp::Swap(2) | CanonicalOp::RotN(2)) => {
            let after_triple: usize = triple_idx + 3;
            (swap, legacy_with_returns_value(body_ops, after_triple))
        }
        _ => (triple_idx, false),
    };
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &body_ops[start..body_end])?;
    let mut out: Vec<Stmt> = stmts;
    if has_return_idiom && let Some(value) = residual.into_iter().next_back() {
        out.push(Stmt::Return(Some(value)));
    }
    Ok(out)
}

/// Index of the first `LoadConst+Dup+Dup` or `LoadConst+LoadConst+LoadConst` triple feeding the
/// implicit `__exit__(None, None, None)` call inside a pre-3.11 with body.
fn legacy_with_exit_triple_start(ops: &[CanonicalOp], from: usize) -> Option<usize> {
    let mut i: usize = from;
    while i + 2 < ops.len() {
        let load: bool = matches!(ops[i], CanonicalOp::LoadConst(_));
        if load {
            let next: bool = matches!(
                ops[i + 1],
                CanonicalOp::LoadConst(_) | CanonicalOp::Dup | CanonicalOp::Copy(_)
            );
            let after: bool = matches!(
                ops[i + 2],
                CanonicalOp::LoadConst(_) | CanonicalOp::Dup | CanonicalOp::Copy(_)
            );
            if next && after {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Whether the ops after the implicit `__exit__` triple are `CallFunction + Pop + Return`, marking
/// the with-body as value-returning (`with X as y: return <expr>` idiom).
fn legacy_with_returns_value(ops: &[CanonicalOp], from: usize) -> bool {
    let mut i: usize = from;
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_) => {
                i += 1;
                break;
            }
            _ => return false,
        }
    }
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Pop => {
                i += 1;
                break;
            }
            _ => return false,
        }
    }
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return true,
            _ => return false,
        }
    }
    false
}

fn build_for(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
    is_async: bool,
) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let (target, iter): (Expr, Expr) = extract_for_header(code, body_ops);
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::For {
        target,
        iter,
        body,
        orelse: Vec::new(),
        is_async,
        line: frame.line,
    })
}

fn build_while(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let test: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::While {
        test,
        body,
        orelse: Vec::new(),
        line: frame.line,
    })
}

fn build_if_chain(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let test: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::If {
        test,
        body,
        orelse: Vec::new(),
        line: frame.line,
    })
}

fn build_match(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let subject: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let mut cases: Vec<MatchCase> = Vec::with_capacity(frame.children.len().max(1));
    for child in &frame.children {
        let case_body: Vec<Stmt> = build_frame(code, child, ops)?;
        cases.push(MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: case_body,
        });
    }
    if cases.is_empty() {
        cases.push(MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: vec![Stmt::Pass],
        });
    }
    Ok(Stmt::Match {
        subject,
        cases,
        line: frame.line,
    })
}

fn build_except_handler_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    if body.is_empty() {
        Ok(vec![Stmt::Pass])
    } else {
        Ok(body)
    }
}

fn build_finally_body(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    if body.is_empty() {
        Ok(vec![Stmt::Pass])
    } else {
        Ok(body)
    }
}

fn build_comprehension(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let elt: Expr = body
        .into_iter()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    Ok(Stmt::Expr(Expr::ListComp {
        elt: Box::new(elt),
        generators: Vec::new(),
    }))
}

fn build_children_or_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    if frame.children.is_empty() {
        return build_linear_stmts(code, slice_ops(frame, ops));
    }
    let mut out: Vec<Stmt> = Vec::new();
    for child in &frame.children {
        match child.kind {
            FrameKind::ExceptHandler | FrameKind::FinallyClause | FrameKind::ExceptGroup => {}
            _ => out.extend(build_frame(code, child, ops)?),
        }
    }
    Ok(out)
}

const PY_CO_FLAG_VARARGS: i32 = 0x0004;
const PY_CO_FLAG_VARKEYWORDS: i32 = 0x0008;
const PY_CO_FLAG_COROUTINE: i32 = 0x0080;
const PY_CO_FLAG_ASYNC_GENERATOR: i32 = 0x0200;

fn code_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        _ => "<anonymous>".to_owned(),
    }
}

fn function_args_from_code(code: &CodeObject) -> Arguments {
    let positional_count: usize = usize::try_from(code.argcount.max(0)).unwrap_or(0);
    let kwonly_count: usize = usize::try_from(code.kwonlyargcount.max(0)).unwrap_or(0);
    let raw_posonly: usize = usize::try_from(code.posonlyargcount.max(0)).unwrap_or(0);
    let posonly_count: usize = raw_posonly.min(positional_count);
    let var_source: &[Object] = if code.varnames.is_empty() {
        &code.localsplusnames
    } else {
        &code.varnames
    };
    let mut all_var_names: Vec<String> = Vec::with_capacity(positional_count + kwonly_count);
    for obj in var_source {
        if let Object::String { value, .. } | Object::ShortAscii { value, .. } = obj {
            all_var_names.push(value.clone());
        } else {
            all_var_names.push(String::new());
        }
    }
    let posonly: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .take(posonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    let args: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .skip(posonly_count)
        .take(positional_count - posonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    let mut cursor: usize = positional_count;
    let kwonly: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .skip(cursor)
        .take(kwonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    cursor += kwonly_count;
    let vararg: Option<Box<crate::ast::node::Arg>> = if (code.flags & PY_CO_FLAG_VARARGS) != 0 {
        let slot: String = all_var_names.get(cursor).cloned().unwrap_or_default();
        cursor += 1;
        Some(Box::new(crate::ast::node::Arg {
            arg: slot,
            annotation: None,
            default: None,
            line: None,
        }))
    } else {
        None
    };
    let kwarg: Option<Box<crate::ast::node::Arg>> = if (code.flags & PY_CO_FLAG_VARKEYWORDS) != 0 {
        let slot: String = all_var_names.get(cursor).cloned().unwrap_or_default();
        Some(Box::new(crate::ast::node::Arg {
            arg: slot,
            annotation: None,
            default: None,
            line: None,
        }))
    } else {
        None
    };
    let kw_defaults: Vec<Option<Expr>> = vec![None; kwonly_count];
    Arguments {
        posonly,
        args,
        vararg,
        kwonly,
        kw_defaults,
        kwarg,
        defaults: Vec::new(),
    }
}

fn collect_class_bases(code: &CodeObject, ops: &[CanonicalOp], frame: &Frame) -> Vec<Expr> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let mut bases: Vec<Expr> = Vec::new();
    for op in body_ops {
        match op {
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(id) = name_at(&code.names, *i, 0, "name")
                    && id != "__build_class__"
                    && id != code_name(code)
                {
                    bases.push(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_) => break,
            _ => {}
        }
    }
    bases
}

fn collect_with_items(code: &CodeObject, ops: &[CanonicalOp], frame: &Frame) -> Vec<WithItem> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let mut items: Vec<WithItem> = Vec::new();
    let mut pending_ctx: Option<Expr> = None;
    for op in body_ops {
        match op {
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) | CanonicalOp::LoadFast(i) => {
                if let Ok(id) = name_at_either(code, *i) {
                    pending_ctx = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::BeforeWith | CanonicalOp::BeforeAsyncWith => {
                if let Some(ctx) = pending_ctx.take() {
                    items.push(WithItem {
                        context_expr: ctx,
                        optional_vars: None,
                    });
                }
            }
            CanonicalOp::StoreFast(i) => {
                if let Ok(id) = local_name_at(code, *i, 0)
                    && let Some(last) = items.last_mut()
                    && last.optional_vars.is_none()
                {
                    last.optional_vars = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                }
            }
            _ => {}
        }
    }
    if items.is_empty()
        && let Some(ctx) = pending_ctx
    {
        items.push(WithItem {
            context_expr: ctx,
            optional_vars: None,
        });
    }
    if items.is_empty() {
        items = legacy_with_items_from_prologue(code, ops, frame);
    }
    items
}

/// Pre-3.11 `SETUP_WITH` is decoded as `Nop` (the opcode-map collapses the block-stack instructions
/// into a single canonical), so `collect_with_items` cannot see the context-expression - it lives
/// in the ops BEFORE `frame.body_range.start`. Walk back from the frame start to recover the
/// `<context_expr>(); SETUP_WITH; STORE_FAST(target)` pattern.
fn legacy_with_items_from_prologue(
    code: &CodeObject,
    ops: &[CanonicalOp],
    frame: &Frame,
) -> Vec<WithItem> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let optional_vars: Option<Expr> = match body_ops.first() {
        Some(CanonicalOp::StoreFast(i)) => {
            local_name_at(code, *i, 0)
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                })
        }
        Some(CanonicalOp::StoreName(i)) => {
            name_at(&code.names, *i, 0, "name")
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                })
        }
        _ => None,
    };
    let prologue_end: usize = (frame.body_range.start as usize).min(ops.len());
    if prologue_end == 0 {
        return Vec::new();
    }
    let mut sim_ops: Vec<CanonicalOp> = ops[..prologue_end].to_vec();
    while let Some(last) = sim_ops.last()
        && matches!(
            last,
            CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    {
        sim_ops.pop();
    }
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &sim_ops).unwrap_or_default();
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    vec![WithItem {
        context_expr,
        optional_vars,
    }]
}

fn extract_for_header(code: &CodeObject, ops: &[CanonicalOp]) -> (Expr, Expr) {
    let mut iter: Option<Expr> = None;
    let mut target: Option<Expr> = None;
    for op in ops {
        match op {
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) | CanonicalOp::LoadFast(i)
                if iter.is_none() =>
            {
                if let Ok(id) = name_at_either(code, *i) {
                    iter = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::StoreFast(i) if target.is_none() => {
                if let Ok(id) = local_name_at(code, *i, 0) {
                    target = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                }
            }
            CanonicalOp::ForIter(_) => break,
            _ => {}
        }
    }
    let target: Expr = target.unwrap_or_else(|| Expr::Name {
        id: "_".to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    });
    let iter: Expr = iter.unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    (target, iter)
}

fn extract_loop_test(code: &CodeObject, ops: &[CanonicalOp]) -> Option<Expr> {
    for op in ops {
        match op {
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) | CanonicalOp::LoadFast(i) => {
                let id: String = name_at_either(code, *i).ok()?;
                return Some(Expr::Name {
                    id,
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::LoadConst(i) => {
                let value: ConstValue = code
                    .consts
                    .get(*i as usize)
                    .map_or(ConstValue::None, object_to_const);
                return Some(Expr::Constant { value, line: None });
            }
            _ => {}
        }
    }
    None
}

fn build_tstr_expr(statics: Expr, interps: Expr) -> Expr {
    let static_strs: Vec<String> = match statics {
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            ..
        } => parts
            .into_iter()
            .map(|c: ConstValue| match c {
                ConstValue::Str(s) => s,
                _ => String::new(),
            })
            .collect(),
        _ => Vec::new(),
    };
    let interp_exprs: Vec<Expr> = match interps {
        Expr::Tuple { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            ..
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant {
                value: c,
                line: None,
            })
            .collect(),
        single => vec![single],
    };
    let mut items: Vec<TStrItem> = Vec::with_capacity(static_strs.len() + interp_exprs.len());
    let mut interp_iter: std::vec::IntoIter<Expr> = interp_exprs.into_iter();
    for (i, part) in static_strs.iter().enumerate() {
        if i > 0
            && let Some(interp) = interp_iter.next()
        {
            items.push(formatted_to_tstr_item(interp));
        }
        if !part.is_empty() {
            items.push(TStrItem::Literal(part.clone()));
        }
    }
    for interp in interp_iter {
        items.push(formatted_to_tstr_item(interp));
    }
    Expr::TStr { items, line: None }
}

fn formatted_to_tstr_item(expr: Expr) -> TStrItem {
    match expr {
        Expr::TStr { mut items, .. } if items.len() == 1 => match items.pop() {
            Some(item @ TStrItem::Interp { .. }) => item,
            Some(TStrItem::Literal(s)) => TStrItem::Interp {
                value: Expr::Constant {
                    value: ConstValue::Str(s),
                    line: None,
                },
                expr_text: None,
                conversion: FormatConversion::None,
                format_spec: None,
            },
            None => unreachable!("len == 1 guarantees a single item"),
        },
        Expr::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => TStrItem::Interp {
            value: *value,
            expr_text: None,
            conversion,
            format_spec: format_spec.map(|b: Box<Expr>| *b),
        },
        other => TStrItem::Interp {
            value: other,
            expr_text: None,
            conversion: FormatConversion::None,
            format_spec: None,
        },
    }
}

fn name_at_either(code: &CodeObject, idx: u32) -> Result<String> {
    if is_deref_local(idx) {
        return local_name_at(code, idx, 0);
    }
    if let Ok(s) = name_at(&code.names, idx, 0, "name") {
        return Ok(s);
    }
    if let Ok(s) = name_at(&code.varnames, idx, 0, "varname") {
        return Ok(s);
    }
    name_at(&code.localsplusnames, idx, 0, "localsplus")
}

#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::similar_names,
    clippy::match_same_arms
)]
fn resolve_jump_target(stream: &DecodedStream, idx: usize, op: &CanonicalOp) -> Option<usize> {
    let here: u32 = *stream.offsets.get(idx)?;
    let step: u32 = if stream.wordcode { 2 } else { 1 };
    let next: u32 = stream.offsets.get(idx + 1).copied().unwrap_or(here + step);
    let jump_unit: u32 = if stream.instr_unit_jumps { 2 } else { 1 };
    let target_byte: u32 = match op {
        CanonicalOp::PopJumpIfFalseRel(a) | CanonicalOp::PopJumpIfTrueRel(a) => {
            next.saturating_add(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalse(a) | CanonicalOp::PopJumpIfTrue(a)
            if stream.relative_cond_jumps =>
        {
            next.saturating_add(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalseBackward(a) | CanonicalOp::PopJumpIfTrueBackward(a) => {
            next.saturating_sub(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalse(a)
        | CanonicalOp::PopJumpIfTrue(a)
        | CanonicalOp::JumpIfTrueOrPop(a)
        | CanonicalOp::JumpIfFalseOrPop(a)
        | CanonicalOp::JumpAbsolute(a) => a.saturating_mul(jump_unit),
        CanonicalOp::Other(121, a) => u32::from(*a).saturating_mul(jump_unit),
        CanonicalOp::JumpForward(rel) => {
            let rel_u: u32 = u32::try_from(*rel).unwrap_or(0).saturating_mul(jump_unit);
            next.saturating_add(rel_u)
        }
        CanonicalOp::ForIter(rel) | CanonicalOp::ForLoopLegacy(rel) | CanonicalOp::Send(rel) => {
            let rel_u: u32 = rel.saturating_mul(jump_unit);
            next.saturating_add(rel_u)
        }
        CanonicalOp::JumpBackward(rel) | CanonicalOp::JumpBackwardNoInterrupt(rel) => {
            let rel_u: u32 = rel.saturating_mul(jump_unit);
            next.saturating_sub(rel_u)
        }
        CanonicalOp::ContinueLoop(a) => a.saturating_mul(jump_unit),
        _ => return None,
    };
    stream
        .index_for_offset(target_byte)
        .or_else(|| resolve_fused_extended_arg_target(stream, target_byte))
}

/// Pre-3.10 `EXTENDED_ARG` is a separate 2-byte instruction that the decoder fuses into the op it
/// prefixes, dropping the prefix byte from `offsets`. A jump whose target lands ON that fused prefix
/// (`SETUP_LOOP` preceded by `EXTENDED_ARG`, so the compiler's jump points at the `EXTENDED_ARG` byte,
/// not the fused op) then fails the exact `index_for_offset` lookup and the cond/loop scan loses the
/// jump entirely. Round the target UP to the first real op at or after the byte - the fused op the
/// prefix belongs to - but only when the rounded op's offset is within one decoded instruction unit of
/// the target (i.e. the gap is genuinely a swallowed `EXTENDED_ARG`, not an arbitrary mid-op address).
/// Gated to pre-3.10 (`!instr_unit_jumps`); 3.10+ keeps `EXTENDED_ARG` as a cache-padded standalone op
/// at its own offset, so the exact lookup always succeeds and this fallback never runs.
fn resolve_fused_extended_arg_target(stream: &DecodedStream, target_byte: u32) -> Option<usize> {
    if stream.instr_unit_jumps {
        return None;
    }
    let idx: usize = stream.index_for_offset_ceil(target_byte)?;
    let op_offset: u32 = *stream.offsets.get(idx)?;
    let step: u32 = if stream.wordcode { 2 } else { 1 };
    if op_offset.saturating_sub(target_byte) <= step {
        Some(idx)
    } else {
        None
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
/// A conditional jump is a value-form short-circuit (boolop machinery, not control flow) when its
/// test is a `COPY 1`'d duplicate of TOS, or it is a `JUMP_IF_*_OR_POP` (pre-3.12 fused form). Such
/// jumps must NOT be treated as `if`-statement boundaries by the region structurer; the value-stack
/// sim folds them into `BoolOp`.
fn is_value_form_shortcircuit(ops: &[CanonicalOp], idx: usize) -> bool {
    match ops[idx] {
        CanonicalOp::JumpIfTrueOrPop(_) | CanonicalOp::JumpIfFalseOrPop(_) => true,
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfFalse(_) => {
            let mut j: usize = idx;
            while j > 0 {
                j -= 1;
                match ops[j] {
                    CanonicalOp::ToBool | CanonicalOp::Cache | CanonicalOp::Nop => {}
                    CanonicalOp::Copy(1) => return true,
                    _ => {
                        return inner_short_circuit_polarity(ops, idx).is_some();
                    }
                }
            }
            inner_short_circuit_polarity(ops, idx).is_some()
        }
        _ => false,
    }
}

fn is_forward_cond_jump(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
    )
}

#[derive(Debug, Clone, Copy)]
enum LoopKind {
    For,
    AsyncFor,
    While,
}

#[derive(Debug, Clone, Copy)]
struct LoopRegion {
    kind: LoopKind,
    header: usize,
    body_start: usize,
    body_end: usize,
    back_edge: usize,
    exit: usize,
    /// `while True:` - the loop is entered unconditionally (its sole back-edge is an unconditional
    /// jump and it carries no bottom cond-test), so the recovered test is the constant `True` and
    /// every in-body forward cond-jump to the loop exit is a `break`.
    infinite: bool,
}

fn is_back_edge(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::JumpAbsolute(_)
    )
}

/// 3.11+ encodes `await x` as `GET_AWAITABLE / LOAD_CONST None / SEND / YIELD_VALUE /
/// JUMP_BACKWARD_NO_INTERRUPT`. The trailing `JUMP_BACKWARD_NO_INTERRUPT` targets the `SEND`
/// instruction (or just before it) and is NOT a user-visible `while` loop. The structurer must
/// skip these or every `await` becomes a spurious `while True: pass`.
fn is_async_send_back_edge(stream: &DecodedStream, jump_idx: usize) -> bool {
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
    else {
        return false;
    };
    if target >= jump_idx {
        return false;
    }
    let scan_lo: usize = target.saturating_sub(2);
    (scan_lo..jump_idx).any(|k: usize| matches!(stream.ops[k], CanonicalOp::Send(_)))
}

/// 3.12+ closes each `await` / async-`for` iteration with a cold `CLEANUP_THROW; JUMP_BACKWARD`
/// pair in the exception-handler region that resumes the `SEND` poll after a thrown value. These
/// back-edges are not user loops; treat any `JUMP_BACKWARD` immediately preceded (modulo cache/nop)
/// by `CLEANUP_THROW` as async throw machinery so it never seeds a spurious `while`.
fn is_async_cleanup_throw_back_edge(stream: &DecodedStream, jump_idx: usize) -> bool {
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return false;
    }
    (0..jump_idx)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::CleanupThrow))
}

fn is_cond_back_edge(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalseBackward(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    )
}

/// Pre-3.11 emits `POP_JUMP_IF_TRUE/POP_JUMP_IF_FALSE` as absolute-target jumps regardless of
/// direction; only the explicit `_BACKWARD` variant (3.11+) is classified by `is_cond_back_edge`.
/// `is_cond_jump_with_backward_target` covers the implicit-backward case so loop detection picks
/// up bottom-test `while` loops on 3.8-3.10.
fn is_cond_jump_with_backward_target(stream: &DecodedStream, idx: usize) -> bool {
    if !matches!(
        stream.ops[idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)
    ) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, idx, &stream.ops[idx]) else {
        return false;
    };
    target < idx
}

#[derive(Debug, Clone)]
struct TryRegion {
    try_start: usize,
    /// First op index past the protected body (start of the inline finally/else copy on 3.11+, or
    /// `POP_BLOCK` boundary pre-3.11). Computed by ceiling-mapping the exception-table range end.
    protected_end: usize,
    try_end: usize,
    handler_start: usize,
    region_end: usize,
    is_with: bool,
    /// The handler runs an unconditional cleanup then re-raises (a `finally:` / pure-finally row) as
    /// opposed to a typed/bare `except`. Drives the pure-finally and combo branch selection.
    is_finally: bool,
}

/// A synthesized pre-3.11 exception row whose protected body begins with `GET_ANEXT` is the
/// `StopAsyncIteration` exhaustion poll-guard of a pre-3.8 `async for`, not a user `try`. `CPython`
/// 3.5-3.7 wraps each `__anext__` poll in a `SETUP_EXCEPT` whose handler does `DUP_TOP / LOAD_GLOBAL
/// StopAsyncIteration / COMPARE_OP(exception match) / POP_JUMP_IF_TRUE` to break the loop - pure
/// loop-termination machinery with no surface `try` syntax. `find_legacy_async_for_loop` recovers
/// that loop directly, so the poll-guard row must be invisible to `find_try_region`; otherwise the
/// guard's `try_start` (the smallest in the window) shadows a genuine enclosing `try`, which then
/// leaks its handler as an unstructured `if … exception matches …` comparison.
fn is_async_for_poll_guard(stream: &DecodedStream, try_start: usize) -> bool {
    let mut probe: usize = try_start;
    while probe < stream.ops.len()
        && matches!(
            stream.ops.get(probe),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        probe += 1;
    }
    matches!(stream.ops.get(probe), Some(CanonicalOp::GetAnext))
}

fn find_try_region(stream: &DecodedStream, lo: usize, hi: usize) -> Option<TryRegion> {
    if stream.exception_table.is_empty() {
        return None;
    }
    let mut best: Option<TryRegion> = None;
    for entry in &stream.exception_table {
        let try_start: usize = stream.index_for_offset(entry.start)?;
        let handler_start: usize = stream.index_for_offset(entry.target)?;
        if !(lo..hi).contains(&try_start) || handler_start >= hi {
            continue;
        }
        if matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::EndAsyncFor)
        ) {
            continue;
        }
        if is_async_for_poll_guard(stream, try_start) {
            continue;
        }
        let is_modern: bool = matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        );
        let is_pre311_handler: bool = !is_modern
            && stream.is_pre_311()
            && is_pre311_except_or_finally_handler(stream, handler_start, hi);
        if !is_modern && !is_pre311_handler {
            continue;
        }
        let is_with: bool = is_modern
            && matches!(
                stream.ops.get(handler_start + 1),
                Some(CanonicalOp::WithExceptStart)
            );
        let setup_start: usize = if is_with {
            let raw: usize = with_setup_start(stream, try_start, lo);
            clamp_with_setup_to_enclosing_except_star(stream, raw, try_start, hi)
        } else {
            try_start
        };
        let protected_end: usize = stream
            .index_for_offset_ceil(entry.end())
            .unwrap_or(handler_start)
            .min(handler_start);
        let try_end: usize = stream
            .index_for_offset(entry.end())
            .unwrap_or(handler_start);
        let region_end: usize = if is_pre311_handler {
            pre311_handler_region_end(stream, handler_start, hi)
        } else {
            handler_join(stream, handler_start, hi)
        };
        let is_finally: bool = !is_with
            && is_pure_finally_handler_shape(
                stream,
                handler_start,
                region_end.min(hi),
                is_pre311_handler,
            );
        let candidate: TryRegion = TryRegion {
            try_start: setup_start,
            protected_end,
            try_end: try_end.min(handler_start),
            handler_start,
            region_end: region_end.min(hi),
            is_with,
            is_finally,
        };
        if best
            .as_ref()
            .is_none_or(|b: &TryRegion| candidate.try_start < b.try_start)
        {
            best = Some(candidate);
        }
    }
    best
}

/// Frame-aware variant of `find_try_region` for the `if <cond>:\n    try: ...` layout where `CPython`
/// lays the inner `try`'s cold handler AFTER the enclosing `if`'s false-branch — so the handler index is
/// PAST the windowed if-body `body_hi` and the standard `find_try_region` (which requires `handler_start
/// < hi`) rejects it. Locates a modern (3.11+) `PUSH_EXC_INFO` try whose protected body opens in
/// `[lo, body_hi)` and whose handler lands in `[body_hi, outer_hi)`, modeling the discontiguous if-body
/// (normal flow + cold handler) the region-recursive structurer cannot otherwise span. Returns `None`
/// when no such straddling try exists; never used for the contiguous case that `find_try_region` serves.
fn find_protected_try_with_outer_handler(
    stream: &DecodedStream,
    lo: usize,
    body_hi: usize,
    outer_hi: usize,
) -> Option<TryRegion> {
    if stream.exception_table.is_empty() {
        return None;
    }
    let mut best: Option<TryRegion> = None;
    for entry in &stream.exception_table {
        let try_start: usize = stream.index_for_offset(entry.start)?;
        let handler_start: usize = stream.index_for_offset(entry.target)?;
        if !(lo..body_hi).contains(&try_start)
            || handler_start < body_hi
            || handler_start >= outer_hi
        {
            continue;
        }
        if !matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        ) {
            continue;
        }
        if matches!(
            stream.ops.get(handler_start + 1),
            Some(CanonicalOp::WithExceptStart)
        ) {
            continue;
        }
        let protected_end: usize = stream
            .index_for_offset_ceil(entry.end())
            .unwrap_or(handler_start)
            .min(handler_start);
        let try_end: usize = stream
            .index_for_offset(entry.end())
            .unwrap_or(handler_start)
            .min(handler_start);
        let region_end: usize = handler_join(stream, handler_start, outer_hi).min(outer_hi);
        let is_finally: bool =
            is_pure_finally_handler_shape(stream, handler_start, region_end, false);
        let candidate: TryRegion = TryRegion {
            try_start,
            protected_end,
            try_end,
            handler_start,
            region_end,
            is_with: false,
            is_finally,
        };
        if best
            .as_ref()
            .is_none_or(|b: &TryRegion| candidate.try_start < b.try_start)
        {
            best = Some(candidate);
        }
    }
    best
}

fn is_pre311_except_or_finally_handler(
    stream: &DecodedStream,
    handler_start: usize,
    hi: usize,
) -> bool {
    if handler_start >= hi {
        return false;
    }
    let mut probe: usize = handler_start;
    while probe < hi
        && matches!(
            stream.ops.get(probe),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        probe += 1;
    }
    if matches!(
        stream.ops.get(probe),
        Some(CanonicalOp::Dup | CanonicalOp::Pop)
    ) {
        return true;
    }
    is_pre311_finally_handler_shape(stream, handler_start, hi)
}

/// When an `async with` is the BODY of a `try` whose handler is a PEP 654 `except*` group, the with's
/// protected body opens at the same offset the enclosing `try` body opens (the context-manager
/// expression is the first statement of the `try`). `with_setup_start` walks the with's `setup_start`
/// back over that context-manager expression, so it can land ONE op before the enclosing `try`'s
/// `try_start` (e.g. on a leading `NOP`/store boundary). `find_try_region` then sees a strictly smaller
/// `try_start` for the with than for the enclosing `except*`, so the with shadows it and the `except*`
/// wrapper is dropped. Clamp the with's `setup_start` so it never precedes the start of an enclosing
/// `except*` `try` whose body the with is: scan the exception table for an entry whose handler is an
/// `except*` dispatch (modern `PUSH_EXC_INFO` reaching a `CHECK_EG_MATCH`) and whose `start` index lies
/// in `(raw_setup_start, with_try_start]` - i.e. the enclosing `try` opens at or after the raw walk-back
/// but at or before the with header. Returns the clamped (larger) `start` so the comparator's
/// earliest-`try_start` selection keeps the `except*` rather than the with. Restricted to `except*`
/// (`CHECK_EG_MATCH`) so plain `try`/`except`/`else`/`finally` + `with` cells are untouched.
fn clamp_with_setup_to_enclosing_except_star(
    stream: &DecodedStream,
    raw_setup_start: usize,
    with_try_start: usize,
    hi: usize,
) -> usize {
    let mut clamped: usize = raw_setup_start;
    for entry in &stream.exception_table {
        let Some(enclosing_start): Option<usize> = stream.index_for_offset(entry.start) else {
            continue;
        };
        if enclosing_start <= raw_setup_start || enclosing_start > with_try_start {
            continue;
        }
        let Some(handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if handler >= hi {
            continue;
        }
        if !matches!(stream.ops.get(handler), Some(CanonicalOp::PushExcInfo)) {
            continue;
        }
        if !handler_is_except_star(stream, handler) {
            continue;
        }
        if enclosing_start > clamped {
            clamped = enclosing_start;
        }
    }
    clamped
}

/// Whether the modern handler at `handler` (a `PUSH_EXC_INFO`) is a PEP 654 `except*` group dispatch -
/// it reaches a `CHECK_EG_MATCH` before the handler chain ends. The `except*` lowering pushes the
/// exception group, then for each arm builds a matcher and runs `CHECK_EG_MATCH`; a plain `except`
/// handler never emits `CHECK_EG_MATCH`, and an async-`with` handler begins `PUSH_EXC_INFO /
/// WITH_EXCEPT_START` (its own `__aexit__` cleanup). Reject the `WITH_EXCEPT_START` shape outright, then
/// scan only this handler's own block - up to the next `PUSH_EXC_INFO` (the start of the SIBLING
/// handler) - so a later sibling `except*`'s `CHECK_EG_MATCH` is not mis-attributed to a with handler
/// that physically precedes it.
fn handler_is_except_star(stream: &DecodedStream, handler: usize) -> bool {
    if first_significant(stream, handler + 1, stream.ops.len())
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))
    {
        return false;
    }
    let block_end: usize = (handler + 1..stream.ops.len())
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
        .unwrap_or(stream.ops.len());
    (handler..block_end).any(|k: usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch))
}

fn pre311_handler_region_end(stream: &DecodedStream, handler_start: usize, hi: usize) -> usize {
    let mut i: usize = handler_start;
    let mut last_end: usize = handler_start;
    let mut last_raise: usize = handler_start;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Reraise(_))
            || stream.pre311_end_finally_idx.contains(&i)
        {
            last_end = i + 1;
        }
        if matches!(stream.ops[i], CanonicalOp::Raise(_)) {
            last_raise = i + 1;
        }
        i += 1;
    }
    if last_end == handler_start {
        last_raise.min(hi)
    } else {
        last_end.min(hi)
    }
}

fn with_setup_start(stream: &DecodedStream, try_start: usize, lo: usize) -> usize {
    let mut i: usize = try_start;
    while i > lo
        && matches!(
            stream.ops.get(i - 1),
            Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::Pop)
        )
    {
        i -= 1;
    }
    if i > lo && matches!(stream.ops.get(i - 1), Some(CanonicalOp::BeforeWith)) {
        let mut j: usize = i - 1;
        while j > lo && !is_value_boundary(&stream.ops[j - 1]) {
            j -= 1;
        }
        return j;
    }
    if let Some(prologue_start) = async_with_prologue_start(stream, try_start, lo) {
        return prologue_start;
    }
    if let Some(prologue_start) = modern_with_prologue_start(stream, i, lo) {
        return prologue_start;
    }
    try_start
}

/// The setup start of an `async with`: the protected body's exception-table `start` sits after the
/// `__aenter__` await (at the trailing `POP_TOP`), so walk backward over the await poll and the
/// `BEFORE_ASYNC_WITH` (3.11-3.13) or `COPY 1; LOAD_SPECIAL` `__aenter__` dance (3.14+) to the index
/// where the context-manager expression begins.
fn async_with_prologue_start(stream: &DecodedStream, try_start: usize, lo: usize) -> Option<usize> {
    let awaitable: usize = (lo..try_start)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))?;
    let before: usize = (lo..awaitable).rev().find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BeforeAsyncWith | CanonicalOp::Copy(1)
        )
    })?;
    match stream.ops.get(before) {
        Some(CanonicalOp::BeforeAsyncWith) => {
            let mut j: usize = before;
            while j > lo && !is_value_boundary(&stream.ops[j - 1]) {
                j -= 1;
            }
            Some(j)
        }
        Some(CanonicalOp::Copy(1))
            if first_significant(stream, before + 1, awaitable)
                .is_some_and(|s: usize| matches!(stream.ops[s], CanonicalOp::LoadSpecial(_))) =>
        {
            let mut j: usize = before;
            while j > lo && !is_value_boundary(&stream.ops[j - 1]) {
                j -= 1;
            }
            Some(j)
        }
        _ => None,
    }
}

fn modern_with_prologue_start(stream: &DecodedStream, store_at: usize, lo: usize) -> Option<usize> {
    let call: usize = (lo..store_at)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !matches!(stream.ops[call], CanonicalOp::CallFunction(0)) {
        return None;
    }
    let enter: usize = (lo..call)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !matches!(stream.ops[enter], CanonicalOp::LoadSpecial(0)) {
        return None;
    }
    let copy: usize = (lo..enter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Copy(1)))?;
    let mut j: usize = copy;
    while j > lo && !is_value_boundary(&stream.ops[j - 1]) {
        j -= 1;
    }
    Some(j)
}

/// Whether an expression is a comprehension (list/set/dict/generator). An `await` wrapping a
/// comprehension is implicit machinery (`CPython` compiles a comprehension containing `await` as an
/// awaited coroutine), never user syntax, so the structurer must not re-emit the outer `await`.
fn is_comprehension_expr(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::ListComp { .. }
            | Expr::SetComp { .. }
            | Expr::DictComp { .. }
            | Expr::GeneratorExp { .. }
    )
}

fn is_value_boundary(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Pop
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::BeforeWith
    )
}

fn handler_join(stream: &DecodedStream, handler_start: usize, hi: usize) -> usize {
    let mut last_reraise: usize = handler_start;
    let mut i: usize = handler_start;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Reraise(_)) {
            last_reraise = i;
        }
        i += 1;
    }
    (last_reraise + 1).min(hi)
}

/// The body end of a PEP 654 `except*` whose protected body is itself an `async with`. The exception
/// table splits the `except*` protection into several short ranges (the `__aenter__` setup, the
/// `__aexit__` normal-exit cleanup, and the with's own handler block) around the with body, which the
/// with's WITH-handler protects separately. `find_try_region` therefore keys the `except*` to the first
/// short range (`__aenter__` setup), whose `entry.end()` lands right after `STORE_FAST tg` -
/// `extend_try_body` then stops at the loop header, truncating the body to `tg = await TaskGroup()` and
/// hoisting the `for`/`match` out as siblings. When a nested `WITH_EXCEPT_START` handler exists inside
/// `[try_start, except_handler)`, extend the `except*` body to the `except*` handler boundary (trimmed of
/// the trailing jump) so the recursive structurer re-enters and recovers the whole `async with` (its
/// body, then the loop/match) in place. Only fires when the truncated end actually precedes a nested with
/// handler, so a plain `except*` body (no with) keeps its `extend_try_body` end untouched.
fn except_star_body_end(stream: &DecodedStream, region: &TryRegion, truncated_end: usize) -> usize {
    let has_nested_with: bool = (region.try_start..region.handler_start)
        .any(|k: usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart));
    if !has_nested_with || truncated_end >= region.handler_start {
        return truncated_end;
    }
    trim_try_body_jump(stream, region.try_start, region.handler_start)
}

/// Index where the inline function epilogue begins inside an `except*` body whose protected region is a
/// nested `async with`. On 3.12+ `CPython` lays the post-`try` epilogue (`if failure is not None:
/// return failure` and the trailing `return {...}`) INLINE between the `async with`'s normal-exit
/// `__aexit__` cleanup and the with's out-of-line `WITH_EXCEPT_START` handler block - i.e. INSIDE the
/// `except*` body span. Source-faithfully that epilogue sits AFTER the whole `try`/`except*`, so the
/// `except*` body must stop at the epilogue and the epilogue must be re-structured as the construct
/// successor. Locate the with-handler `PUSH_EXC_INFO` (just before the nested `WITH_EXCEPT_START`),
/// then the normal-exit `__aexit__` `None`-triple immediately preceding it, and return the index past
/// that cleanup. `None` when there is no nested with-handler, when the post-cleanup flow is NOT a
/// guarded branch (a with-trailing-return idiom, not an epilogue), or when no real statement follows -
/// so plain `except*`-over-`async with` cells keep their existing body end and stay byte-identical.
/// The normal-exit successor of a PEP 654 `except*` group: the statements that run after every arm has
/// been processed and the residual group did NOT need re-raising. `CPython` closes the group dispatch
/// with `CALL_INTRINSIC_2 (prep_reraise_star); COPY 1; POP_JUMP_IF_TRUE reraise; POP_TOP; POP_EXCEPT`,
/// then emits the post-construct fall-through (e.g. `return handled`) inline before the cold
/// `SWAP; POP_EXCEPT; RERAISE` epilogue. The generic gap scan misses this because the tail sits past the
/// handler entry, inside the region, not before it. Locate the `POP_EXCEPT` that follows the reraise
/// guard's fall-through and return `[tail_start, cold_epilogue_start)` so the successor recovers. Returns
/// `None` when the fall-through carries no real statement (3.11 routes the tail past the region instead).
fn except_star_normal_exit_span(
    stream: &DecodedStream,
    region: &TryRegion,
) -> Option<(usize, usize)> {
    let intrinsic: usize = (region.handler_start..region.region_end)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallIntrinsic2(_)))?;
    let guard_jump: usize = (intrinsic + 1..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopJumpIfTrue(_)))?;
    let pop_except: usize = (guard_jump + 1..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopExcept))?;
    let tail_start: usize = first_significant(stream, pop_except + 1, region.region_end)?;
    let cold_start: usize = (tail_start..region.region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Swap(_) | CanonicalOp::Reraise(_)
        )
    })?;
    if tail_start >= cold_start || !slice_has_real_stmt(stream, tail_start, cold_start) {
        return None;
    }
    Some((tail_start, cold_start))
}

fn except_star_nested_with_epilogue_span(
    stream: &DecodedStream,
    region: &TryRegion,
) -> Option<(usize, usize)> {
    let with_except: usize = (region.try_start..region.handler_start)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))?;
    let with_handler_start: usize = (region.try_start..with_except)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))?;
    let cleanup_triple: usize =
        (region.try_start..with_handler_start)
            .rev()
            .find(|&k: &usize| {
                is_none_const_push(&stream.ops[k])
                    && is_exit_none_triple(stream, k, with_handler_start)
            })?;
    let epilogue_start: usize = async_with_cleanup_end(stream, cleanup_triple, with_handler_start)?;
    if !async_with_exit_guarded_by_branch(stream, epilogue_start, with_handler_start) {
        return None;
    }
    let epilogue_end: usize = except_star_epilogue_end(stream, epilogue_start, with_handler_start)?;
    if epilogue_start >= epilogue_end || !slice_has_real_stmt(stream, epilogue_start, epilogue_end)
    {
        return None;
    }
    Some((epilogue_start, epilogue_end))
}

/// The op index one past the last real epilogue statement, before the `async with`'s out-of-line
/// suspension/handler machinery. The inline epilogue ends at its final `RETURN`/`RETURN_CONST`; the ops
/// that follow up to the with-handler `PUSH_EXC_INFO` (`CLEANUP_THROW`, `JUMP_BACKWARD_NO_INTERRUPT`,
/// `END_SEND`, jump-overs) are the with's send-poll tail, never user statements, and must NOT be fed to
/// the structurer (they mis-parse as a spurious `while True` / `await None` loop). Returns the index
/// after the last return; `None` when the span carries no return (not a recognisable epilogue).
fn except_star_epilogue_end(
    stream: &DecodedStream,
    epilogue_start: usize,
    with_handler_start: usize,
) -> Option<usize> {
    (epilogue_start..with_handler_start)
        .rev()
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return | CanonicalOp::ReturnConst(_)
            )
        })
        .map(|last_return: usize| last_return + 1)
}

/// Extend a `try:` protected-body end that `CPython`'s exception table cut short inside an inlined
/// comprehension. A 3.12+ `[... for ...]` in a `try:` body is wrapped by its OWN `LOAD_FAST_AND_CLEAR`
/// cleanup entry, so the user handler's protected range ends at the comp's `BUILD_LIST 0` accumulator
/// rather than past the whole comp — splitting the comp across `protected_end` and corrupting both the
/// recovered body and the phantom `else`. When `protected_end` lands at/inside an inline-comp envelope
/// in `[try_start, handler_start)`, push it to the comp's `end_for` plus the trailing slot-restore noise
/// so the full comp stays in the try body. Idempotent and a no-op when no comp straddles the boundary.
fn extend_protected_end_over_comp(
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
) -> usize {
    let mut end: usize = protected_end.max(try_start);
    while let Some(comp) = detect_inline_comprehension(stream, try_start, handler_start) {
        if comp.clear_idx >= end || comp.end_for <= end {
            break;
        }
        let mut new_end: usize = comp.end_for;
        while new_end < handler_start
            && matches!(
                stream.ops[new_end],
                CanonicalOp::Pop
                    | CanonicalOp::Swap(_)
                    | CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::StoreFast(_)
            )
        {
            new_end += 1;
        }
        if new_end <= end {
            break;
        }
        end = new_end;
    }
    end.min(handler_start)
}

/// Recover an `if <cond>:` whose body is a `try/except` whose cold handler `CPython` lays out PAST the
/// `if`'s false-branch (the discontiguous if-body: normal flow `[guard+1, ft)` plus the cold handler
/// `[handler_start, region_end)`, with the `if`-false-branch `[ft, handler_start)` wedged between). A
/// windowed `structure_try` at the outer level swallows the `if` (linearizing its test) and a windowed
/// if-body excludes the out-of-range handler, so the classic `if action == "list":\n    try: ...` lost
/// both. Locate the straddling try via the exception table (handler past the windowed if-body), build
/// `try`/`except` from its protected body + handler range, and emit
/// `if cond: <try> else: <ft..handler_start>`. Strictly gated: the guard must head the region (no prior
/// branch), the try-body must open strictly inside `[guard+1, ft)`, and the handler must sit at/just
/// past `ft`; returns `None` otherwise so the contiguous cases keep the proven region path untouched.
fn try_structure_guarded_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(guard): Option<usize> = (lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    if (lo..guard).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    }) {
        return Ok(None);
    }
    let Some(false_target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|t: &usize| *t > guard && *t < hi)
    else {
        return Ok(None);
    };
    let Some(region): Option<TryRegion> =
        find_protected_try_with_outer_handler(stream, guard + 1, false_target, hi)
    else {
        return Ok(None);
    };
    if region.is_finally
        || region.try_start <= guard
        || region.try_start >= false_target
        || region.handler_start < false_target
        || first_significant(stream, false_target, region.handler_start).is_none()
    {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
    if !head.is_empty() {
        return Ok(None);
    }
    let Some(raw_test): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    let test: Expr = none_jump_test(stream, guard, raw_test.clone()).unwrap_or(raw_test);
    let test: Expr = if matches!(
        stream.ops[guard],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    ) {
        test
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    };
    let body_end: usize = extend_protected_end_over_comp(
        stream,
        region.try_start,
        region.protected_end,
        false_target,
    );
    let try_body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, region.region_end)?;
    let try_stmt: Stmt = Stmt::Try {
        body: non_empty(try_body),
        handlers,
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let mut if_body: Vec<Stmt> = vec![try_stmt];
    if_body.extend(structure_stmts(code, stream, body_end, false_target)?);
    let orelse_end: usize = trim_trailing_comp_cleanup(stream, false_target, region.handler_start);
    let orelse: Vec<Stmt> = structure_stmts(code, stream, false_target, orelse_end)?;
    let mut out: Vec<Stmt> = vec![Stmt::If {
        test,
        body: non_empty(if_body),
        orelse,
        line: None,
    }];
    out.extend(structure_stmts(code, stream, region.region_end, hi)?);
    Ok(Some(out))
}

/// True when a `try` `region` sits wholly inside a LEADING `if`/`while` guard whose body window the
/// region-windowed `find_try_region` would otherwise structure try-first, swallowing the `if`. The guard
/// heads `[lo, hi)` (no prior statement branch) and its false target lands at or past the try's
/// `region_end`, so the entire try (body + handler) is the `if`-true-body and the `if`-false-branch
/// follows. This is the contiguous 3.11 layout (the inner listcomp is a separate code object, so the
/// handler stays in the if-body window) — distinct from the discontiguous 3.12 case handled by
/// `try_structure_guarded_try`. Defer to the if-structurer, which windows the if-body and recovers the
/// try in place. Gated to a modern (`PUSH_EXC_INFO`) non-`with` region so `with`/finally are untouched.
fn try_enclosed_by_leading_guard(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> bool {
    if region.is_with || region.is_finally {
        return false;
    }
    let _ = hi;
    let Some(guard): Option<usize> = (lo..region.try_start).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return false;
    };
    if (lo..guard).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    }) {
        return false;
    }
    resolve_jump_target(stream, guard, &stream.ops[guard])
        .is_some_and(|t: usize| t >= region.region_end && t > region.handler_start)
}

fn structure_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Vec<Stmt>> {
    let head: Vec<Stmt> = structure_stmts(code, stream, lo, region.try_start)?;
    let (stmt, consumed_end, gap_succ): (Stmt, usize, Vec<Stmt>) = if region.is_with {
        let (with_stmt, with_tail): (Stmt, Vec<Stmt>) = structure_with(code, stream, region)?;
        (with_stmt, region.region_end, with_tail)
    } else {
        let extended_end: usize =
            extend_try_body(code, stream, region.try_end, region.handler_start);
        let body_real_end: usize = trim_try_body_jump(stream, region.try_start, extended_end);
        let is_star: bool = (region.handler_start..region.region_end)
            .any(|k: usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch));
        if region.is_finally && !is_star {
            let (stmt, tail): (Stmt, Vec<Stmt>) =
                structure_pure_finally(code, stream, region, body_real_end)?;
            (stmt, region.region_end, tail)
        } else if is_star {
            let star_body_end: usize = except_star_body_end(stream, region, body_real_end);
            let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, star_body_end)?;
            let handlers: Vec<ExceptHandler> =
                parse_except_star_handlers(code, stream, region.handler_start, region.region_end)?;
            let inline_epilogue: Option<(usize, usize)> =
                except_star_nested_with_epilogue_span(stream, region)
                    .or_else(|| except_star_normal_exit_span(stream, region));
            let (succ_scan_start, succ_end): (usize, usize) =
                if let Some((start, end)) = inline_epilogue {
                    (start, end)
                } else {
                    let scan_start: usize = extended_end.max(star_body_end);
                    (
                        scan_start,
                        trim_try_body_jump(stream, scan_start, region.handler_start),
                    )
                };
            let succ: Vec<Stmt> = if succ_scan_start < succ_end
                && slice_has_real_stmt(stream, succ_scan_start, succ_end)
            {
                structure_stmts(code, stream, succ_scan_start, succ_end)?
            } else {
                Vec::new()
            };
            (
                Stmt::TryStar {
                    body: non_empty(body),
                    handlers,
                    orelse: Vec::new(),
                    finalbody: Vec::new(),
                    line: None,
                },
                region.region_end,
                succ,
            )
        } else {
            let (stmt, consumed_end, construct_tail): (Stmt, usize, Vec<Stmt>) =
                structure_try_except_family(code, stream, region, body_real_end, hi)?;
            (stmt, consumed_end, construct_tail)
        }
    };
    let mut out: Vec<Stmt> = head;
    out.push(stmt);
    out.extend(gap_succ);
    if consumed_end < hi {
        out.extend(structure_stmts(code, stream, consumed_end, hi)?);
    }
    Ok(out)
}

/// True when `[lo, hi)` contains at least one op that materializes a real statement - i.e. not pure
/// control-flow scaffolding (jumps/NOP/cache) that `trim_try_body_jump` would otherwise leave behind.
/// Used to gate the except*-group normal-exit successor recovery: 3.12+ places `return counts` inline
/// in the gap between the try body and the handler entry, while 3.11 routes it past the region (the
/// gap is then pure `JUMP_FORWARD`, which this rejects so no successor is double-emitted).
fn slice_has_real_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Nop
                | CanonicalOp::Cache
                | CanonicalOp::ExtendedArg(_)
        )
    })
}

/// A wrapping `finally:` of a `try/except/...` combo: a pure-finally exception row that protects the
/// whole try+except span. `finally_body_start/end` bound the cold finally body; `inline_copy_len` is
/// the per-exit inline copy length (op count) of that body emitted on each normal exit;
/// `except_region_end` is where the except handlers stop (before the cold finally handler);
/// `region_end` is the op index past the entire construct.
#[derive(Debug, Clone)]
struct ComboFinally {
    finally_body_start: usize,
    finally_body_end: usize,
    inline_copy_len: usize,
    except_region_end: usize,
    region_end: usize,
}

/// Detect a wrapping `finally:` for a `try/except` whose primary handler is at `region.handler_start`.
/// On 3.11+ the compiler emits a SECOND, pure-finally exception row whose handler sits AFTER the
/// except handler(s) and protects the entire try+except. Its handler is finally-shaped
/// (`is_pure_finally_handler_shape`), it begins past the except's region, and the finally body is
/// copied inline on each normal exit. Returns `None` (no combo) on pre-3.11 (handled by the legacy
/// path) and when no such row exists.
fn find_combo_finally(
    stream: &DecodedStream,
    region: &TryRegion,
    hi: usize,
) -> Option<ComboFinally> {
    if stream.is_pre_311() || region.is_with {
        return None;
    }
    let mut best_handler: Option<usize> = None;
    for entry in &stream.exception_table {
        let handler_start: usize = match stream.index_for_offset(entry.target) {
            Some(h) => h,
            None => continue,
        };
        if handler_start <= region.handler_start || handler_start >= hi {
            continue;
        }
        if !matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        ) {
            continue;
        }
        let cold_region_end: usize = handler_join(stream, handler_start, hi);
        if !is_pure_finally_handler_shape(stream, handler_start, cold_region_end, false) {
            continue;
        }
        best_handler =
            Some(best_handler.map_or(handler_start, |prev: usize| prev.min(handler_start)));
    }
    let handler_start: usize = best_handler?;
    let cold_region_end: usize = handler_join(stream, handler_start, hi);
    let fin_start: usize = handler_body_first(stream, handler_start);
    let fin_end: usize = finally_body_end(stream, fin_start, cold_region_end);
    let inline_copy_len: usize = fin_end.saturating_sub(fin_start);
    if inline_copy_len == 0 {
        return None;
    }
    let except_region_end: usize =
        combo_except_region_end(stream, region.handler_start, handler_start);
    Some(ComboFinally {
        finally_body_start: fin_start,
        finally_body_end: fin_end,
        inline_copy_len,
        except_region_end,
        region_end: cold_region_end.min(hi),
    })
}

/// The op index where the except handlers stop, given the first except handler and the cold-finally
/// handler that follows. The except handlers occupy `[except_handler, finally_handler)` minus the
/// trailing inline finally copy + exit; the cold finally handler itself plus its `COPY/POP_EXCEPT`
/// epilogue sit beyond. Bound the except region just before the cold finally handler.
fn combo_except_region_end(
    stream: &DecodedStream,
    except_handler: usize,
    finally_handler: usize,
) -> usize {
    let _ = except_handler;
    let mut end: usize = finally_handler;
    while end > 0
        && matches!(
            stream.ops.get(end - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        end -= 1;
    }
    end
}

/// End of a 3.11+ bare `except:` body. The body runs to the cleanup epilogue (`COPY 3; POP_EXCEPT;
/// RERAISE`) that closes every handler, or to a lone `POP_EXCEPT` on the swallow path; a trailing
/// `RAISE_VARARGS` (explicit `raise`) precedes that epilogue and stays in the body.
fn bare_except_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = lo;
    while end < hi {
        match stream.ops[end] {
            CanonicalOp::Copy(_) | CanonicalOp::PopExcept => break,
            _ => end += 1,
        }
    }
    let mut trimmed: usize = end;
    while trimmed > lo
        && matches!(
            stream.ops.get(trimmed - 1),
            Some(
                CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
            )
        )
    {
        trimmed -= 1;
    }
    trimmed
}

/// The fall-through region between the protected body's end and the first except handler - the `else:`
/// region of a `try/except/else` (pycdc `tryElseJoin` / `tryElseReturnEnd`), or the inline finally
/// copy of a `try/except/finally` (combo). Returns `Some((start, end))` when such a region exists and
/// is entered by direct fall-through (its first op is a real statement, not a jump/NOP/return), else
/// `None`. Only fires 3.11+; pre-3.11 else is handled by the legacy else-join path.
fn try_else_split(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    except_region_end: usize,
) -> Option<(usize, usize)> {
    let _ = except_region_end;
    if stream.is_pre_311() {
        return None;
    }
    let else_start: usize = protected_end;
    let else_end: usize = trim_trailing_comp_cleanup(stream, else_start, region.handler_start);
    if else_start >= else_end {
        return None;
    }
    let first_idx: usize = (else_start..else_end)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !else_entry_is_fallthrough(&stream.ops[first_idx]) {
        return None;
    }
    Some((else_start, else_end))
}

/// Trim the dead inline-comp reraise-cleanup tail (`SWAP; POP; SWAP; STORE_FAST <clear-slot>; RERAISE`)
/// that a 3.12+ comprehension inside a `try:` body leaves in the `[protected_end, handler_start)` span
/// after the try-body's protected end was extended over the comp. This cleanup re-installs the cleared
/// loop variable on the comp's own exception path and is never user source, so it must not materialize as
/// a phantom `<slot> = None; raise` at the end of the recovered `else`/tail. Cut the region back to the
/// last op before a trailing `RERAISE` reached only through that swap/store cleanup; a no-op when the
/// region does not end in such a cleanup.
fn trim_trailing_comp_cleanup(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let last: usize = match (lo..hi)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    {
        Some(k) => k,
        None => return hi,
    };
    if !matches!(stream.ops[last], CanonicalOp::Reraise(_)) {
        return hi;
    }
    let mut k: usize = last;
    while k > lo {
        match stream.ops[k - 1] {
            CanonicalOp::Swap(_)
            | CanonicalOp::Pop
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::Copy(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::Reraise(_) => k -= 1,
            _ => break,
        }
    }
    k
}

/// The else region must be entered by direct fall-through: its first op is a real statement, not a
/// jump over the region, a NOP, a return, or a re-raise (pycdc `tryElseJoin` fall-through gate). A
/// lone `RETURN`/`RETURN_CONST` is the try body's own `return EXPR` exit (value computed inside the
/// protected range, returned just past it), never an `else:`.
fn else_entry_is_fallthrough(op: &CanonicalOp) -> bool {
    !matches!(
        op,
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::Reraise(_)
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::Raise(_)
    )
}

/// Drop the inline finally copy from each except handler body. In a `try/except/finally` combo, every
/// except handler runs the finally inline before exiting; that copy is the same source as `finalbody`
/// and must not be re-emitted inside the handler. `CPython` places the copy at the tail when the handler
/// falls through (finally then exit jump) and at the head-of-exit when the handler returns
/// (`POP_EXCEPT` before the inline finally, then `return`) - so strip both a trailing and a leading
/// occurrence.
fn trim_inline_finally_from_handlers(
    handlers: Vec<ExceptHandler>,
    finalbody: &[Stmt],
) -> Vec<ExceptHandler> {
    if finalbody.is_empty() {
        return handlers;
    }
    handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            strip_trailing_stmts(&mut h.body, finalbody);
            strip_leading_stmts(&mut h.body, finalbody);
            if h.body.is_empty() {
                h.body = vec![Stmt::Pass];
            }
            h
        })
        .collect()
}

/// Remove a trailing run of `suffix` statements from `body` (used to strip the inline finally copy
/// duplicated at the tail of an except handler). Matches structurally via the AST `Debug` shape.
fn strip_trailing_stmts(body: &mut Vec<Stmt>, suffix: &[Stmt]) {
    if suffix.is_empty() || body.len() < suffix.len() {
        return;
    }
    let split: usize = body.len() - suffix.len();
    let tail_matches: bool = body[split..]
        .iter()
        .zip(suffix.iter())
        .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
    if tail_matches {
        body.truncate(split);
    }
}

/// Remove a leading run of `prefix` statements from `body` (used to strip the inline finally copy
/// that precedes the construct exit on the normal path of a combo `try/except/finally` with no
/// `else:`). Matches structurally via the AST `Debug` shape.
fn strip_leading_stmts(body: &mut Vec<Stmt>, prefix: &[Stmt]) {
    if prefix.is_empty() || body.len() < prefix.len() {
        return;
    }
    let head_matches: bool = body[..prefix.len()]
        .iter()
        .zip(prefix.iter())
        .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
    if head_matches {
        body.drain(..prefix.len());
    }
}

/// Structure a `try/except[/else][/finally]` family region into a single `Stmt::Try`. Detects an
/// `else:` clause (a fall-through region between the protected body and the handler - pycdc
/// `tryElseJoin` / `tryElseReturnEnd`, 3.11+) and a wrapping `finally:` (a pure-finally exception
/// row protecting the whole try+except, whose body is duplicated inline on every normal exit and
/// must be trimmed from the body / handlers / else - pycdc combo `BLK_FINALLY`). Returns the statement
/// and the op index past everything consumed.
/// On 3.11+ a `return X` that follows a `try/except` (no `else` in source) is INLINED by `CPython` onto
/// every exit path: once at the try body's normal exit (the `[protected_end, handler_start)` gap) and
/// once at each handler's `POP_EXCEPT`-then-return tail. The gap copy then masquerades as an `else:`. When
/// the gap is exactly that single `return` and every handler ends with the identical statement, it is the
/// shared construct-exit tail, not an `else` - return it so the caller emits it once after the `try` and
/// strips the per-handler copies. Returns `None` (genuine `else`) when the handlers don't all share it.
fn shared_construct_exit_return(raw: &[Stmt], handlers: &[ExceptHandler]) -> Option<Vec<Stmt>> {
    let [exit @ Stmt::Return(_)]: &[Stmt] = raw else {
        return None;
    };
    if handlers.is_empty() {
        return None;
    }
    let exit_repr: String = format!("{exit:?}");
    let all_share: bool = handlers.iter().all(|h: &ExceptHandler| {
        h.body
            .last()
            .is_some_and(|s: &Stmt| format!("{s:?}") == exit_repr)
    });
    all_share.then(|| vec![exit.clone()])
}

/// Drop the trailing shared construct-exit `return` (recovered by `shared_construct_exit_return` and
/// re-emitted once after the `try`) from each except handler body so it is not duplicated inside the
/// handlers. A handler that becomes empty falls back to a single `pass`.
fn strip_shared_exit_return(
    handlers: Vec<ExceptHandler>,
    construct_tail: &[Stmt],
) -> Vec<ExceptHandler> {
    let [tail]: &[Stmt] = construct_tail else {
        return handlers;
    };
    let tail_repr: String = format!("{tail:?}");
    handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            if h.body
                .last()
                .is_some_and(|s: &Stmt| format!("{s:?}") == tail_repr)
            {
                h.body.pop();
                h.body = non_empty(h.body);
            }
            h
        })
        .collect()
}

fn structure_try_except_family(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    extended_body_end: usize,
    hi: usize,
) -> Result<(Stmt, usize, Vec<Stmt>)> {
    let combo: Option<ComboFinally> = find_combo_finally(stream, region, hi);
    let except_region_end: usize = combo
        .as_ref()
        .map_or(region.region_end, |c: &ComboFinally| c.except_region_end);

    let finalbody: Vec<Stmt> = match &combo {
        Some(c) => {
            let fin_body: Vec<Stmt> =
                structure_stmts(code, stream, c.finally_body_start, c.finally_body_end)?;
            non_empty(fin_body)
        }
        None => Vec::new(),
    };

    let inline_copy_len: usize = combo
        .as_ref()
        .map_or(0, |c: &ComboFinally| c.inline_copy_len);
    let has_combo: bool = combo.is_some();
    let protected_end: usize = extend_protected_end_over_comp(
        stream,
        region.try_start,
        region.protected_end,
        region.handler_start,
    );

    if stream.is_pre_311() && !has_combo {
        let (stmt, consumed): (Stmt, usize) =
            structure_pre311_try_except(code, stream, region, extended_body_end, hi)?;
        return Ok((stmt, consumed, Vec::new()));
    }

    let normal_region: Option<(usize, usize)> =
        try_else_split(stream, region, protected_end, except_region_end);

    let body: Vec<Stmt> = if has_combo {
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            protected_end,
            region.handler_start,
            inline_copy_len,
        )?
    } else if normal_region.is_some() {
        structure_stmts(code, stream, region.try_start, protected_end)?
    } else {
        structure_stmts(code, stream, region.try_start, extended_body_end)?
    };

    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, except_region_end)?;
    let handlers: Vec<ExceptHandler> = if has_combo {
        trim_inline_finally_from_handlers(handlers, &finalbody)
    } else {
        handlers
    };

    let body_had_comp: bool = protected_end > region.protected_end;
    let (orelse, construct_tail): (Vec<Stmt>, Vec<Stmt>) = match normal_region {
        Some((s, e)) => {
            let mut raw: Vec<Stmt> = structure_stmts(code, stream, s, e)?;
            if has_combo {
                strip_leading_stmts(&mut raw, &finalbody);
                let tail: Vec<Stmt> = split_construct_tail_after_finally(&mut raw, &finalbody);
                while matches!(raw.last(), Some(Stmt::Return(_))) {
                    raw.pop();
                }
                (raw, tail)
            } else if body_had_comp {
                (Vec::new(), raw)
            } else if let Some(shared) = shared_construct_exit_return(&raw, &handlers) {
                (Vec::new(), shared)
            } else {
                (raw, Vec::new())
            }
        }
        None => (Vec::new(), Vec::new()),
    };
    let handlers: Vec<ExceptHandler> = if construct_tail.is_empty() {
        handlers
    } else {
        strip_shared_exit_return(handlers, &construct_tail)
    };

    let consumed: usize = combo
        .as_ref()
        .map_or(except_region_end, |c: &ComboFinally| c.region_end);
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse,
            finalbody,
            line: None,
        },
        consumed,
        construct_tail,
    ))
}

/// Split off the construct-exit tail that `CPython` inlines AFTER the per-exit finally copy in the
/// normal/`else` fall-through of a `try/except[/else]/finally` combo. On 3.12+ a function whose final
/// statement is `return EXPR` (or that simply falls off the end) places that exit INSIDE the `else`
/// fall-through region, just past the inline finally copy: `<else body>; <finally copy>; return EXPR`.
/// The finally copy is the same source as `finalbody` and is dropped; everything past it is the real
/// post-construct tail and must be lifted out so it is not stripped as a phantom `else` return (the
/// 3.11 layout routes that tail past the cold handlers, where the structurer recovers it for free).
/// Returns the lifted tail statements and truncates `raw` to the genuine `else` body. When no finally
/// copy is found at the tail, the legacy trailing-copy strip applies and no tail is lifted.
fn split_construct_tail_after_finally(raw: &mut Vec<Stmt>, finalbody: &[Stmt]) -> Vec<Stmt> {
    if finalbody.is_empty() {
        return Vec::new();
    }
    let mut copy_at: Option<usize> = None;
    let limit: usize = raw.len().saturating_sub(finalbody.len());
    for start in (0..=limit).rev() {
        let window_matches: bool = raw[start..start + finalbody.len()]
            .iter()
            .zip(finalbody.iter())
            .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
        if window_matches {
            copy_at = Some(start);
            break;
        }
    }
    let Some(copy_at): Option<usize> = copy_at else {
        strip_trailing_stmts(raw, finalbody);
        return Vec::new();
    };
    let tail_start: usize = copy_at + finalbody.len();
    let tail: Vec<Stmt> = raw.split_off(tail_start);
    raw.truncate(copy_at);
    tail.into_iter()
        .filter(|s: &Stmt| matches!(s, Stmt::Return(_)))
        .collect()
}

/// Distinguish a genuine pre-3.11 `try/except/else` from a `try/except` followed by a sibling tail. Both
/// lay the success-path code (`return ...`) in the `[POP_BLOCK-exit, ...)` gap, but a real `else:` is the
/// function's LAST suite, so `CPython` appends the implicit `return None` epilogue (`LOAD_CONST <None>;
/// RETURN_VALUE`) at the very end of the gap, AFTER the else body's own return. A construct tail's own
/// `return` IS the function epilogue, with no trailing `None`-return. Returns true (keep `else:`) when the
/// gap ends in that dead `None`-return following a prior `return`/`raise`. Used ONLY for the non-finally
/// `try/except[/else]` shape — the finally combo inlines its own copies on each exit and is excluded.
fn pre311_else_is_real(
    code: &CodeObject,
    stream: &DecodedStream,
    else_start: usize,
    else_end: usize,
) -> bool {
    let Some(last): Option<usize> = (else_start..else_end)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return false;
    };
    if !matches!(stream.ops[last], CanonicalOp::Return) {
        return false;
    }
    let Some(prev): Option<usize> = (else_start..last)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return false;
    };
    if !loads_none(code, &stream.ops[prev]) {
        return false;
    }
    (else_start..prev)
        .rev()
        .find_map(|k: usize| match stream.ops[k] {
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_) => Some(true),
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => None,
            _ => Some(false),
        })
        .unwrap_or(false)
}

/// Structure a pre-3.11 `try/except[/else]`. The protected body ends at the `POP_BLOCK` that closes
/// the try block (its byte index is recorded in `pre311_pop_block_idx`); any fall-through code between
/// that `POP_BLOCK` and the first except handler - entered directly, ending before the handler - is the
/// `else:` clause. Without a `POP_BLOCK` inside the protected span (rare optimized layouts) the body
/// falls back to the extended-body range and no else is opened.
fn structure_pre311_try_except(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    extended_body_end: usize,
    hi: usize,
) -> Result<(Stmt, usize)> {
    let region_bound: usize = hi.min(stream.ops.len());
    let pop_block: Option<usize> = stream
        .pre311_pop_block_idx
        .range(region.try_start..region.handler_start)
        .next_back()
        .copied();

    let mut body_end: usize = extended_body_end;
    let mut else_region: Option<(usize, usize)> = None;
    let mut handler_region_end: usize = region.region_end;
    let mut consumed: usize = region.region_end;

    if let Some(pb) = pop_block {
        let after: usize = pre311_skip_pop_except(stream, pb + 1, region.handler_start);
        if let Some(jt) = pre311_body_exit_jump_target(stream, pb, region.handler_start)
            && jt > region.handler_start
        {
            let else_start: usize = pre311_skip_jumps(stream, jt, region_bound);
            let else_end: usize = pre311_else_end(stream, else_start, region_bound);
            let shared_with_handler: bool =
                pre311_handler_swallow_target(stream, region.handler_start, jt).is_some_and(
                    |t: usize| pre311_skip_jumps(stream, t, region_bound) == else_start,
                );
            let real_else: bool = !pre311_enclosed_by_finally(stream, region)
                && pre311_else_is_real(code, stream, else_start, else_end);
            if pre311_region_has_real_stmt(stream, else_start, else_end)
                && !shared_with_handler
                && (real_else || pre311_enclosed_by_finally(stream, region))
            {
                body_end = pb;
                handler_region_end = jt;
                else_region = Some((else_start, else_end));
                consumed = consumed.max(else_end);
            } else if pre311_region_has_real_stmt(stream, else_start, else_end)
                && !shared_with_handler
            {
                body_end = pb;
                handler_region_end = jt;
                consumed = else_start;
            } else if shared_with_handler {
                body_end = pb;
                handler_region_end = jt;
                consumed = consumed.max(jt);
            }
        } else if matches!(stream.ops.get(region.handler_start), Some(CanonicalOp::Dup)) {
            let else_start: usize = pre311_skip_jumps(stream, after, region.handler_start);
            let else_end: usize = pre311_else_end(stream, else_start, region.handler_start);
            let first_real: Option<usize> = (else_start..else_end)
                .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop));
            let ends_in_return: bool = (else_start..else_end)
                .rev()
                .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
                .is_some_and(|k: usize| {
                    matches!(
                        stream.ops[k],
                        CanonicalOp::Return | CanonicalOp::ReturnConst(_)
                    )
                });
            let body_return_via_finally: bool =
                ends_in_return && pre311_enclosed_by_finally(stream, region);
            if !body_return_via_finally
                && first_real.is_some_and(|k: usize| else_entry_is_fallthrough(&stream.ops[k]))
            {
                body_end = pb;
                else_region = Some((else_start, else_end));
            }
        }
    }

    let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
    let mut handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, handler_region_end)?;
    let mut orelse: Vec<Stmt> = match else_region {
        Some((s, e)) => structure_stmts(code, stream, s, e)?,
        None => Vec::new(),
    };
    if let Some((else_start, _)) = else_region
        && let Some(shared) = shared_construct_exit_return(&orelse, &handlers)
    {
        orelse.clear();
        handlers = strip_shared_exit_return(handlers, &shared);
        consumed = else_start;
    }
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse,
            finalbody: Vec::new(),
            line: None,
        },
        consumed,
    ))
}

/// True when a pre-3.11 try/except `region` is wrapped by an outer `finally:` - i.e. an exception-table
/// entry strictly encloses the region's protected span and lands on a finally-shaped handler. In that
/// combo, `CPython` duplicates the finally inline on each exit, so the try-body's own `return` is
/// emitted AFTER the inline finally copy, in the region between the body's `POP_BLOCK` and the handler.
/// That region must NOT be mistaken for an `else:` (it is the body's return path); this gate
/// distinguishes it from a genuine `try/except/else` (no enclosing finally), where the same span really
/// is the `else` clause.
fn pre311_enclosed_by_finally(stream: &DecodedStream, region: &TryRegion) -> bool {
    let Some(try_off): Option<u32> = stream.offsets.get(region.try_start).copied() else {
        return false;
    };
    let Some(handler_off): Option<u32> = stream.offsets.get(region.handler_start).copied() else {
        return false;
    };
    for entry in &stream.exception_table {
        let Some(enc_handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if enc_handler <= region.handler_start {
            continue;
        }
        if entry.start > try_off || entry.end() < handler_off {
            continue;
        }
        let enc_end: usize = pre311_handler_region_end(stream, enc_handler, stream.ops.len());
        if is_pre311_finally_handler_shape(stream, enc_handler, enc_end.min(stream.ops.len())) {
            return true;
        }
    }
    false
}

/// Skip a leading `POP_EXCEPT`/no-op run at the head of the post-`POP_BLOCK` region.
fn pre311_skip_pop_except(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::PopExcept | CanonicalOp::Nop | CanonicalOp::Cache)
        )
    {
        k += 1;
    }
    k
}

/// Resolve the target of the body's normal-exit `JUMP_FORWARD` that immediately follows the
/// `POP_BLOCK` (skipping `POP_EXCEPT`/no-ops). On pre-3.11 `try/except/else` the body jumps OVER the
/// handler block to the else region placed after it; the jump target marks the else start. Returns
/// `None` when no such forward jump is present (no else, or else placed inline before the handler).
fn pre311_body_exit_jump_target(
    stream: &DecodedStream,
    pop_block: usize,
    handler_start: usize,
) -> Option<usize> {
    let k: usize = pre311_skip_pop_except(stream, pop_block + 1, handler_start);
    if k >= handler_start {
        return None;
    }
    if matches!(
        stream.ops.get(k),
        Some(CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_))
    ) {
        return resolve_jump_target(stream, k, &stream.ops[k]);
    }
    None
}

/// The target of a pre-3.11 typed-`except` handler's SWALLOW exit: after running the handler body the
/// compiler emits `POP_EXCEPT; JUMP_FORWARD target` to skip the trailing `END_FINALLY` and rejoin the
/// post-`try` flow. Scans `[handler_start, body_exit)` for the last forward jump whose target lands at
/// or past `body_exit`. When that swallow target coincides with the try body's own normal-exit target,
/// the shared landing is plain code AFTER the `try/except` (reached on both the no-exception and
/// exception-handled paths) - NOT an `else:` clause (which only the no-exception path reaches). Returns
/// `None` when the handler re-raises (no swallow jump), leaving the standard else-detection intact.
fn pre311_handler_swallow_target(
    stream: &DecodedStream,
    handler_start: usize,
    body_exit: usize,
) -> Option<usize> {
    (handler_start..body_exit)
        .rev()
        .filter(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
            )
        })
        .find_map(|k: usize| {
            resolve_jump_target(stream, k, &stream.ops[k]).filter(|t: &usize| *t >= body_exit)
        })
}

/// True when `[lo, hi)` contains at least one non-trivial statement op (not a bare jump / no-op /
/// re-raise tail).
fn pre311_region_has_real_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::PopExcept
        )
    })
}

/// Skip leading jumps / no-ops at the head of a pre-3.11 else region (the `POP_BLOCK` is followed by a
/// `JUMP_FORWARD` over the handler block to the else body).
fn pre311_skip_jumps(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        )
    {
        k += 1;
    }
    k
}

/// End of a pre-3.11 else region: the run up to the first except handler, trimming a trailing jump /
/// no-op tail (the else's exit jump to the join point past all handlers).
fn pre311_else_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        )
    {
        end -= 1;
    }
    end
}

/// Classify an exception handler at `handler_start` as a pure `finally:` cleanup (runs an
/// unconditional cleanup then re-raises) versus an `except` (typed or bare). Mirrors pycdc
/// `handlerIsFinally` (ASTree.cpp:1311): a finally reaches its terminal RERAISE with neither a type
/// test (`CHECK_EXC_MATCH` / `CHECK_EG_MATCH`) nor a swallow, and - crucially - without discarding the
/// pushed exception. A bare `except:` looks like a finally except that it POPs the exception value at
/// its head (3.11+: `PUSH_EXC_INFO; POP_TOP`; pre-3.11: a `POP_TOP` triple consuming the exc-info
/// three-tuple) and ends in `RAISE_VARARGS`/`POP_EXCEPT` rather than re-raising the live exception.
/// `is_pre311` selects the head-shape probe.
fn is_pure_finally_handler_shape(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
    is_pre311: bool,
) -> bool {
    if is_pre311 {
        return is_pre311_finally_handler_shape(stream, handler_start, region_end);
    }
    let mut i: usize = handler_start;
    if !matches!(stream.ops.get(i), Some(CanonicalOp::PushExcInfo)) {
        return false;
    }
    i += 1;
    if matches!(stream.ops.get(i), Some(CanonicalOp::Pop)) {
        return false;
    }
    for k in i..region_end {
        match stream.ops[k] {
            CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
            | CanonicalOp::Other(121, _)
            | CanonicalOp::PopExcept
            | CanonicalOp::Dup => return false,
            CanonicalOp::Reraise(_) => return true,
            _ => {}
        }
    }
    false
}

/// Pre-3.11 finally handler head probe. A `finally:` handler runs its cleanup body directly then
/// `RERAISE` / `END_FINALLY` with no type test and no exc-discard prefix; a bare `except:` opens with
/// a `POP_TOP` triple (discarding the pushed exc three-tuple) and a typed `except` opens with `DUP_TOP`
/// then `COMPARE_OP(ExcMatch)` / `JUMP_IF_NOT_EXC_MATCH`.
fn is_pre311_finally_handler_shape(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> bool {
    let mut i: usize = handler_start;
    while i < region_end
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        i += 1;
    }
    if matches!(stream.ops.get(i), Some(CanonicalOp::Pop | CanonicalOp::Dup)) {
        return false;
    }
    for k in i..region_end {
        match stream.ops[k] {
            CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
            | CanonicalOp::Other(121, _)
            | CanonicalOp::PopExcept
            | CanonicalOp::Dup => return false,
            CanonicalOp::Reraise(_) => return true,
            _ if stream.pre311_end_finally_idx.contains(&k) => return true,
            _ => {}
        }
    }
    false
}

/// First op index past the leading `PUSH_EXC_INFO` of a (3.11+) handler, else the handler start.
fn handler_body_first(stream: &DecodedStream, handler_start: usize) -> usize {
    if matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::PushExcInfo)
    ) {
        handler_start + 1
    } else {
        handler_start
    }
}

/// The finally body of a pure-finally handler: from the handler's first real op (past
/// `PUSH_EXC_INFO`) up to its first `RERAISE` / `END_FINALLY`. Mirrors pycdc `finallyBodyLen`
/// (ASTree.cpp:1870) but in op-index space.
fn finally_body_end(stream: &DecodedStream, fin_start: usize, region_end: usize) -> usize {
    (fin_start..region_end)
        .find(|&k: &usize| {
            matches!(stream.ops[k], CanonicalOp::Reraise(_))
                || stream.pre311_end_finally_idx.contains(&k)
        })
        .unwrap_or(region_end)
}

/// The op index past the last inner `try/except` handler inside a pre-3.11 finally's protected span -
/// i.e. the terminal `RERAISE` / `END_FINALLY` of the deepest except-shaped (not finally-shaped) handler
/// strictly before this finally's own handler. `None` when the span wraps no inner except (a plain
/// `try/finally`). Used to gate the inline-finally peel: a `try/except/finally` combo duplicates the
/// finally on EVERY exit path, so a backward peel can land BEFORE the inner handler's terminal and
/// amputate it; when that happens the protected body must instead span the whole inner `try/except` (no
/// peel), letting `fold_pre311_combo_inner` strip the per-clause copies.
fn pre311_inner_except_region_end(stream: &DecodedStream, region: &TryRegion) -> Option<usize> {
    let mut end: Option<usize> = None;
    for entry in &stream.exception_table {
        let Some(inner_handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if inner_handler <= region.try_start || inner_handler >= region.handler_start {
            continue;
        }
        let inner_end: usize =
            pre311_handler_region_end(stream, inner_handler, region.handler_start);
        let bounded: usize = inner_end.min(region.handler_start);
        if !is_pre311_finally_handler_shape(stream, inner_handler, bounded) {
            end = Some(end.map_or(bounded, |prev: usize| prev.max(bounded)));
        }
    }
    end
}

fn structure_pure_finally(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    body_real_end: usize,
) -> Result<(Stmt, Vec<Stmt>)> {
    let _ = body_real_end;
    let fin_start: usize = handler_body_first(stream, region.handler_start);
    let fin_end: usize = finally_body_end(stream, fin_start, region.region_end);
    let finalbody: Vec<Stmt> = structure_stmts(code, stream, fin_start, fin_end)?;
    let finally_len: usize = fin_end.saturating_sub(fin_start);

    let protected_end: usize = region.protected_end.max(region.try_start);
    let body: Vec<Stmt> = if stream.is_pre_311() {
        let peeled: usize = pre311_inline_finally_start(
            stream,
            region.try_start,
            region.handler_start,
            finally_len,
        );
        let inline_start: usize = match pre311_inner_except_region_end(stream, region) {
            Some(inner_end) if peeled < inner_end => region.handler_start,
            _ => peeled,
        };
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            inline_start,
            region.handler_start,
            finally_len,
        )?
    } else {
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            protected_end,
            region.handler_start,
            finally_len,
        )?
    };
    let (mut body, tail, merged_finally): (Vec<Stmt>, Vec<Stmt>, bool) = if stream.is_pre_311() {
        fold_pre311_combo_inner(body, &finalbody)
    } else {
        (body, Vec::new(), false)
    };
    if merged_finally && body.len() == 1 {
        let single: Stmt = body.remove(0);
        return Ok((single, tail));
    }
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers: Vec::new(),
            orelse: Vec::new(),
            finalbody: non_empty(finalbody),
            line: None,
        },
        tail,
    ))
}

/// Fold a pre-3.11 `try/except[/else]/finally` combo's protected body - recovered as a nested inner
/// `try/except[/else]` - into ONE flat `try/except[/else]/finally` statement, plus the lifted
/// construct-exit tail. Pre-3.11 `CPython` lowers a single source `try/except/finally` as a
/// `SETUP_FINALLY` wrapping a `SETUP_EXCEPT`, so the protected body of the finally row is itself a
/// `try/except`; left nested it would print a spurious extra `try:` level. It also DUPLICATES the
/// finally body inline on every normal exit path (try-body return, each handler exit, the `else`
/// fall-through), so the recovered inner `try/except` carries a phantom copy of `finalbody` interleaved
/// into each clause, just before that clause's own `return`. Strip every inline copy in place, then
/// re-attach `finalbody` as the merged statement's `finalbody` so recompilation regenerates the per-exit
/// copies. The `else` clause is special: its trailing `return` after the finally copy is the CONSTRUCT
/// EXIT (function tail), whose value is computed AFTER the finally runs; keeping it inside the `else`
/// would load the value before the finally, so it is LIFTED out and returned as the tail. The third
/// return element is `true` when the finally was merged into a flat statement (caller must NOT re-wrap),
/// `false` for a plain `try/finally` (no inner except) or a non-`Try` body, which the caller wraps.
fn fold_pre311_combo_inner(body: Vec<Stmt>, finalbody: &[Stmt]) -> (Vec<Stmt>, Vec<Stmt>, bool) {
    if finalbody.is_empty() || body.len() != 1 {
        return (body, Vec::new(), false);
    }
    let Some(Stmt::Try {
        body: inner_body,
        handlers,
        orelse,
        finalbody: inner_final,
        line,
    }): Option<Stmt> = body.into_iter().next()
    else {
        return (Vec::new(), Vec::new(), false);
    };
    if !inner_final.is_empty() || handlers.is_empty() {
        return (
            vec![Stmt::Try {
                body: inner_body,
                handlers,
                orelse,
                finalbody: inner_final,
                line,
            }],
            Vec::new(),
            false,
        );
    }
    let mut inner_body: Vec<Stmt> = inner_body;
    strip_clause_inline_finally(&mut inner_body, finalbody, false);
    let handlers: Vec<ExceptHandler> = handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            strip_clause_inline_finally(&mut h.body, finalbody, false);
            if h.body.is_empty() {
                h.body = vec![Stmt::Pass];
            }
            h
        })
        .collect();
    let mut orelse: Vec<Stmt> = orelse;
    let tail: Vec<Stmt> = strip_clause_inline_finally(&mut orelse, finalbody, true);
    (
        vec![Stmt::Try {
            body: non_empty(inner_body),
            handlers,
            orelse,
            finalbody: finalbody.to_vec(),
            line,
        }],
        tail,
        true,
    )
}

/// Strip the inline finally copy from one combo clause. The clause ends `... <finally copy> [return]`;
/// remove the LAST `finalbody`-matching run. When `lift_tail` is false (try-body / except handler) the
/// clause's own trailing `return` STAYS in place - `CPython` re-inlines the finally before it on
/// recompile. When `lift_tail` is true (the `else` clause) the trailing `return` is the construct exit
/// (function tail) whose value loads AFTER the finally; it is removed from the clause and RETURNED so the
/// caller re-emits it past the whole `try/finally`. Returns the lifted tail (empty unless `lift_tail`).
fn strip_clause_inline_finally(
    clause: &mut Vec<Stmt>,
    finalbody: &[Stmt],
    lift_tail: bool,
) -> Vec<Stmt> {
    if finalbody.is_empty() || clause.len() < finalbody.len() {
        return Vec::new();
    }
    let limit: usize = clause.len() - finalbody.len();
    let mut copy_at: Option<usize> = None;
    for start in (0..=limit).rev() {
        let window_matches: bool = clause[start..start + finalbody.len()]
            .iter()
            .zip(finalbody.iter())
            .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
        if window_matches {
            copy_at = Some(start);
            break;
        }
    }
    let Some(copy_at): Option<usize> = copy_at else {
        return Vec::new();
    };
    if lift_tail {
        let tail: Vec<Stmt> = clause.split_off(copy_at + finalbody.len());
        clause.truncate(copy_at);
        return tail
            .into_iter()
            .filter(|s: &Stmt| matches!(s, Stmt::Return(_)))
            .collect();
    }
    clause.drain(copy_at..copy_at + finalbody.len());
    Vec::new()
}

/// Locate the start of the inline normal-path finally copy in a pre-3.11 `try: ... finally: ...`. The
/// finally body is duplicated on the normal exit between the `POP_BLOCK` and the construct exit;
/// `CPython` lays it as a byte copy of the cold handler body (`[handler_start, handler_start+finally_len)`).
/// Scan backward from the handler for the last run of `finally_len` ops whose opcode discriminants
/// match the handler body - that run is the inline copy, and the body ends where it begins. Falls back
/// to the handler start when no copy is found (a finally whose normal path is unreachable).
fn pre311_inline_finally_start(
    stream: &DecodedStream,
    try_start: usize,
    handler_start: usize,
    finally_len: usize,
) -> usize {
    if finally_len == 0 {
        return handler_start;
    }
    let fin_body_start: usize = handler_start;
    let mut candidate: usize = handler_start.saturating_sub(finally_len);
    while candidate > try_start {
        if finally_runs_match(stream, fin_body_start, candidate, finally_len) {
            return candidate;
        }
        candidate -= 1;
    }
    if candidate >= try_start && finally_runs_match(stream, fin_body_start, candidate, finally_len)
    {
        return candidate;
    }
    handler_start
}

/// Two equal-length op runs `[a, a+len)` and `[b, b+len)` match when every op shares the same opcode
/// discriminant (operands may differ for jump distances). Mirrors pycdc `finallyRunsMatch`.
fn finally_runs_match(stream: &DecodedStream, a: usize, b: usize, len: usize) -> bool {
    if a + len > stream.ops.len() || b + len > stream.ops.len() {
        return false;
    }
    (0..len).all(|k: usize| {
        std::mem::discriminant(&stream.ops[a + k]) == std::mem::discriminant(&stream.ops[b + k])
    })
}

/// Build the body of a 3.11+ `try: ... finally: ...`. The protected range covers the try statements;
/// after it, on the normal path, `CPython` emits an inline copy of the finally body (length
/// `finally_len`) followed by the construct's normal exit (a `RETURN_VALUE` for a returning body, or
/// fall-through). The inline copy must be skipped (it is the finally, not body). When the protected
/// range ends mid-statement because the body is `return EXPR` (the value is computed inside the
/// protected range, the finally runs, then `RETURN_VALUE` fires after the inline copy), the trailing
/// residual value is re-wrapped as `return <value>`.
fn structure_finally_protected_body(
    code: &CodeObject,
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
    finally_len: usize,
) -> Result<Vec<Stmt>> {
    let inline_start: usize = protected_end;
    let inline_end: usize = (inline_start + finally_len).min(handler_start);
    let trailing_return: bool = (inline_end..handler_start)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
        .is_some_and(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return | CanonicalOp::ReturnConst(_)
            )
        });
    if trailing_return && region_is_linear(stream, try_start, protected_end) {
        let (head, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[try_start..protected_end])?;
        let mut out: Vec<Stmt> = head;
        if let Some(value) = residual.into_iter().next_back() {
            out.push(Stmt::Return(Some(value)));
        }
        return Ok(out);
    }
    structure_stmts(code, stream, try_start, protected_end)
}

/// True when `[lo, hi)` carries no control flow (no jumps, loops, or block setups) - a straight-line
/// statement run safe to feed through `build_linear_stmts_sim`. Used to gate the trailing-`return`
/// residual reconstruction so it never flattens a control-flow body (a loop / `if` inside the try).
fn region_is_linear(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    !(lo..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::ForIter(_)
                | CanonicalOp::GetIter
                | CanonicalOp::BeforeWith
        )
    })
}

fn special_method_name(slot: u32) -> &'static str {
    match slot {
        0 => "__enter__",
        1 => "__exit__",
        2 => "__aenter__",
        _ => "__aexit__",
    }
}

/// The `async with` setup span on 3.14+, which has no `BEFORE_ASYNC_WITH`: the context manager is
/// duplicated (`COPY 1`), then `LOAD_SPECIAL 3` (`__aexit__`) is stashed and `LOAD_SPECIAL 2`
/// (`__aenter__`) is called with `CALL 0`. Returns `(copy_idx, idx-past-the-enter-call)` so the
/// caller recovers the context expression before `copy_idx` and resumes after the call.
fn find_async_with_setup_end(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<(usize, usize)> {
    let mut i: usize = lo;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Copy(1))
            && let Some(special) = first_significant(stream, i + 1, hi)
            && matches!(stream.ops[special], CanonicalOp::LoadSpecial(_))
        {
            let enter: usize = (special + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadSpecial(2)))?;
            let call: usize = (enter + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
            return Some((i, call + 1));
        }
        i += 1;
    }
    None
}

fn find_with_setup_end(stream: &DecodedStream, lo: usize, hi: usize) -> Option<(usize, usize)> {
    let mut i: usize = lo;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Copy(1))
            && let Some(special) = first_significant(stream, i + 1, hi)
            && matches!(stream.ops[special], CanonicalOp::LoadSpecial(_))
        {
            let enter: usize = (special + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadSpecial(0)))?;
            let call: usize = (enter + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
            return Some((i, call + 1));
        }
        i += 1;
    }
    None
}

/// `async with cm as v:` shares the modern `with` exception-table shape (`PUSH_EXC_INFO;
/// WITH_EXCEPT_START` handler) but awaits both `__aenter__` and `__aexit__`. The discriminator is a
/// `GET_AWAITABLE` immediately after the handler's `WITH_EXCEPT_START` (awaiting `__aexit__`). The
/// context manager is loaded before `BEFORE_ASYNC_WITH` (3.11-3.13) or the `COPY 1; LOAD_SPECIAL`
/// `__aenter__`/`__aexit__` dance (3.14+); the first `GET_AWAITABLE` after the setup awaits
/// `__aenter__`, whose result is stored (`as v`) or popped, then the body runs until the implicit
/// awaited `__aexit__(None, None, None)` cleanup.
fn structure_async_with(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<Option<(Stmt, Vec<Stmt>)>> {
    let with_except: usize = match (region.handler_start..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))
    {
        Some(idx) => idx,
        None => return Ok(None),
    };
    if !first_significant(stream, with_except + 1, region.region_end)
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
    {
        return Ok(None);
    }
    let before_idx: Option<usize> = (region.try_start..region.try_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::BeforeAsyncWith));
    let (context_end, setup_end): (usize, usize) = if let Some(idx) = before_idx {
        (idx, idx + 1)
    } else {
        let Some((copy_idx, setup_end)): Option<(usize, usize)> =
            find_async_with_setup_end(stream, region.try_start, region.try_end)
        else {
            return Ok(None);
        };
        (copy_idx, setup_end)
    };
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[region.try_start..context_end])?;
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let enter_await: usize = (setup_end..region.try_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .unwrap_or(setup_end);
    let after_poll: usize = skip_await_poll(stream, enter_await + 1, region.try_end);
    let mut body_start: usize = after_poll;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(after_poll) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, after_poll).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, after_poll, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => body_start += 1,
        _ => {}
    }
    let search_end: usize = region.region_end.max(region.try_end);
    let body_end: usize = with_body_end(stream, body_start, search_end);
    if let Some(ret) = async_with_stashed_return(code, stream, body_start, body_end)? {
        return Ok(Some((
            Stmt::With {
                items: vec![WithItem {
                    context_expr,
                    optional_vars,
                }],
                body: vec![ret],
                is_async: true,
                line: None,
            },
            Vec::new(),
        )));
    }
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
    let trailing: Option<Stmt> = async_with_trailing_return(code, stream, body_end, search_end)?;
    let post_with: Vec<Stmt> = if trailing.is_some() {
        Vec::new()
    } else {
        async_with_post_tail(code, stream, body_end, region.handler_start)?
    };
    if let Some(ret) = trailing {
        body.push(ret);
    }
    Ok(Some((
        Stmt::With {
            items: vec![WithItem {
                context_expr,
                optional_vars,
            }],
            body: non_empty(body),
            is_async: true,
            line: None,
        },
        post_with,
    )))
}

/// Recover a `return <expr>` that is the entire body of an `async with` whose return value `CPython`
/// computes BEFORE the awaited `__aexit__` and stashes below the exit args with `SWAP 2`
/// (`async with timeout(): return int(await work)`). `with_body_end` stops at the `__aexit__` None-triple,
/// so the body region is `<value-expr>; SWAP 2` — a bare residual value the statement structurer drops,
/// leaving an empty `pass` body and a value-less trailing return. Detect the closing `SWAP 2`, rebuild
/// the value from the ops before it, and emit `return <value>` as the with body. `None` when the body
/// does not end in that stash shape (an ordinary body whose statements/return are recovered normally).
fn async_with_stashed_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> Result<Option<Stmt>> {
    let Some(swap): Option<usize> = (body_start..body_end)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return Ok(None);
    };
    if !matches!(stream.ops[swap], CanonicalOp::Swap(2)) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[body_start..swap])?;
    if !head.is_empty() {
        return Ok(None);
    }
    let Some(value): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    Ok(Some(Stmt::Return(Some(value))))
}

/// Structure the statements that follow an `async with` on its NORMAL (no-exception) exit: the code
/// past the awaited `__aexit__(None, None, None)` cleanup up to the cold exception handler. The async
/// `with` exception region spans the whole construct, so its `region_end` engulfs this post-`with` tail
/// (a `for`/`return`/etc.); without lifting it out the tail is silently consumed and dropped. Cut at the
/// handler entry (`PUSH_EXC_INFO` / `WITH_EXCEPT_START` cold path) and structure `[cleanup_end, handler)`
/// as ordinary statements. Empty when no real statement follows the cleanup.
fn async_with_post_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    handler_start: usize,
) -> Result<Vec<Stmt>> {
    let Some(tail_start): Option<usize> = async_with_cleanup_end(stream, body_end, handler_start)
    else {
        return Ok(Vec::new());
    };
    if tail_start >= handler_start || !slice_has_real_stmt(stream, tail_start, handler_start) {
        return Ok(Vec::new());
    }
    structure_stmts(code, stream, tail_start, handler_start)
}

/// Skip the normal-exit `__aexit__(None, None, None)` cleanup an async `with` emits after its body:
/// the `LOAD_CONST None` triple, the exit `CALL`, the awaited poll, and the discarding `POP`. Returns
/// the index where ordinary post-with flow resumes (the `return EXPR` of a with-trailing-return idiom,
/// OR the inline function epilogue on 3.12+). `None` when no cleanup triple begins at `body_end`.
fn async_with_cleanup_end(stream: &DecodedStream, body_end: usize, hi: usize) -> Option<usize> {
    let mut i: usize = body_end;
    let mut loads: usize = 0;
    while i < hi && loads < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                loads += 1;
            }
            CanonicalOp::Push(0)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {}
            _ => return None,
        }
        i += 1;
    }
    if loads < 3 {
        return None;
    }
    let call: usize =
        (i..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
    let after_await: usize = (call + 1..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .map_or(call + 1, |g: usize| skip_await_poll(stream, g + 1, hi));
    Some(
        first_significant(stream, after_await, hi)
            .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Pop))
            .map_or(after_await, |p: usize| p + 1),
    )
}

/// On the `return EXPR` exit path of an async `with`, `CPython` emits the awaited
/// `__aexit__(None, None, None)` cleanup BEFORE the `return`, so the body's trailing `return EXPR`
/// lands after the implicit exit call. Skip the exit triple/call/await poll and re-simulate the
/// residual `return` (or `RETURN_CONST`).
/// When an `async with` is the last statement of an enclosing `try:` body, `CPython` inlines the
/// enclosing construct's success-exit `return EXPR` right after the with's awaited `__aexit__` cleanup,
/// then lays the `try`'s exception handlers (`PUSH_EXC_INFO` / `CHECK_EG_MATCH`) cold afterward. That
/// return belongs to the enclosing `try`, not the `with` body, so it must not be folded into the with
/// (else it duplicates as a phantom trailing return inside the with). Detect an exception-handler
/// dispatch following the candidate return within the search window: its presence marks the return as
/// the enclosing try's construct-exit, recovered by `structure_try` once the with is consumed.
fn async_with_return_owned_by_enclosing_try(
    stream: &DecodedStream,
    ret_start: usize,
    hi: usize,
) -> bool {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return false;
    };
    (ret_idx + 1..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::CheckEgMatch | CanonicalOp::CheckExcMatch
        )
    })
}

fn async_with_trailing_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    let Some(ret_start): Option<usize> = async_with_cleanup_end(stream, body_end, hi) else {
        return Ok(None);
    };
    if async_with_exit_guarded_by_branch(stream, ret_start, hi) {
        return Ok(None);
    }
    if async_with_return_owned_by_enclosing_try(stream, ret_start, hi) {
        return Ok(None);
    }
    recover_return_at(code, stream, ret_start, hi)
}

/// Whether the code after an `async with`'s `__aexit__` cleanup, up to the first `RETURN`, contains a
/// forward conditional jump - i.e. it is the FUNCTION epilogue (`if failure is not None: return
/// failure`) reached on the with's NORMAL exit, not the with's own unconditional trailing `return EXPR`.
/// A genuine with-trailing-return idiom runs the awaited `__aexit__` then `return EXPR` with no
/// branching; a `POP_JUMP_IF_*` before the return marks an enclosing `if`, so the return belongs to the
/// surrounding flow and must NOT be folded into the with body (else it leaks a spurious `return failure`
/// at the end of the `with` on 3.12+, where the epilogue is laid out inline after the loop-exit aexit).
fn async_with_exit_guarded_by_branch(stream: &DecodedStream, ret_start: usize, hi: usize) -> bool {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return false;
    };
    (ret_start..ret_idx).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            || matches!(
                stream.ops[k],
                CanonicalOp::ForIter(_)
                    | CanonicalOp::GetAnext
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::JumpBackward(_)
            )
    })
}

/// Recover a `return EXPR` statement: find the `RETURN_VALUE`/`RETURN_CONST` in `[ret_start, hi)` and
/// re-simulate its operand (the `RETURN_CONST` operand directly, or the residual feeding
/// `RETURN_VALUE`). Returns `None` when no return is present.
fn recover_return_at(
    code: &CodeObject,
    stream: &DecodedStream,
    ret_start: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(None);
    };
    if let CanonicalOp::ReturnConst(c) = &stream.ops[ret_idx] {
        let value: Expr = load_const(code, *c, ret_idx)?;
        return Ok(Some(Stmt::Return(Some(value))));
    }
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[ret_start..ret_idx])?;
    Ok(Some(Stmt::Return(residual.into_iter().next_back())))
}

/// Advance past an `await` poll: the `LOAD_CONST None` / `SEND` / `YIELD_VALUE` / `RESUME` /
/// `JUMP_BACKWARD_NO_INTERRUPT` / `END_SEND` machinery (3.11+) or `LOAD_CONST None` / `YIELD_FROM`
/// (pre-3.11) that follows a `GET_AWAITABLE`. Stops at the first op that is not part of the poll.
fn skip_await_poll(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi {
        match &stream.ops[i] {
            CanonicalOp::YieldFrom => return i + 1,
            CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadCommonConst(7)
            | CanonicalOp::Push(0)
            | CanonicalOp::Send(_)
            | CanonicalOp::Yield
            | CanonicalOp::Resume(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::EndSend
            | CanonicalOp::CleanupThrow
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => i += 1,
            _ => break,
        }
    }
    i
}

/// One recovered context-manager setup in a `with`-statement prologue: the recovered item, the
/// source line of its setup op (used to split nested vs multi-item), and the index where the next
/// manager's context expression begins. `next_start` is the index immediately after the `as`-target
/// store EXCEPT when the store is the fused `STORE_FAST_LOAD_FAST` superinstruction - there the
/// trailing `LOAD_FAST` half pushes the next manager's context, so the next setup must re-simulate
/// from the fused op itself.
#[derive(Debug)]
struct WithSetup {
    item: WithItem,
    setup_line: Option<u32>,
    next_start: usize,
}

/// A recovered `with` item paired with the source line of its setup op, used to regroup a setup
/// chain into multi-item (`with a, b:`) vs nested (`with a:\n with b:`) statements.
type WithChainEntry = (WithItem, Option<u32>);

/// Recover the context expression and optional `as`-target of one 3.11+ `with` setup beginning at
/// `ctx_start`. The setup is `<ctx> BEFORE_WITH (STORE | POP)` (3.11-3.13) or the
/// `<ctx> COPY 1; LOAD_SPECIAL ...; CALL` enter dance (3.14+) followed by the same store/pop. Returns
/// `None` when no with-setup begins at `ctx_start` within `[ctx_start, hi)`.
fn recover_with_setup(
    code: &CodeObject,
    stream: &DecodedStream,
    ctx_start: usize,
    hi: usize,
) -> Result<Option<WithSetup>> {
    let before_idx: Option<usize> =
        (ctx_start..hi).find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::BeforeWith));
    let modern: Option<(usize, usize)> = find_with_setup_end(stream, ctx_start, hi);
    let (ctx_end, setup_end): (usize, usize) = match (before_idx, modern) {
        (Some(before_idx), Some((copy_idx, _))) if before_idx <= copy_idx => {
            (before_idx, before_idx + 1)
        }
        (Some(before_idx), None) => (before_idx, before_idx + 1),
        (_, Some((copy_idx, modern_end))) => (copy_idx, modern_end),
        (None, None) => return Ok(None),
    };
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[ctx_start..ctx_end])?;
    let carried_fused_store: usize = usize::from(matches!(
        stream.ops.get(ctx_start),
        Some(CanonicalOp::StoreFastLoadFast(_, _))
    ));
    if stmts.len() > carried_fused_store {
        return Ok(None);
    }
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let (optional_vars, next_start): (Option<Expr>, usize) = match stream.ops.get(setup_end) {
        Some(CanonicalOp::StoreFast(slot)) => {
            (local_target(code, *slot, setup_end).ok(), setup_end + 1)
        }
        Some(CanonicalOp::StoreName(slot)) => (
            name_at(&code.names, *slot, setup_end, "name")
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                }),
            setup_end + 1,
        ),
        Some(CanonicalOp::StoreFastLoadFast(slot, _)) => {
            (local_target(code, *slot, setup_end).ok(), setup_end)
        }
        Some(CanonicalOp::Pop) => (None, setup_end + 1),
        _ => (None, setup_end),
    };
    Ok(Some(WithSetup {
        item: WithItem {
            context_expr,
            optional_vars,
        },
        setup_line: stream.line_at(ctx_end),
        next_start,
    }))
}

/// Collect the full chain of consecutive 3.11+ `with` setups starting at `region.try_start`.
/// `with a as x, b as y:` and nested `with a:\n with b:` both compile to back-to-back
/// `BEFORE_WITH` (3.11-3.13) / enter-dance (3.14+) setups, each with its own exception-table region;
/// recovering EVERY setup (not just the first) yields a faithful `with` that recompiles to the same
/// nested-manager bytecode. Returns each item paired with its setup source line and the body start.
fn collect_with_chain(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<(Vec<WithChainEntry>, usize)> {
    let search_end: usize = region.region_end.max(region.try_end);
    let mut items: Vec<WithChainEntry> = Vec::new();
    let mut cursor: usize = region.try_start;
    let mut pending: Option<WithSetup> = recover_with_setup(code, stream, cursor, search_end)?;
    while let Some(setup) = pending {
        let next_start: usize = setup.next_start;
        items.push((setup.item, setup.setup_line));
        if next_start <= cursor {
            break;
        }
        cursor = next_start;
        pending = recover_with_setup(code, stream, cursor, search_end)?;
    }
    Ok((items, cursor))
}

fn structure_with(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<(Stmt, Vec<Stmt>)> {
    if let Some(stmt_and_tail) = structure_async_with(code, stream, region)? {
        return Ok(stmt_and_tail);
    }
    let (chain, body_start): (Vec<WithChainEntry>, usize) =
        collect_with_chain(code, stream, region)?;
    if chain.is_empty() {
        let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, region.try_end)?;
        return Ok((
            Stmt::With {
                items: vec![WithItem {
                    context_expr: Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    },
                    optional_vars: None,
                }],
                body: non_empty(body),
                is_async: false,
                line: None,
            },
            Vec::new(),
        ));
    }
    let search_end: usize = region.region_end.max(region.try_end);
    let body_end: usize = with_body_end(stream, body_start, search_end);
    let body: Vec<Stmt> = structure_with_body(code, stream, body_start, body_end, search_end)?;
    Ok((assemble_with_chain(chain, body), Vec::new()))
}

/// Assemble the recovered (non-empty) `with`-setup chain into a faithful statement. Consecutive
/// setups sharing a source line form ONE multi-item `with a, b:`; a setup on a NEW line opens a
/// nested `with` whose body is everything that follows (so `with a:\n with b:` round-trips its
/// per-line bytecode, which differs from the single-line multi form by line-tracking `NOP`s). With
/// no line info the whole chain folds into one multi-item `with` (the multi shape is the common case
/// and recompiles identically for genuine multi-item sources).
fn assemble_with_chain(chain: Vec<WithChainEntry>, body: Vec<Stmt>) -> Stmt {
    let mut groups: Vec<Vec<WithItem>> = Vec::new();
    let mut last_line: Option<u32> = None;
    for (item, item_line) in chain {
        let same_line: bool = matches!((item_line, last_line), (Some(l), Some(p)) if l == p);
        if same_line && let Some(group) = groups.last_mut() {
            group.push(item);
        } else {
            groups.push(vec![item]);
        }
        last_line = item_line.or(last_line);
    }
    let mut inner_body: Vec<Stmt> = non_empty(body);
    for items in groups.into_iter().rev() {
        inner_body = vec![Stmt::With {
            items,
            body: inner_body,
            is_async: false,
            line: None,
        }];
    }
    inner_body.into_iter().next().unwrap_or(Stmt::Pass)
}

/// Structure a with-body, recognising the trailing-return idiom on 3.11+ where the body's value is
/// stashed below the implicit `__exit__(None, None, None)` call via `Swap(2)` and returned after
/// `Pop` discards the exit result. When detected, drops the trailing `Swap` from the body region
/// and synthesises the implicit `return <body_value>` instead of losing it.
fn structure_with_body(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
    region_end: usize,
) -> Result<Vec<Stmt>> {
    let mut trim_end: usize = body_end;
    while trim_end > body_start
        && matches!(
            stream.ops[trim_end - 1],
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_)
        )
    {
        trim_end -= 1;
    }
    let swap_present: bool = trim_end < body_end;
    let trailing_return: bool = is_with_trailing_return(stream, body_end, region_end);
    if swap_present && trailing_return {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[body_start..trim_end])?;
        let mut out: Vec<Stmt> = stmts;
        if let Some(value) = residual.into_iter().next_back() {
            out.push(Stmt::Return(Some(value)));
        }
        return Ok(out);
    }
    let mut out: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
    if !swap_present
        && let Some(ret) = with_post_cleanup_return(code, stream, body_end, region_end)?
    {
        out.push(ret);
    }
    Ok(out)
}

/// Recover the `with cm: return <value>` idiom where the returned value is re-materialized AFTER the
/// implicit `__exit__(None, None, None)` cleanup rather than stashed across it via `Swap(2)`. On the
/// normal-exit path `CPython` lays the cleanup block(s) then `LOAD <value>; RETURN_VALUE` (or
/// `RETURN_CONST`); the body region therefore ends at the cleanup with no on-stack value, so the
/// `swap_present` recovery never fires and the `return` is otherwise dropped. Skips every consecutive
/// cleanup block (one per open context manager), then recovers the return ONLY when it sits on the
/// straight-line normal-exit path: no exception handler (`PUSH_EXC_INFO`/`WITH_EXCEPT_START`) and no
/// forward conditional jump may intervene, otherwise the candidate is the surrounding function's own
/// epilogue (`return None`) reached on fall-through and must NOT be folded into the with body.
fn with_post_cleanup_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    region_end: usize,
) -> Result<Option<Stmt>> {
    let mut ret_start: usize = body_end;
    let mut cleanups: usize = 0;
    while let Some(next) = skip_with_cleanup_block(stream, ret_start, region_end) {
        ret_start = next;
        cleanups += 1;
    }
    if cleanups == 0 {
        return Ok(None);
    }
    let Some(ret_idx): Option<usize> = (ret_start..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(None);
    };
    let guarded: bool = (ret_start..ret_idx).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
        ) || is_forward_cond_jump(&stream.ops[k])
    });
    if guarded {
        return Ok(None);
    }
    recover_return_at(code, stream, ret_start, region_end)
}

/// Whether the with-cleanup tail at `body_end` is the value-returning idiom: one implicit
/// `__exit__(None, None, None)` cleanup block per open `with` (`[SWAP 2] LOAD_CONST None x3; CALL;
/// POP`, modulo CACHE/NOP) terminated by `RETURN`. Multi-item / nested `with` bodies returning a
/// value emit ONE such cleanup block per context manager before the shared `RETURN`, so the scan
/// must consume every consecutive cleanup block, not just the first.
fn is_with_trailing_return(stream: &DecodedStream, body_end: usize, region_end: usize) -> bool {
    let mut i: usize = body_end;
    while let Some(next) = skip_with_cleanup_block(stream, i, region_end) {
        i = next;
    }
    while i < region_end {
        match &stream.ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return true,
            _ => return false,
        }
    }
    false
}

/// One implicit `__exit__(None, None, None)` cleanup block on the value-return exit path:
/// an optional leading `SWAP 2` (stashing the return value below the manager), three `LOAD_CONST
/// None` pushes, the exit `CALL`, and the discarding `POP` (modulo CACHE/NOP). Returns the index
/// past the block, or `None` when no cleanup block begins at `start`.
fn skip_with_cleanup_block(
    stream: &DecodedStream,
    start: usize,
    region_end: usize,
) -> Option<usize> {
    let mut i: usize = first_significant(stream, start, region_end)?;
    while matches!(stream.ops[i], CanonicalOp::Swap(_) | CanonicalOp::RotN(_)) {
        i = first_significant(stream, i + 1, region_end)?;
    }
    let mut loads: usize = 0;
    while i < region_end && loads < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                loads += 1;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => return None,
        }
        i += 1;
    }
    if loads < 3 {
        return None;
    }
    i = first_significant(stream, i, region_end)?;
    if !matches!(
        stream.ops[i],
        CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
    ) {
        return None;
    }
    i = first_significant(stream, i + 1, region_end)?;
    if !matches!(stream.ops[i], CanonicalOp::Pop) {
        return None;
    }
    Some(i + 1)
}

/// The with-body ends where the innermost implicit `__exit__(None, None, None)` cleanup begins.
/// The cleanup is three `LOAD_CONST None` pushes feeding the exit `CALL` whose result is `POP`ped
/// (`POP_BLOCK` decodes to `Nop` here, so the None-triple is the portable marker). Requiring the
/// trailing `CALL; POP` distinguishes the cleanup from a body's own three-constant op such as
/// `BUILD_SLICE` (the `payload[::-1]` slice in a nested `with` body). A greedy backward trim is
/// wrong: it cannot tell the body's own trailing call from the cleanup call and devours real
/// statements (the `with lock: print(...)` body collapsing to `pass`).
fn with_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    for i in lo..hi {
        if is_none_const_push(&stream.ops[i]) && is_exit_none_triple(stream, i, hi) {
            return i;
        }
    }
    hi
}

/// A `None` push that feeds the implicit `__exit__(None, None, None)` cleanup. Pre-3.15 emits
/// `LOAD_CONST None`; 3.15+ emits `LOAD_COMMON_CONSTANT 7` (the `None` common-constant slot), so
/// both forms mark the cleanup triple.
#[inline]
fn is_none_const_push(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7)
    )
}

/// Three consecutive `LOAD_CONST None` (modulo CACHE/NOP) immediately feeding the implicit
/// `__exit__` `CALL` - i.e. a genuine `with`-cleanup block, not a body-level three-constant push
/// (e.g. the `payload[::-1]` slice literal which feeds `BUILD_SLICE`, not a call). The exit call's
/// result is then discarded by `POP` (sync) or awaited via `GET_AWAITABLE` (async), so only the
/// trailing `CALL` is required to discriminate.
fn is_exit_none_triple(stream: &DecodedStream, start: usize, hi: usize) -> bool {
    let mut seen: usize = 0;
    let mut i: usize = start;
    while i < hi && seen < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                seen += 1;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => return false,
        }
        i += 1;
    }
    if seen < 3 {
        return false;
    }
    first_significant(stream, i, hi).is_some_and(|call: usize| {
        matches!(
            stream.ops[call],
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
        )
    })
}

fn extend_try_body(
    code: &CodeObject,
    stream: &DecodedStream,
    try_end: usize,
    handler_start: usize,
) -> usize {
    let mut end: usize = try_end;
    let mut balanced: bool = try_end
        .checked_sub(1)
        .and_then(|p: usize| stream.ops.get(p))
        .is_some_and(|op: &CanonicalOp| {
            matches!(
                op,
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::StoreAttr(_)
                    | CanonicalOp::StoreSubscr
            )
        });
    while end < handler_start {
        match stream.ops.get(end) {
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)) => {
                end += 1;
            }
            Some(CanonicalOp::ReturnConst(slot)) if balanced && is_const_none(code, *slot) => {
                break;
            }
            Some(
                CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreAttr(_)
                | CanonicalOp::StoreSubscr
                | CanonicalOp::Pop,
            ) => {
                end += 1;
                balanced = true;
            }
            _ => break,
        }
    }
    end
}

fn is_const_none(code: &CodeObject, slot: crate::bytecode::opcode::ConstIndex) -> bool {
    matches!(
        load_const(code, slot, 0),
        Ok(Expr::Constant {
            value: ConstValue::None,
            ..
        })
    )
}

fn trim_try_body_jump(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
            )
        )
    {
        end -= 1;
    }
    end
}

fn parse_except_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    if !matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::PushExcInfo)
    ) && matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::Dup | CanonicalOp::Pop)
    ) {
        return parse_pre311_except_handlers(code, stream, handler_start, region_end);
    }
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    if matches!(stream.ops.get(i), Some(CanonicalOp::PushExcInfo)) {
        i += 1;
    }
    while i < region_end {
        while i < region_end && matches!(stream.ops[i], CanonicalOp::Nop | CanonicalOp::Cache) {
            i += 1;
        }
        if i >= region_end {
            break;
        }
        let clause_start: usize = i;
        let mut check_at: Option<usize> = None;
        for k in clause_start..region_end {
            if matches!(
                stream.ops[k],
                CanonicalOp::CheckExcMatch | CanonicalOp::CheckEgMatch
            ) {
                check_at = Some(k);
                break;
            }
            if matches!(stream.ops[k], CanonicalOp::Reraise(_)) {
                break;
            }
        }
        let Some(check_idx): Option<usize> = check_at else {
            let bare_start: usize =
                if matches!(stream.ops.get(clause_start), Some(CanonicalOp::Pop)) {
                    clause_start + 1
                } else {
                    clause_start
                };
            let bare_end: usize = bare_except_body_end(stream, bare_start, region_end);
            let bare_body: Vec<Stmt> = structure_stmts(code, stream, bare_start, bare_end)?;
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: non_empty(bare_body),
                line: None,
            });
            break;
        };
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[clause_start..check_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let dispatch_idx: usize = check_idx + 1;
        let next_handler: usize = if matches!(
            stream.ops.get(dispatch_idx),
            Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_))
        ) {
            resolve_jump_target(stream, dispatch_idx, &stream.ops[dispatch_idx])
                .filter(|t: &usize| *t > dispatch_idx && *t <= region_end)
                .unwrap_or(region_end)
        } else {
            region_end
        };
        let mut body_start: usize =
            first_significant(stream, dispatch_idx + 1, next_handler).unwrap_or(dispatch_idx + 1);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
            }
            _ => {}
        }
        let body_end: usize = if name.is_some() {
            handler_body_end_at_pop_except(stream, body_start, next_handler)
        } else {
            handler_body_end(stream, body_start, next_handler)
        };
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_handler;
        if matches!(stream.ops.get(i), Some(CanonicalOp::Reraise(_))) {
            break;
        }
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

fn parse_pre311_except_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    while i < region_end {
        while i < region_end
            && matches!(
                stream.ops[i],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        {
            i += 1;
        }
        if i >= region_end {
            break;
        }
        let clause_start: usize = i;
        if is_pre311_reraise_epilogue(stream, clause_start, region_end) {
            break;
        }
        let is_bare: bool = matches!(stream.ops[clause_start], CanonicalOp::Pop);
        if is_bare {
            let body_start: usize = pre311_skip_three_pops(stream, clause_start, region_end);
            let body_end: usize = pre311_handler_body_end(stream, body_start, region_end);
            let next: usize = pre311_advance_after_handler(stream, body_end, region_end);
            let body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: non_empty(body),
                line: None,
            });
            i = next;
            continue;
        }
        if !matches!(stream.ops[clause_start], CanonicalOp::Dup) {
            break;
        }
        let mut j: usize = clause_start + 1;
        let type_start: usize = j;
        let mut type_end: Option<usize> = None;
        let mut next_handler: usize = region_end;
        while j < region_end {
            match &stream.ops[j] {
                CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch) => {
                    type_end = Some(j);
                    let dispatch: usize = j + 1;
                    next_handler = resolve_jump_target(stream, dispatch, &stream.ops[dispatch])
                        .filter(|t: &usize| *t > dispatch && *t <= region_end)
                        .unwrap_or(region_end);
                    j = dispatch + 1;
                    break;
                }
                CanonicalOp::Other(121, _) => {
                    type_end = Some(j);
                    next_handler = resolve_jump_target(stream, j, &stream.ops[j])
                        .filter(|t: &usize| *t > j && *t <= region_end)
                        .unwrap_or(region_end);
                    j += 1;
                    break;
                }
                _ => j += 1,
            }
        }
        let Some(type_end_idx): Option<usize> = type_end else {
            break;
        };
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[type_start..type_end_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let after_dispatch: usize = j;
        let mut body_start: usize = pre311_skip_first_pop(stream, after_dispatch, next_handler);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Nop)) {
                    body_start += 1;
                }
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Nop)) {
                    body_start += 1;
                }
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
            }
            _ => {}
        }
        let body_end: usize = pre311_handler_body_end(stream, body_start, next_handler);
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_handler;
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

/// Pre-3.11 closes each `SETUP_EXCEPT`/`SETUP_FINALLY` handler chain with an implicit re-raise
/// epilogue: when no `except` clause matched, the interpreter discards the saved exception triple's
/// top and runs `END_FINALLY`, which re-raises. The compiler emits this as a lone `POP_TOP`
/// immediately followed by `END_FINALLY` (recorded in `pre311_end_finally_idx`). A genuine bare
/// `except:` instead discards the full three-tuple with `POP_TOP * 3` before its body. The handler
/// parser must stop at this epilogue rather than mistake the single discard for a bare `except: pass`,
/// which would fabricate a phantom handler on every nested try/except. Gated implicitly to pre-3.11 by
/// `pre311_end_finally_idx` being populated only there.
fn is_pre311_reraise_epilogue(stream: &DecodedStream, clause_start: usize, hi: usize) -> bool {
    if !matches!(stream.ops.get(clause_start), Some(CanonicalOp::Pop)) {
        return false;
    }
    let mut k: usize = clause_start + 1;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::ExtendedArg(_))
        )
    {
        k += 1;
    }
    stream.pre311_end_finally_idx.contains(&k)
}

fn pre311_skip_three_pops(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    let mut pops: u32 = 0;
    while k < hi && pops < 3 {
        match stream.ops.get(k) {
            Some(CanonicalOp::Pop) => {
                pops += 1;
                k += 1;
            }
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)) => k += 1,
            _ => break,
        }
    }
    k
}

fn pre311_skip_first_pop(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        k += 1;
    }
    if matches!(stream.ops.get(k), Some(CanonicalOp::Pop)) {
        k += 1;
    }
    k
}

fn pre311_handler_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PopExcept
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::Reraise(_)
            )
        )
    {
        end -= 1;
    }
    end
}

fn pre311_advance_after_handler(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PopExcept
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::Reraise(_)
            )
        )
    {
        k += 1;
    }
    k
}

fn parse_except_star_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    while i < region_end {
        let check_at: Option<usize> = (i..region_end)
            .take_while(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Reraise(_)))
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch));
        let Some(check_idx): Option<usize> = check_at else {
            break;
        };
        let type_start: usize = eg_clause_type_start(stream, check_idx, i);
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[type_start..check_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let dispatch_idx: usize =
            first_significant(stream, check_idx + 1, region_end).unwrap_or(check_idx + 1);
        let dispatch_idx: usize =
            if matches!(stream.ops.get(dispatch_idx), Some(CanonicalOp::Copy(1))) {
                first_significant(stream, dispatch_idx + 1, region_end).unwrap_or(dispatch_idx + 1)
            } else {
                dispatch_idx
            };
        let next_clause: usize =
            resolve_jump_target(stream, dispatch_idx, &stream.ops[dispatch_idx])
                .filter(|t: &usize| *t > dispatch_idx && *t <= region_end)
                .unwrap_or(region_end);
        let mut body_start: usize =
            first_significant(stream, dispatch_idx + 1, next_clause).unwrap_or(dispatch_idx + 1);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
            }
            _ => {}
        }
        let body_end: usize = eg_body_end(stream, body_start, next_clause);
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_clause;
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

fn eg_clause_type_start(stream: &DecodedStream, check_idx: usize, lo: usize) -> usize {
    let mut i: usize = check_idx;
    while i > lo
        && !matches!(
            stream.ops.get(i - 1),
            Some(
                CanonicalOp::Pop
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PushExcInfo
                    | CanonicalOp::Copy(_)
                    | CanonicalOp::ListAppend
            )
        )
    {
        i -= 1;
    }
    i
}

fn eg_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    (lo..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::ListAppend
                    | CanonicalOp::PopExcept
            )
        })
        .unwrap_or(hi)
}

fn strip_named_exc_cleanup(body: &mut Vec<Stmt>, bound: &str) {
    body.retain(|s: &Stmt| !is_bound_clear_stmt(s, bound));
}

fn is_bound_clear_stmt(stmt: &Stmt, bound: &str) -> bool {
    match stmt {
        Stmt::Assign { targets, value, .. } => {
            targets.len() == 1
                && matches!(&targets[0], Expr::Name { id, .. } if id == bound)
                && matches!(
                    value,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                )
        }
        Stmt::Delete(targets) => targets
            .iter()
            .all(|e: &Expr| matches!(e, Expr::Name { id, .. } if id == bound)),
        _ => false,
    }
}

fn handler_body_end_at_pop_except(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut depth: u32 = 0;
    let mut pop_at: Option<usize> = None;
    for k in lo..hi {
        match stream.ops[k] {
            CanonicalOp::PushExcInfo => depth += 1,
            CanonicalOp::PopExcept if depth == 0 => {
                pop_at = Some(k);
                break;
            }
            CanonicalOp::PopExcept => depth -= 1,
            _ => {}
        }
    }
    let Some(pop): Option<usize> = pop_at else {
        return handler_body_end(stream, lo, hi);
    };
    let after_cleanup: usize = skip_handler_name_cleanup(stream, pop + 1, hi);
    let trailing: usize = handler_trailing_terminator_end(stream, after_cleanup, hi);
    if trailing > pop { trailing } else { pop }
}

fn skip_handler_name_cleanup(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut i: usize = lo;
    while i < hi
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        i += 1;
    }
    let load_const: Option<&CanonicalOp> = stream.ops.get(i);
    let store: Option<&CanonicalOp> = stream.ops.get(i + 1);
    let delete: Option<&CanonicalOp> = stream.ops.get(i + 2);
    let cleared: bool = matches!(load_const, Some(CanonicalOp::LoadConst(_)))
        && matches!(
            store,
            Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_))
        )
        && matches!(
            delete,
            Some(CanonicalOp::DeleteFast(_) | CanonicalOp::DeleteName(_))
        );
    if cleared { i + 3 } else { lo }
}

fn handler_trailing_terminator_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        k += 1;
    }
    let mut last_significant: usize = k;
    while k < hi {
        match stream.ops[k] {
            CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::Reraise(_) => return last_significant,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_) => {
                last_significant = k + 1;
                k += 1;
                while k < hi
                    && matches!(
                        stream.ops.get(k),
                        Some(CanonicalOp::Cache | CanonicalOp::Nop)
                    )
                {
                    k += 1;
                }
                return last_significant;
            }
            CanonicalOp::Cache | CanonicalOp::Nop => {}
            _ => {
                last_significant = k + 1;
            }
        }
        k += 1;
    }
    last_significant
}

fn handler_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::PopExcept
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Reraise(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
            )
        )
    {
        end -= 1;
    }
    end
}

/// `async for` has no `FOR_ITER`: the iterator protocol is `GET_AITER` (over the iterable) then a
/// loop whose header is `GET_ANEXT`, each iteration awaiting `__anext__` (a `SEND`/`YIELD_VALUE`
/// poll on 3.11+, `YIELD_FROM` pre-3.11) and storing the loop variable, terminated by
/// `END_ASYNC_FOR`. The real loop back-edge targets the `GET_ANEXT` header (3.11+) or the
/// `SETUP_FINALLY` immediately preceding it (pre-3.11). Recognised before the generic back-edge scan
/// so the await-poll send-loop and the outer iteration loop are not mistaken for a bare `while`.
fn find_async_for_loop(stream: &DecodedStream, lo: usize, hi: usize) -> Option<LoopRegion> {
    let anext: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAnext))?;
    let aiter: usize = (lo..anext)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))?;
    let end_async_for: usize =
        (anext..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))?;
    let back_edge: usize = (anext + 1..end_async_for)
        .rfind(|&k: &usize| {
            is_back_edge(&stream.ops[k])
                && !is_async_send_back_edge(stream, k)
                && !is_async_cleanup_throw_back_edge(stream, k)
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t <= anext && t >= aiter)
        })
        .unwrap_or_else(|| end_async_for.saturating_sub(1).max(anext + 1));
    let store_idx: usize = async_for_store_idx(stream, anext + 1, back_edge);
    Some(LoopRegion {
        kind: LoopKind::AsyncFor,
        header: anext,
        body_start: store_idx,
        body_end: back_edge,
        back_edge,
        exit: (end_async_for + 1).min(hi),
        infinite: false,
    })
}

/// Pre-3.8 (`3.5`-`3.7`) `async for` has no `END_ASYNC_FOR`: the iterator-exhaustion break is a
/// `SETUP_EXCEPT(StopAsyncIteration)` whose handler does `DUP_TOP / LOAD_GLOBAL StopAsyncIteration /
/// COMPARE_OP(exception match) / POP_JUMP_IF_TRUE exit`. The synthesized pre-3.11 exception table
/// otherwise makes `find_try_region` recover the loop as a raw `try/except StopAsyncIteration`. This
/// recognizer reconstructs the `For{is_async:true}` region from that idiom; it is gated to `minor<=7`
/// at the call site so the `END_ASYNC_FOR` path (`3.8`+, commit `9c20a2f`) is never disturbed.
fn find_legacy_async_for_loop(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<LoopRegion> {
    let anext: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAnext))?;
    if (anext..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor)) {
        return None;
    }
    let aiter: usize = (lo..anext)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))?;
    let (handler_start, matched, region_end): (usize, usize, usize) =
        legacy_async_for_handler(code, stream, anext + 1, hi)?;
    let store_idx: usize = async_for_store_idx(stream, anext + 1, handler_start);
    let post_store_jump: Option<usize> = (store_idx + 1..handler_start).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
        )
    });
    let inline_body_start: Option<usize> = post_store_jump.and_then(|j: usize| {
        resolve_jump_target(stream, j, &stream.ops[j])
            .filter(|t: &usize| *t > handler_start && *t < region_end)
    });
    let fallthrough_body: Option<(usize, usize)> = if inline_body_start.is_none() {
        legacy_async_for_fallthrough_body(stream, handler_start, matched, anext, aiter)
    } else {
        None
    };
    let body_start: usize = match fallthrough_body {
        Some((start, _)) => start,
        None => inline_body_start.unwrap_or(store_idx + 1),
    };
    let back_edge: usize = (body_start..region_end)
        .rfind(|&k: &usize| {
            is_back_edge(&stream.ops[k])
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t <= anext && t >= aiter)
        })
        .unwrap_or_else(|| post_store_jump.unwrap_or(handler_start));
    let body_end: usize = match (fallthrough_body, inline_body_start) {
        (Some((_, end)), _) => end,
        (None, Some(_)) => back_edge.max(body_start),
        (None, None) => handler_start.min(back_edge.max(store_idx + 1)),
    };
    Some(LoopRegion {
        kind: LoopKind::AsyncFor,
        header: anext,
        body_start,
        body_end,
        back_edge,
        exit: region_end.min(hi),
        infinite: false,
    })
}

/// Recover the inline loop body of a pre-3.8 `async for` laid out in the `StopAsyncIteration`
/// handler's NON-matched fallthrough: `CPython` 3.5-3.7 emits short bodies (`continue` / `break` / a
/// few statements) between the handler's `END_FINALLY` and the trailing back-edge that returns to the
/// `__anext__` poll. The matched branch (loop exhaustion) lands at `matched` and runs cleanup; the body
/// occupies `[end_finally+1, last_back_edge)` where `last_back_edge` is the final jump to the poll
/// before `matched`. Returns `(body_start, body_end)` only when that span is non-empty (a real body),
/// so the empty-body (`pass`) loop keeps its existing `[store+1, handler_start)` empty span.
fn legacy_async_for_fallthrough_body(
    stream: &DecodedStream,
    handler_start: usize,
    matched: usize,
    anext: usize,
    aiter: usize,
) -> Option<(usize, usize)> {
    let end_finally: usize =
        (handler_start..matched).find(|k: &usize| stream.pre311_end_finally_idx.contains(k))?;
    let body_start: usize = end_finally + 1;
    let back_edge: usize = (body_start..matched).rfind(|&k: &usize| {
        is_back_edge(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t <= anext && t >= aiter)
    })?;
    if back_edge <= body_start {
        return None;
    }
    Some((body_start, back_edge))
}

/// Locate the `StopAsyncIteration` exhaustion handler of a pre-3.8 `async for` whose `__anext__` poll
/// begins at `anext`. The handler is laid out inline between the loop-variable store and the real
/// loop body, with shape `DUP_TOP / LOAD_GLOBAL StopAsyncIteration / COMPARE_OP(exception match) /
/// POP_JUMP_IF_TRUE matched`: the matched branch runs the exception cleanup (`POP_TOP*` /
/// `POP_EXCEPT`) before falling through to post-loop code. Returns `(handler_start, region_end)` - the
/// `DUP_TOP` index (the inline handler's start) and the first op past the matched-branch cleanup (the
/// loop exit) - or `None` when the shape is not a `StopAsyncIteration` break (so a real `try/except`
/// is unaffected).
fn legacy_async_for_handler(
    code: &CodeObject,
    stream: &DecodedStream,
    anext: usize,
    hi: usize,
) -> Option<(usize, usize, usize)> {
    let dup: usize = (anext..hi).find(|&k: &usize| {
        matches!(stream.ops[k], CanonicalOp::Dup)
            && matches!(
                significant_after(stream, k + 1, hi),
                Some((_, CanonicalOp::LoadGlobal(_) | CanonicalOp::LoadName(_)))
            )
    })?;
    let (global_idx, _): (usize, &CanonicalOp) = significant_after(stream, dup + 1, hi)?;
    let name_arg: u32 = match stream.ops[global_idx] {
        CanonicalOp::LoadGlobal(i) | CanonicalOp::LoadName(i) => i,
        _ => return None,
    };
    if name_at(&code.names, name_arg, global_idx, "name")
        .ok()
        .as_deref()
        != Some("StopAsyncIteration")
    {
        return None;
    }
    let (compare_idx, _): (usize, &CanonicalOp) = significant_after(stream, global_idx + 1, hi)?;
    if !matches!(
        stream.ops[compare_idx],
        CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
    ) {
        return None;
    }
    let (jump_idx, jump_op): (usize, &CanonicalOp) =
        significant_after(stream, compare_idx + 1, hi)?;
    if !matches!(
        jump_op,
        CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
    ) {
        return None;
    }
    let matched: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= hi)?;
    Some((dup, matched, skip_async_for_cleanup(stream, matched, hi)))
}

/// Skip the `StopAsyncIteration` exhaustion cleanup (`POP_TOP` / `POP_EXCEPT` / `NOP` from
/// `END_FINALLY` / `POP_BLOCK`) that follows the matched-branch landing of a pre-3.8 `async for`,
/// returning the first op of the real post-loop body. `SETUP_LOOP` / `SETUP_EXCEPT` / `SETUP_FINALLY`
/// all decode to `Nop` on pre-3.8, so a naive skip walks straight past a `try:` or loop that OPENS
/// immediately after the exhaustion cleanup, swallowing its setup into the loop exit and stranding the
/// enclosing handler. Halt at any `Nop` that begins a new protected region - i.e. the next op's byte
/// offset matches a synthesized exception-table `start` (the byte after a `SETUP_EXCEPT/FINALLY`) - so
/// that setup stays available to the post-loop recursion.
fn skip_async_for_cleanup(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi
        && matches!(
            stream.ops[i],
            CanonicalOp::Pop | CanonicalOp::PopExcept | CanonicalOp::Nop | CanonicalOp::Cache
        )
    {
        if matches!(stream.ops[i], CanonicalOp::Nop) && opens_protected_region(stream, i) {
            break;
        }
        i += 1;
    }
    i
}

/// The next significant op (skipping `NOP`/`CACHE`/`EXTENDED_ARG`) at or after `from`, with its index.
fn significant_after(
    stream: &DecodedStream,
    from: usize,
    hi: usize,
) -> Option<(usize, &CanonicalOp)> {
    (from..hi)
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
            )
        })
        .map(|k: usize| (k, &stream.ops[k]))
}

/// The index of the loop-variable `STORE_*`/unpack op for an `async for`: the first store after the
/// `__anext__` await poll (`LOAD_CONST None` / `SEND` / `YIELD_VALUE` / `RESUME` /
/// `JUMP_BACKWARD_NO_INTERRUPT` / `END_SEND` on 3.11+, or `LOAD_CONST None` / `YIELD_FROM` /
/// `POP_BLOCK` pre-3.11). `recover_async_for_target` then reads the target starting here.
fn async_for_store_idx(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    (from..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::StoreFastStoreFast(_, _)
                    | CanonicalOp::UnpackSequence(_)
                    | CanonicalOp::UnpackEx(_)
                    | CanonicalOp::BuildTuple(_)
            )
        })
        .unwrap_or(from)
}

/// Detect a `while True:` whose only back-edge is unconditional and whose head is a leading
/// break-test. The compiler emits `while True:` with no loop test, so the header op stream is a test
/// feeding a `POP_JUMP_IF_x` to the body label, an inline break-exit block, the loop body, then the
/// unconditional back-edge. Recognised before the generic cond-back / bottom-test scan so the body's
/// `if cond: return` / `if cond: break` guards (which themselves carry forward or backward cond-jumps
/// to the header or the exit) are not mistaken for the loop's test. Returns the infinite `LoopRegion`
/// spanning the whole loop, body starting at the header (the leading break-test is re-derived by
/// `structure_infinite_while_body`).
fn has_for_iter(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::ForIter(_)))
}

/// Whether a `while`-loop header at `header` is gated by an entry test - a forward cond-jump
/// immediately before the header (skipping padding) that skips the loop when its condition fails.
/// A genuine `while cond:` compiles `cond; POP_JUMP_IF_FALSE exit; header: body` so the header is
/// preceded by such a gate; a `while True:` has no entry test, so the op before its header is plain
/// body / function setup. Distinguishes the two when both share an unconditional back-edge.
fn has_loop_entry_gate(stream: &DecodedStream, lo: usize, header: usize) -> bool {
    let Some(prev): Option<usize> = (lo..header).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    is_forward_cond_jump(&stream.ops[prev])
        && !is_chain_cond_jump(&stream.ops, prev)
        && resolve_jump_target(stream, prev, &stream.ops[prev]).is_some_and(|t: usize| t > header)
}

fn find_infinite_while(stream: &DecodedStream, lo: usize, hi: usize) -> Option<LoopRegion> {
    for header in lo..hi {
        let back_edge: Option<usize> = (header + 1..hi).find(|&j: &usize| {
            is_back_edge(&stream.ops[j])
                && !is_async_send_back_edge(stream, j)
                && !is_async_cleanup_throw_back_edge(stream, j)
                && resolve_jump_target(stream, j, &stream.ops[j]) == Some(header)
        });
        let Some(back_edge): Option<usize> = back_edge else {
            continue;
        };
        if has_loop_entry_gate(stream, lo, header) {
            continue;
        }
        let first_cond: Option<usize> = (header..back_edge).find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        });
        let Some(first_cond): Option<usize> = first_cond else {
            continue;
        };
        let Some(body_label): Option<usize> =
            resolve_jump_target(stream, first_cond, &stream.ops[first_cond])
                .filter(|t: &usize| *t > first_cond && *t < back_edge)
        else {
            continue;
        };
        let block_start: usize = match first_significant(stream, first_cond + 1, body_label) {
            Some(s) => s,
            None => continue,
        };
        if block_start >= body_label || !block_exits_loop(stream, block_start, body_label) {
            continue;
        }
        let exit: usize = infinite_break_exit(stream, block_start, body_label, back_edge, hi);
        return Some(LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: back_edge,
            back_edge,
            exit,
            infinite: true,
        });
    }
    None
}

/// The post-loop landing of a `while True:` break. When the break action `[lo, hi_block)` is a lone
/// unconditional forward jump to code past the back-edge (the 3.11 layout, where the exit block lives
/// after the back-edge), the loop exit is that jump's target. Otherwise the break action is the inline
/// exit block itself (pre-3.11 / 3.12+ layout) and the exit is its start.
fn infinite_break_exit(
    stream: &DecodedStream,
    lo: usize,
    hi_block: usize,
    back_edge: usize,
    hi: usize,
) -> usize {
    let only_jump: bool = (lo..hi_block).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
        )
    });
    if only_jump
        && let Some(t) = resolve_jump_target(stream, lo, &stream.ops[lo])
        && t > back_edge
        && t <= hi
    {
        return t;
    }
    lo
}

/// Whether a straight-line block `[lo, hi)` is a loop exit block: it ends by returning, raising, or
/// jumping clean out of the loop (no fall-through back into the body). Used to confirm a candidate
/// `while True:` break-exit block sitting inline between the leading break-test and the loop body.
fn block_exits_loop(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let last: usize = (lo..hi)
        .rev()
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .unwrap_or(lo);
    matches!(
        stream.ops.get(last),
        Some(
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
        )
    )
}

/// Whether a leading `if cond:` guard physically encloses the loop `find_loop` selected, so the loop
/// must be structured as the if-body rather than as the region's top-level statement. `CPython` lays
/// `if cond: <loop>` as `cond; POP_JUMP_IF_FALSE after; <loop>; after:`, putting the loop's whole span
/// inside the if-body. `find_loop` (which scans for the innermost loop shape) would otherwise claim the
/// region, emit the guard test as a bare head expression, and dedent the loop out of its `if`. The
/// guard is a non-chain forward cond-jump appearing before the loop header whose target lands at or
/// past the loop's back-edge (the if-join is after the loop), with no intervening loop header between
/// the region start and the guard - i.e. the guard is the region's first control-flow construct.
fn leading_guard_if_encloses_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> bool {
    if stream.version.major() >= 3 {
        return false;
    }
    let Some(guard): Option<usize> = (lo..region.header).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    }) else {
        return false;
    };
    let Some(target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard]) else {
        return false;
    };
    target > region.back_edge && target <= hi
}

fn find_loop(stream: &DecodedStream, lo: usize, hi: usize) -> Option<LoopRegion> {
    if let Some(region) = find_async_for_loop(stream, lo, hi) {
        return Some(region);
    }
    if !has_for_iter(stream, lo, hi)
        && let Some(region) = find_infinite_while(stream, lo, hi)
    {
        return Some(region);
    }
    let mut best: Option<LoopRegion> = None;
    for i in lo..hi {
        if matches!(
            stream.ops[i],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) {
            let raw_exit: usize =
                resolve_jump_target(stream, i, &stream.ops[i]).filter(|t: &usize| *t > i)?;
            let back_edge: usize = (i + 1..hi)
                .filter(|&j: &usize| is_back_edge(&stream.ops[j]))
                .find(|&j: &usize| {
                    resolve_jump_target(stream, j, &stream.ops[j]).is_some_and(|t: usize| t <= i)
                })
                .unwrap_or_else(|| raw_exit.min(hi).saturating_sub(1).max(i + 1));
            let exit_via_foriter: usize = raw_exit.min(hi).max((back_edge + 1).min(hi));
            let body_start: usize = (i + 1).min(hi);
            let region: LoopRegion = LoopRegion {
                kind: LoopKind::For,
                header: i,
                body_start,
                body_end: exit_via_foriter,
                back_edge,
                exit: exit_via_foriter,
                infinite: false,
            };
            return Some(region);
        }
    }
    for j in lo..hi {
        if (is_cond_back_edge(&stream.ops[j]) || is_cond_jump_with_backward_target(stream, j))
            && let Some(t) = resolve_jump_target(stream, j, &stream.ops[j])
            && t >= lo
            && t < j
        {
            let header: usize = t;
            let region: LoopRegion = LoopRegion {
                kind: LoopKind::While,
                header,
                body_start: header,
                body_end: cond_expr_start(stream, j, header),
                back_edge: j,
                exit: (j + 1).min(hi),
                infinite: false,
            };
            if best.is_none_or(|b: LoopRegion| header < b.header) {
                best = Some(region);
            }
            continue;
        }
        if is_back_edge(&stream.ops[j])
            && let Some(t) = resolve_jump_target(stream, j, &stream.ops[j])
            && t >= lo
            && t < j
        {
            if is_async_send_back_edge(stream, j) || is_async_cleanup_throw_back_edge(stream, j) {
                continue;
            }
            let header: usize = t;
            let conds: Vec<usize> = (header..j)
                .filter(|&k: &usize| {
                    is_forward_cond_jump(&stream.ops[k])
                        && !is_chain_cond_jump(&stream.ops, k)
                        && resolve_jump_target(stream, k, &stream.ops[k])
                            .is_some_and(|tt: usize| tt > j)
                })
                .collect();
            let bottom_cond: Option<usize> = conds
                .last()
                .copied()
                .filter(|&c: &usize| is_bottom_test(stream, c, j));
            let region: LoopRegion = while_region(stream, header, j, hi, &conds, bottom_cond);
            if best.is_none_or(|b: LoopRegion| header < b.header) {
                best = Some(region);
            }
        }
    }
    best
}

/// True when a `for` `region` is the body of an enclosing `if` constant/expression guard: a forward
/// conditional jump physically precedes the `FOR_ITER` header and skips *over the whole loop* (its
/// target lands past the loop's back-edge). The loop must then be structured *inside* the guard's
/// `if`, so `structure_stmts` defers `find_loop` to its cond-jump path, which emits the `if` and
/// recurses into the loop. Without this, `if cond:\n    for x in it: ...` collapses to a bare `for`
/// and the guard is lost. Comparing against `back_edge` (not `exit`) is deliberate: `find_loop` sets
/// `exit` to the `FOR_ITER` exhaustion target, which a dead `return None` epilogue can push past the
/// `if`-skip landing; the back-edge is the last real body op, so a target beyond it unambiguously
/// skips the loop. Restricted to `For`/`AsyncFor`: a `while` loop's entry test is itself a forward
/// `JUMP_IF_FALSE` that exits the loop, and treating it as an outer guard would strip the loop's own
/// top condition.
fn loop_enclosed_by_guard(stream: &DecodedStream, lo: usize, region: &LoopRegion) -> bool {
    if !matches!(region.kind, LoopKind::For | LoopKind::AsyncFor) {
        return false;
    }
    (lo..region.header).any(|j: usize| {
        is_forward_cond_jump(&stream.ops[j])
            && !is_chain_cond_jump(&stream.ops, j)
            && !is_value_form_shortcircuit(&stream.ops, j)
            && resolve_jump_target(stream, j, &stream.ops[j])
                .is_some_and(|t: usize| t > region.back_edge)
    })
}

/// True when a `try` `region` sits INSIDE a loop body in `[lo, hi)` - the loop's header precedes the
/// try's protected span and the loop's back-edge runs past the try's handler region. `find_try_region`
/// scans the whole `[lo, hi)` window, so a `for term in it:\n    try: ...` (whose `SETUP_EXCEPT` and
/// handler are both nested in the loop body) is otherwise structured try-first, splitting the loop at
/// the `SETUP_EXCEPT` index: the loop body is amputated to the few ops before it (`for: pass`) and the
/// try surfaces detached at the loop's level. Defer to `find_loop` so the loop is structured first and
/// recurses into the body, where the try is recovered in place. Gated to pre-3.11 (`SETUP_LOOP`/
/// `SETUP_EXCEPT` block era): 3.11+ exception-table tries are already nested by the frame tree and the
/// modern construct matrix must not be perturbed.
fn try_enclosed_by_loop(stream: &DecodedStream, lo: usize, hi: usize, region: &TryRegion) -> bool {
    if !stream.is_pre_311() {
        return false;
    }
    let Some(loop_region): Option<LoopRegion> = find_loop(stream, lo, hi) else {
        return false;
    };
    loop_region.header < region.try_start
        && loop_region.back_edge > region.handler_start
        && loop_region.back_edge <= hi
}

/// Dual of `try_enclosed_by_loop`: true when the pre-3.8 `async for` `loop_region` sits INSIDE a real
/// `try:` whose protected span opens before the loop's `__anext__` header and whose handler lands at
/// or past the loop's exit. The 3.7 async-for gate in `structure_stmts` runs before the try path, so a
/// `try:\n    async for … :` would otherwise be recovered as a bare loop with its `except` clause
/// leaking out as an unstructured `if … exception matches …`. Deferring here lets `find_try_region`
/// surface the enclosing `try` first; its body recursion then re-enters and recovers the loop in place.
/// `find_try_region` already filters the loop's own `StopAsyncIteration` poll-guard rows, so the only
/// candidate it returns in this window is the genuine user `try`.
fn legacy_async_for_enclosed_by_try(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    loop_region: &LoopRegion,
) -> bool {
    if !stream.is_pre_311() {
        return false;
    }
    let Some(region): Option<TryRegion> = find_try_region(stream, lo, hi) else {
        return false;
    };
    region.try_start <= loop_region.header && region.handler_start >= loop_region.exit
}

/// True when the pre-3.8 `async for` `loop_region` sits INSIDE a *synchronous* `for`/`while` loop in
/// `[lo, hi)`. `find_legacy_async_for_loop` scans the whole window for the first `GET_ANEXT`, so a
/// `for i in it:\n    async for x in a: …` matches the inner async-for at the outer level: the enclosing
/// `for i`'s body is then truncated at the async-for header and the async-for chain is hoisted out as a
/// sibling (the `for i` body closes with a phantom `pass`). The enclosing loop is a `FOR_ITER` /
/// `FOR_LOOP` header (or a legacy `while` back-edge) whose protected span opens before the async-for's
/// `GET_AITER` and whose back-edge runs at or past the async-for's exit. Deferring here lets `find_loop`
/// structure the enclosing loop first; its body recursion then re-enters and recovers the async-for in
/// place. Gated to pre-3.11 like its `try` dual; the loop's own poll-guard rows are not loops, so the
/// only enclosing candidate is a genuine user `for`/`while`.
fn legacy_async_for_enclosed_by_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    loop_region: &LoopRegion,
) -> bool {
    if !stream.is_pre_311() {
        return false;
    }
    let aiter: usize = (lo..loop_region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))
        .unwrap_or(loop_region.header);
    for f in lo..aiter {
        if !matches!(
            stream.ops[f],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) {
            continue;
        }
        let Some(exit): Option<usize> =
            resolve_jump_target(stream, f, &stream.ops[f]).filter(|t: &usize| *t > f)
        else {
            continue;
        };
        if exit > loop_region.back_edge && exit <= hi {
            return true;
        }
    }
    for j in (loop_region.back_edge + 1).min(hi)..hi {
        if (is_cond_back_edge(&stream.ops[j]) || is_cond_jump_with_backward_target(stream, j))
            && let Some(header) = resolve_jump_target(stream, j, &stream.ops[j])
            && header >= lo
            && header < aiter
        {
            return true;
        }
    }
    false
}

fn while_region(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    hi: usize,
    conds: &[usize],
    bottom_cond: Option<usize>,
) -> LoopRegion {
    if let Some(bottom) = bottom_cond {
        let exit: usize = resolve_jump_target(stream, bottom, &stream.ops[bottom])
            .filter(|t: &usize| *t > back_edge)
            .unwrap_or(back_edge + 1);
        return LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: cond_expr_start(stream, bottom, header),
            back_edge,
            exit: exit.min(hi),
            infinite: false,
        };
    }
    let Some(&last_top): Option<&usize> = conds.last() else {
        return LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: back_edge,
            back_edge,
            exit: (back_edge + 1).min(hi),
            infinite: true,
        };
    };
    let exit: usize = conds
        .first()
        .copied()
        .and_then(|c: usize| {
            resolve_jump_target(stream, c, &stream.ops[c]).filter(|t: &usize| *t > back_edge)
        })
        .unwrap_or(back_edge + 1);
    LoopRegion {
        kind: LoopKind::While,
        header,
        body_start: last_top + 1,
        body_end: back_edge,
        back_edge,
        exit: exit.min(hi),
        infinite: false,
    }
}

fn is_bottom_test(stream: &DecodedStream, cond: usize, back_edge: usize) -> bool {
    (cond + 1..back_edge).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

/// A `STORE_*` at `idx` that is the store half of a walrus `(name := expr)`: it is immediately
/// preceded by the `Dup`/`Copy 1` that keeps the bound value on the stack as the surrounding
/// expression's operand. Structural mirror of `is_walrus_store` without the name lookup; the
/// `__classcell__`/`__class__` exclusion is irrelevant inside a while-test or comprehension filter.
fn is_walrus_store_shape(ops: &[CanonicalOp], idx: usize) -> bool {
    matches!(
        ops.get(idx),
        Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::StoreGlobal(_))
    ) && idx > 0
        && matches!(
            ops.get(idx - 1),
            Some(CanonicalOp::Dup | CanonicalOp::Copy(1))
        )
}

/// Walks backward from `cond` to the first op of the condition value-expression, halting at a value
/// boundary in `header..cond`. A walrus `Dup`/`Copy 1`; `STORE_*` pair is NOT a boundary: the store
/// binds the name but the duplicated value remains the live operand, so the scan steps THROUGH the
/// pair (mirroring `CPython`, which never truncates a value-expression at its walrus store). Without
/// this, `while (chunk := next(...)):` and `[... if (y := x*2) > 4]` lose their walrus left operand.
fn cond_expr_start(stream: &DecodedStream, cond: usize, header: usize) -> usize {
    let mut i: usize = cond;
    while i > header {
        let prev: usize = i - 1;
        if is_walrus_store_shape(&stream.ops, prev) && prev > header {
            i = prev - 1;
            continue;
        }
        if is_value_boundary(&stream.ops[prev]) {
            break;
        }
        i = prev;
    }
    i
}

/// Start of a compound bottom-test span: the first operand of a `while A and B and ...:` test laid
/// out just before the loop back-edge. Walks back from the back-edge cond-jump over each operand and
/// its short-circuit cond-jump (every intermediate `POP_JUMP_IF_*` whose target is the loop exit)
/// until a non-conjunct value boundary (a body store/pop) is reached, so the whole conjunct chain -
/// not merely the final operand - feeds `collect_while_conjuncts`.
fn bottom_test_start(
    stream: &DecodedStream,
    back_edge: usize,
    header: usize,
    exit: usize,
) -> usize {
    let mut start: usize = cond_expr_start(stream, back_edge, header);
    loop {
        let mut probe: usize = start;
        while probe > header
            && matches!(
                stream.ops.get(probe - 1),
                Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
            )
        {
            probe -= 1;
        }
        let Some(prev): Option<usize> = probe.checked_sub(1) else {
            break;
        };
        let is_exit_cond: bool = matches!(
            stream.ops.get(prev),
            Some(
                CanonicalOp::PopJumpIfFalse(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalseBackward(_)
                    | CanonicalOp::PopJumpIfTrueBackward(_)
            )
        ) && resolve_jump_target(stream, prev, &stream.ops[prev])
            .is_some_and(|t: usize| t >= exit || t <= header);
        if !is_exit_cond {
            break;
        }
        start = cond_expr_start(stream, prev, header);
    }
    start
}

fn structure_loop(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> Result<Vec<Stmt>> {
    let head: Vec<Stmt> = structure_stmts(code, stream, lo, region.header)?;
    let exit_return: Option<Expr> = loop_shared_exit_return(code, stream, region, hi);
    push_loop_frame(LoopFrame {
        header: region.header,
        exit: region.exit,
        exit_return,
    });
    let result: Result<Stmt> = (|| -> Result<Stmt> {
        let loop_stmt: Stmt = match region.kind {
            LoopKind::For => {
                let iter: Expr = recover_for_iter(code, stream, region, lo);
                let (target, body_start): (Expr, usize) = recover_for_target(code, stream, region)
                    .unwrap_or_else(|| {
                        (
                            Expr::Name {
                                id: "_".to_owned(),
                                ctx: ExprCtx::Store,
                                line: None,
                            },
                            region.body_start,
                        )
                    });
                let body: Vec<Stmt> = structure_stmts(code, stream, body_start, region.body_end)?;
                let orelse: Vec<Stmt> = loop_orelse(code, stream, region, hi)?;
                Stmt::For {
                    target,
                    iter,
                    body: non_empty(body),
                    orelse,
                    is_async: false,
                    line: None,
                }
            }
            LoopKind::AsyncFor => {
                let iter: Expr = recover_async_for_iter(code, stream, region, lo);
                let store_idx: usize =
                    async_for_store_idx(stream, region.header + 1, region.body_end);
                let (target, after_store): (Expr, usize) =
                    recover_async_for_target(code, stream, store_idx, region.body_end);
                let body_start: usize = if region.body_start > store_idx {
                    region.body_start
                } else {
                    after_store
                };
                let body: Vec<Stmt> = structure_stmts(code, stream, body_start, region.body_end)?;
                let body: Vec<Stmt> =
                    rewrite_legacy_async_for_body(stream, body, body_start, region);
                let orelse: Vec<Stmt> = loop_orelse(code, stream, region, hi)?;
                Stmt::For {
                    target,
                    iter,
                    body: non_empty(body),
                    orelse,
                    is_async: true,
                    line: None,
                }
            }
            LoopKind::While => {
                let test: Expr = recover_while_test(code, stream, region);
                let body: Vec<Stmt> = if region.infinite {
                    structure_infinite_while_body(code, stream, region)?
                } else {
                    structure_stmts(code, stream, region.body_start, region.body_end)?
                };
                let orelse: Vec<Stmt> = loop_orelse(code, stream, region, hi)?;
                Stmt::While {
                    test,
                    body: non_empty(body),
                    orelse,
                    line: None,
                }
            }
        };
        Ok(loop_stmt)
    })();
    pop_loop_frame();
    let loop_stmt: Stmt = result?;
    let mut out: Vec<Stmt> = head;
    out.push(loop_stmt);
    let tail_start: usize = if region.infinite {
        skip_loop_epilogue(stream, region.exit.min(hi), hi)
    } else {
        loop_tail_start(stream, region, hi)
    };
    if tail_start < hi {
        out.extend(structure_stmts(code, stream, tail_start, hi)?);
    }
    Ok(out)
}

/// A `while True:` whose exit block (the post-loop code reached by `break`) is laid out *inline* -
/// physically between the leading break-test and the loop body - rather than after the back-edge.
/// Pre-3.11 and 3.12/3.13 emit `<test>; POP_JUMP_IF_x body_label; <exit block>; body_label: <body>;
/// back_edge`, so the exit block sits at `[fall_through, body_label)`. Returns `(start, end)` of that
/// inline exit block, or `None` when the exit is conventional (after the back-edge, as on 3.11/3.14).
fn infinite_exit_block(stream: &DecodedStream, region: &LoopRegion) -> Option<(usize, usize)> {
    if !region.infinite {
        return None;
    }
    let first_cond: usize = (region.header..region.back_edge).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    let body_label: usize = resolve_jump_target(stream, first_cond, &stream.ops[first_cond])
        .filter(|t: &usize| *t > first_cond && *t < region.back_edge)?;
    let block_start: usize = first_significant(stream, first_cond + 1, body_label)?;
    if block_start >= body_label {
        return None;
    }
    Some((block_start, body_label))
}

/// Build the body suite of an inline-exit `while True:`: emit the leading break-test as
/// `if not <cond>: break` (the cond-jump's fall-through is the inline exit block, its taken branch is
/// the body) followed by the structured loop body starting at the jump target. When the exit block is
/// conventional (after the back-edge) there is no leading inline break and the whole region body is
/// structured as-is.
fn structure_infinite_while_body(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
) -> Result<Vec<Stmt>> {
    let Some((_, body_label)): Option<(usize, usize)> = infinite_exit_block(stream, region) else {
        return structure_stmts(code, stream, region.body_start, region.back_edge);
    };
    let first_cond: usize = (region.header..region.back_edge)
        .find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        .unwrap_or(region.header);
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[region.header..first_cond])?;
    let test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let keeps_body_when_true: bool =
        matches!(stream.ops[first_cond], CanonicalOp::PopJumpIfTrue(_));
    let break_test: Expr = if keeps_body_when_true {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    } else {
        test
    };
    let body_end: usize = infinite_body_end(stream, region);
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test: break_test,
        body: vec![Stmt::Break],
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_label, body_end)?);
    Ok(out)
}

/// The end of an infinite-loop body, extended past the unconditional back-edge to absorb a trailing
/// `return`/`raise` block that is the forward target of an in-body conditional guard (the 3.13/3.14
/// layout places `if cond: return x` so that `return x` sits just after the `JUMP_BACKWARD`). The
/// back-edge itself is structurally inert in the SIM, so extending the body region lets the guard's
/// `POP_JUMP_IF_*` resolve to the trailing return rather than being dropped as an out-of-range jump.
fn infinite_body_end(stream: &DecodedStream, region: &LoopRegion) -> usize {
    let mut end: usize = region.back_edge;
    let len: usize = stream.ops.len();
    loop {
        let guard_target: Option<usize> = (region.body_start..end)
            .filter(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .filter_map(|k: usize| {
                resolve_jump_target(stream, k, &stream.ops[k]).filter(|t: &usize| {
                    *t >= region.back_edge && *t > end && *t <= len && *t != region.exit
                })
            })
            .max();
        let Some(target): Option<usize> = guard_target else {
            break;
        };
        let block_end: usize = (target..len)
            .find(|&k: &usize| {
                matches!(
                    stream.ops[k],
                    CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_)
                )
            })
            .map_or(len, |r: usize| r + 1);
        if block_end <= end {
            break;
        }
        end = block_end;
    }
    end
}

fn non_empty(body: Vec<Stmt>) -> Vec<Stmt> {
    if body.is_empty() {
        vec![Stmt::Pass]
    } else {
        body
    }
}

fn skip_loop_epilogue(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi
        && matches!(
            stream.ops[i],
            CanonicalOp::Pop | CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::EndAsyncFor
        )
    {
        if matches!(stream.ops[i], CanonicalOp::Nop) && opens_protected_region(stream, i) {
            break;
        }
        i += 1;
    }
    i
}

/// True when the `Nop`-decoded op at `idx` is a `SETUP_EXCEPT` / `SETUP_FINALLY` that OPENS a new
/// protected region: the following op's byte offset is the synthesized exception-table `start` for that
/// setup. Used to stop loop-epilogue / async-for-cleanup skipping at a `try:` that begins right after a
/// pre-3.8 `async for`, so its setup is not swallowed into the loop exit and stranded. Gated to the
/// 3.5-3.7 legacy `async for` era: only there does iterator-exhaustion cleanup (`POP_BLOCK` /
/// `POP_EXCEPT` decoded to `Nop`) run flush against a following `SETUP`, so widening this to 2.x or
/// 3.8+ would needlessly perturb their already-proven loop-epilogue boundaries.
fn opens_protected_region(stream: &DecodedStream, idx: usize) -> bool {
    let (maj, min): (u8, u8) = (stream.version.major(), stream.version.minor());
    if maj != 3 || min > 7 {
        return false;
    }
    let Some(next_off): Option<u32> = stream.offsets.get(idx + 1).copied() else {
        return false;
    };
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start == next_off)
}

/// The value the loop's shared post-exit returns, when that tail collapses to a single `return X`.
/// Recovered by structuring the post-loop region and matching a lone trailing `Stmt::Return(Some)`.
/// Lets `is_peephole_break_return` confirm that an in-body `return X` carrying a leading iterator pop
/// is a peephole-folded `break` to this exit (matching value), rather than an unrelated early return
/// (e.g. `for_else`'s `return True` guard, whose value differs from the `else`/exit `return False`).
fn loop_shared_exit_return(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Option<Expr> {
    let tail_start: usize = if region.infinite {
        skip_loop_epilogue(stream, region.exit.min(hi), hi)
    } else {
        loop_tail_start(stream, region, hi)
    };
    if tail_start >= hi {
        return None;
    }
    let tail: Vec<Stmt> = structure_stmts(code, stream, tail_start, hi).ok()?;
    match tail.as_slice() {
        [Stmt::Return(Some(value))] => Some(value.clone()),
        _ => None,
    }
}

fn loop_tail_start(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> usize {
    if let Some(end_idx) = legacy_loop_orelse_end(stream, region, hi) {
        return skip_loop_epilogue(stream, end_idx.min(hi), hi);
    }
    if let Some(break_target) = find_break_target(stream, region, hi)
        && break_target > region.exit
        && break_target <= hi
    {
        return skip_loop_epilogue(stream, break_target, hi);
    }
    let after_exit: usize = region.exit.max(region.back_edge + 1);
    skip_loop_epilogue(stream, after_exit.min(hi), hi)
}

fn loop_orelse(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Result<Vec<Stmt>> {
    if let Some(else_end) = legacy_loop_orelse_end(stream, region, hi) {
        let else_start: usize = skip_loop_epilogue(stream, region.exit.min(hi), hi);
        if else_end > else_start {
            return structure_stmts(code, stream, else_start, else_end);
        }
        return Ok(Vec::new());
    }
    let else_start: usize = skip_loop_epilogue(stream, region.exit.min(hi), hi);
    let else_end: usize = find_break_target(stream, region, hi).unwrap_or(else_start);
    if else_end > else_start {
        structure_stmts(code, stream, else_start, else_end)
    } else {
        Ok(Vec::new())
    }
}

/// The op index ending a legacy `for`/`while` loop's `else:` clause, from the enclosing pre-3.2
/// `SETUP_LOOP` span. The clause occupies `[exit, end)` where `exit` is past the body `POP_BLOCK` and
/// `end` is the `SETUP_LOOP` target (recovered via `setup_loop_end`). Returns `None` when no enclosing
/// `SETUP_LOOP` is recorded (non-legacy, or the loop carries no block cleanup), so the caller keeps the
/// break-target heuristic. An `end` at/below `exit` (no trailing region) yields `Some(exit)` so the
/// caller emits an empty `orelse` rather than guessing one from a forward break.
fn legacy_loop_orelse_end(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> Option<usize> {
    if stream.setup_loop_end.is_empty() {
        return None;
    }
    let (&_setup_idx, &end_idx): (&usize, &usize) = stream
        .setup_loop_end
        .range(..=region.header)
        .rev()
        .find(|&(&s, &e): &(&usize, &usize)| s < region.header && e >= region.exit)?;
    Some(end_idx.min(hi))
}

fn find_break_target(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> Option<usize> {
    let mut target: Option<usize> = None;
    for k in region.body_start..region.body_end {
        if matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
        ) && let Some(t) = resolve_jump_target(stream, k, &stream.ops[k])
            && t > region.exit
            && t <= hi
        {
            target = Some(target.map_or(t, |prev: usize| prev.max(t)));
        }
    }
    target
}

fn recover_for_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    if matches!(
        stream.ops.get(region.header),
        Some(CanonicalOp::ForLoopLegacy(_))
    ) {
        return recover_for_loop_legacy_iter(code, stream, region, lo);
    }
    let get_iter: Option<usize> = (lo..region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter));
    let setup_end: usize = get_iter.unwrap_or(region.header);
    let setup_start: usize = (lo..setup_end)
        .rev()
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::ForIter(_)
                    | CanonicalOp::JumpBackward(_)
            )
        })
        .last()
        .unwrap_or(setup_end);
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[setup_start..setup_end]).unwrap_or_default();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

/// Recover the iterable of a pre-2.2 `FOR_LOOP` indexed-for. `CPython` pushed `<seq>` then an integer
/// index counter (`LOAD_CONST 0`) just before `FOR_LOOP`, which pops the pair and either re-pushes
/// `<seq>`, `index+1`, `seq[index]` or jumps past the loop when exhausted. The back-edge re-enters at
/// the `FOR_LOOP`, leaving both `<seq>` and the index live across iterations. Simulating the setup span
/// therefore leaves `[<seq>, <index>]` on the stack; the iterable is the value below the trailing index
/// constant.
fn recover_for_loop_legacy_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    let setup_start: usize = (lo..region.header)
        .rev()
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::ForLoopLegacy(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::JumpBackward(_)
            )
        })
        .last()
        .unwrap_or(region.header);
    let (_, mut residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[setup_start..region.header]).unwrap_or_default();
    let _index: Option<Expr> = residual.pop();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

fn recover_for_target(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
) -> Option<(Expr, usize)> {
    let after: usize = region.header + 1;
    match stream.ops.get(after)? {
        CanonicalOp::StoreFast(i) => Some((local_target(code, *i, after).ok()?, after + 1)),
        CanonicalOp::StoreName(i) | CanonicalOp::StoreGlobal(i) => Some((
            Expr::Name {
                id: name_at(&code.names, *i, after, "name").ok()?,
                ctx: ExprCtx::Store,
                line: None,
            },
            after + 1,
        )),
        CanonicalOp::UnpackSequence(0) => Some((
            Expr::Tuple {
                elts: Vec::new(),
                ctx: ExprCtx::Store,
            },
            after + 1,
        )),
        CanonicalOp::UnpackSequence(n) => {
            let (targets, skip): (Vec<Expr>, usize) =
                collect_unpack_targets(code, &stream.ops, after + 1, *n as usize)?;
            Some((
                Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                },
                after + 1 + skip,
            ))
        }
        CanonicalOp::BuildTuple(n) => {
            let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
            let mut k: usize = after + 1;
            while elts.len() < *n as usize && k < region.body_end {
                match &stream.ops[k] {
                    CanonicalOp::StoreFast(i) => {
                        if let Ok(t) = local_target(code, *i, k) {
                            elts.push(t);
                        }
                    }
                    CanonicalOp::StoreName(i) | CanonicalOp::StoreGlobal(i) => {
                        if let Ok(n) = name_at(&code.names, *i, k, "name") {
                            elts.push(Expr::Name {
                                id: n,
                                ctx: ExprCtx::Store,
                                line: None,
                            });
                        }
                    }
                    CanonicalOp::StoreFastStoreFast(a, b) => {
                        if let Ok(t) = local_target(code, *a, k) {
                            elts.push(t);
                        }
                        if let Ok(t) = local_target(code, *b, k) {
                            elts.push(t);
                        }
                    }
                    _ => break,
                }
                k += 1;
            }
            Some((
                Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Store,
                },
                k,
            ))
        }
        _ => None,
    }
}

/// The iterable of an `async for`: the residual expression evaluated just before the `GET_AITER`
/// that anchors the loop. Searches backward from the `GET_ANEXT` header to the most recent
/// `GET_AITER`, then re-simulates the value-producing ops feeding it.
fn recover_async_for_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    let aiter: usize = (lo..region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))
        .unwrap_or(region.header);
    let setup_start: usize = (lo..aiter)
        .rev()
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::EndAsyncFor
                    | CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpAbsolute(_)
            )
        })
        .last()
        .unwrap_or(aiter);
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[setup_start..aiter]).unwrap_or_default();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

/// The loop target of an `async for` given the index of the loop-variable store (after the
/// `__anext__` poll). Returns the target expression and the first body op index past it.
fn recover_async_for_target(
    code: &CodeObject,
    stream: &DecodedStream,
    store_idx: usize,
    hi: usize,
) -> (Expr, usize) {
    match stream.ops.get(store_idx) {
        Some(CanonicalOp::StoreFast(i)) => (
            local_target(code, *i, store_idx).unwrap_or_else(|_| placeholder_target()),
            store_idx + 1,
        ),
        Some(CanonicalOp::StoreName(i) | CanonicalOp::StoreGlobal(i)) => (
            name_at(&code.names, *i, store_idx, "name").map_or_else(
                |_| placeholder_target(),
                |id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                },
            ),
            store_idx + 1,
        ),
        Some(
            CanonicalOp::UnpackSequence(_) | CanonicalOp::UnpackEx(_) | CanonicalOp::BuildTuple(_),
        ) => recover_tuple_target(code, stream, store_idx, hi),
        _ => (placeholder_target(), store_idx + 1),
    }
}

/// A single short-circuit conjunct of a compound `while` test: the value-producing op range
/// `[start, cond_idx)` feeding the cond-jump at `cond_idx`, whether the jump exits the loop, and
/// whether `not` must wrap the operand to preserve continue-on-true semantics.
#[derive(Debug, Clone, Copy)]
struct WhileConjunct {
    start: usize,
    cond_idx: usize,
    negate: bool,
}

/// Reconstruct a compound `while A and B and ...:` test from its short-circuit cond-jump chain. The
/// bottom/top test emits one cond-jump per operand: a conjunct exits to the loop exit on a
/// false operand (`POP_JUMP_IF_FALSE exit`) and re-enters / falls through on a true one. Each operand
/// becomes a `BoolOpKind::And` value, negated when the jump polarity is "continue on false" (a
/// `POP_JUMP_IF_TRUE exit`). With a single conjunct this collapses to the bare operand - identical to
/// the legacy single-residual recovery. Clean-room analogue of pycdc `buildCondTree` (target-grouped
/// short-circuit atoms) restricted to the flat conjunction chains the loop fixtures exercise.
fn fold_while_conjuncts(
    code: &CodeObject,
    stream: &DecodedStream,
    conjuncts: &[WhileConjunct],
) -> Expr {
    let mut values: Vec<Expr> = Vec::with_capacity(conjuncts.len());
    for c in conjuncts {
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[c.start..c.cond_idx]).unwrap_or_default();
        let operand: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        });
        values.push(if c.negate {
            Expr::UnaryOp {
                op: crate::bytecode::opcode::UnaryOp::Not,
                operand: Box::new(operand),
            }
        } else {
            operand
        });
    }
    match values.len() {
        0 => Expr::Constant {
            value: ConstValue::True,
            line: None,
        },
        1 => values.into_iter().next().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        }),
        _ => Expr::BoolOp {
            op: crate::ast::node::BoolOpKind::And,
            values,
        },
    }
}

/// Walk a `while` test span `[lo, hi]` (where `hi` is the index of the final cond-jump, inclusive)
/// and split it into per-operand conjuncts at each non-chain forward/backward cond-jump. Each
/// conjunct records the value-op slice and a `negate` flag computed from the jump polarity relative
/// to its target (loop re-entry vs short-circuit exit), so the folded `and` chain preserves the
/// original continue-on-true semantics regardless of how the compiler laid out the test.
fn collect_while_conjuncts(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    header: usize,
    exit: usize,
) -> Vec<WhileConjunct> {
    let mut conjuncts: Vec<WhileConjunct> = Vec::new();
    let mut start: usize = lo;
    let mut k: usize = lo;
    while k <= hi {
        let is_cond: bool = matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::PopJumpIfFalse(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalseRel(_)
                    | CanonicalOp::PopJumpIfTrueRel(_)
                    | CanonicalOp::PopJumpIfFalseBackward(_)
                    | CanonicalOp::PopJumpIfTrueBackward(_)
            )
        ) && !is_chain_cond_jump(&stream.ops, k);
        if is_cond {
            conjuncts.push(WhileConjunct {
                start,
                cond_idx: k,
                negate: while_conjunct_negation(stream, k, header, exit),
            });
            start = k + 1;
        }
        k += 1;
    }
    conjuncts
}

/// Whether one conjunct's operand must be wrapped in `not`. A jump that re-enters the loop (targets
/// at or before the header) continues iff taken; a jump that short-circuits to the exit continues iff
/// not taken. Combined with the jump's true/false polarity this is `is_if_true XOR is_reentry`: a
/// `POP_JUMP_IF_FALSE exit` and a `POP_JUMP_IF_TRUE header` both read positively (`A`), while their
/// opposites read as `not A`.
fn while_conjunct_negation(
    stream: &DecodedStream,
    cond_idx: usize,
    header: usize,
    exit: usize,
) -> bool {
    let is_if_true: bool = matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
    );
    let target: Option<usize> = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx]);
    let is_reentry: bool = target.is_some_and(|t: usize| t <= header || t < exit && t < cond_idx);
    is_if_true ^ is_reentry
}

fn recover_while_test(code: &CodeObject, stream: &DecodedStream, region: &LoopRegion) -> Expr {
    if region.infinite {
        return Expr::Constant {
            value: ConstValue::True,
            line: None,
        };
    }
    let back_op: &CanonicalOp = &stream.ops[region.back_edge];
    let cond_back: bool =
        is_cond_back_edge(back_op) || is_cond_jump_with_backward_target(stream, region.back_edge);
    if cond_back {
        let test_start: usize =
            bottom_test_start(stream, region.back_edge, region.header, region.exit);
        let conjuncts: Vec<WhileConjunct> = collect_while_conjuncts(
            stream,
            test_start,
            region.back_edge,
            region.header,
            region.exit,
        );
        return fold_while_conjuncts(code, stream, &conjuncts);
    }
    let has_bottom_test: bool = (region.body_end..region.back_edge).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    });
    let (expr_start, last_cond): (usize, usize) = if has_bottom_test {
        let start: usize = bottom_test_start(stream, region.back_edge, region.header, region.exit);
        let last: usize = (start..region.back_edge)
            .rev()
            .find(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .unwrap_or(start);
        (start, last)
    } else {
        let top_end: usize = region.body_start.max(region.header + 1);
        let last: usize = (region.header..top_end)
            .rev()
            .find(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .unwrap_or(region.header);
        (region.header, last)
    };
    let conjuncts: Vec<WhileConjunct> =
        collect_while_conjuncts(stream, expr_start, last_cond, region.header, region.exit);
    fold_while_conjuncts(code, stream, &conjuncts)
}

/// Value-form ternary `x if cond else y` fold. Detects the canonical pattern:
/// `<test_ops>; PopJumpIfFalse(else_idx); <body_ops>; JumpForward(end_idx); <else_ops>; <consumer>`
/// where both `body_ops` and `else_ops` net +1 to the stack with no emitted statements. The fold
/// produces a single `Expr::IfExp` seeded into the `SIM` for the post-join region, which then handles
/// the downstream consumer (`Return`, `StoreFast`, `Subscript`, etc.). Recursively detects nested
/// ternaries in the body or else region.
/// Index of the value-form ternary's then-branch skip jump (`JUMP_FORWARD`/`JUMP_ABSOLUTE` to the
/// join). It normally sits at `target - 1`, but on 3.11 the else branch may open with a `LOAD_GLOBAL`
/// method-self `PUSH_NULL` slot that the `POP_JUMP_IF_*` target lands ON, so the skip jump is one or
/// more `PUSH`/cache/nop ops before `target`. Scan back from `target` past that padding to the real
/// skip jump; returns `target - 1` unchanged when no padding intervenes.
fn ternary_body_jump_before(stream: &DecodedStream, from: usize, target: usize) -> usize {
    let mut k: usize = target;
    while k > from {
        k -= 1;
        match stream.ops[k] {
            CanonicalOp::Push(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {}
            _ => return k,
        }
    }
    target.saturating_sub(1)
}

fn try_structure_ternary_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if target <= jump_idx + 1 || target > hi {
        return Ok(None);
    }
    let last_test_jump: usize = ternary_test_chain_end(stream, lo, jump_idx, target);
    let body_last: usize = ternary_body_jump_before(stream, last_test_jump + 1, target);
    if !matches!(
        stream.ops[body_last],
        CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
    ) {
        return Ok(None);
    }
    let orelse_start: usize = body_last + 1;
    let Some(join): Option<usize> = resolve_jump_target(stream, body_last, &stream.ops[body_last])
        .filter(|j: &usize| *j > body_last && *j <= hi)
    else {
        return Ok(None);
    };
    if last_test_jump + 1 > body_last {
        return Ok(None);
    }
    let Some((head_stmts, below_stack, test_raw)): Option<TernaryTest> =
        build_ternary_test_expr(code, stream, lo, jump_idx, last_test_jump, target)?
    else {
        return Ok(None);
    };
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, last_test_jump + 1, body_last)?
    else {
        return Ok(None);
    };
    let Some(else_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, orelse_start, join)?
    else {
        return Ok(None);
    };
    let negate: bool = matches!(stream.ops[last_test_jump], CanonicalOp::PopJumpIfFalse(_));
    let (then_expr, otherwise_expr): (Expr, Expr) = if negate {
        (body_expr, else_expr)
    } else {
        (else_expr, body_expr)
    };
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(test_raw),
        body: Box::new(then_expr),
        orelse: Box::new(otherwise_expr),
    };
    let mut out: Vec<Stmt> = head_stmts;
    let mut seed: Vec<Expr> = below_stack;
    seed.push(if_exp);
    if let Some(consumer_end) = ternary_tail_split(stream, join, hi) {
        let (consumer_stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim_seed(code, &stream.ops[join..consumer_end], seed)?;
        out.extend(consumer_stmts);
        let rest: Vec<Stmt> = structure_stmts(code, stream, consumer_end, hi)?;
        out.extend(rest);
        return Ok(Some(out));
    }
    let (tail_stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[join..hi], seed)?;
    out.extend(tail_stmts);
    Ok(Some(out))
}

/// When the post-join tail of a value-form ternary contains a further structurable construct (a
/// nested control-flow forward cond-jump that the value-stack sim would otherwise flatten - e.g. a
/// second ternary or an `if`/`else` immediately following an assignment-ternary at module scope),
/// the seeded linear builder must NOT swallow the whole `join..hi` region. Return the op index at
/// which the `IfExp`'s single consumer statement ends so the caller can seed-consume only that one
/// statement and recurse `structure_stmts` over the remainder. Returns `None` when the tail is a
/// pure linear run (no nested construct), preserving the existing single-pass flatten.
fn ternary_tail_split(stream: &DecodedStream, join: usize, hi: usize) -> Option<usize> {
    let consumer_end: usize = ternary_consumer_end(stream, join, hi)?;
    if consumer_end >= hi {
        return None;
    }
    let has_nested_construct: bool = (consumer_end..hi).any(|i: usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
            && resolve_jump_target(stream, i, &stream.ops[i])
                .is_some_and(|t: usize| t > i && t <= hi)
    });
    if has_nested_construct {
        Some(consumer_end)
    } else {
        None
    }
}

/// Locate the end (exclusive) of the single statement that consumes the assembled ternary `IfExp`
/// seeded onto the stack at `join`. The `IfExp` is already complete at `join`, so its consumer is
/// the first stack "sink" op at or after `join` (`STORE_*`, `POP_TOP`, `RETURN*`, `STORE_SUBSCR`,
/// `STORE_ATTR`, …); any intervening `LOAD_*`/`CALL` ops belong to that same statement (e.g. the
/// object/index loads of a `STORE_SUBSCR` target). Returns the index just past that sink, or `None`
/// if no sink is found within `join..hi`.
fn ternary_consumer_end(stream: &DecodedStream, join: usize, hi: usize) -> Option<usize> {
    (join..hi)
        .find(|&i: &usize| is_ternary_consumer_sink(&stream.ops[i]))
        .map(|i: usize| i + 1)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_ternary_consumer_sink(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreName(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreFastStoreFast(_, _)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreSlice
            | CanonicalOp::Pop
            | CanonicalOp::PrintExpr
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
    )
}

/// A value-form ternary whose test is a short-circuit `and` chain (`x if a and b else y`) lays the
/// test out as one `POP_JUMP_IF_FALSE else` per conjunct, every conjunct jumping to the same else
/// target. The caller hands us the first such jump; walk forward over consecutive conjunct jumps
/// (each followed by the next operand's value ops) that all target the same else, returning the
/// index of the final conjunct jump - the true ternary boundary. A lone conjunct returns `jump_idx`
/// unchanged. The walk stops at the first jump whose target differs (that jump belongs to a nested
/// construct, not the test) or once the next operand would cross into the body.
fn ternary_test_chain_end(
    stream: &DecodedStream,
    lo: usize,
    jump_idx: usize,
    target: usize,
) -> usize {
    let mut last: usize = jump_idx;
    let mut cursor: usize = jump_idx + 1;
    while cursor < target {
        let next_opt: Option<usize> = (cursor..target).find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        });
        let Some(next_jump): Option<usize> = next_opt else {
            break;
        };
        let next_target_opt: Option<usize> =
            resolve_jump_target(stream, next_jump, &stream.ops[next_jump]);
        if next_target_opt != Some(target) {
            break;
        }
        last = next_jump;
        cursor = next_jump + 1;
    }
    let _ = lo;
    last
}

/// Result of [`build_ternary_test_expr`]: the leading statements emitted before the test, the
/// residual stack lying BELOW the test operand (values pushed before the branch and consumed by a
/// sink AFTER the merge), and the assembled test expression.
type TernaryTest = (Vec<Stmt>, Vec<Expr>, Expr);

/// Build the ternary test, folding a short-circuit `and` chain `[lo..=last_test_jump]` into a single
/// `BoolOp` when more than one conjunct precedes the body, and returning any leading statements
/// (`lo` may begin with prior statements whose residual is the first conjunct's operand). A single
/// conjunct collapses to the bare operand, identical to the prior single-residual recovery.
///
/// The `below_stack` field is the residual stack lying BELOW the test operand at `lo`: values pushed
/// before the branch and consumed by a sink AFTER the merge (e.g. a `BUILD_TEMPLATE` statics tuple
/// loaded ahead of a ternary interpolation). These must be threaded into the post-join consumer's
/// seed stack so the sink sees them, otherwise they are silently orphaned and the recovered source
/// loses them.
fn build_ternary_test_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    first_jump: usize,
    last_test_jump: usize,
    target: usize,
) -> Result<Option<TernaryTest>> {
    let (head_stmts, mut head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..first_jump])?;
    let Some(first_operand): Option<Expr> = head_residual.pop() else {
        return Ok(None);
    };
    let below_stack: Vec<Expr> = head_residual;
    if last_test_jump == first_jump {
        return Ok(Some((head_stmts, below_stack, first_operand)));
    }
    let mut values: Vec<Expr> = vec![negate_operand(stream, first_jump, target, first_operand)];
    let mut prev_jump: usize = first_jump;
    let mut cursor: usize = first_jump + 1;
    while prev_jump < last_test_jump {
        let Some(next_jump): Option<usize> = (cursor..=last_test_jump).find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        }) else {
            return Ok(None);
        };
        let Some(operand): Option<Expr> =
            build_region_as_single_expr(code, stream, prev_jump + 1, next_jump)?
        else {
            return Ok(None);
        };
        values.push(negate_operand(stream, next_jump, target, operand));
        prev_jump = next_jump;
        cursor = next_jump + 1;
    }
    let test: Expr = Expr::BoolOp {
        op: crate::ast::node::BoolOpKind::And,
        values,
    };
    Ok(Some((head_stmts, below_stack, test)))
}

/// One conjunct of an `and`-chain test jumps to the shared else target on a false operand. A
/// `POP_JUMP_IF_FALSE else` reads the operand positively (`a`); a `POP_JUMP_IF_TRUE else` short-
/// circuits on a true operand, so the conjunct reads as `not a` to preserve the `and` semantics.
fn negate_operand(stream: &DecodedStream, jump_idx: usize, _target: usize, operand: Expr) -> Expr {
    if matches!(stream.ops[jump_idx], CanonicalOp::PopJumpIfTrue(_)) {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(operand),
        }
    } else {
        operand
    }
}

/// Build a region [lo..hi] as a single value-form expression. Used by ternary detection to
/// recursively handle nested ternaries. Returns `Some(expr)` when the region produces a single
/// expression with no emitted statements (the SIM residual has length 1 after consuming all ops).
fn build_region_as_single_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    if lo >= hi {
        return Ok(None);
    }
    let nested_jump_opt: Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    });
    if let Some(nested_jump) = nested_jump_opt {
        let nested_target: usize =
            resolve_jump_target(stream, nested_jump, &stream.ops[nested_jump])
                .filter(|t: &usize| *t > nested_jump && *t <= hi)
                .unwrap_or(hi);
        if nested_target > nested_jump + 1 && nested_target < hi {
            let nested_body_last: usize = nested_target - 1;
            let body_jump_ok: bool = matches!(
                stream.ops[nested_body_last],
                CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
            );
            let nested_join_opt: Option<usize> = if body_jump_ok {
                resolve_jump_target(stream, nested_body_last, &stream.ops[nested_body_last])
                    .filter(|j: &usize| *j > nested_target && *j <= hi)
            } else {
                None
            };
            if let Some(nested_join) = nested_join_opt {
                let folded_opt: Option<Expr> = try_fold_nested_ternary(
                    code,
                    stream,
                    lo,
                    hi,
                    nested_jump,
                    nested_target,
                    nested_join,
                )?;
                if let Some(folded) = folded_opt {
                    return Ok(Some(folded));
                }
            }
        }
    }
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..hi])?;
    if !stmts.is_empty() || residual.len() != 1 {
        return Ok(None);
    }
    Ok(residual.into_iter().next_back())
}

fn try_fold_nested_ternary(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    nested_jump: usize,
    nested_target: usize,
    nested_join: usize,
) -> Result<Option<Expr>> {
    let (_, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..nested_jump])?;
    let Some(test_raw): Option<Expr> = head_residual.into_iter().next_back() else {
        return Ok(None);
    };
    let nested_body_last: usize = nested_target - 1;
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, nested_jump + 1, nested_body_last)?
    else {
        return Ok(None);
    };
    let Some(else_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, nested_target, nested_join)?
    else {
        return Ok(None);
    };
    let negate: bool = matches!(stream.ops[nested_jump], CanonicalOp::PopJumpIfFalse(_));
    let (then_expr, otherwise_expr): (Expr, Expr) = if negate {
        (body_expr, else_expr)
    } else {
        (else_expr, body_expr)
    };
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(test_raw),
        body: Box::new(then_expr),
        orelse: Box::new(otherwise_expr),
    };
    let (tail_stmts, tail_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[nested_join..hi], vec![if_exp])?;
    if !tail_stmts.is_empty() || tail_residual.len() != 1 {
        return Ok(None);
    }
    Ok(tail_residual.into_iter().next_back())
}

/// One short-circuit operand of a value-form boolean expression: the value sub-region [lo, jump),
/// the boolean operator its short-circuit jump implies (`And` for jump-if-false, `Or` for
/// jump-if-true), and the op index the jump targets. The terminal operand of a region has no jump
/// (`jump_target == None`).
#[derive(Debug, Clone, Copy)]
struct BoolOperand {
    value_lo: usize,
    value_hi: usize,
    op: crate::ast::node::BoolOpKind,
    target: usize,
    sc_idx: usize,
}

/// A located short-circuit jump for one operand: where the operand's value sub-region ends
/// (`value_hi`), the short-circuit identity index (`sc_idx`), the implied operator, the target op
/// index, and where the next operand begins (`after`).
#[derive(Debug, Clone, Copy)]
struct ShortCircuit {
    value_hi: usize,
    sc_idx: usize,
    op: crate::ast::node::BoolOpKind,
    target: usize,
    after: usize,
}

/// Locate the next short-circuit jump at or after `from`, recognising the 3.12+ `Copy 1 [;TO_BOOL];
/// PopJumpIf*; POP_TOP` form, the 3.8-3.11 `JumpIf{True,False}OrPop` form, and the bare
/// `PopJumpIf{False,True}` inner short-circuit. Returns `None` once no further short-circuit is found
/// (the terminal operand).
fn next_shortcircuit(stream: &DecodedStream, from: usize, hi: usize) -> Option<ShortCircuit> {
    use crate::ast::node::BoolOpKind;
    let mut i: usize = from;
    while i < hi {
        match stream.ops[i] {
            CanonicalOp::Copy(1) => {
                let jump: usize = skip_to_bool_jump(&stream.ops, i + 1)?;
                if jump >= hi {
                    return None;
                }
                let op: BoolOpKind = match stream.ops[jump] {
                    CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
                    CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
                    _ => return None,
                };
                let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])?;
                let mut after: usize = jump + 1;
                while after < hi
                    && matches!(
                        stream.ops[after],
                        CanonicalOp::Pop | CanonicalOp::Cache | CanonicalOp::Nop
                    )
                {
                    after += 1;
                }
                return Some(ShortCircuit {
                    value_hi: i,
                    sc_idx: i,
                    op,
                    target,
                    after,
                });
            }
            CanonicalOp::JumpIfFalseOrPop(_)
            | CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_) => {
                let op: BoolOpKind = match stream.ops[i] {
                    CanonicalOp::JumpIfFalseOrPop(_) | CanonicalOp::PopJumpIfFalse(_) => {
                        BoolOpKind::And
                    }
                    _ => BoolOpKind::Or,
                };
                let target: usize = resolve_jump_target(stream, i, &stream.ops[i])?;
                if target > hi {
                    return None;
                }
                return Some(ShortCircuit {
                    value_hi: i,
                    sc_idx: i,
                    op,
                    target,
                    after: i + 1,
                });
            }
            _ => i += 1,
        }
    }
    None
}

/// Split a value-form boolean region [lo..hi] into its short-circuit operands, terminated by the
/// final operand which runs to `hi` with no jump. Returns `None` if the region is not a clean
/// short-circuit chain.
fn split_boolop_operands(stream: &DecodedStream, lo: usize, hi: usize) -> Option<Vec<BoolOperand>> {
    let mut operands: Vec<BoolOperand> = Vec::new();
    let mut cursor: usize = lo;
    while let Some(sc) = next_shortcircuit(stream, cursor, hi) {
        operands.push(BoolOperand {
            value_lo: cursor,
            value_hi: sc.value_hi,
            op: sc.op,
            target: sc.target,
            sc_idx: sc.sc_idx,
        });
        cursor = sc.after;
    }
    if operands.is_empty() {
        return None;
    }
    operands.push(BoolOperand {
        value_lo: cursor,
        value_hi: hi,
        op: crate::ast::node::BoolOpKind::And,
        target: hi,
        sc_idx: hi,
    });
    Some(operands)
}

/// A resolved short-circuit operand carrying its recovered value expression, the boolean operator
/// its jump implies, and the op index it short-circuits to.
#[derive(Debug, Clone)]
struct ResolvedOperand {
    expr: Expr,
    op: crate::ast::node::BoolOpKind,
    target: usize,
    sc_idx: usize,
    value_lo: usize,
}

/// Fold a resolved short-circuit operand sequence into a precedence-correct `BoolOp` tree. Models
/// the `CPython` fused jump threading: an operand whose jump targets a later operand `j` (rather
/// than the region exit) is the short-circuit head of the value tested at `j`, so it merges into `j`
/// as `BoolOp(op_i, [expr_i, expr_j])` (the inner sub-expression). After all inner merges resolve,
/// the survivors all short-circuit to the exit; they are grouped left-to-right by polarity, a
/// polarity switch opening a nested same-operator group. Clean-room (pycdc consulted for semantics).
fn fold_shortcircuit_operands(operands: Vec<ResolvedOperand>) -> Option<Expr> {
    use crate::ast::node::BoolOpKind;
    let mut items: Vec<ResolvedOperand> = operands;
    let exit: usize = items
        .last()
        .map_or(usize::MAX, |o: &ResolvedOperand| o.sc_idx);
    let group_span = |items: &[ResolvedOperand], i: usize| -> usize {
        let target: usize = items[i].target;
        let mut k: usize = i + 1;
        while k < items.len() && items[k].value_lo < target {
            k += 1;
        }
        k
    };
    loop {
        let inner_idx: Option<usize> = (0..items.len()).rev().find(|&i: &usize| {
            i + 1 != items.len() && items[i].target != exit && group_span(&items, i) > i + 1
        });
        let Some(i): Option<usize> = inner_idx else {
            break;
        };
        let group_op: BoolOpKind = items[i].op;
        let k: usize = group_span(&items, i);
        if k <= i + 1 || k > items.len() {
            return None;
        }
        let group: Vec<ResolvedOperand> = items.splice(i..k, std::iter::empty()).collect();
        let (tail_op, tail_target, tail_sc, tail_lo): (BoolOpKind, usize, usize, usize) = {
            let last: &ResolvedOperand = group.last()?;
            (last.op, last.target, last.sc_idx, group[0].value_lo)
        };
        let mut values: Vec<Expr> = Vec::with_capacity(group.len());
        for member in group {
            match member.expr {
                Expr::BoolOp { op, values: inner } if op == group_op => values.extend(inner),
                other => values.push(other),
            }
        }
        let merged: Expr = if values.len() == 1 {
            values.into_iter().next()?
        } else {
            Expr::BoolOp {
                op: group_op,
                values,
            }
        };
        items.insert(
            i,
            ResolvedOperand {
                expr: merged,
                op: tail_op,
                target: tail_target,
                sc_idx: tail_sc,
                value_lo: tail_lo,
            },
        );
    }
    fold_same_level(&items)
}

/// Group survivors that all short-circuit to the same exit into a `BoolOp` tree, left-to-right, a
/// polarity switch opening a nested same-operator subgroup that captures the remaining operands of
/// that polarity (and the terminal) until the polarity switches back.
fn fold_same_level(items: &[ResolvedOperand]) -> Option<Expr> {
    use crate::ast::node::BoolOpKind;
    if items.is_empty() {
        return None;
    }
    if items.len() == 1 {
        return Some(items[0].expr.clone());
    }
    let level_op: BoolOpKind = items[0].op;
    let last: usize = items.len() - 1;
    let mut values: Vec<Expr> = Vec::new();
    let mut i: usize = 0;
    while i < items.len() {
        if i == last || items[i].op == level_op {
            values.push(items[i].expr.clone());
            i += 1;
            continue;
        }
        let mut group_end: usize = i;
        while group_end < last && items[group_end].op != level_op {
            group_end += 1;
        }
        group_end += 1;
        let nested: Expr = fold_same_level(&items[i..group_end])?;
        values.push(nested);
        i = group_end;
    }
    if values.len() < 2 {
        return values.into_iter().next();
    }
    Some(Expr::BoolOp {
        op: level_op,
        values,
    })
}

/// Reconstruct a value-form boolean expression region [lo..hi] (ending at the region exit) into a
/// precedence-correct nested `BoolOp`, or `None` when the region is not a clean short-circuit chain.
fn build_shortcircuit_stack_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    let Some(operands): Option<Vec<BoolOperand>> = split_boolop_operands(stream, lo, hi) else {
        return Ok(None);
    };
    if operands.len() < 2 {
        return Ok(None);
    }
    let mut resolved: Vec<ResolvedOperand> = Vec::with_capacity(operands.len());
    for o in &operands {
        let Some(expr): Option<Expr> =
            build_region_as_single_expr(code, stream, o.value_lo, o.value_hi)?
        else {
            return Ok(None);
        };
        resolved.push(ResolvedOperand {
            expr,
            op: o.op,
            target: o.target,
            sc_idx: o.sc_idx,
            value_lo: o.value_lo,
        });
    }
    Ok(fold_shortcircuit_operands(resolved))
}

/// The op that pushes the `AssertionError` raised by a failed `assert`: the dedicated
/// `LOAD_ASSERTION_ERROR` opcode on 3.9-3.13, the `LOAD_COMMON_CONSTANT 0` slot on 3.14+ (which folded
/// the builtin exceptions into a common-constant table), or a `LOAD_GLOBAL AssertionError` on 3.8 and
/// earlier (no dedicated opcode). Used to anchor the assert raise site across versions.
fn is_assertion_error_load(code: &CodeObject, op: &CanonicalOp) -> bool {
    match op {
        CanonicalOp::LoadAssertionError | CanonicalOp::LoadCommonConst(0) => true,
        CanonicalOp::LoadGlobal(slot) | CanonicalOp::LoadName(slot) => {
            name_at_either(code, *slot).is_ok_and(|n: String| n == "AssertionError")
        }
        _ => false,
    }
}

/// Reassemble an `assert <test>[, <msg>]` from its short-circuit lowering. `CPython` compiles the test
/// as a jump-threaded boolean evaluated for truth: each leading `and`-conjunct emits
/// `<value>; POP_JUMP_IF_FALSE raise`, the final conjunct emits `<value>; POP_JUMP_IF_TRUE pass`, and the
/// false fall-through lands on `LOAD_ASSERTION_ERROR; [<msg>; CALL]; RAISE_VARARGS 1`. The generic
/// if-structurer stops at the first conjunct and emits a bare expression plus a phantom `assert False`
/// (compound) or an `if not <test>: assert False` (single); this folds the whole conjunct run into one
/// test (`BoolOp::And` for two-or-more, the lone expr otherwise), recovers an optional message from the
/// `AssertionError(<msg>)` call, emits `assert <test>[, <msg>]`, and continues from the pass successor.
/// Returns `None` when the region is not an assert.
fn try_structure_compound_assert(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(raise_idx): Option<usize> = (lo..hi).find(|&k: &usize| {
        is_assertion_error_load(code, &stream.ops[k]) && assert_raise_after(stream, k, hi).is_some()
    }) else {
        return Ok(None);
    };
    let (raise_op, msg): (usize, Option<Expr>) = match assert_raise_after(stream, raise_idx, hi) {
        Some((r, m)) => (r, assert_msg_expr(code, stream, raise_idx, r, m)?),
        None => return Ok(None),
    };
    let pass_target: usize = first_significant(stream, raise_op + 1, hi).unwrap_or(hi);
    let jump_indices: Vec<usize> = (lo..raise_idx)
        .filter(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        .collect();
    if jump_indices.is_empty() {
        return Ok(None);
    }
    let mut head: Vec<Stmt> = Vec::new();
    let mut operands: Vec<Expr> = Vec::new();
    let mut value_lo: usize = lo;
    for (n, &jump) in jump_indices.iter().enumerate() {
        let target: usize = match resolve_jump_target(stream, jump, &stream.ops[jump]) {
            Some(t) => t,
            None => return Ok(None),
        };
        let jumps_false: bool = matches!(
            stream.ops[jump],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        );
        let conjunct_ok: bool =
            (jumps_false && target <= raise_idx) || (!jumps_false && target >= pass_target);
        if !conjunct_ok {
            return Ok(None);
        }
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        if n == 0 {
            head = stmts;
        } else if !stmts.is_empty() {
            return Ok(None);
        }
        let value: Expr = none_jump_test(stream, jump, value.clone()).unwrap_or(value);
        operands.push(value);
        value_lo = jump + 1;
    }
    let test: Expr = if operands.len() == 1 {
        operands.into_iter().next().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        })
    } else {
        Expr::BoolOp {
            op: crate::ast::node::BoolOpKind::And,
            values: operands,
        }
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::Assert {
        test,
        msg,
        line: None,
    });
    out.extend(structure_stmts(code, stream, pass_target, hi)?);
    Ok(Some(out))
}

/// Resolve the `RAISE_VARARGS` that closes an assert's failure path beginning at the
/// `LOAD_ASSERTION_ERROR` site `raise_idx`, plus a flag for whether the error is CALLED with a message
/// (`LOAD_ASSERTION_ERROR; <msg>; CALL; RAISE`) versus raised bare (`LOAD_ASSERTION_ERROR; RAISE`).
/// Returns `(raise_op_index, has_message)`, or `None` when the tail is not an assert raise.
fn assert_raise_after(
    stream: &DecodedStream,
    raise_idx: usize,
    hi: usize,
) -> Option<(usize, bool)> {
    let next: usize = first_significant(stream, raise_idx + 1, hi)?;
    if matches!(stream.ops[next], CanonicalOp::Raise(_)) {
        return Some((next, false));
    }
    let call: usize = (raise_idx + 1..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
    let raise: usize = first_significant(stream, call + 1, hi)?;
    matches!(stream.ops[raise], CanonicalOp::Raise(_)).then_some((raise, true))
}

/// Recover the optional message expression of an `assert <test>, <msg>`: the operands pushed between the
/// `LOAD_ASSERTION_ERROR` at `raise_idx` and the `RAISE_VARARGS` at `raise_op` form
/// `AssertionError(<msg>)`. Replay that span through the value SIM (seeded with the error name) and
/// return the single call argument. `None` flags a bare `raise AssertionError` (no message).
fn assert_msg_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    raise_idx: usize,
    raise_op: usize,
    has_message: bool,
) -> Result<Option<Expr>> {
    if !has_message {
        return Ok(None);
    }
    let call: usize = match (raise_idx + 1..raise_op)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))
    {
        Some(c) => c,
        None => return Ok(None),
    };
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[raise_idx + 1..call])?;
    Ok(residual.into_iter().next_back())
}

/// Recover a return-form ternary chain `return X if c0 else (Y if c1 else Z)` as a single
/// `Stmt::Return(IfExp)` rather than an `if/return` cascade. On 3.13 the cascade form lowers each
/// constant arm via the `RETURN_CONST` peephole (`LOAD_CONST; RETURN_VALUE` collapses to one op),
/// while the ternary-expression form keeps `LOAD_CONST; RETURN_VALUE`; recovering the expression
/// form makes the recompiled op-stream match the original. The region [lo..hi] must consist solely
/// of `<test>; PopJumpIfFalse(else); <body expr>; Return; <else: nested return-ternary | expr Return>`
/// arms - any emitted side-effect statement aborts the fold so plain `if cond: return` guards with
/// real bodies are untouched.
fn try_structure_return_ternary(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !matches!(stream.ops[jump_idx], CanonicalOp::PopJumpIfFalse(_)) {
        return Ok(None);
    }
    let Some(expr): Option<Expr> =
        build_return_ternary_expr(code, stream, lo, hi, jump_idx, target)?
    else {
        return Ok(None);
    };
    Ok(Some(vec![Stmt::Return(Some(expr))]))
}

/// Build the `IfExp` for a return-ternary region. The body region `jump_idx+1 .. target-1` is a
/// single value expression returned by `RETURN_VALUE` at `target-1`; the else region `target .. hi`
/// is itself a value `return <expr>` or a nested return-ternary.
fn build_return_ternary_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Expr>> {
    if target <= jump_idx + 1 || target >= hi {
        return Ok(None);
    }
    let body_ret: usize = target - 1;
    if !matches!(stream.ops[body_ret], CanonicalOp::Return) {
        return Ok(None);
    }
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    if !head_stmts.is_empty() {
        return Ok(None);
    }
    let Some(test_raw): Option<Expr> = head_residual.into_iter().next_back() else {
        return Ok(None);
    };
    let test: Expr = none_jump_test(stream, jump_idx, test_raw.clone()).unwrap_or(test_raw);
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, jump_idx + 1, body_ret)?
    else {
        return Ok(None);
    };
    let else_expr: Expr = match region_return_or_nested(code, stream, target, hi)? {
        Some(e) => e,
        None => return Ok(None),
    };
    Ok(Some(Expr::IfExp {
        test: Box::new(test),
        body: Box::new(body_expr),
        orelse: Box::new(else_expr),
    }))
}

/// The else-arm of a return-ternary: either a nested return-ternary chain or a terminal
/// `<expr>; Return` region producing a single value expression.
fn region_return_or_nested(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    if lo >= hi {
        return Ok(None);
    }
    let nested_jump_opt: Option<usize> = (lo..hi).find(|&i: &usize| {
        matches!(stream.ops[i], CanonicalOp::PopJumpIfFalse(_))
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    });
    if let Some(nested_jump) = nested_jump_opt {
        let nested_target: usize =
            resolve_jump_target(stream, nested_jump, &stream.ops[nested_jump])
                .filter(|t: &usize| *t > nested_jump && *t <= hi)
                .unwrap_or(hi);
        return build_return_ternary_expr(code, stream, lo, hi, nested_jump, nested_target);
    }
    let last: usize = hi - 1;
    if !matches!(stream.ops[last], CanonicalOp::Return) {
        return Ok(None);
    }
    build_region_as_single_expr(code, stream, lo, last)
}

fn is_subject_dup(op: &CanonicalOp) -> bool {
    matches!(op, CanonicalOp::Dup | CanonicalOp::Copy(1))
}

fn is_match_fail_jump(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)
    )
}

/// A refutable gate of the current arm: a `PopJumpIf*` that escapes forward out of the fall-through
/// body. The structural sub-tests of one pattern (`MATCH_SEQUENCE`/`GET_LEN`/`MATCH_KEYS`/value
/// tests) each emit a forward gate to a partial-cleanup head that cascades to the next arm, so any
/// forward fail jump inside the binding region is a gate; the body is the fall-through.
fn is_arm_gate(stream: &DecodedStream, idx: usize, fail_target: usize) -> bool {
    let _ = fail_target;
    is_match_fail_jump(&stream.ops[idx])
        && resolve_jump_target(stream, idx, &stream.ops[idx]).is_some_and(|t: usize| t > idx)
}

/// A `Dup`/`Copy 1` opens a match arm when the duplicated subject feeds a refutable test
/// (`Compare`, `MatchSequence`/`Mapping`/`Class`) reached only through value loads / a single capture
/// store, terminating in a `PopJumpIf*`. Ordinary boolean comparisons never duplicate the compared
/// operand, so this discriminates a match head from an `if a == b:` chain.
fn dup_leads_match_test(stream: &DecodedStream, from: usize, hi: usize) -> bool {
    let mut k: usize = from;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadAttr(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::Dup
            | CanonicalOp::Copy(_)
            | CanonicalOp::GetLen => k += 1,
            CanonicalOp::Compare(_)
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchClass(_) => {
                return first_significant(stream, k + 1, hi)
                    .is_some_and(|n: usize| is_match_fail_jump(&stream.ops[n]));
            }
            _ => return false,
        }
    }
    false
}

fn region_contains_match_head(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    match_head_index(stream, lo, hi).is_some()
}

#[must_use]
fn match_head_index(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    let mut k: usize = lo;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::MatchClass(_)
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchKeys
            | CanonicalOp::GetLen => return Some(k),
            op if is_subject_dup(op) => {
                if dup_leads_match_test(stream, k + 1, hi) {
                    return Some(k);
                }
                k += 1;
            }
            _ => k += 1,
        }
    }
    None
}

/// A `match` head that sits inside the protected body of an enclosing `try`/`with` region belongs to
/// the try body, not the top of `[lo, hi)`. Structuring the region as a `match` would greedily fold
/// the handler dispatch into bogus arms (e.g. the `except*` group recovery collapsing into duplicate
/// wildcard arms). Defer to `structure_try`, which recurses into the protected body where the genuine
/// `match` is recovered.
#[must_use]
fn match_head_enclosed_by_try(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let Some(head): Option<usize> = match_head_index(stream, lo, hi) else {
        return false;
    };
    let Some(region): Option<TryRegion> = find_try_region(stream, lo, hi) else {
        return false;
    };
    region.try_start <= head && head < region.handler_start
}

/// A `match` head that sits inside a `for`/`while` loop body belongs to that loop, not the top of
/// `[lo, hi)`. When the subject is loaded right after a `FOR_ITER` (`for resp in payloads:\n match
/// resp:`), `structure_match` would otherwise fold the loop's iterator setup into the subject prefix and
/// collapse the loop to a bare `resp = payloads` assignment, hoisting the `match` out. Defer to
/// `find_loop` so the loop is structured first and recurses into its body where the genuine `match` is
/// recovered. Mirrors `match_head_enclosed_by_try`; the loop's header must precede the match head and its
/// back-edge must run past it.
#[must_use]
fn match_head_enclosed_by_loop(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let Some(head): Option<usize> = match_head_index(stream, lo, hi) else {
        return false;
    };
    let Some(region): Option<LoopRegion> = find_loop(stream, lo, hi) else {
        return false;
    };
    region.header < head && region.back_edge > head && region.back_edge <= hi
}

/// Locate where the match subject load ends and the first arm begins. The subject is loaded once at
/// the bottom of the stack ahead of the first `Dup`/`Copy 1` (refutable patterns) or ahead of the
/// first refutable test that consumes it directly (singleton/wildcard-only first arm).
fn match_subject_split(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    (lo..hi).find(|&k: &usize| {
        is_subject_dup(&stream.ops[k])
            || matches!(
                stream.ops[k],
                CanonicalOp::Compare(CmpOp::Is | CmpOp::IsNot)
                    | CanonicalOp::MatchSequence
                    | CanonicalOp::MatchMapping
                    | CanonicalOp::MatchClass(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalse(_)
            )
    })
}

#[derive(Debug)]
struct ParsedArm {
    pattern: Pattern,
    guard: Option<Expr>,
    body_start: usize,
    next_arm: usize,
}

/// First op of an arm's pattern, skipping the leading cleanup `Pop`(s) that pop the failed prior
/// arm's live subject copy when control falls to this arm head.
fn match_arm_head(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    (from..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) | CanonicalOp::Pop
        )
    })
}

/// Resolve the common failure target shared by an arm's refutable sub-tests: the first `PopJumpIf*`
/// in `[start, region_end)` whose target lands inside the region and points forward (the next arm
/// head). All sub-tests of one arm jump to the same head.
fn arm_fail_target(
    stream: &DecodedStream,
    start: usize,
    region_end: usize,
) -> Option<(usize, usize)> {
    let mut k: usize = start;
    while k < region_end {
        if is_match_fail_jump(&stream.ops[k])
            && let Some(t) = resolve_jump_target(stream, k, &stream.ops[k])
            && t > k
            && t <= region_end
        {
            return Some((k, t));
        }
        k += 1;
    }
    None
}

/// Collect the `STORE_FAST`/`STORE_NAME` capture names in bytecode order across `[start, end)`,
/// un-fusing 3.13 `STORE_FAST_STORE_FAST`. The match binding machinery emits one store per captured
/// slot after the shuffle that lands each extracted element on TOS.
fn collect_capture_names(
    code: &CodeObject,
    stream: &DecodedStream,
    start: usize,
    end: usize,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for k in start..end.min(stream.ops.len()) {
        match &stream.ops[k] {
            CanonicalOp::StoreFast(slot) => {
                if let Ok(id) = local_name_at(code, *slot, k) {
                    names.push(id);
                }
            }
            CanonicalOp::StoreName(slot) => {
                if let Ok(id) = name_at(&code.names, *slot, k, "name") {
                    names.push(id);
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Ok(id) = local_name_at(code, *a, k) {
                    names.push(id);
                }
                if let Ok(id) = local_name_at(code, *b, k) {
                    names.push(id);
                }
            }
            CanonicalOp::StoreFastLoadFast(store_slot, _) => {
                if let Ok(id) = local_name_at(code, *store_slot, k) {
                    names.push(id);
                }
            }
            _ => {}
        }
    }
    names
}

/// Walk forward from `from` to the first op that begins the arm body, skipping the pattern binding
/// machinery (cleanup pops, captures, element extraction, value sub-test gates that share the arm
/// fail target). Stops at the first op that is real body control/value flow.
fn match_body_start(
    stream: &DecodedStream,
    from: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let mut k: usize = from;
    while k < region_end && is_match_binding_op(stream, k, fail_target, region_end) {
        k += 1;
    }
    k.min(region_end)
}

/// Whether the op at `idx` is part of the pattern binding machinery the arm body scan must skip: a
/// cleanup pop, capture store, structural extraction op, a literal load feeding a value sub-test, or
/// a refutable gate sharing the arm fail landing.
fn is_match_binding_op(
    stream: &DecodedStream,
    idx: usize,
    fail_target: usize,
    region_end: usize,
) -> bool {
    match &stream.ops[idx] {
        CanonicalOp::Pop
        | CanonicalOp::Nop
        | CanonicalOp::Cache
        | CanonicalOp::ExtendedArg(_)
        | CanonicalOp::StoreFast(_)
        | CanonicalOp::StoreName(_)
        | CanonicalOp::StoreFastStoreFast(_, _)
        | CanonicalOp::UnpackSequence(_)
        | CanonicalOp::UnpackEx(_)
        | CanonicalOp::RotN(_)
        | CanonicalOp::Swap(_)
        | CanonicalOp::Dup
        | CanonicalOp::Copy(_)
        | CanonicalOp::LoadSubscr
        | CanonicalOp::MatchKeys
        | CanonicalOp::GetLen
        | CanonicalOp::MatchSequence
        | CanonicalOp::MatchMapping
        | CanonicalOp::BuildMap(_)
        | CanonicalOp::DictUpdate(_)
        | CanonicalOp::DeleteSubscr
        | CanonicalOp::MatchClass(_)
        | CanonicalOp::ToBool
        | CanonicalOp::Compare(_) => true,
        CanonicalOp::LoadConst(_) | CanonicalOp::LoadSmallInt(_) => matches!(
            first_significant(stream, idx + 1, region_end).map(|n: usize| &stream.ops[n]),
            Some(
                CanonicalOp::LoadSubscr
                    | CanonicalOp::Compare(_)
                    | CanonicalOp::MatchKeys
                    | CanonicalOp::MatchClass(_)
            )
        ),
        op if is_match_fail_jump(op) => is_arm_gate(stream, idx, fail_target),
        _ => false,
    }
}

/// Recover the captured-name pattern for a class/sequence/mapping arm whose element binds were
/// recovered as a flat name list. Positional captures become `MatchAs{None, Some(name)}`; the
/// emitter renders the proper structural pattern around them.
fn captures_to_patterns(names: &[String]) -> Vec<Pattern> {
    names
        .iter()
        .map(|n: &String| Pattern::MatchAs {
            pattern: None,
            name: Some(n.clone()),
        })
        .collect()
}

/// One alternative of a 3.11 forward-jump or-group: its value/singleton pattern and the index just
/// past its `JUMP_FORWARD` to the shared body (start of the next alternative's test).
#[derive(Debug)]
struct ForwardOrAlt {
    pattern: Pattern,
    after: usize,
}

/// Whether this stream uses the 3.11 forward-jump or-pattern encoding. `CPython` 3.11 lowers
/// `case a | b | c:` as N sibling tests each ending `POP_JUMP_FORWARD_IF_FALSE(next alt);
/// JUMP_FORWARD(shared body)` into ONE shared body, where 3.10 and 3.12+ duplicate the body per
/// alternative. Only 3.11 needs the forward-jump grouping pass.
fn uses_forward_jump_or(stream: &DecodedStream) -> bool {
    stream.version.major() == 3 && stream.version.minor() == 11
}

/// Parse one alternative of a 3.11 forward-jump or-group starting at `alt_start`. The shape is
/// `COPY 1; <value load>; COMPARE_OP ==; POP_JUMP_FORWARD_IF_FALSE(next); JUMP_FORWARD(shared)`.
/// Returns the alternative's value pattern, its fail target (next alt head) and the shared body
/// target both alts jump to; `None` when the shape is not present (e.g. a single-value `case`,
/// whose fail gate falls straight through to `POP_TOP`).
fn parse_forward_or_alt(
    code: &CodeObject,
    stream: &DecodedStream,
    alt_start: usize,
    region_end: usize,
) -> Option<(ForwardOrAlt, usize, usize)> {
    let head: usize = match_arm_head(stream, alt_start, region_end)?;
    if !is_subject_dup(&stream.ops[head]) {
        return None;
    }
    let value_start: usize = first_significant(stream, head + 1, region_end)?;
    let (fail_idx, fail_target): (usize, usize) = arm_fail_target(stream, value_start, region_end)?;
    let jump_idx: usize = first_significant(stream, fail_idx + 1, region_end)?;
    let CanonicalOp::JumpForward(_) = stream.ops[jump_idx] else {
        return None;
    };
    let shared_target: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= region_end)?;
    let pattern: Pattern = classify_simple_pattern(code, stream, value_start, fail_idx, region_end);
    if !matches!(pattern, Pattern::MatchValue(_) | Pattern::MatchSingleton(_)) {
        return None;
    }
    let after: usize = first_significant(stream, jump_idx + 1, region_end).unwrap_or(region_end);
    Some((ForwardOrAlt { pattern, after }, fail_target, shared_target))
}

/// Recover a 3.11 forward-jump or-pattern arm (`case a | b | c:` and `case (a | b) as name:`).
/// Walks consecutive alternatives that each `JUMP_FORWARD` to one shared body target, folding their
/// value patterns into a single `MatchOr`. The final alternative's fail gate lands on the shared
/// cleanup (`POP_TOP; JUMP_FORWARD(else)`); the shared body itself drops the matched subject copy
/// (`POP_TOP`) and, for an `as` binding, stores the captured name before the arm body. Returns the
/// merged arm with `body_start` at the real body and `next_arm` at the last alternative's fail
/// target, or `None` when fewer than two alternatives share a forward target (a plain value case).
fn extract_forward_jump_or_arm(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    region_end: usize,
) -> Option<ParsedArm> {
    if !uses_forward_jump_or(stream) {
        return None;
    }
    let mut alts: Vec<Pattern> = Vec::new();
    let mut cursor: usize = arm_start;
    let mut shared_target: Option<usize> = None;
    let mut last_fail: usize = region_end;
    while let Some((alt, fail_target, shared)) =
        parse_forward_or_alt(code, stream, cursor, region_end)
    {
        if shared_target.is_some_and(|t: usize| t != shared) {
            break;
        }
        shared_target = Some(shared);
        last_fail = fail_target;
        alts.push(alt.pattern);
        if alt.after <= cursor {
            break;
        }
        cursor = alt.after;
    }
    if alts.len() < 2 {
        return None;
    }
    let body_target: usize = shared_target?;
    let next_arm: usize = forward_or_next_arm(stream, last_fail, region_end);
    let bind_name: Option<String> =
        forward_or_binding(code, stream, body_target, next_arm, region_end);
    let body_start: usize = match_body_start(stream, body_target, next_arm, region_end);
    let merged: Pattern = Pattern::MatchOr(alts);
    let pattern: Pattern = match bind_name {
        Some(name) => Pattern::MatchAs {
            pattern: Some(Box::new(merged)),
            name: Some(name),
        },
        None => merged,
    };
    Some(ParsedArm {
        pattern,
        guard: None,
        body_start,
        next_arm,
    })
}

/// Where the case AFTER a 3.11 forward-jump or-arm begins. The final alternative's fail gate lands
/// on the shared cleanup `POP_TOP; JUMP_FORWARD(else)`; the next case (the following pattern or the
/// wildcard) starts at that `JUMP_FORWARD`'s target. When no such forward jump follows the cleanup
/// the fail target itself is the next case head.
fn forward_or_next_arm(stream: &DecodedStream, last_fail: usize, region_end: usize) -> usize {
    let Some(jump_idx): Option<usize> = first_significant(stream, last_fail, region_end) else {
        return last_fail;
    };
    if !matches!(stream.ops[jump_idx], CanonicalOp::Pop) {
        return last_fail;
    }
    let Some(forward_idx): Option<usize> = first_significant(stream, jump_idx + 1, region_end)
    else {
        return last_fail;
    };
    if let CanonicalOp::JumpForward(_) = stream.ops[forward_idx] {
        resolve_jump_target(stream, forward_idx, &stream.ops[forward_idx])
            .filter(|t: &usize| *t > forward_idx && *t <= region_end)
            .unwrap_or(last_fail)
    } else {
        last_fail
    }
}

/// The `as` capture name bound by a 3.11 forward-jump or-arm, if any. The shared body begins with
/// the cleanup `POP_TOP` that drops the matched subject copy; an `(... ) as name` arm then stores
/// the subject into `name` (`STORE_FAST`/`STORE_NAME`) before the arm body. Returns the name when
/// such a store directly follows the cleanup, else `None`.
fn forward_or_binding(
    code: &CodeObject,
    stream: &DecodedStream,
    body_target: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<String> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in body_target..scan_end {
        match &stream.ops[k] {
            CanonicalOp::Pop
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::StoreFast(slot) => return local_name_at(code, *slot, k).ok(),
            CanonicalOp::StoreName(slot) => return name_at(&code.names, *slot, k, "name").ok(),
            _ => return None,
        }
    }
    None
}

/// A bare `case _:` wildcard arm keeps the subject live (it is matched, not consumed), so `CPython`
/// discards the duplicated subject copy with a `POP_TOP` at the arm head — peephole-folded to a `NOP`
/// on 3.10. The match dispatch's no-match fall-through (an implicit `return None` past the final
/// refutable arm) has no live subject and so begins with a value load or terminator directly, with no
/// leading `POP_TOP`/`NOP`. The discard op therefore distinguishes a real trailing `case _:` from the
/// synthesized exit; without it the exit would materialize as a phantom wildcard arm that recompiles to
/// two extra bytes for the absent subject pop. `CACHE`/`EXTENDED_ARG` are pure layout and skipped.
fn wildcard_discards_subject(stream: &DecodedStream, arm_start: usize, region_end: usize) -> bool {
    (arm_start..region_end.min(stream.ops.len()))
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
            )
        })
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::Pop | CanonicalOp::Nop))
}

fn extract_match_case(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    region_end: usize,
) -> Option<ParsedArm> {
    if let Some(arm) = extract_forward_jump_or_arm(code, stream, arm_start, region_end) {
        return Some(arm);
    }
    let _first: usize = first_significant(stream, arm_start, region_end)?;

    let Some((_fail_idx, fail_target)): Option<(usize, usize)> =
        arm_fail_target(stream, arm_start, region_end)
    else {
        let names: Vec<String> = collect_capture_names(code, stream, arm_start, region_end);
        if names.is_empty() && !wildcard_discards_subject(stream, arm_start, region_end) {
            return None;
        }
        let body_start: usize = match_body_start(stream, arm_start, region_end, region_end);
        let pattern: Pattern = Pattern::MatchAs {
            pattern: None,
            name: names.first().cloned(),
        };
        return Some(ParsedArm {
            pattern,
            guard: None,
            body_start,
            next_arm: region_end,
        });
    };

    let pattern: Pattern = classify_pattern(code, stream, arm_start, fail_target, region_end);

    if is_irrefutable_capture(&pattern) {
        let store_end: usize = capture_store_end(stream, arm_start, fail_target, region_end);
        let guard: Option<Expr> = extract_guard(code, stream, store_end, fail_target, region_end);
        let body_start: usize = guard
            .as_ref()
            .map_or(store_end, |_| {
                guard_body_start(stream, store_end, fail_target, region_end)
            })
            .max(arm_start);
        return Some(ParsedArm {
            pattern,
            guard,
            body_start,
            next_arm: fail_target,
        });
    }

    let scan_resume: usize = last_gate_after(stream, arm_start, fail_target, region_end);
    if let Some((guard, guard_body)) =
        extract_refutable_guard(code, stream, arm_start, fail_target, region_end)
    {
        return Some(ParsedArm {
            pattern,
            guard: Some(guard),
            body_start: guard_body.max(arm_start),
            next_arm: fail_target,
        });
    }
    let body_start: usize =
        match_body_start(stream, scan_resume, fail_target, region_end).max(arm_start);
    Some(ParsedArm {
        pattern,
        guard: None,
        body_start,
        next_arm: fail_target,
    })
}

/// Recover the `if <guard>` of a REFUTABLE `case` (class/sequence/mapping pattern) - `extract_guard`
/// is wired only for irrefutable captures. The pattern's structural sub-tests all gate to the arm
/// `fail_target` (the partial-cleanup head shared by every failing sub-test); the guard, which runs
/// AFTER the pattern fully binds, gates to a DISTINCT later offset (the post-cleanup next-arm head,
/// `fail_target` + the `POP_TOP` that drops the bound subject). Find the last gate to `fail_target`
/// (the end of structural matching), then a single following gate to a different target - the guard
/// gate. The expression between them (capturing any walrus `:=` store) is the guard; negate it when the
/// gate keeps the body on TRUE. Returns `(guard, body_start)` where `body_start` is the first op past
/// the guard gate. `None` when no such distinct-target gate exists, so a guardless refutable arm keeps
/// its current `guard: None` path and the construct match matrix is untouched.
fn extract_refutable_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<(Expr, usize)> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let last_pattern_gate: usize = (arm_start..scan_end).rfind(|&k: &usize| {
        is_match_fail_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k]) == Some(fail_target)
    })?;
    let guard_start: usize =
        match_body_start(stream, last_pattern_gate + 1, fail_target, region_end);
    let guard_gate: usize = (guard_start..scan_end).find(|&k: &usize| {
        is_match_fail_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t != fail_target)
    })?;
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[guard_start..guard_gate]).ok()?;
    let expr: Expr = residual.into_iter().next_back()?;
    let guard: Expr = if matches!(stream.ops[guard_gate], CanonicalOp::PopJumpIfTrue(_)) {
        Expr::UnaryOp {
            op: crate::ast::node::UnaryOpKind::Not,
            operand: Box::new(expr),
        }
    } else {
        expr
    };
    let body_start: usize = match_body_start(stream, guard_gate + 1, fail_target, region_end);
    Some((guard, body_start))
}

fn is_irrefutable_capture(pattern: &Pattern) -> bool {
    matches!(pattern, Pattern::MatchAs { pattern: None, .. })
}

/// Index where an irrefutable arm's guard (or body) begins, just past the capture store(s). A fused
/// 3.13 `STORE_FAST_LOAD_FAST` stores the capture AND re-loads it for the guard, so the guard sim
/// must include that op to recover the loaded local; the emitted assign is discarded as residual.
fn capture_store_end(
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut end: usize = arm_start;
    for k in arm_start..scan_end {
        match stream.ops[k] {
            CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreFastStoreFast(_, _) => end = k + 1,
            CanonicalOp::StoreFastLoadFast(_, _) => end = k,
            _ => {}
        }
    }
    end
}

/// End of the pattern-capture bind region for an arm: the contiguous run of binding machinery
/// (capture stores, structural extraction, refutable gates, cleanup pops) that follows the arm's
/// first refutable test, stopping at the first real value-flow op. A trailing `if` guard begins with
/// such value flow (its walrus `(name := expr)` loads operands before storing), so any `STORE_FAST`
/// emitted by a guard walrus lies past this boundary and is excluded from the pattern-`as` count.
fn pattern_capture_region_end(
    stream: &DecodedStream,
    inner_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let first_gate: Option<usize> =
        (inner_start..scan_end).find(|&k: &usize| is_arm_gate(stream, k, fail_target));
    let from: usize = first_gate.map_or(inner_start, |gate: usize| gate + 1);
    let mut k: usize = from;
    while k < scan_end
        && (is_match_binding_op(stream, k, fail_target, region_end)
            || matches!(stream.ops[k], CanonicalOp::StoreFastLoadFast(_, _)))
    {
        k += 1;
    }
    k.min(scan_end)
}

/// Index just past the final refutable gate of an arm whose sub-tests all share `fail_target`. The
/// arm body (or guard) begins at the binding machinery that follows.
fn last_gate_after(
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut last_gate: usize = arm_start;
    for k in arm_start..scan_end {
        if is_arm_gate(stream, k, fail_target) {
            last_gate = k + 1;
        }
    }
    last_gate
}

/// Number of subject captures a recovered pattern fixes structurally, i.e. how many `STORE_FAST`
/// slots its own binding machinery consumes. Literal and wildcard sub-patterns bind nothing; named
/// captures and a `**rest` each bind one. Any capture store beyond this count in the arm window is
/// the enclosing subject `as`, never part of the inner pattern.
fn pattern_capture_count(pattern: &Pattern) -> usize {
    match pattern {
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => 0,
        Pattern::MatchStar(name) => usize::from(name.is_some()),
        Pattern::MatchAs { pattern, name } => {
            usize::from(name.is_some()) + pattern.as_deref().map_or(0, pattern_capture_count)
        }
        Pattern::MatchSequence(elems) | Pattern::MatchOr(elems) => {
            elems.iter().map(pattern_capture_count).sum()
        }
        Pattern::MatchMapping { patterns, rest, .. } => {
            patterns.iter().map(pattern_capture_count).sum::<usize>() + usize::from(rest.is_some())
        }
        Pattern::MatchClass {
            patterns,
            kwd_patterns,
            ..
        } => {
            patterns.iter().map(pattern_capture_count).sum::<usize>()
                + kwd_patterns
                    .iter()
                    .map(pattern_capture_count)
                    .sum::<usize>()
        }
    }
}

/// Structural capture count for the enclosing-`as` lift, defined only for the structured arm kinds
/// whose inner classifier is slot-bounded (`MATCH_CLASS` / sequence unpack). Mapping arms self-wrap
/// their outer `as` inside [`classify_mapping_pattern`] and scalar/value arms route through the
/// dup-based `as` paths, so both return `None` here to avoid double-lifting.
fn structural_capture_count(
    stream: &DecodedStream,
    from: usize,
    scan_end: usize,
    inner: &Pattern,
) -> Option<usize> {
    match inner {
        Pattern::MatchClass { .. } => Some(pattern_capture_count(inner)),
        Pattern::MatchSequence(_) => {
            let mut count: Option<usize> = None;
            for k in from..scan_end.min(stream.ops.len()) {
                match &stream.ops[k] {
                    CanonicalOp::UnpackSequence(n) => {
                        count = Some(count.unwrap_or(0) + *n as usize);
                    }
                    CanonicalOp::UnpackEx(arg) => {
                        count = Some(
                            count.unwrap_or(0) + (arg & 0xFF) as usize + (arg >> 8) as usize + 1,
                        );
                    }
                    _ => {}
                }
            }
            count.or_else(|| Some(pattern_capture_count(inner)))
        }
        _ => None,
    }
}

/// Remove an over-collected trailing outer-`as` name from a structured inner pattern. Sequence inners
/// whose final element was folded from a fused `STORE_FAST_STORE_FAST(elem, outer)` carry the outer
/// name as a spurious last element; pop it. All other inners (class arms are slot-bounded by
/// `total_slots`, so they never fold the outer store) are returned unchanged.
fn strip_trailing_outer_as(inner: Pattern, outer: &str) -> Pattern {
    match inner {
        Pattern::MatchSequence(mut elems)
            if matches!(
                elems.last(),
                Some(Pattern::MatchAs { name: Some(n), .. }) if n == outer
            ) =>
        {
            elems.pop();
            Pattern::MatchSequence(elems)
        }
        other => other,
    }
}

fn classify_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head_search: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let Some(head): Option<usize> = match_arm_head(stream, head_search, scan_end) else {
        return Pattern::MatchAs {
            pattern: None,
            name: None,
        };
    };
    let dup_lead: bool = is_subject_dup(&stream.ops[head]);
    let after_first: usize = if dup_lead { head + 1 } else { head };
    let double_dup: bool = dup_lead
        && first_significant(stream, after_first, scan_end)
            .is_some_and(|n: usize| is_subject_dup(&stream.ops[n]));
    let inner_start: usize = if double_dup {
        first_significant(stream, after_first, scan_end).map_or(after_first, |n: usize| n + 1)
    } else {
        after_first
    };

    if dup_lead
        && !double_dup
        && let Some(store) = first_significant(stream, after_first, scan_end)
        && matches!(
            stream.ops[store],
            CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreFastLoadFast(_, _)
        )
    {
        let name: Option<String> = match &stream.ops[store] {
            CanonicalOp::StoreFast(slot) | CanonicalOp::StoreFastLoadFast(slot, _) => {
                local_name_at(code, *slot, store).ok()
            }
            CanonicalOp::StoreName(slot) => name_at(&code.names, *slot, store, "name").ok(),
            _ => None,
        };
        return Pattern::MatchAs {
            pattern: None,
            name,
        };
    }

    let inner: Pattern =
        classify_simple_pattern(code, stream, inner_start, fail_target, region_end);

    let capture_end: usize =
        pattern_capture_region_end(stream, inner_start, fail_target, region_end);

    if let Some(structural) = structural_capture_count(stream, inner_start, scan_end, &inner) {
        let names: Vec<String> = collect_capture_names(code, stream, inner_start, capture_end);
        if names.len() == structural + 1
            && let Some(outer) = names.last()
        {
            return Pattern::MatchAs {
                pattern: Some(Box::new(strip_trailing_outer_as(inner, outer))),
                name: Some(outer.clone()),
            };
        }
        if double_dup && let Some(name) = names.last() {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name.clone()),
            };
        }
    } else if double_dup
        && !matches!(
            inner,
            Pattern::MatchMapping { .. } | Pattern::MatchAs { .. }
        )
    {
        let names: Vec<String> = collect_capture_names(code, stream, inner_start, capture_end);
        if let Some(name) = names.last() {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name.clone()),
            };
        }
    }

    if matches!(inner, Pattern::MatchValue(_) | Pattern::MatchSingleton(_)) {
        let last_gate: usize = last_gate_after(stream, head_search, fail_target, region_end);
        if let Some(name) = scalar_as_binding(code, stream, last_gate, fail_target, region_end) {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name),
            };
        }
    }
    inner
}

/// A scalar value/singleton arm bound via `as`: after the test gate the bind region cleans up the
/// duplicate (`POP_TOP`) and stores the subject into the bound name. Returns the bound name when
/// the bind region is exactly a single capture store with no structural extraction.
fn scalar_as_binding(
    code: &CodeObject,
    stream: &DecodedStream,
    from: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<String> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in from..scan_end {
        match &stream.ops[k] {
            CanonicalOp::Pop
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::StoreFast(slot) => return local_name_at(code, *slot, k).ok(),
            CanonicalOp::StoreName(slot) => return name_at(&code.names, *slot, k, "name").ok(),
            _ => return None,
        }
    }
    None
}

fn body_scan_limit(stream: &DecodedStream, fail_target: usize, region_end: usize) -> usize {
    fail_target.min(region_end).min(stream.ops.len())
}

fn classify_simple_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    test_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let Some(first): Option<usize> = first_significant(stream, test_start, scan_end) else {
        return Pattern::MatchAs {
            pattern: None,
            name: None,
        };
    };
    match &stream.ops[first] {
        CanonicalOp::MatchSequence => {
            classify_sequence_pattern(code, stream, first, fail_target, region_end)
        }
        CanonicalOp::MatchMapping => {
            classify_mapping_pattern(code, stream, first, fail_target, region_end)
        }
        CanonicalOp::LoadGlobal(_) | CanonicalOp::LoadName(_) => {
            classify_dotted_value_pattern(code, stream, first, fail_target, region_end)
                .unwrap_or_else(|| {
                    classify_class_pattern(code, stream, first, fail_target, region_end)
                })
        }
        CanonicalOp::LoadConst(slot) => {
            if let Some(next) = first_significant(stream, first + 1, scan_end) {
                if matches!(
                    stream.ops[next],
                    CanonicalOp::Compare(CmpOp::Is | CmpOp::IsNot)
                ) && let Ok(Expr::Constant { value, .. }) = load_const(code, *slot, first)
                {
                    return Pattern::MatchSingleton(value);
                }
                if matches!(stream.ops[next], CanonicalOp::Compare(_))
                    && let Ok(expr) = load_const(code, *slot, first)
                {
                    return Pattern::MatchValue(expr);
                }
            }
            load_const(code, *slot, first).map_or(
                Pattern::MatchAs {
                    pattern: None,
                    name: None,
                },
                Pattern::MatchValue,
            )
        }
        CanonicalOp::LoadSmallInt(v) => {
            let val: i32 = *v;
            Pattern::MatchValue(Expr::Constant {
                value: ConstValue::Int(i128::from(val)),
                line: None,
            })
        }
        CanonicalOp::PopJumpIfTrue(_) => Pattern::MatchSingleton(ConstValue::None),
        _ => collect_or_value_pattern(code, stream, test_start, fail_target, region_end),
    }
}

/// `MatchOr` arms are emitted as N sibling value-tests (each `Dup;<load>;Compare ==;PopJumpIf`) all
/// sharing the destination body; only the last falls through to the next arm. When the structurer
/// reaches one arm and the pattern is a plain value test, return the single value; the outer arm
/// merge groups duplicated bodies into a single `MatchOr`.
fn collect_or_value_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    test_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in test_start..scan_end {
        match &stream.ops[k] {
            CanonicalOp::LoadConst(slot) => {
                if let Ok(expr) = load_const(code, *slot, k) {
                    return Pattern::MatchValue(expr);
                }
            }
            CanonicalOp::LoadSmallInt(v) => {
                return Pattern::MatchValue(Expr::Constant {
                    value: ConstValue::Int(i128::from(*v)),
                    line: None,
                });
            }
            _ => {}
        }
    }
    Pattern::MatchAs {
        pattern: None,
        name: None,
    }
}

fn classify_sequence_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut star_before: Option<u32> = None;
    let mut fixed_len: Option<u32> = None;
    let mut k: usize = head;
    while k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::UnpackSequence(n) => {
                fixed_len = Some(*n);
                break;
            }
            CanonicalOp::UnpackEx(arg) => {
                star_before = Some(arg & 0xFF);
                break;
            }
            CanonicalOp::Compare(_) if fixed_len.is_none() && star_before.is_none() => {}
            _ => {}
        }
        k += 1;
    }
    let names: Vec<String> = collect_capture_names(code, stream, head, scan_end);
    star_before.map_or_else(
        || match fixed_len {
            Some(0) => Pattern::MatchSequence(Vec::new()),
            Some(n) if (n as usize) < names.len() => {
                Pattern::MatchSequence(captures_to_patterns(&names[..n as usize]))
            }
            _ => Pattern::MatchSequence(captures_to_patterns(&names)),
        },
        |before: u32| {
            let before_n: usize = before as usize;
            let elems: Vec<Pattern> = names
                .iter()
                .enumerate()
                .map(|(i, n): (usize, &String)| {
                    if i == before_n {
                        Pattern::MatchStar(Some(n.clone()))
                    } else {
                        Pattern::MatchAs {
                            pattern: None,
                            name: Some(n.clone()),
                        }
                    }
                })
                .collect();
            Pattern::MatchSequence(elems)
        },
    )
}

fn classify_mapping_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut keys: Vec<Expr> = Vec::new();
    let mut k: usize = head;
    while k < scan_end {
        if matches!(stream.ops[k], CanonicalOp::MatchKeys) {
            if let Some(prev) = (head..k)
                .rev()
                .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::LoadConst(_)))
                && let CanonicalOp::LoadConst(slot) = stream.ops[prev]
                && let Some(strs) = const_string_tuple(code, slot)
            {
                keys = strs
                    .into_iter()
                    .map(|s: String| Expr::Constant {
                        value: ConstValue::Str(s),
                        line: None,
                    })
                    .collect();
            }
            break;
        }
        k += 1;
    }
    let keys_end: usize = (head..scan_end)
        .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::MatchKeys))
        .map_or(head, |j: usize| j + 1);
    let key_count: usize = keys.len();
    let dict_rest_marker: Option<usize> = (keys_end..scan_end).rev().find(|&j: &usize| {
        matches!(
            stream.ops[j],
            CanonicalOp::DeleteSubscr | CanonicalOp::DictUpdate(_) | CanonicalOp::BuildMap(_)
        )
    });

    let mut value_patterns: Vec<Pattern> = Vec::new();
    let mut stores: Vec<MappingStore> = Vec::new();
    let mut k2: usize = keys_end;
    while k2 < scan_end {
        match &stream.ops[k2] {
            CanonicalOp::Compare(_) => {
                if let Some(lit) = (keys_end..k2).rev().find(|&j: &usize| {
                    matches!(
                        stream.ops[j],
                        CanonicalOp::LoadConst(_) | CanonicalOp::LoadSmallInt(_)
                    )
                }) {
                    let val: Pattern = match &stream.ops[lit] {
                        CanonicalOp::LoadConst(slot) => load_const(code, *slot, lit).map_or(
                            Pattern::MatchAs {
                                pattern: None,
                                name: None,
                            },
                            Pattern::MatchValue,
                        ),
                        CanonicalOp::LoadSmallInt(v) => Pattern::MatchValue(Expr::Constant {
                            value: ConstValue::Int(i128::from(*v)),
                            line: None,
                        }),
                        _ => Pattern::MatchAs {
                            pattern: None,
                            name: None,
                        },
                    };
                    value_patterns.push(val);
                }
            }
            CanonicalOp::StoreFast(slot) => {
                if let Ok(name) = local_name_at(code, *slot, k2) {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            CanonicalOp::StoreName(slot) => {
                if let Ok(name) = name_at(&code.names, *slot, k2, "name") {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Ok(name) = local_name_at(code, *a, k2) {
                    stores.push(MappingStore { name, fused: true });
                }
                if let Ok(name) = local_name_at(code, *b, k2) {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            _ => {}
        }
        k2 += 1;
    }

    let capture_key_count: usize = key_count.saturating_sub(value_patterns.len());
    let (rest_idx, outer_idx): (Option<usize>, Option<usize>) = mapping_rest_and_outer(
        &stores,
        capture_key_count,
        dict_rest_marker.is_some(),
        stream.version.minor(),
    );
    let rest: Option<String> =
        rest_idx.and_then(|i: usize| stores.get(i).map(|s: &MappingStore| s.name.clone()));
    let outer_as: Option<String> =
        outer_idx.and_then(|i: usize| stores.get(i).map(|s: &MappingStore| s.name.clone()));
    let capture_names: Vec<String> = stores
        .iter()
        .enumerate()
        .filter(|(i, _): &(usize, &MappingStore)| Some(*i) != rest_idx && Some(*i) != outer_idx)
        .map(|(_, s): (usize, &MappingStore)| s.name.clone())
        .collect();

    let mut value_iter: usize = 0;
    let mut name_iter: usize = 0;
    let patterns: Vec<Pattern> = (0..key_count)
        .map(|_| {
            if value_iter < value_patterns.len() {
                let p: Pattern = value_patterns[value_iter].clone();
                value_iter += 1;
                p
            } else if name_iter < capture_names.len() {
                let p: Pattern = Pattern::MatchAs {
                    pattern: None,
                    name: Some(capture_names[name_iter].clone()),
                };
                name_iter += 1;
                p
            } else {
                Pattern::MatchAs {
                    pattern: None,
                    name: None,
                }
            }
        })
        .collect();

    let mapping: Pattern = Pattern::MatchMapping {
        keys,
        patterns,
        rest,
    };
    match outer_as {
        Some(name) => Pattern::MatchAs {
            pattern: Some(Box::new(mapping)),
            name: Some(name),
        },
        None => mapping,
    }
}

/// One recovered binding store from a mapping arm's tail, tagged with whether it was the first half of
/// a fused `STORE_FAST_STORE_FAST` (3.13+). The fusion tag identifies the adjacent `(rest, as)` pair
/// the modern lowering emits in one op.
#[derive(Debug, Clone)]
struct MappingStore {
    name: String,
    fused: bool,
}

/// Disambiguate a mapping arm's trailing stores into `(rest_idx, outer_as_idx)`. `**rest` exists only
/// when the rest machinery marker (`BUILD_MAP`/`DICT_UPDATE`/`DELETE_SUBSCR`, or 3.10's
/// `COPY_DICT_WITHOUT_KEYS`) is present; the remaining over-count past the key-value captures is the
/// outer subject `as`. The `(rest, as)` pair's store order is `CPython`-version-divergent: 3.13+ fuses
/// it as one `STORE_FAST_STORE_FAST(rest, as)`; 3.11/3.12 emit `rest, as, kv...`; 3.10 emits
/// `kv..., rest, as`. Resolution keys on the fusion tag, then on the minor version for the plain forms.
fn mapping_rest_and_outer(
    stores: &[MappingStore],
    capture_key_count: usize,
    has_rest_marker: bool,
    minor: u8,
) -> (Option<usize>, Option<usize>) {
    let total: usize = stores.len();
    if !has_rest_marker {
        let outer_idx: Option<usize> = (total > capture_key_count).then(|| total - 1);
        return (None, outer_idx);
    }
    let extra: usize = total.saturating_sub(capture_key_count);
    if extra == 0 {
        return (None, None);
    }
    let has_outer: bool = extra >= 2;
    if let Some(fused_first) = stores.iter().position(|s: &MappingStore| s.fused)
        && fused_first + 1 < total
    {
        let outer_idx: Option<usize> = has_outer.then_some(fused_first + 1);
        return (Some(fused_first), outer_idx);
    }
    if minor <= 10 {
        let rest_idx: usize = capture_key_count.min(total - 1);
        let outer_idx: Option<usize> = has_outer.then(|| total - 1);
        (Some(rest_idx), outer_idx)
    } else {
        let outer_idx: Option<usize> = has_outer.then_some(1);
        (Some(0), outer_idx)
    }
}

/// A dotted-name value pattern (`case Status.OK:`) lowers as `LOAD_GLOBAL/LOAD_NAME base; LOAD_ATTR
/// attr...; COMPARE_OP ==; POP_JUMP_IF_FALSE next-arm` — an equality test against the looked-up value,
/// not a `MATCH_CLASS` destructure. A bare-name value pattern is illegal Python (a bare capitalised
/// name is a capture, not a value), so this only fires when at least one `LOAD_ATTR` forms a dotted
/// reference. Returns the `MatchValue(<dotted expr>)` when the load chain is closed by an equality
/// compare with no intervening `MATCH_CLASS`; otherwise `None` so the caller falls back to the class
/// pattern path.
fn classify_dotted_value_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<Pattern> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let base_id: String = match &stream.ops[head] {
        CanonicalOp::LoadGlobal(slot) => name_at_either(code, *slot).ok()?,
        CanonicalOp::LoadName(slot) => name_at(&code.names, *slot, head, "name").ok()?,
        _ => return None,
    };
    let mut expr: Expr = Expr::Name {
        id: base_id,
        ctx: ExprCtx::Load,
        line: None,
    };
    let mut attr_count: usize = 0;
    let mut k: usize = head + 1;
    while k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::LoadAttr(slot) => {
                let attr: String = name_at(&code.names, *slot, k, "attr").ok()?;
                expr = Expr::Attribute {
                    value: Box::new(expr),
                    attr,
                    ctx: ExprCtx::Load,
                };
                attr_count += 1;
            }
            CanonicalOp::Compare(CmpOp::Eq) if attr_count > 0 => {
                return Some(Pattern::MatchValue(expr));
            }
            _ => return None,
        }
        k += 1;
    }
    None
}

fn classify_class_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let cls_name: Result<String> = match &stream.ops[head] {
        CanonicalOp::LoadGlobal(slot) => name_at_either(code, *slot),
        CanonicalOp::LoadName(slot) => name_at(&code.names, *slot, head, "name"),
        _ => Err(DecompileError::AstDesync {
            offset: head,
            reason: "match-class head is not a class load".to_owned(),
        }),
    };
    let cls: Expr = cls_name.map_or(
        Expr::Constant {
            value: ConstValue::None,
            line: None,
        },
        |id: String| Expr::Name {
            id,
            ctx: ExprCtx::Load,
            line: None,
        },
    );
    let mut kwd_attrs: Vec<String> = Vec::new();
    let mut positional: u8 = 0;
    let mut match_class_idx: Option<usize> = None;
    let mut k: usize = head;
    while k < scan_end {
        if let CanonicalOp::MatchClass(count) = stream.ops[k] {
            positional = count;
            match_class_idx = Some(k);
            if let Some(prev) = (head..k)
                .rev()
                .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::LoadConst(_)))
                && let CanonicalOp::LoadConst(slot) = stream.ops[prev]
                && let Some(strs) = const_string_tuple(code, slot)
            {
                kwd_attrs = strs;
            }
            break;
        }
        k += 1;
    }
    let positional_count: usize = positional as usize;
    let kwd_count: usize = kwd_attrs.len();
    let total_slots: usize = positional_count + kwd_count;
    let slot_patterns: Vec<Pattern> = match_class_idx.map_or_else(Vec::new, |mc: usize| {
        recover_class_subpatterns(code, stream, mc, scan_end, total_slots)
    });
    let mut slot_iter: std::vec::IntoIter<Pattern> = slot_patterns.into_iter();
    let patterns: Vec<Pattern> = (0..positional_count)
        .map(|_| {
            slot_iter.next().unwrap_or(Pattern::MatchAs {
                pattern: None,
                name: None,
            })
        })
        .collect();
    let kwd_patterns: Vec<Pattern> = (0..kwd_count)
        .map(|_| {
            slot_iter.next().unwrap_or(Pattern::MatchAs {
                pattern: None,
                name: None,
            })
        })
        .collect();
    Pattern::MatchClass {
        cls,
        patterns,
        kwd_attrs,
        kwd_patterns,
    }
}

/// Reconstruct the ordered class sub-patterns of one `match`-class arm across the two distinct
/// `CPython` lowerings. 3.11+ lowers a successful `MATCH_CLASS` to `UNPACK_SEQUENCE total_slots` which
/// pushes the slots with slot 0 on top; a `SWAP n` may reorder so a non-top slot is tested next, and
/// each slot is consumed by a literal compare, a capture store, the fused `STORE_FAST_STORE_FAST`, the
/// fused `STORE_FAST_LOAD_FAST` (3.13+ binds the capture and re-loads it for an immediate guard, so the
/// store slot is the binding), or a `POP_TOP` wildcard drop. Tracking the slot-index stack across
/// `SWAP`/consume yields each slot's sub-pattern by true position. 3.10 instead leaves the matched-attrs
/// tuple on the stack and
/// subscripts each tested slot by index (`DUP_TOP; LOAD_CONST <i>; BINARY_SUBSCR; <test|capture>`),
/// emitting nothing for wildcard slots. Presence of `UNPACK_SEQUENCE` selects the modern walk;
/// otherwise the subscript-indexed walk fills the addressed slots and leaves the rest wildcard. The
/// first `positional_count` recovered slots map to positional patterns, the remainder to keywords.
fn recover_class_subpatterns(
    code: &CodeObject,
    stream: &DecodedStream,
    match_class_idx: usize,
    scan_end: usize,
    total_slots: usize,
) -> Vec<Pattern> {
    if total_slots == 0 {
        return Vec::new();
    }
    let Some(unpack_idx): Option<usize> = (match_class_idx + 1..scan_end)
        .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::UnpackSequence(_)))
    else {
        return recover_class_subpatterns_subscript(
            code,
            stream,
            match_class_idx,
            scan_end,
            total_slots,
        );
    };
    let mut slots: Vec<Pattern> = vec![
        Pattern::MatchAs {
            pattern: None,
            name: None
        };
        total_slots
    ];
    let mut value_stack: Vec<usize> = (0..total_slots).rev().collect();
    let mut k: usize = unpack_idx + 1;
    while !value_stack.is_empty() && k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::Swap(depth) => {
                let len: usize = value_stack.len();
                let d: usize = *depth as usize;
                if d >= 2 && d <= len {
                    value_stack.swap(len - 1, len - d);
                }
                k += 1;
            }
            CanonicalOp::Pop => {
                value_stack.pop();
                k += 1;
            }
            CanonicalOp::StoreFast(slot) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        local_name_at(code, *slot, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreName(slot) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        name_at(&code.names, *slot, k, "name").unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreFastLoadFast(store_slot, _) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        local_name_at(code, *store_slot, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Some(si) = value_stack.pop() {
                    let name_a: String =
                        local_name_at(code, *a, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name_a),
                    };
                }
                if let Some(si) = value_stack.pop() {
                    let name_b: String =
                        local_name_at(code, *b, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name_b),
                    };
                }
                k += 1;
            }
            CanonicalOp::LoadConst(slot) => {
                if let Some(si) = value_stack.pop() {
                    let expr: Expr = load_const(code, *slot, k).unwrap_or(Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    });
                    slots[si] = Pattern::MatchValue(expr);
                }
                k = skip_value_test(stream, k + 1, scan_end);
            }
            CanonicalOp::LoadSmallInt(v) => {
                if let Some(si) = value_stack.pop() {
                    slots[si] = Pattern::MatchValue(Expr::Constant {
                        value: ConstValue::Int(i128::from(*v)),
                        line: None,
                    });
                }
                k = skip_value_test(stream, k + 1, scan_end);
            }
            _ => {
                k += 1;
            }
        }
    }
    slots
}

/// Recover class sub-patterns from the 3.10 subscript-indexed lowering. There `MATCH_CLASS` leaves
/// the matched-attrs tuple on the stack and each NON-wildcard slot is addressed by index:
/// `DUP_TOP; LOAD_CONST <i>; BINARY_SUBSCR` selects attr `i`. A literal slot follows immediately with
/// `LOAD_CONST/LOAD_SMALL_INT lit; COMPARE_OP; gate` -> `MatchValue`. A captured slot instead rotates
/// its fetched value under the subject (`ROT_TWO`/`ROT_THREE`/...) and defers binding: after the whole
/// subscript section, a subject-drop `POP_TOP` precedes a contiguous run of `STORE_FAST`/`STORE_NAME`
/// that bind the captured slots in their access order. Wildcard slots emit nothing. The walk therefore
/// records value tests by index and capture indices in access order during the subscript section, then
/// zips the deferred store run to those capture indices; unaddressed slots stay wildcard.
fn recover_class_subpatterns_subscript(
    code: &CodeObject,
    stream: &DecodedStream,
    match_class_idx: usize,
    scan_end: usize,
    total_slots: usize,
) -> Vec<Pattern> {
    let mut slots: Vec<Pattern> = vec![
        Pattern::MatchAs {
            pattern: None,
            name: None
        };
        total_slots
    ];
    let mut capture_indices: Vec<usize> = Vec::new();
    let mut k: usize = match_class_idx + 1;
    while k < scan_end
        && matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::Pop
        )
    {
        k += 1;
    }
    while k + 2 < scan_end {
        if !matches!(stream.ops[k], CanonicalOp::Dup) {
            break;
        }
        let idx_at: usize = k + 1;
        let CanonicalOp::LoadConst(idx_const) = stream.ops[idx_at] else {
            break;
        };
        if !matches!(stream.ops[idx_at + 1], CanonicalOp::LoadSubscr) {
            break;
        }
        let slot_idx: Option<usize> = const_index_value(code, idx_const, idx_at);
        let body: usize = idx_at + 2;
        match &stream.ops[body] {
            CanonicalOp::LoadConst(lit) => {
                if let Some(si) = slot_idx
                    && si < slots.len()
                    && let Ok(expr) = load_const(code, *lit, body)
                {
                    slots[si] = Pattern::MatchValue(expr);
                }
                k = skip_value_test(stream, body + 1, scan_end);
            }
            CanonicalOp::LoadSmallInt(v) => {
                if let Some(si) = slot_idx
                    && si < slots.len()
                {
                    slots[si] = Pattern::MatchValue(Expr::Constant {
                        value: ConstValue::Int(i128::from(*v)),
                        line: None,
                    });
                }
                k = skip_value_test(stream, body + 1, scan_end);
            }
            CanonicalOp::RotN(_) | CanonicalOp::Swap(_) => {
                if let Some(si) = slot_idx {
                    capture_indices.push(si);
                }
                k = body + 1;
            }
            _ => {
                break;
            }
        }
    }
    if !capture_indices.is_empty() {
        let mut store_at: usize = k;
        let mut bound: usize = 0;
        while store_at < scan_end && bound < capture_indices.len() {
            let name: Option<String> = match stream.ops[store_at] {
                CanonicalOp::StoreFast(s) => local_name_at(code, s, store_at).ok(),
                CanonicalOp::StoreName(s) => name_at(&code.names, s, store_at, "name").ok(),
                _ => None,
            };
            if let Some(n) = name {
                let si: usize = capture_indices[bound];
                if si < slots.len() {
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(n),
                    };
                }
                bound += 1;
            }
            store_at += 1;
        }
    }
    slots
}

/// Read the integer value of the `LOAD_CONST` that addresses a 3.10 class sub-pattern slot, as a
/// non-negative slot index. Returns `None` for non-integer or negative constants.
fn const_index_value(code: &CodeObject, idx_const: u32, offset: usize) -> Option<usize> {
    match load_const(code, idx_const, offset).ok()? {
        Expr::Constant {
            value: ConstValue::Int(i),
            ..
        } => usize::try_from(i).ok(),
        _ => None,
    }
}

/// Advance past the `COMPARE_OP` plus its fail gate that follow a literal load in a class value
/// sub-test, returning the index of the next sub-pattern op so the caller resumes at the next slot.
fn skip_value_test(stream: &DecodedStream, from: usize, scan_end: usize) -> usize {
    let mut k: usize = from;
    while k < scan_end
        && matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    {
        k += 1;
    }
    if k < scan_end && matches!(stream.ops[k], CanonicalOp::Compare(_) | CanonicalOp::ToBool) {
        k += 1;
        while k < scan_end
            && matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        {
            k += 1;
        }
        if k < scan_end && is_match_fail_jump(&stream.ops[k]) {
            k += 1;
        }
    }
    k
}

/// A guard is boolean-expr bytecode after the pattern binds that ends in a `PopJumpIf*` to the next
/// arm head, distinct from the pattern's own structural gates. Detect it as a non-trivial expression
/// span (loads + ops) terminating in a fail jump within the arm.
fn extract_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<Expr> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let guard_jump: usize =
        (body_start..scan_end).find(|&k: &usize| is_arm_gate(stream, k, fail_target))?;
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[body_start..guard_jump]).ok()?;
    let expr: Expr = residual.into_iter().next_back()?;
    if matches!(stream.ops[guard_jump], CanonicalOp::PopJumpIfTrue(_)) {
        Some(Expr::UnaryOp {
            op: crate::ast::node::UnaryOpKind::Not,
            operand: Box::new(expr),
        })
    } else {
        Some(expr)
    }
}

fn guard_body_start(
    stream: &DecodedStream,
    body_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    (body_start..scan_end)
        .find(|&k: &usize| is_arm_gate(stream, k, fail_target))
        .map_or(body_start, |j: usize| {
            match_body_start(stream, j + 1, fail_target, region_end)
        })
}

fn region_has_match_op(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::MatchClass(_)
                | CanonicalOp::MatchSequence
                | CanonicalOp::MatchMapping
                | CanonicalOp::MatchKeys
        )
    })
}

/// Decide whether `[subject_split, hi)` is a genuine `match` rather than a walrus / `if`-elif /
/// `all(genexpr)` chain that incidentally shares the `Dup; <load>; Compare; PopJumpIf` shape. A
/// structural `MATCH_*` opcode is conclusive. Otherwise require the one signature `CPython` emits
/// only for a value/or `case`: a duplicated subject tested to a fail gate whose SUCCESS fall-through
/// is the `POP_TOP` that drops the just-tested copy. A walrus consumes its value in the compare and
/// drops no copy; an `if` / `all(genexpr)` chain has no leading subject `Dup` feeding the compare.
fn is_genuine_match_region(stream: &DecodedStream, subject_split: usize, hi: usize) -> bool {
    if region_has_match_op(stream, subject_split, hi) {
        return true;
    }
    (subject_split..hi).any(|k: usize| is_dup_value_arm_with_cleanup(stream, k, hi))
}

/// A `Dup`/`Copy 1` of the subject at `idx` that feeds a `Compare` fail gate whose success
/// fall-through is the subject-cleanup `POP_TOP` (3.10/3.12+ value/or `case`) or a `JUMP_FORWARD`
/// to a shared body (3.11 forward-jump or-pattern). No walrus or boolean comparison chain produces
/// this, since those consume the value in the compare and drop no copy.
fn is_dup_value_arm_with_cleanup(stream: &DecodedStream, idx: usize, hi: usize) -> bool {
    if !is_subject_dup(&stream.ops[idx]) {
        return false;
    }
    let mut k: usize = idx + 1;
    let mut saw_compare: bool = false;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadAttr(_)
            | CanonicalOp::Dup
            | CanonicalOp::Copy(_)
            | CanonicalOp::ToBool => k += 1,
            CanonicalOp::Compare(_) => {
                saw_compare = true;
                k += 1;
            }
            op if saw_compare && is_match_fail_jump(op) => {
                return matches!(
                    first_significant(stream, k + 1, hi).map(|n: usize| &stream.ops[n]),
                    Some(CanonicalOp::Pop | CanonicalOp::JumpForward(_))
                );
            }
            _ => return false,
        }
    }
    false
}

/// Recover a two-case `match <subject>:\n  case <lit>:\n    ...\n  case _:\n    ...` whose single-literal
/// arm `CPython` lowers without the usual subject `COPY`/`DUP` (there is nothing to keep for a later
/// arm): `<subject>; LOAD_CONST <lit>; COMPARE_OP ==; POP_JUMP_IF_FALSE wild; <arm1>; wild: NOP; <arm2>`.
/// The generic match-head scan needs a subject dup, so this falls through to the if-structurer and
/// recovers a plain `if <subject> == <lit>:` — which recompiles ONE byte short because it drops the
/// wildcard arm's subject-discard `POP_TOP` (peephole-folded to that `NOP` at the second-arm head). The
/// `NOP` at the `POP_JUMP_IF_FALSE` target is the unambiguous match-wildcard signal (a real
/// `if x == lit:` has the two arms contiguous, no `NOP`); rebuild the `match` so the discard regenerates.
fn try_structure_literal_wildcard_match(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !stream.supports_match() {
        return Ok(None);
    }
    let Some(jump_idx): Option<usize> = (lo..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        )
    }) else {
        return Ok(None);
    };
    let Some(cmp_idx): Option<usize> = last_significant_back(stream, lo, jump_idx) else {
        return Ok(None);
    };
    if !matches!(stream.ops[cmp_idx], CanonicalOp::Compare(CmpOp::Eq)) {
        return Ok(None);
    }
    let Some(lit_idx): Option<usize> = last_significant_back(stream, lo, cmp_idx) else {
        return Ok(None);
    };
    let literal: Expr = match &stream.ops[lit_idx] {
        CanonicalOp::LoadConst(slot) => load_const(code, *slot, lit_idx)?,
        CanonicalOp::LoadSmallInt(v) => Expr::Constant {
            value: ConstValue::Int(i128::from(*v)),
            line: None,
        },
        _ => return Ok(None),
    };
    let Some(wild): Option<usize> = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t < hi)
    else {
        return Ok(None);
    };
    if !matches!(stream.ops[wild], CanonicalOp::Nop) {
        return Ok(None);
    }
    let subject_end: usize = lit_idx;
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..subject_end])?;
    let Some(subject): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    if !head.is_empty() {
        return Ok(None);
    }
    let arm1: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, wild)?;
    if !matches!(
        arm1.last(),
        Some(Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Break | Stmt::Continue)
    ) {
        return Ok(None);
    }
    let arm2: Vec<Stmt> = structure_stmts(code, stream, wild + 1, hi)?;
    let cases: Vec<MatchCase> = vec![
        MatchCase {
            pattern: Pattern::MatchValue(literal),
            guard: None,
            body: non_empty(arm1),
        },
        MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: non_empty(arm2),
        },
    ];
    Ok(Some(vec![Stmt::Match {
        subject,
        cases,
        line: None,
    }]))
}

fn structure_match(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(subject_split): Option<usize> = match_subject_split(stream, lo, hi) else {
        return Ok(None);
    };
    if subject_split <= lo {
        return Ok(None);
    }
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..subject_split])?;
    let Some(subject): Option<Expr> = head_residual.into_iter().next_back() else {
        return Ok(None);
    };

    if !is_genuine_match_region(stream, subject_split, hi) {
        return Ok(None);
    }

    let mut cases: Vec<MatchCase> = Vec::new();
    let mut arm_start: usize = subject_split;
    while arm_start < hi {
        let Some(arm): Option<ParsedArm> = extract_match_case(code, stream, arm_start, hi) else {
            break;
        };
        let body_end: usize = arm.next_arm.min(hi);
        let body_start: usize = arm.body_start.min(body_end);
        let body: Vec<Stmt> = if body_start < body_end {
            structure_stmts(code, stream, body_start, body_end)?
        } else {
            Vec::new()
        };
        cases.push(MatchCase {
            pattern: arm.pattern,
            guard: arm.guard,
            body: non_empty(body),
        });
        if arm.next_arm <= arm_start {
            break;
        }
        arm_start = arm.next_arm;
    }

    if cases.len() < 2 {
        return Ok(None);
    }
    if expr_references_code_const(&subject) || !cases.iter().all(case_is_plausible) {
        return Ok(None);
    }

    let cases: Vec<MatchCase> = merge_or_arms(cases);

    let mut out: Vec<Stmt> = head_stmts;
    out.push(Stmt::Match {
        subject,
        cases,
        line: None,
    });
    Ok(Some((out, hi)))
}

/// Whether an expression carries a `__DR_CODE_CONST_*` placeholder for a nested code object. Such a
/// reference inside a match subject or pattern only arises from misreading non-match bytecode (e.g.
/// an inlined `all(genexpr)`), so a match carrying one is spurious and must be rejected.
fn expr_references_code_const(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id.starts_with(DR_CODE_CONST_PREFIX))
}

fn name_is_code_const(name: Option<&String>) -> bool {
    name.is_some_and(|n: &String| n.starts_with(DR_CODE_CONST_PREFIX))
}

/// A pattern is implausible (evidence the region is not really a `match`) when it binds or matches a
/// nested code-object placeholder - impossible in real `match` syntax.
fn pattern_is_plausible(pattern: &Pattern) -> bool {
    match pattern {
        Pattern::MatchValue(expr) => !expr_references_code_const(expr),
        Pattern::MatchClass { cls, .. } => !expr_references_code_const(cls),
        Pattern::MatchStar(name) => !name_is_code_const(name.as_ref()),
        Pattern::MatchAs { pattern, name } => {
            !name_is_code_const(name.as_ref())
                && pattern
                    .as_deref()
                    .is_none_or(|p: &Pattern| pattern_is_plausible(p))
        }
        Pattern::MatchOr(alts) => alts.iter().all(pattern_is_plausible),
        Pattern::MatchSequence(items) => items.iter().all(pattern_is_plausible),
        Pattern::MatchMapping { patterns, .. } => patterns.iter().all(pattern_is_plausible),
        Pattern::MatchSingleton(_) => true,
    }
}

fn case_is_plausible(case: &MatchCase) -> bool {
    pattern_is_plausible(&case.pattern)
}

/// Adjacent arms that share an identical body and are plain value/singleton patterns are the
/// `CPython` expansion of a single `case a | b | c:` arm; an `(a | b | c) as name` arm expands the
/// same way with each alt re-binding `name`. Fold consecutive value-like arms (optionally `as`
/// bound to one name) with matching bodies back into a single `MatchOr` (wrapped in `MatchAs` when
/// a binding is present).
fn merge_or_arms(cases: Vec<MatchCase>) -> Vec<MatchCase> {
    let mut out: Vec<MatchCase> = Vec::with_capacity(cases.len());
    for case in cases {
        if let Some(last) = out.last_mut()
            && last.guard.is_none()
            && case.guard.is_none()
            && last.body == case.body
            && let Some((last_inner, last_name)) = or_mergeable_parts(&last.pattern)
            && let Some((case_inner, case_name)) = or_mergeable_parts(&case.pattern)
            && last_name == case_name
        {
            let alts: Vec<Pattern> = merge_patterns(last_inner, case_inner);
            let merged: Pattern = Pattern::MatchOr(alts);
            last.pattern = match last_name {
                Some(name) => Pattern::MatchAs {
                    pattern: Some(Box::new(merged)),
                    name: Some(name),
                },
                None => merged,
            };
            continue;
        }
        out.push(case);
    }
    out
}

/// Decompose an or-mergeable arm pattern into `(value_or_inner, optional_as_name)`. Bare
/// value/singleton/or patterns carry no name; an `(value) as name` arm carries the name and its
/// inner value pattern.
fn or_mergeable_parts(pattern: &Pattern) -> Option<(Pattern, Option<String>)> {
    match pattern {
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) | Pattern::MatchOr(_) => {
            Some((pattern.clone(), None))
        }
        Pattern::MatchAs {
            pattern: Some(inner),
            name: Some(name),
        } if matches!(
            inner.as_ref(),
            Pattern::MatchValue(_) | Pattern::MatchSingleton(_) | Pattern::MatchOr(_)
        ) =>
        {
            Some((inner.as_ref().clone(), Some(name.clone())))
        }
        _ => None,
    }
}

fn merge_patterns(left: Pattern, right: Pattern) -> Vec<Pattern> {
    let mut alts: Vec<Pattern> = match left {
        Pattern::MatchOr(existing) => existing,
        other => vec![other],
    };
    match right {
        Pattern::MatchOr(more) => alts.extend(more),
        other => alts.push(other),
    }
    alts
}

fn legacy_with_cleanup_idx(stream: &DecodedStream, setup_idx: usize, rel: u32) -> Option<usize> {
    let setup_byte: u32 = *stream.offsets.get(setup_idx)?;
    let delta: u32 = if stream.instr_unit_jumps {
        rel.saturating_mul(2)
    } else {
        rel
    };
    let cleanup_byte: u32 = setup_byte
        .saturating_add(u32::try_from(WIDE_STEP).unwrap_or(2))
        .saturating_add(delta);
    stream.index_for_offset(cleanup_byte)
}

fn is_legacy_with_exit_triple(stream: &DecodedStream, start: usize, hi: usize) -> bool {
    let Some(first): Option<usize> = first_significant(stream, start, hi) else {
        return false;
    };
    if !matches!(stream.ops[first], CanonicalOp::LoadConst(_)) {
        return false;
    }
    let Some(dup_a): Option<usize> = first_significant(stream, first + 1, hi) else {
        return false;
    };
    if !matches!(stream.ops[dup_a], CanonicalOp::Dup) {
        return false;
    }
    let Some(dup_b): Option<usize> = first_significant(stream, dup_a + 1, hi) else {
        return false;
    };
    if !matches!(stream.ops[dup_b], CanonicalOp::Dup) {
        return false;
    }
    let Some(call): Option<usize> = first_significant(stream, dup_b + 1, hi) else {
        return false;
    };
    matches!(stream.ops[call], CanonicalOp::CallFunction(3))
}

/// Recover the pre-3.11 `with cm: return <const>` idiom whose returned value is re-materialized AFTER
/// the implicit `__exit__(None, None, None)` cleanup (`LOAD_CONST None; DUP; DUP; CALL 3; POP; LOAD
/// <value>; RETURN_VALUE`) rather than stashed across it via `ROT_N`. `body_end` points at the cleanup
/// `LOAD_CONST None`; skip past the cleanup `CALL` and discarding `POP`, then recover the trailing
/// return ONLY when it sits on the straight-line normal-exit path - any `WITH_EXCEPT_START` /
/// `PUSH_EXC_INFO` handler op or forward conditional jump before the return marks the surrounding
/// function epilogue reached on fall-through, which must not be folded into the with body.
fn legacy_with_post_cleanup_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    region_end: usize,
) -> Result<Option<Stmt>> {
    if !is_legacy_with_exit_triple(stream, body_end, region_end) {
        return Ok(None);
    }
    let Some(call): Option<usize> = (body_end..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
        )
    }) else {
        return Ok(None);
    };
    let Some(pop): Option<usize> = first_significant(stream, call + 1, region_end) else {
        return Ok(None);
    };
    if !matches!(stream.ops[pop], CanonicalOp::Pop) {
        return Ok(None);
    }
    let ret_start: usize = pop + 1;
    let Some(ret_idx): Option<usize> = (ret_start..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(None);
    };
    let guarded: bool = (ret_start..ret_idx).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
        ) || is_forward_cond_jump(&stream.ops[k])
    });
    if guarded {
        return Ok(None);
    }
    recover_return_at(code, stream, ret_start, region_end)
}

fn legacy_with_body_bound(
    stream: &DecodedStream,
    body_start: usize,
    region_end: usize,
) -> (usize, bool) {
    let mut depth: usize = 0;
    let mut k: usize = body_start;
    while k < region_end {
        match &stream.ops[k] {
            CanonicalOp::SetupWith(_) => {
                depth += 1;
                k += 1;
            }
            CanonicalOp::RotN(2 | 3) => {
                if depth == 0 {
                    return (k, true);
                }
                depth -= 1;
                k += 1;
            }
            CanonicalOp::LoadConst(_) if is_legacy_with_exit_triple(stream, k, region_end) => {
                if depth == 0 {
                    return (k, false);
                }
                depth -= 1;
                k += 1;
            }
            _ => k += 1,
        }
    }
    (region_end, false)
}

fn region_contains_setup_with(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::SetupWith(_)))
}

fn region_contains_setup_async_with(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::SetupAsyncWith))
}

/// Pre-3.11 `async with cm as v:` block form: `<cm> / BEFORE_ASYNC_WITH / GET_AWAITABLE /
/// LOAD_CONST None / YIELD_FROM` (await `__aenter__`) / `SETUP_ASYNC_WITH` / `STORE v` or `POP` /
/// body / `POP_BLOCK` / await `__aexit__`. The context manager is the residual before
/// `BEFORE_ASYNC_WITH`; the body runs from after the enter-result store/pop to the normal-path
/// `__aexit__` await (`GET_AWAITABLE` after the `POP_BLOCK`). `return EXPR` bodies land after the
/// exit await, mirroring `structure_legacy_with`.
fn structure_legacy_async_with(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(setup_idx): Option<usize> =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::SetupAsyncWith))
    else {
        return Ok(None);
    };
    let Some(before_idx): Option<usize> = (lo..setup_idx)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::BeforeAsyncWith))
    else {
        return Ok(None);
    };
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..before_idx])?;
    let context_expr: Expr = head_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let mut body_start: usize = setup_idx + 1;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(body_start) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, body_start).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, body_start, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => body_start += 1,
        _ => {}
    }
    let exit_await: usize = (body_start..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .unwrap_or(hi);
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_start, exit_await)?;
    if let Some(ret) = legacy_async_with_trailing_return(code, stream, exit_await, hi)? {
        body.push(ret);
    }
    let with_stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr,
            optional_vars,
        }],
        body: non_empty(body),
        is_async: true,
        line: None,
    };
    let mut out: Vec<Stmt> = head_stmts;
    out.push(with_stmt);
    Ok(Some((out, hi)))
}

/// A pre-3.11 `async with` body's trailing `return EXPR`: the normal-path `__aexit__` await runs
/// before the `return`, so skip the `GET_AWAITABLE` / `LOAD_CONST None` / `YIELD_FROM` poll and any
/// cleanup `NOP`s, then re-simulate the residual return value.
fn legacy_async_with_trailing_return(
    code: &CodeObject,
    stream: &DecodedStream,
    exit_await: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    if exit_await >= hi || !matches!(stream.ops[exit_await], CanonicalOp::GetAwaitable) {
        return Ok(None);
    }
    let after_poll: usize = skip_await_poll(stream, exit_await + 1, hi);
    recover_return_at(code, stream, after_poll, hi)
}

fn structure_legacy_with(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(setup_idx): Option<usize> =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::SetupWith(_)))
    else {
        return Ok(None);
    };
    let CanonicalOp::SetupWith(rel): CanonicalOp = stream.ops[setup_idx] else {
        return Ok(None);
    };
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..setup_idx])?;
    let context_expr: Expr = head_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let mut body_start: usize = setup_idx + 1;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(body_start) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, body_start).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, body_start, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => {
            body_start += 1;
        }
        _ => {}
    }
    let cleanup_idx: usize =
        legacy_with_cleanup_idx(stream, setup_idx, rel).map_or(hi, |idx: usize| idx.min(hi));
    let region_end: usize = cleanup_idx.min(hi).max(body_start);
    let (body_end, is_return): (usize, bool) =
        legacy_with_body_bound(stream, body_start, region_end);
    let body: Vec<Stmt> = if is_return && !region_contains_setup_with(stream, body_start, body_end)
    {
        let (mut stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[body_start..body_end])?;
        if let Some(value) = residual.into_iter().next_back() {
            stmts.push(Stmt::Return(Some(value)));
        }
        stmts
    } else {
        let mut stmts: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if !region_contains_setup_with(stream, body_start, body_end)
            && let Some(ret) = legacy_with_post_cleanup_return(code, stream, body_end, region_end)?
        {
            stmts.push(ret);
        }
        stmts
    };
    let with_stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr,
            optional_vars,
        }],
        body: non_empty(body),
        is_async: false,
        line: None,
    };
    let mut out: Vec<Stmt> = head_stmts;
    out.push(with_stmt);
    Ok(Some((out, hi)))
}

/// True when a then-branch's trailing skip-jump at `last` exits the current region `[.., hi)` to a
/// SHARED outer join (its target lands at or past `hi`), confirming the else clause occupies the rest
/// of the region `[target, hi)`. Pre-3.x `CPython` peephole-folds the inner `if`'s normal-exit jump
/// straight to the OUTERMOST `if/elif/else` join when the inner `if/else` is the last statement of an
/// enclosing branch - there is nothing between the inner join and the outer join, so the byte-saving
/// jump skips both. The standard else-detection requires the skip-target to stay inside `hi` and so
/// drops the else, flattening it as an unconditional sibling. This recovers it: the region from the
/// `JUMP_IF_FALSE` target up to `hi` is a real, non-empty else suite, and the skip lands no earlier
/// than `hi`. Gated to pre-3.x (`major < 3`): the modern 3.8-3.14 matrix is exhaustively proven and
/// its joins never overshoot the enclosing region, so it must not be perturbed.
fn else_jump_exits_to_shared_join(
    stream: &DecodedStream,
    last: usize,
    target: usize,
    hi: usize,
) -> bool {
    if stream.version.major() >= 3 {
        return false;
    }
    let Some(join): Option<usize> = resolve_jump_target(stream, last, &stream.ops[last]) else {
        return false;
    };
    join >= hi && target < hi
}

/// True when a then-branch ending at `body_end` is the first arm of an `if/elif` (no trailing `else`)
/// inside a loop. `CPython` lowers such an `if A: ... elif B: ...` so the first arm's normal exit is a
/// `JUMP_BACKWARD` straight to the loop header (the implicit per-iteration continue), and the `elif`
/// test occupies `[target, hi)`, itself exiting via its own back-edge. The generic structurer only
/// opens an `else` on a FORWARD skip-jump, so without this the two arms flatten into sibling `if`s and
/// the first arm loses its skip — the recompiled bytecode drops the `JUMP` that `CPython` emits to hop
/// over the `elif` test. Recover it as a real `orelse` so the emitter renders `elif` and the skip
/// regenerates. Gated to inside a loop frame whose header the first arm's back-edge targets, with a
/// genuine forward conditional opening `[target, hi)`.
fn elif_arm_continues_to_loop(
    stream: &DecodedStream,
    jump_idx: usize,
    body_end: usize,
    target: usize,
    hi: usize,
) -> Option<(usize, usize)> {
    if target >= hi || body_end <= jump_idx + 1 {
        return None;
    }
    let header: usize = loop_continue_target()?;
    let back: usize = (jump_idx + 1..body_end)
        .rev()
        .find(|&k: &usize| is_back_edge(&stream.ops[k]))?;
    if (back + 1..body_end).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::Push(_)
        )
    }) {
        return None;
    }
    let lands_on_header: bool =
        resolve_jump_target(stream, back, &stream.ops[back]).is_some_and(|t: usize| t <= header);
    if !lands_on_header {
        return None;
    }
    let elif_lo: usize = first_significant(stream, back + 1, hi).unwrap_or(target);
    let elif_jump: usize = (elif_lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    let valid: bool = resolve_jump_target(stream, elif_jump, &stream.ops[elif_jump])
        .is_some_and(|t: usize| t > elif_jump && t <= hi);
    if !valid {
        return None;
    }
    let orelse_at: usize = (back + 1).min(body_end);
    Some((back, orelse_at))
}

/// Structure the `orelse` region of an `if/elif` (no trailing `else`) inside a loop, where each `elif`
/// arm is lowered by `CPython` as `<cond> POP_JUMP_IF_{TRUE,FALSE} <arm-body>` with the false path
/// falling into a `JUMP_BACKWARD` to the loop header (the implicit per-iteration continue) and the arm
/// body laid out after that back-edge. The generic forward-if structurer treats the conditional's
/// jump target as the JOIN and so loses both the body and the continue, flushing the test as a bare
/// expression statement. This recovers the arm as `if <cond>: <body>` (recursing into the body and any
/// deeper `elif`), which the emitter renders as `elif` and which recompiles to the same skip/continue
/// layout. Falls back to the generic structurer when the region is not a recognizable arm.
fn structure_elif_chain_arm(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Vec<Stmt>> {
    let Some(cond_at): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return structure_stmts(code, stream, lo, hi);
    };
    let Some(jump_target): Option<usize> =
        resolve_jump_target(stream, cond_at, &stream.ops[cond_at])
            .filter(|t: &usize| *t > cond_at && *t <= hi)
    else {
        return structure_stmts(code, stream, lo, hi);
    };
    let header: usize = match loop_continue_target() {
        Some(h) => h,
        None => return structure_stmts(code, stream, lo, hi),
    };
    let lands_on_header = |idx: usize| -> bool {
        is_back_edge(&stream.ops[idx])
            && resolve_jump_target(stream, idx, &stream.ops[idx])
                .is_some_and(|t: usize| t <= header)
    };
    let jump_skips_arm: bool = matches!(
        stream.ops[cond_at],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    );
    let (arm_body_start, arm_end, next_arm_start): (usize, usize, usize) = if jump_skips_arm {
        let arm_back: usize = (cond_at + 1..jump_target)
            .rev()
            .find(|&k: &usize| lands_on_header(k))
            .unwrap_or(jump_target);
        (cond_at + 1, arm_back, jump_target)
    } else {
        let pre_continue: bool = (cond_at + 1..jump_target).any(|k: usize| lands_on_header(k));
        if !pre_continue {
            return structure_stmts(code, stream, lo, hi);
        }
        let arm_back: Option<usize> = (jump_target..hi).find(|&k: &usize| lands_on_header(k));
        arm_back.map_or((jump_target, hi, hi), |b: usize| {
            (
                jump_target,
                b,
                first_significant(stream, b + 1, hi).unwrap_or(hi),
            )
        })
    };
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..cond_at])?;
    let raw_test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let test: Expr = none_jump_test(stream, cond_at, raw_test.clone()).unwrap_or(raw_test);
    let body: Vec<Stmt> = structure_stmts(code, stream, arm_body_start, arm_end)?;
    let deeper: Vec<Stmt> = if next_arm_start < hi {
        structure_elif_chain_arm(code, stream, next_arm_start, hi)?
    } else {
        Vec::new()
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: deeper,
        line: None,
    });
    Ok(out)
}

fn structure_stmts(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Vec<Stmt>> {
    let hi: usize = hi.min(stream.ops.len());
    if lo >= hi {
        return Ok(Vec::new());
    }
    if let Some(stmts) = try_structure_inline_comprehension(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_inframe_listcomp(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if region_contains_setup_async_with(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_legacy_async_with(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if region_contains_setup_with(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_legacy_with(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if stream.supports_match()
        && region_contains_match_head(stream, lo, hi)
        && !match_head_enclosed_by_try(stream, lo, hi)
        && !match_head_enclosed_by_loop(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_match(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_literal_wildcard_match(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if stream.version.major() == 3
        && stream.version.minor() <= 7
        && let Some(loop_region) = find_legacy_async_for_loop(code, stream, lo, hi)
        && !legacy_async_for_enclosed_by_try(stream, lo, hi, &loop_region)
        && !legacy_async_for_enclosed_by_loop(stream, lo, hi, &loop_region)
    {
        return structure_loop(code, stream, lo, hi, &loop_region);
    }
    if let Some(stmts) = try_structure_guarded_try(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(try_region) = find_try_region(stream, lo, hi)
        && !try_enclosed_by_loop(stream, lo, hi, &try_region)
        && !try_enclosed_by_leading_guard(stream, lo, hi, &try_region)
    {
        return structure_try(code, stream, lo, hi, &try_region);
    }
    if let Some(loop_region) = find_loop(stream, lo, hi)
        && !leading_guard_if_encloses_loop(stream, lo, hi, &loop_region)
        && !loop_enclosed_by_guard(stream, lo, &loop_region)
    {
        return structure_loop(code, stream, lo, hi, &loop_region);
    }
    if let Some(stmts) = structure_backward_continue_guard(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if matches!(stream.ops.get(hi - 1), Some(CanonicalOp::Return))
        && (lo..hi - 1).any(|i: usize| is_value_form_shortcircuit(&stream.ops, i))
        && !(lo..hi - 1).any(|i: usize| {
            is_forward_cond_jump(&stream.ops[i])
                && !is_chain_cond_jump(&stream.ops, i)
                && !is_value_form_shortcircuit(&stream.ops, i)
                && resolve_jump_target(stream, i, &stream.ops[i])
                    .is_some_and(|t: usize| t > i && t <= hi)
        })
        && let Some(expr) = build_shortcircuit_stack_expr(code, stream, lo, hi - 1)?
    {
        return Ok(vec![Stmt::Return(Some(expr))]);
    }
    if let Some(stmts) = try_structure_compound_assert(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    let mut cond_at: Option<usize> = None;
    for i in lo..hi {
        if is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
            && let Some(t) = resolve_jump_target(stream, i, &stream.ops[i])
            && t > i
            && t <= hi
        {
            cond_at = Some(i);
            break;
        }
    }
    let Some(jump_idx): Option<usize> = cond_at else {
        return build_linear_stmts(code, &stream.ops[lo..hi]);
    };
    let target: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= hi)
        .unwrap_or(hi);

    if let Some(stmts) = structure_guarded_continue(code, stream, lo, hi, jump_idx, target)? {
        return Ok(stmts);
    }

    if let Some(stmts) = try_structure_ternary_expr(code, stream, lo, hi, jump_idx, target)? {
        return Ok(stmts);
    }

    if active_version().is_some_and(|v: PyVersion| v.major() == 3 && v.minor() == 13)
        && matches!(stream.ops.get(hi - 1), Some(CanonicalOp::Return))
        && let Some(stmts) = try_structure_return_ternary(code, stream, lo, hi, jump_idx, target)?
    {
        return Ok(stmts);
    }

    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    let raw_test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let negate: bool = matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    );
    let test: Expr = none_jump_test(stream, jump_idx, raw_test.clone()).unwrap_or(raw_test);

    let body_end: usize = target;
    let mut join: usize = target;
    let mut orelse_start: Option<usize> = None;
    let mut else_via_jump: bool = false;
    let mut else_via_continue: bool = false;
    if body_end > jump_idx + 1 {
        let last: usize = body_end - 1;
        if let CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) = stream.ops[last]
            && let Some(j) = resolve_jump_target(stream, last, &stream.ops[last])
            && j > target
            && (j <= hi || else_jump_exits_to_shared_join(stream, last, target, hi))
        {
            join = j.min(hi);
            orelse_start = Some(target);
            else_via_jump = true;
        }
    }
    let mut elif_body_end: usize = body_end;
    if orelse_start.is_none()
        && let Some((back, orelse_at)) =
            elif_arm_continues_to_loop(stream, jump_idx, body_end, target, hi)
    {
        join = hi;
        orelse_start = Some(orelse_at);
        elif_body_end = back;
        else_via_continue = true;
    }
    if orelse_start.is_none()
        && target < hi
        && region_ends_in_hard_terminator(stream, jump_idx + 1, body_end)
        && let Some(epilogue_start) = dead_none_epilogue_start(code, stream, lo, hi)
        && target < epilogue_start
        && region_ends_in_hard_terminator(stream, target, epilogue_start)
    {
        join = hi;
        orelse_start = Some(target);
    }
    let body_real_end: usize = if else_via_jump {
        body_end.saturating_sub(1)
    } else if else_via_continue {
        elif_body_end
    } else {
        body_end
    };
    let fallthrough: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, body_real_end)?;
    let fallthrough: Vec<Stmt> = if else_via_continue {
        fallthrough
    } else {
        rewrite_jump_to_break_continue(stream, fallthrough, jump_idx + 1, body_real_end)
    };
    let jumped: Vec<Stmt> = match orelse_start {
        Some(s) if else_via_continue => structure_elif_chain_arm(code, stream, s, join)?,
        Some(s) => structure_stmts(code, stream, s, join)?,
        None => Vec::new(),
    };
    let jumped: Vec<Stmt> = match orelse_start {
        Some(_) if else_via_continue => jumped,
        Some(s) => rewrite_jump_to_break_continue(stream, jumped, s, join),
        None => jumped,
    };
    let none_jump: bool = stream.none_jump_kind.contains_key(&jump_idx);
    let negated_single_branch: bool =
        !negate && orelse_start.is_none() && !fallthrough.is_empty() && !none_jump;
    let (test, body, orelse): (Expr, Vec<Stmt>, Vec<Stmt>) = if negated_single_branch {
        (
            Expr::UnaryOp {
                op: crate::bytecode::opcode::UnaryOp::Not,
                operand: Box::new(test),
            },
            fallthrough,
            Vec::new(),
        )
    } else if negate || none_jump {
        (test, fallthrough, jumped)
    } else {
        (test, jumped, fallthrough)
    };

    let tail: Vec<Stmt> = structure_stmts(code, stream, join, hi)?;

    let empty_pass_body: bool = target == jump_idx + 1 && orelse_start.is_none();
    let mut out: Vec<Stmt> = head;
    if body.is_empty() && orelse.is_empty() && !empty_pass_body {
        out.push(Stmt::Expr(test));
    } else {
        out.push(Stmt::If {
            test,
            body: if body.is_empty() {
                vec![Stmt::Pass]
            } else {
                body
            },
            orelse,
            line: None,
        });
    }
    out.extend(tail);
    Ok(out)
}

fn build_linear_stmts(code: &CodeObject, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    build_linear_stmts_sim(code, ops).map(|(stmts, _residual): (Vec<Stmt>, Vec<Expr>)| stmts)
}

/// 3.11+ encodes `yield from <iter>` as `GET_YIELD_FROM_ITER / LOAD_CONST None / SEND / YIELD_VALUE
/// / JUMP_BACKWARD_NO_INTERRUPT [/ END_SEND]`. Both `GET_YIELD_FROM_ITER` and the plain `GET_ITER`
/// decode to `CanonicalOp::GetIter`, so detect the `Send` between the `LoadConst` and the
/// `Yield` to fold the four-op send-loop into a single `Expr::YieldFrom`.
fn is_yield_from_send_pattern(ops: &[CanonicalOp], yield_idx: usize) -> bool {
    let mut k: usize = yield_idx;
    let mut saw_send: bool = false;
    let mut saw_const_none: bool = false;
    let mut saw_get_iter: bool = false;
    while k > 0 {
        k -= 1;
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Send(_) if !saw_send => saw_send = true,
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7)
                if saw_send && !saw_const_none =>
            {
                saw_const_none = true;
            }
            CanonicalOp::GetIter if saw_send && saw_const_none && !saw_get_iter => {
                saw_get_iter = true;
                break;
            }
            _ => break,
        }
    }
    saw_send && saw_const_none && saw_get_iter
}

/// Pre-2.3 `YIELD_VALUE` (named `YIELD_STMT` in 2.2's ceval) is a pure statement: yield-expressions
/// did not exist until PEP 342 (2.5), and 2.2's opcode consumes the value and pushes nothing, so the
/// compiler emits no trailing `POP_TOP`. The stack SIM therefore never sees a consumer and the yield
/// is silently dropped as an unflushed residual. For these versions the recovered `yield <value>` is
/// always a statement; emit it directly rather than leaving it on the value stack.
fn is_pre23_statement_yield() -> bool {
    active_version().is_some_and(|v: PyVersion| {
        let (maj, min): (u8, u8) = (v.major(), v.minor());
        maj < 2 || (maj == 2 && min < 3)
    })
}

/// 3.11+ encodes `await x` as `GET_AWAITABLE / LOAD_CONST None / SEND / YIELD_VALUE / RESUME /
/// JUMP_BACKWARD_NO_INTERRUPT [/ END_SEND]`. The mid-poll `YIELD_VALUE` is suspension machinery, not
/// a user `yield`; the stack-based await peephole only collapses it when `GET_AWAITABLE` ran in the
/// same simulation segment. When the structurer splits the poll across segments (loop body hoisted
/// into a sibling branch) the stack peek misses and a spurious `yield None` leaks, which falsely
/// marks the host as an async generator and makes any `return <value>` illegal. The trailing
/// `RESUME / JUMP_BACKWARD_NO_INTERRUPT / (END_SEND | CLEANUP_THROW)` epilogue is unique to the
/// send-poll suspension and never follows a user `yield` (which resumes into `POP` / `STORE` / a
/// plain op), so detect the poll by that forward signature regardless of the segment boundary.
fn is_await_poll_yield(ops: &[CanonicalOp], yield_idx: usize) -> bool {
    let mut k: usize = yield_idx + 1;
    let mut saw_resume: bool = false;
    let mut saw_back_jump: bool = false;
    while k < ops.len() {
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Resume(_) if !saw_resume => saw_resume = true,
            CanonicalOp::JumpBackwardNoInterrupt(_) if saw_resume && !saw_back_jump => {
                saw_back_jump = true;
            }
            CanonicalOp::EndSend | CanonicalOp::CleanupThrow if saw_back_jump => return true,
            _ => return false,
        }
        k += 1;
    }
    false
}

/// Python rejects `return <value>` inside an async generator (`CO_ASYNC_GENERATOR=0x200`); only bare
/// `return` is legal. Recovered code that pops a None constant and emits `return None` triggers a
/// `SyntaxError` on recompile. Strip the None when the host code object is an async generator.
fn filter_async_gen_return(code: &CodeObject, value: Option<Expr>) -> Option<Expr> {
    if code.flags & PY_CO_FLAG_ASYNC_GENERATOR == 0 {
        return value;
    }
    match value {
        Some(Expr::Constant {
            value: ConstValue::None,
            ..
        })
        | None => None,
        other => other,
    }
}

/// Replace an empty-or-skeletal body that ends with an unconditional jump out of the current loop
/// region with `Stmt::Break`/`Stmt::Continue`. The structurer treats `JumpForward`/`JumpAbsolute`
/// as ignorable Nops, so an `if cond: break` body falls to `[]`. Re-derive break/continue by
/// inspecting the last non-Nop op at `[lo, hi)` against the enclosing loop frame's header/exit
/// indices.
/// The compiler peephole-folds `if cond: break` inside a `for` / `while` whose shared loop exit is a
/// `return X` into an inline iterator pop, value load, and `RETURN_VALUE` at the break site (the jump
/// to the exit return is rewritten to the return itself). The recovered body therefore looks like
/// `return X` rather than `break`. The byte signature that distinguishes this from a genuine
/// `return X` written inside the loop is the leading iterator pop: the peephole emits a
/// `POP_TOP`/`POP_ITER` (discarding the loop iterator) before loading the value, whereas a real
/// in-loop return loads the value first and cleans up after with a trailing swap-and-pop. Recover
/// the peephole site as `break` so recompilation regenerates the shared exit and matches the original
/// bytecode layout. Gated on being inside a loop frame and the body collapsing to a lone `Return`.
fn is_peephole_break_return(stream: &DecodedStream, body: &[Stmt], lo: usize, hi: usize) -> bool {
    let [Stmt::Return(Some(value))]: &[Stmt] = body else {
        return false;
    };
    let Some(exit_return): Option<Expr> = loop_exit_return() else {
        return false;
    };
    if *value != exit_return {
        return false;
    }
    let Some(first): Option<usize> = (lo..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    matches!(stream.ops[first], CanonicalOp::Pop)
}

/// Recover a `break` / `continue` that forms the entire body of a pre-3.8 `async for`. Such bodies are
/// laid out in the `StopAsyncIteration` handler fallthrough as a bare `BREAK_LOOP` (which decodes to
/// `Nop` and so structures to an empty `pass`) or a lone `JUMP_ABSOLUTE` back to the `__anext__` poll
/// (the loop header), neither of which the generic body structurer materializes. Only rewrites when the
/// structured body is empty/`pass`: a non-trivial recovered body already carries its real statements and
/// its trailing jump is handled by the in-body `if`-path rewrite.
fn rewrite_legacy_async_for_body(
    stream: &DecodedStream,
    body: Vec<Stmt>,
    body_start: usize,
    region: &LoopRegion,
) -> Vec<Stmt> {
    if body.iter().any(|s: &Stmt| !matches!(s, Stmt::Pass)) {
        return body;
    }
    if body_start == 0 || !stream.pre311_end_finally_idx.contains(&(body_start - 1)) {
        return body;
    }
    let has_break: bool =
        (body_start..region.body_end).any(|k: usize| stream.pre311_break_loop_idx.contains(&k));
    if has_break {
        return vec![Stmt::Break];
    }
    let is_continue: bool = (body_start..region.body_end).any(|k: usize| {
        is_back_edge(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t <= region.header)
    });
    if is_continue {
        return vec![Stmt::Continue];
    }
    body
}

/// Pre-3.8 `break` is a `BREAK_LOOP` opcode that decodes to `Nop`, so a non-empty branch body that
/// ends in `break` (`if x == 3:\n    print('x')\n    break`) loses the break entirely - the surviving
/// statements materialize but the trailing `BREAK_LOOP` vanishes. The existing jump-rewrite only
/// converts an empty/skeletal body whose LAST op is an unconditional jump out of the loop, so it never
/// fires here. When the branch window's last significant op is a recorded `BREAK_LOOP` and the
/// structured body does not already end in a hard terminator, append `Stmt::Break`. Gated implicitly to
/// pre-3.11 (`pre311_break_loop_idx` is empty on 3.11+) so the modern construct matrix is untouched.
fn append_pre311_break_loop(
    stream: &DecodedStream,
    body: &[Stmt],
    lo: usize,
    hi: usize,
) -> Option<Vec<Stmt>> {
    let last_idx: usize = (lo..hi).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    })?;
    if !stream.pre311_break_loop_idx.contains(&last_idx) {
        return None;
    }
    if matches!(
        body.last(),
        Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
    ) {
        return None;
    }
    let mut out: Vec<Stmt> = body.to_vec();
    out.push(Stmt::Break);
    Some(out)
}

fn rewrite_jump_to_break_continue(
    stream: &DecodedStream,
    body: Vec<Stmt>,
    lo: usize,
    hi: usize,
) -> Vec<Stmt> {
    if let Some(appended) = append_pre311_break_loop(stream, &body, lo, hi) {
        return appended;
    }
    if is_peephole_break_return(stream, &body, lo, hi) {
        return vec![Stmt::Break];
    }
    if body
        .iter()
        .any(|s: &Stmt| !matches!(s, Stmt::Pass | Stmt::Expr(_)))
    {
        return body;
    }
    let last: Option<usize> = (lo..hi).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    });
    let Some(last_idx): Option<usize> = last else {
        return body;
    };
    if !matches!(
        stream.ops[last_idx],
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return body;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, last_idx, &stream.ops[last_idx])
    else {
        return body;
    };
    let break_at: Option<usize> = loop_break_target();
    let continue_at: Option<usize> = loop_continue_target();
    if let Some(exit) = break_at
        && target >= exit
    {
        return vec![Stmt::Break];
    }
    if let Some(header) = continue_at
        && target == header
    {
        return vec![Stmt::Continue];
    }
    body
}

#[derive(Debug, Clone, Copy)]
struct InlineComp {
    clear_idx: usize,
    accumulator: usize,
    for_iter: usize,
    end_for: usize,
}

fn detect_inline_comprehension(stream: &DecodedStream, lo: usize, hi: usize) -> Option<InlineComp> {
    let clear_idx: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))?;
    let accumulator: usize = (clear_idx + 1..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BuildList(0) | CanonicalOp::BuildSet(0) | CanonicalOp::BuildMap(0)
        )
    })?;
    let header: usize = (accumulator + 1..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::GetAnext
        )
    })?;
    let end_for: usize = match stream.ops[header] {
        CanonicalOp::ForIter(_) => resolve_jump_target(stream, header, &stream.ops[header])
            .filter(|t: &usize| *t > header && *t <= hi)?,
        _ => (header + 1..hi)
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))
            .map(|e: usize| (e + 1).min(hi))?,
    };
    Some(InlineComp {
        clear_idx,
        accumulator,
        for_iter: header,
        end_for,
    })
}

/// Locate a nested inline-comprehension envelope inside an outer comp body. Python 3.12+ inlines
/// a comp-of-comps as two zero-length `BUILD_LIST`/`BUILD_SET`/`BUILD_MAP` accumulators each with
/// their own `FOR_ITER`/`END_FOR`; the inner accumulator/`FOR_ITER` belongs to the element, not to
/// a sibling `for` clause of the outer comp. Returns the inner envelope so the outer scan stops
/// before it and the inner comp folds as the outer element.
fn detect_nested_inline_comp(
    stream: &DecodedStream,
    body_start: usize,
    outer_end_for: usize,
) -> Option<InlineComp> {
    let accumulator: usize = (body_start..outer_end_for).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BuildList(0) | CanonicalOp::BuildSet(0) | CanonicalOp::BuildMap(0)
        )
    })?;
    let header: usize = (accumulator + 1..outer_end_for).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::GetAnext
        )
    })?;
    let end_for: usize = match stream.ops[header] {
        CanonicalOp::ForIter(_) => resolve_jump_target(stream, header, &stream.ops[header])
            .filter(|t: &usize| *t > header && *t <= outer_end_for)?,
        _ => (header + 1..outer_end_for)
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))
            .map(|e: usize| (e + 1).min(outer_end_for))?,
    };
    let for_iter: usize = header;
    let clear_idx: usize = (body_start..accumulator)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))
        .unwrap_or(body_start);
    Some(InlineComp {
        clear_idx,
        accumulator,
        for_iter,
        end_for,
    })
}

/// Assemble the comprehension element expression for an inline comp whose body spans
/// `[for_iter, end_for)`. When the body contains a nested inline-comp envelope the element is
/// that nested comprehension (recursively structured); otherwise it is the plain residual the
/// existing parts extractor recovers. Returns `(elt, key_value, ifs)`.
fn inline_comp_element(
    code: &CodeObject,
    stream: &DecodedStream,
    for_iter: usize,
    end_for: usize,
    kind: CompKind,
) -> ComprehensionParts {
    let parts: ComprehensionParts =
        extract_inline_comp_parts(code, stream, for_iter, end_for, kind);
    let (_, after_target): (Expr, usize) = comp_loop_target(code, stream, for_iter + 1);
    if let Some(nested) = detect_nested_inline_comp(stream, after_target, end_for)
        && let Some(nested_elt) = inline_comp_expr(code, stream, &nested)
    {
        return ComprehensionParts {
            target: parts.target,
            elt: nested_elt,
            key_value: None,
            ifs: parts.ifs,
        };
    }
    parts
}

/// Recursively structure a (possibly nested) inline comprehension into a single `Expr`. The
/// generators are bounded so an inner comp's `FOR_ITER` is never absorbed as a sibling `for`
/// clause, and the element is recovered via `inline_comp_element`, which recurses on nesting.
fn inline_comp_expr(code: &CodeObject, stream: &DecodedStream, comp: &InlineComp) -> Option<Expr> {
    let kind: CompKind = match stream.ops[comp.accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let iter_search_lo: usize = comp.clear_idx.saturating_sub(4);
    let iter_end: usize = (iter_search_lo..comp.for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .filter(|&k: &usize| k <= comp.clear_idx + 1)
        .unwrap_or(comp.clear_idx);
    let iter_start: usize = (iter_search_lo.saturating_sub(8)..iter_end)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(iter_search_lo, |b: usize| b + 1)
        .min(iter_end);
    let (_, iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, slice_clamped(&stream.ops, iter_start, iter_end)).ok()?;
    let iter: Expr = iter_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts = inline_comp_element(code, stream, comp.for_iter, comp.end_for, kind);
    let nested_bound: usize = detect_nested_inline_comp(stream, comp.for_iter + 1, comp.end_for)
        .map_or(comp.end_for, |n: InlineComp| n.clear_idx);
    let head_is_async: bool = matches!(stream.ops.get(comp.for_iter), Some(CanonicalOp::GetAnext));
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        kind,
        iter.clone(),
        comp.for_iter,
        nested_bound,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: head_is_async,
        });
    }
    Some(comp_expr_from_parts(kind, elt, key_value, generators))
}

fn comp_expr_from_parts(
    kind: CompKind,
    elt: Expr,
    key_value: Option<(Expr, Expr)>,
    generators: Vec<Comprehension>,
) -> Expr {
    match kind {
        CompKind::List => Expr::ListComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Set => Expr::SetComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Gen => Expr::GeneratorExp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Dict => {
            let (k, v): (Expr, Expr) = key_value.unwrap_or((
                elt,
                Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                },
            ));
            Expr::DictComp {
                key: Box::new(k),
                value: Box::new(v),
                generators,
            }
        }
    }
}

/// True when a forward conditional jump (an `if`/`while` guard or sibling branch) precedes the inline
/// comprehension in `[lo, comp.clear_idx)` and skips forward within the region. The comp fold runs at
/// the top of the structurer and rebuilds its leading `head` with the flat value sim, which mangles any
/// preceding control flow; deferring lets the if/loop structurer process the leading statements first
/// and reach the comp as a later top-level statement in its own sub-region. A backward jump (a prior
/// loop's back-edge already structured away) does not count; only a forward branch ahead of the comp.
fn comp_preceded_by_branch(stream: &DecodedStream, lo: usize, comp: &InlineComp) -> bool {
    (lo..comp.clear_idx).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t <= comp.clear_idx)
    })
}

fn try_structure_inline_comprehension(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(comp): Option<InlineComp> = detect_inline_comprehension(stream, lo, hi) else {
        return Ok(None);
    };
    if let Some(region) = find_try_region(stream, lo, hi)
        && region.try_start > lo
        && region.try_start <= comp.clear_idx
        && comp.clear_idx < region.handler_start
        && !try_enclosed_by_loop(stream, lo, hi, &region)
    {
        return Ok(None);
    }
    if comp_preceded_by_branch(stream, lo, &comp) {
        return Ok(None);
    }
    let kind: CompKind = match stream.ops[comp.accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let iter_end: usize = (lo..comp.clear_idx)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(comp.clear_idx);
    let (head, mut iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..iter_end])?;
    let iter: Expr = iter_residual.pop().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let pre_residual: Vec<Expr> = iter_residual;
    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts = inline_comp_element(code, stream, comp.for_iter, comp.end_for, kind);
    let nested_bound: usize = detect_nested_inline_comp(stream, comp.for_iter + 1, comp.end_for)
        .map_or(comp.end_for, |n: InlineComp| n.clear_idx);
    let head_is_async: bool = matches!(stream.ops.get(comp.for_iter), Some(CanonicalOp::GetAnext));
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        kind,
        iter.clone(),
        comp.for_iter,
        nested_bound,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: head_is_async,
        });
    }
    let result: Expr = comp_expr_from_parts(kind, elt, key_value, generators);
    let clear_slots: Vec<u32> = (lo..comp.accumulator)
        .filter_map(|k: usize| match stream.ops[k] {
            CanonicalOp::LoadFastAndClear(slot) => Some(slot),
            _ => None,
        })
        .collect();
    let mut out: Vec<Stmt> = head;
    let tail_stmts: Vec<Stmt> = consume_inline_comp_result(
        code,
        stream,
        result,
        comp.end_for,
        &clear_slots,
        hi,
        pre_residual,
    )?;
    out.extend(tail_stmts);
    Ok(Some(out))
}

/// A pre-3.0 in-frame list comprehension accumulator opens at `idx` with `BUILD_LIST 0` whose
/// resulting list is NOT immediately discarded but iterated into by a following `FOR_ITER` loop
/// terminated by `LIST_APPEND`, the whole `[idx, end_for)` span producing one list value left on
/// the stack for a downstream consumer (`PRINT_ITEM`, `STORE_*`, a `BUILD_TUPLE` element, a call
/// argument, `POP_TOP`). This is the 2.6/2.7 idiom where the comprehension runs in the enclosing
/// frame rather than a nested code object; `SETUP_LOOP` is absent (a statement `for` always carries
/// it), so the bare `BUILD_LIST 0 … GET_ITER … FOR_ITER … LIST_APPEND … JUMP_ABSOLUTE`-back shape
/// is an unambiguous accumulator. Returns the `FOR_ITER` index and the comp's end (the `FOR_ITER`
/// exhaustion target, which spans every nested `for`/`if` clause).
fn inframe_listcomp_at(stream: &DecodedStream, idx: usize, hi: usize) -> Option<(usize, usize)> {
    if !matches!(stream.ops.get(idx), Some(CanonicalOp::BuildList(0))) {
        return None;
    }
    let for_iter: usize =
        (idx + 1..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::ForIter(_)))?;
    let get_iter: usize = (idx + 1..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))?;
    if (idx + 1..get_iter).any(|k: usize| is_value_boundary(&stream.ops[k])) {
        return None;
    }
    let end_for: usize = resolve_jump_target(stream, for_iter, &stream.ops[for_iter])
        .filter(|t: &usize| *t > for_iter && *t <= hi)?;
    let has_append: bool =
        (for_iter + 1..end_for).any(|k: usize| matches!(stream.ops[k], CanonicalOp::ListAppend));
    if !has_append {
        return None;
    }
    Some((for_iter, end_for))
}

/// Recover the pre-3.0 in-frame list comprehension(s) in `[lo, hi)` as real `ListComp` expressions
/// threaded into their downstream consumers, instead of the spurious statement-`for` (with a dropped
/// `LIST_APPEND`) the loop structurer would otherwise emit. Each accumulator span folds to one
/// `Expr`; the consumer run between this comp's end and the next accumulator (or `hi`) is replayed
/// through the value-stack SIM seeded with that list, so `print [x for x in it]` and friends are
/// reconstructed. Gated to `major < 3`: 3.x list comprehensions are separate code objects with their
/// own path.
fn try_structure_inframe_listcomp(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if stream.version.major() >= 3 {
        return Ok(None);
    }
    let Some(comp_start): Option<usize> =
        (lo..hi).find(|&k: &usize| inframe_listcomp_at(stream, k, hi).is_some())
    else {
        return Ok(None);
    };
    let Some((for_iter, end_for)): Option<(usize, usize)> =
        inframe_listcomp_at(stream, comp_start, hi)
    else {
        return Ok(None);
    };

    let (head, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..comp_start])?;

    let get_iter: usize = (comp_start + 1..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(comp_start);
    let iter_start: usize = (comp_start..get_iter)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(comp_start + 1, |b: usize| b + 1)
        .min(get_iter);
    let (_, iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, slice_clamped(&stream.ops, iter_start, get_iter))?;
    let iter: Expr = iter_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });

    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts =
        extract_inline_comp_parts(code, stream, for_iter, end_for, CompKind::List);
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        CompKind::List,
        iter.clone(),
        for_iter,
        end_for,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: false,
        });
    }
    let comp: Expr = comp_expr_from_parts(CompKind::List, elt, key_value, generators);

    let consumer_end: usize = (end_for..hi)
        .find(|&k: &usize| inframe_listcomp_at(stream, k, hi).is_some())
        .unwrap_or(hi);
    let mut seed: Vec<Expr> = head_residual;
    seed.push(comp);
    let (consumed, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[end_for..consumer_end], seed)?;

    let mut out: Vec<Stmt> = head;
    out.extend(consumed);
    out.extend(structure_stmts(code, stream, consumer_end, hi)?);
    Ok(Some(out))
}

fn extract_inline_comp_parts(
    code: &CodeObject,
    stream: &DecodedStream,
    for_iter: usize,
    end_for: usize,
    kind: CompKind,
) -> ComprehensionParts {
    let mut body_start: usize = for_iter + 1;
    let target: Expr = match stream.ops.get(body_start) {
        Some(CanonicalOp::StoreFast(slot)) => {
            body_start += 1;
            local_target(code, *slot, body_start).unwrap_or_else(|_| placeholder_target())
        }
        Some(CanonicalOp::StoreFastLoadFast(t, _)) => {
            local_target(code, *t, body_start).unwrap_or_else(|_| placeholder_target())
        }
        Some(CanonicalOp::BuildTuple(_)) => {
            let (tgt, next): (Expr, usize) =
                recover_tuple_target(code, stream, body_start, end_for);
            body_start = next;
            tgt
        }
        _ => placeholder_target(),
    };
    let mut ifs: Vec<Expr> = Vec::new();
    let mut elt: Option<Expr> = None;
    let mut key_value: Option<(Expr, Expr)> = None;
    let mut elt_start: usize = body_start;
    let mut i: usize = body_start;
    while i < end_for {
        match &stream.ops[i] {
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_) => {
                let cond_end: usize = i;
                let expr_start: usize = cond_expr_start(stream, cond_end, body_start);
                let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[expr_start..cond_end])
                        .unwrap_or_default();
                if let Some(cond) = residual.into_iter().next_back() {
                    let keep_when_true: bool = inline_filter_keeps_when_true(stream, cond_end);
                    ifs.push(if keep_when_true {
                        cond
                    } else {
                        Expr::UnaryOp {
                            op: crate::bytecode::opcode::UnaryOp::Not,
                            operand: Box::new(cond),
                        }
                    });
                }
                let append: usize = (cond_end + 1..end_for)
                    .find(|&k: &usize| {
                        matches!(
                            stream.ops[k],
                            CanonicalOp::ListAppend | CanonicalOp::SetAdd | CanonicalOp::MapAdd
                        )
                    })
                    .unwrap_or(end_for);
                let fallthrough: Option<usize> = first_significant(stream, cond_end + 1, append)
                    .filter(|&k: &usize| !is_back_edge(&stream.ops[k]));
                i = fallthrough.unwrap_or_else(|| {
                    resolve_jump_target(stream, cond_end, &stream.ops[cond_end])
                        .filter(|&t: &usize| t > cond_end && t < append)
                        .unwrap_or(append)
                });
                elt_start = i;
            }
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[elt_start..i]).unwrap_or_default();
                elt = residual.into_iter().next_back();
                break;
            }
            CanonicalOp::MapAdd => {
                let (_, mut residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[elt_start..i]).unwrap_or_default();
                let v: Option<Expr> = residual.pop();
                let k: Option<Expr> = residual.pop();
                if let (Some(kk), Some(vv)) = (k, v) {
                    elt = Some(kk.clone());
                    key_value = Some((kk, vv));
                }
                break;
            }
            _ => i += 1,
        }
    }
    let _ = kind;
    ComprehensionParts {
        target,
        elt: elt.unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        }),
        key_value,
        ifs,
    }
}

/// Collect `n` consecutive `STORE_*` targets that consume the values produced by an `UNPACK_*` op,
/// so the whole sequence can be re-emitted as `t0, t1, ..., tn = <source>`. Returns `(targets,
/// skip)` where `skip` is the number of ops the caller should advance past in the sim loop.
fn collect_unpack_targets(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
    n: usize,
) -> Option<(Vec<Expr>, usize)> {
    if n == 0 {
        return None;
    }
    let mut targets: Vec<Expr> = Vec::with_capacity(n);
    let mut i: usize = start;
    let mut consumed: usize = 0;
    while consumed < n && i < ops.len() {
        match &ops[i] {
            CanonicalOp::StoreFast(slot) => {
                targets.push(local_target(code, *slot, i).ok()?);
                consumed += 1;
            }
            CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => {
                let name: String = name_at(&code.names, *slot, i, "name").ok()?;
                targets.push(Expr::Name {
                    id: name,
                    ctx: ExprCtx::Store,
                    line: None,
                });
                consumed += 1;
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                targets.push(local_target(code, *a, i).ok()?);
                if consumed + 1 >= n {
                    return None;
                }
                targets.push(local_target(code, *b, i).ok()?);
                consumed += 2;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => {
                let group_end: usize = chain_group_end(ops, i)?;
                let target: Expr = recover_chain_target(code, ops, i, group_end)?;
                targets.push(target);
                consumed += 1;
                i = group_end;
                continue;
            }
        }
        i += 1;
    }
    if consumed != n {
        return None;
    }
    Some((targets, i - start))
}

/// Append a `del <target>` statement, merging into the previous `Stmt::Delete` when adjacent so a
/// `DELETE_FAST a; DELETE_FAST b` byte sequence round-trips as the single Python `del a, b`.
fn merge_or_push_delete(out: &mut Vec<Stmt>, target: Expr) {
    if let Some(Stmt::Delete(prev)) = out.last_mut() {
        prev.push(target);
    } else {
        out.push(Stmt::Delete(vec![target]));
    }
}

fn placeholder_target() -> Expr {
    Expr::Name {
        id: "_".to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}

fn recover_tuple_target(
    code: &CodeObject,
    stream: &DecodedStream,
    at: usize,
    hi: usize,
) -> (Expr, usize) {
    let region: LoopRegion = LoopRegion {
        kind: LoopKind::For,
        header: at.saturating_sub(1),
        body_start: at,
        body_end: hi,
        back_edge: hi,
        exit: hi,
        infinite: false,
    };
    recover_for_target(code, stream, &region).unwrap_or_else(|| (placeholder_target(), at + 1))
}

fn inline_filter_keeps_when_true(stream: &DecodedStream, cond_idx: usize) -> bool {
    let jumps_to_continue: bool = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])
        .and_then(|t: usize| {
            first_significant(stream, t, stream.ops.len())
                .map(|s: usize| is_back_edge(&stream.ops[s]))
        })
        .unwrap_or(false);
    let fallthrough_is_continue: bool = first_significant(stream, cond_idx + 1, stream.ops.len())
        .is_some_and(|s: usize| is_back_edge(&stream.ops[s]));
    match stream.ops[cond_idx] {
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_) => {
            !jumps_to_continue && fallthrough_is_continue
        }
        _ => jumps_to_continue || !fallthrough_is_continue,
    }
}

fn consume_inline_comp_result(
    code: &CodeObject,
    stream: &DecodedStream,
    result: Expr,
    end_for: usize,
    clear_slots: &[u32],
    hi: usize,
    pre_residual: Vec<Expr>,
) -> Result<Vec<Stmt>> {
    let is_restore_noise = |op: &CanonicalOp| -> bool {
        matches!(
            op,
            CanonicalOp::Swap(_) | CanonicalOp::Pop | CanonicalOp::Cache | CanonicalOp::Nop
        ) || matches!(op, CanonicalOp::StoreFast(s) if clear_slots.contains(s))
    };
    let mut consumer: usize = end_for;
    while consumer < hi && is_restore_noise(&stream.ops[consumer]) {
        consumer += 1;
    }
    let tail_after = |stream: &DecodedStream, mut j: usize| -> usize {
        while j < hi && is_restore_noise(&stream.ops[j]) {
            j += 1;
        }
        j
    };
    if pre_residual.is_empty() {
        match stream.ops.get(consumer) {
            Some(CanonicalOp::Return | CanonicalOp::ReturnConst(_)) => {
                return Ok(vec![Stmt::Return(Some(result))]);
            }
            Some(CanonicalOp::StoreFast(slot)) => {
                let target: Expr = local_target(code, *slot, consumer)?;
                let mut out: Vec<Stmt> = vec![Stmt::Assign {
                    targets: vec![target],
                    value: result,
                    type_comment: None,
                    line: None,
                }];
                out.extend(structure_stmts(
                    code,
                    stream,
                    tail_after(stream, consumer + 1),
                    hi,
                )?);
                return Ok(out);
            }
            Some(CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot)) => {
                let target: Expr = Expr::Name {
                    id: name_at(&code.names, *slot, consumer, "name")?,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                let mut out: Vec<Stmt> = vec![Stmt::Assign {
                    targets: vec![target],
                    value: result,
                    type_comment: None,
                    line: None,
                }];
                out.extend(structure_stmts(
                    code,
                    stream,
                    tail_after(stream, consumer + 1),
                    hi,
                )?);
                return Ok(out);
            }
            _ => return Ok(vec![Stmt::Expr(result)]),
        }
    }
    let mut seed: Vec<Expr> = pre_residual;
    seed.push(result);
    let consumer_end: usize = (consumer..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))
        .map_or(hi, |next_comp: usize| {
            (consumer..next_comp)
                .rev()
                .find(|&k: &usize| {
                    matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter)
                })
                .map_or(next_comp, |get_iter: usize| {
                    inline_comp_consumer_boundary(stream, consumer, get_iter)
                })
        });
    let (consumed, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[consumer..consumer_end], seed)?;
    let mut out: Vec<Stmt> = if consumed.is_empty() {
        residual
            .into_iter()
            .next_back()
            .map(Stmt::Expr)
            .into_iter()
            .collect()
    } else {
        consumed
    };
    out.extend(structure_stmts(code, stream, consumer_end, hi)?);
    Ok(out)
}

/// The op index at which the seeded replay of an inline-comp consumer must stop so the NEXT inline comp
/// (opening at `get_iter`'s `GET_ITER` ahead of its `LOAD_FAST_AND_CLEAR`) is structured in its own
/// sub-region rather than flattened by the value sim. Walk back from `get_iter` over the leading value
/// loads that belong to the next comp's iterable/operand stack so they are NOT consumed as part of this
/// statement; the boundary is the first op past the current statement's own consumer run.
fn inline_comp_consumer_boundary(
    stream: &DecodedStream,
    consumer: usize,
    get_iter: usize,
) -> usize {
    let mut k: usize = get_iter;
    while k > consumer {
        match stream.ops[k - 1] {
            CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadAttr(_)
            | CanonicalOp::Push(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => k -= 1,
            _ => break,
        }
    }
    k
}

fn first_significant(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    (from..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

/// Whether the `Push(0)` at `idx` is the 3.15 await ABI's SEND-receiver NULL slot, i.e. the
/// immediately preceding significant op (skipping `CACHE`/`NOP`/`EXTENDED_ARG`) is `GET_AWAITABLE`.
/// Pre-3.15 await sequences carry no such slot, so this never fires there; the only other source of
/// `Push(0)` is the `LOAD_GLOBAL`/`LOAD_ATTR` method self-slot, which always PRECEDES its load op and
/// thus is never preceded by `GET_AWAITABLE`.
#[inline]
fn is_await_null_slot(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::GetAwaitable => return true,
            _ => return false,
        }
    }
    false
}

/// The last significant op of `[lo, hi)` is a hard control-flow terminator (`return` / `raise` /
/// `reraise`), ignoring trailing structural padding.
fn region_ends_in_hard_terminator(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    last_significant_back(stream, lo, hi).is_some_and(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
        )
    })
}

fn last_significant_back(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    (lo..hi).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

fn loads_none(code: &CodeObject, op: &CanonicalOp) -> bool {
    matches!(op, CanonicalOp::LoadConst(idx) | CanonicalOp::ReturnConst(idx)
        if matches!(code.consts.get(*idx as usize), Some(Object::None)))
}

/// `[lo, hi)` ends in the dead `LOAD_CONST None; RETURN_VALUE` (or `RETURN_CONST None`) epilogue that
/// the pre-3.11 compiler appends after a fully-terminating `if/else`. This is the precise bytecode
/// fingerprint distinguishing a genuine trailing `else: return` (which carries the dead epilogue) from
/// a fall-through guard chain `if C: return A; return B` (which ends in a bare reachable return, no
/// epilogue): on 3.8/3.9 the former is 7 ops, the latter 6 - `if_else`/`if_elif_else` regress to
/// `CodeDiff` precisely because the recovered fall-through omits the epilogue. The dead `return None`
/// is recognised by an immediately-preceding hard terminator (it is unreachable). On 3.10+ the
/// compiler dropped this epilogue and the else-shape converges with fall-through, so this never fires
/// there - keeping 3.10+ untouched while letting the structurer regenerate the `else` only on the
/// pre-3.11 shape that needs it.
fn dead_none_epilogue_start(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<usize> {
    let last: usize = last_significant_back(stream, lo, hi)?;
    let epilogue_start: usize = match stream.ops[last] {
        CanonicalOp::ReturnConst(idx)
            if matches!(code.consts.get(idx as usize), Some(Object::None)) =>
        {
            last
        }
        CanonicalOp::Return => {
            let prev: usize = last_significant_back(stream, lo, last)?;
            if !loads_none(code, &stream.ops[prev]) {
                return None;
            }
            prev
        }
        _ => return None,
    };
    region_ends_in_hard_terminator(stream, lo, epilogue_start).then_some(epilogue_start)
}

/// A loop-body `if cond:` whose false branch falls through to the loop's back-edge: the compiler
/// emits `<cond> POP_JUMP_IF_{FALSE,TRUE} <loop header / continue>` so the guarded statements run
/// only when the test holds. The conditional jump targets backward (at or before the enclosing
/// loop's continue point) and the remaining body is the guarded suite. Pre-3.11 emits this as a
/// plain `POP_JUMP_IF_FALSE` to an absolute backward target, which the forward-only `cond_at` scan
/// misses - recover it as `if cond: <rest>`.
fn structure_backward_continue_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(continue_target): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let Some(jump_idx): Option<usize> = (lo..hi).find(|&i: &usize| {
        matches!(
            stream.ops[i],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) && resolve_jump_target(stream, i, &stream.ops[i])
            .is_some_and(|t: usize| t <= continue_target + 1 && t <= lo)
    }) else {
        return Ok(None);
    };
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    let Some(test): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    let keep_when_true: bool = matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseBackward(_)
    );
    let test: Expr = if keep_when_true {
        test
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    };
    let body_end: usize = trim_body_back_edge(stream, jump_idx + 1, hi);
    let body: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, body_end)?;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_end, hi)?);
    Ok(Some(out))
}

fn structure_guarded_continue(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(skip_idx): Option<usize> = first_significant(stream, jump_idx + 1, target) else {
        return Ok(None);
    };
    if !is_back_edge(&stream.ops[skip_idx]) {
        return Ok(None);
    }
    let Some(back_target): Option<usize> =
        resolve_jump_target(stream, skip_idx, &stream.ops[skip_idx])
    else {
        return Ok(None);
    };
    if back_target >= jump_idx {
        return Ok(None);
    }
    let after_skip: usize = first_significant(stream, skip_idx + 1, hi).unwrap_or(hi);
    if after_skip != target && target != hi {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    let test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body_end: usize = trim_body_back_edge(stream, target, hi);
    let rest: Vec<Stmt> = structure_stmts(code, stream, target, body_end)?;
    let continues_when_true: bool = matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseBackward(_)
    );
    let guard_test: Expr = if continues_when_true {
        test
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    };
    let mut out: Vec<Stmt> = head;
    if loop_continue_target().is_some() {
        out.push(Stmt::If {
            test: guard_test,
            body: vec![Stmt::Continue],
            orelse: Vec::new(),
            line: None,
        });
        out.extend(rest);
    } else {
        let inverted_test: Expr = if continues_when_true {
            Expr::UnaryOp {
                op: crate::bytecode::opcode::UnaryOp::Not,
                operand: Box::new(guard_test),
            }
        } else {
            match guard_test {
                Expr::UnaryOp {
                    op: crate::bytecode::opcode::UnaryOp::Not,
                    operand,
                } => *operand,
                other => Expr::UnaryOp {
                    op: crate::bytecode::opcode::UnaryOp::Not,
                    operand: Box::new(other),
                },
            }
        };
        out.push(Stmt::If {
            test: inverted_test,
            body: non_empty(rest),
            orelse: Vec::new(),
            line: None,
        });
    }
    out.extend(structure_stmts(code, stream, body_end, hi)?);
    Ok(Some(out))
}

fn trim_body_back_edge(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        end -= 1;
    }
    if end > lo && is_back_edge(&stream.ops[end - 1]) {
        end -= 1;
    }
    end.max(lo)
}

const DR_CHAIN_SENTINEL: &str = "__DR_CHAIN_SENTINEL__";

fn chain_sentinel() -> Expr {
    Expr::Name {
        id: DR_CHAIN_SENTINEL.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn is_chain_sentinel(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_CHAIN_SENTINEL)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainLink {
    None,
    Legacy,
    Modern,
}

fn classify_chain_link(ops: &[CanonicalOp], idx: usize) -> ChainLink {
    if !preceded_by_dup_rot(ops, idx) {
        return ChainLink::None;
    }
    let significant: Vec<&CanonicalOp> = ops
        .iter()
        .skip(idx + 1)
        .filter(|op: &&CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::ToBool
            )
        })
        .take(2)
        .collect();
    let mut after: std::slice::Iter<'_, &CanonicalOp> = significant.iter();
    match after.next().copied() {
        Some(CanonicalOp::JumpIfFalseOrPop(_) | CanonicalOp::JumpIfTrueOrPop(_)) => {
            ChainLink::Legacy
        }
        Some(CanonicalOp::Copy(1)) => match after.next().copied() {
            Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)) => {
                ChainLink::Modern
            }
            _ => ChainLink::None,
        },
        _ => ChainLink::None,
    }
}

fn is_chain_cond_jump(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut compare_idx: Option<usize> = None;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::ToBool
            | CanonicalOp::Copy(1) => {}
            CanonicalOp::Compare(_) => {
                compare_idx = Some(back);
                break;
            }
            _ => break,
        }
    }
    compare_idx.is_some_and(|cmp: usize| classify_chain_link(ops, cmp) == ChainLink::Modern)
}

/// Whether the jump at `idx` is the chained-comparison jump (i.e., the `*_OR_POP` or
/// `Copy 1 + PopJumpIf*` immediately following a chain-link Compare). Used by the boolop short-
/// circuit detector to skip jumps that are part of a `a < b < c` chain rather than `a and b`.
fn is_chain_compare_jump(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut compare_idx: Option<usize> = None;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::ToBool
            | CanonicalOp::Copy(1) => {}
            CanonicalOp::Compare(_) => {
                compare_idx = Some(back);
                break;
            }
            _ => break,
        }
    }
    compare_idx.is_some_and(|cmp: usize| classify_chain_link(ops, cmp) != ChainLink::None)
}

fn preceded_by_dup_rot(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut seen_swap: bool = false;
    let mut seen_dup: bool = false;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_) => seen_swap = true,
            CanonicalOp::Dup | CanonicalOp::Copy(_) => seen_dup = true,
            CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
                if !(seen_swap && seen_dup) => {}
            _ => return seen_swap && seen_dup,
        }
    }
    seen_swap && seen_dup
}

fn build_linear_stmts_sim(
    code: &CodeObject,
    ops: &[CanonicalOp],
) -> Result<(Vec<Stmt>, Vec<Expr>)> {
    build_linear_stmts_sim_seed(code, ops, Vec::new())
}

/// Count of ops to skip after a `JumpForward` that targets the chained-comparison cleanup tail
/// (`RotN(2)+Pop` on 3.8-3.10, `Swap(2)+Pop` on 3.11+). Returns `Some(n)` when the next n ops are
/// the cleanup the SIM must elide so the chain Compare is the lone residual ahead of the consumer
/// (`Return`, `StoreFast`, etc.). The chain bytecode pattern is `JumpForward(_); Swap/Rot; Pop`.
fn compare_chain_cleanup_skip(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    let after: &[CanonicalOp] = ops.get(idx + 1..)?;
    match after {
        [
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_),
            CanonicalOp::Pop,
            ..,
        ] => Some(2),
        _ => None,
    }
}

/// A `return <value>` executed inside `N` open `for`-loops carries the per-iterator stack
/// unwind: each enclosing iterator sitting below the return value is discarded just before
/// `RETURN_VALUE`. Pre-3.15 each iterator is one slot, discarded by a `ROT_TWO; POP_TOP`
/// (pre-3.11) or `SWAP 2; POP_TOP` (3.11-3.14) pair. On 3.15 the `LOAD_FAST_BORROW`/`FOR_ITER`
/// codegen leaves TWO slots per iterator, so the return value is buried two deep and the unwind
/// is a `SWAP 3; POP_TOP; POP_TOP` triple per loop. These groups are pure stack plumbing the SIM
/// never models; left unhandled the trailing `POP_TOP`(s) discard the assembled return value as a
/// bare `Expr` and `RETURN_VALUE` returns nothing. Returns `Some(group_len)` for the cleanup group
/// at `idx` when (a) inside at least one open loop frame and (b) skipping further cleanup
/// groups/padding lands on a `RETURN_VALUE`/`RETURN_CONST`; the SIM skips that group so the value
/// survives to the return. The `SWAP 3` triple is gated to 3.15+ so the 100% stable matrix
/// (<= 3.14) is untouched.
fn iterator_return_cleanup_pair(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    if loop_frame_depth() == 0 {
        return None;
    }
    let allow_borrow_triple: bool =
        active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) >= (3, 15));
    let head_len: usize = cleanup_group_len(ops, idx, allow_borrow_triple)?;
    let mut k: usize = idx + head_len;
    while let Some(op) = ops.get(k) {
        match op {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => k += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return Some(head_len),
            _ => match cleanup_group_len(ops, k, allow_borrow_triple) {
                Some(len) => k += len,
                None => return None,
            },
        }
    }
    None
}

/// Length of the per-loop iterator-unwind group at `idx`, or `None` if no group starts there.
/// `Swap(2)|RotN(2) + Pop` is the 1-slot iterator shape (all versions); `Swap(3) + Pop + Pop` is
/// the 3.15+ 2-slot borrow-iterator shape, matched only when `allow_borrow_triple`.
#[inline]
fn cleanup_group_len(ops: &[CanonicalOp], idx: usize, allow_borrow_triple: bool) -> Option<usize> {
    match ops.get(idx) {
        Some(CanonicalOp::Swap(2) | CanonicalOp::RotN(2))
            if matches!(ops.get(idx + 1), Some(CanonicalOp::Pop)) =>
        {
            Some(2)
        }
        Some(CanonicalOp::Swap(3))
            if allow_borrow_triple
                && matches!(ops.get(idx + 1), Some(CanonicalOp::Pop))
                && matches!(ops.get(idx + 2), Some(CanonicalOp::Pop)) =>
        {
            Some(3)
        }
        _ => None,
    }
}

/// Recover a 3.11+ `SWAP(n)`-based simultaneous tuple assignment such as
/// `a[i], a[j], a[2] = a[j], a[i], a[4]`.
///
/// `CPython` evaluates the right-hand values left-to-right, emits a single `SWAP 2`/`SWAP 3` to
/// reorder them so the store sequence consumes them in target order, then runs the n stores. The
/// current `Swap` SIM op faithfully reorders the stack but the stores then emit n independent
/// `Assign` statements, which sequentializes the swap and silently corrupts the semantics. This
/// recognizer folds the `SWAP` plus the n target stores back into one `Assign { Tuple, Tuple }`.
///
/// `pre_swap_top` holds the n right-hand values currently on the SIM (bottom-to-top). The store
/// region begins at `swap_idx + 1`; its exact length is discovered by re-simulating progressively
/// longer slices, seeded with the post-`SWAP` value order, until exactly n single-target `Assign`
/// statements are produced with an empty residual stack. Returns the merged statement and the
/// number of ops the caller must skip after the `SWAP`. `CPython` only emits the `SWAP` form for
/// n == 2 and n == 3 (n >= 4 uses `BUILD_TUPLE`/`UNPACK_SEQUENCE`, handled elsewhere).
fn try_swap_simultaneous_assign(
    code: &CodeObject,
    ops: &[CanonicalOp],
    swap_idx: usize,
    n: usize,
    pre_swap_top: &[Expr],
) -> Option<(Stmt, usize)> {
    if !matches!(n, 2 | 3) || pre_swap_top.len() != n {
        return None;
    }
    if active_version().is_none_or(|v: PyVersion| v.is_pre_311()) {
        return None;
    }
    let mut post_swap: Vec<Expr> = pre_swap_top.to_vec();
    let last: usize = post_swap.len() - 1;
    post_swap.swap(last, last - (n - 1));
    let region_start: usize = swap_idx + 1;
    if !matches!(
        ops.get(region_start),
        Some(
            CanonicalOp::LoadFast(_)
                | CanonicalOp::LoadName(_)
                | CanonicalOp::LoadGlobal(_)
                | CanonicalOp::LoadFastLoadFast(_, _)
                | CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreFastLoadFast(_, _)
        )
    ) {
        return None;
    }
    let mut end: usize = region_start;
    while end < ops.len() {
        let slice: &[CanonicalOp] = ops.get(region_start..=end)?;
        if let Ok((stmts, residual)) = build_linear_stmts_sim_seed(code, slice, post_swap.clone())
            && residual.is_empty()
            && stmts.len() == n
            && stmts.iter().all(is_single_target_store_assign)
        {
            let mut targets: Vec<Expr> = Vec::with_capacity(n);
            let mut values: Vec<Expr> = Vec::with_capacity(n);
            for stmt in stmts {
                let Stmt::Assign {
                    targets: mut assign_targets,
                    value,
                    ..
                }: Stmt = stmt
                else {
                    return None;
                };
                targets.push(assign_targets.pop()?);
                values.push(value);
            }
            let merged: Stmt = Stmt::Assign {
                targets: vec![Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                }],
                value: Expr::Tuple {
                    elts: values,
                    ctx: ExprCtx::Load,
                },
                type_comment: None,
                line: None,
            };
            return Some((merged, end - swap_idx));
        }
        end += 1;
    }
    None
}

fn is_single_target_store_assign(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign { targets, value, .. }
            if targets.len() == 1
                && matches!(
                    targets[0],
                    Expr::Subscript { .. } | Expr::Attribute { .. } | Expr::Name { .. }
                )
                && !matches!(value, Expr::NamedExpr { .. })
    )
}

fn build_linear_stmts_sim_seed(
    code: &CodeObject,
    ops: &[CanonicalOp],
    seed_stack: Vec<Expr>,
) -> Result<(Vec<Stmt>, Vec<Expr>)> {
    let mut sim: StackSim = StackSim::new();
    sim.stack = seed_stack;
    let mut out: Vec<Stmt> = Vec::new();
    let mut cmp_chain: Option<(Expr, Vec<crate::bytecode::opcode::CmpOp>, Vec<Expr>)> = None;
    let mut fn_meta: std::collections::BTreeMap<u32, FunctionMeta> =
        std::collections::BTreeMap::new();
    let mut boolop: Option<(crate::ast::node::BoolOpKind, Vec<Expr>)> = None;
    let mut boolop_base_depth: usize = 0;
    let mut skip_next: usize = 0;
    let mut print_acc: Option<(Option<Expr>, Vec<Expr>)> = None;
    for (idx, op) in ops.iter().enumerate() {
        if skip_next > 0 {
            skip_next -= 1;
            continue;
        }
        if matches!(op, CanonicalOp::JumpForward(_))
            && let Some(after_skip) = compare_chain_cleanup_skip(ops, idx)
        {
            skip_next = after_skip;
            continue;
        }
        if let Some(group_len) = iterator_return_cleanup_pair(ops, idx) {
            skip_next = group_len - 1;
            continue;
        }
        if boolop.is_some()
            && !is_value_boolop_shortcircuit(ops, idx)
            && sim.stack.len() > boolop_base_depth
        {
            flush_boolop(&mut sim, &mut boolop);
        }
        if let Some(kind) = value_boolop_at(ops, idx) {
            let operand: Expr = sim.pop_or_synth(code, idx);
            match &mut boolop {
                Some((existing, operands)) if *existing == kind => operands.push(operand),
                _ => {
                    sim.push(operand);
                    flush_boolop(&mut sim, &mut boolop);
                    let restart: Expr = sim.pop_or_synth(code, idx);
                    boolop_base_depth = sim.stack.len();
                    boolop = Some((kind, vec![restart]));
                }
            }
            skip_next = boolop_shortcircuit_skip(ops, idx);
            continue;
        }
        if let CanonicalOp::Swap(n) = op
            && matches!(usize::from(*n), 2 | 3)
            && sim.stack.len() >= usize::from(*n)
            && let Some(top) = sim.stack.get(sim.stack.len() - usize::from(*n)..)
            && let Some((merged, skip)) =
                try_swap_simultaneous_assign(code, ops, idx, usize::from(*n), top)
        {
            for _ in 0..usize::from(*n) {
                let _ = sim.try_pop();
            }
            out.push(merged);
            skip_next = skip;
            continue;
        }
        match op {
            CanonicalOp::LoadConst(i) => sim.push(load_const(code, *i, idx)?),
            CanonicalOp::LoadSmallInt(value) => sim.push(Expr::Constant {
                value: ConstValue::Int(i128::from(*value)),
                line: None,
            }),
            CanonicalOp::LoadCommonConst(slot) => sim.push(load_common_constant(*slot)),
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                sim.push(load_name(code, *i, idx)?);
            }
            CanonicalOp::LoadFast(i) | CanonicalOp::LoadFastAndClear(i) => {
                sim.push(load_local(code, *i, idx)?);
            }
            CanonicalOp::LoadFromDictOrDeref(i) => {
                let _mapping: Expr = sim.pop_or_synth(code, idx);
                sim.push(load_local(code, *i, idx)?);
            }
            CanonicalOp::LoadAttr(i) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                if decode_import_module_marker(&value).is_some()
                    || decode_import_fromset_marker(&value).is_some()
                {
                    sim.push(value);
                    continue;
                }
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSpecial(slot) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr: special_method_name(*slot).to_owned(),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSuperAttr(i) => {
                let _self_obj: Expr = sim.pop_or_synth(code, idx);
                let _class: Expr = sim.pop_or_synth(code, idx);
                let super_callable: Expr = sim.pop_call_target(code, idx).0;
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                sim.push(Expr::Attribute {
                    value: Box::new(Expr::Call {
                        func: Box::new(super_callable),
                        args: Vec::new(),
                        keywords: Vec::new(),
                    }),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::ImportName(i) => {
                let fromlist_expr: Expr = sim.pop_or_synth(code, idx);
                let level_expr: Expr = sim.pop_or_synth(code, idx);
                let module: String = name_at(&code.names, *i, idx, "name")?;
                let level: u32 = extract_level_const(&level_expr).unwrap_or(0);
                let fromlist: Option<Vec<String>> = extract_tuple_of_strings(&fromlist_expr);
                let is_star: bool = matches!(fromlist.as_deref(), Some([s]) if s == "*");
                if is_star {
                    sim.push(Expr::Name {
                        id: encode_import_module_marker(&ImportModuleMarker {
                            module: module.clone(),
                            level,
                            fromlist: Some(vec!["*".to_owned()]),
                        }),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                if let Some(names) = fromlist.clone() {
                    let aliases: Vec<Alias> = names
                        .iter()
                        .map(|n: &String| Alias {
                            name: n.clone(),
                            asname: None,
                        })
                        .collect();
                    out.push(Stmt::ImportFrom {
                        module: if module.is_empty() {
                            None
                        } else {
                            Some(module.clone())
                        },
                        names: aliases,
                        level,
                        line: None,
                    });
                    sim.push(Expr::Name {
                        id: encode_import_fromset_marker(&module, level),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                sim.push(Expr::Name {
                    id: encode_import_module_marker(&ImportModuleMarker {
                        module,
                        level,
                        fromlist,
                    }),
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::ImportFrom(i) => {
                let attr: String = name_at(&code.names, *i, idx, "name")?;
                let module_top: Option<Expr> = sim.peek_clone();
                if let Some(top) = &module_top
                    && let Some((module, level)) = decode_import_fromset_marker(top)
                {
                    sim.push(Expr::Name {
                        id: encode_import_attr_marker(&module, level, &attr),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                sim.push(Expr::Name {
                    id: attr,
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::ImportStar => {
                out.push(import_star_stmt(sim.try_pop()));
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BinarySlice => {
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                let obj: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(obj),
                    slice: Box::new(Expr::Slice {
                        lower: slice_bound(lower),
                        upper: slice_bound(upper),
                        step: None,
                    }),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::StoreSlice => {
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower: slice_bound(lower),
                            upper: slice_bound(upper),
                            step: None,
                        }),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::LoadSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let obj: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(obj),
                    slice: Box::new(Expr::Slice {
                        lower,
                        upper,
                        step: None,
                    }),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::StoreSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower,
                            upper,
                            step: None,
                        }),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::DeleteSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let container: Expr = sim.pop_or_synth(code, idx);
                merge_or_push_delete(
                    &mut out,
                    Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower,
                            upper,
                            step: None,
                        }),
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::StoreAttr(i) => {
                let target_value: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                out.push(Stmt::Assign {
                    targets: vec![Expr::Attribute {
                        value: Box::new(target_value),
                        attr,
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::StoreSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                let legacy_dict_idiom: bool =
                    active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) < (2, 6));
                if legacy_dict_idiom
                    && matches!(container, Expr::Dict { .. })
                    && matches!(sim.peek_clone(), Some(Expr::Dict { .. }))
                    && let Some(Expr::Dict {
                        mut keys,
                        mut values,
                    }) = sim.try_pop()
                {
                    keys.push(Some(slice));
                    values.push(rhs);
                    sim.push(Expr::Dict { keys, values });
                    continue;
                }
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(slice),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.pop_or_synth(code, idx);
                let left: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::UnaryOp(op_kind) => {
                let operand: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::UnaryOp {
                    op: *op_kind,
                    operand: Box::new(operand),
                });
            }
            CanonicalOp::Compare(cmp) => {
                let right: Expr = sim.pop_or_synth(code, idx);
                let left: Expr = sim.pop_or_synth(code, idx);
                let link: ChainLink = classify_chain_link(ops, idx);
                let is_chain_link: bool = link != ChainLink::None;
                if let Some((_, chain_ops, comparators)) = cmp_chain.as_mut() {
                    chain_ops.push(*cmp);
                    comparators.push(right);
                    drop(left);
                } else if is_chain_link {
                    cmp_chain = Some((left, vec![*cmp], vec![right]));
                } else {
                    sim.push(Expr::Compare {
                        left: Box::new(left),
                        ops: vec![*cmp],
                        comparators: vec![right],
                    });
                }
                if cmp_chain.is_some() {
                    if is_chain_link {
                        if link == ChainLink::Modern {
                            sim.push(chain_sentinel());
                        }
                    } else if let Some((chain_left, chain_ops, comparators)) = cmp_chain.take() {
                        sim.push(Expr::Compare {
                            left: Box::new(chain_left),
                            ops: chain_ops,
                            comparators,
                        });
                    }
                }
            }
            CanonicalOp::KwNames(i) => {
                let names: Vec<String> = load_const(code, *i, idx)
                    .ok()
                    .and_then(|e: Expr| extract_tuple_of_strings(&e))
                    .unwrap_or_default();
                sim.push(Expr::Name {
                    id: encode_kw_names(&names),
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::CallFunction(argc) => {
                let pending_kw: Option<Vec<String>> =
                    sim.peek_clone().as_ref().and_then(decode_kw_names);
                if let Some(kw_names) = pending_kw {
                    let _: Option<Expr> = sim.try_pop();
                    let total: usize = usize::from(*argc);
                    let kw_count: usize = kw_names.len().min(total);
                    let pos_count: usize = total - kw_count;
                    let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                    for _ in 0..kw_count {
                        kw_values.insert(0, sim.pop_or_synth(code, idx));
                    }
                    let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                    for _ in 0..pos_count {
                        args.insert(0, sim.pop_or_synth(code, idx));
                    }
                    let (func, implicit_self): (Expr, Option<Expr>) =
                        sim.pop_call_target(code, idx);
                    if let Some(self_arg) = implicit_self {
                        args.insert(0, self_arg);
                    }
                    let keywords: Vec<crate::ast::node::Keyword> = kw_names
                        .into_iter()
                        .zip(kw_values)
                        .map(|(name, value): (String, Expr)| crate::ast::node::Keyword {
                            arg: Some(name),
                            value,
                        })
                        .collect();
                    sim.push(Expr::Call {
                        func: Box::new(func),
                        args,
                        keywords,
                    });
                    continue;
                }
                let mut args: Vec<Expr> = Vec::with_capacity(usize::from(*argc));
                for _ in 0..*argc {
                    args.insert(0, sim.pop_or_synth(code, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                if let Some(comp) = try_build_comprehension_expr(code, &func, &args) {
                    sim.push(comp);
                    continue;
                }
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords: Vec::new(),
                });
            }
            CanonicalOp::CallFunctionKw(argc) => {
                let kw_names_expr: Expr = sim.pop_or_synth(code, idx);
                let kw_names: Vec<String> = decode_kw_names(&kw_names_expr)
                    .or_else(|| extract_tuple_of_strings(&kw_names_expr))
                    .unwrap_or_default();
                let total: usize = usize::from(*argc);
                let kw_count: usize = kw_names.len().min(total);
                let pos_count: usize = total - kw_count;
                let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                for _ in 0..kw_count {
                    kw_values.insert(0, sim.pop_or_synth(code, idx));
                }
                let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                for _ in 0..pos_count {
                    args.insert(0, sim.pop_or_synth(code, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                let keywords: Vec<crate::ast::node::Keyword> = kw_names
                    .into_iter()
                    .zip(kw_values)
                    .map(|(name, value): (String, Expr)| crate::ast::node::Keyword {
                        arg: Some(name),
                        value,
                    })
                    .collect();
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords,
                });
            }
            CanonicalOp::CallFunctionLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, false, false, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionVarLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, true, false, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionKwLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, false, true, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionVarKwLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, true, true, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionEx(has_kw) => {
                let kwargs_on_314: bool =
                    active_version().is_some_and(|v: PyVersion| v.major() > 3 || v.minor() >= 14);
                let kwargs: Option<Expr> = if kwargs_on_314 {
                    let top: Expr = sim.pop_or_synth(code, idx);
                    if is_null_marker(&top) {
                        None
                    } else {
                        Some(top)
                    }
                } else if *has_kw {
                    Some(sim.pop_or_synth(code, idx))
                } else {
                    None
                };
                let args_iter: Expr = sim.pop_or_synth(code, idx);
                let (func, _implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                let args: Vec<Expr> = call_ex_args(args_iter);
                let keywords: Vec<crate::ast::node::Keyword> =
                    kwargs.map(call_ex_kwargs).unwrap_or_default();
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords,
                });
            }
            CanonicalOp::BuildList(n) | CanonicalOp::BuildSet(n) => {
                let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    elts.insert(0, sim.pop_or_synth(code, idx));
                }
                let pushed: Expr = if matches!(op, CanonicalOp::BuildSet(_)) {
                    Expr::Set(elts)
                } else {
                    Expr::List {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                };
                sim.push(pushed);
            }
            CanonicalOp::BuildTuple(n) => {
                let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    elts.insert(0, sim.pop_or_synth(code, idx));
                }
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BuildMap(n) => {
                let presize_hint: bool =
                    active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) < (3, 5));
                let pair_count: u32 = if presize_hint { 0 } else { *n };
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(pair_count as usize);
                let mut values: Vec<Expr> = Vec::with_capacity(pair_count as usize);
                for _ in 0..pair_count {
                    let v: Expr = sim.pop_or_synth(code, idx);
                    let k: Expr = sim.pop_or_synth(code, idx);
                    values.insert(0, v);
                    keys.insert(0, Some(k));
                }
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::StoreMap => {
                let key: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                match sim.try_pop() {
                    Some(Expr::Dict {
                        mut keys,
                        mut values,
                    }) => {
                        keys.push(Some(key));
                        values.push(value);
                        sim.push(Expr::Dict { keys, values });
                    }
                    Some(other) => {
                        sim.push(other);
                        sim.push(value);
                        sim.push(key);
                    }
                    None => {
                        sim.push(value);
                        sim.push(key);
                    }
                }
            }
            CanonicalOp::BuildConstKeyMap(n) => {
                let key_tuple: Expr = sim.pop_or_synth(code, idx);
                let key_exprs: Vec<Expr> = match key_tuple {
                    Expr::Tuple { elts, .. } => elts,
                    Expr::Constant {
                        value: ConstValue::Tuple(parts),
                        line,
                    } => parts
                        .into_iter()
                        .map(|c: ConstValue| Expr::Constant { value: c, line })
                        .collect(),
                    other => vec![other],
                };
                let count: usize = *n as usize;
                let mut values: Vec<Expr> = Vec::with_capacity(count);
                for _ in 0..count {
                    values.insert(0, sim.pop_or_synth(code, idx));
                }
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(count);
                for k in key_exprs.into_iter().take(count) {
                    keys.push(Some(k));
                }
                while keys.len() < values.len() {
                    keys.push(None);
                }
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::BuildString(n) => {
                let mut parts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    parts.insert(0, sim.pop_or_synth(code, idx));
                }
                sim.push(Expr::JoinedStr {
                    values: parts,
                    line: None,
                });
            }
            CanonicalOp::BuildSlice(n) => {
                let step: Option<Box<Expr>> = if *n == 3 {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Slice {
                    lower: slice_bound(lower),
                    upper: slice_bound(upper),
                    step,
                });
            }
            CanonicalOp::FormatValue(flags) => {
                let conv_bits: u8 = flags & 0x03;
                let has_spec: bool = (flags & 0x04) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match conv_bits {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec,
                    line: None,
                });
            }
            CanonicalOp::ConvertValue(flags) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match flags & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec: None,
                    line: None,
                });
            }
            CanonicalOp::FormatSimple => {
                let value: Expr = sim.pop_or_synth(code, idx);
                match value {
                    Expr::FormattedValue {
                        format_spec: None, ..
                    } => sim.push(value),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: None,
                        line: None,
                    }),
                }
            }
            CanonicalOp::FormatWithSpec => {
                let spec: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                match value {
                    Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: None,
                        line,
                    } => sim.push(Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: Some(Box::new(spec)),
                        line,
                    }),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: Some(Box::new(spec)),
                        line: None,
                    }),
                }
            }
            CanonicalOp::BuildInterpolation(flags) => {
                let has_spec: bool = (flags & 0x01) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let popped_text: Expr = sim.pop_or_synth(code, idx);
                let expr_text: Option<String> = match popped_text {
                    Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    } => Some(s),
                    _ => None,
                };
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match (flags >> 2) & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::TStr {
                    items: vec![TStrItem::Interp {
                        value,
                        expr_text,
                        conversion,
                        format_spec: format_spec.map(|b: Box<Expr>| *b),
                    }],
                    line: None,
                });
            }
            CanonicalOp::BuildTemplate => {
                let interps: Expr = sim.pop_or_synth(code, idx);
                let statics: Expr = sim.pop_or_synth(code, idx);
                sim.push(build_tstr_expr(statics, interps));
            }
            CanonicalOp::GetIter
            | CanonicalOp::GetAiter
            | CanonicalOp::GetAnext
            | CanonicalOp::ToBool => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(value);
            }
            CanonicalOp::Dup | CanonicalOp::Copy(1)
                if cmp_chain.is_none()
                    && boolop.is_none()
                    && let Some((groups, chain_end)) = detect_assign_chain(ops, idx)
                    && let Some(targets) = groups
                        .iter()
                        .map(|&(s, e): &(usize, usize)| recover_chain_target(code, ops, s, e))
                        .collect::<Option<Vec<Expr>>>() =>
            {
                let value: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets,
                    value,
                    type_comment: None,
                    line: None,
                });
                skip_next = chain_end - idx - 1;
            }
            CanonicalOp::Dup => {
                if let Some(top) = sim.peek_clone() {
                    sim.push(top);
                }
            }
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::Swap(n) => sim.swap(usize::from(*n)),
            CanonicalOp::RotN(n) => sim.rotn(usize::from(*n)),
            CanonicalOp::Push(_) if is_await_null_slot(ops, idx) => {}
            CanonicalOp::Push(_) => sim.push(Expr::Name {
                id: DR_NULL_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::LoadBuildClass => sim.push(Expr::Name {
                id: DR_BUILD_CLASS_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::LoadAssertionError => sim.push(Expr::Name {
                id: DR_ASSERTION_ERROR_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::MakeFunction(flags) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let meta: FunctionMeta = make_function_meta(*flags, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::MakeFunctionLegacy(packed) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let meta: FunctionMeta = make_function_meta_legacy(*packed, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::MakeClosureLegacy(packed) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let _closure: Option<Expr> = sim.try_pop();
                    let meta: FunctionMeta = make_function_meta_legacy(*packed, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::Resume(_)
            | CanonicalOp::MakeCell(_)
            | CanonicalOp::ReturnGenerator
            | CanonicalOp::BeforeAsyncWith
            | CanonicalOp::SetupAsyncWith
            | CanonicalOp::AsyncForLoop
            | CanonicalOp::AsyncWithExitStart
            | CanonicalOp::AsyncWithExitFinish
            | CanonicalOp::AsyncGenWrap
            | CanonicalOp::PushExcInfo
            | CanonicalOp::PopExcept
            | CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::CleanupThrow
            | CanonicalOp::WithExceptStart
            | CanonicalOp::BeforeWith
            | CanonicalOp::SetupWith(_)
            | CanonicalOp::MatchClass(_)
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchKeys
            | CanonicalOp::GetLen
            | CanonicalOp::EndAsyncFor
            | CanonicalOp::EndSend
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::ForIter(_)
            | CanonicalOp::ForLoopLegacy(_)
            | CanonicalOp::Send(_)
            | CanonicalOp::Specialized(_)
            | CanonicalOp::Other(_, _) => {}
            CanonicalOp::ContinueLoop(_) => out.push(Stmt::Continue),
            CanonicalOp::PrintItem => {
                let item: Expr = sim.pop_or_synth(code, idx);
                let entry: &mut (Option<Expr>, Vec<Expr>) =
                    print_acc.get_or_insert_with(|| (None, Vec::new()));
                entry.1.push(item);
            }
            CanonicalOp::PrintItemTo => {
                let dest: Expr = sim.pop_or_synth(code, idx);
                let item: Expr = sim.pop_or_synth(code, idx);
                let entry: &mut (Option<Expr>, Vec<Expr>) =
                    print_acc.get_or_insert_with(|| (None, Vec::new()));
                if entry.0.is_none() {
                    entry.0 = Some(dest);
                }
                entry.1.push(item);
            }
            CanonicalOp::PrintNewlineTo => {
                let stream: Expr = sim.pop_or_synth(code, idx);
                let (dest, items): (Option<Expr>, Vec<Expr>) =
                    print_acc.take().unwrap_or((None, Vec::new()));
                let dest: Option<Expr> = dest.or(Some(stream));
                out.push(Stmt::Expr(build_print_call(dest, items, false)));
            }
            CanonicalOp::PrintNewline => {
                let (dest, items): (Option<Expr>, Vec<Expr>) =
                    print_acc.take().unwrap_or((None, Vec::new()));
                out.push(Stmt::Expr(build_print_call(dest, items, false)));
            }
            CanonicalOp::PrintExpr => {
                let value: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Expr(value));
            }
            CanonicalOp::Exec => {
                let locals: Expr = sim.pop_or_synth(code, idx);
                let globals: Expr = sim.pop_or_synth(code, idx);
                let body: Expr = sim.pop_or_synth(code, idx);
                let args: Vec<Expr> = build_exec_args(body, globals, locals);
                out.push(Stmt::Expr(Expr::Call {
                    func: Box::new(Expr::Name {
                        id: "exec".to_owned(),
                        ctx: ExprCtx::Load,
                        line: None,
                    }),
                    args,
                    keywords: Vec::new(),
                }));
            }
            CanonicalOp::BuildClassLegacy => {
                let class_dict: Expr = sim.pop_or_synth(code, idx);
                let bases_expr: Expr = sim.pop_or_synth(code, idx);
                let name_expr: Expr = sim.pop_or_synth(code, idx);
                let code_marker: Expr = match class_dict {
                    Expr::Call { func, ref args, .. } if args.is_empty() => *func,
                    other => other,
                };
                let name: String = extract_str_const(&name_expr).unwrap_or_default();
                let bases: Vec<Expr> = match bases_expr {
                    Expr::Tuple { elts, .. } => elts,
                    _ => Vec::new(),
                };
                let mut call_args: Vec<Expr> = Vec::with_capacity(bases.len() + 2);
                call_args.push(code_marker);
                call_args.push(Expr::Constant {
                    value: ConstValue::Str(name),
                    line: None,
                });
                call_args.extend(bases);
                sim.push(Expr::Call {
                    func: Box::new(Expr::Name {
                        id: DR_BUILD_CLASS_MARKER.to_owned(),
                        ctx: ExprCtx::Load,
                        line: None,
                    }),
                    args: call_args,
                    keywords: Vec::new(),
                });
            }
            CanonicalOp::Pop => {
                if print_acc
                    .as_ref()
                    .is_some_and(|(dest, _): &(Option<Expr>, Vec<Expr>)| dest.is_some())
                {
                    let _stream: Expr = sim.pop_or_synth(code, idx);
                    let (dest, items): (Option<Expr>, Vec<Expr>) =
                        print_acc.take().unwrap_or((None, Vec::new()));
                    out.push(Stmt::Expr(build_print_call(dest, items, true)));
                    continue;
                }
                if let Some(value) = sim.try_pop() {
                    if is_chain_sentinel(&value)
                        || is_null_marker(&value)
                        || decode_import_fromset_marker(&value).is_some()
                        || decode_import_module_marker(&value).is_some()
                        || decode_import_attr_marker(&value).is_some()
                    {
                        continue;
                    }
                    out.push(Stmt::Expr(value));
                }
            }
            CanonicalOp::DiscardTop => {
                let _ = sim.try_pop();
            }
            CanonicalOp::SetFunctionAttribute(flag) => {
                let func: Option<Expr> = sim.try_pop();
                let attr: Option<Expr> = sim.try_pop();
                if let (Some(f), Some(a)) = (&func, attr)
                    && let Some(const_idx) = nested_code_index(f)
                {
                    let entry: &mut FunctionMeta = fn_meta.entry(const_idx).or_default();
                    match flag {
                        1 => entry.defaults = defaults_from_expr(a),
                        2 => entry.kw_defaults = kwdefaults_from_expr(a),
                        4 => {
                            let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                annotations_from_expr(a);
                            entry.annotations = params;
                            entry.returns = ret;
                        }
                        16 => {
                            if let Some(dict) = annotate_codeobj_dict(code, &a) {
                                let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                    annotations_from_expr(dict);
                                if !params.is_empty() {
                                    entry.annotations = params;
                                }
                                if ret.is_some() {
                                    entry.returns = ret;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(f) = func {
                    sim.push(f);
                }
            }
            CanonicalOp::CallIntrinsic1(intrinsic) => match intrinsic {
                2 => {
                    out.push(import_star_stmt(sim.try_pop()));
                }
                7..=9 => {
                    let name_expr: Expr = sim.pop_or_synth(code, idx);
                    let name: String = extract_str_const(&name_expr).unwrap_or_default();
                    let kind: TypeParamKind = type_param_kind_from_intrinsic1(*intrinsic)
                        .unwrap_or(TypeParamKind::TypeVar);
                    sim.push(build_typevar_marker(kind, &name, None));
                }
                11 => {
                    let tuple: Expr = sim.pop_or_synth(code, idx);
                    if let Expr::Tuple { mut elts, .. } = tuple
                        && elts.len() == 3
                    {
                        let evaluator: Expr = elts.pop().unwrap_or(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                        let _type_params: Option<Expr> = elts.pop();
                        let name: String = elts
                            .pop()
                            .as_ref()
                            .and_then(extract_str_const)
                            .unwrap_or_default();
                        let value: Expr =
                            unwrap_evaluator_expr(code, &evaluator).unwrap_or(evaluator);
                        sim.push(type_alias_marker_call(&name, value));
                    }
                }
                _ => {}
            },
            CanonicalOp::CallIntrinsic2(intrinsic) => match intrinsic {
                2 | 3 => {
                    let evaluator: Expr = sim.pop_or_synth(code, idx);
                    let name_expr: Expr = sim.pop_or_synth(code, idx);
                    let name: String = extract_str_const(&name_expr).unwrap_or_default();
                    let bound: Option<Expr> = unwrap_evaluator_expr(code, &evaluator);
                    sim.push(build_typevar_marker(TypeParamKind::TypeVar, &name, bound));
                }
                4 => {
                    let _type_params: Expr = sim.pop_or_synth(code, idx);
                    let func: Expr = sim.pop_or_synth(code, idx);
                    sim.push(func);
                }
                _ => {}
            },
            CanonicalOp::Return => {
                let value: Option<Expr> = sim.try_pop();
                let value: Option<Expr> = filter_async_gen_return(code, value);
                out.push(Stmt::Return(value));
            }
            CanonicalOp::ReturnConst(i) => {
                let value: Expr = load_const(code, *i, idx)?;
                let value: Option<Expr> = filter_async_gen_return(code, Some(value));
                out.push(Stmt::Return(value));
            }
            CanonicalOp::Yield => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let is_async_ctx: bool =
                    (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
                let is_none_const: bool = matches!(
                    value,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                );
                if is_async_ctx && is_none_const && is_await_poll_yield(ops, idx) {
                    continue;
                }
                if is_async_ctx
                    && is_none_const
                    && sim.peek_clone().is_some_and(|u: Expr| {
                        matches!(u, Expr::Await(_)) || is_comprehension_expr(&u)
                    })
                {
                    continue;
                }
                if !is_async_ctx
                    && is_none_const
                    && is_yield_from_send_pattern(ops, idx)
                    && let Some(iter) = sim.try_pop()
                {
                    sim.push(Expr::YieldFrom(Box::new(iter)));
                    continue;
                }
                if is_pre23_statement_yield() {
                    out.push(Stmt::Expr(Expr::Yield(Some(Box::new(value)))));
                    continue;
                }
                sim.push(Expr::Yield(Some(Box::new(value))));
            }
            CanonicalOp::YieldFrom => {
                let top: Expr = sim.pop_or_synth(code, idx);
                let is_none_const: bool = matches!(
                    top,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                );
                let is_async_ctx: bool =
                    (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
                if is_async_ctx {
                    if is_none_const && matches!(sim.peek_clone(), Some(Expr::Await(_))) {
                        continue;
                    }
                    if let Some(under) = sim.peek_clone() {
                        let _ = sim.try_pop();
                        if matches!(under, Expr::Await(_)) || is_comprehension_expr(&under) {
                            sim.push(under);
                        } else {
                            sim.push(Expr::Await(Box::new(under)));
                        }
                        continue;
                    }
                    continue;
                }
                let value: Expr = if is_none_const {
                    match sim.peek_clone() {
                        Some(under)
                            if !matches!(
                                under,
                                Expr::Await(_) | Expr::Yield(_) | Expr::YieldFrom(_)
                            ) =>
                        {
                            let _ = sim.try_pop();
                            under
                        }
                        _ => top,
                    }
                } else {
                    top
                };
                let expr: Expr = Expr::YieldFrom(Box::new(value));
                sim.push(expr);
            }
            CanonicalOp::StoreGlobal(i) | CanonicalOp::StoreName(i) => {
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                if is_walrus_store(ops, idx, &target_name) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: target_name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                if let Some((mod_name, _level, attr)) = decode_import_attr_marker(&value) {
                    let _ = mod_name;
                    if attr != target_name {
                        update_last_import_from_asname(&mut out, &attr, &target_name);
                    }
                    continue;
                }
                if let Some(marker) = decode_import_module_marker(&value) {
                    out.push(import_module_to_stmt(&marker, &target_name));
                    continue;
                }
                if let Some(alias) = try_build_type_alias(&value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(alias) = try_build_generic_type_alias(code, &value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(generic_def) = try_build_generic_def(code, &value, &target_name) {
                    out.push(generic_def);
                    continue;
                }
                if let Some(decorated) = try_build_decorated_generic_def(code, &value, &target_name)
                {
                    out.push(decorated);
                    continue;
                }
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(class_def) = try_build_decorated_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(mut fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
                {
                    if let Some(meta) = fn_meta.get(&const_idx) {
                        attach_fn_meta(&mut fn_def, meta);
                    }
                    out.push(fn_def);
                    continue;
                }
                if let Some(fn_def) =
                    try_build_decorated_function_def(code, &value, &target_name, &fn_meta)
                {
                    out.push(fn_def);
                    continue;
                }
                let target: Expr = Expr::Name {
                    id: target_name,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::StoreAnnotation(i) => {
                let annotation: Expr = sim.pop_or_synth(code, idx);
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                out.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation,
                    value: None,
                    simple: true,
                    line: None,
                });
            }
            CanonicalOp::StoreFast(i) => {
                let target_name: String = local_name_at(code, *i, idx)?;
                if is_walrus_store(ops, idx, &target_name) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: target_name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                if is_typevar_marker(&value) {
                    continue;
                }
                if let Some((mod_name, _level, attr)) = decode_import_attr_marker(&value) {
                    let _ = mod_name;
                    if attr != target_name {
                        update_last_import_from_asname(&mut out, &attr, &target_name);
                    }
                    continue;
                }
                if let Some(marker) = decode_import_module_marker(&value) {
                    out.push(import_module_to_stmt(&marker, &target_name));
                    continue;
                }
                if let Some(alias) = try_build_type_alias(&value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(alias) = try_build_generic_type_alias(code, &value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(generic_def) = try_build_generic_def(code, &value, &target_name) {
                    out.push(generic_def);
                    continue;
                }
                if let Some(decorated) = try_build_decorated_generic_def(code, &value, &target_name)
                {
                    out.push(decorated);
                    continue;
                }
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(class_def) = try_build_decorated_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(mut fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
                {
                    if let Some(meta) = fn_meta.get(&const_idx) {
                        attach_fn_meta(&mut fn_def, meta);
                    }
                    out.push(fn_def);
                    continue;
                }
                if let Some(fn_def) =
                    try_build_decorated_function_def(code, &value, &target_name, &fn_meta)
                {
                    out.push(fn_def);
                    continue;
                }
                let target: Expr = Expr::Name {
                    id: target_name,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                sim.push(load_local(code, *a, idx)?);
                sim.push(load_local(code, *b, idx)?);
            }
            CanonicalOp::StoreFastLoadFast(a, b) => {
                if idx > 0 && matches!(ops[idx - 1], CanonicalOp::Copy(1) | CanonicalOp::Dup) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    let name: String = local_name_at(code, *a, idx)?;
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    sim.push(load_local(code, *b, idx)?);
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                let target: Expr = local_target(code, *a, idx)?;
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
                sim.push(load_local(code, *b, idx)?);
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if idx > 0 && matches!(ops[idx - 1], CanonicalOp::Copy(1) | CanonicalOp::Dup) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    let inner_name: String = local_name_at(code, *a, idx)?;
                    let outer_target: Expr = local_target(code, *b, idx)?;
                    out.push(Stmt::Assign {
                        targets: vec![outer_target],
                        value: Expr::NamedExpr {
                            target: Box::new(Expr::Name {
                                id: inner_name,
                                ctx: ExprCtx::Store,
                                line: None,
                            }),
                            value: Box::new(underlying),
                        },
                        type_comment: None,
                        line: None,
                    });
                    continue;
                }
                let v_b: Expr = sim.pop_or_synth(code, idx);
                let v_a: Expr = sim.pop_or_synth(code, idx);
                let target_a: Expr = local_target(code, *a, idx)?;
                let target_b: Expr = local_target(code, *b, idx)?;
                out.push(Stmt::Assign {
                    targets: vec![target_a],
                    value: v_a,
                    type_comment: None,
                    line: None,
                });
                out.push(Stmt::Assign {
                    targets: vec![target_b],
                    value: v_b,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::MapAdd => {
                let _value: Expr = sim.pop_or_synth(code, idx);
                let _key: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::UnpackSequence(n) => {
                let source: Expr = sim.pop_or_synth(code, idx);
                let n_usize: usize = *n as usize;
                if n_usize == 0 {
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: Vec::new(),
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                } else if let Some((targets, skip)) =
                    collect_unpack_targets(code, ops, idx + 1, n_usize)
                {
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: targets,
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                    skip_next = skip;
                } else {
                    sim.push(source);
                    for _ in 0..n_usize {
                        sim.push(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                    }
                }
            }
            CanonicalOp::UnpackEx(arg) => {
                let source: Expr = sim.pop_or_synth(code, idx);
                let before: u32 = arg & 0xFF;
                let after: u32 = arg >> 8;
                let total: usize = (before + after + 1) as usize;
                if let Some((mut targets, skip)) = collect_unpack_targets(code, ops, idx + 1, total)
                {
                    let star_idx: usize = before as usize;
                    if star_idx < targets.len() {
                        let starred_val: Expr = targets.remove(star_idx);
                        targets.insert(
                            star_idx,
                            Expr::Starred {
                                value: Box::new(starred_val),
                                ctx: ExprCtx::Store,
                            },
                        );
                    }
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: targets,
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                    skip_next = skip;
                } else {
                    for _ in 0..total {
                        sim.push(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                    }
                }
            }
            CanonicalOp::ListExtend(_) | CanonicalOp::SetUpdate(_) => {
                let iterable: Expr = sim.pop_or_synth(code, idx);
                let base: Option<Expr> = sim.try_pop();
                let merged: Expr = merge_extend(base, iterable, false);
                sim.push(merged);
            }
            CanonicalOp::DictMerge(_) | CanonicalOp::DictUpdate(_) => {
                let mapping: Expr = sim.pop_or_synth(code, idx);
                let base: Option<Expr> = sim.try_pop();
                let merged: Expr = merge_extend(base, mapping, true);
                sim.push(merged);
            }
            CanonicalOp::ListToTuple => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let elts: Vec<Expr> = match value {
                    Expr::List { elts, .. } => elts,
                    other => vec![other],
                };
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BuildTupleUnpack(n) | CanonicalOp::BuildListUnpack(n) => {
                let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    let item: Expr = sim.pop_or_synth(code, idx);
                    elts.insert(0, starred(item));
                }
                sim.push(if matches!(op, CanonicalOp::BuildTupleUnpack(_)) {
                    Expr::Tuple {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                } else {
                    Expr::List {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                });
            }
            CanonicalOp::BuildSetUnpack(n) => {
                let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    let item: Expr = sim.pop_or_synth(code, idx);
                    elts.insert(0, starred(item));
                }
                sim.push(Expr::Set(elts));
            }
            CanonicalOp::BuildMapUnpack(n) => {
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(*n as usize);
                let mut values: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    let item: Expr = sim.pop_or_synth(code, idx);
                    keys.insert(0, None);
                    values.insert(0, item);
                }
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::GetAwaitable => {
                let value: Expr = sim.pop_or_synth(code, idx);
                if is_comprehension_expr(&value) {
                    sim.push(value);
                } else {
                    sim.push(Expr::Await(Box::new(value)));
                }
            }
            CanonicalOp::Raise(argc) => {
                let cause: Option<Expr> = if *argc >= 2 { sim.try_pop() } else { None };
                let exc: Option<Expr> = if *argc >= 1 { sim.try_pop() } else { None };
                if let Some(e) = &exc
                    && is_assertion_error_marker(e)
                {
                    out.push(Stmt::Assert {
                        test: Expr::Constant {
                            value: ConstValue::False,
                            line: None,
                        },
                        msg: None,
                        line: None,
                    });
                    continue;
                }
                out.push(Stmt::Raise {
                    exc,
                    cause,
                    line: None,
                });
            }
            CanonicalOp::Reraise(_) => {
                out.push(Stmt::Raise {
                    exc: None,
                    cause: None,
                    line: None,
                });
            }
            CanonicalOp::DeleteFast(i) => {
                let target_name: String = local_name_at(code, *i, idx)?;
                merge_or_push_delete(
                    &mut out,
                    Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Del,
                        line: None,
                    },
                );
            }
            CanonicalOp::DeleteName(i) => {
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                merge_or_push_delete(
                    &mut out,
                    Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Del,
                        line: None,
                    },
                );
            }
            CanonicalOp::DeleteAttr(i) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                merge_or_push_delete(
                    &mut out,
                    Expr::Attribute {
                        value: Box::new(value),
                        attr,
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::DeleteSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                merge_or_push_delete(
                    &mut out,
                    Expr::Subscript {
                        value: Box::new(value),
                        slice: Box::new(slice),
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
            | CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::JumpIfFalseOrPop(_) => {
                if is_chain_compare_jump(ops, idx) {
                    continue;
                }
                let _condition: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                let item: Expr = sim.pop_or_synth(code, idx);
                match sim.peek_clone() {
                    Some(Expr::List {
                        elts: list_elts,
                        ctx,
                    }) => {
                        let mut elts: Vec<Expr> = list_elts;
                        elts.push(item);
                        let _ = sim.try_pop();
                        sim.push(Expr::List { elts, ctx });
                    }
                    Some(Expr::Set(set_elts)) => {
                        let mut elts: Vec<Expr> = set_elts;
                        elts.push(item);
                        let _ = sim.try_pop();
                        sim.push(Expr::Set(elts));
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some((dest, items)) = print_acc.take() {
        out.push(Stmt::Expr(build_print_call(dest, items, true)));
    }
    flush_boolop(&mut sim, &mut boolop);
    let residual: Vec<Expr> = sim.stack;
    Ok((out, residual))
}

const DR_PRINT_DEST_MARKER: &str = "__DR_PRINT_DEST__";
const DR_PRINT_NONL_MARKER: &str = "__DR_PRINT_NONL__";

/// Reassembles a Python-2 `print` statement into a `Call(Name("print"), ...)` the codegen layer
/// renders back to statement form. A redirect destination is encoded as a leading
/// `__DR_PRINT_DEST__` sentinel followed by the stream expression; a node closed without its
/// terminating `PRINT_NEWLINE`/`PRINT_NEWLINE_TO` (trailing-comma `print a,`) appends a trailing
/// `__DR_PRINT_NONL__` sentinel.
fn build_print_call(dest: Option<Expr>, items: Vec<Expr>, trailing_comma: bool) -> Expr {
    let mut args: Vec<Expr> = Vec::with_capacity(items.len() + 3);
    if let Some(stream) = dest {
        args.push(Expr::Name {
            id: DR_PRINT_DEST_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        });
        args.push(stream);
    }
    args.extend(items);
    if trailing_comma {
        args.push(Expr::Name {
            id: DR_PRINT_NONL_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        });
    }
    Expr::Call {
        func: Box::new(Expr::Name {
            id: "print".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args,
        keywords: Vec::new(),
    }
}

/// Picks the `exec` statement form from the three values `EXEC_STMT` consumes. A `None` globals
/// constant means the bare `exec body`; globals structurally equal to locals is the `DUP_TOP`'d
/// `exec body in g` case; otherwise the full `exec body in g , l`.
fn build_exec_args(body: Expr, globals: Expr, locals: Expr) -> Vec<Expr> {
    let globals_is_none: bool = matches!(
        globals,
        Expr::Constant {
            value: ConstValue::None,
            ..
        }
    );
    if globals_is_none {
        vec![body]
    } else if globals == locals {
        vec![body, globals]
    } else {
        vec![body, globals, locals]
    }
}

/// `JUMP_IF_FALSE_OR_POP`/`JUMP_IF_TRUE_OR_POP` (3.8-3.11) and the 3.12+ `COPY 1 [; TO_BOOL];
/// POP_JUMP_IF_*` sequence are value-form boolop short-circuits: the operand is preserved on the
/// stack while the chain decides truth. Returns the boolean operator the short-circuit implies.
/// Excludes jumps emitted as part of a chained comparison (`a < b < c`), which use the same
/// `JumpIfFalseOrPop`/`Copy 1 + PopJumpIf*` idiom but are owned by the comparison-chain fold.
/// Also recognises the bare `PopJumpIf*` used as an inner-AND/OR short-circuit when the outer
/// boolop is the opposite polarity (the compiler elides the keep-and-jump because the outer
/// boolop's result is independent of this inner operand's truth value).
fn value_boolop_at(ops: &[CanonicalOp], idx: usize) -> Option<crate::ast::node::BoolOpKind> {
    use crate::ast::node::BoolOpKind;
    if is_chain_compare_jump(ops, idx) {
        return None;
    }
    match ops[idx] {
        CanonicalOp::JumpIfFalseOrPop(_) => Some(BoolOpKind::And),
        CanonicalOp::JumpIfTrueOrPop(_) => Some(BoolOpKind::Or),
        CanonicalOp::Copy(1) => {
            let jump: usize = skip_to_bool_jump(ops, idx + 1)?;
            match ops[jump] {
                CanonicalOp::PopJumpIfFalse(_) => Some(BoolOpKind::And),
                CanonicalOp::PopJumpIfTrue(_) => Some(BoolOpKind::Or),
                _ => None,
            }
        }
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => {
            inner_short_circuit_polarity(ops, idx)
        }
        _ => None,
    }
}

/// Whether the op at `idx` continues an in-progress value-form boolop chain.
fn is_value_boolop_shortcircuit(ops: &[CanonicalOp], idx: usize) -> bool {
    value_boolop_at(ops, idx).is_some()
}

/// Whether a bare `PopJumpIfFalse`/`PopJumpIfTrue` at `idx` is the inner-AND/OR short-circuit
/// emitted when the outer boolop has the opposite polarity. The compiler elides the keep-and-jump
/// because the outer boolop's result is independent of this inner operand's truth value (e.g.,
/// `(a and b) or X`: `PopJumpIfFalse` on `a` discards `a` because if `a` is false the AND is false
/// and the outer OR moves on to `X`). Returns the implied boolop kind for the local arm.
fn inner_short_circuit_polarity(
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<crate::ast::node::BoolOpKind> {
    use crate::ast::node::BoolOpKind;
    let local_kind: BoolOpKind = match ops[idx] {
        CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
        CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
        _ => return None,
    };
    let next: usize = first_significant_after(ops, idx + 1)?;
    let after_load: usize = first_significant_after(ops, next + 1)?;
    let outer_kind: BoolOpKind = match ops.get(after_load)? {
        CanonicalOp::JumpIfFalseOrPop(_) => BoolOpKind::And,
        CanonicalOp::JumpIfTrueOrPop(_) => BoolOpKind::Or,
        CanonicalOp::Copy(1) => {
            let jump: usize = skip_to_bool_jump(ops, after_load + 1)?;
            match ops[jump] {
                CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
                CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
                _ => return None,
            }
        }
        _ => return None,
    };
    if outer_kind == local_kind {
        return None;
    }
    Some(local_kind)
}

fn first_significant_after(ops: &[CanonicalOp], from: usize) -> Option<usize> {
    let mut i: usize = from;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            _ => return Some(i),
        }
    }
    None
}

/// Index of the `POP_JUMP_IF_*` reached from a `COPY 1` by skipping an optional `TO_BOOL`/`CACHE`.
fn skip_to_bool_jump(ops: &[CanonicalOp], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::ToBool | CanonicalOp::Cache | CanonicalOp::Nop => i += 1,
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => return Some(i),
            _ => return None,
        }
    }
    None
}

/// Ops to skip after recording a short-circuit operand: the 3.12+ form consumes the `COPY 1`'s
/// duplicate via `POP_JUMP` and drops the original with a trailing `POP_TOP`, so skip through that
/// `POP_TOP`. The 3.8-3.11 `*_OR_POP` form is self-contained (nothing to skip).
fn boolop_shortcircuit_skip(ops: &[CanonicalOp], idx: usize) -> usize {
    if !matches!(ops[idx], CanonicalOp::Copy(1)) {
        return 0;
    }
    let Some(jump): Option<usize> = skip_to_bool_jump(ops, idx + 1) else {
        return 0;
    };
    let mut count: usize = jump - idx;
    let mut i: usize = jump + 1;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop => {
                count += 1;
                i += 1;
            }
            CanonicalOp::Pop => {
                count += 1;
                break;
            }
            _ => break,
        }
    }
    count
}

/// Combine the accumulated boolop operands with the final value on the stack into a single
/// `Expr::BoolOp`, flattening a nested same-operator tail produced by right-associative chaining.
fn flush_boolop(
    sim: &mut StackSim,
    boolop: &mut Option<(crate::ast::node::BoolOpKind, Vec<Expr>)>,
) {
    let Some((kind, mut operands)): Option<(crate::ast::node::BoolOpKind, Vec<Expr>)> =
        boolop.take()
    else {
        return;
    };
    let Some(tail): Option<Expr> = sim.try_pop() else {
        if let Some(first) = operands.into_iter().next() {
            sim.push(first);
        }
        return;
    };
    operands.push(tail);
    sim.push(Expr::BoolOp {
        op: kind,
        values: operands,
    });
}

#[derive(Debug, Default)]
struct StackSim {
    stack: Vec<Expr>,
}

impl StackSim {
    fn new() -> Self {
        Self { stack: Vec::new() }
    }

    fn push(&mut self, e: Expr) {
        self.stack.push(e);
    }

    fn try_pop(&mut self) -> Option<Expr> {
        self.stack.pop()
    }

    fn peek_clone(&self) -> Option<Expr> {
        self.stack.last().cloned()
    }

    fn peek_at(&self, n: usize) -> Option<Expr> {
        if n == 0 || self.stack.len() < n {
            return None;
        }
        self.stack.get(self.stack.len() - n).cloned()
    }

    fn swap(&mut self, n: usize) {
        let len: usize = self.stack.len();
        if n >= 2 && len >= n {
            self.stack.swap(len - 1, len - n);
        }
    }

    fn rotn(&mut self, n: usize) {
        let len: usize = self.stack.len();
        if n >= 2 && len >= n {
            let top: Expr = self.stack.remove(len - 1);
            self.stack.insert(len - n, top);
        }
    }

    fn pop_or_synth(&mut self, code: &CodeObject, idx: usize) -> Expr {
        let _: (&CodeObject, usize) = (code, idx);
        self.stack.pop().unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        })
    }

    /// Resolve the callable for a CALL after the explicit positional args have been popped.
    ///
    /// Python 3.11+ uses a two-slot calling convention: the callable, then a `self_or_null` slot,
    /// then the positional args. The `self_or_null` slot is either a `PUSH_NULL` sentinel (plain
    /// call) or a bound first positional argument (the function passed to a `classmethod(fn)`
    /// decorator emitted as `CALL 0`).
    /// Pre-3.11 has no such slot; the item below the args is the callable itself.
    ///
    /// Returns `(callable, implicit_self_arg)` where `implicit_self_arg` is prepended to the
    /// positional args by the caller when present.
    fn pop_call_target(&mut self, code: &CodeObject, idx: usize) -> (Expr, Option<Expr>) {
        let two_slot: bool = active_version().is_some_and(|v: PyVersion| !v.is_pre_311());
        if !two_slot {
            return (self.pop_or_synth(code, idx), None);
        }
        let tos1: Expr = self.pop_or_synth(code, idx);
        if is_null_marker(&tos1) {
            return (self.pop_or_synth(code, idx), None);
        }
        match self.try_pop() {
            Some(callable) if is_null_marker(&callable) => (tos1, None),
            Some(callable) => (callable, Some(tos1)),
            None => (tos1, None),
        }
    }

    #[allow(dead_code)]
    fn pop(&mut self, offset: usize, ctx: &'static str) -> Result<Expr> {
        self.stack.pop().ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("stack underflow at {ctx}"),
        })
    }
}

const DR_CODE_CONST_PREFIX: &str = "__DR_CODE_CONST_";
const DR_IMPORT_MODULE_PREFIX: &str = "__DR_IMPORT_MOD__";
const DR_IMPORT_FROMSET_PREFIX: &str = "__DR_IMPORT_FROMSET__";
const DR_IMPORT_ATTR_PREFIX: &str = "__DR_IMPORT_ATTR__";
const DR_BUILD_CLASS_MARKER: &str = "__DR_BUILD_CLASS__";
const DR_ASSERTION_ERROR_MARKER: &str = "__DR_ASSERTION_ERROR__";
const DR_NULL_MARKER: &str = "__DR_NULL__";
const DR_KW_NAMES_PREFIX: &str = "__DR_KW_NAMES__\u{0}";
const DR_TYPE_ALIAS_MARKER: &str = "__DR_TYPE_ALIAS__";
const DR_TYPEVAR_MARKER: &str = "__DR_TYPEVAR__";

fn is_build_class_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_BUILD_CLASS_MARKER)
}

/// A `:=` walrus stores via `DUP_TOP`/`COPY 1` immediately followed by a `STORE_*`: the duplicate is
/// captured into the name while the original value stays on the stack as the expression result.
/// Compiler-synthesized dunder captures (notably `__classcell__ = __class__` at a class-body tail)
/// share the `COPY; STORE` shape but are not user walruses and must not be rewritten.
fn is_walrus_store(ops: &[CanonicalOp], idx: usize, target_name: &str) -> bool {
    idx > 0
        && matches!(ops[idx - 1], CanonicalOp::Dup | CanonicalOp::Copy(1))
        && !matches!(target_name, "__classcell__" | "__class__")
}

const DR_CHAIN_VALUE_MARKER: &str = "__DR_CHAIN_VALUE__";

fn is_chain_value_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_CHAIN_VALUE_MARKER)
}

/// A target-store op that fills exactly one assignment target slot: a bare name/global/local store,
/// or the trailing `STORE_ATTR`/`STORE_SUBSCR`/`STORE_SLICE` of an attribute/subscript/slice target.
fn is_chain_target_store(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreSlice
    )
}

/// Walk one chained-assignment target group starting at `start`, returning the exclusive end index.
/// The group consumes exactly one duplicated stack value; `UNPACK_SEQUENCE n` / `UNPACK_EX` expand
/// the single slot into the nested element targets, every other op is either a target store
/// (closes one slot) or an operand load for an attribute/subscript target (slot-neutral). The group
/// ends when every opened slot has been closed by a store.
fn chain_group_end(ops: &[CanonicalOp], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut pending: usize = 1;
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::UnpackSequence(n) => {
                pending = pending - 1 + *n as usize;
            }
            CanonicalOp::UnpackEx(arg) => {
                let before: usize = (arg & 0xFF) as usize;
                let after: usize = (arg >> 8) as usize;
                pending = pending - 1 + before + after + 1;
            }
            op if is_chain_target_store(op) => {
                pending -= 1;
            }
            _ => {}
        }
        i += 1;
        if pending == 0 {
            return Some(i);
        }
    }
    None
}

/// Detect a statement-context chained multi-target assignment whose value already sits on TOS and
/// whose first duplicate is at `dup_idx` (a `Dup`/`Copy 1`). `CPython` emits `a = b = c = expr` as
/// the value followed by a run of duplicate-prefixed target groups closed by one terminal target
/// group: the duplicate is consumed only by stores, never by a value-expression, which is exactly
/// the discriminator that separates this from a walrus `name := expr` (whose duplicate feeds a
/// surrounding expression). Returns the parsed target groups (each `[start, end)` op range) and the
/// exclusive end of the whole chain when the shape holds for two or more groups; otherwise `None`
/// so the walrus path stays in force.
fn detect_assign_chain(
    ops: &[CanonicalOp],
    dup_idx: usize,
) -> Option<(Vec<(usize, usize)>, usize)> {
    if !matches!(
        ops.get(dup_idx),
        Some(CanonicalOp::Dup | CanonicalOp::Copy(1))
    ) {
        return None;
    }
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = dup_idx;
    while matches!(ops.get(i), Some(CanonicalOp::Dup | CanonicalOp::Copy(1))) {
        let group_start: usize = i + 1;
        let group_end: usize = chain_group_end(ops, group_start)?;
        groups.push((group_start, group_end));
        i = group_end;
    }
    let terminal_end: usize = chain_group_end(ops, i)?;
    groups.push((i, terminal_end));
    if groups.len() < 2 {
        return None;
    }
    if groups
        .iter()
        .any(|&(s, e): &(usize, usize)| !group_is_pure_target(ops, s, e))
    {
        return None;
    }
    Some((groups, terminal_end))
}

/// A parsed target group is a pure assignment target (no value-expression side that would make the
/// duplicate a walrus operand): every op is a target store, an unpack, an operand load for an
/// attribute/subscript/slice target, or stack noise. Guards against folding a `DUP`/store shape that
/// is actually a walrus feeding a call/compare into the chain.
fn group_is_pure_target(ops: &[CanonicalOp], start: usize, end: usize) -> bool {
    let mut last_store: bool = false;
    for op in &ops[start..end] {
        last_store = is_chain_target_store(op);
        if matches!(
            op,
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::ForIter(_)
                | CanonicalOp::Return
                | CanonicalOp::Dup
                | CanonicalOp::Copy(_)
        ) {
            return false;
        }
    }
    last_store || matches!(ops.get(end - 1), Some(CanonicalOp::UnpackSequence(0)))
}

/// Recover one chained-assignment target group `[start, end)` by replaying its op slice through the
/// shared linear SIM seeded with a sentinel value: the existing `STORE_*` handlers fold the operand
/// loads into the correct `Attribute`/`Subscript`/`Slice`/`Tuple` target, and we lift that target out
/// of the emitted single-assign statement. Returns `None` if the slice did not yield exactly one
/// assignment target (so the caller can fall back rather than emit a malformed chain).
fn recover_chain_target(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
    end: usize,
) -> Option<Expr> {
    let slice: Vec<CanonicalOp> = ops[start..end].to_vec();
    let seed: Vec<Expr> = vec![Expr::Name {
        id: DR_CHAIN_VALUE_MARKER.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }];
    let (stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &slice, seed).ok()?;
    let [Stmt::Assign { targets, value, .. }]: [Stmt; 1] = stmts.try_into().ok()? else {
        return None;
    };
    if !is_chain_value_marker(&value) {
        return None;
    }
    let [target]: [Expr; 1] = targets.try_into().ok()?;
    Some(target)
}

fn is_null_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_NULL_MARKER)
}

fn is_assertion_error_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_ASSERTION_ERROR_MARKER)
}

fn encode_kw_names(names: &[String]) -> String {
    format!("{DR_KW_NAMES_PREFIX}{}__", names.join("\u{1F}"))
}

fn decode_kw_names(expr: &Expr) -> Option<Vec<String>> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id.strip_prefix(DR_KW_NAMES_PREFIX)?.strip_suffix("__")?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    Some(inner.split('\u{1F}').map(str::to_owned).collect())
}

#[derive(Debug, Clone)]
struct ImportModuleMarker {
    module: String,
    level: u32,
    fromlist: Option<Vec<String>>,
}

fn encode_import_module_marker(m: &ImportModuleMarker) -> String {
    let fl: String = m.fromlist.as_ref().map_or_else(
        || "NONE".to_owned(),
        |items| format!("LIST|{}", items.join("\u{1F}")),
    );
    format!("{DR_IMPORT_MODULE_PREFIX}{}|{}|{}__", m.module, m.level, fl)
}

fn decode_import_module_marker(expr: &Expr) -> Option<ImportModuleMarker> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id
        .strip_prefix(DR_IMPORT_MODULE_PREFIX)?
        .strip_suffix("__")?;
    let mut parts: std::str::SplitN<'_, char> = inner.splitn(3, '|');
    let module: &str = parts.next()?;
    let level_str: &str = parts.next()?;
    let level: u32 = level_str.parse::<u32>().ok()?;
    let fromlist_str: &str = parts.next()?;
    let fromlist: Option<Vec<String>> = if fromlist_str == "NONE" {
        None
    } else if let Some(items) = fromlist_str.strip_prefix("LIST|") {
        if items.is_empty() {
            Some(Vec::new())
        } else {
            Some(
                items
                    .split('\u{1F}')
                    .map(str::to_owned)
                    .collect::<Vec<String>>(),
            )
        }
    } else {
        return None;
    };
    Some(ImportModuleMarker {
        module: module.to_owned(),
        level,
        fromlist,
    })
}

fn encode_import_fromset_marker(module: &str, level: u32) -> String {
    format!("{DR_IMPORT_FROMSET_PREFIX}{module}|{level}__")
}

fn decode_import_fromset_marker(expr: &Expr) -> Option<(String, u32)> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id
        .strip_prefix(DR_IMPORT_FROMSET_PREFIX)?
        .strip_suffix("__")?;
    let (module, level_str): (&str, &str) = inner.split_once('|')?;
    let level: u32 = level_str.parse::<u32>().ok()?;
    Some((module.to_owned(), level))
}

fn encode_import_attr_marker(module: &str, level: u32, attr: &str) -> String {
    format!("{DR_IMPORT_ATTR_PREFIX}{module}|{level}|{attr}__")
}

fn decode_import_attr_marker(expr: &Expr) -> Option<(String, u32, String)> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id.strip_prefix(DR_IMPORT_ATTR_PREFIX)?.strip_suffix("__")?;
    let mut parts: std::str::SplitN<'_, char> = inner.splitn(3, '|');
    let module: &str = parts.next()?;
    let level_str: &str = parts.next()?;
    let level: u32 = level_str.parse::<u32>().ok()?;
    let attr: &str = parts.next()?;
    Some((module.to_owned(), level, attr.to_owned()))
}

fn extract_str_const(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => Some(s.clone()),
        _ => None,
    }
}

fn extract_tuple_of_strings(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Constant {
            value: ConstValue::Tuple(items),
            ..
        } => {
            let mut out: Vec<String> = Vec::with_capacity(items.len());
            for item in items {
                let ConstValue::Str(s) = item else {
                    return None;
                };
                out.push(s.clone());
            }
            Some(out)
        }
        Expr::Tuple { elts, .. } => {
            let mut out: Vec<String> = Vec::with_capacity(elts.len());
            for elt in elts {
                let s: String = extract_str_const(elt)?;
                out.push(s);
            }
            Some(out)
        }
        _ => None,
    }
}

fn extract_level_const(expr: &Expr) -> Option<u32> {
    match expr {
        Expr::Constant {
            value: ConstValue::Int(i),
            ..
        } => u32::try_from((*i).max(0)).ok(),
        Expr::Constant {
            value: ConstValue::None,
            ..
        } => Some(0),
        _ => None,
    }
}

/// Build the `from MODULE import *` statement from the import marker on TOS. Shared by the pre-3.12
/// dedicated `IMPORT_STAR` opcode and the 3.12+ `CALL_INTRINSIC_1 INTRINSIC_IMPORT_STAR` form.
fn import_star_stmt(top: Option<Expr>) -> Stmt {
    let (module, level): (Option<String>, u32) = top.map_or((None, 0), |t: Expr| {
        if let Some(m) = decode_import_module_marker(&t) {
            (Some(m.module), m.level)
        } else if let Some((mod_name, lvl)) = decode_import_fromset_marker(&t) {
            (Some(mod_name), lvl)
        } else {
            (None, 0)
        }
    });
    Stmt::ImportFrom {
        module,
        names: vec![Alias {
            name: "*".to_owned(),
            asname: None,
        }],
        level,
        line: None,
    }
}

fn import_module_to_stmt(marker: &ImportModuleMarker, store_name: &str) -> Stmt {
    let top_level: &str = marker.module.split('.').next().unwrap_or(&marker.module);
    let asname: Option<String> = if store_name == top_level {
        None
    } else {
        Some(store_name.to_owned())
    };
    Stmt::Import(vec![Alias {
        name: marker.module.clone(),
        asname,
    }])
}

/// 3.14 defers class-scope annotations (`x: int`, `y: int = 0`) into an `__annotate__` code object
/// stored under the class-namespace key `__annotate_func__`; the class body itself only carries the
/// value-bearing `STORE_NAME` (`y = 0`) and nothing for the value-less `x`. Recover the annotations
/// from the recovered `__annotate_func__` function body (a sequence of `__classdict__["name"] = ann`
/// assigns) and thread them back: upgrade a matching value `Assign` to an `AnnAssign`, or insert a
/// bare `AnnAssign` where the body had no statement, then drop the synthetic `__annotate_func__` def.
fn thread_class_annotations(mut body: Vec<Stmt>) -> Vec<Stmt> {
    let annotations: Vec<(String, Expr)> = body
        .iter()
        .find_map(|s: &Stmt| match s {
            Stmt::FunctionDef {
                name,
                body: fn_body,
                ..
            } if name == "__annotate_func__" => Some(class_annotation_pairs(fn_body)),
            _ => None,
        })
        .unwrap_or_default();
    if annotations.is_empty() {
        return body;
    }
    body.retain(
        |s: &Stmt| !matches!(s, Stmt::FunctionDef { name, .. } if name == "__annotate_func__"),
    );
    let mut threaded: Vec<Stmt> = Vec::with_capacity(body.len() + annotations.len());
    let mut consumed: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (name, annotation) in &annotations {
        let existing: Option<usize> = body.iter().position(|s: &Stmt| match s {
            Stmt::Assign { targets, .. } => matches!(
                targets.as_slice(),
                [Expr::Name { id, .. }] if id == name
            ),
            _ => false,
        });
        match existing {
            Some(pos) => {
                consumed.insert(pos);
                let Stmt::Assign { value, line, .. }: Stmt = body[pos].clone() else {
                    continue;
                };
                threaded.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: name.clone(),
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation: annotation.clone(),
                    value: Some(value),
                    simple: true,
                    line,
                });
            }
            None => threaded.push(Stmt::AnnAssign {
                target: Expr::Name {
                    id: name.clone(),
                    ctx: ExprCtx::Store,
                    line: None,
                },
                annotation: annotation.clone(),
                value: None,
                simple: true,
                line: None,
            }),
        }
    }
    for (pos, stmt) in body.into_iter().enumerate() {
        if !consumed.contains(&pos) {
            threaded.push(stmt);
        }
    }
    threaded
}

/// 3.14 (PEP 649/749) defers MODULE-scope annotations (`X: T = v`, `X: T`) into a top-level
/// `__annotate__` code object guarded by a per-module `__conditional_annotations__` set. The module
/// body keeps only the value-bearing `STORE_NAME` (`X = v`) plus a `__conditional_annotations__` seed
/// (`__conditional_annotations__ = set()`, already dropped by `is_conditional_annotations_seed`) and,
/// per annotated name, a `__conditional_annotations__.add(idx)` membership marker that the structurer
/// surfaces as a dangling `__conditional_annotations__` expression. Recover the `(name, annotation)`
/// pairs from the synthetic `def __annotate__` body - each a `if idx in __conditional_annotations__:
/// <annotation>[name] = ...` clause whose subscript BASE is the annotation expression and whose slice
/// is the name literal - then upgrade the matching value `Assign` to an `AnnAssign` (or insert a bare
/// `AnnAssign` where the body had no value), and drop both the synthetic `__annotate__` def and the
/// leftover `__conditional_annotations__` membership expression. Mirrors `thread_class_annotations`
/// for module scope so 3.14 modules recover `X: T = v` instead of leaking the lazy-annotation shell.
fn thread_module_annotations(mut body: Vec<Stmt>) -> Vec<Stmt> {
    let annotations: Vec<(String, Expr)> = body
        .iter()
        .find_map(|s: &Stmt| match s {
            Stmt::FunctionDef {
                name,
                body: fn_body,
                ..
            } if name == "__annotate__" => Some(module_annotation_pairs(fn_body)),
            _ => None,
        })
        .unwrap_or_default();
    if annotations.is_empty() {
        return body;
    }
    body.retain(|s: &Stmt| {
        !matches!(s, Stmt::FunctionDef { name, .. } if name == "__annotate__")
            && !is_conditional_annotations_membership(s)
    });
    let mut threaded: Vec<Stmt> = Vec::with_capacity(body.len() + annotations.len());
    for stmt in body {
        let upgrade: Option<(String, Expr)> = match &stmt {
            Stmt::Assign { targets, .. } => match targets.as_slice() {
                [Expr::Name { id, .. }] => annotations
                    .iter()
                    .find(|(name, _): &&(String, Expr)| name == id)
                    .map(|(name, annotation): &(String, Expr)| (name.clone(), annotation.clone())),
                _ => None,
            },
            _ => None,
        };
        match (upgrade, stmt) {
            (Some((name, annotation)), Stmt::Assign { value, line, .. }) => {
                threaded.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation,
                    value: Some(value),
                    simple: true,
                    line,
                });
            }
            (_, stmt) => threaded.push(stmt),
        }
    }
    let assigned: std::collections::BTreeSet<&String> = threaded
        .iter()
        .filter_map(|s: &Stmt| match s {
            Stmt::AnnAssign {
                target: Expr::Name { id, .. },
                ..
            } => Some(id),
            _ => None,
        })
        .collect();
    let bare: Vec<Stmt> = annotations
        .iter()
        .filter(|(name, _): &&(String, Expr)| !assigned.contains(name))
        .map(|(name, annotation): &(String, Expr)| Stmt::AnnAssign {
            target: Expr::Name {
                id: name.clone(),
                ctx: ExprCtx::Store,
                line: None,
            },
            annotation: annotation.clone(),
            value: None,
            simple: true,
            line: None,
        })
        .collect();
    threaded.splice(0..0, bare);
    threaded
}

/// Ordered `(name, annotation)` pairs from a recovered module-scope `__annotate__` body. Each
/// annotation lives inside an `if idx in __conditional_annotations__:` guard whose single body
/// statement assigns into `<annotation>[name]`; the subscript base is the annotation and the string
/// slice is the annotated name. Plain (unconditional) subscript-store bodies are accepted too so a
/// non-conditional 3.14 `__annotate__` shape still recovers.
fn module_annotation_pairs(fn_body: &[Stmt]) -> Vec<(String, Expr)> {
    let mut pairs: Vec<(String, Expr)> = Vec::new();
    for stmt in fn_body {
        match stmt {
            Stmt::If { test, body, .. } if is_conditional_annotations_test(test) => {
                for inner in body {
                    if let Some(pair) = module_annotation_subscript_pair(inner) {
                        pairs.push(pair);
                    }
                }
            }
            _ => {
                if let Some(pair) = module_annotation_subscript_pair(stmt) {
                    pairs.push(pair);
                }
            }
        }
    }
    pairs
}

/// `<annotation>[name] = ...` -> `(name, annotation)`. The 3.14 lazy-annotation body materializes the
/// annotations dict via `STORE_SUBSCR` against an empty `BUILD_MAP`, which the linear structurer
/// surfaces as a subscript-store whose base is the annotation expression and whose slice is the name
/// string literal.
fn module_annotation_subscript_pair(stmt: &Stmt) -> Option<(String, Expr)> {
    let Stmt::Assign { targets, .. }: &Stmt = stmt else {
        return None;
    };
    let [
        Expr::Subscript {
            value: base, slice, ..
        },
    ]: &[Expr] = targets.as_slice()
    else {
        return None;
    };
    let Expr::Constant {
        value: ConstValue::Str(name),
        ..
    }: &Expr = slice.as_ref()
    else {
        return None;
    };
    Some((name.clone(), unstringify_annotation((**base).clone())))
}

/// True for the `<int> in __conditional_annotations__` membership test that guards each 3.14 lazy
/// module annotation.
fn is_conditional_annotations_test(test: &Expr) -> bool {
    let Expr::Compare {
        ops, comparators, ..
    }: &Expr = test
    else {
        return false;
    };
    matches!(ops.as_slice(), [CmpOp::In])
        && matches!(
            comparators.as_slice(),
            [Expr::Name { id, .. }] if id == "__conditional_annotations__"
        )
}

/// True for the leftover `__conditional_annotations__.add(idx)` membership marker the structurer
/// surfaces as a bare `__conditional_annotations__` expression statement once the seed assign is
/// stripped; dropping it keeps the recovered 3.14 module free of lazy-annotation scaffolding.
fn is_conditional_annotations_membership(s: &Stmt) -> bool {
    let Stmt::Expr(expr): &Stmt = s else {
        return false;
    };
    matches!(expr, Expr::Name { id, .. } if id == "__conditional_annotations__")
}

/// Extract ordered `(name, annotation)` pairs from a recovered `__annotate_func__` body whose
/// statements are `__classdict__["name"] = annotation` subscript assigns.
fn class_annotation_pairs(fn_body: &[Stmt]) -> Vec<(String, Expr)> {
    let mut pairs: Vec<(String, Expr)> = Vec::new();
    for stmt in fn_body {
        let Stmt::Assign { targets, value, .. }: &Stmt = stmt else {
            continue;
        };
        let [
            Expr::Subscript {
                value: base, slice, ..
            },
        ]: &[Expr] = targets.as_slice()
        else {
            continue;
        };
        if !is_class_annotation_base(base.as_ref()) {
            continue;
        }
        let Expr::Constant {
            value: ConstValue::Str(name),
            ..
        }: &Expr = slice.as_ref()
        else {
            continue;
        };
        pairs.push((name.clone(), unstringify_annotation(value.clone())));
    }
    pairs
}

/// The subscript base a deferred `__annotate__` body assigns each annotation into: a non-generic
/// class scope stores into the `__classdict__` cell, whereas a PEP 695 generic class scope builds
/// the annotations map locally (`BUILD_MAP 0`) and writes `<map>["name"] = ann`, which the
/// structurer recovers as an empty-dict-literal base.
fn is_class_annotation_base(base: &Expr) -> bool {
    match base {
        Expr::Name { id, .. } => id == "__classdict__",
        Expr::Dict { keys, values } => keys.is_empty() && values.is_empty(),
        _ => false,
    }
}

fn try_build_class_def(parent: &CodeObject, value: &Expr, target_name: &str) -> Option<Stmt> {
    let Expr::Call {
        func,
        args,
        keywords,
    } = value
    else {
        return None;
    };
    if !is_build_class_marker(func) {
        return None;
    }
    if args.len() < 2 {
        return None;
    }
    let const_idx: u32 = nested_code_index(&args[0])?;
    let mut bases: Vec<Expr> = args.iter().skip(2).cloned().collect();
    if pre_36_build_class_bases_reversed() {
        bases.reverse();
    }
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let body_raw: Vec<Stmt> =
        structure_stmts(nested, &stream, 0, stream.ops.len()).unwrap_or_default();
    let stripped: Vec<Stmt> = strip_class_implicit(strip_module_implicit_return(
        strip_module_docstring_stmt(body_raw, nested),
    ));
    let processed: Vec<Stmt> =
        thread_class_annotations(postprocess_body(stripped, BodyKind::Class));
    let final_body: Vec<Stmt> = if processed.is_empty() {
        vec![Stmt::Pass]
    } else {
        processed
    };
    Some(Stmt::ClassDef {
        name: target_name.to_owned(),
        type_params: Vec::new(),
        bases,
        keywords: keywords.clone(),
        body: final_body,
        decorators: Vec::new(),
        docstring: class_docstring(nested, &stream.ops),
        line: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeParamKind {
    TypeVar,
    ParamSpec,
    TypeVarTuple,
}

fn type_param_kind_from_intrinsic1(op: u8) -> Option<TypeParamKind> {
    match op {
        7 => Some(TypeParamKind::TypeVar),
        8 => Some(TypeParamKind::ParamSpec),
        9 => Some(TypeParamKind::TypeVarTuple),
        _ => None,
    }
}

/// `INTRINSIC_TYPEALIAS` value evaluators and `INTRINSIC_TYPEVAR_WITH_BOUND` bound evaluators are
/// lazy nested code objects whose body is a single `return <expr>`. Unwrap such a `MAKE_FUNCTION`
/// marker to that returned expression; an extra `SET_FUNCTION_ATTRIBUTE` (3.14 `__type_params__`)
/// before the `BUILD_TUPLE` does not change the single returned value.
fn unwrap_evaluator_expr(parent: &CodeObject, marker: &Expr) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(marker)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    if let Some(unpack) = starred_default_unpack_index(&ops) {
        let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(nested, &ops[..unpack]).ok()?;
        let inner: Expr = residual.into_iter().next_back()?;
        return Some(Expr::Starred {
            value: Box::new(inner),
            ctx: ExprCtx::Load,
        });
    }
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(nested, &ops).ok()?;
    stmts
        .into_iter()
        .rev()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .or_else(|| residual.into_iter().next_back())
}

/// Index of the closing `UNPACK_SEQUENCE 1` of a PEP 696 starred default evaluator (`*Ts = *tuple[int,
/// ...]`), whose code object is `<expr>; UNPACK_SEQUENCE 1; RETURN_VALUE`. That trailing single-element
/// unpack is the starred-default marker, not a real destructuring; recovering the value from the ops
/// BEFORE it and re-emitting a leading `*` round-trips the default. Returns `None` when the evaluator is
/// an ordinary (non-starred) default, so the value sim handles it normally.
fn starred_default_unpack_index(ops: &[CanonicalOp]) -> Option<usize> {
    let ret: usize = ops
        .iter()
        .rposition(|op: &CanonicalOp| {
            matches!(op, CanonicalOp::Return | CanonicalOp::ReturnConst(_))
        })
        .unwrap_or(ops.len());
    let unpack: usize = (0..ret).rev().find(|&k: &usize| {
        !matches!(
            ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })?;
    matches!(ops[unpack], CanonicalOp::UnpackSequence(1)).then_some(unpack)
}

/// On 3.14 annotations are deferred into a `__annotate__` code object attached via
/// `SET_FUNCTION_ATTRIBUTE 16`. Its body is a `format`-guarded `BUILD_MAP` of `{name: annotation}`;
/// run it and return the returned dict (the format-guard `if` and its raise are ignored - only the
/// final returned mapping carries the annotations).
fn annotate_codeobj_dict(parent: &CodeObject, marker: &Expr) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(marker)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.as_str(),
        _ => "",
    };
    if name != "__annotate__" {
        return None;
    }
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(nested, &ops).ok()?;
    stmts
        .into_iter()
        .rev()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e @ Expr::Dict { .. })) => Some(e),
            _ => None,
        })
        .or_else(|| {
            residual
                .into_iter()
                .rev()
                .find(|e: &Expr| matches!(e, Expr::Dict { .. }))
        })
}

fn encode_typevar_marker(kind: TypeParamKind, name: &str) -> String {
    let tag: char = match kind {
        TypeParamKind::TypeVar => 'T',
        TypeParamKind::ParamSpec => 'P',
        TypeParamKind::TypeVarTuple => 'V',
    };
    format!("{DR_TYPEVAR_MARKER}{tag}\u{1F}{name}__")
}

fn build_typevar_marker(kind: TypeParamKind, name: &str, bound: Option<Expr>) -> Expr {
    let head: Expr = Expr::Name {
        id: encode_typevar_marker(kind, name),
        ctx: ExprCtx::Load,
        line: None,
    };
    match bound {
        Some(b) => Expr::Call {
            func: Box::new(head),
            args: vec![b],
            keywords: Vec::new(),
        },
        None => head,
    }
}

fn is_typevar_marker(expr: &Expr) -> bool {
    let head: &Expr = match expr {
        Expr::Call { func, args, .. } if args.len() == 1 => func.as_ref(),
        other => other,
    };
    matches!(head, Expr::Name { id, .. } if id.starts_with(DR_TYPEVAR_MARKER))
}

fn type_alias_marker_call(name: &str, value: Expr) -> Expr {
    Expr::Call {
        func: Box::new(Expr::Name {
            id: DR_TYPE_ALIAS_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args: vec![
            Expr::Constant {
                value: ConstValue::Str(name.to_owned()),
                line: None,
            },
            value,
        ],
        keywords: Vec::new(),
    }
}

fn try_build_type_alias(value: &Expr, target_name: &str) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if !matches!(func.as_ref(), Expr::Name { id, .. } if id == DR_TYPE_ALIAS_MARKER) {
        return None;
    }
    let alias_value: Expr = args.get(1).cloned()?;
    Some(Stmt::TypeAlias {
        name: target_name.to_owned(),
        type_params: Vec::new(),
        value: alias_value,
        line: None,
    })
}

/// A generic wrapper is the `<generic parameters of X>` code object `CPython` emits for a PEP 695
/// `def f[...]` / `class X[...]`. It is identified by `CALL_INTRINSIC_2 4`
/// (`INTRINSIC_SET_FUNCTION_TYPE_PARAMS`, generic function) or `CALL_INTRINSIC_1 10`
/// (`INTRINSIC_SUBSCRIPT_GENERIC`, generic class) anywhere in its stream.
fn is_generic_wrapper(wrapper: &CodeObject) -> bool {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    ops.iter().any(|op: &CanonicalOp| {
        matches!(
            op,
            CanonicalOp::CallIntrinsic2(4) | CanonicalOp::CallIntrinsic1(10)
        )
    })
}

/// Recover the ordered `[T, **P, *Ts, T: int, ...]` type-param list from a generic wrapper by
/// scanning its bytecode for the typevar-construction intrinsics in source order. `CALL_INTRINSIC_1
/// 7/8/9` consume the preceding `LOAD_CONST <name>`; `CALL_INTRINSIC_2 2/3` consume `LOAD_CONST
/// <name>` plus a bound/constraints evaluator built by the immediately-preceding `MAKE_FUNCTION`.
fn collect_wrapper_type_params(
    wrapper: &CodeObject,
    ops: &[CanonicalOp],
) -> Vec<crate::ast::node::TypeParam> {
    use crate::ast::node::TypeParam;
    let mut params: Vec<TypeParam> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::CallIntrinsic1(code) => {
                let Some(kind): Option<TypeParamKind> = type_param_kind_from_intrinsic1(*code)
                else {
                    continue;
                };
                if let Some(name) = prev_load_const_str(wrapper, ops, i) {
                    params.push(match kind {
                        TypeParamKind::TypeVar => TypeParam::TypeVar {
                            name,
                            bound: None,
                            default: None,
                        },
                        TypeParamKind::ParamSpec => TypeParam::ParamSpec {
                            name,
                            default: None,
                        },
                        TypeParamKind::TypeVarTuple => TypeParam::TypeVarTuple {
                            name,
                            default: None,
                        },
                    });
                }
            }
            CanonicalOp::CallIntrinsic2(2 | 3) => {
                let eval_idx: Option<usize> = prev_make_function_const(ops, i);
                let bound: Option<Expr> = eval_idx
                    .and_then(|j: usize| match ops[j] {
                        CanonicalOp::LoadConst(slot) => Some(slot),
                        _ => None,
                    })
                    .and_then(|slot: u32| {
                        unwrap_evaluator_expr(
                            wrapper,
                            &Expr::Name {
                                id: format!("{DR_CODE_CONST_PREFIX}{slot}__"),
                                ctx: ExprCtx::Load,
                                line: None,
                            },
                        )
                    });
                if let Some(name) =
                    nearest_load_const_str_before(wrapper, ops, eval_idx.unwrap_or(i))
                {
                    params.push(TypeParam::TypeVar {
                        name,
                        bound,
                        default: None,
                    });
                }
            }
            CanonicalOp::CallIntrinsic2(5) => {
                let Some(default): Option<Expr> = prev_make_function_const(ops, i)
                    .and_then(|j: usize| match ops[j] {
                        CanonicalOp::LoadConst(slot) => Some(slot),
                        _ => None,
                    })
                    .and_then(|slot: u32| {
                        unwrap_evaluator_expr(
                            wrapper,
                            &Expr::Name {
                                id: format!("{DR_CODE_CONST_PREFIX}{slot}__"),
                                ctx: ExprCtx::Load,
                                line: None,
                            },
                        )
                    })
                else {
                    continue;
                };
                if let Some(param) = params.last_mut() {
                    match param {
                        TypeParam::TypeVar { default: slot, .. }
                        | TypeParam::ParamSpec { default: slot, .. }
                        | TypeParam::TypeVarTuple { default: slot, .. } => {
                            *slot = Some(default);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    params
}

/// Index of the `LOAD_CONST <code object>` feeding the `MAKE_FUNCTION` that precedes `CALL_INTRINSIC_2
/// 2/3` at `idx` (the bound/constraints lazy evaluator).
fn prev_make_function_const(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        if matches!(ops[k], CanonicalOp::MakeFunction(_)) {
            let mut j: usize = k;
            while j > 0 {
                j -= 1;
                match ops[j] {
                    CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
                    CanonicalOp::LoadConst(_) => return Some(j),
                    _ => return None,
                }
            }
            return None;
        }
    }
    None
}

/// The nearest preceding `LOAD_CONST` whose constant is a string, skipping intervening
/// code-object/tuple constants (e.g. the 3.14 bound-evaluator codeobj and its `(1,)` defaults
/// tuple sit between the typevar name and `CALL_INTRINSIC_2`). This is the typevar's name.
fn nearest_load_const_str_before(
    code: &CodeObject,
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<String> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        if let CanonicalOp::LoadConst(slot) = ops[k]
            && let Ok(Expr::Constant {
                value: ConstValue::Str(s),
                ..
            }) = load_const(code, slot, k)
        {
            return Some(s);
        }
    }
    None
}

/// The string constant loaded by the `LOAD_CONST` immediately preceding op `idx`.
fn prev_load_const_str(code: &CodeObject, ops: &[CanonicalOp], idx: usize) -> Option<String> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        match ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::LoadConst(slot) => {
                return load_const(code, slot, k).ok().and_then(|e: Expr| match e {
                    Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    } => Some(s),
                    _ => None,
                });
            }
            _ => return None,
        }
    }
    None
}

/// Lift a generic wrapper call (`MAKE_FUNCTION <wrapper>; CALL 0`) into the real PEP 695 definition
/// it produces: `def X[...](...)` for an `INTRINSIC_SET_FUNCTION_TYPE_PARAMS` wrapper or `class
/// X[...](...)` for an `INTRINSIC_SUBSCRIPT_GENERIC` wrapper. The wrapper is re-decoded; its inner
/// def/class body is recovered through the existing nested-def/class machinery and the recovered
/// type params are attached.
fn try_build_generic_def(parent: &CodeObject, value: &Expr, target_name: &str) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if args.len() > 1 {
        return None;
    }
    let const_idx: u32 = nested_code_index(func)?;
    let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
    if !is_generic_wrapper(wrapper) {
        return None;
    }
    let value_defaults: Vec<Expr> = args.first().map(value_default_tuple).unwrap_or_default();
    extract_generic(wrapper, target_name, &value_defaults)
}

/// The positional `__defaults__` tuple a generic-function wrapper receives as its single call
/// argument (`MAKE_FUNCTION <wrapper>; SWAP 2; CALL 0` with a leading `LOAD_CONST (d0, d1, …)`):
/// these are the inner def's value defaults, which the wrapper threads in via its `.defaults`
/// local rather than baking into the inner code object, so they must be lifted from the call site.
fn value_default_tuple(arg: &Expr) -> Vec<Expr> {
    defaults_from_expr(arg.clone())
}

/// Peel a decorator chain wrapping a PEP 695 generic wrapper call
/// (`Call(decorator, [Call(decorator, [… Call(wrapper, [..])])])`) and lift the inner
/// `def X[...]` / `class X[...]`, re-attaching the outer decorators in source order. The inner
/// wrapper may carry one redundant value-default arg (see `try_build_generic_def`), which is
/// discarded.
fn try_build_decorated_generic_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        let Expr::Call {
            func,
            args,
            keywords,
        } = cursor
        else {
            return None;
        };
        if let Some(const_idx) = nested_code_index(func) {
            if decorators.is_empty() {
                return None;
            }
            if args.len() > 1 {
                return None;
            }
            let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
            if !is_generic_wrapper(wrapper) {
                return None;
            }
            let value_defaults: Vec<Expr> =
                args.first().map(value_default_tuple).unwrap_or_default();
            let mut def: Stmt = extract_generic(wrapper, target_name, &value_defaults)?;
            match &mut def {
                Stmt::ClassDef {
                    decorators: slot, ..
                }
                | Stmt::FunctionDef {
                    decorators: slot, ..
                } => *slot = decorators,
                _ => return None,
            }
            return Some(def);
        }
        if args.len() != 1 || !keywords.is_empty() {
            return None;
        }
        decorators.push((**func).clone());
        cursor = &args[0];
    }
}

/// Lift a PEP 695 GENERIC `type` alias (`type Name[...] = value`) out of its `<generic parameters of
/// Name>` wrapper call (`MAKE_FUNCTION <wrapper>; CALL 0`). The wrapper is identified by a terminal
/// `CALL_INTRINSIC_1 INTRINSIC_TYPEALIAS` (11); its ordered type params are recovered with the same
/// scanner the generic def/class path uses, and the aliased value is unwrapped from the lazy
/// evaluator code object feeding the `MAKE_FUNCTION` immediately before that intrinsic.
fn try_build_generic_type_alias(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if !args.is_empty() {
        return None;
    }
    let const_idx: u32 = nested_code_index(func)?;
    let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let alias_intrinsic: usize = ops
        .iter()
        .position(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic1(11)))?;
    let type_params: Vec<crate::ast::node::TypeParam> = collect_wrapper_type_params(wrapper, &ops);
    let eval_idx: usize = prev_make_function_const(&ops, alias_intrinsic)?;
    let eval_slot: u32 = match ops[eval_idx] {
        CanonicalOp::LoadConst(slot) => slot,
        _ => return None,
    };
    let alias_value: Expr = unwrap_evaluator_expr(
        wrapper,
        &Expr::Name {
            id: format!("{DR_CODE_CONST_PREFIX}{eval_slot}__"),
            ctx: ExprCtx::Load,
            line: None,
        },
    )?;
    Some(Stmt::TypeAlias {
        name: target_name.to_owned(),
        type_params,
        value: alias_value,
        line: None,
    })
}

fn extract_generic(
    wrapper: &CodeObject,
    target_name: &str,
    value_defaults: &[Expr],
) -> Option<Stmt> {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let type_params: Vec<crate::ast::node::TypeParam> = collect_wrapper_type_params(wrapper, &ops);
    let is_class: bool = ops
        .iter()
        .any(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic1(10)));
    let inner_idx: u32 = generic_inner_code_index(wrapper, &ops, is_class)?;
    if is_class {
        extract_generic_class(wrapper, inner_idx, target_name, type_params)
    } else {
        extract_generic_function(wrapper, inner_idx, target_name, type_params, value_defaults)
    }
}

/// The const-pool index of the inner def/class code object inside a generic wrapper. For a function
/// wrapper it is the `<X>` codeobj whose `MAKE_FUNCTION` feeds the terminal `CALL_INTRINSIC_2 4`; for
/// a class wrapper it is the `<X>` closure codeobj passed to `__build_class__`.
fn generic_inner_code_index(
    wrapper: &CodeObject,
    ops: &[CanonicalOp],
    is_class: bool,
) -> Option<u32> {
    if is_class {
        let build_class: usize = ops
            .iter()
            .position(|op: &CanonicalOp| matches!(op, CanonicalOp::LoadBuildClass))?;
        for (i, op) in ops.iter().enumerate().skip(build_class) {
            if matches!(op, CanonicalOp::MakeFunction(_))
                && let Some(j) = prev_load_const_code(wrapper, ops, i)
            {
                return Some(j);
            }
        }
        None
    } else {
        let set_tp: usize = ops
            .iter()
            .position(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic2(4)))?;
        let mut last_make: Option<usize> = None;
        for (i, op) in ops.iter().enumerate().take(set_tp) {
            if matches!(op, CanonicalOp::MakeFunction(_)) {
                last_make = Some(i);
            }
        }
        last_make.and_then(|i: usize| prev_load_const_code(wrapper, ops, i))
    }
}

/// The const-pool index of the code-object constant feeding the `MAKE_FUNCTION` at `make_idx`
/// (skipping the intervening annotation/closure builders by walking back to the nearest
/// `LOAD_CONST` that points at a code object).
fn prev_load_const_code(code: &CodeObject, ops: &[CanonicalOp], make_idx: usize) -> Option<u32> {
    let mut k: usize = make_idx;
    while k > 0 {
        k -= 1;
        if let CanonicalOp::LoadConst(slot) = ops[k]
            && nested_code_object_at(code, slot).is_some()
        {
            return Some(slot);
        }
    }
    None
}

fn extract_generic_function(
    wrapper: &CodeObject,
    inner_idx: u32,
    target_name: &str,
    type_params: Vec<crate::ast::node::TypeParam>,
    value_defaults: &[Expr],
) -> Option<Stmt> {
    let mut fn_def: Stmt =
        build_nested_function_def(wrapper, inner_idx, target_name.to_owned(), false)?;
    if let Some(meta) = generic_inner_function_meta(wrapper, inner_idx) {
        attach_fn_meta(&mut fn_def, &meta);
    }
    if let Stmt::FunctionDef {
        type_params: tp,
        args,
        ..
    } = &mut fn_def
    {
        *tp = type_params;
        if args.defaults.is_empty() && !value_defaults.is_empty() {
            args.defaults = value_defaults.to_vec();
        }
    }
    Some(fn_def)
}

/// Re-run the wrapper stream to recover the inner function's defaults/annotations/returns the same
/// way the main loop does for any nested def - `SET_FUNCTION_ATTRIBUTE` / `MAKE_FUNCTION` flags
/// populate the `FunctionMeta` keyed by the inner code-object const index.
fn generic_inner_function_meta(wrapper: &CodeObject, inner_idx: u32) -> Option<FunctionMeta> {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let mut sim: StackSim = StackSim::new();
    let mut fn_meta: std::collections::BTreeMap<u32, FunctionMeta> =
        std::collections::BTreeMap::new();
    for (idx, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(e) = load_name(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFast(i) | CanonicalOp::LoadFastAndClear(i) => {
                if let Ok(e) = load_local(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                if let (Ok(ea), Ok(eb)) =
                    (load_local(wrapper, *a, idx), load_local(wrapper, *b, idx))
                {
                    sim.push(ea);
                    sim.push(eb);
                }
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(wrapper, idx);
                let value: Expr = sim.pop_or_synth(wrapper, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.pop_or_synth(wrapper, idx);
                let left: Expr = sim.pop_or_synth(wrapper, idx);
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::BuildTuple(n) => {
                let mut elts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    elts.insert(0, sim.pop_or_synth(wrapper, idx));
                }
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::MakeFunction(flags) => {
                let top: Option<Expr> = sim.try_pop();
                if let Some(marker) = top {
                    let meta: FunctionMeta = make_function_meta(*flags, &mut sim);
                    if let Some(ci) = nested_code_index(&marker) {
                        fn_meta.insert(ci, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::SetFunctionAttribute(flag) => {
                let func: Option<Expr> = sim.try_pop();
                let attr: Option<Expr> = sim.try_pop();
                if let (Some(f), Some(a)) = (&func, attr)
                    && let Some(ci) = nested_code_index(f)
                {
                    let entry: &mut FunctionMeta = fn_meta.entry(ci).or_default();
                    match flag {
                        1 => entry.defaults = defaults_from_expr(a),
                        2 => entry.kw_defaults = kwdefaults_from_expr(a),
                        4 => {
                            let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                annotations_from_expr(a);
                            entry.annotations = params;
                            entry.returns = ret;
                        }
                        16 => {
                            if let Some(dict) = annotate_codeobj_dict(wrapper, &a) {
                                let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                    annotations_from_expr(dict);
                                entry.annotations = params;
                                entry.returns = ret;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(f) = func {
                    sim.push(f);
                }
            }
            CanonicalOp::Swap(n) => sim.swap(usize::from(*n)),
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::StoreFast(_) => {
                let _ = sim.try_pop();
            }
            _ => {}
        }
    }
    fn_meta.remove(&inner_idx)
}

fn extract_generic_class(
    wrapper: &CodeObject,
    inner_idx: u32,
    target_name: &str,
    type_params: Vec<crate::ast::node::TypeParam>,
) -> Option<Stmt> {
    let build_class_value: Expr = Expr::Call {
        func: Box::new(Expr::Name {
            id: DR_BUILD_CLASS_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args: vec![
            Expr::Name {
                id: format!("{DR_CODE_CONST_PREFIX}{inner_idx}__"),
                ctx: ExprCtx::Load,
                line: None,
            },
            Expr::Constant {
                value: ConstValue::Str(target_name.to_owned()),
                line: None,
            },
        ],
        keywords: Vec::new(),
    };
    let mut class_def: Stmt = try_build_class_def(wrapper, &build_class_value, target_name)?;
    if let Stmt::ClassDef {
        type_params: tp,
        body,
        ..
    } = &mut class_def
    {
        *tp = type_params;
        body.retain(|s: &Stmt| !is_type_params_setup_assign(s));
        if body.is_empty() {
            body.push(Stmt::Pass);
        }
    }
    Some(class_def)
}

/// `__type_params__ = .type_params` (and the `.type_params` deref binding) are compiler-synthesized
/// inside a generic class body; they must be stripped so the recovered class body matches source.
fn is_type_params_setup_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    matches!(id.as_str(), "__type_params__" | ".type_params")
}

fn strip_class_implicit(mut body: Vec<Stmt>) -> Vec<Stmt> {
    body.retain(|s: &Stmt| !is_class_setup_assign(s));
    if body.last().is_some_and(is_class_implicit_return) {
        body.pop();
    }
    body
}

fn is_class_implicit_return(s: &Stmt) -> bool {
    match s {
        Stmt::Return(None) => true,
        Stmt::Return(Some(value)) => match value {
            Expr::Constant {
                value: ConstValue::None,
                ..
            } => true,
            Expr::Name { id, .. } => {
                id == "__class__" || id == "__classcell__" || id == DR_NULL_MARKER
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_class_setup_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    matches!(
        id.as_str(),
        "__module__"
            | "__qualname__"
            | "__doc__"
            | "__firstlineno__"
            | "__static_attributes__"
            | "__classcell__"
            | "__class__"
            | "__classdict__"
            | "__classdictcell__"
            | "__type_params__"
            | ".type_params"
    )
}

fn update_last_import_from_asname(out: &mut [Stmt], attr: &str, asname: &str) {
    for stmt in out.iter_mut().rev() {
        if let Stmt::ImportFrom { names, .. } = stmt {
            for alias in names.iter_mut() {
                if alias.name == attr && alias.asname.is_none() {
                    alias.asname = Some(asname.to_owned());
                    return;
                }
            }
        }
    }
}

fn load_const(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let obj: &Object = code
        .consts
        .get(idx as usize)
        .ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("const index {idx} out of range"),
        })?;
    if matches!(obj, Object::Code(_)) {
        return Ok(Expr::Name {
            id: format!("{DR_CODE_CONST_PREFIX}{idx}__"),
            ctx: ExprCtx::Load,
            line: None,
        });
    }
    Ok(Expr::Constant {
        value: object_to_const(obj),
        line: None,
    })
}

#[derive(Debug, Clone, Default)]
struct FunctionMeta {
    defaults: Vec<Expr>,
    kw_defaults: Vec<(String, Expr)>,
    annotations: Vec<(String, Expr)>,
    returns: Option<Expr>,
}

fn make_function_meta(flags: u8, sim: &mut StackSim) -> FunctionMeta {
    let mut meta: FunctionMeta = FunctionMeta::default();
    if flags & 0x08 != 0 {
        let _closure: Option<Expr> = sim.try_pop();
    }
    if flags & 0x04 != 0
        && let Some(anns) = sim.try_pop()
    {
        let (params, ret): (Vec<(String, Expr)>, Option<Expr>) = annotations_from_expr(anns);
        meta.annotations = params;
        meta.returns = ret;
    }
    if flags & 0x02 != 0
        && let Some(kwd) = sim.try_pop()
    {
        meta.kw_defaults = kwdefaults_from_expr(kwd);
    }
    if flags & 0x01 != 0
        && let Some(defs) = sim.try_pop()
    {
        meta.defaults = defaults_from_expr(defs);
    }
    meta
}

fn make_function_meta_legacy(packed: u32, sim: &mut StackSim) -> FunctionMeta {
    let mut meta: FunctionMeta = FunctionMeta::default();
    let pos_defaults: usize = (packed & 0xFF) as usize;
    let kw_defaults: usize = ((packed >> 8) & 0xFF) as usize;
    let num_annotations: usize = ((packed >> 16) & 0x7FFF) as usize;
    if num_annotations > 0 {
        let names: Option<Expr> = sim.try_pop();
        let mut values: Vec<Expr> = Vec::with_capacity(num_annotations);
        for _ in 0..num_annotations {
            if let Some(v) = sim.try_pop() {
                values.insert(0, v);
            }
        }
        if let Some(name_tuple) = names {
            let keys: Vec<String> = match name_tuple {
                Expr::Tuple { elts, .. } => elts
                    .into_iter()
                    .filter_map(|e: Expr| match e {
                        Expr::Constant {
                            value: ConstValue::Str(s),
                            ..
                        } => Some(s),
                        _ => None,
                    })
                    .collect(),
                Expr::Constant {
                    value: ConstValue::Tuple(parts),
                    ..
                } => parts
                    .into_iter()
                    .filter_map(|c: ConstValue| match c {
                        ConstValue::Str(s) => Some(s),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            for (name, value) in keys.into_iter().zip(values) {
                if name == "return" {
                    meta.returns = Some(value);
                } else {
                    meta.annotations.push((name, value));
                }
            }
        }
    }
    let mut kw_pairs: Vec<(String, Expr)> = Vec::with_capacity(kw_defaults);
    for _ in 0..kw_defaults {
        let value: Option<Expr> = sim.try_pop();
        let name: Option<Expr> = sim.try_pop();
        if let (
            Some(value),
            Some(Expr::Constant {
                value: ConstValue::Str(name),
                ..
            }),
        ) = (value, name)
        {
            kw_pairs.insert(0, (name, value));
        }
    }
    meta.kw_defaults = kw_pairs;
    let mut defaults: Vec<Expr> = Vec::with_capacity(pos_defaults);
    for _ in 0..pos_defaults {
        if let Some(v) = sim.try_pop() {
            defaults.insert(0, v);
        }
    }
    meta.defaults = defaults;
    meta
}

/// Split a `BUILD_CONST_KEY_MAP`-produced annotations dict into per-parameter annotations and the
/// optional `'return'` entry which becomes the function's return type. The dict's keys are str
/// constants like `'a'`, `'b'`, `'return'`.
fn annotations_from_expr(expr: Expr) -> (Vec<(String, Expr)>, Option<Expr>) {
    let pairs: Vec<(String, Expr)> = match expr {
        Expr::Dict { keys, values } => keys
            .into_iter()
            .zip(values)
            .filter_map(|(k, v): (Option<Expr>, Expr)| match k {
                Some(Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                }) => Some((name, v)),
                _ => None,
            })
            .collect(),
        Expr::Tuple { elts, .. } => {
            let mut out: Vec<(String, Expr)> = Vec::with_capacity(elts.len() / 2);
            let mut iter: std::vec::IntoIter<Expr> = elts.into_iter();
            while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                let Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                } = k
                else {
                    continue;
                };
                out.push((name, v));
            }
            out
        }
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => {
            let mut out: Vec<(String, Expr)> = Vec::with_capacity(parts.len() / 2);
            let mut iter: std::vec::IntoIter<ConstValue> = parts.into_iter();
            while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                let ConstValue::Str(name) = k else {
                    continue;
                };
                out.push((name, Expr::Constant { value: v, line }));
            }
            out
        }
        _ => Vec::new(),
    };
    let mut params: Vec<(String, Expr)> = Vec::with_capacity(pairs.len());
    let mut returns: Option<Expr> = None;
    for (name, value) in pairs {
        let value: Expr = unstringify_annotation(value);
        if name == "return" {
            returns = Some(value);
        } else {
            params.push((name, value));
        }
    }
    (params, returns)
}

/// Re-parse a stringified (`PEP 563`) annotation const back into the real annotation `Expr`, matching
/// the module-level `merge_annotations` convention. Only fires when the module compiled under
/// `from __future__ import annotations` (which stringifies every annotation); otherwise a string-const
/// annotation is a genuine quoted forward reference (`-> "Color"`) and must round-trip as a string
/// literal, so it is returned untouched. A non-`Str` annotation is likewise returned untouched.
fn unstringify_annotation(value: Expr) -> Expr {
    if !future_annotations_active() {
        return value;
    }
    match value {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => parse_annotation_string(&s),
        other => other,
    }
}

fn defaults_from_expr(expr: Expr) -> Vec<Expr> {
    match expr {
        Expr::Tuple { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant { value: c, line })
            .collect(),
        _ => Vec::new(),
    }
}

fn kwdefaults_from_expr(expr: Expr) -> Vec<(String, Expr)> {
    match expr {
        Expr::Dict { keys, values } => keys
            .into_iter()
            .zip(values)
            .filter_map(|(k, v): (Option<Expr>, Expr)| match k {
                Some(Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                }) => Some((name, v)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn attach_fn_meta(stmt: &mut Stmt, meta: &FunctionMeta) {
    if let Stmt::FunctionDef { args, returns, .. } = stmt {
        let taken: Arguments = std::mem::take(args);
        *args = apply_function_meta(taken, meta);
        if returns.is_none() {
            returns.clone_from(&meta.returns);
        }
    }
}

fn apply_function_meta(mut args: Arguments, meta: &FunctionMeta) -> Arguments {
    if !meta.defaults.is_empty() {
        args.defaults.clone_from(&meta.defaults);
    }
    if !meta.kw_defaults.is_empty() {
        args.kw_defaults = args
            .kwonly
            .iter()
            .map(|kw_arg: &crate::ast::node::Arg| {
                meta.kw_defaults
                    .iter()
                    .find(|(n, _): &&(String, Expr)| *n == kw_arg.arg)
                    .map(|(_, e): &(String, Expr)| e.clone())
            })
            .collect();
    }
    if !meta.annotations.is_empty() {
        let apply: &dyn Fn(&mut crate::ast::node::Arg) = &|arg: &mut crate::ast::node::Arg| {
            if arg.annotation.is_some() {
                return;
            }
            if let Some((_, ann)) = meta
                .annotations
                .iter()
                .find(|(n, _): &&(String, Expr)| *n == arg.arg)
            {
                arg.annotation = Some(Box::new(ann.clone()));
            }
        };
        for arg in &mut args.posonly {
            apply(arg);
        }
        for arg in &mut args.args {
            apply(arg);
        }
        for arg in &mut args.kwonly {
            apply(arg);
        }
        if let Some(arg) = args.vararg.as_deref_mut() {
            apply(arg);
        }
        if let Some(arg) = args.kwarg.as_deref_mut() {
            apply(arg);
        }
    }
    args
}

fn call_ex_args(args_iter: Expr) -> Vec<Expr> {
    match args_iter {
        Expr::Tuple { elts, .. } | Expr::List { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant { value: c, line })
            .collect(),
        other => vec![starred(other)],
    }
}

fn call_ex_kwargs(kwargs: Expr) -> Vec<crate::ast::node::Keyword> {
    match kwargs {
        Expr::Dict { keys, values } => keys
            .into_iter()
            .zip(values)
            .map(|(key, value): (Option<Expr>, Expr)| {
                let arg: Option<String> = match key {
                    Some(Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    }) => Some(s),
                    _ => None,
                };
                crate::ast::node::Keyword { arg, value }
            })
            .collect(),
        other => vec![crate::ast::node::Keyword {
            arg: None,
            value: other,
        }],
    }
}

fn starred(expr: Expr) -> Expr {
    match expr {
        Expr::Starred { .. } => expr,
        other => Expr::Starred {
            value: Box::new(other),
            ctx: ExprCtx::Load,
        },
    }
}

fn build_legacy_call(
    code: &CodeObject,
    idx: usize,
    packed: u32,
    has_var: bool,
    has_kw: bool,
    sim: &mut StackSim,
) -> Expr {
    let npos: usize = (packed & 0xFF) as usize;
    let nkw: usize = ((packed >> 8) & 0xFF) as usize;
    let kwargs_double: Option<Expr> = if has_kw {
        Some(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let args_star: Option<Expr> = if has_var {
        Some(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let mut keywords: Vec<crate::ast::node::Keyword> =
        Vec::with_capacity(nkw + usize::from(has_kw));
    for _ in 0..nkw {
        let value: Expr = sim.pop_or_synth(code, idx);
        let name: Expr = sim.pop_or_synth(code, idx);
        let arg: Option<String> = match name {
            Expr::Constant {
                value: ConstValue::Str(s),
                ..
            } => Some(s),
            _ => None,
        };
        keywords.insert(0, crate::ast::node::Keyword { arg, value });
    }
    let mut args: Vec<Expr> = Vec::with_capacity(npos + usize::from(has_var));
    for _ in 0..npos {
        args.insert(0, sim.pop_or_synth(code, idx));
    }
    let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
    if let Some(self_arg) = implicit_self {
        args.insert(0, self_arg);
    }
    if let Some(star) = args_star {
        args.push(starred(star));
    }
    if let Some(double) = kwargs_double {
        keywords.push(crate::ast::node::Keyword {
            arg: None,
            value: double,
        });
    }
    Expr::Call {
        func: Box::new(func),
        args,
        keywords,
    }
}

fn const_collection_elements(addition: &Expr) -> Option<Vec<Expr>> {
    let Expr::Constant { value, line }: &Expr = addition else {
        return None;
    };
    let (ConstValue::Tuple(items) | ConstValue::Frozenset(items)): &ConstValue = value else {
        return None;
    };
    Some(
        items
            .iter()
            .map(|c: &ConstValue| Expr::Constant {
                value: c.clone(),
                line: *line,
            })
            .collect(),
    )
}

fn merge_extend(base: Option<Expr>, addition: Expr, is_mapping: bool) -> Expr {
    let Some(base): Option<Expr> = base else {
        return addition;
    };
    match base {
        Expr::List { mut elts, ctx } => {
            match const_collection_elements(&addition) {
                Some(spliced) => elts.extend(spliced),
                None => elts.push(starred(addition)),
            }
            Expr::List { elts, ctx }
        }
        Expr::Set(mut elts) => {
            match const_collection_elements(&addition) {
                Some(spliced) => elts.extend(spliced),
                None => elts.push(starred(addition)),
            }
            Expr::Set(elts)
        }
        Expr::Dict {
            mut keys,
            mut values,
        } if is_mapping => {
            keys.push(None);
            values.push(addition);
            Expr::Dict { keys, values }
        }
        other => other,
    }
}

fn slice_bound(expr: Expr) -> Option<Box<Expr>> {
    match expr {
        Expr::Constant {
            value: ConstValue::None,
            ..
        } => None,
        other => Some(Box::new(other)),
    }
}

fn pop_legacy_slice_bounds(
    sim: &mut StackSim,
    code: &CodeObject,
    idx: usize,
    variant: u8,
) -> (Option<Box<Expr>>, Option<Box<Expr>>) {
    let has_upper: bool = variant == 2 || variant == 3;
    let has_lower: bool = variant == 1 || variant == 3;
    let upper: Option<Box<Expr>> = if has_upper {
        slice_bound(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let lower: Option<Box<Expr>> = if has_lower {
        slice_bound(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    (lower, upper)
}

fn nested_code_index(expr: &Expr) -> Option<u32> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let s: &str = id.strip_prefix(DR_CODE_CONST_PREFIX)?.strip_suffix("__")?;
    s.parse::<u32>().ok()
}

fn nested_code_object_at(code: &CodeObject, idx: u32) -> Option<&CodeObject> {
    let obj: &Object = code.consts.get(idx as usize)?;
    match obj {
        Object::Code(boxed) => Some(boxed.as_ref()),
        _ => None,
    }
}

fn try_build_decorated_class_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        let Expr::Call {
            func,
            args,
            keywords,
        }: &Expr = cursor
        else {
            return None;
        };
        if is_build_class_marker(func) {
            if decorators.is_empty() {
                return None;
            }
            let mut class_def: Stmt = try_build_class_def(parent, cursor, target_name)?;
            let Stmt::ClassDef {
                decorators: slot, ..
            }: &mut Stmt = &mut class_def
            else {
                return None;
            };
            *slot = decorators;
            return Some(class_def);
        }
        if args.len() != 1 || !keywords.is_empty() {
            return None;
        }
        decorators.push((**func).clone());
        cursor = &args[0];
    }
}

fn try_build_decorated_function_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
    fn_meta: &std::collections::BTreeMap<u32, FunctionMeta>,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        match cursor {
            Expr::Call {
                func,
                args,
                keywords,
            } if args.len() == 1 && keywords.is_empty() => {
                if nested_code_index(&args[0]).is_some() {
                    let const_idx: u32 = nested_code_index(&args[0])?;
                    let Some(Stmt::FunctionDef {
                        name,
                        type_params,
                        args: fn_args,
                        body,
                        returns,
                        is_async,
                        docstring,
                        line,
                        ..
                    }): Option<Stmt> =
                        build_nested_function_def(parent, const_idx, target_name.to_owned(), false)
                    else {
                        return None;
                    };
                    let (fn_args, returns): (Arguments, Option<Expr>) =
                        match fn_meta.get(&const_idx) {
                            Some(meta) => (
                                apply_function_meta(fn_args, meta),
                                returns.or_else(|| meta.returns.clone()),
                            ),
                            None => (fn_args, returns),
                        };
                    decorators.push((**func).clone());
                    return Some(Stmt::FunctionDef {
                        name,
                        type_params,
                        args: fn_args,
                        body,
                        decorators,
                        returns,
                        is_async,
                        docstring,
                        line,
                    });
                }
                decorators.push((**func).clone());
                cursor = &args[0];
            }
            _ => return None,
        }
    }
}

/// Prepend `global <names>` for every name the scope assigns via `STORE_GLOBAL`; without the
/// declaration the recompiled body would emit `STORE_NAME` and bind a local instead of the module
/// global. Names are sorted for deterministic output and de-duplicated. A name annotated in this
/// scope (`x: T`) is skipped - `global x` alongside an annotation is a hard `SyntaxError`
/// ("annotated name can't be global"), so emitting it would make the source un-recompilable; the
/// `STORE_NAME`/`STORE_GLOBAL` divergence is the lesser evil. The decl is inserted AFTER any leading
/// `from __future__` imports, which must remain the first statements of the module.
fn prepend_global_decls(code: &CodeObject, ops: &[CanonicalOp], body: Vec<Stmt>) -> Vec<Stmt> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, op) in ops.iter().enumerate() {
        if let CanonicalOp::StoreGlobal(n) = op
            && let Ok(name) = name_at(&code.names, *n, i, "name")
        {
            names.insert(name);
        }
    }
    let annotated: std::collections::BTreeSet<&str> = body
        .iter()
        .filter_map(|s: &Stmt| match s {
            Stmt::AnnAssign {
                target: Expr::Name { id, .. },
                ..
            } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    names.retain(|n: &String| !annotated.contains(n.as_str()));
    if names.is_empty() {
        return body;
    }
    let insert_at: usize = body
        .iter()
        .position(
            |s: &Stmt| !matches!(s, Stmt::ImportFrom { module: Some(m), .. } if m == "__future__"),
        )
        .unwrap_or(body.len());
    let mut out: Vec<Stmt> = body;
    out.insert(insert_at, Stmt::Global(names.into_iter().collect()));
    out
}

/// Prepend `nonlocal <names>` for every freevar the function assigns via `STORE_DEREF`; without
/// the declaration the recompiled body would bind a local of the same name instead of writing
/// through the closure cell, which alters semantics AND drops the outer's `STORE_DEREF` + cell
/// allocation. Names come from the freevars pool (or `localsplusnames` on 3.11+) - never from
/// cellvars (those are own cells, not nonlocals). Sorted, deduped.
/// Build the set of names that the code object treats as free-variable cells from outer scopes.
/// On 3.8-3.10 the marshal stream populates `code.freevars` directly. On 3.11+ that field is empty
/// and free-var slots are encoded into `localsplusnames` keyed by `localspluskinds` byte flags
/// (`CO_FAST_FREE = 0x80`).
const CO_FAST_FREE: u8 = 0x80;

fn collect_freevar_names(code: &CodeObject) -> std::collections::BTreeSet<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obj in &code.freevars {
        if let Object::String { value, .. } | Object::ShortAscii { value, .. } = obj {
            out.insert(value.clone());
        }
    }
    if !code.localspluskinds.is_empty() && !code.localsplusnames.is_empty() {
        for (kind, obj) in code.localspluskinds.iter().zip(code.localsplusnames.iter()) {
            if *kind & CO_FAST_FREE == 0 {
                continue;
            }
            if let Object::String { value, .. } | Object::ShortAscii { value, .. } = obj {
                out.insert(value.clone());
            }
        }
    }
    out
}

fn prepend_nonlocal_decls(code: &CodeObject, ops: &[CanonicalOp], body: Vec<Stmt>) -> Vec<Stmt> {
    let freevar_names: std::collections::BTreeSet<String> = collect_freevar_names(code);
    let mut assigned: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, op) in ops.iter().enumerate() {
        let CanonicalOp::StoreFast(raw) = op else {
            continue;
        };
        if !is_deref_local(*raw) {
            continue;
        }
        let Ok(name) = local_name_at(code, *raw, i) else {
            continue;
        };
        if freevar_names.contains(&name) {
            assigned.insert(name);
        }
    }
    if assigned.is_empty() {
        return body;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len() + 1);
    out.push(Stmt::Nonlocal(assigned.into_iter().collect()));
    out.extend(body);
    out
}

fn build_nested_function_def(
    parent: &CodeObject,
    const_idx: u32,
    target_name: String,
    is_async_default: bool,
) -> Option<Stmt> {
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let body_raw: Vec<Stmt> =
        structure_stmts(nested, &stream, 0, stream.ops.len()).unwrap_or_default();
    let stripped: Vec<Stmt> =
        strip_module_implicit_return(strip_module_docstring_stmt(body_raw, nested));
    let processed: Vec<Stmt> = prepend_nonlocal_decls(
        nested,
        &stream.ops,
        prepend_global_decls(
            nested,
            &stream.ops,
            postprocess_body(stripped, BodyKind::Function),
        ),
    );
    let final_body: Vec<Stmt> = if processed.is_empty() {
        vec![Stmt::Pass]
    } else {
        processed
    };
    let is_async: bool = is_async_default
        || (nested.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    let args: Arguments = function_args_from_code(nested);
    Some(Stmt::FunctionDef {
        name: target_name,
        type_params: Vec::new(),
        args,
        body: final_body,
        decorators: Vec::new(),
        returns: None,
        is_async,
        docstring: extract_docstring(nested),
        line: None,
    })
}

/// A `<lambda>` code object loaded by `MAKE_FUNCTION` and used as a value (call argument, default,
/// assignment RHS) lifts to an `Expr::Lambda`. Its body is a single expression returned by the
/// nested code object; defaults captured by `MAKE_FUNCTION` are applied to the parameter list.
fn try_build_lambda_expr(parent: &CodeObject, const_idx: u32, meta: &FunctionMeta) -> Option<Expr> {
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return None,
    };
    if name != "<lambda>" {
        return None;
    }
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(nested, &ops).ok()?;
    let body: Expr = stmts
        .into_iter()
        .rev()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .or_else(|| residual.into_iter().next_back())
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let args: Arguments = apply_function_meta(function_args_from_code(nested), meta);
    Some(Expr::Lambda {
        args: Box::new(args),
        body: Box::new(body),
    })
}

fn try_build_comprehension_expr(parent: &CodeObject, func: &Expr, args: &[Expr]) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(func)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return None,
    };
    let comp_kind: CompKind = match name {
        "<listcomp>" => CompKind::List,
        "<setcomp>" => CompKind::Set,
        "<dictcomp>" => CompKind::Dict,
        "<genexpr>" => CompKind::Gen,
        _ => return None,
    };
    let iter: Expr = args.first().cloned().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let parts: ComprehensionParts = extract_comprehension_parts(nested, &stream.ops, comp_kind);
    let is_async: bool = (nested.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    let mut generators: Vec<Comprehension> =
        comprehension_generators(nested, &stream, comp_kind, iter);
    if generators.is_empty() {
        generators.push(Comprehension {
            target: parts.target,
            iter: Expr::Constant {
                value: ConstValue::None,
                line: None,
            },
            ifs: parts.ifs,
            is_async,
        });
    }
    let elt: Expr = parts.elt;
    let key_value: Option<(Expr, Expr)> = parts.key_value;
    let result: Expr = match comp_kind {
        CompKind::List => Expr::ListComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Set => Expr::SetComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Gen => Expr::GeneratorExp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Dict => {
            let (k, v): (Expr, Expr) = key_value.unwrap_or((
                elt,
                Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                },
            ));
            Expr::DictComp {
                key: Box::new(k),
                value: Box::new(v),
                generators,
            }
        }
    };
    Some(result)
}

/// Walk a comprehension code object's `FOR_ITER` loops to recover every `for`/`if` clause. The first
/// generator iterates the passed-in `.0` argument; each subsequent generator's iterable is the
/// expression evaluated before its `GET_ITER`. Filters are the conditions guarding each loop body.
fn comprehension_generators(
    nested: &CodeObject,
    stream: &DecodedStream,
    kind: CompKind,
    outer_iter: Expr,
) -> Vec<Comprehension> {
    comprehension_generators_in(nested, stream, kind, outer_iter, 0, stream.ops.len())
}

/// One comprehension clause header located by the generator scan: a sync `FOR_ITER` or an async
/// `GET_ANEXT`, tagged with its async-ness so each generator stamps the correct `is_async`.
#[derive(Debug, Clone, Copy)]
struct CompClause {
    header: usize,
    is_async: bool,
}

fn comprehension_generators_in(
    nested: &CodeObject,
    stream: &DecodedStream,
    kind: CompKind,
    outer_iter: Expr,
    lo: usize,
    hi: usize,
) -> Vec<Comprehension> {
    let hi: usize = hi.min(stream.ops.len());
    let mut clauses: Vec<CompClause> = (lo..hi)
        .filter_map(|k: usize| match stream.ops[k] {
            CanonicalOp::ForIter(_) => Some(CompClause {
                header: k,
                is_async: false,
            }),
            CanonicalOp::GetAnext => Some(CompClause {
                header: k,
                is_async: true,
            }),
            _ => None,
        })
        .collect();
    clauses.sort_unstable_by_key(|c: &CompClause| c.header);
    if clauses.is_empty() {
        return Vec::new();
    }
    let mut generators: Vec<Comprehension> = Vec::with_capacity(clauses.len());
    let mut prev_target_end: usize = lo;
    for (gi, clause) in clauses.iter().enumerate() {
        let iter: Expr = if gi == 0 {
            outer_iter.clone()
        } else {
            comp_inner_iter(nested, stream, prev_target_end, clause.header)
        };
        let target_scan_start: usize = comp_clause_target_start(stream, clause, hi);
        let (target, after_target): (Expr, usize) =
            comp_loop_target(nested, stream, target_scan_start);
        let clause_end: usize = clauses
            .get(gi + 1)
            .map_or(hi, |next: &CompClause| next.header);
        let ifs: Vec<Expr> = comp_clause_filters(nested, stream, after_target, clause_end);
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: clause.is_async,
        });
        prev_target_end = after_target;
    }
    let _ = kind;
    generators
}

/// The index at which the loop-variable `STORE_*` begins for a comprehension clause. A sync
/// `FOR_ITER` stores immediately at `header + 1`. An async clause's `GET_ANEXT` is followed by the
/// awaited `__anext__` poll (`LOAD_CONST None; SEND/YIELD_FROM; …; END_SEND` on 3.12+, or
/// `LOAD_CONST None; YIELD_FROM; POP_BLOCK` on 3.8-3.11); the target store is the first
/// `STORE_FAST*`/`STORE_NAME`/`UNPACK_*` after that poll, located by skipping the await machinery.
fn comp_clause_target_start(stream: &DecodedStream, clause: &CompClause, hi: usize) -> usize {
    if !clause.is_async {
        return clause.header + 1;
    }
    (clause.header + 1..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreFastLoadFast(_, _)
                    | CanonicalOp::StoreFastStoreFast(_, _)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::UnpackSequence(_)
                    | CanonicalOp::UnpackEx(_)
            )
        })
        .unwrap_or(clause.header + 1)
}

/// Whether the guarding conditional jump's target is the element-skip path: a loop back-edge, the
/// next `FOR_ITER`, or an `async for` loop header (`GET_ANEXT`/`END_ASYNC_FOR`). The complement is a
/// forward jump into the append (keep) body.
fn filter_jump_target_is_skip(stream: &DecodedStream, cond_idx: usize) -> bool {
    resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])
        .and_then(|t: usize| first_significant(stream, t, stream.ops.len()))
        .is_some_and(|s: usize| {
            is_back_edge(&stream.ops[s])
                || matches!(
                    stream.ops[s],
                    CanonicalOp::ForIter(_) | CanonicalOp::GetAnext | CanonicalOp::EndAsyncFor
                )
        })
}

/// Whether a comprehension filter keeps the element when its condition is true. The guarding
/// conditional jump skips the element (targets a loop back-edge or the next `FOR_ITER`) on failure;
/// a forward jump into the append body is the inverse. Combine target direction with jump polarity.
fn filter_keeps_when_true(stream: &DecodedStream, cond_idx: usize) -> bool {
    let jump_true: bool = matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    );
    if filter_jump_target_is_skip(stream, cond_idx) {
        !jump_true
    } else {
        jump_true
    }
}

/// The loop variable stored immediately after a `FOR_ITER` (simple name or a tuple unpack target).
fn comp_loop_target(nested: &CodeObject, stream: &DecodedStream, start: usize) -> (Expr, usize) {
    match stream.ops.get(start) {
        Some(CanonicalOp::StoreFast(slot)) => (
            local_target(nested, *slot, start).unwrap_or_else(|_| placeholder_target()),
            start + 1,
        ),
        Some(CanonicalOp::StoreFastLoadFast(slot, _)) => (
            local_target(nested, *slot, start).unwrap_or_else(|_| placeholder_target()),
            start,
        ),
        Some(CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot)) => (
            name_at(&nested.names, *slot, start, "name").map_or_else(
                |_| placeholder_target(),
                |id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                },
            ),
            start + 1,
        ),
        Some(CanonicalOp::UnpackSequence(n)) => {
            let count: usize = *n as usize;
            let Some((targets, skip)): Option<(Vec<Expr>, usize)> =
                collect_unpack_targets(nested, &stream.ops, start + 1, count)
            else {
                return (placeholder_target(), start + 1);
            };
            (
                Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                },
                start + 1 + skip,
            )
        }
        Some(CanonicalOp::UnpackEx(_)) => {
            let (tgt, next): (Expr, usize) =
                recover_tuple_target(nested, stream, start + 1, stream.ops.len());
            (tgt, next)
        }
        _ => (placeholder_target(), start + 1),
    }
}

/// The inner generator's iterable expression: the residual produced between the previous clause and
/// this loop's `GET_ITER`/`FOR_ITER`.
fn comp_inner_iter(
    nested: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    for_iter: usize,
) -> Expr {
    let get_iter: usize = (lo..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(for_iter);
    let expr_lo: usize = (lo..get_iter)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(lo, |b: usize| b + 1);
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(nested, slice_clamped(&stream.ops, expr_lo, get_iter))
            .unwrap_or_default();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

/// Bounds-safe op-slice: returns an empty slice when `lo >= hi` or either bound is out of range,
/// avoiding panics from comprehension clause boundaries that can momentarily invert.
fn slice_clamped(ops: &[CanonicalOp], lo: usize, hi: usize) -> &[CanonicalOp] {
    let hi: usize = hi.min(ops.len());
    let lo: usize = lo.min(hi);
    &ops[lo..hi]
}

/// Filter conditions (`if`) guarding a comprehension clause body, recovered from the conditional
/// jumps between the loop target and the next clause. A pre-3.8 `async for` lays its
/// `StopAsyncIteration` exhaustion poll-guard
/// (`DUP_TOP / LOAD_GLOBAL StopAsyncIteration / COMPARE_OP(exception match) / POP_JUMP_IF_*`) inline
/// in this same range; that `exception match` jump is loop-termination machinery with no surface
/// comprehension syntax, so it is detected via `is_exc_match_compare` and skipped rather than leaked
/// as a bogus `if … exception matches …` filter - mirroring the statement-level async-for guard skip
/// and the `extract_comprehension_parts` path.
fn comp_clause_filters(
    nested: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Vec<Expr> {
    let mut ifs: Vec<Expr> = Vec::new();
    let mut i: usize = lo;
    while i < hi {
        if matches!(
            stream.ops[i],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) {
            let expr_lo: usize = cond_expr_start(stream, i, lo);
            let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                build_linear_stmts_sim(nested, slice_clamped(&stream.ops, expr_lo, i))
                    .unwrap_or_default();
            if let Some(cond) = residual.into_iter().next_back() {
                if is_exc_match_compare(&cond) {
                    i += 1;
                    continue;
                }
                ifs.push(comp_filter_expr(stream, i, cond));
            }
        }
        i += 1;
    }
    ifs
}

/// Build one comprehension `if` clause from its guarding conditional jump. A `None`-fused guard
/// (`POP_JUMP_IF_NONE`/`POP_JUMP_IF_NOT_NONE`, which canonicalize to `PopJumpIf{True,False}` and
/// carry their `is`/`is not None` semantics only in `stream.none_jump_kind`) reconstructs the
/// `value is None` / `value is not None` compare. `none_jump_kind` encodes the test that holds on
/// fall-through (jump not taken); when the jump targets the skip path the element is kept on
/// fall-through, so the test is used as-is, otherwise it is flipped (`is`↔`is not`, never
/// `not`-wrapped, to stay byte-identical on recompile). A plain truthiness guard keeps `cond` (or
/// `not cond`) per `filter_keeps_when_true`.
fn comp_filter_expr(stream: &DecodedStream, cond_idx: usize, cond: Expr) -> Expr {
    if let Some(none_kind) = stream.none_jump_kind.get(&cond_idx).copied() {
        let kept_kind: NoneJumpKind = if filter_jump_target_is_skip(stream, cond_idx) {
            none_kind
        } else {
            match none_kind {
                NoneJumpKind::IsNone => NoneJumpKind::IsNotNone,
                NoneJumpKind::IsNotNone => NoneJumpKind::IsNone,
            }
        };
        let op: CmpOp = match kept_kind {
            NoneJumpKind::IsNone => CmpOp::Is,
            NoneJumpKind::IsNotNone => CmpOp::IsNot,
        };
        return Expr::Compare {
            left: Box::new(cond),
            ops: vec![op],
            comparators: vec![Expr::Constant {
                value: ConstValue::None,
                line: None,
            }],
        };
    }
    if filter_keeps_when_true(stream, cond_idx) {
        cond
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(cond),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompKind {
    List,
    Set,
    Dict,
    Gen,
}

#[derive(Debug, Clone)]
struct ComprehensionParts {
    target: Expr,
    elt: Expr,
    key_value: Option<(Expr, Expr)>,
    ifs: Vec<Expr>,
}

/// 3.6/3.7 async comprehensions guard each `async for` step with a `SETUP_EXCEPT` whose handler
/// does `DUP_TOP / LOAD_GLOBAL StopAsyncIteration / COMPARE_OP(exception match) / POP_JUMP_IF_TRUE`
/// to break the loop on exhaustion. That `exception match` compare is loop-termination machinery,
/// never a user filter, and Python has no surface syntax for it inside a comprehension, so it must
/// not leak into the `if` clauses.
fn is_exc_match_compare(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Compare { ops, .. }
            if ops.iter().any(|c: &crate::bytecode::opcode::CmpOp| {
                matches!(c, crate::bytecode::opcode::CmpOp::ExcMatch)
            })
    )
}

#[allow(clippy::match_same_arms)]
fn extract_comprehension_parts(
    nested: &CodeObject,
    ops: &[CanonicalOp],
    kind: CompKind,
) -> ComprehensionParts {
    let mut sim: StackSim = StackSim::new();
    let mut target: Option<Expr> = None;
    let mut elt: Option<Expr> = None;
    let mut key_value: Option<(Expr, Expr)> = None;
    let mut ifs: Vec<Expr> = Vec::new();
    let mut seen_target: bool = false;
    let mut pending_unpack: u32 = 0;
    let mut tuple_targets: Vec<Expr> = Vec::new();
    let mut idx: usize = 0;
    while idx < ops.len() {
        let op: &CanonicalOp = &ops[idx];
        match op {
            CanonicalOp::UnpackSequence(n) if !seen_target => {
                pending_unpack = *n;
                tuple_targets.clear();
                idx += 1;
                continue;
            }
            CanonicalOp::UnpackEx(_) if !seen_target => {
                pending_unpack = 0;
                tuple_targets.clear();
                idx += 1;
                continue;
            }
            _ => {}
        }
        match op {
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
                if seen_target && elt.is_none() =>
            {
                if let Some(cond) = sim.try_pop() {
                    if is_exc_match_compare(&cond) {
                        idx += 1;
                        continue;
                    }
                    let cond: Expr = if matches!(
                        op,
                        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
                    ) {
                        Expr::UnaryOp {
                            op: crate::bytecode::opcode::UnaryOp::Not,
                            operand: Box::new(cond),
                        }
                    } else {
                        cond
                    };
                    ifs.push(cond);
                }
            }
            CanonicalOp::Compare(cmp) => {
                let right: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                let left: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                sim.push(Expr::Compare {
                    left: Box::new(left),
                    ops: vec![*cmp],
                    comparators: vec![right],
                });
            }
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadSmallInt(value) => sim.push(Expr::Constant {
                value: ConstValue::Int(i128::from(*value)),
                line: None,
            }),
            CanonicalOp::LoadCommonConst(slot) => sim.push(load_common_constant(*slot)),
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(e) = load_name(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadAttr(i) => {
                let value: Expr = sim.pop_or_synth(nested, idx);
                let attr: String =
                    name_at_either(nested, *i).unwrap_or_else(|_| format!("attr_{i}"));
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(nested, idx);
                let value: Expr = sim.pop_or_synth(nested, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::Push(_) if is_await_null_slot(ops, idx) => {}
            CanonicalOp::Push(_) => sim.push(Expr::Name {
                id: DR_NULL_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::BuildString(n) => {
                let mut parts: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    parts.insert(0, sim.pop_or_synth(nested, idx));
                }
                sim.push(Expr::JoinedStr {
                    values: parts,
                    line: None,
                });
            }
            CanonicalOp::FormatValue(flags) => {
                let has_spec: bool = (flags & 0x04) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(nested, idx)))
                } else {
                    None
                };
                let value: Expr = sim.pop_or_synth(nested, idx);
                let conversion: FormatConversion = match flags & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec,
                    line: None,
                });
            }
            CanonicalOp::ConvertValue(flags) => {
                let value: Expr = sim.pop_or_synth(nested, idx);
                let conversion: FormatConversion = match flags & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec: None,
                    line: None,
                });
            }
            CanonicalOp::FormatSimple => {
                let value: Expr = sim.pop_or_synth(nested, idx);
                match value {
                    Expr::FormattedValue {
                        format_spec: None, ..
                    } => sim.push(value),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: None,
                        line: None,
                    }),
                }
            }
            CanonicalOp::FormatWithSpec => {
                let spec: Expr = sim.pop_or_synth(nested, idx);
                let value: Expr = sim.pop_or_synth(nested, idx);
                match value {
                    Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: None,
                        line,
                    } => sim.push(Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: Some(Box::new(spec)),
                        line,
                    }),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: Some(Box::new(spec)),
                        line: None,
                    }),
                }
            }
            CanonicalOp::LoadFast(i) => {
                if let Ok(name) = local_name_at(nested, *i, idx)
                    && name != ".0"
                {
                    sim.push(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                if let Ok(e) = load_local(nested, *a, idx) {
                    sim.push(e);
                }
                if let Ok(e) = load_local(nested, *b, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::StoreFastLoadFast(t, r) => {
                if target.is_none()
                    && let Ok(name) = local_name_at(nested, *t, idx)
                    && name != ".0"
                {
                    target = Some(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    seen_target = true;
                }
                let _ = sim.try_pop();
                if let Ok(e) = load_local(nested, *r, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if target.is_none()
                    && let (Ok(name_a), Ok(name_b)) = (
                        local_name_at(nested, *a, idx),
                        local_name_at(nested, *b, idx),
                    )
                {
                    target = Some(Expr::Tuple {
                        elts: vec![
                            Expr::Name {
                                id: name_a,
                                ctx: ExprCtx::Store,
                                line: None,
                            },
                            Expr::Name {
                                id: name_b,
                                ctx: ExprCtx::Store,
                                line: None,
                            },
                        ],
                        ctx: ExprCtx::Store,
                    });
                    seen_target = true;
                }
                let _ = sim.try_pop();
                let _ = sim.try_pop();
            }
            CanonicalOp::StoreFast(i) => {
                if pending_unpack > 0
                    && let Ok(name) = local_name_at(nested, *i, idx)
                {
                    tuple_targets.push(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    pending_unpack -= 1;
                    if pending_unpack == 0 {
                        target = Some(Expr::Tuple {
                            elts: std::mem::take(&mut tuple_targets),
                            ctx: ExprCtx::Store,
                        });
                        seen_target = true;
                    }
                    idx += 1;
                    continue;
                }
                if seen_target
                    && is_walrus_store_shape(ops, idx)
                    && let Ok(name) = local_name_at(nested, *i, idx)
                {
                    let _dup: Option<Expr> = sim.try_pop();
                    let underlying: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    });
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    idx += 1;
                    continue;
                }
                if target.is_none()
                    && let Ok(name) = local_name_at(nested, *i, idx)
                    && name != ".0"
                {
                    target = Some(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    seen_target = true;
                }
                let _ = sim.try_pop();
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                let left: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::MakeFunction(_) | CanonicalOp::MakeFunctionLegacy(_) => {
                let top: Option<Expr> = sim.try_pop();
                match top {
                    Some(t) if nested_code_index(&t).is_some() => sim.push(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => sim.push(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                            }
                        }
                    }
                    None => {}
                }
            }
            CanonicalOp::Dup => {
                if let Some(top) = sim.peek_clone() {
                    sim.push(top);
                }
            }
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::GetIter
            | CanonicalOp::GetAiter
            | CanonicalOp::Send(_)
            | CanonicalOp::EndSend
            | CanonicalOp::Resume(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_) => {}
            CanonicalOp::GetAwaitable => {
                if let Some(value) = sim.try_pop() {
                    sim.push(Expr::Await(Box::new(value)));
                }
            }
            CanonicalOp::YieldFrom => {
                let top: Option<Expr> = sim.try_pop();
                let top_is_none: bool = matches!(
                    top,
                    Some(Expr::Constant {
                        value: ConstValue::None,
                        ..
                    })
                );
                if !top_is_none && let Some(value) = top {
                    sim.push(value);
                }
            }
            CanonicalOp::CallFunction(argc) => {
                let mut args: Vec<Expr> = Vec::with_capacity(usize::from(*argc));
                for _ in 0..*argc {
                    args.insert(0, sim.pop_or_synth(nested, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(nested, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                if let Some(inner) = try_build_comprehension_expr(nested, &func, &args) {
                    sim.push(inner);
                } else {
                    sim.push(Expr::Call {
                        func: Box::new(func),
                        args,
                        keywords: Vec::new(),
                    });
                }
            }
            CanonicalOp::CallFunctionKw(argc) => {
                let kw_names_expr: Expr = sim.pop_or_synth(nested, idx);
                let kw_names: Vec<String> = decode_kw_names(&kw_names_expr)
                    .or_else(|| extract_tuple_of_strings(&kw_names_expr))
                    .unwrap_or_default();
                let total: usize = usize::from(*argc);
                let kw_count: usize = kw_names.len().min(total);
                let pos_count: usize = total - kw_count;
                let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                for _ in 0..kw_count {
                    kw_values.insert(0, sim.pop_or_synth(nested, idx));
                }
                let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                for _ in 0..pos_count {
                    args.insert(0, sim.pop_or_synth(nested, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(nested, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                let keywords: Vec<crate::ast::node::Keyword> = kw_names
                    .into_iter()
                    .zip(kw_values)
                    .map(|(name, value): (String, Expr)| crate::ast::node::Keyword {
                        arg: Some(name),
                        value,
                    })
                    .collect();
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords,
                });
            }
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                if elt.is_none()
                    && let Some(e) = sim.try_pop()
                {
                    elt = Some(e);
                }
                break;
            }
            CanonicalOp::MapAdd => {
                if matches!(kind, CompKind::Dict) {
                    let pre38_order: bool = active_version()
                        .is_some_and(|v: PyVersion| v.major() == 3 && v.minor() < 8);
                    let top: Option<Expr> = sim.try_pop();
                    let below: Option<Expr> = sim.try_pop();
                    let (k, v): (Option<Expr>, Option<Expr>) = if pre38_order {
                        (top, below)
                    } else {
                        (below, top)
                    };
                    if let (Some(kk), Some(vv)) = (k, v) {
                        elt = Some(kk.clone());
                        key_value = Some((kk, vv));
                    }
                }
                break;
            }
            CanonicalOp::Yield => {
                let top_is_none: bool = matches!(
                    sim.peek_clone(),
                    Some(Expr::Constant {
                        value: ConstValue::None,
                        ..
                    })
                );
                if top_is_none {
                    let _ = sim.try_pop();
                    idx += 1;
                    continue;
                }
                if matches!(kind, CompKind::Gen)
                    && elt.is_none()
                    && let Some(e) = sim.try_pop()
                {
                    elt = Some(e);
                }
                break;
            }
            _ => {}
        }
        idx += 1;
    }
    let target_final: Expr = target.unwrap_or_else(|| Expr::Name {
        id: "_".to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    });
    let elt_final: Expr = elt.unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    ComprehensionParts {
        target: target_final,
        elt: elt_final,
        key_value,
        ifs,
    }
}

thread_local! {
    static ACTIVE_VERSION: std::cell::RefCell<Option<PyVersion>> =
        const { std::cell::RefCell::new(None) };
    static LOOP_FRAMES: std::cell::RefCell<Vec<LoopFrame>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FUTURE_ANNOTATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `co_flags` bit set when a module compiled under `from __future__ import annotations` (PEP 563): all
/// annotation expressions are stringified into `str` consts. Only then may a string-const annotation be
/// un-stringified back to its source `Expr`; without it a quoted annotation (`-> "Color"`) is a genuine
/// string literal and must stay quoted, or the recompiled `MAKE_FUNCTION` gains a spurious name load.
const CO_FUTURE_ANNOTATIONS: i32 = 0x0100_0000;

fn set_future_annotations(flags: i32) {
    FUTURE_ANNOTATIONS.with(|slot: &std::cell::Cell<bool>| {
        slot.set(flags & CO_FUTURE_ANNOTATIONS != 0);
    });
}

fn future_annotations_active() -> bool {
    FUTURE_ANNOTATIONS.with(std::cell::Cell::get)
}

#[derive(Debug, Clone)]
struct LoopFrame {
    header: usize,
    exit: usize,
    /// The value the loop's shared exit returns (`return X` after the loop), when the post-loop tail
    /// is a single return. Used to confirm that an in-body `return X` whose bytecode leads with the
    /// iterator pop is the peephole-folded `break` to this shared exit, not an unrelated return.
    exit_return: Option<Expr>,
}

fn push_loop_frame(frame: LoopFrame) {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow_mut().push(frame));
}

fn pop_loop_frame() {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        let _ = slot.borrow_mut().pop();
    });
}

fn loop_break_target() -> Option<usize> {
    LOOP_FRAMES
        .with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().last().map(|f| f.exit))
}

fn loop_continue_target() -> Option<usize> {
    LOOP_FRAMES
        .with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().last().map(|f| f.header))
}

fn loop_exit_return() -> Option<Expr> {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        slot.borrow()
            .last()
            .and_then(|f: &LoopFrame| f.exit_return.clone())
    })
}

fn loop_frame_depth() -> usize {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().len())
}

fn set_active_version(version: &PyVersion) {
    ACTIVE_VERSION.with(|slot: &std::cell::RefCell<Option<PyVersion>>| {
        *slot.borrow_mut() = Some(version.clone());
    });
}

fn active_version() -> Option<PyVersion> {
    ACTIVE_VERSION.with(|slot: &std::cell::RefCell<Option<PyVersion>>| slot.borrow().clone())
}

fn pre_36_build_class_bases_reversed() -> bool {
    active_version().is_some_and(|v: PyVersion| v.major() == 3 && v.minor() < 6)
}

fn pick_nested_version(code: &CodeObject) -> PyVersion {
    use disrobe_py_marshal::CodeEra;
    if let Some(active) = active_version() {
        let matches_era: bool = match code.era {
            CodeEra::Py10to12 => active.major() == 1 && active.minor() <= 2,
            CodeEra::Py13to14 => active.major() == 1 && (3..=4).contains(&active.minor()),
            CodeEra::Py15to20 => {
                (active.major() == 1 && active.minor() >= 5)
                    || (active.major() == 2 && active.minor() == 0)
            }
            CodeEra::Py21to22 => active.major() == 2 && (1..=2).contains(&active.minor()),
            CodeEra::Py27 => active.major() == 2 && active.minor() >= 3,
            CodeEra::Py30to37 => active.major() == 3 && active.minor() <= 7,
            CodeEra::Py38to310 => {
                active.major() == 3 && active.minor() >= 8 && active.minor() <= 10
            }
            CodeEra::Py311Plus => active.major() > 3 || active.minor() >= 11,
        };
        if matches_era {
            return active;
        }
    }
    match code.era {
        CodeEra::Py10to12 => PyVersion::V1_1,
        CodeEra::Py13to14 => PyVersion::V1_4,
        CodeEra::Py15to20 => PyVersion::V1_5,
        CodeEra::Py21to22 => PyVersion::V2_1,
        CodeEra::Py27 => PyVersion::V2_7,
        CodeEra::Py30to37 => PyVersion::V3_7,
        CodeEra::Py38to310 => PyVersion::V3_10,
        CodeEra::Py311Plus => PyVersion::V3_14,
    }
}

fn load_name(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = name_at(&code.names, idx, offset, "name")?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Load,
        line: None,
    })
}

fn load_common_constant(slot: u8) -> Expr {
    let const_value: Option<ConstValue> = match slot {
        7 => Some(ConstValue::None),
        8 => Some(ConstValue::Str(String::new())),
        9 => Some(ConstValue::True),
        10 => Some(ConstValue::False),
        11 => Some(ConstValue::Int(-1)),
        _ => None,
    };
    if let Some(value) = const_value {
        return Expr::Constant { value, line: None };
    }
    let id: &'static str = match slot {
        0 => "AssertionError",
        1 => "NotImplementedError",
        2 => "tuple",
        3 => "all",
        4 => "any",
        5 => "list",
        6 => "set",
        _ => "None",
    };
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn local_name_at(code: &CodeObject, idx: u32, offset: usize) -> Result<String> {
    if is_deref_local(idx) {
        let payload: u32 = deref_local_payload(idx);
        let cell_len: u32 = u32::try_from(code.cellvars.len()).unwrap_or(0);
        if !code.cellvars.is_empty()
            && payload < cell_len
            && let Ok(s) = name_at(&code.cellvars, payload, offset, "cellvar")
        {
            return Ok(s);
        }
        if !code.freevars.is_empty() {
            let free_idx: u32 = payload.saturating_sub(cell_len);
            if let Ok(s) = name_at(&code.freevars, free_idx, offset, "freevar") {
                return Ok(s);
            }
        }
        if !code.localsplusnames.is_empty()
            && let Ok(s) = name_at(&code.localsplusnames, payload, offset, "localsplus")
        {
            return Ok(s);
        }
        return Err(DecompileError::AstDesync {
            offset,
            reason: format!("deref index {payload} out of range"),
        });
    }
    if !code.varnames.is_empty()
        && let Ok(s) = name_at(&code.varnames, idx, offset, "varname")
    {
        return Ok(s);
    }
    if !code.localsplusnames.is_empty()
        && let Ok(s) = name_at(&code.localsplusnames, idx, offset, "localsplus")
    {
        return Ok(s);
    }
    Err(DecompileError::AstDesync {
        offset,
        reason: format!("local index {idx} out of range"),
    })
}

fn load_local(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = local_name_at(code, idx, offset)?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Load,
        line: None,
    })
}

fn local_target(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = local_name_at(code, idx, offset)?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Store,
        line: None,
    })
}

fn name_at(pool: &[Object], idx: u32, offset: usize, kind: &'static str) -> Result<String> {
    let obj: &Object = pool
        .get(idx as usize)
        .ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("{kind} index {idx} out of range"),
        })?;
    match obj {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Ok(value.clone()),
        other => Err(DecompileError::AstDesync {
            offset,
            reason: format!("{kind} pool slot {idx} is not a string: {other:?}"),
        }),
    }
}

fn const_string_tuple(code: &CodeObject, idx: u32) -> Option<Vec<String>> {
    match code.consts.get(idx as usize)? {
        Object::Tuple(items) => items
            .iter()
            .map(|obj: &Object| match obj {
                Object::String { value, .. } | Object::ShortAscii { value, .. } => {
                    Some(value.clone())
                }
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn object_to_const(obj: &Object) -> ConstValue {
    match obj {
        Object::Ellipsis => ConstValue::Ellipsis,
        Object::True => ConstValue::True,
        Object::False => ConstValue::False,
        Object::Int(i) => ConstValue::Int(i128::from(*i)),
        Object::Int64(i) => ConstValue::Int(i128::from(*i)),
        Object::Long(bi) => ConstValue::BigInt(crate::ast::node::BigUint {
            sign: bi.sign,
            digits: bi.digits.clone(),
        }),
        Object::Float(f) => ConstValue::Float(*f),
        Object::Complex { real, imag } => ConstValue::Complex {
            real: *real,
            imag: *imag,
        },
        Object::String { value, .. } | Object::ShortAscii { value, .. } => {
            ConstValue::Str(value.clone())
        }
        Object::Unicode { value, .. } => ConstValue::Unicode(value.clone()),
        Object::Bytes(b) => ConstValue::Bytes(b.clone()),
        Object::Tuple(items) => ConstValue::Tuple(items.iter().map(object_to_const).collect()),
        Object::FrozenSet(items) => {
            ConstValue::Frozenset(items.iter().map(object_to_const).collect())
        }
        Object::None
        | Object::StopIteration
        | Object::Dict(_)
        | Object::List(_)
        | Object::Set(_)
        | Object::FrozenDict(_)
        | Object::Code(_)
        | Object::Ref(_)
        | Object::Null => ConstValue::None,
    }
}
