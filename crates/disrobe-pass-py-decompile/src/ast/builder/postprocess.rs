use super::{extract_docstring, future_annotations_active};
use crate::ast::node::{ConstValue, ExceptHandler, Expr, ExprCtx, MatchCase, Stmt};
use disrobe_py_marshal::CodeObject;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyKind {
    Module,
    Function,
    Class,
}

pub(super) fn postprocess_body(body: Vec<Stmt>, kind: BodyKind) -> Vec<Stmt> {
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
        (
            Expr::BinOp {
                left: al,
                op: ao,
                right: ar,
            },
            Expr::BinOp {
                left: bl,
                op: bo,
                right: br,
            },
        ) => ao == bo && aug_targets_match(al, bl) && aug_targets_match(ar, br),
        (
            Expr::UnaryOp {
                op: ao,
                operand: aop,
            },
            Expr::UnaryOp {
                op: bo,
                operand: bop,
            },
        ) => ao == bo && aug_targets_match(aop, bop),
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

pub(super) fn strip_generator_stopiteration_raise(body: &mut Vec<Stmt>) {
    if matches!(
        body.last(),
        Some(Stmt::Raise {
            exc: None,
            cause: None,
            ..
        })
    ) {
        body.pop();
    }
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

pub(super) fn parse_annotation_string(s: &str) -> Expr {
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

pub(super) fn is_implicit_none_return(s: &Stmt) -> bool {
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

fn while_test_is_infinite(test: &Expr) -> bool {
    matches!(
        test,
        Expr::Constant {
            value: ConstValue::True,
            ..
        } | Expr::Constant {
            value: ConstValue::Int(1..),
            ..
        }
    )
}

fn prev_is_compound_if_returning(body: &[Stmt]) -> bool {
    let Some(prev): Option<&Stmt> = body.len().checked_sub(2).map(|i: usize| &body[i]) else {
        return false;
    };
    let Stmt::If {
        test,
        body: b,
        orelse,
        ..
    }: &Stmt = prev
    else {
        return false;
    };
    orelse.is_empty()
        && matches!(test, Expr::BoolOp { .. })
        && matches!(b.last(), Some(Stmt::Return(_)))
}

fn strip_trailing_implicit_return(body: &mut Vec<Stmt>) {
    while body.last().is_some_and(is_implicit_none_return) && !prev_is_compound_if_returning(body) {
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
        Some(Stmt::While { test, .. }) if while_test_is_infinite(test) => {}
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

pub(super) fn strip_module_implicit_return(mut body: Vec<Stmt>) -> Vec<Stmt> {
    strip_trailing_implicit_return(&mut body);
    body
}

pub(super) fn strip_module_scope_implicit_returns(body: &mut Vec<Stmt>) {
    body.retain(|s: &Stmt| !is_implicit_none_return(s));
    for stmt in body.iter_mut() {
        strip_module_scope_in_stmt(stmt);
    }
}

fn strip_module_scope_in_stmt(stmt: &mut Stmt) {
    match stmt {
        Stmt::If { body, orelse, .. }
        | Stmt::For { body, orelse, .. }
        | Stmt::While { body, orelse, .. } => {
            strip_module_scope_implicit_returns(body);
            strip_module_scope_implicit_returns(orelse);
        }
        Stmt::With { body, .. } => strip_module_scope_implicit_returns(body),
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            strip_module_scope_implicit_returns(body);
            for handler in handlers.iter_mut() {
                strip_module_scope_implicit_returns(&mut handler.body);
            }
            strip_module_scope_implicit_returns(orelse);
            strip_module_scope_implicit_returns(finalbody);
        }
        Stmt::Match { cases, .. } => {
            for case in cases.iter_mut() {
                strip_module_scope_implicit_returns(&mut case.body);
            }
        }
        _ => {}
    }
}

pub(super) fn strip_module_docstring_stmt(mut body: Vec<Stmt>, code: &CodeObject) -> Vec<Stmt> {
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
