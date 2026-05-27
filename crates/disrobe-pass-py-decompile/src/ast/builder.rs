use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{
    Alias, Arguments, AstModule, Comprehension, ConstValue, ExceptHandler, Expr, ExprCtx,
    FormatConversion, MatchCase, Pattern, Stmt, WithItem,
};
use crate::bytecode::opcode::{CanonicalOp, OpcodeMap, map_for};
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
        let opmap: Box<dyn OpcodeMap> = map_for(version.clone());
        let ops: Vec<CanonicalOp> = decode_stream(code, opmap.as_ref(), version);
        let raw_body: Vec<Stmt> = build_frame(code, &frame_tree.root, &ops)?;
        let stripped: Vec<Stmt> =
            strip_module_implicit_return(strip_module_docstring_stmt(raw_body, code));
        let body: Vec<Stmt> = postprocess_body(stripped, BodyKind::Module);
        Ok(AstModule {
            docstring: extract_docstring(code),
            body,
            blank_lines: std::collections::BTreeMap::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Module,
    Function,
    Class,
}

fn postprocess_body(body: Vec<Stmt>, kind: BodyKind) -> Vec<Stmt> {
    let merged: Vec<Stmt> = merge_annotations(body);
    let pruned: Vec<Stmt> = match kind {
        BodyKind::Function => prune_after_first_terminator(merged),
        _ => merged,
    };
    fix_nested_bodies(pruned, kind)
}

fn fix_nested_bodies(body: Vec<Stmt>, parent_kind: BodyKind) -> Vec<Stmt> {
    body.into_iter()
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
            && let Expr::Constant {
                value: ConstValue::Str(annotation_str),
                ..
            } = value
        {
            let annotation_expr: Expr = parse_annotation_string(annotation_str);
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
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
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

fn strip_module_implicit_return(mut body: Vec<Stmt>) -> Vec<Stmt> {
    while matches!(
        body.last(),
        Some(Stmt::Return(
            None | Some(Expr::Constant {
                value: ConstValue::None,
                ..
            })
        ))
    ) {
        body.pop();
    }
    body
}

fn strip_module_docstring_stmt(mut body: Vec<Stmt>, code: &CodeObject) -> Vec<Stmt> {
    let Some(doc) = extract_docstring(code) else {
        return body;
    };
    if let Some(Stmt::Expr(Expr::Constant {
        value: ConstValue::Str(s),
        ..
    })) = body.first()
        && s == &doc
    {
        body.remove(0);
    }
    body.retain(|s: &Stmt| !is_doc_assign(s, &doc));
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

fn extract_docstring(code: &CodeObject) -> Option<String> {
    match code.consts.first()? {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn decode_stream(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> Vec<CanonicalOp> {
    let mut out: Vec<CanonicalOp> = Vec::new();
    if version.supports_word_code() {
        decode_wordcode(code, opmap, &mut out);
    } else {
        decode_legacy(code, opmap, &mut out);
    }
    out
}

const LEGACY_HAVE_ARGUMENT: u8 = 90;
const WIDE_STEP: usize = 2;
const NARROW_STEP: usize = 1;
const EXTENDED_ARG_OP: u8 = 144;

fn decode_wordcode(code: &CodeObject, opmap: &dyn OpcodeMap, out: &mut Vec<CanonicalOp>) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    let mut extended: u32 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if raw == EXTENDED_ARG_OP {
            extended = (extended | u32::from(arg_byte)) << 8;
            cursor += WIDE_STEP;
            continue;
        }
        let arg: u32 = extended | u32::from(arg_byte);
        extended = 0;
        out.push(opmap.decode(raw, arg));
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
    let name: String = code_name(code);
    let is_async: bool = (code.flags & PY_CO_FLAG_COROUTINE) != 0;
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
        docstring: extract_docstring(code),
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
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::With {
        items,
        body,
        is_async,
        line: frame.line,
    })
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
const PY_CO_FLAG_COROUTINE: i32 = 0x0100;

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
                if let Ok(id) = name_at(&code.varnames, *i, 0, "varname")
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
    items
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
                if let Ok(id) = name_at(&code.varnames, *i, 0, "varname") {
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

fn name_at_either(code: &CodeObject, idx: u32) -> Result<String> {
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
fn build_linear_stmts(code: &CodeObject, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    let mut sim: StackSim = StackSim::new();
    let mut out: Vec<Stmt> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::Resume(_) => {}
            CanonicalOp::LoadConst(i) => sim.push(load_const(code, *i, idx)?),
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                sim.push(load_name(code, *i, idx)?);
            }
            CanonicalOp::LoadFast(i) => sim.push(load_local(code, *i, idx)?),
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
                let top: Option<Expr> = sim.try_pop();
                let (module, level): (Option<String>, u32) = top.map_or((None, 0), |t: Expr| {
                    if let Some(m) = decode_import_module_marker(&t) {
                        (Some(m.module), m.level)
                    } else if let Some((mod_name, lvl)) = decode_import_fromset_marker(&t) {
                        (Some(mod_name), lvl)
                    } else {
                        (None, 0)
                    }
                });
                out.push(Stmt::ImportFrom {
                    module,
                    names: vec![Alias {
                        name: "*".to_owned(),
                        asname: None,
                    }],
                    level,
                    line: None,
                });
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
                sim.push(Expr::Compare {
                    left: Box::new(left),
                    ops: vec![*cmp],
                    comparators: vec![right],
                });
            }
            CanonicalOp::CallFunction(argc) => {
                let mut args: Vec<Expr> = Vec::with_capacity(usize::from(*argc));
                for _ in 0..*argc {
                    args.insert(0, sim.pop_or_synth(code, idx));
                }
                let func: Expr = sim.pop_or_synth(code, idx);
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
                let func: Expr = sim.pop_or_synth(code, idx);
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
            CanonicalOp::CallFunctionEx(has_kw) => {
                if *has_kw {
                    let _kwargs: Expr = sim.pop_or_synth(code, idx);
                }
                let _args: Expr = sim.pop_or_synth(code, idx);
                let func: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args: Vec::new(),
                    keywords: Vec::new(),
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
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(*n as usize);
                let mut values: Vec<Expr> = Vec::with_capacity(*n as usize);
                for _ in 0..*n {
                    let v: Expr = sim.pop_or_synth(code, idx);
                    let k: Expr = sim.pop_or_synth(code, idx);
                    values.insert(0, v);
                    keys.insert(0, Some(k));
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
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                let step: Option<Expr> = if *n == 3 {
                    Some(sim.pop_or_synth(code, idx))
                } else {
                    None
                };
                sim.push(Expr::Slice {
                    lower: Some(Box::new(lower)),
                    upper: Some(Box::new(upper)),
                    step: step.map(Box::new),
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
            CanonicalOp::GetIter
            | CanonicalOp::GetAiter
            | CanonicalOp::GetAnext
            | CanonicalOp::ToBool => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(value);
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
            CanonicalOp::Swap(_) => {}
            CanonicalOp::Push(_) => sim.push(Expr::Constant {
                value: ConstValue::None,
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
            CanonicalOp::MakeFunction(_) => {
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
                    sim.push(marker);
                }
            }
            CanonicalOp::MakeCell(_)
            | CanonicalOp::ReturnGenerator
            | CanonicalOp::BeforeAsyncWith
            | CanonicalOp::SetupAsyncWith
            | CanonicalOp::AsyncForLoop
            | CanonicalOp::AsyncWithExitStart
            | CanonicalOp::AsyncWithExitFinish
            | CanonicalOp::PushExcInfo
            | CanonicalOp::PopExcept
            | CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::CleanupThrow
            | CanonicalOp::WithExceptStart
            | CanonicalOp::BeforeWith
            | CanonicalOp::MatchClass(_)
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchKeys
            | CanonicalOp::GetLen
            | CanonicalOp::EndAsyncFor
            | CanonicalOp::EndSend => {}
            CanonicalOp::Pop => {
                if let Some(value) = sim.try_pop() {
                    if decode_import_fromset_marker(&value).is_some()
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
            CanonicalOp::Return => {
                let value: Option<Expr> = sim.try_pop();
                out.push(Stmt::Return(value));
            }
            CanonicalOp::ReturnConst(i) => {
                let value: Expr = load_const(code, *i, idx)?;
                out.push(Stmt::Return(Some(value)));
            }
            CanonicalOp::Yield => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Yield(Some(Box::new(value))));
            }
            CanonicalOp::YieldFrom => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let expr: Expr = Expr::YieldFrom(Box::new(value));
                sim.push(expr);
            }
            CanonicalOp::StoreGlobal(i) | CanonicalOp::StoreName(i) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
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
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
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
                let value: Expr = sim.pop_or_synth(code, idx);
                let target_name: String = local_name_at(code, *i, idx)?;
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
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
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
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                let _value: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::MapAdd => {
                let _value: Expr = sim.pop_or_synth(code, idx);
                let _key: Expr = sim.pop_or_synth(code, idx);
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
            CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::ForIter(_)
            | CanonicalOp::Send(_) => {}
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => {
                let _condition: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::JumpIfTrueOrPop(_) | CanonicalOp::JumpIfFalseOrPop(_) => {
                let _condition: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::Specialized(_) | CanonicalOp::Other(_, _) => {}
        }
    }
    Ok(out)
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

    fn pop_or_synth(&mut self, code: &CodeObject, idx: usize) -> Expr {
        let _: (&CodeObject, usize) = (code, idx);
        self.stack.pop().unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        })
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
const DR_KW_NAMES_PREFIX: &str = "__DR_KW_NAMES__\u{0}";

fn is_build_class_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_BUILD_CLASS_MARKER)
}

fn is_assertion_error_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_ASSERTION_ERROR_MARKER)
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
    let bases: Vec<Expr> = args.iter().skip(2).cloned().collect();
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let nested_ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let body_raw: Vec<Stmt> = build_linear_stmts(nested, &nested_ops).unwrap_or_default();
    let stripped: Vec<Stmt> = strip_class_implicit(strip_module_implicit_return(
        strip_module_docstring_stmt(body_raw, nested),
    ));
    let processed: Vec<Stmt> = postprocess_body(stripped, BodyKind::Class);
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
        docstring: extract_docstring(nested),
        line: None,
    })
}

fn strip_class_implicit(mut body: Vec<Stmt>) -> Vec<Stmt> {
    body.retain(|s: &Stmt| !is_class_setup_assign(s));
    body
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
            | "__firstlineno__"
            | "__static_attributes__"
            | "__classcell__"
            | "__class__"
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

fn build_nested_function_def(
    parent: &CodeObject,
    const_idx: u32,
    target_name: String,
    is_async_default: bool,
) -> Option<Stmt> {
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let nested_ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let body_raw: Vec<Stmt> = build_linear_stmts(nested, &nested_ops).unwrap_or_default();
    let stripped: Vec<Stmt> =
        strip_module_implicit_return(strip_module_docstring_stmt(body_raw, nested));
    let processed: Vec<Stmt> = postprocess_body(stripped, BodyKind::Function);
    let final_body: Vec<Stmt> = if processed.is_empty() {
        vec![Stmt::Pass]
    } else {
        processed
    };
    let is_async: bool = is_async_default || (nested.flags & PY_CO_FLAG_COROUTINE) != 0;
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
    let nested_ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let (target, elt, key_value): (Expr, Expr, Option<(Expr, Expr)>) =
        extract_comprehension_parts(nested, &nested_ops, comp_kind);
    let comprehension: Comprehension = Comprehension {
        target,
        iter,
        ifs: Vec::new(),
        is_async: (nested.flags & PY_CO_FLAG_COROUTINE) != 0,
    };
    let result: Expr = match comp_kind {
        CompKind::List => Expr::ListComp {
            elt: Box::new(elt),
            generators: vec![comprehension],
        },
        CompKind::Set => Expr::SetComp {
            elt: Box::new(elt),
            generators: vec![comprehension],
        },
        CompKind::Gen => Expr::GeneratorExp {
            elt: Box::new(elt),
            generators: vec![comprehension],
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
                generators: vec![comprehension],
            }
        }
    };
    Some(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompKind {
    List,
    Set,
    Dict,
    Gen,
}

fn extract_comprehension_parts(
    nested: &CodeObject,
    ops: &[CanonicalOp],
    kind: CompKind,
) -> (Expr, Expr, Option<(Expr, Expr)>) {
    let mut sim: StackSim = StackSim::new();
    let mut target: Option<Expr> = None;
    let mut elt: Option<Expr> = None;
    let mut key_value: Option<(Expr, Expr)> = None;
    for (idx, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(e) = load_name(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFast(i) => {
                if let Ok(e) = load_local(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::StoreFast(i) => {
                if target.is_none()
                    && let Ok(name) = name_at(&nested.varnames, *i, idx, "varname")
                    && name != ".0"
                {
                    target = Some(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
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
                    let v: Option<Expr> = sim.try_pop();
                    let k: Option<Expr> = sim.try_pop();
                    if let (Some(kk), Some(vv)) = (k, v) {
                        elt = Some(kk.clone());
                        key_value = Some((kk, vv));
                    }
                }
                break;
            }
            CanonicalOp::Yield => {
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
    (target_final, elt_final, key_value)
}

fn pick_nested_version(code: &CodeObject) -> PyVersion {
    use disrobe_py_marshal::CodeEra;
    match code.era {
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

fn local_name_at(code: &CodeObject, idx: u32, offset: usize) -> Result<String> {
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
