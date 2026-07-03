use std::collections::BTreeMap;

use ruff_python_ast::{
    Expr, ExprAttribute, ExprName, Mod, ModModule, Stmt, StmtAssign, StmtFunctionDef,
};
use ruff_python_parser::{Mode, ParseOptions, parse};

use super::cipher::{CipherOp, apply_inverse};
use super::value::{ConstValue, eval_const};
use crate::codec::{b85_decode, zlib_decompress};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub(crate) struct LoaderPeel {
    pub(crate) marshal_blob: Vec<u8>,
    pub(crate) chain: Vec<CipherOp>,
}

#[derive(Debug, Clone)]
pub(crate) struct LazyBlob {
    pub(crate) key: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

pub(crate) fn extract_lazy_blobs(module: &ModModule) -> Vec<LazyBlob> {
    for stmt in &module.body {
        let Stmt::Assign(StmtAssign { targets, value, .. }): &Stmt = stmt else {
            continue;
        };
        let [Expr::Name(name)]: &[Expr] = targets.as_slice() else {
            continue;
        };
        if name.id.as_str() != "__pw_blobs" {
            continue;
        }
        let Some(ConstValue::Tuple(entries)): Option<ConstValue> = eval_const(value) else {
            return Vec::new();
        };
        let mut blobs: Vec<LazyBlob> = Vec::with_capacity(entries.len());
        for entry in entries {
            let ConstValue::Tuple(pair): ConstValue = entry else {
                return Vec::new();
            };
            let [ConstValue::Bytes(key), ConstValue::Bytes(ciphertext)]: &[ConstValue] =
                pair.as_slice()
            else {
                return Vec::new();
            };
            blobs.push(LazyBlob {
                key: key.clone(),
                ciphertext: ciphertext.clone(),
            });
        }
        return blobs;
    }
    Vec::new()
}

#[derive(Debug, Default, Clone)]
struct HelperClassification {
    perm_inv_fn: Option<String>,
    decoder_ops: BTreeMap<String, CipherOp>,
}

pub(crate) fn parse_module(source: &str) -> Result<ModModule> {
    let parsed: ruff_python_parser::Parsed<Mod> =
        parse(source, ParseOptions::from(Mode::Module))
            .map_err(|e| Error::AstCleanup(format!("ruff parse failed: {e}")))?;
    match parsed.into_syntax() {
        Mod::Module(m) => Ok(m),
        Mod::Expression(_) => Err(Error::AstCleanup(
            "expected module, got expression".to_owned(),
        )),
    }
}

pub(crate) fn classify_loader(module: &ModModule) -> Option<HelperClassificationResult> {
    let mut classification: HelperClassification = HelperClassification::default();
    for stmt in &module.body {
        let Stmt::FunctionDef(func): &Stmt = stmt else {
            continue;
        };
        let arg_count: usize = func.parameters.args.len();
        let dump: FunctionShape = inspect_function(func);
        if arg_count == 1 && dump.has_sha256 && dump.has_shuffle {
            classification.perm_inv_fn = Some(func.name.to_string());
        }
    }
    for stmt in &module.body {
        let Stmt::FunctionDef(func): &Stmt = stmt else {
            continue;
        };
        if func.parameters.args.len() != 2 {
            continue;
        }
        let dump: FunctionShape = inspect_function(func);
        if dump.has_zip && !dump.has_sha256 {
            classification
                .decoder_ops
                .insert(func.name.to_string(), CipherOp::Xor);
        } else if dump.has_lshift && dump.has_rshift && !dump.has_sha256 {
            classification
                .decoder_ops
                .insert(func.name.to_string(), CipherOp::Rot);
        } else if let Some(perm_inv) = classification.perm_inv_fn.as_ref()
            && dump.calls.contains(perm_inv)
        {
            classification
                .decoder_ops
                .insert(func.name.to_string(), CipherOp::Perm);
        }
    }
    if classification.decoder_ops.is_empty() {
        return None;
    }
    Some(HelperClassificationResult {
        decoder_ops: classification.decoder_ops,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct HelperClassificationResult {
    decoder_ops: BTreeMap<String, CipherOp>,
}

#[derive(Debug, Default)]
struct FunctionShape {
    has_sha256: bool,
    has_shuffle: bool,
    has_zip: bool,
    has_lshift: bool,
    has_rshift: bool,
    calls: Vec<String>,
}

fn inspect_function(func: &StmtFunctionDef) -> FunctionShape {
    let mut shape: FunctionShape = FunctionShape::default();
    for stmt in &func.body {
        inspect_stmt(stmt, &mut shape);
    }
    shape
}

fn inspect_stmt(stmt: &Stmt, shape: &mut FunctionShape) {
    match stmt {
        Stmt::Return(r) => {
            if let Some(v) = r.value.as_ref() {
                inspect_expr(v, shape);
            }
        }
        Stmt::Assign(a) => inspect_expr(&a.value, shape),
        Stmt::AugAssign(a) => inspect_expr(&a.value, shape),
        Stmt::Expr(e) => inspect_expr(&e.value, shape),
        Stmt::For(f) => {
            inspect_expr(&f.iter, shape);
            for s in &f.body {
                inspect_stmt(s, shape);
            }
        }
        Stmt::While(w) => {
            inspect_expr(&w.test, shape);
            for s in &w.body {
                inspect_stmt(s, shape);
            }
        }
        Stmt::If(i) => {
            inspect_expr(&i.test, shape);
            for s in &i.body {
                inspect_stmt(s, shape);
            }
            for clause in &i.elif_else_clauses {
                for s in &clause.body {
                    inspect_stmt(s, shape);
                }
            }
        }
        _ => {}
    }
}

fn inspect_expr(expr: &Expr, shape: &mut FunctionShape) {
    match expr {
        Expr::Call(call) => {
            collect_call_name(&call.func, shape);
            inspect_expr(&call.func, shape);
            for arg in &call.arguments.args {
                inspect_expr(arg, shape);
            }
            for kw in &call.arguments.keywords {
                inspect_expr(&kw.value, shape);
            }
        }
        Expr::Attribute(attr) => {
            if attr.attr.as_str() == "sha256" {
                shape.has_sha256 = true;
            }
            if attr.attr.as_str() == "shuffle" {
                shape.has_shuffle = true;
            }
            inspect_expr(&attr.value, shape);
        }
        Expr::Name(n) if n.id.as_str() == "zip" => {
            shape.has_zip = true;
        }
        Expr::BinOp(b) => {
            match b.op {
                ruff_python_ast::Operator::LShift => shape.has_lshift = true,
                ruff_python_ast::Operator::RShift => shape.has_rshift = true,
                _ => {}
            }
            inspect_expr(&b.left, shape);
            inspect_expr(&b.right, shape);
        }
        Expr::UnaryOp(u) => inspect_expr(&u.operand, shape),
        Expr::Subscript(s) => {
            inspect_expr(&s.value, shape);
            inspect_expr(&s.slice, shape);
        }
        Expr::Compare(c) => {
            inspect_expr(&c.left, shape);
            for cmp in &c.comparators {
                inspect_expr(cmp, shape);
            }
        }
        Expr::Generator(g) => {
            inspect_expr(&g.elt, shape);
            inspect_comprehensions(&g.generators, shape);
        }
        Expr::ListComp(g) => {
            inspect_expr(&g.elt, shape);
            inspect_comprehensions(&g.generators, shape);
        }
        Expr::SetComp(g) => {
            inspect_expr(&g.elt, shape);
            inspect_comprehensions(&g.generators, shape);
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                inspect_expr(e, shape);
            }
        }
        Expr::List(t) => {
            for e in &t.elts {
                inspect_expr(e, shape);
            }
        }
        Expr::BoolOp(b) => {
            for v in &b.values {
                inspect_expr(v, shape);
            }
        }
        _ => {}
    }
}

fn inspect_comprehensions(
    comprehensions: &[ruff_python_ast::Comprehension],
    shape: &mut FunctionShape,
) {
    for comp in comprehensions {
        inspect_expr(&comp.iter, shape);
        for cond in &comp.ifs {
            inspect_expr(cond, shape);
        }
    }
}

fn collect_call_name(func: &Expr, shape: &mut FunctionShape) {
    if let Expr::Name(ExprName { id, .. }) = func {
        shape.calls.push(id.to_string());
    }
}

pub(crate) fn peel_loader_source(source: &str) -> Result<LoaderPeel> {
    let module: ModModule = parse_module(source)?;
    let classification: HelperClassificationResult =
        classify_loader(&module).ok_or(Error::XorKeyMissing)?;

    let mut data_var: Option<String> = None;
    let mut payload: Option<Vec<u8>> = None;
    let mut chain: Vec<CipherOp> = Vec::new();
    let mut working: Vec<u8> = Vec::new();

    for stmt in &module.body {
        let Stmt::Assign(StmtAssign { targets, value, .. }): &Stmt = stmt else {
            continue;
        };
        let [Expr::Name(target)]: &[Expr] = targets.as_slice() else {
            continue;
        };
        let Expr::Call(call): &Expr = value else {
            continue;
        };

        if let Expr::Attribute(ExprAttribute { attr, .. }) = call.func.as_ref()
            && attr.as_str() == "b85decode"
            && let Some(arg) = call.arguments.args.first()
            && let Some(ConstValue::Bytes(encoded)) = eval_const(arg)
        {
            let decoded: Vec<u8> = b85_decode(&encoded)?;
            data_var = Some(target.id.to_string());
            working.clone_from(&decoded);
            payload = Some(decoded);
            continue;
        }

        let Some(active): Option<&String> = data_var.as_ref() else {
            continue;
        };
        if target.id.as_str() != active.as_str() {
            continue;
        }

        if let Expr::Name(ExprName { id, .. }) = call.func.as_ref()
            && let Some(&op) = classification.decoder_ops.get(id.as_str())
            && let Some(key_arg) = call.arguments.args.get(1)
            && let Some(ConstValue::Bytes(key)) = eval_const(key_arg)
        {
            working = apply_inverse(op, &working, &key);
            chain.push(op);
            continue;
        }

        if let Expr::Attribute(ExprAttribute {
            attr, value: inner, ..
        }) = call.func.as_ref()
            && attr.as_str() == "decompress"
            && matches!(inner.as_ref(), Expr::Name(_))
        {
            let inflated: Vec<u8> = zlib_decompress(&working)?;
            return Ok(LoaderPeel {
                marshal_blob: inflated,
                chain,
            });
        }
    }

    if payload.is_some()
        && !chain.is_empty()
        && let Ok(inflated) = zlib_decompress(&working)
    {
        return Ok(LoaderPeel {
            marshal_blob: inflated,
            chain,
        });
    }
    Err(Error::Marshal(
        "patchwork loader did not reduce to a marshal blob".to_owned(),
    ))
}
