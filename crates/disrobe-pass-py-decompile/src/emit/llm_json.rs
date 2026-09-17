#![allow(
    clippy::collapsible_match,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::too_many_lines,
    clippy::elidable_lifetime_names,
    clippy::cast_precision_loss,
    clippy::manual_checked_ops
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::ast::node::{
    Alias, Arg, Arguments, AstModule, ConstValue, ExceptHandler, Expr, ExprCtx, Stmt, TypeParam,
};
use crate::ast::visitor::{
    Visitor, walk_comprehension, walk_expr, walk_handler, walk_match_case, walk_pattern, walk_stmt,
};
use crate::bytecode::version::PyVersion;
use crate::codegen::{CodeEmitter, DefaultEmitter, format_string_literal};

pub const SCHEMA_ID: &str = "disrobe.python.decompile.llm.v1";

const PY_BUILTINS: &[&str] = &[
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BaseExceptionGroup",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "EncodingWarning",
    "EnvironmentError",
    "Exception",
    "ExceptionGroup",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "None",
    "NotADirectoryError",
    "NotImplemented",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "True",
    "False",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
    "__name__",
    "__file__",
    "__doc__",
    "__package__",
    "__loader__",
    "__spec__",
    "__builtins__",
    "__import__",
];

#[must_use]
pub fn build_llm_sidecar(module: &AstModule, version: &PyVersion, source: &str) -> Value {
    let mut imports_used: BTreeSet<String> = BTreeSet::new();
    let mut unresolved_externals: BTreeSet<String> = BTreeSet::new();
    let module_docstring: Option<String> = module.docstring.clone();
    let imports: Vec<Value> = collect_imports(&module.body, &mut imports_used);
    let module_vars: Vec<Value> = collect_module_vars(&module.body);
    let bound_at_module: BTreeSet<String> = module_bound_names(&module.body, &imports_used);
    let functions: Vec<Value> = collect_functions(&module.body, "", version);
    let classes: Vec<Value> = collect_classes(&module.body, "", version);
    let string_literals: Vec<Value> = collect_string_literals(&module.body);
    let mut builtins_used: BTreeSet<String> = BTreeSet::new();
    collect_referenced_externals(
        &module.body,
        &bound_at_module,
        &mut builtins_used,
        &mut unresolved_externals,
    );
    let total_lines: usize = source.lines().count();
    let metrics: Value = build_metrics(&functions, &classes, total_lines);

    json!({
        "schema": SCHEMA_ID,
        "version": pyversion_label(version),
        "source": source,
        "module_docstring": module_docstring,
        "module_vars": module_vars,
        "imports": imports,
        "functions": functions,
        "classes": classes,
        "imports_used": to_string_array(&imports_used),
        "builtins_used": to_string_array(&builtins_used),
        "unresolved_externals": to_string_array(&unresolved_externals),
        "string_literals": string_literals,
        "metrics": metrics,
    })
}

fn pyversion_label(version: &PyVersion) -> String {
    format!("{}.{}", version.major(), version.minor())
}

fn to_string_array(set: &BTreeSet<String>) -> Vec<Value> {
    set.iter()
        .map(|s: &String| Value::String(s.clone()))
        .collect()
}

fn collect_imports(body: &[Stmt], imports_used: &mut BTreeSet<String>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for stmt in body {
        match stmt {
            Stmt::Import(aliases) => {
                for alias in aliases {
                    imports_used.insert(alias.asname.clone().unwrap_or_else(|| alias.name.clone()));
                    out.push(json!({
                        "module": alias.name,
                        "names": Value::Null,
                        "level": 0,
                        "alias": alias.asname,
                        "line": Value::Null,
                    }));
                }
            }
            Stmt::ImportFrom {
                module,
                names,
                level,
                line,
            } => {
                let name_values: Vec<Value> = names
                    .iter()
                    .map(|a: &Alias| {
                        json!({
                            "name": a.name,
                            "asname": a.asname,
                        })
                    })
                    .collect();
                for alias in names {
                    imports_used.insert(alias.asname.clone().unwrap_or_else(|| alias.name.clone()));
                }
                out.push(json!({
                    "module": module,
                    "names": name_values,
                    "level": level,
                    "alias": Value::Null,
                    "line": line,
                }));
            }
            _ => {}
        }
    }
    out
}

fn collect_module_vars(body: &[Stmt]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for stmt in body {
        match stmt {
            Stmt::Assign { targets, line, .. } => {
                for t in targets {
                    if let Expr::Name { id, .. } = t {
                        out.push(json!({
                            "name": id,
                            "kind": "assign",
                            "line": line,
                        }));
                    }
                }
            }
            Stmt::AnnAssign { target, line, .. } => {
                if let Expr::Name { id, .. } = target {
                    out.push(json!({
                        "name": id,
                        "kind": "ann_assign",
                        "line": line,
                    }));
                }
            }
            Stmt::AugAssign { target, line, .. } => {
                if let Expr::Name { id, .. } = target {
                    out.push(json!({
                        "name": id,
                        "kind": "aug_assign",
                        "line": line,
                    }));
                }
            }
            _ => {}
        }
    }
    out
}

fn module_bound_names(body: &[Stmt], imports_used: &BTreeSet<String>) -> BTreeSet<String> {
    let mut bound: BTreeSet<String> = imports_used.clone();
    for stmt in body {
        match stmt {
            Stmt::FunctionDef { name, .. } | Stmt::ClassDef { name, .. } => {
                bound.insert(name.clone());
            }
            Stmt::TypeAlias { name, .. } => {
                bound.insert(name.clone());
            }
            Stmt::Assign { targets, .. } => {
                for t in targets {
                    if let Expr::Name { id, .. } = t {
                        bound.insert(id.clone());
                    }
                }
            }
            Stmt::AnnAssign { target, .. } => {
                if let Expr::Name { id, .. } = target {
                    bound.insert(id.clone());
                }
            }
            _ => {}
        }
    }
    bound
}

fn collect_functions(body: &[Stmt], parent_qual: &str, version: &PyVersion) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for stmt in body {
        if let Stmt::FunctionDef {
            name,
            type_params,
            args,
            body: fn_body,
            decorators,
            returns,
            is_async,
            docstring,
            line,
        } = stmt
        {
            let qualname: String = qualify(parent_qual, name);
            out.push(build_function_entry(
                &qualname,
                name,
                type_params,
                args,
                fn_body,
                decorators,
                returns.as_ref(),
                *is_async,
                docstring.as_deref(),
                *line,
                version,
            ));
        }
    }
    out
}

fn collect_classes(body: &[Stmt], parent_qual: &str, version: &PyVersion) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for stmt in body {
        if let Stmt::ClassDef {
            name,
            type_params,
            bases,
            keywords: _,
            body: cls_body,
            decorators,
            docstring,
            line,
        } = stmt
        {
            let qualname: String = qualify(parent_qual, name);
            let bases_rendered: Vec<Value> = bases
                .iter()
                .map(|b: &Expr| Value::String(render_expr(b, version)))
                .collect();
            let type_params_rendered: Vec<Value> = type_params
                .iter()
                .map(|tp: &TypeParam| Value::String(render_type_param(tp)))
                .collect();
            let decorators_rendered: Vec<Value> = decorators
                .iter()
                .map(|d: &Expr| Value::String(render_expr(d, version)))
                .collect();
            let methods: Vec<Value> = collect_functions(cls_body, &qualname, version);
            let class_vars: Vec<Value> = collect_class_vars(cls_body, version);
            out.push(json!({
                "qualname": qualname,
                "name": name,
                "type_params": type_params_rendered,
                "bases": bases_rendered,
                "decorators": decorators_rendered,
                "class_vars": class_vars,
                "methods": methods,
                "docstring": docstring,
                "line": line,
            }));
        }
    }
    out
}

fn collect_class_vars(body: &[Stmt], version: &PyVersion) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for stmt in body {
        match stmt {
            Stmt::AnnAssign {
                target,
                annotation,
                value,
                ..
            } => {
                if let Expr::Name { id, .. } = target {
                    out.push(json!({
                        "name": id,
                        "annotation": render_expr(annotation, version),
                        "default_repr": value.as_ref().map(|e: &Expr| render_expr(e, version)),
                    }));
                }
            }
            Stmt::Assign { targets, value, .. } => {
                for t in targets {
                    if let Expr::Name { id, .. } = t {
                        out.push(json!({
                            "name": id,
                            "annotation": Value::Null,
                            "default_repr": render_expr(value, version),
                        }));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn build_function_entry(
    qualname: &str,
    name: &str,
    type_params: &[TypeParam],
    args: &Arguments,
    body: &[Stmt],
    decorators: &[Expr],
    returns: Option<&Expr>,
    is_async: bool,
    docstring: Option<&str>,
    line: Option<u32>,
    version: &PyVersion,
) -> Value {
    let decorators_rendered: Vec<Value> = decorators
        .iter()
        .map(|d: &Expr| Value::String(render_expr(d, version)))
        .collect();
    let type_params_rendered: Vec<Value> = type_params
        .iter()
        .map(|tp: &TypeParam| Value::String(render_type_param(tp)))
        .collect();
    let posonly: Vec<Value> = render_args(&args.posonly, &[], version);
    let pos_args: Vec<Value> = render_args(&args.args, &args.defaults, version);
    let kwonly: Vec<Value> = render_kwonly_args(&args.kwonly, &args.kw_defaults, version);
    let vararg: Value = args
        .vararg
        .as_deref()
        .map_or(Value::Null, |a: &Arg| render_single_arg(a, None, version));
    let kwarg: Value = args
        .kwarg
        .as_deref()
        .map_or(Value::Null, |a: &Arg| render_single_arg(a, None, version));

    let mut metrics: FunctionMetrics = FunctionMetrics::default();
    metrics.scan_body(body);
    let n_locals_val: u32 = metrics.n_locals();
    let cyclomatic_val: u32 = metrics.cyclomatic_complexity;
    let is_generator: bool = metrics.is_generator;
    let calls: Vec<Value> = metrics.calls.into_iter().map(Value::String).collect();
    let raises: Vec<Value> = metrics.raises.into_iter().map(Value::String).collect();
    let catches: Vec<Value> = metrics.catches.into_iter().map(Value::String).collect();
    let globals_used: Vec<Value> = metrics
        .globals_used
        .into_iter()
        .map(Value::String)
        .collect();
    let attributes_set: Vec<Value> = metrics
        .attributes_set
        .into_iter()
        .map(Value::String)
        .collect();
    let attributes_read: Vec<Value> = metrics
        .attributes_read
        .into_iter()
        .map(Value::String)
        .collect();
    let exception_table: Vec<Value> = metrics
        .exception_table
        .into_iter()
        .map(|e: ExceptionEntry| {
            json!({
                "exc_type": e.exc_type,
                "name": e.name,
                "line": e.line,
            })
        })
        .collect();

    let body_summary: String = summarize_body(body, version);
    let n_lines: usize = body_summary.lines().count();
    let returns_rendered: Value = returns.map_or(Value::Null, |r: &Expr| {
        Value::String(render_expr(r, version))
    });

    json!({
        "qualname": qualname,
        "name": name,
        "is_async": is_async,
        "is_generator": is_generator,
        "decorators": decorators_rendered,
        "type_params": type_params_rendered,
        "posonly": posonly,
        "args": pos_args,
        "kwonly": kwonly,
        "vararg": vararg,
        "kwarg": kwarg,
        "returns": returns_rendered,
        "docstring": docstring,
        "body_summary": body_summary,
        "calls": calls,
        "raises": raises,
        "catches": catches,
        "globals_used": globals_used,
        "attributes_set": attributes_set,
        "attributes_read": attributes_read,
        "cyclomatic_complexity": cyclomatic_val,
        "n_locals": n_locals_val,
        "n_lines": n_lines,
        "exception_table": exception_table,
        "line": line,
    })
}

fn render_args(args: &[Arg], defaults: &[Expr], version: &PyVersion) -> Vec<Value> {
    let arg_count: usize = args.len();
    let default_count: usize = defaults.len();
    let first_with_default: usize = arg_count.saturating_sub(default_count);
    args.iter()
        .enumerate()
        .map(|(idx, a): (usize, &Arg)| {
            let default: Option<&Expr> = if idx >= first_with_default {
                defaults.get(idx - first_with_default)
            } else {
                None
            };
            render_single_arg(a, default, version)
        })
        .collect()
}

fn render_kwonly_args(
    args: &[Arg],
    kw_defaults: &[Option<Expr>],
    version: &PyVersion,
) -> Vec<Value> {
    args.iter()
        .enumerate()
        .map(|(idx, a): (usize, &Arg)| {
            let default: Option<&Expr> = kw_defaults.get(idx).and_then(Option::as_ref);
            render_single_arg(a, default, version)
        })
        .collect()
}

fn render_single_arg(arg: &Arg, default: Option<&Expr>, version: &PyVersion) -> Value {
    json!({
        "name": arg.arg,
        "annotation": arg.annotation.as_deref().map(|e: &Expr| render_expr(e, version)),
        "default": default.map(|e: &Expr| render_expr(e, version)),
        "line": arg.line,
    })
}

fn render_type_param(tp: &TypeParam) -> String {
    match tp {
        TypeParam::TypeVar { name, .. } => name.clone(),
        TypeParam::ParamSpec { name, .. } => format!("**{name}"),
        TypeParam::TypeVarTuple { name, .. } => format!("*{name}"),
    }
}

#[derive(Debug, Default)]
struct FunctionMetrics {
    calls: BTreeSet<String>,
    raises: BTreeSet<String>,
    catches: BTreeSet<String>,
    globals_used: BTreeSet<String>,
    attributes_set: BTreeSet<String>,
    attributes_read: BTreeSet<String>,
    locals_set: BTreeSet<String>,
    exception_table: Vec<ExceptionEntry>,
    cyclomatic_complexity: u32,
    is_generator: bool,
}

#[derive(Debug)]
struct ExceptionEntry {
    exc_type: Option<String>,
    name: Option<String>,
    line: Option<u32>,
}

impl FunctionMetrics {
    fn scan_body(&mut self, body: &[Stmt]) {
        self.cyclomatic_complexity = 1;
        for stmt in body {
            self.scan_stmt(stmt);
        }
    }

    fn n_locals(&self) -> u32 {
        u32::try_from(self.locals_set.len()).unwrap_or(u32::MAX)
    }

    fn scan_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::If {
                test, body, orelse, ..
            } => {
                self.cyclomatic_complexity += 1;
                self.scan_expr(test);
                for s in body {
                    self.scan_stmt(s);
                }
                for s in orelse {
                    self.scan_stmt(s);
                }
            }
            Stmt::While {
                test, body, orelse, ..
            } => {
                self.cyclomatic_complexity += 1;
                self.scan_expr(test);
                for s in body {
                    self.scan_stmt(s);
                }
                for s in orelse {
                    self.scan_stmt(s);
                }
            }
            Stmt::For {
                target,
                iter,
                body,
                orelse,
                ..
            } => {
                self.cyclomatic_complexity += 1;
                self.scan_expr(target);
                self.scan_expr(iter);
                self.collect_targets(target);
                for s in body {
                    self.scan_stmt(s);
                }
                for s in orelse {
                    self.scan_stmt(s);
                }
            }
            Stmt::Match { subject, cases, .. } => {
                self.scan_expr(subject);
                for case in cases {
                    self.cyclomatic_complexity += 1;
                    if let Some(g) = case.guard.as_ref() {
                        self.scan_expr(g);
                    }
                    for s in &case.body {
                        self.scan_stmt(s);
                    }
                }
            }
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
                line,
            }
            | Stmt::TryStar {
                body,
                handlers,
                orelse,
                finalbody,
                line,
            } => {
                for s in body {
                    self.scan_stmt(s);
                }
                for h in handlers {
                    self.cyclomatic_complexity += 1;
                    self.record_handler(h, *line);
                    for s in &h.body {
                        self.scan_stmt(s);
                    }
                }
                for s in orelse {
                    self.scan_stmt(s);
                }
                for s in finalbody {
                    self.scan_stmt(s);
                }
            }
            Stmt::Raise { exc, cause, .. } => {
                if let Some(e) = exc.as_ref() {
                    self.record_raise(e);
                    self.scan_expr(e);
                }
                if let Some(c) = cause.as_ref() {
                    self.scan_expr(c);
                }
            }
            Stmt::With { items, body, .. } => {
                for item in items {
                    self.scan_expr(&item.context_expr);
                    if let Some(t) = item.optional_vars.as_ref() {
                        self.scan_expr(t);
                        self.collect_targets(t);
                    }
                }
                for s in body {
                    self.scan_stmt(s);
                }
            }
            Stmt::FunctionDef { .. } | Stmt::ClassDef { .. } => {}
            Stmt::Assign { targets, value, .. } => {
                for t in targets {
                    self.collect_targets(t);
                    self.scan_expr(t);
                }
                self.scan_expr(value);
            }
            Stmt::AugAssign { target, value, .. } => {
                self.collect_targets(target);
                self.scan_expr(target);
                self.scan_expr(value);
            }
            Stmt::AnnAssign {
                target,
                annotation,
                value,
                ..
            } => {
                self.collect_targets(target);
                self.scan_expr(target);
                self.scan_expr(annotation);
                if let Some(v) = value.as_ref() {
                    self.scan_expr(v);
                }
            }
            Stmt::TypeAlias { value, .. } => self.scan_expr(value),
            Stmt::Return(maybe) => {
                if let Some(e) = maybe.as_ref() {
                    self.scan_expr(e);
                }
            }
            Stmt::Delete(targets) => {
                for t in targets {
                    self.scan_expr(t);
                }
            }
            Stmt::Assert { test, msg, .. } => {
                self.cyclomatic_complexity += 1;
                self.scan_expr(test);
                if let Some(m) = msg.as_ref() {
                    self.scan_expr(m);
                }
            }
            Stmt::Expr(e) => self.scan_expr(e),
            Stmt::Global(names) => {
                for n in names {
                    self.globals_used.insert(n.clone());
                }
            }
            Stmt::Nonlocal(names) => {
                for n in names {
                    self.globals_used.insert(n.clone());
                }
            }
            Stmt::Import(_)
            | Stmt::ImportFrom { .. }
            | Stmt::Pass
            | Stmt::Break
            | Stmt::Continue => {}
        }
    }

    fn record_handler(&mut self, h: &ExceptHandler, line: Option<u32>) {
        let exc_type: Option<String> = h.typ.as_ref().map(|t: &Expr| render_dotted_name(t));
        if let Some(name) = exc_type.clone() {
            self.catches.insert(name);
        }
        self.exception_table.push(ExceptionEntry {
            exc_type,
            name: h.name.clone(),
            line,
        });
    }

    fn record_raise(&mut self, exc: &Expr) {
        let name: Option<String> = match exc {
            Expr::Call { func, .. } => Some(render_dotted_name(func)),
            other => Some(render_dotted_name(other)),
        };
        if let Some(n) = name {
            self.raises.insert(n);
        }
    }

    fn collect_targets(&mut self, expr: &Expr) {
        match expr {
            Expr::Name {
                id,
                ctx: ExprCtx::Store,
                ..
            } => {
                self.locals_set.insert(id.clone());
            }
            Expr::Tuple { elts, .. } | Expr::List { elts, .. } => {
                for e in elts {
                    self.collect_targets(e);
                }
            }
            Expr::Starred { value, .. } => self.collect_targets(value),
            Expr::Attribute {
                value,
                attr,
                ctx: ExprCtx::Store,
            } => {
                self.attributes_set
                    .insert(format!("{}.{attr}", render_dotted_name(value)));
            }
            _ => {}
        }
    }

    fn scan_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Yield(_) | Expr::YieldFrom(_) => {
                self.is_generator = true;
            }
            Expr::Call {
                func,
                args,
                keywords,
            } => {
                self.calls.insert(render_dotted_name(func));
                self.scan_expr(func);
                for a in args {
                    self.scan_expr(a);
                }
                for kw in keywords {
                    self.scan_expr(&kw.value);
                }
                return;
            }
            Expr::Attribute { value, attr, ctx } => {
                if matches!(ctx, ExprCtx::Load) {
                    self.attributes_read
                        .insert(format!("{}.{attr}", render_dotted_name(value)));
                }
                self.scan_expr(value);
                return;
            }
            Expr::BoolOp { .. } => {
                self.cyclomatic_complexity += 1;
            }
            Expr::IfExp { .. } => {
                self.cyclomatic_complexity += 1;
            }
            _ => {}
        }
        let mut walker: ExprForwarder<'_> = ExprForwarder { metrics: self };
        walker.visit_expr(expr);
    }
}

struct ExprForwarder<'a> {
    metrics: &'a mut FunctionMetrics,
}

impl<'a> Visitor for ExprForwarder<'a> {
    fn visit_stmt(&mut self, _stmt: &Stmt) {}
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call { .. } | Expr::Attribute { .. } | Expr::Yield(_) | Expr::YieldFrom(_) => {
                self.metrics.scan_expr(expr);
            }
            Expr::BoolOp { values, .. } => {
                for v in values {
                    self.visit_expr(v);
                }
            }
            Expr::IfExp { test, body, orelse } => {
                self.visit_expr(test);
                self.visit_expr(body);
                self.visit_expr(orelse);
            }
            other => walk_expr(self, other),
        }
    }
}

fn render_dotted_name(expr: &Expr) -> String {
    match expr {
        Expr::Name { id, .. } => id.clone(),
        Expr::Attribute { value, attr, .. } => {
            format!("{}.{attr}", render_dotted_name(value))
        }
        Expr::Call { func, .. } => render_dotted_name(func),
        Expr::Subscript { value, .. } => format!("{}[…]", render_dotted_name(value)),
        _ => "<expr>".to_owned(),
    }
}

fn render_expr(expr: &Expr, version: &PyVersion) -> String {
    let emitter: DefaultEmitter = DefaultEmitter::new();
    emitter.emit_expr(expr, version)
}

fn summarize_body(body: &[Stmt], version: &PyVersion) -> String {
    let emitter: DefaultEmitter = DefaultEmitter::new();
    let mut out: String = String::new();
    let last: usize = body.len();
    for (idx, s) in body.iter().enumerate() {
        out.push_str(&emitter.emit_stmt(s, 0, version));
        if idx + 1 < last {
            out.push('\n');
        }
    }
    out
}

fn qualify(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}.{name}")
    }
}

fn collect_string_literals(body: &[Stmt]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut collector: StringLitCollector = StringLitCollector { out: &mut out };
    for stmt in body {
        collector.visit_stmt(stmt);
    }
    out
}

struct StringLitCollector<'a> {
    out: &'a mut Vec<Value>,
}

impl<'a> Visitor for StringLitCollector<'a> {
    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Constant {
            value: ConstValue::Str(s),
            line,
        } = expr
        {
            self.out.push(json!({
                "value": format_string_literal(s, true),
                "line": line,
            }));
        }
        walk_expr(self, expr);
    }
}

fn collect_referenced_externals(
    body: &[Stmt],
    bound: &BTreeSet<String>,
    builtins_used: &mut BTreeSet<String>,
    unresolved: &mut BTreeSet<String>,
) {
    let mut builtins_set: BTreeSet<&'static str> = BTreeSet::new();
    for b in PY_BUILTINS {
        builtins_set.insert(b);
    }
    let mut collector: NameRefCollector = NameRefCollector {
        bound,
        local_scope: BTreeSet::new(),
        builtins_set: &builtins_set,
        builtins_used,
        unresolved,
    };
    for stmt in body {
        collector.visit_stmt(stmt);
    }
}

struct NameRefCollector<'a> {
    bound: &'a BTreeSet<String>,
    local_scope: BTreeSet<String>,
    builtins_set: &'a BTreeSet<&'static str>,
    builtins_used: &'a mut BTreeSet<String>,
    unresolved: &'a mut BTreeSet<String>,
}

impl<'a> Visitor for NameRefCollector<'a> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::FunctionDef {
            name, args, body, ..
        } = stmt
        {
            self.local_scope.insert(name.clone());
            for a in args.posonly.iter().chain(&args.args).chain(&args.kwonly) {
                self.local_scope.insert(a.arg.clone());
            }
            if let Some(va) = args.vararg.as_deref() {
                self.local_scope.insert(va.arg.clone());
            }
            if let Some(kw) = args.kwarg.as_deref() {
                self.local_scope.insert(kw.arg.clone());
            }
            for s in body {
                self.visit_stmt(s);
            }
            return;
        }
        if let Stmt::ClassDef { name, body, .. } = stmt {
            self.local_scope.insert(name.clone());
            for s in body {
                self.visit_stmt(s);
            }
            return;
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Name {
            id,
            ctx: ExprCtx::Load,
            ..
        } = expr
        {
            if self.builtins_set.contains(id.as_str()) {
                self.builtins_used.insert(id.clone());
            } else if !self.bound.contains(id) && !self.local_scope.contains(id) {
                self.unresolved.insert(id.clone());
            }
        }
        walk_expr(self, expr);
    }

    fn visit_pattern(&mut self, pattern: &crate::ast::node::Pattern) {
        walk_pattern(self, pattern);
    }

    fn visit_handler(&mut self, handler: &ExceptHandler) {
        walk_handler(self, handler);
    }

    fn visit_match_case(&mut self, case: &crate::ast::node::MatchCase) {
        walk_match_case(self, case);
    }

    fn visit_comprehension(&mut self, comp: &crate::ast::node::Comprehension) {
        walk_comprehension(self, comp);
    }
}

fn build_metrics(functions: &[Value], classes: &[Value], total_lines: usize) -> Value {
    let n_functions: usize = functions.len();
    let n_classes: usize = classes.len();
    let mut method_total: usize = 0;
    let mut complexity_sum: u64 = 0;
    let mut complexity_count: u64 = 0;

    for f in functions {
        if let Some(c) = f.get("cyclomatic_complexity").and_then(Value::as_u64) {
            complexity_sum += c;
            complexity_count += 1;
        }
    }
    for c in classes {
        if let Some(methods) = c.get("methods").and_then(Value::as_array) {
            method_total += methods.len();
            for m in methods {
                if let Some(cc) = m.get("cyclomatic_complexity").and_then(Value::as_u64) {
                    complexity_sum += cc;
                    complexity_count += 1;
                }
            }
        }
    }

    let avg_cyclomatic: f64 = if complexity_count > 0 {
        let avg_x10: u64 = (complexity_sum * 10 + complexity_count / 2) / complexity_count;
        (avg_x10 as f64) / 10.0
    } else {
        0.0
    };

    let mut map: Map<String, Value> = Map::new();
    map.insert("total_lines".to_owned(), json!(total_lines));
    map.insert("n_functions".to_owned(), json!(n_functions));
    map.insert("n_classes".to_owned(), json!(n_classes));
    map.insert("n_methods".to_owned(), json!(method_total));
    map.insert(
        "avg_cyclomatic".to_owned(),
        json!(round_to_tenth(avg_cyclomatic)),
    );
    Value::Object(map)
}

fn round_to_tenth(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmJsonBundle {
    pub module_path: String,
    pub python_version: String,
    pub source: String,
    pub schema: String,
    pub data: BTreeMap<String, Value>,
}
