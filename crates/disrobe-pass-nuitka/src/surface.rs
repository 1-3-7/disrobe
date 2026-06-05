use std::collections::BTreeSet;

use disrobe_pass_pickle::{PickleValue, to_python};
use serde::{Deserialize, Serialize};

use crate::body::{
    BodyLift, LiftFidelity, PythonExpr, PythonStmt, extract_impl_body_text, lift_body_detailed,
};
use crate::c_module::{CFunctionWiring, CImplBody, CModuleStructure};
use crate::constants::ConstantsPool;
use crate::error::Error;
use crate::symbols::SymbolGraph;
use crate::{DemangledFunction, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceFidelity {
    StructuredFromCSource,
    NamesOnly,
}

impl From<SurfaceFidelity> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(fidelity: SurfaceFidelity) -> Self {
        match fidelity {
            SurfaceFidelity::StructuredFromCSource => Self::StructuredNoVerify,
            SurfaceFidelity::NamesOnly => Self::SignaturesOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceParam {
    pub name: String,
    pub annotation: Option<String>,
    pub default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceFunction {
    pub name: String,
    pub source_index: u32,
    pub params: Vec<SurfaceParam>,
    pub return_annotation: Option<String>,
    pub docstring: Option<String>,
    pub body_recovered: bool,
    pub body_stmts: Vec<PythonStmt>,
    pub lift_fidelity: LiftFidelity,
    pub unrecognized_c_lines: Vec<String>,
    pub source_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceModule {
    pub module_name: String,
    pub functions: Vec<SurfaceFunction>,
    pub has_main_guard: bool,
    pub python_source: String,
    pub fidelity: SurfaceFidelity,
    pub notes: Vec<String>,
}

const RETURN_KEY: &str = "return";

#[inline]
fn strip_builtins(rendered: &str) -> String {
    rendered
        .strip_prefix("builtins.")
        .unwrap_or(rendered)
        .to_owned()
}

fn dict_pairs(value: &PickleValue) -> Option<&[(PickleValue, PickleValue)]> {
    match value {
        PickleValue::Dict(pairs) => Some(pairs),
        _ => None,
    }
}

fn dict_key_set(pairs: &[(PickleValue, PickleValue)]) -> Option<BTreeSet<String>> {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for (k, _) in pairs {
        match k {
            PickleValue::Str(s) => {
                keys.insert(s.clone());
            }
            _ => return None,
        }
    }
    Some(keys)
}

fn lookup_annotation(pairs: &[(PickleValue, PickleValue)], key: &str) -> Option<String> {
    for (k, v) in pairs {
        if let PickleValue::Str(s) = k
            && s == key
        {
            return Some(strip_builtins(&to_python(v)));
        }
    }
    None
}

fn find_annotation_dict<'a>(
    pool: &'a ConstantsPool,
    expected_keys: &BTreeSet<String>,
) -> Option<&'a [(PickleValue, PickleValue)]> {
    pool.entries
        .iter()
        .filter_map(|e| dict_pairs(&e.value))
        .find(|pairs| {
            dict_key_set(pairs).is_some_and(|keys: BTreeSet<String>| &keys == expected_keys)
        })
}

struct DefaultsResult {
    values: Vec<String>,
    unresolved: Option<String>,
}

fn default_values(wiring: Option<&CFunctionWiring>) -> DefaultsResult {
    DefaultsResult {
        values: Vec::new(),
        unresolved: wiring.and_then(|w: &CFunctionWiring| w.defaults_const.clone()),
    }
}

fn docstring_value(wiring: Option<&CFunctionWiring>) -> (Option<String>, Option<String>) {
    (
        None,
        wiring.and_then(|w: &CFunctionWiring| w.doc_const.clone()),
    )
}

pub fn build_surface(
    c_module: &CModuleStructure,
    pool: &ConstantsPool,
    c_source: Option<&str>,
) -> Result<SurfaceModule> {
    let mut bodies: Vec<&CImplBody> = c_module.impl_bodies.iter().collect();
    bodies.sort_by_key(|b: &&CImplBody| b.source_index);

    let mut functions: Vec<SurfaceFunction> = Vec::with_capacity(bodies.len());
    let mut notes: Vec<String> = c_module.notes.clone();

    for body in bodies {
        let wiring: Option<&CFunctionWiring> = c_module
            .wirings
            .iter()
            .find(|w: &&CFunctionWiring| w.function_name == body.function_name);

        let mut expected_keys: BTreeSet<String> =
            body.params.iter().cloned().collect::<BTreeSet<String>>();
        expected_keys.insert(RETURN_KEY.to_owned());

        let annotation_dict: Option<&[(PickleValue, PickleValue)]> =
            match wiring.and_then(|w: &CFunctionWiring| w.annotations_dict_const.as_deref()) {
                Some(_) => find_annotation_dict(pool, &expected_keys),
                None => None,
            };

        let defaults_result: DefaultsResult = default_values(wiring);
        if let Some(unresolved) = &defaults_result.unresolved {
            notes.push(format!(
                "function '{}' defaults const '{unresolved}' present but not value-resolved (follow-on)",
                body.function_name
            ));
        }
        let defaults: Vec<String> = defaults_result.values;
        let n_params: usize = body.params.len();
        let first_defaulted: usize = n_params.saturating_sub(defaults.len());

        let mut params: Vec<SurfaceParam> = Vec::with_capacity(n_params);
        for (i, pname) in body.params.iter().enumerate() {
            let annotation: Option<String> =
                annotation_dict.and_then(|pairs| lookup_annotation(pairs, pname));
            let default: Option<String> = if i >= first_defaulted {
                defaults.get(i - first_defaulted).cloned()
            } else {
                None
            };
            params.push(SurfaceParam {
                name: pname.clone(),
                annotation,
                default,
            });
        }

        let return_annotation: Option<String> =
            annotation_dict.and_then(|pairs| lookup_annotation(pairs, RETURN_KEY));

        if wiring.is_none() {
            notes.push(format!(
                "function '{}' has no wiring record; annotations unresolved",
                body.function_name
            ));
        }

        let source_line: Option<u32> = c_module
            .code_objects
            .iter()
            .find(|c| c.name == body.function_name)
            .map(|c| c.line);

        let (docstring, doc_unresolved): (Option<String>, Option<String>) = docstring_value(wiring);
        if let Some(unresolved) = &doc_unresolved {
            notes.push(format!(
                "function '{}' doc const '{unresolved}' present but not value-resolved (follow-on)",
                body.function_name
            ));
        }

        let lift: BodyLift = c_source
            .and_then(|src: &str| {
                extract_impl_body_text(
                    src,
                    &c_module.module_name,
                    body.source_index,
                    &body.function_name,
                )
            })
            .map_or_else(
                || BodyLift {
                    stmts: Vec::new(),
                    fidelity: LiftFidelity::Skeleton,
                    unrecognized_lines: Vec::new(),
                },
                |slice: &str| lift_body_detailed(slice, &body.params, pool),
            );
        let body_recovered: bool = !lift.stmts.is_empty();
        if !lift.unrecognized_lines.is_empty() {
            notes.push(format!(
                "function '{}' dropped {} unrecognized C line(s); fidelity downgraded from full coverage",
                body.function_name,
                lift.unrecognized_lines.len()
            ));
        }

        functions.push(SurfaceFunction {
            name: body.function_name.clone(),
            source_index: body.source_index,
            params,
            return_annotation,
            docstring,
            body_recovered,
            body_stmts: lift.stmts,
            lift_fidelity: lift.fidelity,
            unrecognized_c_lines: lift.unrecognized_lines,
            source_line,
        });
    }

    let mut module: SurfaceModule = SurfaceModule {
        module_name: c_module.module_name.clone(),
        functions,
        has_main_guard: c_module.has_main_guard,
        python_source: String::new(),
        fidelity: SurfaceFidelity::StructuredFromCSource,
        notes,
    };
    module.python_source = emit_python(&module);
    if module.python_source.is_empty() {
        return Err(Error::SurfaceBinding(
            "emitter produced empty source".to_owned(),
        ));
    }
    Ok(module)
}

pub fn build_surface_names_only(graph: &SymbolGraph, pool: &ConstantsPool) -> SurfaceModule {
    let mut functions: Vec<SurfaceFunction> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut module_name: String = String::new();

    for imp in &graph.impl_functions {
        let Some(demangled): Option<&DemangledFunction> = imp.demangled.as_ref() else {
            continue;
        };
        if module_name.is_empty() {
            module_name.clone_from(&demangled.module_path);
        }
        if !seen.insert(demangled.function_name.clone()) {
            continue;
        }
        functions.push(SurfaceFunction {
            name: demangled.function_name.clone(),
            source_index: demangled.source_index,
            params: Vec::new(),
            return_annotation: None,
            docstring: None,
            body_recovered: false,
            body_stmts: Vec::new(),
            lift_fidelity: LiftFidelity::Skeleton,
            unrecognized_c_lines: Vec::new(),
            source_line: None,
        });
    }
    functions.sort_by_key(|f: &SurfaceFunction| f.source_index);

    let has_main: bool = pool.strings.contains("__main__") && seen.contains("main");
    let mut module: SurfaceModule = SurfaceModule {
        module_name,
        functions,
        has_main_guard: has_main,
        python_source: String::new(),
        fidelity: SurfaceFidelity::NamesOnly,
        notes: vec![
            "names-only fidelity: no module.<name>.c; signatures/annotations not recoverable"
                .to_owned(),
        ],
    };
    module.python_source = emit_python(&module);
    module
}

fn render_signature(function: &SurfaceFunction) -> String {
    let mut sig: String = format!("def {}(", function.name);
    for (i, param) in function.params.iter().enumerate() {
        if i > 0 {
            sig.push_str(", ");
        }
        sig.push_str(&param.name);
        if let Some(annotation) = &param.annotation {
            sig.push_str(": ");
            sig.push_str(annotation);
        }
        if let Some(default) = &param.default {
            if param.annotation.is_some() {
                sig.push_str(" = ");
            } else {
                sig.push('=');
            }
            sig.push_str(default);
        }
    }
    sig.push(')');
    if let Some(ret) = &function.return_annotation {
        sig.push_str(" -> ");
        sig.push_str(ret);
    }
    sig.push(':');
    sig
}

#[must_use]
pub fn emit_python(module: &SurfaceModule) -> String {
    let mut out: String = String::new();
    let bodies_lifted: bool = module
        .functions
        .iter()
        .any(|f: &SurfaceFunction| !f.body_stmts.is_empty());
    if bodies_lifted {
        out.push_str("# Recovered by disrobe (bodies partially lifted from Nuitka-generated C).\n");
    } else {
        out.push_str("# Recovered by disrobe (surface skeleton; bodies not lifted).\n");
    }
    out.push_str("from __future__ import annotations\n\n");

    for (i, function) in module.functions.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&render_signature(function));
        out.push('\n');
        if let Some(doc) = &function.docstring {
            out.push_str("    ");
            out.push_str(&py_docstring(doc));
            out.push('\n');
        }
        if function.body_stmts.is_empty() {
            out.push_str("    ...  # disrobe: body not recovered\n");
        } else {
            for stmt in &function.body_stmts {
                out.push_str(&emit_stmt(stmt, 1));
            }
        }
    }

    let has_main_fn: bool = module
        .functions
        .iter()
        .any(|f: &SurfaceFunction| f.name == "main");
    if module.has_main_guard && has_main_fn {
        if !module.functions.is_empty() {
            out.push('\n');
        }
        out.push_str("\nif __name__ == \"__main__\":\n");
        out.push_str("    raise SystemExit(main())\n");
    }

    out
}

fn py_docstring(doc: &str) -> String {
    let escaped: String = doc.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    format!("\"\"\"{escaped}\"\"\"")
}

fn emit_indent(indent: usize) -> String {
    "    ".repeat(indent)
}

fn emit_expr(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::Name(s) | PythonExpr::Const(s) => s.clone(),
        PythonExpr::FStringJoin { parts } => {
            let mut inner: String = String::new();
            for part in parts {
                match part {
                    PythonExpr::Const(s) => {
                        let stripped: &str = s
                            .strip_prefix('\'')
                            .and_then(|s2: &str| s2.strip_suffix('\''))
                            .unwrap_or(s);
                        inner.push_str(stripped);
                    }
                    PythonExpr::Name(n) => {
                        inner.push('{');
                        inner.push_str(n);
                        inner.push('}');
                    }
                    other => {
                        inner.push('{');
                        inner.push_str(&emit_expr(other));
                        inner.push('}');
                    }
                }
            }
            format!("f\"{inner}\"")
        }
        PythonExpr::BinOp { op, left, right } => {
            let op_str: &str = match op {
                crate::body::BinOpKind::Add => "+",
                crate::body::BinOpKind::Sub => "-",
            };
            format!("{} {} {}", emit_expr(left), op_str, emit_expr(right))
        }
        PythonExpr::Compare { op, left, right } => {
            let op_str: &str = match op {
                crate::body::CmpOpKind::Lt => "<",
                crate::body::CmpOpKind::Eq => "==",
            };
            format!("{} {} {}", emit_expr(left), op_str, emit_expr(right))
        }
        PythonExpr::Call { func, args } => {
            let args_str: String = args
                .iter()
                .map(emit_expr)
                .collect::<Vec<String>>()
                .join(", ");
            format!("{}({})", emit_expr(func), args_str)
        }
        PythonExpr::Tuple(items) => {
            let inner: String = items
                .iter()
                .map(emit_expr)
                .collect::<Vec<String>>()
                .join(", ");
            if items.len() == 1 {
                format!("({inner},)")
            } else {
                format!("({inner})")
            }
        }
        PythonExpr::List(items) => {
            let inner: String = items
                .iter()
                .map(emit_expr)
                .collect::<Vec<String>>()
                .join(", ");
            format!("[{inner}]")
        }
    }
}

fn emit_expr_unpack(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::Tuple(items) | PythonExpr::List(items) => items
            .iter()
            .map(emit_expr)
            .collect::<Vec<String>>()
            .join(", "),
        other => emit_expr(other),
    }
}

fn emit_stmt(stmt: &PythonStmt, indent: usize) -> String {
    let prefix: String = emit_indent(indent);
    match stmt {
        PythonStmt::Return(e) => format!("{prefix}return {}\n", emit_expr(e)),
        PythonStmt::Raise(e) => format!("{prefix}raise {}\n", emit_expr(e)),
        PythonStmt::Expr(e) => format!("{prefix}{}\n", emit_expr(e)),
        PythonStmt::Assign { targets, value } => {
            format!("{prefix}{} = {}\n", targets.join(", "), emit_expr(value))
        }
        PythonStmt::TupleUnpackAssign { targets, value } => {
            format!(
                "{prefix}{} = {}\n",
                targets.join(", "),
                emit_expr_unpack(value)
            )
        }
        PythonStmt::If { test, body, orelse } => {
            let mut out: String = format!("{prefix}if {}:\n", emit_expr(test));
            for s in body {
                out.push_str(&emit_stmt(s, indent + 1));
            }
            if !orelse.is_empty() {
                out.push_str(prefix.as_str());
                out.push_str("else:\n");
                for s in orelse {
                    out.push_str(&emit_stmt(s, indent + 1));
                }
            }
            out
        }
        PythonStmt::For { target, iter, body } => {
            let mut out: String = format!("{prefix}for {target} in {}:\n", emit_expr(iter));
            for s in body {
                out.push_str(&emit_stmt(s, indent + 1));
            }
            out
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::c_module::parse_c_module;
    use crate::constants::decode_const_file;
    use crate::demangle_function;

    const C_SRC: &str =
        include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
    const CONST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");

    fn surface() -> SurfaceModule {
        let cmod: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        build_surface(&cmod, &pool, Some(C_SRC)).expect("surface")
    }

    #[test]
    fn functions_in_source_order_with_annotations() {
        let s: SurfaceModule = surface();
        let names: Vec<&str> = s.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["greet", "fib", "main"]);

        let greet: &SurfaceFunction = &s.functions[0];
        assert_eq!(greet.params.len(), 1);
        assert_eq!(greet.params[0].name, "name");
        assert_eq!(greet.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(greet.return_annotation.as_deref(), Some("str"));

        let fib: &SurfaceFunction = &s.functions[1];
        assert_eq!(fib.params[0].name, "n");
        assert_eq!(fib.params[0].annotation.as_deref(), Some("int"));
        assert_eq!(fib.return_annotation.as_deref(), Some("int"));

        let main: &SurfaceFunction = &s.functions[2];
        assert!(main.params.is_empty());
        assert_eq!(main.return_annotation.as_deref(), Some("int"));

        for f in &s.functions {
            assert!(f.docstring.is_none());
            for p in &f.params {
                assert!(p.default.is_none());
            }
        }
    }

    #[test]
    fn emitted_signatures_match_pyi() {
        let s: SurfaceModule = surface();
        let py: String = emit_python(&s);
        assert!(py.contains("def greet(name: str) -> str:"));
        assert!(py.contains("def fib(n: int) -> int:"));
        assert!(py.contains("def main() -> int:"));
        assert!(py.contains("if n < 2:") || py.contains("return"));
    }

    #[test]
    fn main_guard_emits_systemexit() {
        let s: SurfaceModule = surface();
        assert!(s.has_main_guard);
        let py: String = emit_python(&s);
        assert!(py.contains("if __name__ == \"__main__\":"));
        assert!(py.contains("raise SystemExit(main())"));
    }

    #[test]
    fn names_only_degrades_cleanly() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        graph.impl_functions.push(crate::symbols::ImpFunction {
            identifier: "hello$$$function__1_greet".to_owned(),
            demangled: demangle_function("impl_hello$$$function__1_greet"),
        });
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        let s: SurfaceModule = build_surface_names_only(&graph, &pool);
        assert_eq!(s.fidelity, SurfaceFidelity::NamesOnly);
        assert_eq!(s.functions.len(), 1);
        assert_eq!(s.functions[0].name, "greet");
        assert!(s.functions[0].params.is_empty());
    }
}
