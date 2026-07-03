use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_pickle::{PickleValue, to_python};
use serde::{Deserialize, Serialize};

use crate::body::{
    BodyLift, LiftFidelity, PythonExpr, PythonStmt, extract_impl_body_by_symbol,
    lift_body_with_source,
};
use crate::c_module::{CFunctionWiring, CImplBody, CModuleStructure};
use crate::constants::ConstantsPool;
use crate::error::Error;
use crate::skeleton::{SkeletonFunction, SkeletonModule, SkeletonParam};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamStar {
    None,
    Args,
    Kwargs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceParam {
    pub name: String,
    pub annotation: Option<String>,
    pub default: Option<String>,
    pub star: ParamStar,
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
    pub parent_names: Vec<String>,
    pub nested: Vec<Self>,
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
            return Some(render_annotation_value(v));
        }
    }
    None
}

fn render_annotation_value(value: &PickleValue) -> String {
    if let PickleValue::Str(s) = value
        && is_annotation_expression(s)
    {
        return s.clone();
    }
    strip_builtins(&to_python(value))
}

fn is_annotation_expression(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let allowed: bool = s
        .chars()
        .all(|c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '[' | ']' | ',' | ' ' | '|'));
    if !allowed {
        return false;
    }
    let first: char = s.chars().next().unwrap_or(' ');
    if !(first.is_alphabetic() || first == '_') {
        return false;
    }
    let opens: usize = s.bytes().filter(|&b: &u8| b == b'[').count();
    let closes: usize = s.bytes().filter(|&b: &u8| b == b']').count();
    opens == closes
}

type AnnotationPairs<'a> = &'a [(PickleValue, PickleValue)];
type AnnotationCandidate<'a> = (BTreeSet<String>, AnnotationPairs<'a>);

struct AnnotationDictPool<'a> {
    candidates: Vec<AnnotationCandidate<'a>>,
    consumed: Vec<bool>,
    by_name: BTreeMap<String, Option<usize>>,
}

impl<'a> AnnotationDictPool<'a> {
    fn from_pool(pool: &'a ConstantsPool) -> Self {
        let candidates: Vec<AnnotationCandidate<'a>> = pool
            .entries
            .iter()
            .filter_map(|e| dict_pairs(&e.value))
            .filter_map(|pairs| dict_key_set(pairs).map(|keys: BTreeSet<String>| (keys, pairs)))
            .collect();
        let consumed: Vec<bool> = vec![false; candidates.len()];
        Self {
            candidates,
            consumed,
            by_name: BTreeMap::new(),
        }
    }

    fn resolve(
        &mut self,
        dict_name: &str,
        expected_keys: &BTreeSet<String>,
    ) -> Option<AnnotationPairs<'a>> {
        if let Some(slot) = self.by_name.get(dict_name) {
            return slot.map(|idx: usize| self.candidates[idx].1);
        }
        let idx: Option<usize> = self
            .candidates
            .iter()
            .enumerate()
            .position(|(i, (keys, _))| !self.consumed[i] && keys == expected_keys);
        if let Some(found) = idx {
            self.consumed[found] = true;
        }
        self.by_name.insert(dict_name.to_owned(), idx);
        idx.map(|found: usize| self.candidates[found].1)
    }
}

struct DefaultsResult {
    values: Vec<String>,
    unresolved: Option<String>,
}

fn default_values(wiring: Option<&CFunctionWiring>, pool: &ConstantsPool) -> DefaultsResult {
    let Some(token): Option<String> =
        wiring.and_then(|w: &CFunctionWiring| w.defaults_const.clone())
    else {
        return DefaultsResult {
            values: Vec::new(),
            unresolved: None,
        };
    };
    let rendered: Vec<String> = crate::body::render_const_token(&token, pool);
    if rendered.is_empty() || rendered.iter().any(|s: &String| s.contains("UNRESOLVED")) {
        DefaultsResult {
            values: Vec::new(),
            unresolved: Some(token),
        }
    } else {
        DefaultsResult {
            values: rendered,
            unresolved: None,
        }
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
    let mut annotation_dicts: AnnotationDictPool<'_> = AnnotationDictPool::from_pool(pool);

    for body in bodies {
        let wiring: Option<&CFunctionWiring> =
            c_module.wirings.iter().find(|w: &&CFunctionWiring| {
                w.function_name == body.function_name && w.parent_names == body.parent_names
            });

        let mut expected_keys: BTreeSet<String> =
            body.params.iter().cloned().collect::<BTreeSet<String>>();
        expected_keys.insert(RETURN_KEY.to_owned());

        let annotation_dict: Option<&[(PickleValue, PickleValue)]> = wiring
            .and_then(|w: &CFunctionWiring| w.annotations_dict_const.as_deref())
            .and_then(|dict_name: &str| annotation_dicts.resolve(dict_name, &expected_keys));

        let defaults_result: DefaultsResult = default_values(wiring, pool);
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
        let code_object: Option<&crate::c_module::CCodeObject> = c_module
            .code_objects
            .iter()
            .find(|c| c.name == body.function_name);
        let vararg_index: Option<usize> = code_object.and_then(|c| {
            c.has_varargs
                .then_some(c.arg_count as usize + c.kw_only_count as usize)
        });
        let kwarg_index: Option<usize> = code_object.and_then(|c| {
            let base: usize = c.arg_count as usize + c.kw_only_count as usize;
            let offset: usize = usize::from(c.has_varargs);
            c.has_kwargs.then_some(base + offset)
        });

        for (i, pname) in body.params.iter().enumerate() {
            let annotation: Option<String> =
                annotation_dict.and_then(|pairs| lookup_annotation(pairs, pname));
            let star: ParamStar = if vararg_index == Some(i) {
                ParamStar::Args
            } else if kwarg_index == Some(i) {
                ParamStar::Kwargs
            } else {
                ParamStar::None
            };
            let default: Option<String> = if star == ParamStar::None && i >= first_defaulted {
                defaults.get(i - first_defaulted).cloned()
            } else {
                None
            };
            params.push(SurfaceParam {
                name: pname.clone(),
                annotation,
                default,
                star,
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

        let source_line: Option<u32> = code_object.map(|c| c.line);

        let (docstring, doc_unresolved): (Option<String>, Option<String>) = docstring_value(wiring);
        if let Some(unresolved) = &doc_unresolved {
            notes.push(format!(
                "function '{}' doc const '{unresolved}' present but not value-resolved (follow-on)",
                body.function_name
            ));
        }

        let lift: BodyLift = c_source
            .and_then(|src: &str| {
                extract_impl_body_by_symbol(src, &body.impl_symbol).map(|slice: &str| (src, slice))
            })
            .map_or_else(
                || BodyLift {
                    stmts: Vec::new(),
                    fidelity: LiftFidelity::Skeleton,
                    unrecognized_lines: Vec::new(),
                },
                |(src, slice): (&str, &str)| lift_body_with_source(slice, &body.params, pool, src),
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
            parent_names: body.parent_names.clone(),
            nested: Vec::new(),
        });
    }

    let functions: Vec<SurfaceFunction> = nest_functions(functions);

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

fn attach_nested(
    parents: &mut [SurfaceFunction],
    child: SurfaceFunction,
) -> Option<SurfaceFunction> {
    let Some((immediate, ancestors)): Option<(String, Vec<String>)> = child
        .parent_names
        .split_last()
        .map(|(last, rest): (&String, &[String])| (last.clone(), rest.to_vec()))
    else {
        return Some(child);
    };
    let mut pending: Option<SurfaceFunction> = Some(child);
    for parent in parents.iter_mut() {
        let Some(candidate): Option<SurfaceFunction> = pending.take() else {
            break;
        };
        if parent.name == immediate && parent.parent_names == ancestors {
            parent.nested.push(candidate);
            return None;
        }
        pending = attach_nested(&mut parent.nested, candidate);
    }
    pending
}

fn nest_functions(flat: Vec<SurfaceFunction>) -> Vec<SurfaceFunction> {
    let mut ordered: Vec<SurfaceFunction> = flat;
    ordered.sort_by_key(|f: &SurfaceFunction| f.parent_names.len());
    let mut roots: Vec<SurfaceFunction> = Vec::new();
    for func in ordered {
        if func.parent_names.is_empty() {
            roots.push(func);
            continue;
        }
        if let Some(orphan) = attach_nested(&mut roots, func) {
            roots.push(orphan);
        }
    }
    sort_tree(&mut roots);
    roots
}

fn sort_tree(funcs: &mut [SurfaceFunction]) {
    funcs.sort_by_key(|f: &SurfaceFunction| f.source_index);
    for f in funcs.iter_mut() {
        sort_tree(&mut f.nested);
    }
}

#[must_use]
pub fn build_surface_names_only(graph: &SymbolGraph, pool: &ConstantsPool) -> SurfaceModule {
    build_surface_names_only_with_skeleton(graph, pool, None)
}

#[must_use]
pub fn build_surface_names_only_with_skeleton(
    graph: &SymbolGraph,
    pool: &ConstantsPool,
    skeleton: Option<&SkeletonModule>,
) -> SurfaceModule {
    let mut functions: Vec<SurfaceFunction> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    let mut module_name: String =
        skeleton.map_or_else(String::new, |m: &SkeletonModule| m.name.clone());
    let mut by_qualname: BTreeMap<String, &SkeletonFunction> = BTreeMap::new();
    let mut by_name: BTreeMap<String, Option<&SkeletonFunction>> = BTreeMap::new();

    if let Some(module) = skeleton {
        for function in &module.functions {
            by_qualname.insert(function.qualname.clone(), function);
            by_name
                .entry(function.name.clone())
                .and_modify(|slot: &mut Option<&SkeletonFunction>| *slot = None)
                .or_insert(Some(function));
        }
    }

    for imp in &graph.impl_functions {
        let Some(demangled): Option<&DemangledFunction> = imp.demangled.as_ref() else {
            continue;
        };
        if module_name.is_empty() {
            module_name.clone_from(&demangled.module_path);
        }
        let qualname: String = demangled_qualname(demangled);
        if !seen.insert(qualname) {
            continue;
        }
        seen_names.insert(demangled.function_name.clone());
        let skeleton_function: Option<&SkeletonFunction> =
            find_skeleton_function(demangled, &by_qualname, &by_name);
        if let Some(function) = skeleton_function {
            seen.insert(function.qualname.clone());
        }
        functions.push(surface_function_from_parts(
            &demangled.function_name,
            demangled.source_index,
            demangled.parent_names.clone(),
            skeleton_function,
        ));
    }

    if let Some(module) = skeleton {
        for (index, function) in module.functions.iter().enumerate() {
            if !seen.insert(function.qualname.clone()) {
                continue;
            }
            seen_names.insert(function.name.clone());
            functions.push(surface_function_from_parts(
                &function.name,
                skeleton_only_source_index(index),
                parent_names_from_qualname(&function.qualname),
                Some(function),
            ));
        }
    }
    let functions: Vec<SurfaceFunction> = nest_functions(functions);

    let has_main: bool = pool.strings.contains("__main__") && seen_names.contains("main");
    let note: String = if skeleton.is_some() {
        "names-only fidelity: no module.<name>.c; signatures sourced from constants metadata where present; bodies not recovered".to_owned()
    } else {
        "names-only fidelity: no module.<name>.c; signatures/annotations not recoverable".to_owned()
    };
    let mut module: SurfaceModule = SurfaceModule {
        module_name,
        functions,
        has_main_guard: has_main,
        python_source: String::new(),
        fidelity: SurfaceFidelity::NamesOnly,
        notes: vec![note],
    };
    module.python_source = emit_python(&module);
    module
}

fn find_skeleton_function<'a>(
    demangled: &DemangledFunction,
    by_qualname: &BTreeMap<String, &'a SkeletonFunction>,
    by_name: &BTreeMap<String, Option<&'a SkeletonFunction>>,
) -> Option<&'a SkeletonFunction> {
    let qualname: String = demangled_qualname(demangled);
    by_qualname
        .get(&qualname)
        .copied()
        .or_else(|| match by_name.get(&demangled.function_name) {
            Some(Some(function)) => Some(*function),
            _ => None,
        })
}

fn demangled_qualname(demangled: &DemangledFunction) -> String {
    if demangled.parent_names.is_empty() {
        return demangled.function_name.clone();
    }
    let mut out: String = String::new();
    for parent in &demangled.parent_names {
        if !out.is_empty() {
            out.push_str(".<locals>.");
        }
        out.push_str(parent);
    }
    out.push_str(".<locals>.");
    out.push_str(&demangled.function_name);
    out
}

fn surface_function_from_parts(
    name: &str,
    source_index: u32,
    parent_names: Vec<String>,
    skeleton: Option<&SkeletonFunction>,
) -> SurfaceFunction {
    SurfaceFunction {
        name: name.to_owned(),
        source_index,
        params: skeleton.map_or_else(Vec::new, |function: &SkeletonFunction| {
            function
                .params
                .iter()
                .map(surface_param_from_skeleton)
                .collect()
        }),
        return_annotation: skeleton
            .and_then(|function: &SkeletonFunction| function.return_annotation.clone()),
        docstring: None,
        body_recovered: false,
        body_stmts: Vec::new(),
        lift_fidelity: LiftFidelity::Skeleton,
        unrecognized_c_lines: Vec::new(),
        source_line: None,
        parent_names,
        nested: Vec::new(),
    }
}

fn surface_param_from_skeleton(param: &SkeletonParam) -> SurfaceParam {
    SurfaceParam {
        name: param.name.clone(),
        annotation: param.annotation.clone(),
        default: None,
        star: ParamStar::None,
    }
}

fn parent_names_from_qualname(qualname: &str) -> Vec<String> {
    let parts: Vec<&str> = qualname.split(".<locals>.").collect();
    if parts.len() <= 1 {
        return Vec::new();
    }
    parts[..parts.len() - 1]
        .iter()
        .map(|part: &&str| part.rsplit('.').next().unwrap_or(*part).to_owned())
        .collect()
}

fn skeleton_only_source_index(index: usize) -> u32 {
    1_000_000u32.saturating_add(u32::try_from(index).unwrap_or(u32::MAX - 1_000_000))
}

fn sanitize_fn_name(name: &str) -> String {
    name.replace("$$$", "__").replace('$', "_")
}

fn render_signature(function: &SurfaceFunction) -> String {
    let mut sig: String = format!("def {}(", sanitize_fn_name(&function.name));
    for (i, param) in function.params.iter().enumerate() {
        if i > 0 {
            sig.push_str(", ");
        }
        match param.star {
            ParamStar::Args => sig.push('*'),
            ParamStar::Kwargs => sig.push_str("**"),
            ParamStar::None => {}
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

fn any_body_lifted(funcs: &[SurfaceFunction]) -> bool {
    funcs
        .iter()
        .any(|f: &SurfaceFunction| !f.body_stmts.is_empty() || any_body_lifted(&f.nested))
}

fn emit_function(function: &SurfaceFunction, indent: usize, out: &mut String) {
    let prefix: String = emit_indent(indent);
    out.push_str(&prefix);
    out.push_str(&render_signature(function));
    out.push('\n');
    if let Some(doc) = &function.docstring {
        out.push_str(&emit_indent(indent + 1));
        out.push_str(&py_docstring(doc));
        out.push('\n');
    }
    let mut body_text: String = String::new();
    for stmt in &function.body_stmts {
        body_text.push_str(&emit_stmt(stmt, indent + 1));
    }
    let body_emittable: bool =
        !function.body_stmts.is_empty() && !body_text.contains("UNRESOLVED:");
    let empty: bool = !body_emittable && function.nested.is_empty();
    if empty {
        out.push_str(&emit_indent(indent + 1));
        out.push_str("...  # disrobe: body not recovered\n");
        return;
    }
    for (i, nested) in function.nested.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_function(nested, indent + 1, out);
    }
    if !function.nested.is_empty() && body_emittable {
        out.push('\n');
    }
    if body_emittable {
        out.push_str(&body_text);
    } else if function.nested.is_empty() {
        out.push_str(&emit_indent(indent + 1));
        out.push_str("...  # disrobe: body not recovered\n");
    }
}

#[must_use]
pub fn emit_python(module: &SurfaceModule) -> String {
    let mut out: String = String::new();
    if any_body_lifted(&module.functions) {
        out.push_str("# Recovered by disrobe (bodies partially lifted from Nuitka-generated C).\n");
    } else {
        out.push_str("# Recovered by disrobe (surface skeleton; bodies not lifted).\n");
    }
    out.push_str("from __future__ import annotations\n\n");

    for (i, function) in module.functions.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_function(function, 0, &mut out);
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
            format!(
                "{} {} {}",
                emit_operand(left),
                op.symbol(),
                emit_operand(right)
            )
        }
        PythonExpr::UnaryOp { op, operand } => {
            format!("{}{}", op.symbol(), emit_operand(operand))
        }
        PythonExpr::Compare { op, left, right } => {
            format!(
                "{} {} {}",
                emit_operand(left),
                op.symbol(),
                emit_operand(right)
            )
        }
        PythonExpr::BoolOp { op, left, right } => {
            format!(
                "{} {} {}",
                emit_operand(left),
                op.keyword(),
                emit_operand(right)
            )
        }
        PythonExpr::IfExp { test, body, orelse } => {
            format!(
                "{} if {} else {}",
                emit_operand(body),
                emit_operand(test),
                emit_operand(orelse)
            )
        }
        PythonExpr::Attribute { value, attr } => {
            format!("{}.{attr}", emit_operand(value))
        }
        PythonExpr::Subscript { value, index } => {
            format!("{}[{}]", emit_operand(value), emit_expr(index))
        }
        PythonExpr::Dict(pairs) => {
            let inner: String = pairs
                .iter()
                .map(|(k, v): &(PythonExpr, PythonExpr)| {
                    format!("{}: {}", emit_expr(k), emit_expr(v))
                })
                .collect::<Vec<String>>()
                .join(", ");
            format!("{{{inner}}}")
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
        PythonExpr::ListComp {
            element,
            target,
            iter,
        } => {
            format!(
                "[{} for {target} in {}]",
                emit_expr(element),
                emit_expr(iter)
            )
        }
        PythonExpr::DictComp {
            key,
            value,
            target,
            iter,
        } => {
            format!(
                "{{{}: {} for {target} in {}}}",
                emit_expr(key),
                emit_expr(value),
                emit_expr(iter)
            )
        }
        PythonExpr::SetComp {
            element,
            target,
            iter,
        } => {
            format!(
                "{{{} for {target} in {}}}",
                emit_expr(element),
                emit_expr(iter)
            )
        }
    }
}

fn emit_operand(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::BinOp { .. }
        | PythonExpr::Compare { .. }
        | PythonExpr::UnaryOp { .. }
        | PythonExpr::BoolOp { .. }
        | PythonExpr::IfExp { .. } => {
            format!("({})", emit_expr(expr))
        }
        other => emit_expr(other),
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
        PythonStmt::While { test, body } => {
            let mut out: String = format!("{prefix}while {}:\n", emit_expr(test));
            for s in body {
                out.push_str(&emit_stmt(s, indent + 1));
            }
            out
        }
        PythonStmt::Break => format!("{prefix}break\n"),
        PythonStmt::Continue => format!("{prefix}continue\n"),
        PythonStmt::Yield(e) => format!("{prefix}yield {}\n", emit_expr(e)),
        PythonStmt::Try { body, handlers } => {
            let mut out: String = format!("{prefix}try:\n");
            for s in body {
                out.push_str(&emit_stmt(s, indent + 1));
            }
            for handler in handlers {
                out.push_str(&prefix);
                let clause: String = match (&handler.exc_type, &handler.name) {
                    (Some(ty), Some(name)) => format!("except {ty} as {name}:\n"),
                    (Some(ty), None) => format!("except {ty}:\n"),
                    (None, _) => "except:\n".to_owned(),
                };
                out.push_str(&clause);
                if handler.body.is_empty() {
                    out.push_str(&emit_indent(indent + 1));
                    out.push_str("pass\n");
                } else {
                    for s in &handler.body {
                        out.push_str(&emit_stmt(s, indent + 1));
                    }
                }
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

    #[test]
    fn names_only_uses_skeleton_signatures_when_available() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        graph.impl_functions.push(crate::symbols::ImpFunction {
            identifier: "hello$$$function__1_greet".to_owned(),
            demangled: demangle_function("impl_hello$$$function__1_greet"),
        });
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        let skeleton: SkeletonModule = SkeletonModule {
            name: "hello".to_owned(),
            filename: None,
            docstring: None,
            functions: vec![SkeletonFunction {
                name: "greet".to_owned(),
                qualname: "greet".to_owned(),
                params: vec![SkeletonParam {
                    name: "name".to_owned(),
                    annotation: Some("str".to_owned()),
                }],
                return_annotation: Some("str".to_owned()),
                kind: crate::const_blob::CodeKind::Function,
                nested: false,
                from_annotations: true,
            }],
            constant_names: Vec::new(),
            python: String::new(),
            from_code_objects: true,
        };
        let s: SurfaceModule =
            build_surface_names_only_with_skeleton(&graph, &pool, Some(&skeleton));
        assert_eq!(s.fidelity, SurfaceFidelity::NamesOnly);
        assert_eq!(s.functions.len(), 1);
        let greet: &SurfaceFunction = &s.functions[0];
        assert_eq!(greet.params.len(), 1);
        assert_eq!(greet.params[0].name, "name");
        assert_eq!(greet.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(greet.return_annotation.as_deref(), Some("str"));
        assert!(s.python_source.contains("def greet(name: str) -> str:"));
    }

    #[test]
    fn names_only_uses_skeleton_qualnames_for_nested_functions() {
        let graph: SymbolGraph = SymbolGraph::default();
        let pool: ConstantsPool = ConstantsPool::default();
        let skeleton: SkeletonModule = SkeletonModule {
            name: "nested".to_owned(),
            filename: None,
            docstring: None,
            functions: vec![
                SkeletonFunction {
                    name: "outer".to_owned(),
                    qualname: "outer".to_owned(),
                    params: Vec::new(),
                    return_annotation: None,
                    kind: crate::const_blob::CodeKind::Function,
                    nested: false,
                    from_annotations: false,
                },
                SkeletonFunction {
                    name: "inner".to_owned(),
                    qualname: "outer.<locals>.inner".to_owned(),
                    params: vec![SkeletonParam {
                        name: "x".to_owned(),
                        annotation: Some("int".to_owned()),
                    }],
                    return_annotation: Some("int".to_owned()),
                    kind: crate::const_blob::CodeKind::Function,
                    nested: true,
                    from_annotations: true,
                },
            ],
            constant_names: Vec::new(),
            python: String::new(),
            from_code_objects: true,
        };
        let s: SurfaceModule =
            build_surface_names_only_with_skeleton(&graph, &pool, Some(&skeleton));
        assert_eq!(s.functions.len(), 1);
        assert_eq!(s.functions[0].name, "outer");
        assert_eq!(s.functions[0].nested.len(), 1);
        assert_eq!(s.functions[0].nested[0].name, "inner");
        assert_eq!(
            s.functions[0].nested[0].params[0].annotation.as_deref(),
            Some("int")
        );
        assert!(s.python_source.contains("    def inner(x: int) -> int:"));
    }
}
