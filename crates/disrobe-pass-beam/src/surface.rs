use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::body_lift::expr::{AfterClause, CaseArm, CatchArm, Expr, IfArm, Stmt};
use crate::core_erlang::{CoreFunction, CoreModule};
use crate::dbgi::DebugInfo;
use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};
use crate::etf::Term;
use crate::file::BeamFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErlangSurface {
    pub module: String,
    pub source: String,
    pub recovered_from: RecoverySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoverySource {
    AbstractCode,
    ElixirDbgiForm,
    CoreLifted,
}

pub fn recover(beam: &BeamFile) -> Result<ErlangSurface> {
    dbg_section("dbgi recovery");
    let module: String = beam
        .module_name()
        .ok_or(Error::MissingChunk("Atom (module name)"))?
        .to_owned();
    dbg_kv("module", || module.clone());
    if let Some(dbgi) = &beam.chunks.dbgi {
        let info: DebugInfo = crate::dbgi::parse(&dbgi.term)?;
        match &info {
            DebugInfo::ErlangAbstractCode { forms, .. } => {
                dbg_kv("dbgi_class", || {
                    format!(
                        "erlang abstract-code ({} top-level forms)",
                        forms.as_list().map_or(0, <[Term]>::len)
                    )
                });
                let core: CoreModule = crate::core_erlang::lift(beam)?;
                let source: String = render_abstract_forms(&module, forms, &core);
                dbg_kv("erlang_emit", || {
                    format!("source_bytes={} from=abstract-code", source.len())
                });
                return Ok(ErlangSurface {
                    module,
                    source,
                    recovered_from: RecoverySource::AbstractCode,
                });
            }
            DebugInfo::ElixirV1 { backend, .. } => {
                dbg_kv("dbgi_class", || {
                    format!("elixir quoted-AST (backend={backend})")
                });
                let module_docs: Option<crate::docs::ModuleDocs> = beam
                    .chunks
                    .docs
                    .as_ref()
                    .and_then(|d| crate::docs::parse(&d.term));
                let recovered: crate::elixir::ElixirRecovery =
                    crate::elixir::recover_with_docs(&module, &info, module_docs.as_ref())?;
                dbg_kv("elixir_emit", || {
                    format!(
                        "definitions={} attributes={} struct_fields={} source_bytes={}",
                        recovered.definitions.len(),
                        recovered.attributes.len(),
                        recovered.struct_fields.len(),
                        recovered.source.len()
                    )
                });
                return Ok(ErlangSurface {
                    module,
                    source: recovered.source,
                    recovered_from: RecoverySource::ElixirDbgiForm,
                });
            }
            DebugInfo::Other(_) => {
                dbg_kv("dbgi_class", || {
                    "unrecognized debug_info term, falling back to core lift".to_owned()
                });
            }
        }
    } else {
        dbg_line(|| {
            "no Dbgi chunk: register names erased, lifting from Code with synthetic Xn params"
                .to_owned()
        });
    }
    let mut core: CoreModule = crate::core_erlang::lift(beam)?;
    crate::body_lift::comprehension::resugar_module(&mut core);
    rename_lifted_helpers(&mut core);
    let attributes: Option<&Term> = beam.chunks.attributes.as_ref().map(|a| &a.term);
    let source: String = render_from_core(&core, attributes);
    dbg_kv("core_emit", || {
        format!(
            "functions={} exports={} source_bytes={} from=core-lifted",
            core.functions.len(),
            core.exports.len(),
            source.len()
        )
    });
    Ok(ErlangSurface {
        module,
        source,
        recovered_from: RecoverySource::CoreLifted,
    })
}

fn render_abstract_forms(module: &str, forms: &Term, core: &CoreModule) -> String {
    let mut out: String = String::new();
    out.push_str("-module(");
    out.push_str(module);
    out.push_str(").\n");
    let Some(list) = forms.as_list() else {
        return out;
    };
    for form in list {
        let Some(tuple) = form.as_tuple() else {
            continue;
        };
        match tuple.first().and_then(Term::as_atom) {
            Some("attribute") if tuple.len() >= 4 => {
                let attr_name: &str = tuple[2].as_atom().unwrap_or("?");
                if attr_name == "module" || attr_name == "file" {
                    continue;
                }
                out.push('-');
                out.push_str(attr_name);
                out.push('(');
                out.push_str(&render_attr_value(attr_name, &tuple[3]));
                out.push_str(").\n");
            }
            Some("function") if tuple.len() >= 5 => {
                let name: &str = tuple[2].as_atom().unwrap_or("?");
                let arity: u32 = small_int(&tuple[3])
                    .unwrap_or(0)
                    .min(crate::chunks::MAX_FUN_ARITY);
                let clauses: Option<&[Term]> = tuple[4].as_list();
                if let Some(clauses) = clauses.filter(|c: &&[Term]| !c.is_empty()) {
                    out.push('\n');
                    out.push_str(&crate::erlang_abstract::render_function(name, clauses));
                } else if let Some(f) = core
                    .functions
                    .iter()
                    .find(|f: &&CoreFunction| f.name == name && f.arity == arity)
                {
                    render_function(&mut out, f);
                } else {
                    out.push('\n');
                    out.push_str(&render_atom_name(name));
                    out.push('(');
                    let params: Vec<String> = (0..arity).map(|i: u32| format!("X{i}")).collect();
                    out.push_str(&params.join(", "));
                    out.push_str(") ->\n    ok.\n");
                }
            }
            _ => {}
        }
    }
    out
}

fn render_attr_value(attr_name: &str, val: &Term) -> String {
    match attr_name {
        "export" | "import" => render_export_import(val),
        "module" => val.as_atom().unwrap_or("?").to_owned(),
        _ => render_inline(val),
    }
}

fn render_export_import(val: &Term) -> String {
    let Some(list) = val.as_list() else {
        return render_inline(val);
    };
    let parts: Vec<String> = list
        .iter()
        .filter_map(|t: &Term| t.as_tuple())
        .filter_map(|t: &[Term]| {
            if t.len() == 2 {
                let n: &str = t[0].as_atom()?;
                let a: u32 = small_int(&t[1])?;
                Some(format!("{n}/{a}"))
            } else {
                None
            }
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

fn render_inline(val: &Term) -> String {
    match val {
        Term::Atom(a) => a.clone(),
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::Float(f) => f.to_string(),
        Term::Nil => "[]".to_owned(),
        Term::Binary(b) => match core::str::from_utf8(b) {
            Ok(s) => format!("<<\"{s}\">>"),
            Err(_) => format!("<<{} bytes>>", b.len()),
        },
        Term::String(b) => match core::str::from_utf8(b) {
            Ok(s) => format!("\"{s}\""),
            Err(_) => format!("\"<{} bytes>\"", b.len()),
        },
        Term::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(render_inline).collect();
            format!("{{{}}}", parts.join(", "))
        }
        Term::List { elements, .. } => {
            let parts: Vec<String> = elements.iter().map(render_inline).collect();
            format!("[{}]", parts.join(", "))
        }
        _ => "<term>".to_owned(),
    }
}

fn small_int(t: &Term) -> Option<u32> {
    match t {
        Term::SmallInt(v) => Some(u32::from(*v)),
        Term::Int(v) => u32::try_from(*v).ok(),
        _ => None,
    }
}

fn is_module_info_export(name: &str, arity: u32) -> bool {
    name == "module_info" && (arity == 0 || arity == 1)
}

fn safe_helper_name(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len() * 3 + 1);
    out.push('f');
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push(byte as char);
        } else {
            out.push_str(&format!("_{byte:02x}"));
        }
    }
    out
}

fn rename_lifted_helpers(core: &mut CoreModule) {
    let mut captured: BTreeSet<String> = BTreeSet::new();
    for f in &core.functions {
        for clause in &f.clauses {
            collect_captured_stmts(&clause.body.stmts, &mut captured);
        }
    }
    if captured.is_empty() {
        return;
    }
    let mut refs: BTreeMap<String, String> = BTreeMap::new();
    let mut defs: BTreeMap<String, String> = BTreeMap::new();
    for f in &core.functions {
        if f.name.starts_with('-') {
            let quoted: String = crate::body_lift::render::render_atom(&f.name);
            if captured.contains(&quoted) {
                let safe: String = safe_helper_name(&f.name);
                refs.insert(quoted, safe.clone());
                defs.insert(f.name.clone(), safe);
            }
        }
    }
    if refs.is_empty() {
        return;
    }
    for f in &mut core.functions {
        if let Some(safe) = defs.get(&f.name) {
            f.name = safe.clone();
        }
        for clause in &mut f.clauses {
            for pattern in &mut clause.patterns {
                rename_expr(pattern, &refs);
            }
            if let Some(guard) = &mut clause.guard {
                rename_expr(guard, &refs);
            }
            rename_stmts(&mut clause.body.stmts, &refs);
        }
    }
}

fn collect_captured_stmts(stmts: &[Stmt], out: &mut BTreeSet<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Bind { pattern, value } | Stmt::Match { pattern, value } => {
                collect_captured_expr(pattern, out);
                collect_captured_expr(value, out);
            }
            Stmt::Send { dest, msg } => {
                collect_captured_expr(dest, out);
                collect_captured_expr(msg, out);
            }
            Stmt::Expr(expr) | Stmt::Return(expr) => collect_captured_expr(expr, out),
            Stmt::Comment(_) => {}
        }
    }
}

fn collect_captured_expr(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::MakeFun { name, env, .. } => {
            if !env.is_empty() {
                out.insert(name.clone());
            }
            for item in env {
                collect_captured_expr(item, out);
            }
        }
        Expr::Call { args, .. } | Expr::Guard { args, .. } => {
            for arg in args {
                collect_captured_expr(arg, out);
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                collect_captured_expr(item, out);
            }
        }
        Expr::List { elements, tail } => {
            for element in elements {
                collect_captured_expr(element, out);
            }
            collect_captured_expr(tail, out);
        }
        Expr::Cons { head, tail } => {
            collect_captured_expr(head, out);
            collect_captured_expr(tail, out);
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => {
            for (key, value) in pairs {
                collect_captured_expr(key, out);
                collect_captured_expr(value, out);
            }
        }
        Expr::MapUpdate { base, pairs, .. } => {
            collect_captured_expr(base, out);
            for (key, value) in pairs {
                collect_captured_expr(key, out);
                collect_captured_expr(value, out);
            }
        }
        Expr::TupleElement { tuple, .. } => collect_captured_expr(tuple, out),
        Expr::RecordUpdate { base, updates } => {
            collect_captured_expr(base, out);
            for (_, value) in updates {
                collect_captured_expr(value, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_captured_expr(lhs, out);
            collect_captured_expr(rhs, out);
        }
        Expr::UnOp { operand, .. } => collect_captured_expr(operand, out),
        Expr::CallFun { fun, args } => {
            collect_captured_expr(fun, out);
            for arg in args {
                collect_captured_expr(arg, out);
            }
        }
        Expr::BinaryConstruct(segments) => {
            for seg in segments {
                collect_captured_expr(&seg.value, out);
                if let Some(size) = &seg.size {
                    collect_captured_expr(size, out);
                }
            }
        }
        Expr::Catch(inner) => collect_captured_expr(inner, out),
        Expr::Case { subject, arms } => {
            collect_captured_expr(subject, out);
            for arm in arms {
                collect_captured_arm(arm, out);
            }
        }
        Expr::If { arms } => {
            for arm in arms {
                collect_captured_expr(&arm.guard, out);
                collect_captured_stmts(&arm.body, out);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms {
                collect_captured_arm(arm, out);
            }
            if let Some(after) = after {
                collect_captured_expr(&after.timeout, out);
                collect_captured_stmts(&after.body, out);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            collect_captured_stmts(body, out);
            for arm in of_arms {
                collect_captured_arm(arm, out);
            }
            for arm in catch_arms {
                collect_captured_stmts(&arm.body, out);
            }
            collect_captured_stmts(after, out);
        }
        Expr::Block(stmts) => collect_captured_stmts(stmts, out),
        Expr::Var(_)
        | Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_)
        | Expr::Raw(_) => {}
    }
}

fn collect_captured_arm(arm: &CaseArm, out: &mut BTreeSet<String>) {
    collect_captured_expr(&arm.pattern, out);
    if let Some(guard) = &arm.guard {
        collect_captured_expr(guard, out);
    }
    collect_captured_stmts(&arm.body, out);
}

fn rename_stmts(stmts: &mut [Stmt], refs: &BTreeMap<String, String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Bind { pattern, value } | Stmt::Match { pattern, value } => {
                rename_expr(pattern, refs);
                rename_expr(value, refs);
            }
            Stmt::Send { dest, msg } => {
                rename_expr(dest, refs);
                rename_expr(msg, refs);
            }
            Stmt::Expr(expr) | Stmt::Return(expr) => rename_expr(expr, refs),
            Stmt::Comment(_) => {}
        }
    }
}

fn rename_arm(arm: &mut CaseArm, refs: &BTreeMap<String, String>) {
    rename_expr(&mut arm.pattern, refs);
    if let Some(guard) = &mut arm.guard {
        rename_expr(guard, refs);
    }
    rename_stmts(&mut arm.body, refs);
}

fn rename_expr(expr: &mut Expr, refs: &BTreeMap<String, String>) {
    match expr {
        Expr::Call { target, args } => {
            if let Some(new) = refs.get(target) {
                *target = new.clone();
            }
            for arg in args {
                rename_expr(arg, refs);
            }
        }
        Expr::MakeFun { name, env, .. } => {
            if let Some(new) = refs.get(name) {
                *name = new.clone();
            }
            for item in env {
                rename_expr(item, refs);
            }
        }
        Expr::Guard { args, .. } => {
            for arg in args {
                rename_expr(arg, refs);
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                rename_expr(item, refs);
            }
        }
        Expr::List { elements, tail } => {
            for element in elements {
                rename_expr(element, refs);
            }
            rename_expr(tail, refs);
        }
        Expr::Cons { head, tail } => {
            rename_expr(head, refs);
            rename_expr(tail, refs);
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => {
            for (key, value) in pairs {
                rename_expr(key, refs);
                rename_expr(value, refs);
            }
        }
        Expr::MapUpdate { base, pairs, .. } => {
            rename_expr(base, refs);
            for (key, value) in pairs {
                rename_expr(key, refs);
                rename_expr(value, refs);
            }
        }
        Expr::TupleElement { tuple, .. } => rename_expr(tuple, refs),
        Expr::RecordUpdate { base, updates } => {
            rename_expr(base, refs);
            for (_, value) in updates {
                rename_expr(value, refs);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rename_expr(lhs, refs);
            rename_expr(rhs, refs);
        }
        Expr::UnOp { operand, .. } => rename_expr(operand, refs),
        Expr::CallFun { fun, args } => {
            rename_expr(fun, refs);
            for arg in args {
                rename_expr(arg, refs);
            }
        }
        Expr::BinaryConstruct(segments) => {
            for seg in segments {
                rename_expr(&mut seg.value, refs);
                if let Some(size) = &mut seg.size {
                    rename_expr(size, refs);
                }
            }
        }
        Expr::Catch(inner) => rename_expr(inner, refs),
        Expr::Case { subject, arms } => {
            rename_expr(subject, refs);
            for arm in arms {
                rename_arm(arm, refs);
            }
        }
        Expr::If { arms } => {
            for arm in arms {
                rename_if_arm(arm, refs);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms {
                rename_arm(arm, refs);
            }
            if let Some(after) = after {
                rename_after(after, refs);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            rename_stmts(body, refs);
            for arm in of_arms {
                rename_arm(arm, refs);
            }
            for arm in catch_arms {
                rename_catch_arm(arm, refs);
            }
            rename_stmts(after, refs);
        }
        Expr::Block(stmts) => rename_stmts(stmts, refs),
        Expr::Var(_)
        | Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_)
        | Expr::Raw(_) => {}
    }
}

fn rename_if_arm(arm: &mut IfArm, refs: &BTreeMap<String, String>) {
    rename_expr(&mut arm.guard, refs);
    rename_stmts(&mut arm.body, refs);
}

fn rename_catch_arm(arm: &mut CatchArm, refs: &BTreeMap<String, String>) {
    rename_expr(&mut arm.pattern, refs);
    rename_stmts(&mut arm.body, refs);
}

fn rename_after(after: &mut AfterClause, refs: &BTreeMap<String, String>) {
    rename_expr(&mut after.timeout, refs);
    rename_stmts(&mut after.body, refs);
}

fn render_from_core(core: &CoreModule, attributes: Option<&Term>) -> String {
    let mut out: String = String::new();
    out.push_str("-module(");
    out.push_str(&core.module);
    out.push_str(").\n");
    if let Some(attrs) = attributes {
        render_module_attributes(&mut out, attrs);
    }
    let exports: Vec<String> = core
        .exports
        .iter()
        .filter(|(n, a): &&(String, u32)| !is_module_info_export(n, *a))
        .map(|(n, a): &(String, u32)| format!("{}/{a}", render_atom_name(n)))
        .collect();
    if !exports.is_empty() {
        out.push_str("-export([");
        out.push_str(&exports.join(", "));
        out.push_str("]).\n");
    }
    for f in &core.functions {
        if is_module_info_export(&f.name, f.arity) {
            continue;
        }
        render_function(&mut out, f);
    }
    out
}

fn render_module_attributes(out: &mut String, attrs: &Term) {
    let Some(list) = attrs.as_list() else {
        return;
    };
    for attr in list {
        let Some(tuple) = attr.as_tuple() else {
            continue;
        };
        if tuple.len() != 2 {
            continue;
        }
        let Some(name) = tuple[0].as_atom() else {
            continue;
        };
        if name == "vsn" {
            continue;
        }
        let value: &Term = match tuple[1].as_list() {
            Some([single]) => single,
            _ => &tuple[1],
        };
        out.push('-');
        out.push_str(name);
        out.push('(');
        out.push_str(&render_inline(value));
        out.push_str(").\n");
    }
}

fn render_function(out: &mut String, f: &CoreFunction) {
    out.push('\n');
    let head: String = render_atom_name(&f.name);
    let clause_count: usize = f.clauses.len();
    for (i, clause) in f.clauses.iter().enumerate() {
        out.push_str(&head);
        out.push('(');
        let params: Vec<String> = if clause.patterns.len() == f.arity as usize {
            clause
                .patterns
                .iter()
                .map(crate::body_lift::render::render_expr)
                .collect()
        } else {
            (0..f.arity).map(|i: u32| format!("X{i}")).collect()
        };
        out.push_str(&params.join(", "));
        out.push(')');
        if let Some(guard) = &clause.guard {
            out.push_str(" when ");
            out.push_str(&crate::body_lift::render::render_expr(guard));
        }
        out.push_str(" ->\n");
        out.push_str(&crate::body_lift::render::render_body(
            &clause.body.stmts,
            1,
        ));
        let terminator: &str = if i + 1 == clause_count { ".\n" } else { ";\n" };
        out.push_str(terminator);
    }
}

fn render_atom_name(name: &str) -> String {
    crate::body_lift::render::render_atom(name)
}
