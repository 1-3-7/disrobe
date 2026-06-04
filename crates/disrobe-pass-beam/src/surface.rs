use serde::{Deserialize, Serialize};

use crate::core_erlang::{CoreFunction, CoreModule};
use crate::dbgi::DebugInfo;
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
    let module: String = beam
        .module_name()
        .ok_or(Error::MissingChunk("Atom (module name)"))?
        .to_owned();
    if let Some(dbgi) = &beam.chunks.dbgi {
        let info: DebugInfo = crate::dbgi::parse(&dbgi.term)?;
        match &info {
            DebugInfo::ErlangAbstractCode { forms, .. } => {
                let core: CoreModule = crate::core_erlang::lift(beam)?;
                let source: String = render_abstract_forms(&module, forms, &core);
                return Ok(ErlangSurface {
                    module,
                    source,
                    recovered_from: RecoverySource::AbstractCode,
                });
            }
            DebugInfo::ElixirV1 { .. } => {
                let recovered: crate::elixir::ElixirRecovery =
                    crate::elixir::recover(&module, &info)?;
                return Ok(ErlangSurface {
                    module,
                    source: recovered.source,
                    recovered_from: RecoverySource::ElixirDbgiForm,
                });
            }
            DebugInfo::Other(_) => {}
        }
    }
    let core: CoreModule = crate::core_erlang::lift(beam)?;
    let source: String = render_from_core(&core);
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
                let arity: u32 = small_int(&tuple[3]).unwrap_or(0);
                if let Some(f) = core
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

fn render_from_core(core: &CoreModule) -> String {
    let mut out: String = String::new();
    out.push_str("-module(");
    out.push_str(&core.module);
    out.push_str(").\n");
    if !core.exports.is_empty() {
        out.push_str("-export([");
        let parts: Vec<String> = core
            .exports
            .iter()
            .map(|(n, a): &(String, u32)| format!("{n}/{a}"))
            .collect();
        out.push_str(&parts.join(", "));
        out.push_str("]).\n");
    }
    for (m, n, a) in &core.imports {
        out.push_str(&format!("-import({m}, [{n}/{a}]).\n"));
    }
    for f in &core.functions {
        render_function(&mut out, f);
    }
    out
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
