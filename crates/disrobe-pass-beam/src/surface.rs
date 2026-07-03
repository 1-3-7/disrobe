use serde::{Deserialize, Serialize};

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
