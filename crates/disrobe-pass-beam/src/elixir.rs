use serde::{Deserialize, Serialize};

use crate::dbgi::DebugInfo;
use crate::docs::ModuleDocs;
use crate::elixir_quoted::{self, QuotedClause};
use crate::error::{Error, Result};
use crate::etf::Term;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElixirRecovery {
    pub module: String,
    pub backend: String,
    pub attributes: Vec<(String, Term)>,
    pub struct_fields: Vec<StructField>,
    pub module_doc: Option<String>,
    pub definitions: Vec<ElixirDefinition>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub default: Option<Term>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElixirDefinition {
    pub kind: String,
    pub name: String,
    pub arity: u32,
    pub doc: Option<String>,
    pub clauses: Vec<String>,
}

pub fn recover(module_atom: &str, info: &DebugInfo) -> Result<ElixirRecovery> {
    recover_with_docs(module_atom, info, None)
}

pub fn recover_with_docs(
    module_atom: &str,
    info: &DebugInfo,
    docs: Option<&ModuleDocs>,
) -> Result<ElixirRecovery> {
    let (backend, metadata): (&str, &Term) = match info {
        DebugInfo::ElixirV1 { backend, metadata } => (backend.as_str(), metadata),
        _ => return Err(Error::NotElixirDbgi("not ElixirV1 debug_info".to_owned())),
    };
    let mut attributes: Vec<(String, Term)> = Vec::new();
    let mut definitions: Vec<ElixirDefinition> = Vec::new();

    if let Term::Tuple(t) = metadata {
        for item in t {
            scan_for_defs_and_attrs(item, &mut attributes, &mut definitions, 0);
        }
    } else {
        scan_for_defs_and_attrs(metadata, &mut attributes, &mut definitions, 0);
    }

    let struct_fields: Vec<StructField> = capture_struct_fields(metadata);
    let module_doc: Option<String> = docs.and_then(|d: &ModuleDocs| d.module_doc.clone());

    if let Some(docs) = docs {
        for def in &mut definitions {
            def.doc = docs.function_doc(&def.name, def.arity).map(str::to_owned);
        }
    }

    let module_name: String = elixir_quoted::strip_module_prefix(module_atom);
    let mut src: String = String::new();
    src.push_str("defmodule ");
    src.push_str(&module_name);
    src.push_str(" do\n");
    if let Some(doc) = &module_doc {
        push_doc(&mut src, "moduledoc", doc, 1);
    }
    if !struct_fields.is_empty() {
        src.push_str("  defstruct ");
        src.push_str(&render_struct_fields(&struct_fields));
        src.push('\n');
    }
    for (name, term) in &attributes {
        if matches!(name.as_str(), "moduledoc" | "doc" | "typedoc")
            && let Some(text) = term.as_str()
        {
            src.push_str("  @");
            src.push_str(name);
            src.push_str(" \"\"\"\n");
            for line in text.lines() {
                src.push_str("  ");
                src.push_str(line);
                src.push('\n');
            }
            src.push_str("  \"\"\"\n");
            continue;
        }
        src.push_str("  @");
        src.push_str(name);
        src.push(' ');
        src.push_str(&render_term_inline(term, 0));
        src.push('\n');
    }
    for def in &definitions {
        if let Some(doc) = &def.doc {
            push_doc(&mut src, "doc", doc, 1);
        }
        for clause in &def.clauses {
            src.push_str("  ");
            src.push_str(clause);
            src.push('\n');
        }
    }
    src.push_str("end\n");

    Ok(ElixirRecovery {
        module: module_atom.to_owned(),
        backend: backend.to_owned(),
        attributes,
        struct_fields,
        module_doc,
        definitions,
        source: src,
    })
}

fn capture_struct_fields(metadata: &Term) -> Vec<StructField> {
    let Some(list): Option<&[Term]> = find_struct_list(metadata, 0) else {
        return Vec::new();
    };
    let mut out: Vec<StructField> = Vec::with_capacity(list.len());
    for item in list {
        let Some(map): Option<&std::collections::BTreeMap<String, Term>> = item.as_map() else {
            continue;
        };
        let Some(name): Option<&str> = map.get("field").and_then(Term::as_atom) else {
            continue;
        };
        let default: Option<Term> = map.get("default").cloned();
        out.push(StructField {
            name: name.to_owned(),
            default,
        });
    }
    out
}

fn find_struct_list(term: &Term, depth: u32) -> Option<&[Term]> {
    if depth >= MAX_SCAN_DEPTH {
        return None;
    }
    match term {
        Term::Map(map) => map.get("struct").and_then(Term::as_list),
        Term::Tuple(items) => items
            .iter()
            .find_map(|e: &Term| find_struct_list(e, depth + 1)),
        _ => None,
    }
}

fn render_struct_fields(fields: &[StructField]) -> String {
    let mut bare: Vec<String> = Vec::new();
    let mut keyed: Vec<String> = Vec::new();
    for f in fields {
        match &f.default {
            Some(d) if !matches!(d, Term::Atom(a) if a == "nil") => {
                keyed.push(format!("{}: {}", f.name, render_term_inline(d, 0)));
            }
            _ => bare.push(format!(":{}", f.name)),
        }
    }
    let mut parts: Vec<String> = bare;
    parts.extend(keyed);
    format!("[{}]", parts.join(", "))
}

fn push_doc(out: &mut String, attr: &str, text: &str, indent: usize) {
    let pad: String = "  ".repeat(indent);
    out.push_str(&pad);
    out.push('@');
    out.push_str(attr);
    if text.contains('\n') {
        out.push_str(" \"\"\"\n");
        for line in text.lines() {
            out.push_str(&pad);
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&pad);
        out.push_str("\"\"\"\n");
    } else {
        out.push_str(" \"");
        out.push_str(&text.replace('\\', "\\\\").replace('"', "\\\""));
        out.push_str("\"\n");
    }
}

const MAX_SCAN_DEPTH: u32 = 256;

fn scan_for_defs_and_attrs(
    term: &Term,
    attributes: &mut Vec<(String, Term)>,
    definitions: &mut Vec<ElixirDefinition>,
    depth: u32,
) {
    if depth >= MAX_SCAN_DEPTH {
        return;
    }
    match term {
        Term::Map(map) => {
            if let Some(defs) = map.get("definitions")
                && let Some(list) = defs.as_list()
            {
                for d in list {
                    try_capture_definition(d, definitions);
                }
            }
            if let Some(attrs) = map.get("attributes")
                && let Some(list) = attrs.as_list()
            {
                for a in list {
                    try_capture_attribute(a, attributes);
                }
            }
        }
        Term::List { elements, .. } => {
            for e in elements {
                scan_for_defs_and_attrs(e, attributes, definitions, depth + 1);
            }
        }
        Term::Tuple(t) => {
            for e in t {
                scan_for_defs_and_attrs(e, attributes, definitions, depth + 1);
            }
        }
        _ => {}
    }
}

fn try_capture_definition(term: &Term, out: &mut Vec<ElixirDefinition>) {
    let Some(tuple) = term.as_tuple() else {
        return;
    };
    if tuple.len() < 3 {
        return;
    }
    let head: &Term = &tuple[0];
    let Some(name_arity) = head.as_tuple() else {
        return;
    };
    if name_arity.len() != 2 {
        return;
    }
    let Some(name) = name_arity[0].as_atom() else {
        return;
    };
    let arity: u32 = match &name_arity[1] {
        Term::SmallInt(v) => u32::from(*v),
        Term::Int(v) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    }
    .min(crate::chunks::MAX_FUN_ARITY);
    let kind: String = tuple[1]
        .as_atom()
        .map(str::to_owned)
        .unwrap_or_else(|| "def".to_owned());
    let mut clauses: Vec<String> = Vec::new();
    if let Some(rest) = tuple.get(3)
        && let Some(list) = rest.as_list()
    {
        for clause in list {
            if let Some(rendered) = render_definition_clause(&kind, name, clause) {
                clauses.push(rendered);
            }
        }
    }
    out.push(ElixirDefinition {
        kind,
        name: name.to_owned(),
        arity,
        doc: None,
        clauses,
    });
}

fn render_definition_clause(kind: &str, name: &str, clause: &Term) -> Option<String> {
    let QuotedClause {
        params,
        guard,
        body,
    }: QuotedClause = elixir_quoted::render_clause(clause)?;
    let head: String = if params.is_empty() {
        name.to_owned()
    } else {
        format!("{name}({})", params.join(", "))
    };
    let guard_clause: String = guard.map_or_else(String::new, |g: String| format!(" when {g}"));
    let body_indented: String = body
        .lines()
        .map(|line: &str| {
            if line.is_empty() {
                String::new()
            } else {
                format!("    {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!(
        "{kind} {head}{guard_clause} do\n{body_indented}\n  end"
    ))
}

fn try_capture_attribute(term: &Term, out: &mut Vec<(String, Term)>) {
    let Some(tuple) = term.as_tuple() else {
        return;
    };
    if tuple.len() < 2 {
        return;
    }
    let Some(name) = tuple[0].as_atom() else {
        return;
    };
    out.push((name.to_owned(), tuple[1].clone()));
}

fn render_term_inline(term: &Term, depth: u32) -> String {
    if depth >= MAX_SCAN_DEPTH {
        return "...".to_owned();
    }
    match term {
        Term::Atom(a) => format!(":{a}"),
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::Float(f) => f.to_string(),
        Term::Nil => "[]".to_owned(),
        Term::Binary(b) => match core::str::from_utf8(b) {
            Ok(s) => format!("\"{s}\""),
            Err(_) => format!("<<{} bytes>>", b.len()),
        },
        Term::String(b) => match core::str::from_utf8(b) {
            Ok(s) => format!("'{s}'"),
            Err(_) => format!("<<{} bytes>>", b.len()),
        },
        Term::Tuple(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|t: &Term| render_term_inline(t, depth + 1))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Term::List { elements, .. } => {
            let parts: Vec<String> = elements
                .iter()
                .map(|t: &Term| render_term_inline(t, depth + 1))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Term::Map(m) => {
            let parts: Vec<String> = m
                .iter()
                .map(|(k, v): (&String, &Term)| {
                    format!("{k}: {}", render_term_inline(v, depth + 1))
                })
                .collect();
            format!("%{{{}}}", parts.join(", "))
        }
        Term::MapMixed(m) => {
            let parts: Vec<String> = m
                .iter()
                .map(|(k, v): &(Term, Term)| {
                    format!(
                        "{} => {}",
                        render_term_inline(k, depth + 1),
                        render_term_inline(v, depth + 1)
                    )
                })
                .collect();
            format!("%{{{}}}", parts.join(", "))
        }
        Term::BigInt { sign, magnitude_le } => {
            let hex: String = magnitude_le
                .iter()
                .rev()
                .map(|b: &u8| format!("{b:02x}"))
                .collect();
            format!("{}0x{hex}", if *sign == 0 { "" } else { "-" })
        }
        Term::BitBinary { .. } => "<<bitstring>>".to_owned(),
        Term::Pid { node, id, .. } => format!("#PID<{node}:{id}>"),
        Term::Reference { node, .. } => format!("#Ref<{node}>"),
        Term::Export {
            module,
            function,
            arity,
        } => format!("&{module}.{function}/{arity}"),
    }
}
