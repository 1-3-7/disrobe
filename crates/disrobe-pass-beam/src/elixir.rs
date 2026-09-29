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
    pub required: bool,
}

enum ModuleShape {
    Plain,
    Protocol { fallback_to_any: bool },
    Implementation { protocol: String, target: String },
}

impl ModuleShape {
    fn of(attributes: &[(String, Term)]) -> Self {
        let find = |key: &str| -> Option<&Term> {
            attributes
                .iter()
                .find_map(|(name, value): &(String, Term)| (name == key).then_some(value))
        };
        if let Some(protocol) = find("__protocol__") {
            return Self::Protocol {
                fallback_to_any: keyword_atom(protocol, "fallback_to_any") == Some("true"),
            };
        }
        if let Some(implementation) = find("__impl__")
            && let Some(protocol) = keyword_atom(implementation, "protocol")
            && let Some(target) = keyword_atom(implementation, "for")
        {
            return Self::Implementation {
                protocol: elixir_quoted::strip_module_prefix(protocol),
                target: elixir_quoted::strip_module_prefix(target),
            };
        }
        Self::Plain
    }

    fn generated_attribute(&self, name: &str) -> bool {
        match self {
            Self::Plain => false,
            Self::Protocol { .. } => {
                matches!(name, "__protocol__" | "behaviour" | "dialyzer" | "callback")
            }
            Self::Implementation { .. } => matches!(name, "__impl__" | "behaviour"),
        }
    }

    fn generated_definition(&self, name: &str, arity: u32) -> bool {
        match self {
            Self::Plain => false,
            Self::Protocol { .. } => {
                arity == 1
                    && matches!(
                        name,
                        "__protocol__"
                            | "impl_for"
                            | "impl_for!"
                            | "struct_impl_for"
                            | "behaviour_info"
                    )
            }
            Self::Implementation { .. } => name == "__impl__" && arity == 1,
        }
    }
}

fn keyword_atom<'a>(list: &'a Term, key: &str) -> Option<&'a str> {
    list.as_list()?.iter().find_map(|entry: &Term| {
        let pair: &[Term] = entry.as_tuple()?;
        match pair {
            [k, v] if k.as_atom() == Some(key) => v.as_atom(),
            _ => None,
        }
    })
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
    let mut default_stubs: Vec<DefaultStub> = Vec::new();

    if let Term::Tuple(t) = metadata {
        for item in t {
            scan_for_defs_and_attrs(
                item,
                &mut attributes,
                &mut definitions,
                &mut default_stubs,
                0,
            );
        }
    } else {
        scan_for_defs_and_attrs(
            metadata,
            &mut attributes,
            &mut definitions,
            &mut default_stubs,
            0,
        );
    }

    let mut struct_fields: Vec<StructField> = capture_struct_fields(metadata);
    let enforced_keys: Vec<String> = find_enforced_keys(metadata, 0).unwrap_or_default();
    for field in &mut struct_fields {
        field.required = enforced_keys.contains(&field.name);
    }
    let module_doc: Option<String> = docs.and_then(|d: &ModuleDocs| d.module_doc.clone());

    if let Some(docs) = docs {
        for def in &mut definitions {
            def.doc = docs.function_doc(&def.name, def.arity).map(str::to_owned);
        }
    }

    let module_name: String = elixir_quoted::strip_module_prefix(module_atom);
    let shape: ModuleShape = ModuleShape::of(&attributes);
    let mut src: String = String::new();
    match &shape {
        ModuleShape::Protocol { .. } => {
            src.push_str("defprotocol ");
            src.push_str(&module_name);
        }
        ModuleShape::Implementation { protocol, target } => {
            src.push_str("defimpl ");
            src.push_str(protocol);
            src.push_str(", for: ");
            src.push_str(target);
        }
        ModuleShape::Plain => {
            src.push_str("defmodule ");
            src.push_str(&module_name);
        }
    }
    src.push_str(" do\n");
    if let Some(doc) = &module_doc {
        push_doc(&mut src, "moduledoc", doc, 1);
    }
    if matches!(
        shape,
        ModuleShape::Protocol {
            fallback_to_any: true
        }
    ) {
        src.push_str("  @fallback_to_any true\n");
    }
    let enforced: Vec<String> = struct_fields
        .iter()
        .filter(|f: &&StructField| f.required)
        .map(|f: &StructField| format!(":{}", f.name))
        .collect();
    if !enforced.is_empty() {
        src.push_str("  @enforce_keys [");
        src.push_str(&enforced.join(", "));
        src.push_str("]\n");
    }
    if !struct_fields.is_empty() {
        src.push_str("  defstruct ");
        src.push_str(&render_struct_fields(&struct_fields));
        src.push('\n');
    }
    for (name, term) in &attributes {
        if shape.generated_attribute(name) {
            continue;
        }
        if matches!(name.as_str(), "moduledoc" | "doc" | "typedoc")
            && let Some(text) = term.as_str()
        {
            push_doc(&mut src, name, &text, 1);
            continue;
        }
        src.push_str("  @");
        src.push_str(name);
        src.push(' ');
        src.push_str(&elixir_quoted::render_value(term));
        src.push('\n');
    }
    for def in &definitions {
        if shape.generated_definition(&def.name, def.arity)
            || (!struct_fields.is_empty() && def.name == "__struct__" && def.arity <= 1)
        {
            continue;
        }
        if let Some(doc) = &def.doc {
            push_doc(&mut src, "doc", doc, 1);
        }
        if let Some(head) = default_head(def, &default_stubs) {
            src.push_str("  ");
            src.push_str(&head);
            src.push('\n');
        }
        if matches!(shape, ModuleShape::Protocol { .. }) {
            let params: Vec<String> = (1..=def.arity).map(|i: u32| format!("arg{i}")).collect();
            src.push_str(&format!("  def {}({})\n", def.name, params.join(", ")));
            continue;
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
            required: false,
        });
    }
    out
}

fn find_enforced_keys(term: &Term, depth: u32) -> Option<Vec<String>> {
    if depth >= MAX_SCAN_DEPTH {
        return None;
    }
    match term {
        Term::Map(map) => map.get("definitions")?.as_list()?.iter().find_map(|d: &Term| {
            let def: &[Term] = d.as_tuple()?;
            let head: &[Term] = def.first()?.as_tuple()?;
            let is_builder: bool = matches!(head, [name, Term::SmallInt(1)] if name.as_atom() == Some("__struct__"));
            if is_builder {
                enforced_keys_in(d, 0)
            } else {
                None
            }
        }),
        Term::Tuple(items) => items
            .iter()
            .find_map(|e: &Term| find_enforced_keys(e, depth + 1)),
        _ => None,
    }
}

fn enforced_keys_in(term: &Term, depth: u32) -> Option<Vec<String>> {
    if depth >= MAX_SCAN_DEPTH {
        return None;
    }
    match term {
        Term::Tuple(items) => {
            if let [literal, keys] = items.as_slice()
                && literal.as_tuple().is_some_and(|t: &[Term]| {
                    matches!(t.first().and_then(Term::as_atom), Some("%" | "%{}"))
                })
            {
                let listed: Option<Vec<String>> = match keys {
                    Term::Nil => Some(Vec::new()),
                    Term::List { elements, .. } => elements
                        .iter()
                        .map(|k: &Term| k.as_atom().map(str::to_owned))
                        .collect(),
                    _ => None,
                };
                if listed.is_some() {
                    return listed;
                }
            }
            items
                .iter()
                .find_map(|e: &Term| enforced_keys_in(e, depth + 1))
        }
        Term::List { elements, .. } => elements
            .iter()
            .find_map(|e: &Term| enforced_keys_in(e, depth + 1)),
        _ => None,
    }
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
                keyed.push(format!("{}: {}", f.name, elixir_quoted::render_value(d)));
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
            out.push_str(
                &line
                    .replace('\\', "\\\\")
                    .replace("#{", "\\#{")
                    .replace("\"\"\"", "\\\"\"\""),
            );
            out.push('\n');
        }
        out.push_str(&pad);
        out.push_str("\"\"\"\n");
    } else {
        out.push(' ');
        out.push_str(&elixir_quoted::render_value(&Term::Binary(
            text.as_bytes().to_vec(),
        )));
        out.push('\n');
    }
}

const MAX_SCAN_DEPTH: u32 = 256;

struct DefaultStub {
    name: String,
    arity: u32,
    defaults: Vec<Term>,
}

fn default_head(def: &ElixirDefinition, stubs: &[DefaultStub]) -> Option<String> {
    let shortest: &DefaultStub = stubs
        .iter()
        .filter(|s: &&DefaultStub| {
            s.name == def.name
                && def
                    .arity
                    .checked_sub(s.arity)
                    .and_then(|gap: u32| usize::try_from(gap).ok())
                    == Some(s.defaults.len())
        })
        .min_by_key(|s: &&DefaultStub| s.arity)?;
    let required: usize = usize::try_from(shortest.arity).ok()?;
    let mut params: Vec<String> = (1..=required).map(|i: usize| format!("arg{i}")).collect();
    for (offset, default) in shortest.defaults.iter().enumerate() {
        params.push(format!(
            "arg{} \\\\ {}",
            required + offset + 1,
            elixir_quoted::render_block(default)
        ));
    }
    Some(format!("{} {}({})", def.kind, def.name, params.join(", ")))
}

fn default_stub(name: &str, arity: u32, clauses: &[Term]) -> Option<DefaultStub> {
    let [clause] = clauses else {
        return None;
    };
    let body: &[Term] = clause.as_tuple()?.get(3)?.as_tuple()?;
    let [callee, _, args] = body else {
        return None;
    };
    if callee.as_atom() != Some("super") {
        return None;
    }
    let args: &[Term] = args.as_list()?;
    let supplied: usize = usize::try_from(arity).ok()?;
    let defaults: &[Term] = args.get(supplied..)?;
    (!defaults.is_empty()).then(|| DefaultStub {
        name: name.to_owned(),
        arity,
        defaults: defaults.to_vec(),
    })
}

fn scan_for_defs_and_attrs(
    term: &Term,
    attributes: &mut Vec<(String, Term)>,
    definitions: &mut Vec<ElixirDefinition>,
    default_stubs: &mut Vec<DefaultStub>,
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
                    try_capture_definition(d, definitions, default_stubs);
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
                scan_for_defs_and_attrs(e, attributes, definitions, default_stubs, depth + 1);
            }
        }
        Term::Tuple(t) => {
            for e in t {
                scan_for_defs_and_attrs(e, attributes, definitions, default_stubs, depth + 1);
            }
        }
        _ => {}
    }
}

fn try_capture_definition(
    term: &Term,
    out: &mut Vec<ElixirDefinition>,
    default_stubs: &mut Vec<DefaultStub>,
) {
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
    if let Some(stub) = tuple
        .get(3)
        .and_then(Term::as_list)
        .and_then(|list: &[Term]| default_stub(name, arity, list))
    {
        default_stubs.push(stub);
        return;
    }
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
