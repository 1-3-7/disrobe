//! Renders the Erlang abstract format (the `erl_parse` AST stored in a
//! `debug_info_v1` / `erl_abstract_code` `Dbgi` chunk) back to source.
//!
//! Clean-room reimplementation of the `erl_pp` pretty-printing contract, studied
//! from the documented `erl_parse` abstract-form grammar (no source copied). The
//! abstract code preserves original variable names, guards, records, and list/
//! binary comprehensions, so a faithful printer recovers near-original Erlang
//! when this chunk is present.

use crate::body_lift::render::render_atom;
use crate::etf::Term;

/// Renders a `{function, L, Name, Arity, Clauses}` form to a full definition.
#[must_use]
pub fn render_function(name: &str, clauses: &[Term]) -> String {
    let head: String = render_atom(name);
    let rendered: Vec<String> = clauses
        .iter()
        .map(|c: &Term| render_function_clause(&head, c))
        .collect();
    format!("{}.\n", rendered.join(";\n"))
}

fn render_function_clause(head: &str, clause: &Term) -> String {
    let Some(parts) = clause.as_tuple() else {
        return format!("{head}() ->\n    ok");
    };
    if parts.len() != 5 || parts[0].as_atom() != Some("clause") {
        return format!("{head}() ->\n    ok");
    }
    let params: Vec<String> = list(&parts[2]).iter().map(render).collect();
    let guard: String = render_guard_seq(&parts[3]);
    let body: String = render_body(&parts[4], 1);
    format!("{head}({}){guard} ->\n{body}", params.join(", "))
}

/// Renders a guard sequence `[[G11, G12], [G21], ...]`: inner lists are
/// comma-joined (conjunction), outer lists are `;`-joined (disjunction). An
/// empty sequence yields no `when`.
fn render_guard_seq(term: &Term) -> String {
    let disjuncts: Vec<Term> = list(term);
    if disjuncts.is_empty() {
        return String::new();
    }
    let rendered: Vec<String> = disjuncts
        .iter()
        .map(|conj: &Term| list(conj).iter().map(render).collect::<Vec<_>>().join(", "))
        .filter(|s: &String| !s.is_empty())
        .collect();
    if rendered.is_empty() {
        return String::new();
    }
    format!(" when {}", rendered.join("; "))
}

fn render_body(term: &Term, indent: usize) -> String {
    let stmts: Vec<Term> = list(term);
    if stmts.is_empty() {
        return format!("{}ok", pad(indent));
    }
    stmts
        .iter()
        .map(|s: &Term| format!("{}{}", pad(indent), render_indented(s, indent)))
        .collect::<Vec<_>>()
        .join(",\n")
}

fn render_indented(term: &Term, indent: usize) -> String {
    match node_kind(term) {
        Some("case") => render_case(term, indent),
        Some("if") => render_if(term, indent),
        Some("receive") => render_receive(term, indent),
        Some("try") => render_try(term, indent),
        Some("block") => render_block(term, indent),
        Some("fun") => render_fun(term, indent),
        _ => render(term),
    }
}

#[must_use]
fn render(term: &Term) -> String {
    let Some(parts) = term.as_tuple() else {
        return literal_fallback(term);
    };
    let Some(kind) = parts.first().and_then(Term::as_atom) else {
        return literal_fallback(term);
    };
    match kind {
        "atom" => render_atom(parts.get(2).and_then(Term::as_atom).unwrap_or("?")),
        "integer" => int_string(&parts[2]),
        "float" => float_string(&parts[2]),
        "char" => format!("${}", char_repr(&parts[2])),
        "string" => format!("\"{}\"", escape_str(&str_value(&parts[2]))),
        "var" => parts
            .get(2)
            .and_then(Term::as_atom)
            .unwrap_or("_")
            .to_owned(),
        "nil" => "[]".to_owned(),
        "cons" => render_cons(term),
        "tuple" => {
            let elems: Vec<String> = list(&parts[2]).iter().map(render).collect();
            format!("{{{}}}", elems.join(", "))
        }
        "map" if parts.len() == 4 => render_map(&parts[3], Some(&parts[2])),
        "map" => render_map(&parts[2], None),
        "map_field_assoc" => format!("{} => {}", render(&parts[2]), render(&parts[3])),
        "map_field_exact" => format!("{} := {}", render(&parts[2]), render(&parts[3])),
        "op" => render_op(parts),
        "call" => render_call(&parts[2], &parts[3]),
        "remote" => format!("{}:{}", render(&parts[2]), render(&parts[3])),
        "match" => format!("{} = {}", render(&parts[2]), render(&parts[3])),
        "bin" => render_bin(&parts[2]),
        "bin_element" => render_bin_element(parts),
        "lc" => format!("[{} || {}]", render(&parts[2]), render_quals(&parts[3])),
        "bc" => format!("<< {} || {} >>", render(&parts[2]), render_quals(&parts[3])),
        "mc" => format!("#{{{} || {}}}", render(&parts[2]), render_quals(&parts[3])),
        "generate" => format!("{} <- {}", render(&parts[2]), render(&parts[3])),
        "b_generate" => format!("{} <= {}", render(&parts[2]), render(&parts[3])),
        "m_generate" => format!("{} <- {}", render(&parts[2]), render(&parts[3])),
        "record" => render_record(parts),
        "record_index" => format!("#{}.{}", atom_at(parts, 2), atom_at(parts, 3)),
        "record_field" => render_record_field(parts),
        "case" => render_case(term, 0),
        "if" => render_if(term, 0),
        "receive" => render_receive(term, 0),
        "try" => render_try(term, 0),
        "block" => render_block(term, 0),
        "fun" => render_fun(term, 0),
        "named_fun" => render_fun(term, 0),
        "catch" => format!("catch {}", render(&parts[2])),
        _ => literal_fallback(term),
    }
}

fn render_op(parts: &[Term]) -> String {
    let op: &str = parts.get(2).and_then(Term::as_atom).unwrap_or("?");
    if parts.len() == 5 {
        let prec: u8 = binary_op_prec(op);
        return format!(
            "{} {op} {}",
            render_operand(&parts[3], prec),
            render_operand(&parts[4], prec.saturating_sub(1))
        );
    }
    if parts.len() == 4 {
        let sep: &str = if op.len() > 1 { " " } else { "" };
        return format!("{op}{sep}{}", render_operand(&parts[3], 9));
    }
    "?".to_owned()
}

/// Erlang binary-operator precedence (higher binds tighter), used to drop
/// redundant parentheses so `X rem 2 =:= 1` does not become `(X rem 2) =:= 1`.
fn binary_op_prec(op: &str) -> u8 {
    match op {
        "orelse" => 2,
        "andalso" => 3,
        "==" | "/=" | "=<" | "<" | ">=" | ">" | "=:=" | "=/=" => 4,
        "++" | "--" => 5,
        "+" | "-" | "bor" | "bxor" | "bsl" | "bsr" | "or" | "xor" => 6,
        "*" | "/" | "div" | "rem" | "band" | "and" => 7,
        _ => 4,
    }
}

fn render_operand(term: &Term, parent_prec: u8) -> String {
    if node_kind(term) == Some("op")
        && let Some(parts) = term.as_tuple()
        && parts.len() == 5
        && let Some(op) = parts.get(2).and_then(Term::as_atom)
        && binary_op_prec(op) < parent_prec
    {
        return format!("({})", render(term));
    }
    render(term)
}

fn render_call(target: &Term, args: &Term) -> String {
    let rendered: Vec<String> = list(args).iter().map(render).collect();
    format!("{}({})", render_callee(target), rendered.join(", "))
}

fn render_callee(target: &Term) -> String {
    match node_kind(target) {
        Some("remote" | "atom" | "var") => render(target),
        _ => format!("({})", render(target)),
    }
}

fn render_cons(term: &Term) -> String {
    let mut elements: Vec<String> = Vec::new();
    let mut current: Term = term.clone();
    loop {
        let Some(parts) = current.as_tuple() else {
            return format!("[{} | {}]", elements.join(", "), render(&current));
        };
        match parts.first().and_then(Term::as_atom) {
            Some("cons") if parts.len() == 4 => {
                elements.push(render(&parts[2]));
                current = parts[3].clone();
            }
            Some("nil") => return format!("[{}]", elements.join(", ")),
            _ => {
                return format!("[{} | {}]", elements.join(", "), render(&current));
            }
        }
    }
}

fn render_map(fields: &Term, base: Option<&Term>) -> String {
    let rendered: Vec<String> = list(fields).iter().map(render).collect();
    let prefix: String = base.map_or_else(String::new, |b: &Term| match node_kind(b) {
        Some("var" | "atom" | "map" | "record" | "call" | "tuple" | "nil") => render(b),
        _ => format!("({})", render(b)),
    });
    format!("{prefix}#{{{}}}", rendered.join(", "))
}

fn render_record(parts: &[Term]) -> String {
    if parts.len() == 5 {
        let base: String = render(&parts[2]);
        let name: String = atom_at(parts, 3);
        let fields: String = render_record_fields(&parts[4]);
        return format!("{base}#{name}{{{fields}}}");
    }
    if parts.len() == 4 {
        let name: String = atom_at(parts, 2);
        let fields: String = render_record_fields(&parts[3]);
        return format!("#{name}{{{fields}}}");
    }
    "?".to_owned()
}

fn render_record_fields(term: &Term) -> String {
    list(term)
        .iter()
        .map(|f: &Term| {
            let Some(p) = f.as_tuple() else {
                return render(f);
            };
            if p.first().and_then(Term::as_atom) == Some("record_field") && p.len() >= 4 {
                return format!("{} = {}", render(&p[2]), render(&p[3]));
            }
            render(f)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_record_field(parts: &[Term]) -> String {
    if parts.len() == 5 {
        return format!(
            "{}#{}.{}",
            render(&parts[2]),
            atom_at(parts, 3),
            atom_at(parts, 4)
        );
    }
    if parts.len() == 4 {
        return format!("{} = {}", render(&parts[2]), render(&parts[3]));
    }
    "?".to_owned()
}

fn render_quals(term: &Term) -> String {
    list(term).iter().map(render).collect::<Vec<_>>().join(", ")
}

fn render_bin(segments: &Term) -> String {
    let rendered: Vec<String> = list(segments).iter().map(render).collect();
    format!("<<{}>>", rendered.join(", "))
}

fn render_bin_element(parts: &[Term]) -> String {
    if parts.len() < 5 {
        return "?".to_owned();
    }
    let mut out: String = render_bin_value(&parts[2]);
    let size_absent: bool = matches!(&parts[3], Term::Atom(a) if a == "default");
    if !size_absent {
        out.push(':');
        match node_kind(&parts[3]) {
            Some("integer" | "var") => out.push_str(&render(&parts[3])),
            _ => out.push_str(&format!("({})", render(&parts[3]))),
        }
    }
    let specs: Vec<String> = match &parts[4] {
        Term::Atom(a) if a == "default" => Vec::new(),
        other => list(other)
            .iter()
            .map(render_type_spec)
            .filter(|s: &String| !s.is_empty() && s != "default")
            .collect(),
    };
    if !specs.is_empty() {
        out.push('/');
        out.push_str(&specs.join("-"));
    }
    out
}

/// Binary-segment values must be primaries; a bare string literal in a segment
/// is the original `<<"GIF87a", ...>>` charlist surface.
fn render_bin_value(term: &Term) -> String {
    match node_kind(term) {
        Some("op") => format!("({})", render(term)),
        _ => render(term),
    }
}

fn render_type_spec(term: &Term) -> String {
    match term {
        Term::Atom(a) => a.clone(),
        Term::Tuple(t) if t.len() == 2 => {
            format!(
                "{}:{}",
                t[0].as_atom().unwrap_or("?"),
                int_string_inner(&t[1])
            )
        }
        _ => String::new(),
    }
}

fn render_case(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "case ?".to_owned();
    };
    let subject: String = render(&parts[2]);
    let arms: String = render_clauses(&parts[3], indent + 1, ClauseStyle::Case);
    format!("case {subject} of\n{arms}\n{}end", pad(indent))
}

fn render_if(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "if ?".to_owned();
    };
    let arms: String = render_clauses(&parts[2], indent + 1, ClauseStyle::If);
    format!("if\n{arms}\n{}end", pad(indent))
}

fn render_receive(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "receive ?".to_owned();
    };
    let arms: String = render_clauses(&parts[2], indent + 1, ClauseStyle::Case);
    let mut out: String = format!("receive\n{arms}");
    if parts.len() == 5 {
        let after: String = render(&parts[3]);
        let after_body: String = render_body(&parts[4], indent + 1);
        out.push_str(&format!("\n{}after {after} ->\n{after_body}", pad(indent)));
    }
    out.push_str(&format!("\n{}end", pad(indent)));
    out
}

fn render_try(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "try ?".to_owned();
    };
    let body: String = render_body(&parts[2], indent + 1);
    let mut out: String = format!("try\n{body}");
    let of_clauses: Vec<Term> = list(&parts[3]);
    if !of_clauses.is_empty() {
        out.push_str(&format!("\n{}of\n", pad(indent)));
        out.push_str(&render_clauses(&parts[3], indent + 1, ClauseStyle::Case));
    }
    let catch_clauses: Vec<Term> = list(&parts[4]);
    if !catch_clauses.is_empty() {
        out.push_str(&format!("\n{}catch\n", pad(indent)));
        out.push_str(&render_clauses(&parts[4], indent + 1, ClauseStyle::Catch));
    }
    let after: Vec<Term> = list(&parts[5]);
    if !after.is_empty() {
        out.push_str(&format!("\n{}after\n", pad(indent)));
        out.push_str(&render_body(&parts[5], indent + 1));
    }
    out.push_str(&format!("\n{}end", pad(indent)));
    out
}

fn render_block(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "begin ? end".to_owned();
    };
    let body: String = render_body(&parts[2], indent + 1);
    format!("begin\n{body}\n{}end", pad(indent))
}

fn render_fun(term: &Term, indent: usize) -> String {
    let Some(parts) = term.as_tuple() else {
        return "fun ? end".to_owned();
    };
    if parts.len() == 3
        && let Some(inner) = parts[2].as_tuple()
    {
        match inner.first().and_then(Term::as_atom) {
            Some("function") if inner.len() == 3 => {
                return format!(
                    "fun {}/{}",
                    render_atom(inner[1].as_atom().unwrap_or("?")),
                    int_string_inner(&inner[2])
                );
            }
            Some("function") if inner.len() == 4 => {
                return format!(
                    "fun {}:{}/{}",
                    render(&inner[1]),
                    render(&inner[2]),
                    render(&inner[3])
                );
            }
            Some("clauses") if inner.len() == 2 => {
                let clauses: Vec<Term> = list(&inner[1]);
                if let [single] = clauses.as_slice()
                    && let Some(rendered) = render_inline_fun_clause(single)
                {
                    return format!("fun{rendered} end");
                }
                let arms: String = render_clauses(&inner[1], indent + 1, ClauseStyle::Fun);
                return format!("fun\n{arms}\n{}end", pad(indent));
            }
            _ => {}
        }
    }
    "fun ? end".to_owned()
}

/// Renders a single-clause anonymous fun inline `(Params) [when G] -> Body`
/// when its body is a single non-compound statement; otherwise returns `None`
/// to fall back to the multi-line form.
fn render_inline_fun_clause(clause: &Term) -> Option<String> {
    let parts: &[Term] = clause.as_tuple()?;
    if parts.len() != 5 || parts[0].as_atom() != Some("clause") {
        return None;
    }
    let body: Vec<Term> = list(&parts[4]);
    if body.len() != 1 {
        return None;
    }
    if matches!(
        node_kind(&body[0]),
        Some("case" | "if" | "receive" | "try" | "block" | "fun")
    ) {
        return None;
    }
    let params: Vec<String> = list(&parts[2]).iter().map(render).collect();
    let guard: String = render_guard_seq(&parts[3]);
    Some(format!(
        "({}){guard} -> {}",
        params.join(", "),
        render(&body[0])
    ))
}

#[derive(Clone, Copy)]
enum ClauseStyle {
    Case,
    If,
    Catch,
    Fun,
}

fn render_clauses(term: &Term, indent: usize, style: ClauseStyle) -> String {
    let clauses: Vec<Term> = list(term);
    let rendered: Vec<String> = clauses
        .iter()
        .map(|c: &Term| render_one_clause(c, indent, style))
        .collect();
    rendered.join(";\n")
}

fn render_one_clause(clause: &Term, indent: usize, style: ClauseStyle) -> String {
    let Some(parts) = clause.as_tuple() else {
        return format!("{}_ ->\n{}ok", pad(indent), pad(indent + 1));
    };
    if parts.len() != 5 {
        return format!("{}_ ->\n{}ok", pad(indent), pad(indent + 1));
    }
    let patterns: Vec<Term> = list(&parts[2]);
    let head: String = match style {
        ClauseStyle::If => String::new(),
        ClauseStyle::Catch => render_catch_head(&patterns),
        ClauseStyle::Case | ClauseStyle::Fun => {
            patterns.iter().map(render).collect::<Vec<_>>().join(", ")
        }
    };
    let guard: String = render_guard_seq(&parts[3]);
    let body: String = render_body(&parts[4], indent + 1);
    if matches!(style, ClauseStyle::If) {
        let g: String = guard.strip_prefix(" when ").unwrap_or(&guard).to_owned();
        let cond: String = if g.is_empty() { "true".to_owned() } else { g };
        return format!("{}{cond} ->\n{body}", pad(indent));
    }
    format!("{}{head}{guard} ->\n{body}", pad(indent))
}

/// Catch clauses carry the `{Class, Reason, Stack}` triple as a single tuple
/// pattern; surface it as `Class:Reason[:Stack]`.
fn render_catch_head(patterns: &[Term]) -> String {
    if let [first] = patterns
        && node_kind(first) == Some("tuple")
        && let Some(parts) = first.as_tuple()
    {
        let elems: Vec<Term> = list(&parts[2]);
        if elems.len() == 3 {
            let class: String = render(&elems[0]);
            let reason: String = render(&elems[1]);
            let stack: String = render(&elems[2]);
            if stack == "_" {
                return format!("{class}:{reason}");
            }
            return format!("{class}:{reason}:{stack}");
        }
    }
    patterns.iter().map(render).collect::<Vec<_>>().join(", ")
}

fn node_kind(term: &Term) -> Option<&str> {
    term.as_tuple()
        .and_then(|t: &[Term]| t.first())
        .and_then(Term::as_atom)
}

fn list(term: &Term) -> Vec<Term> {
    match term {
        Term::List { elements, .. } => elements.clone(),
        Term::Nil => Vec::new(),
        other => vec![other.clone()],
    }
}

fn atom_at(parts: &[Term], i: usize) -> String {
    parts
        .get(i)
        .and_then(Term::as_atom)
        .map(render_atom)
        .unwrap_or_else(|| "?".to_owned())
}

fn int_string(term: &Term) -> String {
    int_string_inner(term)
}

fn int_string_inner(term: &Term) -> String {
    match term {
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::BigInt { sign, magnitude_le } => render_bigint(*sign, magnitude_le),
        _ => "0".to_owned(),
    }
}

fn float_string(term: &Term) -> String {
    match term {
        Term::Float(f) => {
            let s: String = format!("{f}");
            if s.contains('.') || s.contains('e') || s.contains('E') {
                s
            } else {
                format!("{s}.0")
            }
        }
        _ => "0.0".to_owned(),
    }
}

fn char_repr(term: &Term) -> String {
    let code: u32 = match term {
        Term::SmallInt(v) => u32::from(*v),
        Term::Int(v) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    };
    char::from_u32(code).map_or_else(|| format!("\\x{code:x}"), |c: char| c.to_string())
}

fn str_value(term: &Term) -> String {
    match term {
        Term::String(b) | Term::Binary(b) => String::from_utf8_lossy(b).into_owned(),
        Term::Nil => String::new(),
        Term::List { elements, .. } => elements
            .iter()
            .filter_map(|e: &Term| match e {
                Term::SmallInt(v) => char::from_u32(u32::from(*v)),
                Term::Int(v) => u32::try_from(*v).ok().and_then(char::from_u32),
                _ => None,
            })
            .collect(),
        _ => String::new(),
    }
}

fn literal_fallback(term: &Term) -> String {
    match term {
        Term::Atom(a) => render_atom(a),
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::Nil => "[]".to_owned(),
        Term::Binary(b) | Term::String(b) => {
            format!("\"{}\"", escape_str(&String::from_utf8_lossy(b)))
        }
        _ => "_".to_owned(),
    }
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
}

fn pad(indent: usize) -> String {
    "    ".repeat(indent)
}

fn render_bigint(sign: u8, magnitude_le: &[u8]) -> String {
    let mut be: Vec<u8> = magnitude_le.to_vec();
    be.reverse();
    let mut work: Vec<u8> = be;
    let mut digits: Vec<u8> = Vec::new();
    while work.iter().any(|&b: &u8| b != 0) {
        let mut remainder: u16 = 0;
        let mut quotient: Vec<u8> = Vec::with_capacity(work.len());
        for &byte in &work {
            let acc: u16 = (remainder << 8) | u16::from(byte);
            quotient.push((acc / 10) as u8);
            remainder = acc % 10;
        }
        digits.push(b'0' + remainder as u8);
        let first_nonzero: usize = quotient
            .iter()
            .position(|&b: &u8| b != 0)
            .unwrap_or(quotient.len());
        work = quotient[first_nonzero..].to_vec();
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    digits.reverse();
    let body: String = String::from_utf8(digits).unwrap_or_else(|_| "0".to_owned());
    if sign == 1 { format!("-{body}") } else { body }
}
