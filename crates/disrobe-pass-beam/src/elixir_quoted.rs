use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use crate::etf::Term;

const MAX_RENDER_DEPTH: u32 = 256;

thread_local! {
    static RENDER_DEPTH: Cell<u32> = const { Cell::new(0) };
    static RENDERED_MODULE: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn within_module<R>(module_atom: &str, render: impl FnOnce() -> R) -> R {
    let previous: Option<String> = RENDERED_MODULE
        .with(|slot: &RefCell<Option<String>>| slot.replace(Some(module_atom.to_owned())));
    let result: R = render();
    RENDERED_MODULE.with(|slot: &RefCell<Option<String>>| slot.replace(previous));
    result
}

fn rendered_module() -> Option<String> {
    RENDERED_MODULE.with(|slot: &RefCell<Option<String>>| slot.borrow().clone())
}

struct DepthGuard;

impl DepthGuard {
    fn enter() -> Option<Self> {
        RENDER_DEPTH.with(|d: &Cell<u32>| {
            if d.get() >= MAX_RENDER_DEPTH {
                None
            } else {
                d.set(d.get() + 1);
                Some(Self)
            }
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        RENDER_DEPTH.with(|d: &Cell<u32>| d.set(d.get().saturating_sub(1)));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedClause {
    pub params: Vec<String>,
    pub guard: Option<String>,
    pub body: String,
}

#[must_use]
pub fn render_clause(clause: &Term) -> Option<QuotedClause> {
    let parts: &[Term] = clause.as_tuple()?;
    if parts.len() != 4 {
        return None;
    }
    let params: Vec<String> = list_items(&parts[1])
        .iter()
        .map(|p: &Term| render(p, Prec::Lowest))
        .collect();
    let guard: Option<String> = render_guard(&parts[2]);
    let body: String = render_block(&parts[3]);
    Some(QuotedClause {
        params,
        guard,
        body,
    })
}

#[must_use]
pub fn strip_module_prefix(module: &str) -> String {
    strip_elixir(module)
}

fn render_guard(term: &Term) -> Option<String> {
    let items: Vec<Term> = list_items(term);
    if items.is_empty() {
        return None;
    }
    let parts: Vec<String> = items
        .iter()
        .map(|g: &Term| render(g, Prec::Lowest))
        .collect();
    Some(parts.join(" when "))
}

#[must_use]
pub fn render_block(term: &Term) -> String {
    if let Some(tuple) = term.as_tuple()
        && tuple.len() == 3
        && tuple[0].as_atom() == Some("__block__")
        && let Some(stmts) = tuple.get(2).map(list_items)
    {
        if let Some(nested) = render_nested_defmodule(&stmts) {
            return nested;
        }
        return stmts
            .iter()
            .map(|s: &Term| render(s, Prec::Lowest))
            .collect::<Vec<_>>()
            .join("\n");
    }
    render(term, Prec::Lowest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Prec {
    Lowest,
    Or,
    And,
    Equality,
    Relational,
    Pipe,
    In,
    Concat,
    Additive,
    Multiplicative,
    Unary,
    Highest,
}

#[must_use]
fn render(term: &Term, parent: Prec) -> String {
    let Some(_guard): Option<DepthGuard> = DepthGuard::enter() else {
        return "nil".to_owned();
    };
    match term {
        Term::Atom(a) => render_atom_literal(a),
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::BigInt { sign, magnitude_le } => render_bigint(*sign, magnitude_le),
        Term::Float(f) => format_float(*f),
        Term::Nil => "[]".to_owned(),
        Term::Binary(b) => render_string_literal(b),
        Term::String(b) => render_charlist_literal(b),
        Term::Tuple(items) => render_quoted_tuple(items, parent),
        Term::List { elements, tail } => render_list(elements, tail),
        Term::Map(m) => {
            let pairs: Vec<(Term, Term)> = m
                .iter()
                .map(|(k, v): (&String, &Term)| (Term::Atom(k.clone()), v.clone()))
                .collect();
            render_map_from_pairs(&pairs)
        }
        Term::MapMixed(pairs) => render_map_from_pairs(pairs),
        Term::BitBinary { data, .. } => render_string_literal(data),
        Term::Pid { .. } => "#PID<...>".to_owned(),
        Term::Reference { .. } => "#Reference<...>".to_owned(),
        Term::Export {
            module,
            function,
            arity,
        } => format!("&{}.{function}/{arity}", strip_elixir(module)),
    }
}

fn render_quoted_tuple(items: &[Term], parent: Prec) -> String {
    if let Some(quoted) = render_as_quote(items) {
        return quoted;
    }
    if items.len() == 3 {
        let meta_is_list: bool = matches!(&items[1], Term::List { .. } | Term::Nil);
        if meta_is_list {
            match &items[2] {
                Term::Atom(_) => return render_variable(&items[0]),
                Term::Nil | Term::List { .. } | Term::String(_) => {
                    return render_call(&items[0], &items[2], parent);
                }
                _ => {}
            }
        }
    }
    if items.len() == 2 {
        return format!(
            "{{{}, {}}}",
            render(&items[0], Prec::Lowest),
            render(&items[1], Prec::Lowest)
        );
    }
    let parts: Vec<String> = items
        .iter()
        .map(|i: &Term| render(i, Prec::Lowest))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

fn render_variable(name_term: &Term) -> String {
    match name_term {
        Term::Atom(a) => a.clone(),
        other => render(other, Prec::Lowest),
    }
}

fn render_call(target: &Term, args_term: &Term, parent: Prec) -> String {
    let args: Vec<Term> = list_items(args_term);
    if let Term::Atom(name) = target {
        return render_named_call(name, &args, parent);
    }
    if let Some(remote) = remote_target(target) {
        return render_remote_call(&remote, &args, parent);
    }
    if let Some(dot) = target.as_tuple()
        && dot.len() == 3
        && dot[0].as_atom() == Some(".")
        && let [fun] = list_items(&dot[2]).as_slice()
    {
        let rendered: Vec<String> = args
            .iter()
            .map(|a: &Term| render(a, Prec::Lowest))
            .collect();
        return format!("{}.({})", render(fun, Prec::Highest), rendered.join(", "));
    }
    let rendered: Vec<String> = args
        .iter()
        .map(|a: &Term| render(a, Prec::Lowest))
        .collect();
    format!("{}({})", render(target, Prec::Highest), rendered.join(", "))
}

fn remote_target(target: &Term) -> Option<(Term, String)> {
    let tuple: &[Term] = target.as_tuple()?;
    if tuple.len() == 3 && tuple[0].as_atom() == Some(".") {
        let inner: Vec<Term> = list_items(&tuple[2]);
        if inner.len() == 2
            && let Term::Atom(fun) = &inner[1]
        {
            return Some((inner[0].clone(), fun.clone()));
        }
    }
    None
}

fn render_remote_call(remote: &(Term, String), args: &[Term], parent: Prec) -> String {
    let (module, fun): &(Term, String) = remote;
    if let Term::Atom(m) = module
        && matches!(m.as_str(), "erlang" | "Elixir.Kernel" | "Elixir.Bitwise")
    {
        if args.len() == 2
            && let Some((op, prec)) = infix_operator(fun)
        {
            return render_binary_op(op, &args[0], &args[1], prec, parent);
        }
        if args.len() == 1 {
            match fun.as_str() {
                "-" | "+" => return render_sign(fun, &args[0]),
                "not" => return format!("not {}", render(&args[0], Prec::Unary)),
                _ => {}
            }
        }
        if is_bitwise(fun, args.len()) {
            let rendered: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            return format!("Bitwise.{fun}({})", rendered.join(", "));
        }
        if is_kernel_imported(fun, args.len()) {
            let rendered: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            return format!("{fun}({})", rendered.join(", "));
        }
    }
    let module_is_atom: bool = matches!(module, Term::Atom(_));
    let module_str: String = match module {
        Term::Atom(a) => render_atom_literal(a),
        other => render(other, Prec::Highest),
    };
    if args.is_empty() {
        if module_is_atom {
            return format!("{module_str}.{fun}()");
        }
        return format!("{module_str}.{fun}");
    }
    let rendered: Vec<String> = args
        .iter()
        .map(|a: &Term| render(a, Prec::Lowest))
        .collect();
    format!("{module_str}.{fun}({})", rendered.join(", "))
}

#[allow(clippy::too_many_lines)]
fn render_named_call(name: &str, args: &[Term], parent: Prec) -> String {
    match (name, args.len()) {
        (".", 2) => {
            let module: String = render(&args[0], Prec::Highest);
            let fun: String = match &args[1] {
                Term::Atom(a) => a.clone(),
                other => render(other, Prec::Highest),
            };
            return format!("{module}.{fun}");
        }
        ("__block__", _) => {
            if let Some(nested) = render_nested_defmodule(args) {
                return nested;
            }
            let parts: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            return parts.join("\n");
        }
        ("__aliases__", _) => {
            let parts: Vec<String> = args
                .iter()
                .map(|a: &Term| match a {
                    Term::Atom(segment) => strip_elixir(segment),
                    other => render(other, Prec::Highest),
                })
                .collect();
            return parts.join(".");
        }
        ("@", 1) => {
            if let Some(attribute) = render_attribute(&args[0]) {
                return attribute;
            }
        }
        ("def" | "defp" | "defmacro" | "defmacrop", 1 | 2) => {
            if let Some(definition) = render_definition(name, args) {
                return definition;
            }
        }
        ("\\\\", 2) => {
            return render_binary_op("\\\\", &args[0], &args[1], Prec::Lowest, parent);
        }
        ("%{}", _) => return render_map_call(args),
        ("{}", _) => {
            let parts: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            return format!("{{{}}}", parts.join(", "));
        }
        ("%", 2) => return render_struct(&args[0], &args[1]),
        ("<<>>", _) => return render_bitstring(args),
        ("fn", _) => return render_fn(args),
        ("->", 2) => return render_arrow(&args[0], &args[1]),
        ("=", 2) => return render_binary_op("=", &args[0], &args[1], Prec::Lowest, parent),
        ("<-", 2) => return render_binary_op("<-", &args[0], &args[1], Prec::Lowest, parent),
        ("|", 2) => return render_binary_op("|", &args[0], &args[1], Prec::Lowest, parent),
        ("::", 2) => return render_binary_op("::", &args[0], &args[1], Prec::Lowest, parent),
        ("^", 1) => return format!("^{}", render(&args[0], Prec::Unary)),
        ("when", _) if args.len() == 2 => {
            return format!(
                "{} when {}",
                render(&args[0], Prec::Lowest),
                render(&args[1], Prec::Lowest)
            );
        }
        ("case", 2) => return render_case(&args[0], &args[1]),
        ("cond", 1) => return render_cond(&args[0]),
        ("receive", 1) => return render_receive(&args[0]),
        ("try", 1) => return render_try(&args[0]),
        ("for", _) => return render_for(args),
        ("with", _) => return render_with(args),
        ("if", 2) => return render_if(&args[0], &args[1]),
        ("&", 1) => return format!("&{}", render(&args[0], Prec::Unary)),
        ("not", 1) => return format!("not {}", render(&args[0], Prec::Unary)),
        ("!", 1) => return format!("!{}", render(&args[0], Prec::Unary)),
        ("-" | "+", 1) => return render_sign(name, &args[0]),
        ("in", 2) => return render_binary_op("in", &args[0], &args[1], Prec::In, parent),
        _ => {}
    }
    if let Some((op, prec)) = infix_operator(name)
        && args.len() == 2
    {
        return render_binary_op(op, &args[0], &args[1], prec, parent);
    }
    let rendered: Vec<String> = args
        .iter()
        .map(|a: &Term| render(a, Prec::Lowest))
        .collect();
    format!("{name}({})", rendered.join(", "))
}

fn infix_operator(name: &str) -> Option<(&'static str, Prec)> {
    let entry: (&'static str, Prec) = match name {
        "orelse" | "or" => ("or", Prec::Or),
        "||" => ("||", Prec::Or),
        "andalso" | "and" => ("and", Prec::And),
        "&&" => ("&&", Prec::And),
        "==" => ("==", Prec::Equality),
        "=~" => ("=~", Prec::Equality),
        "=:=" | "===" => ("===", Prec::Equality),
        "/=" | "!=" => ("!=", Prec::Equality),
        "=/=" | "!==" => ("!==", Prec::Equality),
        "<" => ("<", Prec::Relational),
        ">" => (">", Prec::Relational),
        "=<" | "<=" => ("<=", Prec::Relational),
        ">=" => (">=", Prec::Relational),
        "|>" => ("|>", Prec::Pipe),
        "<>" => ("<>", Prec::Concat),
        "++" => ("++", Prec::Concat),
        "--" => ("--", Prec::Concat),
        ".." => ("..", Prec::Concat),
        "+" => ("+", Prec::Additive),
        "-" => ("-", Prec::Additive),
        "*" => ("*", Prec::Multiplicative),
        "/" => ("/", Prec::Multiplicative),
        _ => return None,
    };
    Some(entry)
}

fn is_kernel_imported(fun: &str, arity: usize) -> bool {
    match fun {
        "is_atom" | "is_binary" | "is_bitstring" | "is_boolean" | "is_float" | "is_integer"
        | "is_list" | "is_map" | "is_number" | "is_pid" | "is_port" | "is_reference"
        | "is_tuple" | "abs" | "bit_size" | "byte_size" | "ceil" | "floor" | "hd" | "tl"
        | "length" | "map_size" | "round" | "trunc" | "throw" | "exit" => arity == 1,
        "is_function" => matches!(arity, 1 | 2),
        "is_map_key" | "elem" | "max" | "min" | "send" | "div" | "rem" => arity == 2,
        "node" => matches!(arity, 0 | 1),
        "self" | "make_ref" => arity == 0,
        "binary_part" => arity == 3,
        "spawn" | "spawn_link" | "spawn_monitor" => matches!(arity, 1 | 3),
        _ => false,
    }
}

fn is_bitwise(fun: &str, arity: usize) -> bool {
    match fun {
        "band" | "bor" | "bxor" | "bsl" | "bsr" => arity == 2,
        "bnot" => arity == 1,
        _ => false,
    }
}

fn render_sign(sign: &str, operand: &Term) -> String {
    let inner: String = render(operand, Prec::Unary);
    if inner.starts_with(['-', '+']) {
        format!("{sign}({inner})")
    } else {
        format!("{sign}{inner}")
    }
}

fn render_binary_op(op: &str, lhs: &Term, rhs: &Term, prec: Prec, parent: Prec) -> String {
    let (lhs_prec, rhs_prec): (Prec, Prec) = if prec == Prec::Concat {
        (next_prec(prec), prec)
    } else {
        (prec, next_prec(prec))
    };
    let inner: String = format!("{} {op} {}", render(lhs, lhs_prec), render(rhs, rhs_prec));
    if parent > prec {
        format!("({inner})")
    } else {
        inner
    }
}

const fn next_prec(prec: Prec) -> Prec {
    match prec {
        Prec::Lowest => Prec::Or,
        Prec::Or => Prec::And,
        Prec::And => Prec::Equality,
        Prec::Equality => Prec::Relational,
        Prec::Relational => Prec::Pipe,
        Prec::Pipe => Prec::In,
        Prec::In => Prec::Concat,
        Prec::Concat => Prec::Additive,
        Prec::Additive => Prec::Multiplicative,
        Prec::Multiplicative | Prec::Unary => Prec::Unary,
        Prec::Highest => Prec::Highest,
    }
}

fn render_arrow(lhs: &Term, rhs: &Term) -> String {
    let heads: Vec<String> = list_items(lhs)
        .iter()
        .map(|p: &Term| render(p, Prec::Lowest))
        .collect();
    format!("{} -> {}", heads.join(", "), render_block(rhs))
}

fn render_fn(clauses: &[Term]) -> String {
    let arms: Vec<String> = clauses
        .iter()
        .filter_map(|c: &Term| arrow_parts(c))
        .map(|(head, body): (String, String)| format!("{head} -> {body}"))
        .collect();
    if arms.len() == 1 {
        format!("fn {} end", arms[0])
    } else {
        format!("fn\n  {}\nend", arms.join("\n  "))
    }
}

fn arrow_parts(term: &Term) -> Option<(String, String)> {
    let tuple: &[Term] = term.as_tuple()?;
    if tuple.len() == 3 && tuple[0].as_atom() == Some("->") {
        let args: Vec<Term> = list_items(&tuple[2]);
        if args.len() == 2 {
            let heads: Vec<String> = list_items(&args[0])
                .iter()
                .map(|p: &Term| render(p, Prec::Lowest))
                .collect();
            return Some((heads.join(", "), render_block(&args[1])));
        }
    }
    None
}

fn render_case(subject: &Term, opts: &Term) -> String {
    let arms: String = render_do_arms(opts, "do");
    format!("case {} do\n{arms}\nend", render(subject, Prec::Lowest))
}

fn render_cond(opts: &Term) -> String {
    let arms: String = render_do_arms(opts, "do");
    format!("cond do\n{arms}\nend")
}

fn render_receive(opts: &Term) -> String {
    let mut out: String = String::from("receive do\n");
    out.push_str(&render_do_arms(opts, "do"));
    if let Some(after) = keyword_value(opts, "after") {
        out.push_str("\nafter\n");
        out.push_str(&render_clause_arms(&after));
    }
    out.push_str("\nend");
    out
}

fn render_try(opts: &Term) -> String {
    let mut out: String = String::from("try do\n");
    if let Some(do_body) = keyword_value(opts, "do") {
        out.push_str(&indent(&render_block(&do_body)));
    }
    for section in ["rescue", "catch", "else", "after"] {
        if let Some(val) = keyword_value(opts, section) {
            out.push('\n');
            out.push_str(section);
            out.push('\n');
            if matches!(val, Term::List { .. }) && is_arrow_list(&val) {
                out.push_str(&render_clause_arms(&val));
            } else {
                out.push_str(&indent(&render_block(&val)));
            }
        }
    }
    out.push_str("\nend");
    out
}

fn render_for(args: &[Term]) -> String {
    let (do_opts, gens): (Option<Term>, Vec<&Term>) = split_do(args);
    let mut parts: Vec<String> = gens
        .iter()
        .map(|q: &&Term| render(q, Prec::Lowest))
        .collect();
    if let Some(last) = args.last()
        && is_keyword_list(last)
    {
        for item in list_items(last) {
            if let Some([key, value]) = item.as_tuple()
                && let Some(name) = key.as_atom()
                && name != "do"
            {
                parts.push(format!("{name}: {}", render(value, Prec::Lowest)));
            }
        }
    }
    let body: String = do_opts.map_or_else(|| "nil".to_owned(), |t: Term| render_block(&t));
    format!("for {}, do: {body}", parts.join(", "))
}

fn render_with(args: &[Term]) -> String {
    let (do_opts, gens): (Option<Term>, Vec<&Term>) = split_do(args);
    let qual_strs: Vec<String> = gens
        .iter()
        .map(|q: &&Term| render(q, Prec::Lowest))
        .collect();
    let opts_term: Option<&Term> = args.last().filter(|t: &&Term| is_keyword_list(t));
    let mut out: String = format!("with {} do\n", qual_strs.join(", "));
    if let Some(body) = do_opts {
        out.push_str(&indent(&render_block(&body)));
    }
    if let Some(opts) = opts_term
        && let Some(else_body) = keyword_value(opts, "else")
    {
        out.push_str("\nelse\n");
        out.push_str(&render_clause_arms(&else_body));
    }
    out.push_str("\nend");
    out
}

fn render_if(cond: &Term, opts: &Term) -> String {
    let mut out: String = format!("if {} do\n", render(cond, Prec::Lowest));
    if let Some(do_body) = keyword_value(opts, "do") {
        out.push_str(&indent(&render_block(&do_body)));
    }
    if let Some(else_body) = keyword_value(opts, "else") {
        out.push_str("\nelse\n");
        out.push_str(&indent(&render_block(&else_body)));
    }
    out.push_str("\nend");
    out
}

fn split_do(args: &[Term]) -> (Option<Term>, Vec<&Term>) {
    let Some((last, head)): Option<(&Term, &[Term])> = args.split_last() else {
        return (None, Vec::new());
    };
    if is_keyword_list(last) {
        let do_body: Option<Term> = keyword_value(last, "do");
        (do_body, head.iter().collect())
    } else {
        (None, args.iter().collect())
    }
}

fn render_do_arms(opts: &Term, key: &str) -> String {
    keyword_value(opts, key).map_or_else(String::new, |arms: Term| render_clause_arms(&arms))
}

fn render_clause_arms(arms: &Term) -> String {
    let items: Vec<Term> = list_items(arms);
    let rendered: Vec<String> = items
        .iter()
        .filter_map(|a: &Term| arrow_parts(a))
        .map(|(head, body): (String, String)| indent(&format!("{head} ->\n{}", indent(&body))))
        .collect();
    rendered.join("\n")
}

fn is_arrow_list(term: &Term) -> bool {
    list_items(term)
        .first()
        .and_then(Term::as_tuple)
        .is_some_and(|t: &[Term]| t.first().and_then(Term::as_atom) == Some("->"))
}

fn render_map_call(args: &[Term]) -> String {
    if let [single] = args
        && let Some(tuple) = single.as_tuple()
        && tuple.len() == 3
        && tuple[0].as_atom() == Some("|")
    {
        let update_args: Vec<Term> = list_items(&tuple[2]);
        if update_args.len() == 2 {
            let base: String = render(&update_args[0], Prec::Lowest);
            let updates: Vec<(Term, Term)> = list_items(&update_args[1])
                .iter()
                .filter_map(|p: &Term| {
                    let t: &[Term] = p.as_tuple()?;
                    (t.len() == 2).then(|| (t[0].clone(), t[1].clone()))
                })
                .collect();
            return format!("%{{{base} | {}}}", map_pairs_body(&updates));
        }
    }
    let pairs: Vec<(Term, Term)> = args
        .iter()
        .filter_map(|p: &Term| {
            let t: &[Term] = p.as_tuple()?;
            (t.len() == 2).then(|| (t[0].clone(), t[1].clone()))
        })
        .collect();
    render_map_from_pairs(&pairs)
}

fn render_struct(module: &Term, fields: &Term) -> String {
    let name: String = match module {
        Term::Atom(a) => render_module_alias(a),
        other => render(other, Prec::Highest),
    };
    let body: String = render_map_inner(fields);
    format!("%{name}{{{body}}}")
}

fn render_map_inner(map_call: &Term) -> String {
    if let Some(tuple) = map_call.as_tuple()
        && tuple.len() == 3
        && tuple[0].as_atom() == Some("%{}")
    {
        let pairs: Vec<(Term, Term)> = list_items(&tuple[2])
            .iter()
            .filter_map(|p: &Term| {
                let t: &[Term] = p.as_tuple()?;
                (t.len() == 2).then(|| (t[0].clone(), t[1].clone()))
            })
            .collect();
        return map_pairs_body(&pairs);
    }
    String::new()
}

fn render_map_from_pairs(pairs: &[(Term, Term)]) -> String {
    if let Some(structish) = struct_name(pairs) {
        let rest: Vec<(Term, Term)> = pairs
            .iter()
            .filter(|(k, _): &&(Term, Term)| k.as_atom() != Some("__struct__"))
            .cloned()
            .collect();
        return format!("%{}{{{}}}", structish, map_pairs_body(&rest));
    }
    format!("%{{{}}}", map_pairs_body(pairs))
}

fn struct_name(pairs: &[(Term, Term)]) -> Option<String> {
    pairs.iter().find_map(|(k, v): &(Term, Term)| {
        (k.as_atom() == Some("__struct__")).then(|| match v {
            Term::Atom(a) => render_module_alias(a),
            other => render(other, Prec::Highest),
        })
    })
}

fn map_pairs_body(pairs: &[(Term, Term)]) -> String {
    pairs
        .iter()
        .map(|(k, v): &(Term, Term)| match k {
            Term::Atom(a) if is_plain_key(a) => format!("{a}: {}", render(v, Prec::Lowest)),
            other => format!(
                "{} => {}",
                render(other, Prec::Lowest),
                render(v, Prec::Lowest)
            ),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_bitstring(segments: &[Term]) -> String {
    let parts: Vec<String> = segments
        .iter()
        .map(|s: &Term| render_bit_segment(s))
        .collect();
    format!("<<{}>>", parts.join(", "))
}

fn render_bit_segment(seg: &Term) -> String {
    if let Some(tuple) = seg.as_tuple()
        && tuple.len() == 3
        && tuple[0].as_atom() == Some("::")
    {
        let args: Vec<Term> = list_items(&tuple[2]);
        if args.len() == 2 {
            let value: String = render(&args[0], Prec::Highest);
            let spec: String = render_bit_spec(&args[1]);
            if spec.is_empty() || (spec == "binary" && matches!(args[0], Term::Binary(_))) {
                return value;
            }
            return format!("{value}::{spec}");
        }
    }
    render(seg, Prec::Highest)
}

fn render_bit_spec(spec: &Term) -> String {
    if let Term::Atom(a) = spec {
        return a.clone();
    }
    if let Some(tuple) = spec.as_tuple()
        && tuple.len() == 3
        && let Term::Atom(name) = &tuple[0]
    {
        let args: Vec<Term> = list_items(&tuple[2]);
        if let ("-" | "*", [lhs, rhs]) = (name.as_str(), args.as_slice()) {
            return format!("{}{name}{}", render_bit_spec(lhs), render_bit_spec(rhs));
        }
        if args.is_empty() || matches!(&tuple[2], Term::Atom(_)) {
            return name.clone();
        }
        let rendered: Vec<String> = args
            .iter()
            .map(|a: &Term| render(a, Prec::Highest))
            .collect();
        return format!("{name}({})", rendered.join(", "));
    }
    String::new()
}

fn render_list(elements: &[Term], tail: &Term) -> String {
    if is_keyword_pairs(elements) && matches!(tail, Term::Nil) {
        let body: String = elements
            .iter()
            .filter_map(|e: &Term| {
                let t: &[Term] = e.as_tuple()?;
                let key: &str = t[0].as_atom()?;
                Some(format!(
                    "{} {}",
                    keyword_key(key),
                    render(&t[1], Prec::Lowest)
                ))
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!("[{body}]");
    }
    let parts: Vec<String> = elements
        .iter()
        .map(|e: &Term| render(e, Prec::Lowest))
        .collect();
    if matches!(tail, Term::Nil) {
        format!("[{}]", parts.join(", "))
    } else {
        format!("[{} | {}]", parts.join(", "), render(tail, Prec::Lowest))
    }
}

fn is_keyword_pairs(elements: &[Term]) -> bool {
    !elements.is_empty()
        && elements.iter().all(|e: &Term| {
            e.as_tuple()
                .is_some_and(|t: &[Term]| t.len() == 2 && matches!(t[0], Term::Atom(_)))
        })
}

fn is_keyword_list(term: &Term) -> bool {
    matches!(term, Term::List { elements, tail }
        if matches!(**tail, Term::Nil) && is_keyword_pairs(elements))
}

fn keyword_value(term: &Term, key: &str) -> Option<Term> {
    list_items(term).into_iter().find_map(|e: Term| {
        let t: &[Term] = e.as_tuple()?;
        (t.len() == 2 && t[0].as_atom() == Some(key)).then(|| t[1].clone())
    })
}

fn list_items(term: &Term) -> Vec<Term> {
    match term {
        Term::List { elements, .. } => elements.clone(),
        Term::Nil => Vec::new(),
        Term::String(bytes) => bytes.iter().map(|b: &u8| Term::SmallInt(*b)).collect(),
        other => vec![other.clone()],
    }
}

fn render_atom_literal(a: &str) -> String {
    match a {
        "nil" => "nil".to_owned(),
        "true" => "true".to_owned(),
        "false" => "false".to_owned(),
        _ if a.starts_with("Elixir.") => render_module_alias(a),
        _ if is_plain_atom(a) => format!(":{a}"),
        _ => format!(":\"{}\"", escape_double(a)),
    }
}

fn render_module_alias(a: &str) -> String {
    strip_elixir(a)
}

fn strip_elixir(a: &str) -> String {
    a.strip_prefix("Elixir.").unwrap_or(a).to_owned()
}

fn is_plain_atom(a: &str) -> bool {
    let Some(first): Option<char> = a.chars().next() else {
        return false;
    };
    let body: &str = a.strip_suffix(['?', '!']).unwrap_or(a);
    (first.is_ascii_lowercase() || first == '_')
        && !body.is_empty()
        && body
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '@')
}

fn keyword_key(a: &str) -> String {
    if is_plain_atom(a) {
        format!("{a}:")
    } else {
        format!("\"{}\":", escape_double(a))
    }
}

#[must_use]
pub fn render_value(term: &Term) -> String {
    let Some(_guard): Option<DepthGuard> = DepthGuard::enter() else {
        return "nil".to_owned();
    };
    match term {
        Term::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(render_value).collect();
            format!("{{{}}}", parts.join(", "))
        }
        Term::List { elements, tail } => {
            if is_keyword_pairs(elements) && matches!(**tail, Term::Nil) {
                let body: Vec<String> = elements
                    .iter()
                    .filter_map(|e: &Term| {
                        let t: &[Term] = e.as_tuple()?;
                        Some(format!(
                            "{} {}",
                            keyword_key(t[0].as_atom()?),
                            render_value(&t[1])
                        ))
                    })
                    .collect();
                return format!("[{}]", body.join(", "));
            }
            let parts: Vec<String> = elements.iter().map(render_value).collect();
            if matches!(**tail, Term::Nil) {
                format!("[{}]", parts.join(", "))
            } else {
                format!("[{} | {}]", parts.join(", "), render_value(tail))
            }
        }
        Term::Map(m) => {
            let parts: Vec<String> = m
                .iter()
                .map(|(k, v): (&String, &Term)| format!("{} {}", keyword_key(k), render_value(v)))
                .collect();
            format!("%{{{}}}", parts.join(", "))
        }
        Term::MapMixed(pairs) => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(k, v): &(Term, Term)| format!("{} => {}", render_value(k), render_value(v)))
                .collect();
            format!("%{{{}}}", parts.join(", "))
        }
        other => render(other, Prec::Lowest),
    }
}

fn is_plain_key(a: &str) -> bool {
    is_plain_atom(a) && !a.is_empty()
}

fn render_string_literal(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(s) => format!("\"{}\"", escape_double(s)),
        Err(_) => format!("<<{}>>", join_bytes(bytes)),
    }
}

fn render_charlist_literal(bytes: &[u8]) -> String {
    if bytes
        .iter()
        .all(|b: &u8| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\t' | b'\r'))
    {
        let text: String = bytes.iter().map(|b: &u8| char::from(*b)).collect();
        format!("~c\"{}\"", escape_double(&text))
    } else {
        format!("[{}]", join_bytes(bytes))
    }
}

fn join_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn escape_double(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '#' if chars.peek() == Some(&'{') => out.push_str("\\#"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:X}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|line: &str| {
            if line.is_empty() {
                String::new()
            } else {
                format!("  {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_float(f: f64) -> String {
    let s: String = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
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

fn render_attribute(attribute: &Term) -> Option<String> {
    let [name, _, value] = attribute.as_tuple()? else {
        return None;
    };
    let name: &str = name.as_atom().filter(|n: &&str| is_identifier(n))?;
    match value {
        Term::Atom(_) => Some(format!("@{name}")),
        Term::List { .. } | Term::Nil | Term::String(_) => match list_items(value).as_slice() {
            [single] => Some(format!("@{name} {}", render(single, Prec::Lowest))),
            _ => None,
        },
        _ => None,
    }
}

fn render_definition(kind: &str, args: &[Term]) -> Option<String> {
    let head: String = render(args.first()?, Prec::Lowest);
    let Some(options) = args.get(1) else {
        return Some(format!("{kind} {head}"));
    };
    if !is_keyword_list(options) || list_items(options).len() != 1 {
        return None;
    }
    let body: Term = keyword_value(options, "do")?;
    Some(format!(
        "{kind} {head} do\n{}\nend",
        indent(&render_block(&body))
    ))
}

fn is_identifier(name: &str) -> bool {
    let body: &str = name.strip_suffix(['?', '!']).unwrap_or(name);
    body.chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_lowercase() || c == '_')
        && body
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn is_alias_segment(segment: &str) -> bool {
    segment
        .chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_uppercase())
        && segment
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn call_name_renderable(name: &str, arity: usize) -> bool {
    if is_identifier(name) {
        return true;
    }
    if arity == 2 && infix_operator(name).is_some() {
        return true;
    }
    matches!(
        (name, arity),
        ("%{}" | "{}" | "<<>>", _)
            | ("." | "%" | "->" | "=" | "<-" | "|" | "::" | "\\\\", 2)
            | ("^" | "&" | "!" | "-" | "+" | "@", 1)
    )
}

fn source_renderable(term: &Term) -> bool {
    let Some(_guard): Option<DepthGuard> = DepthGuard::enter() else {
        return false;
    };
    match term {
        Term::Tuple(items) => {
            if let [head, meta, args] = items.as_slice()
                && matches!(meta, Term::List { .. } | Term::Nil)
                && matches!(args, Term::List { .. } | Term::Nil | Term::String(_))
            {
                let arguments: Vec<Term> = list_items(args);
                let head_ok: bool = match head {
                    Term::Atom(name) => call_name_renderable(name, arguments.len()),
                    other => source_renderable(other),
                };
                return head_ok && arguments.iter().all(source_renderable);
            }
            items.iter().all(source_renderable)
        }
        Term::List { elements, tail } => {
            matches!(**tail, Term::Nil) && elements.iter().all(source_renderable)
        }
        Term::Map(_) | Term::MapMixed(_) | Term::Pid { .. } | Term::Reference { .. } => false,
        _ => true,
    }
}

fn escaped_tuple_fields(term: &Term) -> Option<Vec<Term>> {
    let [marker, _, fields] = term.as_tuple()? else {
        return None;
    };
    if marker.as_atom() != Some("{}") || !matches!(fields, Term::List { .. } | Term::Nil) {
        return None;
    }
    Some(list_items(fields))
}

fn unescape_data(term: &Term) -> Option<Term> {
    let _guard: DepthGuard = DepthGuard::enter()?;
    match term {
        Term::Atom(_)
        | Term::SmallInt(_)
        | Term::Int(_)
        | Term::BigInt { .. }
        | Term::Float(_)
        | Term::Binary(_)
        | Term::String(_)
        | Term::Nil => Some(term.clone()),
        Term::List { elements, tail } if matches!(**tail, Term::Nil) => Some(Term::List {
            elements: elements
                .iter()
                .map(unescape_data)
                .collect::<Option<Vec<Term>>>()?,
            tail: Box::new(Term::Nil),
        }),
        Term::Tuple(items) if items.len() == 2 => Some(Term::Tuple(
            items
                .iter()
                .map(unescape_data)
                .collect::<Option<Vec<Term>>>()?,
        )),
        Term::Tuple(_) => Some(Term::Tuple(
            escaped_tuple_fields(term)?
                .iter()
                .map(unescape_data)
                .collect::<Option<Vec<Term>>>()?,
        )),
        _ => None,
    }
}

fn render_nested_defmodule(statements: &[Term]) -> Option<String> {
    let [Term::Atom(_), compile] = statements else {
        return None;
    };
    let [target, _, arguments] = compile.as_tuple()? else {
        return None;
    };
    let (callee, function): (Term, String) = remote_target(target)?;
    if callee.as_atom() != Some("elixir_module") || function != "compile" {
        return None;
    }
    let arguments: Vec<Term> = list_items(arguments);
    let [_, module, escaped, _, _, env] = arguments.as_slice() else {
        return None;
    };
    let body: Term = unescape_data(escaped)?;
    if !source_renderable(&body) {
        return None;
    }
    let env_fields: Vec<Term> = match env.as_tuple()? {
        [marker, _, fields] if marker.as_atom() == Some("%{}") => list_items(fields),
        _ => return None,
    };
    let env_fields: Term = Term::List {
        elements: env_fields,
        tail: Box::new(Term::Nil),
    };
    if keyword_value(&env_fields, "__struct__")
        .as_ref()
        .and_then(Term::as_atom)
        != Some("Elixir.Macro.Env")
    {
        return None;
    }
    let enclosing: Option<Term> = keyword_value(&env_fields, "module");
    let name: String = nested_module_name(module, enclosing.as_ref().and_then(Term::as_atom));
    let lexical: BTreeMap<String, String> = keyword_value(&env_fields, "aliases")
        .map(|aliases: Term| lexical_aliases(&aliases))
        .unwrap_or_default();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    collect_alias_heads(&body, &mut referenced);
    let mut lines: Vec<String> = Vec::new();
    for head in &referenced {
        if let Some(full) = lexical.get(head) {
            let full: String = strip_elixir(full);
            if full.rsplit('.').next() == Some(head.as_str()) {
                lines.push(format!("alias {full}"));
            } else {
                lines.push(format!("alias {full}, as: {head}"));
            }
        }
    }
    lines.push(render_block(&body));
    Some(format!(
        "defmodule {name} do\n{}\nend",
        indent(&lines.join("\n"))
    ))
}

fn nested_module_name(module: &Term, enclosing: Option<&str>) -> String {
    let Term::Atom(full) = module else {
        return render(module, Prec::Lowest);
    };
    if let Some(enclosing) = enclosing
        && let Some(nested) = full
            .strip_prefix(enclosing)
            .and_then(|rest: &str| rest.strip_prefix('.'))
        && nested.split('.').all(is_alias_segment)
    {
        return nested.to_owned();
    }
    if let Some(rest) = full.strip_prefix("Elixir.")
        && rest.split('.').all(is_alias_segment)
    {
        return full.clone();
    }
    render_atom_literal(full)
}

fn lexical_aliases(aliases: &Term) -> BTreeMap<String, String> {
    list_items(aliases)
        .iter()
        .filter_map(|pair: &Term| match pair.as_tuple()? {
            [Term::Atom(short), Term::Atom(full)] => {
                Some((short.strip_prefix("Elixir.")?.to_owned(), full.clone()))
            }
            _ => None,
        })
        .collect()
}

fn collect_alias_heads(term: &Term, out: &mut BTreeSet<String>) {
    let Some(_guard): Option<DepthGuard> = DepthGuard::enter() else {
        return;
    };
    match term {
        Term::Tuple(items) => {
            if let [head, _, segments] = items.as_slice()
                && head.as_atom() == Some("__aliases__")
                && let Some(Term::Atom(first)) = list_items(segments).first()
            {
                out.insert(first.clone());
            }
            for item in items {
                collect_alias_heads(item, out);
            }
        }
        Term::List { elements, tail } => {
            for element in elements {
                collect_alias_heads(element, out);
            }
            collect_alias_heads(tail, out);
        }
        _ => {}
    }
}

struct QuoteScan<'a> {
    module: &'a str,
    quoted: bool,
}

fn render_as_quote(items: &[Term]) -> Option<String> {
    let [marker, _, fields] = items else {
        return None;
    };
    if marker.as_atom() != Some("{}") || !matches!(fields, Term::List { .. }) {
        return None;
    }
    let module: String = rendered_module()?;
    let mut scan: QuoteScan<'_> = QuoteScan {
        module: &module,
        quoted: false,
    };
    let ast: Term = unquote_ast(&Term::Tuple(items.to_vec()), &mut scan);
    if !scan.quoted || is_unquote_hole(&ast) {
        return None;
    }
    Some(format!("quote do\n{}\nend", indent(&render_block(&ast))))
}

fn is_unquote_hole(term: &Term) -> bool {
    term.as_tuple()
        .and_then(<[Term]>::first)
        .and_then(Term::as_atom)
        == Some("unquote")
}

fn unquote_hole(expression: &Term, scan: &mut QuoteScan<'_>) -> Term {
    let inner: Term = match expression.as_tuple() {
        Some([target, _, arguments])
            if remote_target(target).is_some_and(|(callee, function): (Term, String)| {
                callee.as_atom() == Some("elixir_quote") && function == "shallow_validate_ast"
            }) =>
        {
            match list_items(arguments).as_slice() {
                [validated] => {
                    scan.quoted = true;
                    validated.clone()
                }
                _ => expression.clone(),
            }
        }
        _ => expression.clone(),
    };
    Term::Tuple(vec![
        Term::Atom("unquote".to_owned()),
        Term::Nil,
        Term::List {
            elements: vec![inner],
            tail: Box::new(Term::Nil),
        },
    ])
}

fn unquote_ast(term: &Term, scan: &mut QuoteScan<'_>) -> Term {
    let Some(_guard): Option<DepthGuard> = DepthGuard::enter() else {
        return unquote_hole(term, scan);
    };
    match term {
        Term::Atom(_)
        | Term::SmallInt(_)
        | Term::Int(_)
        | Term::BigInt { .. }
        | Term::Float(_)
        | Term::Binary(_)
        | Term::String(_)
        | Term::Nil => term.clone(),
        Term::List { elements, tail }
            if matches!(**tail, Term::Nil) && !has_cons_tail(elements) =>
        {
            Term::List {
                elements: elements
                    .iter()
                    .map(|e: &Term| unquote_ast(e, scan))
                    .collect(),
                tail: Box::new(Term::Nil),
            }
        }
        Term::Tuple(items) if items.len() == 2 => Term::Tuple(
            items
                .iter()
                .map(|item: &Term| unquote_ast(item, scan))
                .collect(),
        ),
        Term::Tuple(_) => match escaped_tuple_fields(term).as_deref() {
            Some([head, meta, arguments]) => unquote_node(term, head, meta, arguments, scan),
            _ => unquote_hole(term, scan),
        },
        _ => unquote_hole(term, scan),
    }
}

fn has_cons_tail(elements: &[Term]) -> bool {
    elements
        .last()
        .and_then(Term::as_tuple)
        .is_some_and(|t: &[Term]| t.len() == 3 && t[0].as_atom() == Some("|"))
}

fn unquote_node(
    term: &Term,
    head: &Term,
    meta: &Term,
    arguments: &Term,
    scan: &mut QuoteScan<'_>,
) -> Term {
    let Some(meta) = quote_generated_meta(meta, scan.module) else {
        return unquote_hole(term, scan);
    };
    if meta.context {
        scan.quoted = true;
    }
    if head.as_atom() == Some("__aliases__")
        && let Some(expanded) = meta.alias
    {
        return Term::Atom(expanded);
    }
    if let Term::Atom(context) = arguments {
        if !matches!(head, Term::Atom(_)) || context != scan.module {
            return unquote_hole(term, scan);
        }
        scan.quoted = true;
        return Term::Tuple(vec![head.clone(), Term::Nil, arguments.clone()]);
    }
    if !matches!(arguments, Term::List { .. } | Term::Nil | Term::String(_))
        || matches!(arguments, Term::List { elements, tail } if !matches!(**tail, Term::Nil) || has_cons_tail(elements))
    {
        return unquote_hole(term, scan);
    }
    let arguments: Vec<Term> = list_items(arguments);
    if let Term::Atom(name) = head
        && !call_name_renderable(name, arguments.len())
    {
        return unquote_hole(term, scan);
    }
    let head: Term = unquote_ast(head, scan);
    let arguments: Vec<Term> = arguments
        .iter()
        .map(|argument: &Term| unquote_ast(argument, scan))
        .collect();
    let arguments: Term = if arguments.is_empty() {
        Term::Nil
    } else {
        Term::List {
            elements: arguments,
            tail: Box::new(Term::Nil),
        }
    };
    Term::Tuple(vec![head, Term::Nil, arguments])
}

struct GeneratedMeta {
    context: bool,
    alias: Option<String>,
}

fn quote_generated_meta(meta: &Term, module: &str) -> Option<GeneratedMeta> {
    let mut generated: GeneratedMeta = GeneratedMeta {
        context: false,
        alias: None,
    };
    for entry in list_items(meta) {
        let [Term::Atom(key), value] = entry.as_tuple()? else {
            return None;
        };
        match (key.as_str(), value) {
            ("context", Term::Atom(context)) if context == module => generated.context = true,
            ("imports", imports) if imports_are_kernel(imports) => {}
            ("alias", Term::Atom(alias)) if alias == "false" => {}
            ("alias", Term::Atom(alias)) => generated.alias = Some(alias.clone()),
            _ => return None,
        }
    }
    Some(generated)
}

fn imports_are_kernel(imports: &Term) -> bool {
    list_items(imports).iter().all(|import: &Term| {
        matches!(import.as_tuple(), Some([Term::SmallInt(_), Term::Atom(module)]) if module == "Elixir.Kernel")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(name: &str) -> Term {
        Term::Atom(name.to_owned())
    }

    fn list(elements: Vec<Term>) -> Term {
        Term::List {
            elements,
            tail: Box::new(Term::Nil),
        }
    }

    fn var(name: &str) -> Term {
        Term::Tuple(vec![atom(name), Term::Nil, atom("nil")])
    }

    fn erlang_call(fun: &str, args: Vec<Term>) -> Term {
        let dot: Term = Term::Tuple(vec![
            atom("."),
            Term::Nil,
            list(vec![atom("erlang"), atom(fun)]),
        ]);
        Term::Tuple(vec![dot, Term::Nil, list(args)])
    }

    #[test]
    fn erlang_operators_render_with_elixir_semantics_and_precedence() {
        let strict: Term = erlang_call("=:=", vec![var("a"), var("b")]);
        assert_eq!(render_block(&strict), "a === b");
        let loose: Term = erlang_call("/=", vec![var("a"), var("b")]);
        assert_eq!(render_block(&loose), "a != b");
        let masked: Term = erlang_call(
            "+",
            vec![
                erlang_call("band", vec![var("a"), var("b")]),
                Term::SmallInt(1),
            ],
        );
        assert_eq!(render_block(&masked), "Bitwise.band(a, b) + 1");
        let quotient: Term = erlang_call("div", vec![var("a"), var("b")]);
        assert_eq!(render_block(&quotient), "div(a, b)");
        let left_nested: Term = erlang_call(
            "--",
            vec![erlang_call("--", vec![var("a"), var("b")]), var("c")],
        );
        assert_eq!(render_block(&left_nested), "(a -- b) -- c");
        let right_nested: Term = erlang_call(
            "--",
            vec![var("a"), erlang_call("--", vec![var("b"), var("c")])],
        );
        assert_eq!(render_block(&right_nested), "a -- b -- c");
        let double_negation: Term = erlang_call("-", vec![Term::Int(-1)]);
        assert_eq!(render_block(&double_negation), "-(-1)");
        let relational_in_equality: Term = erlang_call(
            "==",
            vec![erlang_call("<", vec![var("a"), var("b")]), atom("true")],
        );
        assert_eq!(render_block(&relational_in_equality), "a < b == true");
        let equality_in_relational: Term = erlang_call(
            "<",
            vec![erlang_call("==", vec![var("a"), var("b")]), atom("true")],
        );
        assert_eq!(render_block(&equality_in_relational), "(a == b) < true");
    }

    #[test]
    fn local_calls_keep_their_parentheses_and_integer_list_arguments() {
        let no_args: Term = Term::Tuple(vec![atom("helper"), Term::Nil, Term::Nil]);
        assert_eq!(render_block(&no_args), "helper()");
        let byte_args: Term =
            Term::Tuple(vec![atom("masked"), Term::Nil, Term::String(vec![6, 3])]);
        assert_eq!(render_block(&byte_args), "masked(6, 3)");
        assert_eq!(render_block(&var("helper")), "helper");
        assert_eq!(render_block(&Term::String(vec![1, 2, 3])), "[1, 2, 3]");
        assert_eq!(render_block(&Term::String(b"ok".to_vec())), "~c\"ok\"");
    }

    #[test]
    fn literals_escape_interpolation_and_control_characters() {
        assert_eq!(
            render_block(&Term::Binary(b"a#{b} #x".to_vec())),
            "\"a\\#{b} #x\""
        );
        assert_eq!(
            render_block(&Term::String(b"c#{d}".to_vec())),
            "~c\"c\\#{d}\""
        );
        assert_eq!(render_block(&atom("x#{y}")), ":\"x\\#{y}\"");
        assert_eq!(
            render_block(&Term::Binary(b"\x1b\x00q\\".to_vec())),
            "\"\\u{1B}\\u{0}q\\\\\""
        );
    }

    fn pair(key: &str, value: Term) -> Term {
        Term::Tuple(vec![atom(key), value])
    }

    fn escaped_node(head: Term, meta: Term, args: Term) -> Term {
        Term::Tuple(vec![atom("{}"), Term::Nil, list(vec![head, meta, args])])
    }

    fn nested_defmodule(module: &str, body: Term) -> Term {
        let compile: Term = Term::Tuple(vec![
            Term::Tuple(vec![
                atom("."),
                Term::Nil,
                list(vec![atom("elixir_module"), atom("compile")]),
            ]),
            Term::Nil,
            list(vec![
                Term::Nil,
                atom(module),
                body,
                Term::Nil,
                atom("false"),
                Term::Tuple(vec![
                    atom("%{}"),
                    Term::Nil,
                    list(vec![
                        pair("__struct__", atom("Elixir.Macro.Env")),
                        pair(
                            "aliases",
                            list(vec![Term::Tuple(vec![
                                atom("Elixir.Peer"),
                                atom("Elixir.Outer.Peer"),
                            ])]),
                        ),
                        pair("file", Term::Binary(b"/build/outer.ex".to_vec())),
                        pair("module", atom("Elixir.Outer")),
                    ]),
                ]),
            ]),
        ]);
        Term::Tuple(vec![
            atom("__block__"),
            Term::Nil,
            list(vec![atom(module), compile]),
        ])
    }

    #[test]
    fn an_escaped_ast_with_quote_metadata_renders_as_a_quote_block() {
        let context: Term = list(vec![pair("context", atom("Elixir.Outer"))]);
        let kernel_call: Term = escaped_node(
            atom("helper"),
            context,
            list(vec![escaped_node(
                atom("name"),
                Term::Nil,
                atom("Elixir.Outer"),
            )]),
        );
        assert_eq!(
            within_module("Elixir.Outer", || render_block(&kernel_call)),
            "quote do\n  helper(name)\nend"
        );
        let foreign_context: String =
            within_module("Elixir.Elsewhere", || render_block(&kernel_call));
        assert!(!foreign_context.contains("quote"), "{foreign_context}");
        let foreign_import: Term = escaped_node(
            atom("helper"),
            list(vec![
                pair("context", atom("Elixir.Outer")),
                pair(
                    "imports",
                    list(vec![Term::Tuple(vec![
                        Term::SmallInt(0),
                        atom("Elixir.Imported"),
                    ])]),
                ),
            ]),
            Term::Nil,
        );
        let rendered: String = within_module("Elixir.Outer", || render_block(&foreign_import));
        assert!(!rendered.contains("quote"), "{rendered}");
    }

    #[test]
    fn a_macro_body_variable_becomes_an_unquote() {
        let validated: Term = Term::Tuple(vec![
            Term::Tuple(vec![
                atom("."),
                Term::Nil,
                list(vec![atom("elixir_quote"), atom("shallow_validate_ast")]),
            ]),
            Term::Nil,
            list(vec![var("expr")]),
        ]);
        let node: Term = escaped_node(atom("inspect"), Term::Nil, list(vec![validated]));
        assert_eq!(
            within_module("Elixir.Outer", || render_block(&node)),
            "quote do\n  inspect(unquote(expr))\nend"
        );
    }

    #[test]
    fn a_module_defined_in_a_function_renders_as_a_nested_defmodule() {
        let body: Term = escaped_node(
            atom("use"),
            Term::Nil,
            list(vec![escaped_node(
                atom("__aliases__"),
                Term::Nil,
                list(vec![atom("Peer")]),
            )]),
        );
        let rendered: String = render_block(&nested_defmodule("Elixir.Outer.Inner", body));
        assert_eq!(
            rendered,
            "defmodule Inner do\n  alias Outer.Peer\n  use(Peer)\nend"
        );
        let unrelated: String = render_block(&nested_defmodule(
            "Elixir.Other.Inner",
            escaped_node(atom("x"), Term::Nil, Term::Nil),
        ));
        assert_eq!(unrelated, "defmodule Elixir.Other.Inner do\n  x()\nend");
    }

    #[test]
    fn a_nested_module_body_that_is_not_source_ast_keeps_the_compile_call() {
        let rendered: String = render_block(&nested_defmodule(
            "Elixir.Outer.Inner",
            Term::Map(BTreeMap::new()),
        ));
        assert!(
            rendered.contains(":elixir_module.compile") && !rendered.contains("defmodule"),
            "{rendered}"
        );
    }

    #[test]
    fn a_for_comprehension_keeps_its_into_option() {
        let generator: Term =
            Term::Tuple(vec![atom("<-"), Term::Nil, list(vec![var("x"), var("xs")])]);
        let empty_map: Term = Term::Tuple(vec![atom("%{}"), Term::Nil, Term::Nil]);
        let options: Term = list(vec![
            Term::Tuple(vec![atom("into"), empty_map]),
            Term::Tuple(vec![atom("do"), var("x")]),
        ]);
        let call: Term = Term::Tuple(vec![atom("for"), Term::Nil, list(vec![generator, options])]);
        let rendered: String = render_block(&call);
        assert!(
            rendered.contains("x <- xs")
                && rendered.contains("into: %{}")
                && rendered.contains("do: x"),
            "{rendered}"
        );
    }
}
