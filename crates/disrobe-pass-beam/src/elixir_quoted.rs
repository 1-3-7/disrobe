use std::cell::Cell;

use crate::etf::Term;

const MAX_RENDER_DEPTH: u32 = 256;

thread_local! {
    static RENDER_DEPTH: Cell<u32> = const { Cell::new(0) };
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
    Comparison,
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
    if items.len() == 3 {
        let meta_is_list: bool = matches!(&items[1], Term::List { .. } | Term::Nil);
        if meta_is_list {
            match &items[2] {
                Term::Atom(_) => return render_variable(&items[0]),
                Term::Nil => return render_variable(&items[0]),
                Term::List { .. } => return render_call(&items[0], &items[2], parent),
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
                "-" => return format!("-{}", render(&args[0], Prec::Unary)),
                "+" => return format!("+{}", render(&args[0], Prec::Unary)),
                "not" => return format!("not {}", render(&args[0], Prec::Unary)),
                "bnot" => return format!("~~~{}", render(&args[0], Prec::Unary)),
                _ => {}
            }
        }
        if is_kernel_imported(fun, args.len()) {
            let rendered: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            if rendered.is_empty() {
                return fun.clone();
            }
            return format!("{fun}({})", rendered.join(", "));
        }
    }
    let module_is_alias: bool = matches!(module, Term::Atom(a) if a.starts_with("Elixir.") || a.chars().next().is_some_and(|c: char| c.is_ascii_uppercase()));
    let module_str: String = match module {
        Term::Atom(a) => render_module_alias(a),
        other => render(other, Prec::Highest),
    };
    if args.is_empty() {
        if module_is_alias {
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
            let parts: Vec<String> = args
                .iter()
                .map(|a: &Term| render(a, Prec::Lowest))
                .collect();
            return parts.join("\n");
        }
        ("__aliases__", _) => {
            let parts: Vec<String> = args
                .iter()
                .filter_map(|a: &Term| a.as_atom().map(strip_elixir))
                .collect();
            return parts.join(".");
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
        ("-", 1) => return format!("-{}", render(&args[0], Prec::Unary)),
        ("in", 2) => return render_binary_op("in", &args[0], &args[1], Prec::Comparison, parent),
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
    if rendered.is_empty() {
        return name.to_owned();
    }
    format!("{name}({})", rendered.join(", "))
}

fn infix_operator(name: &str) -> Option<(&'static str, Prec)> {
    let entry: (&'static str, Prec) = match name {
        "orelse" | "or" => ("or", Prec::Or),
        "andalso" | "and" => ("and", Prec::And),
        "==" | "=:=" => ("==", Prec::Comparison),
        "/=" | "=/=" => ("!=", Prec::Comparison),
        "<" => ("<", Prec::Comparison),
        ">" => (">", Prec::Comparison),
        "=<" => ("<=", Prec::Comparison),
        ">=" => (">=", Prec::Comparison),
        "<>" => ("<>", Prec::Concat),
        "++" => ("++", Prec::Concat),
        "--" => ("--", Prec::Concat),
        "+" => ("+", Prec::Additive),
        "-" => ("-", Prec::Additive),
        "*" => ("*", Prec::Multiplicative),
        "/" => ("/", Prec::Multiplicative),
        "div" => ("div", Prec::Multiplicative),
        "rem" => ("rem", Prec::Multiplicative),
        "band" => ("&&&", Prec::Multiplicative),
        "bor" => ("|||", Prec::Additive),
        "bxor" => ("^^^", Prec::Additive),
        "bsl" => ("<<<", Prec::Comparison),
        "bsr" => (">>>", Prec::Comparison),
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

fn render_binary_op(op: &str, lhs: &Term, rhs: &Term, prec: Prec, parent: Prec) -> String {
    let inner: String = format!(
        "{} {op} {}",
        render(lhs, prec),
        render(rhs, next_prec(prec))
    );
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
        Prec::And => Prec::Comparison,
        Prec::Comparison => Prec::Concat,
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
    let (opts, quals): (&[Term], &[Term]) =
        args.split_last().map_or((&[], args), |(last, head)| {
            if is_keyword_list(last) {
                (head, std::slice::from_ref(last))
            } else {
                (args, &[])
            }
        });
    let _ = quals;
    let (do_opts, gens): (Option<Term>, Vec<&Term>) = split_do(args);
    let qual_strs: Vec<String> = gens
        .iter()
        .map(|q: &&Term| render(q, Prec::Lowest))
        .collect();
    let body: String = do_opts.map_or_else(|| "nil".to_owned(), |t: Term| render_block(&t));
    let _ = opts;
    format!("for {}, do: {body}", qual_strs.join(", "))
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
            if spec.is_empty() || spec == "binary" {
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
                Some(format!("{key}: {}", render(&t[1], Prec::Lowest)))
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
        _ => format!(":\"{}\"", a.replace('"', "\\\"")),
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
    (first.is_ascii_lowercase() || first == '_')
        && a.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '@')
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
    match core::str::from_utf8(bytes) {
        Ok(s) => format!("~c\"{}\"", escape_double(s)),
        Err(_) => format!("[{}]", join_bytes(bytes)),
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
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
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
