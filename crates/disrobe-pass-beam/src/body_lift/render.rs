use crate::body_lift::expr::{AfterClause, BinSegment, CaseArm, CatchArm, Expr, IfArm, Stmt};

#[must_use]
pub fn render_body(stmts: &[Stmt], indent: usize) -> String {
    if stmts.is_empty() {
        return format!("{}ok", pad(indent));
    }
    let rendered: Vec<String> = stmts
        .iter()
        .map(|s: &Stmt| render_stmt(s, indent))
        .collect();
    rendered.join(",\n")
}

fn render_stmt(stmt: &Stmt, indent: usize) -> String {
    let p: String = pad(indent);
    match stmt {
        Stmt::Return(expr) | Stmt::Expr(expr) => {
            format!("{p}{}", render_expr_indented(expr, indent))
        }
        Stmt::Bind { pattern, value } | Stmt::Match { pattern, value } => format!(
            "{p}{} = {}",
            render_expr(pattern),
            render_bind_value(value, indent)
        ),
        Stmt::Send { dest, msg } => {
            format!("{p}{} ! {}", render_operand(dest), render_operand(msg))
        }
        Stmt::Comment(text) => format!("{p}erlang:error({{disrobe_unrecovered, {text:?}}})"),
    }
}

fn render_bind_value(expr: &Expr, indent: usize) -> String {
    match expr {
        Expr::Catch(_) => format!("({})", render_expr(expr)),
        _ => render_expr_indented(expr, indent),
    }
}

fn render_expr_indented(expr: &Expr, indent: usize) -> String {
    match expr {
        Expr::Case { subject, arms } => render_case(subject, arms, indent),
        Expr::If { arms } => render_if(arms, indent),
        Expr::Receive { arms, after } => render_receive(arms, after.as_deref(), indent),
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => render_try(body, of_arms, catch_arms, after, indent),
        Expr::Block(stmts) => render_body(stmts, indent),
        _ => render_expr(expr),
    }
}

fn render_case(subject: &Expr, arms: &[CaseArm], indent: usize) -> String {
    let p: String = pad(indent);
    let mut out: String = format!("case {} of\n", render_expr(subject));
    out.push_str(&render_arms(arms, indent + 1));
    out.push('\n');
    out.push_str(&p);
    out.push_str("end");
    out
}

fn render_arms(arms: &[CaseArm], indent: usize) -> String {
    let rendered: Vec<String> = arms
        .iter()
        .map(|arm: &CaseArm| {
            let head: String = match &arm.guard {
                Some(g) => format!("{} when {}", render_expr(&arm.pattern), render_expr(g)),
                None => render_expr(&arm.pattern),
            };
            format!(
                "{}{head} ->\n{}",
                pad(indent),
                render_body(&arm.body, indent + 1)
            )
        })
        .collect();
    rendered.join(";\n")
}

fn render_if(arms: &[IfArm], indent: usize) -> String {
    let p: String = pad(indent);
    let rendered: Vec<String> = arms
        .iter()
        .map(|arm: &IfArm| {
            format!(
                "{}{} ->\n{}",
                pad(indent + 1),
                render_expr(&arm.guard),
                render_body(&arm.body, indent + 2)
            )
        })
        .collect();
    format!("if\n{}\n{p}end", rendered.join(";\n"))
}

fn render_receive(arms: &[CaseArm], after: Option<&AfterClause>, indent: usize) -> String {
    let p: String = pad(indent);
    let mut out: String = String::from("receive\n");
    out.push_str(&render_arms(arms, indent + 1));
    if let Some(after) = after {
        out.push('\n');
        out.push_str(&p);
        out.push_str(&format!("after {} ->\n", render_expr(&after.timeout)));
        out.push_str(&render_body(&after.body, indent + 1));
    }
    out.push('\n');
    out.push_str(&p);
    out.push_str("end");
    out
}

fn render_try(
    body: &[Stmt],
    of_arms: &[CaseArm],
    catch_arms: &[CatchArm],
    after: &[Stmt],
    indent: usize,
) -> String {
    let p: String = pad(indent);
    let mut out: String = String::from("try\n");
    out.push_str(&render_body(body, indent + 1));
    if !of_arms.is_empty() {
        out.push('\n');
        out.push_str(&p);
        out.push_str("of\n");
        out.push_str(&render_arms(of_arms, indent + 1));
    }
    if !catch_arms.is_empty() {
        out.push('\n');
        out.push_str(&p);
        out.push_str("catch\n");
        let rendered: Vec<String> = catch_arms
            .iter()
            .map(|arm: &CatchArm| {
                let st: String = arm
                    .stacktrace
                    .as_ref()
                    .map_or_else(String::new, |s: &String| format!(":{s}"));
                format!(
                    "{}{}:{}{st} ->\n{}",
                    pad(indent + 1),
                    arm.class,
                    render_expr(&arm.pattern),
                    render_body(&arm.body, indent + 2)
                )
            })
            .collect();
        out.push_str(&rendered.join(";\n"));
    }
    if !after.is_empty() {
        out.push('\n');
        out.push_str(&p);
        out.push_str("after\n");
        out.push_str(&render_body(after, indent + 1));
    }
    out.push('\n');
    out.push_str(&p);
    out.push_str("end");
    out
}

fn pad(indent: usize) -> String {
    "    ".repeat(indent)
}

#[must_use]
pub fn render_expr(expr: &Expr) -> String {
    match expr {
        Expr::Var(name) => name.clone(),
        Expr::Atom(a) => render_atom(a),
        Expr::Nil => "[]".to_owned(),
        Expr::Int(v) => v.to_string(),
        Expr::BigInt { sign, magnitude_le } => render_bigint(*sign, magnitude_le),
        Expr::Float(s) => s.clone(),
        Expr::Str(s) => format!("\"{}\"", escape_string(s)),
        Expr::CharLit(c) => format!("${}", render_char(*c)),
        Expr::BinaryLit(bytes) => render_binary_literal(bytes),
        Expr::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(render_expr).collect();
            format!("{{{}}}", parts.join(", "))
        }
        Expr::List { elements, tail } => render_list(elements, tail),
        Expr::Cons { head, tail } => format!("[{} | {}]", render_expr(head), render_expr(tail)),
        Expr::Map { pairs } => render_map_pairs("#{", pairs, "=>"),
        Expr::MapPattern { pairs } => render_map_pairs("#{", pairs, ":="),
        Expr::MapUpdate { base, exact, pairs } => {
            let op: &str = if *exact { ":=" } else { "=>" };
            let body: String = pairs
                .iter()
                .map(|(k, v): &(Expr, Expr)| format!("{} {op} {}", render_expr(k), render_expr(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}#{{{body}}}", render_primary(base))
        }
        Expr::TupleElement { tuple, index } => {
            format!("element({}, {})", index + 1, render_expr(tuple))
        }
        Expr::RecordUpdate { base, updates } => render_record_update(base, updates),
        Expr::Call { target, args } => {
            let parts: Vec<String> = args.iter().map(render_expr).collect();
            format!("{target}({})", parts.join(", "))
        }
        Expr::BinOp { op, lhs, rhs } => {
            format!("{} {op} {}", render_operand(lhs), render_operand(rhs))
        }
        Expr::UnOp { op, operand } => {
            let sep: &str = if op.len() > 1 { " " } else { "" };
            format!("{op}{sep}{}", render_operand(operand))
        }
        Expr::Guard { name, args } => {
            let parts: Vec<String> = args.iter().map(render_expr).collect();
            format!("{name}({})", parts.join(", "))
        }
        Expr::MakeFun { name, arity, .. } => format!("fun {name}/{arity}"),
        Expr::CallFun { fun, args } => {
            let parts: Vec<String> = args.iter().map(render_expr).collect();
            format!("{}({})", render_operand(fun), parts.join(", "))
        }
        Expr::BinaryConstruct(segments) => render_binary_construct(segments),
        Expr::Catch(inner) => format!("catch {}", render_expr(inner)),
        Expr::Case { subject, arms } => render_case(subject, arms, 0),
        Expr::If { arms } => render_if(arms, 0),
        Expr::Receive { arms, after } => render_receive(arms, after.as_deref(), 0),
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => render_try(body, of_arms, catch_arms, after, 0),
        Expr::Block(stmts) => render_body(stmts, 0),
        Expr::Raw(s) => s.clone(),
    }
}

fn render_record_update(base: &Expr, updates: &[(u32, Expr)]) -> String {
    let mut acc: String = render_expr(base);
    for (index, value) in updates {
        acc = format!("setelement({index}, {acc}, {})", render_expr(value));
    }
    acc
}

fn render_operand(expr: &Expr) -> String {
    match expr {
        Expr::BinOp { .. } | Expr::UnOp { .. } | Expr::Catch(_) => {
            format!("({})", render_expr(expr))
        }
        _ => render_expr(expr),
    }
}

fn render_primary(expr: &Expr) -> String {
    match expr {
        Expr::Var(_)
        | Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_)
        | Expr::Tuple(_)
        | Expr::List { .. }
        | Expr::Cons { .. }
        | Expr::Map { .. }
        | Expr::MapUpdate { .. } => render_expr(expr),
        _ => format!("({})", render_expr(expr)),
    }
}

fn render_list(elements: &[Expr], tail: &Expr) -> String {
    let parts: Vec<String> = elements.iter().map(render_expr).collect();
    match tail {
        Expr::Nil => format!("[{}]", parts.join(", ")),
        other => format!("[{} | {}]", parts.join(", "), render_expr(other)),
    }
}

fn render_map_pairs(open: &str, pairs: &[(Expr, Expr)], arrow: &str) -> String {
    let body: String = pairs
        .iter()
        .map(|(k, v): &(Expr, Expr)| format!("{} {arrow} {}", render_expr(k), render_expr(v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{open}{body}}}")
}

#[must_use]
pub fn render_atom(a: &str) -> String {
    if needs_quoting(a) {
        format!("'{}'", a.replace('\\', "\\\\").replace('\'', "\\'"))
    } else {
        a.to_owned()
    }
}

fn needs_quoting(a: &str) -> bool {
    let Some(first): Option<char> = a.chars().next() else {
        return true;
    };
    if !first.is_ascii_lowercase() {
        return true;
    }
    !a.chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '@')
}

fn render_char(c: u32) -> String {
    char::from_u32(c).map_or_else(|| format!("\\x{c:x}"), |ch: char| ch.to_string())
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
}

fn render_binary_literal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<<>>".to_owned();
    }
    if let Ok(s) = core::str::from_utf8(bytes)
        && s.chars().all(|c: char| !c.is_control() || c == '\n')
    {
        return format!("<<\"{}\">>", escape_string(s));
    }
    let parts: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("<<{}>>", parts.join(", "))
}

fn render_bin_size(expr: &Expr) -> String {
    match expr {
        Expr::Int(_) | Expr::Var(_) | Expr::CharLit(_) => render_expr(expr),
        _ => format!("({})", render_expr(expr)),
    }
}

fn render_binary_construct(segments: &[BinSegment]) -> String {
    let parts: Vec<String> = segments
        .iter()
        .map(|seg: &BinSegment| {
            let mut s: String = render_primary(&seg.value);
            let mut specs: Vec<String> = Vec::new();
            if let Some(size) = &seg.size {
                s.push(':');
                s.push_str(&render_bin_size(size));
            }
            if !seg.kind.is_empty() && seg.kind != "integer" {
                specs.push(seg.kind.clone());
            }
            for flag in &seg.flags {
                specs.push(flag.clone());
            }
            if seg.unit != 0 && seg.unit != default_unit(&seg.kind) {
                specs.push(format!("unit:{}", seg.unit));
            }
            if !specs.is_empty() {
                s.push('/');
                s.push_str(&specs.join("-"));
            }
            s
        })
        .collect();
    format!("<<{}>>", parts.join(", "))
}

const fn default_unit(kind: &str) -> u32 {
    match kind.as_bytes() {
        b"binary" | b"bytes" => 8,
        _ => 1,
    }
}

fn render_bigint(sign: u8, magnitude_le: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    let mut be: Vec<u8> = magnitude_le.to_vec();
    be.reverse();
    let mut work: Vec<u8> = be;
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
