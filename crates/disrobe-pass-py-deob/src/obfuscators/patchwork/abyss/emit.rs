use std::fmt::Arguments;

use super::Const;
use super::lift::{AssignTarget, PyExpr, PyStmt};

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    push_format(output, args);
    output.push('\n');
}

pub(super) fn render_stmt(stmt: &PyStmt, indent: usize, mut out: &mut String) {
    let pad: String = "    ".repeat(indent);
    match stmt {
        PyStmt::Pass => {
            push_line!(out, "{pad}pass");
        }
        PyStmt::Break => {
            push_line!(out, "{pad}break");
        }
        PyStmt::Continue => {
            push_line!(out, "{pad}continue");
        }
        PyStmt::Global(names) => {
            push_line!(out, "{pad}global {}", names.join(", "));
        }
        PyStmt::Return(None) => {
            push_line!(out, "{pad}return");
        }
        PyStmt::Return(Some(value)) => {
            push_line!(out, "{pad}return {}", render_expr(value, 0));
        }
        PyStmt::ExprStmt(value) => {
            push_line!(out, "{pad}{}", render_expr(value, 0));
        }
        PyStmt::Assign(targets, value) => {
            let mut lhs: String = String::new();
            for target in targets {
                lhs.push_str(&render_target(target));
                lhs.push_str(" = ");
            }
            push_line!(out, "{pad}{lhs}{}", render_expr(value, 0));
        }
        PyStmt::If(test, body, orelse) => {
            push_line!(out, "{pad}if {}:", render_expr(test, 0));
            render_block(body, indent + 1, out);
            if !orelse.is_empty() {
                push_line!(out, "{pad}else:");
                render_block(orelse, indent + 1, out);
            }
        }
        PyStmt::While(test, body) => {
            push_line!(out, "{pad}while {}:", render_expr(test, 0));
            render_block(body, indent + 1, out);
        }
        PyStmt::For(target, iter, body) => {
            push_line!(
                out,
                "{pad}for {} in {}:",
                render_target(target),
                render_expr(iter, 0)
            );
            render_block(body, indent + 1, out);
        }
    }
}

fn render_block(body: &[PyStmt], indent: usize, mut out: &mut String) {
    if body.is_empty() {
        let pad: String = "    ".repeat(indent);
        push_line!(out, "{pad}pass");
        return;
    }
    for stmt in body {
        render_stmt(stmt, indent, out);
    }
}

fn render_target(target: &AssignTarget) -> String {
    match target {
        AssignTarget::Name(name) => name.clone(),
        AssignTarget::Tuple(elts) => {
            let parts: Vec<String> = elts.iter().map(render_target).collect();
            if parts.len() == 1 {
                format!("({},)", parts.join(", "))
            } else {
                format!("({})", parts.join(", "))
            }
        }
    }
}

fn render_expr(expr: &PyExpr, parent_prec: u8) -> String {
    let (text, prec): (String, u8) = render_expr_prec(expr);
    if prec < parent_prec {
        format!("({text})")
    } else {
        text
    }
}

fn render_expr_prec(expr: &PyExpr) -> (String, u8) {
    match expr {
        PyExpr::Name(name) => (name.clone(), 20),
        PyExpr::ConstLit(konst) => (render_const(konst), 20),
        PyExpr::Bin(left, op, right) => {
            let prec: u8 = bin_prec(op);
            let lhs: String = render_expr(left, prec);
            let rhs: String = render_expr(right, prec + 1);
            (format!("{lhs} {op} {rhs}"), prec)
        }
        PyExpr::Unary(op, operand) => {
            let inner: String = render_expr(operand, 15);
            if op == "not " {
                (format!("not {inner}"), 6)
            } else {
                (format!("{op}{inner}"), 15)
            }
        }
        PyExpr::Compare(left, comps) => {
            let mut text: String = render_expr(left, 8);
            for (op, rhs) in comps {
                text.push(' ');
                text.push_str(op);
                text.push(' ');
                text.push_str(&render_expr(rhs, 8));
            }
            (text, 7)
        }
        PyExpr::BoolOp(op, values) => {
            let prec: u8 = if op == "or" { 4 } else { 5 };
            let parts: Vec<String> = values
                .iter()
                .map(|v: &PyExpr| render_expr(v, prec + 1))
                .collect();
            (parts.join(&format!(" {op} ")), prec)
        }
        PyExpr::Call(func, args, kwargs) => {
            let callee: String = render_expr(func, 18);
            let mut parts: Vec<String> = args.iter().map(|a: &PyExpr| render_expr(a, 0)).collect();
            for (name, value) in kwargs {
                parts.push(format!("{name}={}", render_expr(value, 0)));
            }
            (format!("{callee}({})", parts.join(", ")), 18)
        }
        PyExpr::Attr(value, attr) => (format!("{}.{attr}", render_expr(value, 18)), 18),
        PyExpr::Subscript(value, key) => (
            format!("{}[{}]", render_expr(value, 18), render_slice(key)),
            18,
        ),
        PyExpr::Slice(lower, upper, step) => (render_slice_parts(lower, upper, step), 1),
        PyExpr::List(items) => {
            let parts: Vec<String> = items.iter().map(|i: &PyExpr| render_expr(i, 0)).collect();
            (format!("[{}]", parts.join(", ")), 20)
        }
        PyExpr::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(|i: &PyExpr| render_expr(i, 1)).collect();
            if parts.len() == 1 {
                (format!("({},)", parts.join(", ")), 20)
            } else {
                (format!("({})", parts.join(", ")), 20)
            }
        }
        PyExpr::Set(items) => {
            let parts: Vec<String> = items.iter().map(|i: &PyExpr| render_expr(i, 0)).collect();
            (format!("{{{}}}", parts.join(", ")), 20)
        }
        PyExpr::Dict(pairs) => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(k, v): &(PyExpr, PyExpr)| {
                    format!("{}: {}", render_expr(k, 0), render_expr(v, 0))
                })
                .collect();
            (format!("{{{}}}", parts.join(", ")), 20)
        }
        PyExpr::JoinedStr(parts) => (render_fstring(parts), 20),
        PyExpr::FormatValue(value, conversion, spec) => (
            render_fstring(std::slice::from_ref(&PyExpr::FormatValue(
                value.clone(),
                *conversion,
                spec.clone(),
            ))),
            20,
        ),
        PyExpr::Walrus(name, value) => (format!("({name} := {})", render_expr(value, 0)), 20),
        PyExpr::ListComp(elt, target, iter, ifs) => {
            let mut text: String = format!(
                "[{} for {} in {}",
                render_expr(elt, 0),
                render_target(target),
                render_expr(iter, 5)
            );
            for cond in ifs {
                text.push_str(" if ");
                text.push_str(&render_expr(cond, 5));
            }
            text.push(']');
            (text, 20)
        }
    }
}

fn render_slice(key: &PyExpr) -> String {
    match key {
        PyExpr::Slice(lower, upper, step) => render_slice_parts(lower, upper, step),
        other => render_expr(other, 0),
    }
}

fn render_slice_parts(lower: &PyExpr, upper: &PyExpr, step: &PyExpr) -> String {
    let lower_s: String = render_slice_component(lower);
    let upper_s: String = render_slice_component(upper);
    let step_s: String = render_slice_component(step);
    if matches!(step, PyExpr::ConstLit(Const::None)) {
        format!("{lower_s}:{upper_s}")
    } else {
        format!("{lower_s}:{upper_s}:{step_s}")
    }
}

fn render_slice_component(expr: &PyExpr) -> String {
    if matches!(expr, PyExpr::ConstLit(Const::None)) {
        String::new()
    } else {
        render_expr(expr, 0)
    }
}

fn render_fstring(parts: &[PyExpr]) -> String {
    let mut out: String = String::from("f\"");
    for part in parts {
        match part {
            PyExpr::ConstLit(Const::Str(text)) => {
                for ch in text.chars() {
                    match ch {
                        '{' => out.push_str("{{"),
                        '}' => out.push_str("}}"),
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\t' => out.push_str("\\t"),
                        '\r' => out.push_str("\\r"),
                        _ => out.push(ch),
                    }
                }
            }
            PyExpr::FormatValue(value, conversion, spec) => {
                out.push('{');
                out.push_str(&render_expr(value, 0));
                match conversion {
                    115 => out.push_str("!s"),
                    114 => out.push_str("!r"),
                    97 => out.push_str("!a"),
                    _ => {}
                }
                if let Some(spec_expr) = spec {
                    out.push(':');
                    out.push_str(&render_format_spec(spec_expr));
                }
                out.push('}');
            }
            other => {
                out.push('{');
                out.push_str(&render_expr(other, 0));
                out.push('}');
            }
        }
    }
    out.push('"');
    out
}

fn render_format_spec(spec: &PyExpr) -> String {
    match spec {
        PyExpr::ConstLit(Const::Str(text)) => text.clone(),
        PyExpr::JoinedStr(parts) => {
            let mut out: String = String::new();
            for part in parts {
                match part {
                    PyExpr::ConstLit(Const::Str(text)) => out.push_str(text),
                    PyExpr::FormatValue(value, _, _) => {
                        out.push('{');
                        out.push_str(&render_expr(value, 0));
                        out.push('}');
                    }
                    other => {
                        out.push('{');
                        out.push_str(&render_expr(other, 0));
                        out.push('}');
                    }
                }
            }
            out
        }
        other => render_expr(other, 0),
    }
}

fn bin_prec(op: &str) -> u8 {
    match op {
        "|" => 9,
        "^" => 10,
        "&" => 11,
        "<<" | ">>" => 12,
        "*" | "/" | "//" | "%" | "@" => 14,
        "**" => 16,
        _ => 13,
    }
}

fn render_const(konst: &Const) -> String {
    match konst {
        Const::None => "None".to_owned(),
        Const::Ellipsis => "...".to_owned(),
        Const::Bool(true) => "True".to_owned(),
        Const::Bool(false) => "False".to_owned(),
        Const::Int(text) | Const::Float(text) => text.clone(),
        Const::Str(text) => render_string_literal(text),
        Const::Bytes(data) => render_bytes_literal(data),
    }
}

pub(super) fn render_string_literal(text: &str) -> String {
    let mut out: String = String::from("'");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn render_bytes_literal(data: &[u8]) -> String {
    let mut out: String = String::from("b'");
    for &byte in data {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                push_text!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push('\'');
    out
}
