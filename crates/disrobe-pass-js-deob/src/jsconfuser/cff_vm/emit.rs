use super::ir::{
    AssignOp, BinaryOp, Expr, FuncDef, LogicalOp, Param, PropKey, Stmt, SwitchCase, UnaryOp,
    UpdateOp, VarKind,
};

pub(super) fn emit_stmts(stmts: &[Stmt]) -> String {
    let mut out: String = String::new();
    for stmt in stmts {
        emit_stmt(stmt, 0, &mut out);
        out.push('\n');
    }
    out
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn emit_block(stmts: &[Stmt], level: usize, out: &mut String) {
    out.push_str("{\n");
    for stmt in stmts {
        indent(level + 1, out);
        emit_stmt(stmt, level + 1, out);
        out.push('\n');
    }
    indent(level, out);
    out.push('}');
}

#[allow(clippy::too_many_lines)]
fn emit_stmt(stmt: &Stmt, level: usize, out: &mut String) {
    match stmt {
        Stmt::Expr(e) => {
            out.push_str(&emit_expr(e));
            out.push(';');
        }
        Stmt::Empty => out.push(';'),
        Stmt::Block(body) => emit_block(body, level, out),
        Stmt::VarDecl { kind, decls } => {
            out.push_str(match kind {
                VarKind::Var => "var ",
                VarKind::Let => "let ",
                VarKind::Const => "const ",
            });
            let parts: Vec<String> = decls
                .iter()
                .map(|(name, init): &(String, Option<Expr>)| {
                    init.as_ref()
                        .map_or_else(|| name.clone(), |e| format!("{name} = {}", emit_expr(e)))
                })
                .collect();
            out.push_str(&parts.join(", "));
            out.push(';');
        }
        Stmt::FuncDecl(f) => out.push_str(&emit_func(f)),
        Stmt::Return(arg) => match arg {
            Some(e) => {
                out.push_str("return ");
                out.push_str(&emit_expr(e));
                out.push(';');
            }
            None => out.push_str("return;"),
        },
        Stmt::Break(label) => match label {
            Some(l) => {
                out.push_str("break ");
                out.push_str(l);
                out.push(';');
            }
            None => out.push_str("break;"),
        },
        Stmt::Continue(label) => match label {
            Some(l) => {
                out.push_str("continue ");
                out.push_str(l);
                out.push(';');
            }
            None => out.push_str("continue;"),
        },
        Stmt::If {
            test,
            consequent,
            alternate,
        } => {
            out.push_str("if (");
            out.push_str(&emit_expr(test));
            out.push_str(") ");
            emit_block(consequent, level, out);
            if !alternate.is_empty() {
                out.push_str(" else ");
                emit_block(alternate, level, out);
            }
        }
        Stmt::While { test, body } => {
            out.push_str("while (");
            out.push_str(&emit_expr(test));
            out.push_str(") ");
            emit_block(body, level, out);
        }
        Stmt::DoWhile { body, test } => {
            out.push_str("do ");
            emit_block(body, level, out);
            out.push_str(" while (");
            out.push_str(&emit_expr(test));
            out.push_str(");");
        }
        Stmt::For {
            init,
            test,
            update,
            body,
        } => {
            out.push_str("for (");
            if let Some(i) = init {
                let mut head: String = String::new();
                emit_stmt(i, 0, &mut head);
                out.push_str(head.trim_end_matches(';'));
            }
            out.push_str("; ");
            if let Some(t) = test {
                out.push_str(&emit_expr(t));
            }
            out.push_str("; ");
            if let Some(u) = update {
                out.push_str(&emit_expr(u));
            }
            out.push_str(") ");
            emit_block(body, level, out);
        }
        Stmt::ForIn { left, right, body } => {
            emit_for_inof("in", left, right, body, level, out);
        }
        Stmt::ForOf { left, right, body } => {
            emit_for_inof("of", left, right, body, level, out);
        }
        Stmt::Switch {
            discriminant,
            cases,
        } => {
            out.push_str("switch (");
            out.push_str(&emit_expr(discriminant));
            out.push_str(") {\n");
            for case in cases {
                emit_case(case, level + 1, out);
            }
            indent(level, out);
            out.push('}');
        }
        Stmt::With { object, body } => {
            out.push_str("with (");
            out.push_str(&emit_expr(object));
            out.push_str(") ");
            emit_block(body, level, out);
        }
        Stmt::Throw(e) => {
            out.push_str("throw ");
            out.push_str(&emit_expr(e));
            out.push(';');
        }
        Stmt::Labeled { label, body } => {
            out.push_str(label);
            out.push_str(": ");
            emit_stmt(body, level, out);
        }
        Stmt::Raw(s) => out.push_str(s),
    }
}

fn emit_for_inof(
    kw: &str,
    left: &Stmt,
    right: &Expr,
    body: &[Stmt],
    level: usize,
    out: &mut String,
) {
    out.push_str("for (");
    let mut head: String = String::new();
    emit_stmt(left, 0, &mut head);
    out.push_str(head.trim_end_matches(';'));
    out.push(' ');
    out.push_str(kw);
    out.push(' ');
    out.push_str(&emit_expr(right));
    out.push_str(") ");
    emit_block(body, level, out);
}

fn emit_case(case: &SwitchCase, level: usize, out: &mut String) {
    indent(level, out);
    match &case.test {
        Some(t) => {
            out.push_str("case ");
            out.push_str(&emit_expr(t));
            out.push_str(":\n");
        }
        None => out.push_str("default:\n"),
    }
    for stmt in &case.body {
        indent(level + 1, out);
        emit_stmt(stmt, level + 1, out);
        out.push('\n');
    }
}

pub(super) fn emit_func(func: &FuncDef) -> String {
    let mut out: String = String::new();
    if func.is_arrow {
        out.push_str(&emit_params(&func.params));
        out.push_str(" => ");
        if let Some(body) = &func.expression_body {
            out.push_str(&wrap_arrow_body(body));
        } else {
            emit_block(&func.body, 0, &mut out);
        }
        return out;
    }
    if func.is_async {
        out.push_str("async ");
    }
    out.push_str("function");
    if func.is_generator {
        out.push('*');
    }
    out.push(' ');
    if let Some(name) = &func.name {
        out.push_str(name);
    }
    out.push_str(&emit_params(&func.params));
    out.push(' ');
    emit_block(&func.body, 0, &mut out);
    out
}

fn wrap_arrow_body(body: &Expr) -> String {
    match body {
        Expr::Object(_) => format!("({})", emit_expr(body)),
        _ => emit_expr(body),
    }
}

fn emit_params(params: &[Param]) -> String {
    let parts: Vec<String> = params
        .iter()
        .map(|p: &Param| {
            let mut s: String = String::new();
            if p.rest {
                s.push_str("...");
            }
            s.push_str(&p.name);
            if let Some(d) = &p.default {
                s.push_str(" = ");
                s.push_str(&emit_expr(d));
            }
            s
        })
        .collect();
    format!("({})", parts.join(", "))
}

#[allow(clippy::too_many_lines)]
pub(super) fn emit_expr(expr: &Expr) -> String {
    match expr {
        Expr::Num(n) => format_number(*n),
        Expr::Str(s) => format_string(s),
        Expr::Bool(b) => b.to_string(),
        Expr::Null => "null".to_owned(),
        Expr::Undefined => "undefined".to_owned(),
        Expr::Ident(name) => name.clone(),
        Expr::This => "this".to_owned(),
        Expr::Raw(s) => s.clone(),
        Expr::Member {
            object,
            property,
            computed,
        } => {
            let obj: String = emit_member_object(object);
            if *computed {
                format!("{obj}[{}]", emit_expr(property))
            } else if let Expr::Str(name) = property.as_ref() {
                format!("{obj}.{name}")
            } else {
                format!("{obj}[{}]", emit_expr(property))
            }
        }
        Expr::Unary { op, argument } => {
            let kw: &str = match op {
                UnaryOp::Neg => "-",
                UnaryOp::Pos => "+",
                UnaryOp::Not => "!",
                UnaryOp::BitNot => "~",
                UnaryOp::Typeof => "typeof ",
                UnaryOp::Void => "void ",
                UnaryOp::Delete => "delete ",
            };
            format!("{kw}{}", paren_if_low(argument))
        }
        Expr::Update {
            op,
            prefix,
            argument,
        } => {
            let kw: &str = match op {
                UpdateOp::Inc => "++",
                UpdateOp::Dec => "--",
            };
            if *prefix {
                format!("{kw}{}", emit_expr(argument))
            } else {
                format!("{}{kw}", emit_expr(argument))
            }
        }
        Expr::Binary { op, left, right } => {
            format!(
                "{} {} {}",
                paren_if_low(left),
                binary_op_str(*op),
                paren_if_low(right)
            )
        }
        Expr::Logical { op, left, right } => {
            let kw: &str = match op {
                LogicalOp::And => "&&",
                LogicalOp::Or => "||",
                LogicalOp::Coalesce => "??",
            };
            format!("{} {kw} {}", paren_if_low(left), paren_if_low(right))
        }
        Expr::Conditional {
            test,
            consequent,
            alternate,
        } => {
            format!(
                "{} ? {} : {}",
                paren_if_low(test),
                emit_expr(consequent),
                emit_expr(alternate)
            )
        }
        Expr::Assign { op, target, value } => {
            format!(
                "{} {} {}",
                emit_expr(target),
                assign_op_str(*op),
                emit_expr(value)
            )
        }
        Expr::ArrayDestructure { targets, value } => {
            let parts: Vec<String> = targets
                .iter()
                .map(|t: &Option<Expr>| t.as_ref().map_or_else(String::new, emit_expr))
                .collect();
            format!("[{}] = {}", parts.join(", "), emit_expr(value))
        }
        Expr::Array(elements) => {
            let parts: Vec<String> = elements
                .iter()
                .map(|e: &Option<Expr>| e.as_ref().map_or_else(String::new, emit_expr))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Expr::Object(props) => emit_object(props),
        Expr::Sequence(exprs) => {
            let parts: Vec<String> = exprs.iter().map(emit_expr).collect();
            format!("({})", parts.join(", "))
        }
        Expr::Call {
            callee,
            args,
            spread_last,
        } => {
            let parts: Vec<String> = args
                .iter()
                .enumerate()
                .map(|(idx, a): (usize, &Expr)| {
                    if *spread_last && idx + 1 == args.len() {
                        format!("...{}", emit_expr(a))
                    } else {
                        emit_expr(a)
                    }
                })
                .collect();
            format!("{}({})", emit_member_object(callee), parts.join(", "))
        }
        Expr::New { callee, args } => {
            let parts: Vec<String> = args.iter().map(emit_expr).collect();
            format!("new {}({})", emit_member_object(callee), parts.join(", "))
        }
        Expr::Func(f) => {
            let body: String = emit_func(f);
            if f.is_arrow {
                body
            } else {
                format!("({body})")
            }
        }
        Expr::Template { quasis, exprs } => emit_template(quasis, exprs),
        Expr::Spread(inner) => format!("...{}", emit_expr(inner)),
    }
}

fn emit_member_object(expr: &Expr) -> String {
    match expr {
        Expr::Num(_)
        | Expr::Binary { .. }
        | Expr::Logical { .. }
        | Expr::Conditional { .. }
        | Expr::Assign { .. }
        | Expr::Sequence(_)
        | Expr::Unary { .. }
        | Expr::Func(_) => format!("({})", emit_expr(expr)),
        _ => emit_expr(expr),
    }
}

fn emit_object(props: &[(PropKey, Expr)]) -> String {
    if props.is_empty() {
        return "{}".to_owned();
    }
    let parts: Vec<String> = props
        .iter()
        .map(|(key, value): &(PropKey, Expr)| {
            if let Expr::Spread(inner) = value {
                return format!("...{}", emit_expr(inner));
            }
            let k: String = match key {
                PropKey::Ident(name) => name.clone(),
                PropKey::Str(s) => format_string(s),
                PropKey::Num(n) => format_number(*n),
                PropKey::Computed(e) => format!("[{}]", emit_expr(e)),
            };
            format!("{k}: {}", emit_expr(value))
        })
        .collect();
    format!("{{ {} }}", parts.join(", "))
}

fn emit_template(quasis: &[String], exprs: &[Expr]) -> String {
    let mut out: String = String::from("`");
    for (idx, quasi) in quasis.iter().enumerate() {
        out.push_str(&escape_template_chunk(quasi));
        if let Some(e) = exprs.get(idx) {
            out.push_str("${");
            out.push_str(&emit_expr(e));
            out.push('}');
        }
    }
    out.push('`');
    out
}

fn escape_template_chunk(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace("${", "\\${")
        .replace('\r', "\\r")
}

fn paren_if_low(expr: &Expr) -> String {
    match expr {
        Expr::Binary { .. }
        | Expr::Logical { .. }
        | Expr::Conditional { .. }
        | Expr::Assign { .. }
        | Expr::Sequence(_) => format!("({})", emit_expr(expr)),
        _ => emit_expr(expr),
    }
}

const fn binary_op_str(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Pow => "**",
        BinaryOp::Eq => "==",
        BinaryOp::Neq => "!=",
        BinaryOp::StrictEq => "===",
        BinaryOp::StrictNeq => "!==",
        BinaryOp::Lt => "<",
        BinaryOp::Lte => "<=",
        BinaryOp::Gt => ">",
        BinaryOp::Gte => ">=",
        BinaryOp::BitOr => "|",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitXor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::UShr => ">>>",
        BinaryOp::In => "in",
        BinaryOp::Instanceof => "instanceof",
    }
}

const fn assign_op_str(op: AssignOp) -> &'static str {
    match op {
        AssignOp::Assign => "=",
        AssignOp::Add => "+=",
        AssignOp::Sub => "-=",
        AssignOp::Mul => "*=",
        AssignOp::Div => "/=",
        AssignOp::Mod => "%=",
        AssignOp::BitOr => "|=",
        AssignOp::BitAnd => "&=",
        AssignOp::BitXor => "^=",
        AssignOp::Shl => "<<=",
        AssignOp::Shr => ">>=",
        AssignOp::UShr => ">>>=",
        AssignOp::Pow => "**=",
        AssignOp::And => "&&=",
        AssignOp::Or => "||=",
        AssignOp::Coalesce => "??=",
    }
}

pub(super) fn format_number(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_owned();
    }
    if n.is_infinite() {
        return if n < 0.0 {
            "-Infinity".to_owned()
        } else {
            "Infinity".to_owned()
        };
    }
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    let mut buf: String = format!("{n}");
    if !buf.contains('.') && !buf.contains('e') && !buf.contains('E') {
        buf.push_str(".0");
    }
    buf
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

pub(super) fn format_string(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                push_format(&mut out, format_args!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;
    use std::process::{Command, Output};

    fn node_available() -> bool {
        Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|o: Output| o.status.success())
    }

    fn relex_codepoints(assignment: &str) -> Option<String> {
        let program: String = format!(
            "{assignment}\nprocess.stdout.write(Array.from(x).map(c => c.codePointAt(0).toString(16)).join(\",\"));"
        );
        let (scratch, mut file): (disrobe_core::scratch::ScratchFile, fs::File) =
            disrobe_core::scratch::ScratchFile::create("disrobe_cff_emit", "js").ok()?;
        file.write_all(program.as_bytes()).ok()?;
        drop(file);
        let output: Output = Command::new("node")
            .arg("--")
            .arg(scratch.path())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok()
    }

    fn expected_codepoints(value: &str) -> String {
        value
            .chars()
            .map(|c: char| format!("{:x}", c as u32))
            .collect::<Vec<String>>()
            .join(",")
    }

    fn battery() -> Vec<String> {
        vec![
            "\u{0}\u{1}\u{7}\u{8}\u{b}\u{c}\u{1f}\u{7f}".to_owned(),
            "tab \t lf \n cr \r crlf \r\n".to_owned(),
            "quotes \" ' ` mixed".to_owned(),
            "back\\slash and ${interp}".to_owned(),
            "line \u{2028} para \u{2029} sep".to_owned(),
            "astral \u{1f600}\u{1f4a9} bmp caf\u{e9} \u{2603} \u{3a9}".to_owned(),
            "a\r\nb\tc\u{2028}d".to_owned(),
        ]
    }

    #[test]
    fn double_quote_emit_reparses_and_roundtrips_under_node() {
        if !node_available() {
            return;
        }
        for value in battery() {
            let literal: String = format_string(&value);
            let assignment: String = format!("var x = {literal};");
            let got: String = relex_codepoints(&assignment).unwrap_or_else(|| {
                panic!("node rejected or failed to re-lex double-quote emit: {assignment:?}")
            });
            assert_eq!(
                got,
                expected_codepoints(&value),
                "double-quote emit diverged after node re-lex for {value:?} -> {literal:?}"
            );
        }
    }

    #[test]
    fn template_chunk_emit_reparses_and_roundtrips_under_node() {
        if !node_available() {
            return;
        }
        for value in battery() {
            let expr: Expr = Expr::Template {
                quasis: vec![value.clone()],
                exprs: vec![],
            };
            let literal: String = emit_expr(&expr);
            let assignment: String = format!("var x = {literal};");
            let got: String = relex_codepoints(&assignment).unwrap_or_else(|| {
                panic!("node rejected or failed to re-lex template emit: {assignment:?}")
            });
            assert_eq!(
                got,
                expected_codepoints(&value),
                "template emit diverged after node re-lex for {value:?} -> {literal:?}"
            );
        }
    }

    #[test]
    fn carriage_return_is_escaped_in_template_chunks() {
        let chunk: String = escape_template_chunk("a\rb\r\nc");
        assert!(
            !chunk.contains('\r'),
            "a raw carriage return in a template chunk cooks to line feed and corrupts the value"
        );
        assert_eq!(chunk, "a\\rb\\r\nc");
    }
}
