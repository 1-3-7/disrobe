#![allow(clippy::format_push_string)]
pub mod async_emit;
pub mod comprehension;
pub mod except_group_emit;
pub mod expr;
pub mod flow;
pub mod fstring_emit;
pub mod inlined_comprehension_emit;
pub mod match_emit;
pub mod modern;
pub mod modern_expr_render;
pub mod name_demangle;
pub mod stmt;
pub mod tstring_emit;
pub mod type_params_emit;
pub mod version_dispatch;
pub mod walrus_emit;

use crate::ast::node::{AstModule, Expr, Stmt};
use crate::bytecode::version::PyVersion;

#[derive(Debug, Clone)]
pub struct EmitOptions {
    pub version: PyVersion,
    pub include_provenance: bool,
    pub line_hint_attribution: bool,
}

impl EmitOptions {
    #[must_use]
    pub const fn new(version: PyVersion) -> Self {
        Self {
            version,
            include_provenance: false,
            line_hint_attribution: true,
        }
    }
}

pub trait CodeEmitter: std::fmt::Debug + Send + Sync {
    fn emit_module(&self, m: &AstModule, version: &PyVersion) -> String;
    fn emit_stmt(&self, s: &Stmt, indent: u32, version: &PyVersion) -> String;
    fn emit_expr(&self, e: &Expr, version: &PyVersion) -> String;
}

#[derive(Debug, Clone)]
pub struct DefaultEmitter {
    pub indent_width: u32,
    pub use_double_quotes: bool,
    pub preserve_blank_lines: bool,
    pub unicode_literals: bool,
}

impl Default for DefaultEmitter {
    fn default() -> Self {
        Self {
            indent_width: 4,
            use_double_quotes: true,
            preserve_blank_lines: true,
            unicode_literals: false,
        }
    }
}

impl DefaultEmitter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            indent_width: 4,
            use_double_quotes: true,
            preserve_blank_lines: true,
            unicode_literals: false,
        }
    }

    #[must_use]
    pub fn indent_str(&self, indent: u32) -> String {
        let total: usize = (self.indent_width as usize).saturating_mul(indent as usize);
        let mut s: String = String::with_capacity(total);
        for _ in 0..total {
            s.push(' ');
        }
        s
    }
}

impl CodeEmitter for DefaultEmitter {
    fn emit_module(&self, m: &AstModule, version: &PyVersion) -> String {
        let scoped: Self = Self {
            unicode_literals: self.unicode_literals || module_has_unicode_literals(m),
            ..self.clone()
        };
        let mut out: String = String::new();
        if let Some(doc) = &m.docstring {
            out.push_str(&format_docstring_literal(doc, scoped.use_double_quotes));
            out.push('\n');
        }
        let body_len: usize = m.body.len();
        for (idx, s) in m.body.iter().enumerate() {
            if scoped.preserve_blank_lines
                && let Some(line) = stmt_line(s)
            {
                let blanks: u8 = m.blank_lines.get(&line).copied().unwrap_or(0);
                for _ in 0..blanks {
                    out.push('\n');
                }
            }
            out.push_str(&scoped.emit_stmt(s, 0, version));
            if idx + 1 < body_len {
                out.push('\n');
            }
        }
        out
    }

    fn emit_stmt(&self, s: &Stmt, indent: u32, version: &PyVersion) -> String {
        stmt::emit_stmt(self, s, indent, version)
    }

    fn emit_expr(&self, e: &Expr, version: &PyVersion) -> String {
        expr::emit_expr(self, e, version, expr::Precedence::Lowest)
    }
}

#[must_use]
pub(crate) fn format_string_literal(s: &str, prefer_double: bool) -> String {
    let has_single: bool = s.contains('\'');
    let has_double: bool = s.contains('"');
    let quote: char = if prefer_double {
        if has_double && !has_single { '\'' } else { '"' }
    } else if has_single && !has_double {
        '"'
    } else {
        '\''
    };
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[must_use]
pub(crate) fn format_docstring_literal(s: &str, prefer_double: bool) -> String {
    let multiline: bool = s.contains('\n');
    let has_backslash: bool = s.contains('\\');
    let has_carriage: bool = s.contains('\r');
    let has_tab_or_control: bool = s
        .chars()
        .any(|c: char| (c as u32) < 0x20 && c != '\n' && c != '\t');
    if !multiline || has_backslash || has_carriage || has_tab_or_control {
        return format_string_literal(s, prefer_double);
    }
    let quote: char = if prefer_double { '"' } else { '\'' };
    let fence: String = std::iter::repeat_n(quote, 3).collect();
    let mut out: String = String::with_capacity(s.len() + 8);
    out.push_str(&fence);
    let chars: Vec<char> = s.chars().collect();
    let last: usize = chars.len().saturating_sub(1);
    for (i, ch) in chars.iter().enumerate() {
        match ch {
            '\t' => out.push_str("\\t"),
            c if *c == quote && (i == 0 || chars[i - 1] == quote) => {
                out.push('\\');
                out.push(*c);
            }
            c if *c == quote && i == last => {
                out.push('\\');
                out.push(*c);
            }
            c => out.push(*c),
        }
    }
    out.push_str(&fence);
    out
}

#[must_use]
pub(crate) fn format_bytes_literal(b: &[u8]) -> String {
    let mut out: String = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push('"');
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(byte as char),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out.push('"');
    out
}

#[must_use]
fn stmt_line(s: &Stmt) -> Option<u32> {
    match s {
        Stmt::FunctionDef { line, .. }
        | Stmt::ClassDef { line, .. }
        | Stmt::Assign { line, .. }
        | Stmt::AugAssign { line, .. }
        | Stmt::AnnAssign { line, .. }
        | Stmt::TypeAlias { line, .. }
        | Stmt::For { line, .. }
        | Stmt::While { line, .. }
        | Stmt::If { line, .. }
        | Stmt::With { line, .. }
        | Stmt::Match { line, .. }
        | Stmt::Raise { line, .. }
        | Stmt::Try { line, .. }
        | Stmt::TryStar { line, .. }
        | Stmt::Assert { line, .. }
        | Stmt::ImportFrom { line, .. } => *line,
        _ => None,
    }
}

#[must_use]
pub fn module_has_unicode_literals(m: &AstModule) -> bool {
    m.body.iter().any(|s: &Stmt| {
        matches!(
            s,
            Stmt::ImportFrom { module: Some(module), names, .. }
                if module == "__future__"
                    && names.iter().any(|a: &crate::ast::node::Alias| a.name == "unicode_literals")
        )
    })
}
