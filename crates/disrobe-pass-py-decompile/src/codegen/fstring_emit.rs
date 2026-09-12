use crate::ast::node::{ConstValue, Expr};
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{
    conversion_suffix, render_expr, render_format_spec_inner,
};

#[must_use]
pub fn emit_fstring(values: &[Expr], version: &PyVersion) -> String {
    format!("f\"{}\"", render_joinedstr_body(values, version))
}

#[must_use]
pub fn render_joinedstr_body(values: &[Expr], version: &PyVersion) -> String {
    let mut out: String = String::new();
    for v in values {
        match v {
            Expr::Constant {
                value: ConstValue::Str(s),
                ..
            } => out.push_str(&escape_fstring_literal(s)),
            Expr::FormattedValue {
                value,
                conversion,
                format_spec,
                ..
            } => {
                let inner_expr: String = render_expr(value, version);
                let mut inner: String = inner_expr;
                inner.push_str(conversion_suffix(*conversion));
                if let Some(spec) = format_spec.as_deref() {
                    inner.push(':');
                    inner.push_str(&render_format_spec_inner(spec, version));
                }
                out.push('{');
                out.push_str(&inner);
                out.push('}');
            }
            other => out.push_str(&render_expr(other, version)),
        }
    }
    out
}

#[must_use]
fn escape_fstring_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[must_use]
pub fn supports_fstring(version: &PyVersion) -> bool {
    version.supports_fstring()
}

#[must_use]
pub fn supports_pep_701(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 12)
}
