use crate::ast::node::TStrItem;
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{
    conversion_suffix, render_expr, render_format_spec_inner,
};

#[must_use]
pub fn emit_tstring(items: &[TStrItem], version: &PyVersion) -> String {
    if supports_tstring(version) {
        format!("t\"{}\"", render_tstr_body(items, version))
    } else {
        format!("f\"{}\"", render_tstr_body(items, version))
    }
}

#[must_use]
pub fn render_tstr_body(items: &[TStrItem], version: &PyVersion) -> String {
    let mut out: String = String::new();
    for item in items {
        match item {
            TStrItem::Literal(s) => out.push_str(&escape_tstring_literal(s)),
            TStrItem::Interp {
                value,
                conversion,
                format_spec,
            } => {
                let mut inner: String = render_expr(value, version);
                inner.push_str(conversion_suffix(*conversion));
                if let Some(spec) = format_spec.as_ref() {
                    inner.push(':');
                    inner.push_str(&render_format_spec_inner(spec, version));
                }
                out.push('{');
                out.push_str(&inner);
                out.push('}');
            }
        }
    }
    out
}

#[must_use]
fn escape_tstring_literal(s: &str) -> String {
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
            c => out.push(c),
        }
    }
    out
}

#[must_use]
pub fn supports_tstring(version: &PyVersion) -> bool {
    version.supports_tstring()
}
