use syn::Expr;

use crate::rust::builder::{file, function, trailing_expr};

#[must_use]
pub fn render(file: &syn::File) -> String {
    prettyplease::unparse(file)
}

#[must_use]
pub fn render_expr(expr: &Expr) -> String {
    let wrapped: syn::File = file(vec![function(
        "__disrobe_emit_expr",
        Vec::new(),
        None,
        vec![trailing_expr(expr.clone())],
    )]);
    let rendered: String = render(&wrapped);
    let open: usize = rendered.find('{').map_or(0, |idx: usize| idx + 1);
    let close: usize = rendered.rfind('}').unwrap_or(rendered.len());
    rendered[open..close]
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

#[must_use]
pub fn parse_expr(text: &str) -> Option<Expr> {
    syn::parse_str(text).ok()
}
