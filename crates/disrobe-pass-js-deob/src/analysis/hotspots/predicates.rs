use oxc_ast::ast::{
    Argument, BinaryOperator, CallExpression, Expression, ObjectExpression, ObjectPropertyKind,
    PropertyKey,
};

pub(super) struct LineIndex {
    starts: Vec<u32>,
}

impl LineIndex {
    pub(super) fn new(source: &str) -> Self {
        let mut starts: Vec<u32> = vec![0];
        for (idx, byte) in source.as_bytes().iter().enumerate() {
            if *byte == b'\n' {
                starts.push(u32::try_from(idx + 1).unwrap_or(u32::MAX));
            }
        }
        Self { starts }
    }

    pub(super) fn line_col(&self, offset: u32) -> (u32, u32) {
        let line_idx: usize = match self.starts.binary_search(&offset) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        let line_start: u32 = self.starts.get(line_idx).copied().unwrap_or(0);
        (
            u32::try_from(line_idx + 1).unwrap_or(u32::MAX),
            offset.saturating_sub(line_start) + 1,
        )
    }
}

pub(super) fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(inner) => unwrap_paren(&inner.expression),
        other => other,
    }
}

pub(super) fn ident_name<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    match unwrap_paren(expr) {
        Expression::Identifier(ident) => Some(ident.name.as_str()),
        _ => None,
    }
}

pub(super) fn member_callee<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    match unwrap_paren(expr) {
        Expression::StaticMemberExpression(member) => {
            Some((&member.object, member.property.name.as_str()))
        }
        _ => None,
    }
}

pub(super) fn is_global_object(expr: &Expression<'_>, name: &str) -> bool {
    ident_name(expr) == Some(name)
}

pub(super) fn is_any_global_object(expr: &Expression<'_>) -> bool {
    matches!(
        ident_name(expr),
        Some("window" | "self" | "top" | "parent" | "document" | "globalThis")
    )
}

pub(super) fn is_location_target(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::Identifier(ident) => ident.name == "location",
        Expression::StaticMemberExpression(member) => {
            member.property.name == "location" && is_any_global_object(&member.object)
        }
        _ => false,
    }
}

pub(super) fn is_process_env(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::StaticMemberExpression(member) => {
            member.property.name == "env" && ident_name(&member.object) == Some("process")
        }
        _ => false,
    }
}

pub(super) fn disables_tls(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::StringLiteral(lit) => lit.value == "0",
        Expression::NumericLiteral(lit) => lit.value == 0.0,
        _ => false,
    }
}

pub(super) fn arg_expression<'a>(
    args: &'a [Argument<'a>],
    index: usize,
) -> Option<&'a Expression<'a>> {
    args.get(index).and_then(Argument::as_expression)
}

pub(super) fn find_object_argument<'a>(
    call: &'a CallExpression<'a>,
) -> Option<&'a ObjectExpression<'a>> {
    for arg in &call.arguments {
        if let Some(Expression::ObjectExpression(obj)) = arg.as_expression() {
            return Some(obj);
        }
    }
    None
}

pub(super) fn object_has_true_flag(obj: &ObjectExpression<'_>, name: &str) -> bool {
    for prop in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(entry) = prop
            && property_key_name(&entry.key).as_deref() == Some(name)
        {
            return matches!(&entry.value, Expression::BooleanLiteral(lit) if lit.value);
        }
    }
    false
}

pub(super) fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(ident) => Some(ident.name.as_str().to_owned()),
        PropertyKey::StringLiteral(lit) => Some(lit.value.as_str().to_owned()),
        _ => None,
    }
}

pub(super) fn static_string_value(expr: &Expression<'_>) -> Option<String> {
    match unwrap_paren(expr) {
        Expression::StringLiteral(lit) => Some(lit.value.as_str().to_owned()),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
            let mut out: String = String::new();
            for quasi in &tpl.quasis {
                if let Some(cooked) = quasi.value.cooked.as_ref() {
                    out.push_str(cooked.as_str());
                }
            }
            Some(out)
        }
        _ => None,
    }
}

pub(super) fn is_static_string(expr: &Expression<'_>) -> bool {
    static_string_value(expr).is_some()
}

pub(super) fn is_string_valued(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => true,
        Expression::BinaryExpression(bin) if bin.operator == BinaryOperator::Addition => {
            is_string_valued(&bin.left) || is_string_valued(&bin.right)
        }
        _ => false,
    }
}
