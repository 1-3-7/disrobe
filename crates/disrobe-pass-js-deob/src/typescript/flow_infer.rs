use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, Expression, ObjectPropertyKind, Program, PropertyKey, Statement,
    VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct TypeFlowReport {
    pub bindings: BTreeMap<String, InferredType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InferredType {
    StringLiteral(String),
    NumberLiteral(String),
    BigIntLiteral(String),
    BooleanLiteral(bool),
    NullLit,
    UndefinedLit,
    Primitive(&'static str),
    ArrayOf(Box<Self>),
    ObjectLiteral(BTreeMap<String, Self>),
    Function { params: Vec<Self>, ret: Box<Self> },
    Unknown,
}

impl InferredType {
    pub fn render(&self) -> String {
        match self {
            Self::StringLiteral(s) => format!("'{}'", escape_single(s)),
            Self::NumberLiteral(n) => n.clone(),
            Self::BigIntLiteral(n) => format!("{n}n"),
            Self::BooleanLiteral(b) => if *b { "true" } else { "false" }.to_owned(),
            Self::NullLit => "null".to_owned(),
            Self::UndefinedLit => "undefined".to_owned(),
            Self::Primitive(p) => (*p).to_owned(),
            Self::ArrayOf(t) => format!("{}[]", t.render()),
            Self::ObjectLiteral(fields) => {
                if fields.is_empty() {
                    return "Record<string, unknown>".to_owned();
                }
                let body: String = fields
                    .iter()
                    .map(|(k, v): (&String, &Self)| format!("{k}: {}", v.render()))
                    .collect::<Vec<String>>()
                    .join("; ");
                format!("{{ {body} }}")
            }
            Self::Function { params, ret } => {
                let p: String = params
                    .iter()
                    .enumerate()
                    .map(|(i, t): (usize, &Self)| format!("p{i}: {}", t.render()))
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("({p}) => {}", ret.render())
            }
            Self::Unknown => "unknown".to_owned(),
        }
    }
}

fn escape_single(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

#[must_use]
pub fn analyze(source: &str) -> TypeFlowReport {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("flow.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return TypeFlowReport::default();
    }
    let mut report: TypeFlowReport = TypeFlowReport::default();
    walk_program(&parsed.program, &mut report);
    report
}

fn walk_program(program: &Program<'_>, report: &mut TypeFlowReport) {
    for stmt in &program.body {
        walk_statement(stmt, report);
    }
}

fn walk_statement(stmt: &Statement<'_>, report: &mut TypeFlowReport) {
    if let Statement::VariableDeclaration(decl) = stmt {
        for d in &decl.declarations {
            walk_declarator(d, report);
        }
    }
}

fn walk_declarator(decl: &VariableDeclarator<'_>, report: &mut TypeFlowReport) {
    let BindingPatternKind::BindingIdentifier(id) = &decl.id.kind else {
        return;
    };
    let name: String = id.name.as_str().to_owned();
    let inferred: InferredType = decl
        .init
        .as_ref()
        .map_or(InferredType::Unknown, infer_expression);
    report.bindings.insert(name, inferred);
}

fn infer_expression(expr: &Expression<'_>) -> InferredType {
    match expr {
        Expression::StringLiteral(s) => InferredType::StringLiteral(s.value.as_str().to_owned()),
        Expression::NumericLiteral(n) => InferredType::NumberLiteral(n.value.to_string()),
        Expression::BigIntLiteral(n) => {
            InferredType::BigIntLiteral(n.raw.as_str().trim_end_matches('n').to_owned())
        }
        Expression::BooleanLiteral(b) => InferredType::BooleanLiteral(b.value),
        Expression::NullLiteral(_) => InferredType::NullLit,
        Expression::Identifier(id) if id.name == "undefined" => InferredType::UndefinedLit,
        Expression::TemplateLiteral(_) => InferredType::Primitive("string"),
        Expression::RegExpLiteral(_) => InferredType::Primitive("RegExp"),
        Expression::ArrayExpression(arr) => {
            let elem: InferredType = arr
                .elements
                .iter()
                .find_map(|e| match e {
                    oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)
                    | oxc_ast::ast::ArrayExpressionElement::Elision(_) => None,
                    other => other.as_expression().map(infer_expression),
                })
                .unwrap_or(InferredType::Unknown);
            InferredType::ArrayOf(Box::new(elem))
        }
        Expression::ObjectExpression(obj) => {
            let mut fields: BTreeMap<String, InferredType> = BTreeMap::new();
            for prop in &obj.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    let key: String = match &p.key {
                        PropertyKey::StaticIdentifier(id) => id.name.as_str().to_owned(),
                        PropertyKey::StringLiteral(s) => s.value.as_str().to_owned(),
                        _ => continue,
                    };
                    fields.insert(key, infer_expression(&p.value));
                }
            }
            InferredType::ObjectLiteral(fields)
        }
        Expression::ArrowFunctionExpression(arrow) => InferredType::Function {
            params: vec![InferredType::Unknown; arrow.params.items.len()],
            ret: Box::new(InferredType::Unknown),
        },
        Expression::FunctionExpression(func) => InferredType::Function {
            params: vec![InferredType::Unknown; func.params.items.len()],
            ret: Box::new(InferredType::Unknown),
        },
        Expression::UnaryExpression(u) => match u.operator.as_str() {
            "!" => InferredType::Primitive("boolean"),
            "-" | "+" | "~" => InferredType::Primitive("number"),
            "typeof" => InferredType::Primitive("string"),
            "void" => InferredType::UndefinedLit,
            _ => InferredType::Unknown,
        },
        Expression::BinaryExpression(b) => match b.operator.as_str() {
            "+" | "-" | "*" | "/" | "%" | "**" | "<<" | ">>" | ">>>" | "|" | "&" | "^" => {
                InferredType::Primitive("number")
            }
            "==" | "!=" | "===" | "!==" | "<" | "<=" | ">" | ">=" | "in" | "instanceof" => {
                InferredType::Primitive("boolean")
            }
            _ => InferredType::Unknown,
        },
        _ => InferredType::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn infers_string_literal() {
        let r: TypeFlowReport = analyze("var x = 'hi';");
        let t: &InferredType = r.bindings.get("x").expect("got x");
        assert!(matches!(t, InferredType::StringLiteral(s) if s == "hi"));
    }

    #[test]
    fn infers_number_from_arith() {
        let r: TypeFlowReport = analyze("var x = 1 + 2 * 3;");
        let t: &InferredType = r.bindings.get("x").expect("got x");
        assert!(matches!(t, InferredType::Primitive("number")));
    }

    #[test]
    fn infers_object_literal_shape() {
        let r: TypeFlowReport = analyze("var x = { a: 1, b: 'two' };");
        let t: &InferredType = r.bindings.get("x").expect("got x");
        let rendered: String = t.render();
        assert!(rendered.contains("a:"));
        assert!(rendered.contains("b:"));
    }

    #[test]
    fn infers_array_element_type() {
        let r: TypeFlowReport = analyze("var x = [1, 2, 3];");
        let t: &InferredType = r.bindings.get("x").expect("got x");
        let rendered: String = t.render();
        assert!(rendered.ends_with("[]"));
    }
}
