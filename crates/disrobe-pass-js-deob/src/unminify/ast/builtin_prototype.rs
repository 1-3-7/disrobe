use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, Expression, Program, Statement, StaticMemberExpression, StringLiteral,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct BuiltinPrototypeStats {
    pub(super) prototypes_expanded: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, BuiltinPrototypeStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), BuiltinPrototypeStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: BuiltinPrototypeStats = BuiltinPrototypeStats::default();
    for stmt in &program.body {
        walk_statement(stmt, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement(stmt: &Statement<'_>, edits: &mut Vec<Edit>, stats: &mut BuiltinPrototypeStats) {
    match stmt {
        Statement::ExpressionStatement(s) => walk_expression(&s.expression, edits, stats),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, edits, stats);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, edits, stats);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, edits, stats);
            walk_statement(&s.consequent, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(init) = s.init.as_ref()
                && let Some(expr) = init.as_expression()
            {
                walk_expression(expr, edits, stats);
            }
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, edits, stats);
            }
            if let Some(update) = s.update.as_ref() {
                walk_expression(update, edits, stats);
            }
            walk_statement(&s.body, edits, stats);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, edits, stats);
            walk_statement(&s.body, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, edits, stats);
            walk_statement(&s.body, edits, stats);
        }
        Statement::ForInStatement(s) => {
            walk_expression(&s.right, edits, stats);
            walk_statement(&s.body, edits, stats);
        }
        Statement::ForOfStatement(s) => {
            walk_expression(&s.right, edits, stats);
            walk_statement(&s.body, edits, stats);
        }
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                walk_statement(inner, edits, stats);
            }
            if let Some(handler) = s.handler.as_ref() {
                for inner in &handler.body.body {
                    walk_statement(inner, edits, stats);
                }
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                for inner in &finalizer.body {
                    walk_statement(inner, edits, stats);
                }
            }
        }
        Statement::LabeledStatement(s) => walk_statement(&s.body, edits, stats),
        Statement::ThrowStatement(s) => walk_expression(&s.argument, edits, stats),
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, edits, stats);
            for case in &s.cases {
                if let Some(test) = case.test.as_ref() {
                    walk_expression(test, edits, stats);
                }
                for inner in &case.consequent {
                    walk_statement(inner, edits, stats);
                }
            }
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, edits, stats);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    edits: &mut Vec<Edit>,
    stats: &mut BuiltinPrototypeStats,
) {
    match expr {
        Expression::CallExpression(call) => {
            if let Some(edit) = try_expand(call) {
                edits.push(edit);
                stats.prototypes_expanded += 1;
                for arg in &call.arguments {
                    if let Some(inner) = arg.as_expression() {
                        walk_expression(inner, edits, stats);
                    }
                }
                return;
            }
            walk_expression(&call.callee, edits, stats);
            for arg in &call.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, edits, stats);
                }
            }
        }
        Expression::NewExpression(n) => {
            walk_expression(&n.callee, edits, stats);
            for arg in &n.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, edits, stats);
                }
            }
        }
        Expression::StaticMemberExpression(m) => walk_expression(&m.object, edits, stats),
        Expression::ComputedMemberExpression(m) => {
            walk_expression(&m.object, edits, stats);
            walk_expression(&m.expression, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => walk_expression(&p.expression, edits, stats),
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, edits, stats);
            walk_expression(&b.right, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, edits, stats);
            walk_expression(&b.right, edits, stats);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, edits, stats);
            walk_expression(&c.consequent, edits, stats);
            walk_expression(&c.alternate, edits, stats);
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, edits, stats),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, edits, stats);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, edits, stats);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, edits, stats);
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, edits, stats);
                }
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, edits, stats);
            }
        }
        Expression::AwaitExpression(a) => walk_expression(&a.argument, edits, stats),
        _ => {}
    }
}

fn try_expand(call: &CallExpression<'_>) -> Option<Edit> {
    let outer: &StaticMemberExpression<'_> = as_static_member(&call.callee)?;
    let outer_prop: &str = outer.property.name.as_str();
    if outer_prop != "call" && outer_prop != "apply" {
        return None;
    }
    let inner: &StaticMemberExpression<'_> = as_static_member(&outer.object)?;
    let method: &str = inner.property.name.as_str();
    let base_object: &Expression<'_> = unwrap_parens(&inner.object);
    let base: &'static str = classify_base(base_object)?;
    if !prototype_has(base, method) {
        return None;
    }
    let span = inner.object.span();
    Some(Edit {
        start: span.start as usize,
        end: span.end as usize,
        replacement: format!("{base}.prototype"),
    })
}

fn as_static_member<'a, 'b>(expr: &'a Expression<'b>) -> Option<&'a StaticMemberExpression<'b>> {
    match unwrap_parens(expr) {
        Expression::StaticMemberExpression(m) if !m.optional => Some(m),
        _ => None,
    }
}

fn unwrap_parens<'a, 'b>(expr: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current: &'a Expression<'b> = expr;
    while let Expression::ParenthesizedExpression(p) = current {
        current = &p.expression;
    }
    current
}

fn classify_base(expr: &Expression<'_>) -> Option<&'static str> {
    match expr {
        Expression::ArrayExpression(a) if a.elements.is_empty() => Some("Array"),
        Expression::ObjectExpression(o) if o.properties.is_empty() => Some("Object"),
        Expression::NumericLiteral(n) if n.value == 0.0 => Some("Number"),
        Expression::StringLiteral(s) if is_empty_string(s) => Some("String"),
        Expression::RegExpLiteral(_) => Some("RegExp"),
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
            Some("Function")
        }
        _ => None,
    }
}

fn is_empty_string(literal: &StringLiteral<'_>) -> bool {
    literal.value.as_str().is_empty()
}

fn prototype_has(base: &str, method: &str) -> bool {
    match base {
        "Array" => ARRAY_PROTO.contains(&method),
        "Number" => NUMBER_PROTO.contains(&method),
        "Object" => OBJECT_PROTO.contains(&method),
        "String" => STRING_PROTO.contains(&method),
        "RegExp" => REGEXP_PROTO.contains(&method),
        "Function" => FUNCTION_PROTO.contains(&method),
        _ => false,
    }
}

const OBJECT_PROTO: [&str; 12] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

const ARRAY_PROTO: [&str; 49] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "at",
    "concat",
    "constructor",
    "copyWithin",
    "entries",
    "every",
    "fill",
    "filter",
    "find",
    "findIndex",
    "findLast",
    "findLastIndex",
    "flat",
    "flatMap",
    "forEach",
    "hasOwnProperty",
    "includes",
    "indexOf",
    "isPrototypeOf",
    "join",
    "keys",
    "lastIndexOf",
    "length",
    "map",
    "pop",
    "propertyIsEnumerable",
    "push",
    "reduce",
    "reduceRight",
    "reverse",
    "shift",
    "slice",
    "some",
    "sort",
    "splice",
    "toLocaleString",
    "toReversed",
    "toSorted",
    "toSpliced",
    "toString",
    "unshift",
    "valueOf",
    "values",
    "with",
];

const NUMBER_PROTO: [&str; 15] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toExponential",
    "toFixed",
    "toLocaleString",
    "toPrecision",
    "toString",
    "valueOf",
];

const STRING_PROTO: [&str; 61] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "anchor",
    "at",
    "big",
    "blink",
    "bold",
    "charAt",
    "charCodeAt",
    "codePointAt",
    "concat",
    "constructor",
    "endsWith",
    "fixed",
    "fontcolor",
    "fontsize",
    "hasOwnProperty",
    "includes",
    "indexOf",
    "isPrototypeOf",
    "isWellFormed",
    "italics",
    "lastIndexOf",
    "length",
    "link",
    "localeCompare",
    "match",
    "matchAll",
    "normalize",
    "padEnd",
    "padStart",
    "propertyIsEnumerable",
    "repeat",
    "replace",
    "replaceAll",
    "search",
    "slice",
    "small",
    "split",
    "startsWith",
    "strike",
    "sub",
    "substr",
    "substring",
    "sup",
    "toLocaleLowerCase",
    "toLocaleString",
    "toLocaleUpperCase",
    "toLowerCase",
    "toString",
    "toUpperCase",
    "toWellFormed",
    "trim",
    "trimEnd",
    "trimLeft",
    "trimRight",
    "trimStart",
    "valueOf",
];

const REGEXP_PROTO: [&str; 25] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "compile",
    "constructor",
    "dotAll",
    "exec",
    "flags",
    "global",
    "hasIndices",
    "hasOwnProperty",
    "ignoreCase",
    "isPrototypeOf",
    "multiline",
    "propertyIsEnumerable",
    "source",
    "sticky",
    "test",
    "toLocaleString",
    "toString",
    "unicode",
    "unicodeSets",
    "valueOf",
];

const FUNCTION_PROTO: [&str; 19] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "apply",
    "arguments",
    "bind",
    "call",
    "caller",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "length",
    "name",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

#[cfg(test)]
mod tests {
    use super::{BuiltinPrototypeStats, Edit, RuleOutcome, recover};

    fn splice(source: &str, outcome: &RuleOutcome) -> String {
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn empty_array_slice_call_expands_to_array_prototype() {
        let source: &str = "var a = [].slice.call(arguments);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var a = Array.prototype.slice.call(arguments);"
        );
    }

    #[test]
    fn empty_string_method_expands_to_string_prototype() {
        let source: &str = "var s = \"\".charCodeAt.call(x, 0);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var s = String.prototype.charCodeAt.call(x, 0);"
        );
    }

    #[test]
    fn zero_literal_method_expands_to_number_prototype() {
        let source: &str = "var n = (0).toString.call(y, 16);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var n = Number.prototype.toString.call(y, 16);"
        );
    }

    #[test]
    fn empty_object_method_expands_to_object_prototype() {
        let source: &str = "var h = ({}).hasOwnProperty.call(o, \"k\");";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var h = Object.prototype.hasOwnProperty.call(o, \"k\");"
        );
    }

    #[test]
    fn regex_literal_method_expands_to_regexp_prototype() {
        let source: &str = "var t = /ab/.test.call(re, \"z\");";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var t = RegExp.prototype.test.call(re, \"z\");"
        );
    }

    #[test]
    fn function_expression_method_expands_to_function_prototype() {
        let source: &str = "var b = (function(){}).apply.call(fn, ctx, args);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 1);
        assert_eq!(
            splice(source, &outcome),
            "var b = Function.prototype.apply.call(fn, ctx, args);"
        );
    }

    #[test]
    fn non_empty_array_is_left_untouched() {
        let source: &str = "var keep = [1].slice.call(arr);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 0);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn identifier_object_is_left_untouched() {
        let source: &str = "var keep2 = obj.slice.call(arr);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 0);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn method_not_in_prototype_is_left_untouched() {
        let source: &str = "var keep3 = [].notAMethod.call(arr);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 0);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn direct_call_without_call_or_apply_is_left_untouched() {
        let source: &str = "var x = [].concat(head, tail);";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 0);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn nested_argument_idiom_is_also_expanded() {
        let source: &str = "f([].slice.call(a), \"\".charAt.call(b, 0));";
        let (outcome, stats): (RuleOutcome, BuiltinPrototypeStats) = recover(source);
        assert_eq!(stats.prototypes_expanded, 2);
        assert_eq!(
            splice(source, &outcome),
            "f(Array.prototype.slice.call(a), String.prototype.charAt.call(b, 0));"
        );
    }
}
