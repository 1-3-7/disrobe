use oxc_allocator::Allocator;
use oxc_ast::ast::{ComputedMemberExpression, Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct BracketToDotStats {
    pub(super) accesses_rewritten: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, BracketToDotStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), BracketToDotStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: BracketToDotStats = BracketToDotStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut BracketToDotStats,
) {
    match stmt {
        Statement::ExpressionStatement(s) => walk_expression(&s.expression, source, edits, stats),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, edits, stats);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, source, edits, stats);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, edits, stats);
            }
            if let Some(update) = s.update.as_ref() {
                walk_expression(update, source, edits, stats);
            }
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForInStatement(s) => {
            walk_expression(&s.right, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForOfStatement(s) => {
            walk_expression(&s.right, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                walk_statement(inner, source, edits, stats);
            }
            if let Some(handler) = s.handler.as_ref() {
                for inner in &handler.body.body {
                    walk_statement(inner, source, edits, stats);
                }
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                for inner in &finalizer.body {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::LabeledStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::ThrowStatement(s) => walk_expression(&s.argument, source, edits, stats),
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, edits, stats);
            for case in &s.cases {
                if let Some(test) = case.test.as_ref() {
                    walk_expression(test, source, edits, stats);
                }
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut BracketToDotStats,
) {
    if let Expression::ComputedMemberExpression(member) = expr
        && let Some(edit) = try_dot(member)
    {
        edits.push(edit);
        stats.accesses_rewritten += 1;
        walk_expression(&member.object, source, edits, stats);
        return;
    }
    match expr {
        Expression::ComputedMemberExpression(m) => {
            walk_expression(&m.object, source, edits, stats);
            walk_expression(&m.expression, source, edits, stats);
        }
        Expression::StaticMemberExpression(m) => {
            walk_expression(&m.object, source, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::CallExpression(c) => {
            walk_expression(&c.callee, source, edits, stats);
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::NewExpression(n) => {
            walk_expression(&n.callee, source, edits, stats);
            for arg in &n.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, source, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, source, edits, stats);
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, source, edits, stats);
            }
        }
        _ => {}
    }
}

fn try_dot(member: &ComputedMemberExpression<'_>) -> Option<Edit> {
    if member.optional {
        return None;
    }
    let Expression::StringLiteral(key): &Expression<'_> = &member.expression else {
        return None;
    };
    let name: &str = key.value.as_str();
    if !is_identifier_name(name) {
        return None;
    }
    Some(Edit {
        start: member.object.span().end as usize,
        end: member.span.end as usize,
        replacement: format!(".{name}"),
    })
}

fn is_identifier_name(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    if !chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
        return false;
    }
    !is_reserved_word(name)
}

fn is_reserved_word(name: &str) -> bool {
    matches!(
        name,
        "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "new"
            | "null"
            | "return"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
    )
}

#[cfg(test)]
mod tests {
    use super::{BracketToDotStats, RuleOutcome, recover};

    fn splice(source: &str, outcome: &RuleOutcome) -> String {
        let mut sorted: Vec<&super::Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&super::Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn single_level_access_is_dotted() {
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover("a[\"prop\"];");
        assert_eq!(stats.accesses_rewritten, 1);
        assert_eq!(splice("a[\"prop\"];", &outcome), "a.prop;");
    }

    #[test]
    fn chained_access_is_fully_dotted_in_one_pass() {
        let source: &str = "a[\"prop0\"][\"prop1\"][\"prop2\"];";
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover(source);
        assert_eq!(stats.accesses_rewritten, 3);
        assert_eq!(splice(source, &outcome), "a.prop0.prop1.prop2;");
    }

    #[test]
    fn long_chain_produces_non_overlapping_edits() {
        let mut source: String = String::from("a");
        for i in 0..500 {
            source.push_str("[\"prop");
            source.push_str(&i.to_string());
            source.push_str("\"]");
        }
        source.push(';');
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover(&source);
        assert_eq!(stats.accesses_rewritten, 500);
        let rewritten: String = splice(&source, &outcome);
        assert!(
            rewritten.starts_with("a.prop0.prop1.prop2."),
            "got: {rewritten}"
        );
        assert!(rewritten.ends_with(".prop499;"), "got: {rewritten}");
    }

    #[test]
    fn optional_chaining_bracket_access_is_left_untransformed() {
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover("a?.[\"prop\"];");
        assert_eq!(
            stats.accesses_rewritten, 0,
            "optional computed access must never be flattened to a non-optional dot access"
        );
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn mixed_chain_skips_only_the_non_identifier_level() {
        let source: &str = "a[\"prop0\"][1][\"prop2\"];";
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover(source);
        assert_eq!(stats.accesses_rewritten, 2);
        assert_eq!(splice(source, &outcome), "a.prop0[1].prop2;");
    }

    #[test]
    fn reserved_word_key_is_left_bracketed() {
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover("a[\"class\"];");
        assert_eq!(stats.accesses_rewritten, 0);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn numeric_key_is_left_bracketed() {
        let (outcome, stats): (RuleOutcome, BracketToDotStats) = recover("a[0];");
        assert_eq!(stats.accesses_rewritten, 0);
        assert!(outcome.edits.is_empty());
    }
}
