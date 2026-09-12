use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentOperator, AssignmentTarget, CallExpression,
    Expression, Program, Statement, VariableDeclaration,
};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct InteropUnwrapStats {
    pub(super) wildcard_imports: usize,
    pub(super) esmodule_markers_stripped: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, InteropUnwrapStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), InteropUnwrapStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: InteropUnwrapStats = InteropUnwrapStats::default();

    for stmt in &program.body {
        if let Some(edit) = try_wildcard_import(stmt) {
            edits.push(edit);
            stats.wildcard_imports += 1;
            continue;
        }
        if let Some(span) = try_esmodule_marker(stmt) {
            edits.push(Edit {
                start: span.start as usize,
                end: span.end as usize,
                replacement: String::new(),
            });
            stats.esmodule_markers_stripped += 1;
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn try_wildcard_import(stmt: &Statement<'_>) -> Option<Edit> {
    let Statement::VariableDeclaration(decl): &Statement<'_> = stmt else {
        return None;
    };
    let decl: &VariableDeclaration<'_> = decl;
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let oxc_ast::ast::BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let local: &str = binding.name.as_str();
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::CallExpression(call): &Expression<'_> = init else {
        return None;
    };
    if !is_named_call(call, "_interopRequireWildcard") {
        return None;
    }
    let module: &str = single_require_arg(call)?;
    Some(Edit {
        start: decl.span.start as usize,
        end: decl.span.end as usize,
        replacement: format!("import * as {local} from \"{module}\";"),
    })
}

fn try_esmodule_marker(stmt: &Statement<'_>) -> Option<Span> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return None;
    };
    match &expr_stmt.expression {
        Expression::CallExpression(call) if is_define_property_esmodule(call) => {
            Some(expr_stmt.span)
        }
        Expression::AssignmentExpression(assign) if is_exports_esmodule_assign(assign) => {
            Some(expr_stmt.span)
        }
        _ => None,
    }
}

fn is_define_property_esmodule(call: &CallExpression<'_>) -> bool {
    let Some(member) = call.callee.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    if sm.property.name.as_str() != "defineProperty" {
        return false;
    }
    let Expression::Identifier(obj) = &sm.object else {
        return false;
    };
    if obj.name.as_str() != "Object" || call.arguments.len() != 3 {
        return false;
    }
    let first_is_exports: bool = matches!(
        call.arguments[0].as_expression(),
        Some(Expression::Identifier(id)) if id.name.as_str() == "exports"
    );
    let second_is_marker: bool = matches!(
        call.arguments[1].as_expression(),
        Some(Expression::StringLiteral(s)) if s.value.as_str() == "__esModule"
    );
    first_is_exports && second_is_marker
}

fn is_exports_esmodule_assign(assign: &AssignmentExpression<'_>) -> bool {
    if assign.operator != AssignmentOperator::Assign {
        return false;
    }
    let target_name: Option<&str> = match &assign.left {
        AssignmentTarget::StaticMemberExpression(member) => {
            if let Expression::Identifier(obj) = &member.object {
                if obj.name.as_str() == "exports" {
                    Some(member.property.name.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        }
        AssignmentTarget::ComputedMemberExpression(member) => {
            let is_exports: bool = matches!(
                &member.object,
                Expression::Identifier(obj) if obj.name.as_str() == "exports"
            );
            if is_exports {
                match &member.expression {
                    Expression::StringLiteral(s) => Some(s.value.as_str()),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    };
    target_name == Some("__esModule")
}

fn is_named_call(call: &CallExpression<'_>, name: &str) -> bool {
    matches!(&call.callee, Expression::Identifier(id) if id.name.as_str() == name)
}

fn single_require_arg<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    if call.arguments.len() != 1 {
        return None;
    }
    let Argument::CallExpression(require_call) = &call.arguments[0] else {
        return None;
    };
    if !is_named_call(require_call, "require") || require_call.arguments.len() != 1 {
        return None;
    }
    match require_call.arguments[0].as_expression()? {
        Expression::StringLiteral(s) => Some(s.value.as_str()),
        _ => None,
    }
}
