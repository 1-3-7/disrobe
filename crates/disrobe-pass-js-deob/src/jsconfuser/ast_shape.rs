use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpression, ArrayExpressionElement, AssignmentTarget, Expression, NewExpression, Program,
    Statement, VariableDeclarator,
};
use oxc_parser::{Parser, ParserReturn};
use oxc_span::SourceType;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RgfShape {
    pub array_id: String,
    pub entry_count: usize,
    pub call_sites: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispatcherShape {
    pub table_id: String,
    pub entry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalculatorShape {
    pub fn_name: String,
    pub op_count: usize,
}

#[must_use]
pub fn detect_rgf_shapes(source: &str) -> Vec<RgfShape> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("jsconfuser-rgf.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Vec::new();
    }
    let mut shapes: Vec<RgfShape> = Vec::new();
    for stmt in &parsed.program.body {
        if let Some(shape) = inspect_statement_for_rgf(stmt, source) {
            shapes.push(shape);
        }
    }
    shapes
}

fn inspect_statement_for_rgf(stmt: &Statement<'_>, source: &str) -> Option<RgfShape> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    for declarator in &decl.declarations {
        if let Some(shape) = inspect_declarator_for_rgf(declarator, source) {
            return Some(shape);
        }
    }
    None
}

fn inspect_declarator_for_rgf(decl: &VariableDeclarator<'_>, source: &str) -> Option<RgfShape> {
    let array_id: String = decl.id.get_identifier_name()?.to_string();
    let Some(init) = &decl.init else {
        return None;
    };
    let Expression::ArrayExpression(array_expr) = init else {
        return None;
    };
    let entry_count: usize = count_new_function_entries(array_expr);
    if entry_count == 0 {
        return None;
    }
    let call_sites: usize = count_rgf_call_sites(source, &array_id);
    Some(RgfShape {
        array_id,
        entry_count,
        call_sites,
    })
}

fn count_new_function_entries(array_expr: &ArrayExpression<'_>) -> usize {
    array_expr
        .elements
        .iter()
        .filter(|el| matches!(el, ArrayExpressionElement::NewExpression(ne) if is_new_function(ne)))
        .count()
}

fn is_new_function(expr: &NewExpression<'_>) -> bool {
    let Expression::Identifier(ident) = &expr.callee else {
        return false;
    };
    ident.name == "Function"
}

fn count_rgf_call_sites(source: &str, array_id: &str) -> usize {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("jsconfuser-calls.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return 0;
    }
    let mut count: usize = 0;
    for stmt in &parsed.program.body {
        walk_statement_for_rgf_calls(stmt, array_id, &mut count);
    }
    count
}

fn walk_statement_for_rgf_calls(stmt: &Statement<'_>, array_id: &str, count: &mut usize) {
    match stmt {
        Statement::ExpressionStatement(es) => {
            walk_expression_for_rgf_calls(&es.expression, array_id, count);
        }
        Statement::VariableDeclaration(vd) => {
            for d in &vd.declarations {
                if let Some(init) = &d.init {
                    walk_expression_for_rgf_calls(init, array_id, count);
                }
            }
        }
        Statement::BlockStatement(block) => {
            for inner in &block.body {
                walk_statement_for_rgf_calls(inner, array_id, count);
            }
        }
        Statement::FunctionDeclaration(fd) => {
            if let Some(body) = &fd.body {
                for inner in &body.statements {
                    walk_statement_for_rgf_calls(inner, array_id, count);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression_for_rgf_calls(expr: &Expression<'_>, array_id: &str, count: &mut usize) {
    match expr {
        Expression::CallExpression(call) => {
            if call_matches_rgf_apply(&call.callee, array_id) {
                *count += 1;
            }
            for arg in &call.arguments {
                if let Some(inner_expr) = arg.as_expression() {
                    walk_expression_for_rgf_calls(inner_expr, array_id, count);
                }
            }
        }
        Expression::AssignmentExpression(assign) => {
            walk_expression_for_rgf_calls(&assign.right, array_id, count);
        }
        Expression::BinaryExpression(bin) => {
            walk_expression_for_rgf_calls(&bin.left, array_id, count);
            walk_expression_for_rgf_calls(&bin.right, array_id, count);
        }
        _ => {}
    }
}

fn call_matches_rgf_apply(callee: &Expression<'_>, array_id: &str) -> bool {
    let Expression::StaticMemberExpression(member) = callee else {
        return false;
    };
    if member.property.name != "apply" {
        return false;
    }
    let Expression::ComputedMemberExpression(inner) = &member.object else {
        return false;
    };
    let Expression::Identifier(id) = &inner.object else {
        return false;
    };
    id.name == array_id
}

#[must_use]
pub fn detect_dispatcher_shapes(source: &str) -> Vec<DispatcherShape> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType =
        SourceType::from_path("jsconfuser-dispatch.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Vec::new();
    }
    let mut shapes: Vec<DispatcherShape> = Vec::new();
    for stmt in &parsed.program.body {
        if let Some(table_id) = identify_object_create_null_decl(stmt) {
            let entry_count: usize = count_dispatcher_entries(&parsed.program, &table_id);
            shapes.push(DispatcherShape {
                table_id,
                entry_count,
            });
        }
    }
    shapes
}

fn identify_object_create_null_decl(stmt: &Statement<'_>) -> Option<String> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    for declarator in &decl.declarations {
        let Some(name) = declarator.id.get_identifier_name() else {
            continue;
        };
        let Some(init) = &declarator.init else {
            continue;
        };
        let Expression::CallExpression(call) = init else {
            continue;
        };
        if call_is_object_create_null(call) {
            return Some(name.to_string());
        }
    }
    None
}

fn call_is_object_create_null(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return false;
    };
    if member.property.name != "create" {
        return false;
    }
    let Expression::Identifier(id) = &member.object else {
        return false;
    };
    if id.name != "Object" {
        return false;
    }
    if call.arguments.len() != 1 {
        return false;
    }
    matches!(
        call.arguments.first().and_then(|a| a.as_expression()),
        Some(Expression::NullLiteral(_))
    )
}

fn count_dispatcher_entries(program: &Program<'_>, table_id: &str) -> usize {
    let mut count: usize = 0;
    for stmt in &program.body {
        if let Statement::ExpressionStatement(es) = stmt
            && let Expression::AssignmentExpression(assign) = &es.expression
            && assignment_targets_table_index(&assign.left, table_id)
            && matches!(&assign.right, Expression::FunctionExpression(_))
        {
            count += 1;
        }
    }
    count
}

fn assignment_targets_table_index(target: &AssignmentTarget<'_>, table_id: &str) -> bool {
    let AssignmentTarget::ComputedMemberExpression(member) = target else {
        return false;
    };
    let Expression::Identifier(id) = &member.object else {
        return false;
    };
    id.name == table_id
}

#[must_use]
pub fn detect_calculator_shapes(source: &str) -> Vec<CalculatorShape> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("jsconfuser-calc.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Vec::new();
    }
    let mut shapes: Vec<CalculatorShape> = Vec::new();
    for stmt in &parsed.program.body {
        let candidate: Option<(String, usize)> = match stmt {
            Statement::FunctionDeclaration(fd) => {
                let Some(name) = fd.id.as_ref().map(|i| i.name.to_string()) else {
                    continue;
                };
                fd.body
                    .as_ref()
                    .map(|body| (name, count_calculator_switch_arms(&body.statements)))
            }
            Statement::VariableDeclaration(decl) => decl.declarations.iter().find_map(|d| {
                let name: String = d.id.get_identifier_name()?.to_string();
                let init: &Expression<'_> = d.init.as_ref()?;
                let Expression::FunctionExpression(func) = init else {
                    return None;
                };
                let body = func.body.as_ref()?;
                Some((name, count_calculator_switch_arms(&body.statements)))
            }),
            _ => None,
        };
        if let Some((name, arms)) = candidate
            && arms >= 2
        {
            shapes.push(CalculatorShape {
                fn_name: name,
                op_count: arms,
            });
        }
    }
    shapes
}

fn count_calculator_switch_arms(stmts: &[Statement<'_>]) -> usize {
    for stmt in stmts {
        if let Statement::SwitchStatement(switch) = stmt {
            return switch
                .cases
                .iter()
                .filter(|case| case.test.is_some())
                .count();
        }
    }
    0
}

trait IdentifierExt {
    fn get_identifier_name(&self) -> Option<&str>;
}

impl IdentifierExt for oxc_ast::ast::BindingPattern<'_> {
    fn get_identifier_name(&self) -> Option<&str> {
        match &self.kind {
            oxc_ast::ast::BindingPatternKind::BindingIdentifier(b) => Some(b.name.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_rgf_with_long_identifier() {
        let src: &str = "var _rgf_xyz = [new Function('return 1'), new Function('return 2')]; _rgf_xyz[0].apply(this, [_rgf_xyz, arguments]);";
        let shapes: Vec<RgfShape> = detect_rgf_shapes(src);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].array_id, "_rgf_xyz");
        assert_eq!(shapes[0].entry_count, 2);
        assert_eq!(shapes[0].call_sites, 1);
    }

    #[test]
    fn detects_rgf_under_minified_identifier_where_regex_would_fail() {
        let src: &str = "var a = [new Function('return 1'), new Function('return 2')]; a[1].apply(this, [a, arguments]);";
        let shapes: Vec<RgfShape> = detect_rgf_shapes(src);
        assert_eq!(
            shapes.len(),
            1,
            "AST-based detection must work without name prefix"
        );
        assert_eq!(shapes[0].array_id, "a");
        assert_eq!(shapes[0].entry_count, 2);
        assert_eq!(shapes[0].call_sites, 1);
    }

    #[test]
    fn ignores_non_function_array_declaration() {
        let src: &str = "var data = [1, 2, 3, 4];";
        let shapes: Vec<RgfShape> = detect_rgf_shapes(src);
        assert!(shapes.is_empty());
    }

    #[test]
    fn rejects_malformed_source_safely() {
        let shapes: Vec<RgfShape> = detect_rgf_shapes("var x = @@@ broken;");
        assert!(shapes.is_empty());
    }

    #[test]
    fn detects_dispatcher_with_minified_identifier() {
        let src: &str = "var t = Object.create(null); t[\"k\"] = function(){ return 1; };";
        let shapes: Vec<DispatcherShape> = detect_dispatcher_shapes(src);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].table_id, "t");
        assert_eq!(shapes[0].entry_count, 1);
    }

    #[test]
    fn detects_calculator_with_minified_identifier() {
        let src: &str =
            "function c(op, a, b) { switch (op) { case 0: return a + b; case 1: return a - b; } }";
        let shapes: Vec<CalculatorShape> = detect_calculator_shapes(src);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].fn_name, "c");
        assert_eq!(shapes[0].op_count, 2);
    }

    #[test]
    fn detects_calculator_var_assigned_form() {
        let src: &str = "var c = function(op, a, b) { switch (op) { case 0: return a + b; case 1: return a * b; case 2: return a - b; } };";
        let shapes: Vec<CalculatorShape> = detect_calculator_shapes(src);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].op_count, 3);
    }
}
