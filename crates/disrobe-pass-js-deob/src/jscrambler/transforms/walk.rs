use oxc_ast::ast::{Expression, ForStatementInit, MemberExpression, Statement};

pub(super) fn walk_nested_statements<F: FnMut(&Statement<'_>)>(stmt: &Statement<'_>, f: &mut F) {
    match stmt {
        Statement::BlockStatement(block) => {
            for inner in &block.body {
                f(inner);
            }
        }
        Statement::IfStatement(s) => {
            f(&s.consequent);
            if let Some(alt) = s.alternate.as_ref() {
                f(alt);
            }
        }
        Statement::ForStatement(s) => f(&s.body),
        Statement::ForInStatement(s) => f(&s.body),
        Statement::ForOfStatement(s) => f(&s.body),
        Statement::WhileStatement(s) => f(&s.body),
        Statement::DoWhileStatement(s) => f(&s.body),
        Statement::LabeledStatement(s) => f(&s.body),
        Statement::WithStatement(s) => f(&s.body),
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                f(inner);
            }
            if let Some(handler) = s.handler.as_ref() {
                for inner in &handler.body.body {
                    f(inner);
                }
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                for inner in &finalizer.body {
                    f(inner);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                for inner in &case.consequent {
                    f(inner);
                }
            }
        }
        Statement::FunctionDeclaration(func) => {
            if let Some(body) = func.body.as_ref() {
                for inner in &body.statements {
                    f(inner);
                }
            }
        }
        _ => {}
    }
}

pub(super) fn walk_expressions_in_statement<F: FnMut(&Expression<'_>)>(
    stmt: &Statement<'_>,
    f: &mut F,
) {
    match stmt {
        Statement::ExpressionStatement(s) => walk_expression(&s.expression, f),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, f);
            }
        }
        Statement::ThrowStatement(s) => walk_expression(&s.argument, f),
        Statement::VariableDeclaration(s) => {
            for declarator in &s.declarations {
                if let Some(init) = declarator.init.as_ref() {
                    walk_expression(init, f);
                }
            }
        }
        Statement::IfStatement(s) => walk_expression(&s.test, f),
        Statement::WhileStatement(s) => walk_expression(&s.test, f),
        Statement::DoWhileStatement(s) => walk_expression(&s.test, f),
        Statement::SwitchStatement(s) => walk_expression(&s.discriminant, f),
        Statement::ForStatement(s) => {
            if let Some(init) = s.init.as_ref() {
                if let ForStatementInit::VariableDeclaration(decl) = init {
                    for declarator in &decl.declarations {
                        if let Some(value) = declarator.init.as_ref() {
                            walk_expression(value, f);
                        }
                    }
                } else if let Some(expr) = init.as_expression() {
                    walk_expression(expr, f);
                }
            }
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, f);
            }
            if let Some(update) = s.update.as_ref() {
                walk_expression(update, f);
            }
        }
        Statement::ForInStatement(s) => walk_expression(&s.right, f),
        Statement::ForOfStatement(s) => walk_expression(&s.right, f),
        _ => {}
    }
}

pub(super) fn walk_expression<F: FnMut(&Expression<'_>)>(expr: &Expression<'_>, f: &mut F) {
    f(expr);
    match expr {
        Expression::ParenthesizedExpression(e) => walk_expression(&e.expression, f),
        Expression::ArrayExpression(arr) => {
            for el in &arr.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, f);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                match prop {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                        walk_expression(&p.value, f);
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(s) => {
                        walk_expression(&s.argument, f);
                    }
                }
            }
        }
        Expression::CallExpression(call) => {
            walk_expression(&call.callee, f);
            for arg in &call.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, f);
                }
            }
        }
        Expression::NewExpression(new_expr) => {
            walk_expression(&new_expr.callee, f);
            for arg in &new_expr.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, f);
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, f),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, f);
            walk_expression(&c.consequent, f);
            walk_expression(&c.alternate, f);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, f);
            }
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, f);
            walk_expression(&b.right, f);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, f);
            walk_expression(&b.right, f);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, f),
        Expression::AwaitExpression(a) => walk_expression(&a.argument, f),
        Expression::YieldExpression(y) => {
            if let Some(arg) = y.argument.as_ref() {
                walk_expression(arg, f);
            }
        }
        Expression::StaticMemberExpression(m) => walk_expression(&m.object, f),
        Expression::ComputedMemberExpression(m) => {
            walk_expression(&m.object, f);
            walk_expression(&m.expression, f);
        }
        Expression::PrivateFieldExpression(m) => walk_expression(&m.object, f),
        Expression::TemplateLiteral(t) => {
            for inner in &t.expressions {
                walk_expression(inner, f);
            }
        }
        Expression::ChainExpression(c) => match &c.expression {
            oxc_ast::ast::ChainElement::CallExpression(call) => {
                walk_expression(&call.callee, f);
                for arg in &call.arguments {
                    if let Some(inner) = arg.as_expression() {
                        walk_expression(inner, f);
                    }
                }
            }
            other => {
                if let Some(member) = other.member_expression() {
                    walk_member_object(member, f);
                }
            }
        },
        _ => {}
    }
}

fn walk_member_object<F: FnMut(&Expression<'_>)>(member: &MemberExpression<'_>, f: &mut F) {
    match member {
        MemberExpression::ComputedMemberExpression(m) => {
            walk_expression(&m.object, f);
            walk_expression(&m.expression, f);
        }
        MemberExpression::StaticMemberExpression(m) => walk_expression(&m.object, f),
        MemberExpression::PrivateFieldExpression(m) => walk_expression(&m.object, f),
    }
}

pub(super) fn for_each_expression_deep<F: FnMut(&Expression<'_>)>(stmt: &Statement<'_>, f: &mut F) {
    walk_nested_statements(stmt, &mut |inner: &Statement<'_>| {
        for_each_expression_deep(inner, f);
    });
    walk_expressions_in_statement(stmt, &mut |expr: &Expression<'_>| {
        walk_expression(expr, &mut |node: &Expression<'_>| {
            f(node);
            descend_into_function_body(node, f);
        });
    });
}

fn descend_into_function_body<F: FnMut(&Expression<'_>)>(node: &Expression<'_>, f: &mut F) {
    match node {
        Expression::FunctionExpression(func) => {
            if let Some(body) = func.body.as_ref() {
                for stmt in &body.statements {
                    for_each_expression_deep(stmt, f);
                }
            }
        }
        Expression::ArrowFunctionExpression(arrow) => {
            for stmt in &arrow.body.statements {
                for_each_expression_deep(stmt, f);
            }
        }
        _ => {}
    }
}
