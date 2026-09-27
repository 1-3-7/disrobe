use std::collections::BTreeMap;
use std::fmt::Write as _;

use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentTarget, BindingPatternKind, Expression,
    ForStatementInit, Function, ObjectPropertyKind, PropertyKey, PropertyKind,
    SimpleAssignmentTarget, Statement, UnaryOperator, VariableDeclarationKind,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::Span;

const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnsupportedShape;

pub(super) fn function_shape(
    function: &Function<'_>,
    semantic: &Semantic<'_>,
) -> Result<String, UnsupportedShape> {
    let mut canon: Canon<'_, '_> = Canon {
        semantic,
        scope: function.span,
        names: BTreeMap::new(),
        out: String::new(),
        depth: 0,
    };
    canon.function(function)?;
    Ok(canon.out)
}

struct Canon<'s, 'a> {
    semantic: &'s Semantic<'a>,
    scope: Span,
    names: BTreeMap<SymbolId, usize>,
    out: String,
    depth: usize,
}

impl Canon<'_, '_> {
    fn token(&mut self, token: &str) {
        self.out.push_str(token);
        self.out.push(' ');
    }

    const fn enter(&mut self) -> Result<(), UnsupportedShape> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(UnsupportedShape);
        }
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth -= 1;
    }

    fn symbol_token(&mut self, symbol: SymbolId) {
        let declared: Span = self.semantic.symbols().get_span(symbol);
        if self.scope.start <= declared.start && declared.end <= self.scope.end {
            let next: usize = self.names.len();
            let index: usize = *self.names.entry(symbol).or_insert(next);
            let _: std::fmt::Result = write!(self.out, "${index} ");
        } else {
            let name: String = format!("@{}", self.semantic.symbols().get_name(symbol));
            self.token(&name);
        }
    }

    fn binding(
        &mut self,
        binding: &oxc_ast::ast::BindingIdentifier<'_>,
    ) -> Result<(), UnsupportedShape> {
        let symbol: SymbolId = binding.symbol_id.get().ok_or(UnsupportedShape)?;
        self.symbol_token(symbol);
        Ok(())
    }

    fn reference(
        &mut self,
        reference: &oxc_ast::ast::IdentifierReference<'_>,
    ) -> Result<(), UnsupportedShape> {
        let reference_id: oxc_semantic::ReferenceId =
            reference.reference_id.get().ok_or(UnsupportedShape)?;
        match self
            .semantic
            .symbols()
            .get_reference(reference_id)
            .symbol_id()
        {
            Some(symbol) => self.symbol_token(symbol),
            None if reference.name == "undefined" => self.token("undefined!"),
            None => {
                let name: String = format!("#{}", reference.name);
                self.token(&name);
            }
        }
        Ok(())
    }

    fn function(&mut self, function: &Function<'_>) -> Result<(), UnsupportedShape> {
        self.enter()?;
        if function.r#async || function.generator || function.params.rest.is_some() {
            return Err(UnsupportedShape);
        }
        self.token("(fn");
        if let Some(id) = &function.id {
            self.binding(id)?;
        }
        self.token("(");
        for param in &function.params.items {
            let BindingPatternKind::BindingIdentifier(binding) = &param.pattern.kind else {
                return Err(UnsupportedShape);
            };
            self.binding(binding)?;
        }
        self.token(")");
        let body: &oxc_ast::ast::FunctionBody<'_> =
            function.body.as_deref().ok_or(UnsupportedShape)?;
        if !body.directives.is_empty() {
            return Err(UnsupportedShape);
        }
        self.statements(&body.statements)?;
        self.token(")");
        self.leave();
        Ok(())
    }

    fn statements(&mut self, statements: &[Statement<'_>]) -> Result<(), UnsupportedShape> {
        self.token("{");
        for statement in statements {
            self.statement(statement)?;
        }
        self.token("}");
        Ok(())
    }

    fn statement(&mut self, statement: &Statement<'_>) -> Result<(), UnsupportedShape> {
        self.enter()?;
        match statement {
            Statement::EmptyStatement(_) => {}
            Statement::BlockStatement(block) => self.statements(&block.body)?,
            Statement::ExpressionStatement(expression) => {
                self.token("(expr");
                self.expression(&expression.expression)?;
                self.token(")");
            }
            Statement::ReturnStatement(ret) => {
                self.token("(return");
                if let Some(argument) = &ret.argument {
                    self.expression(argument)?;
                }
                self.token(")");
            }
            Statement::ThrowStatement(throw) => {
                self.token("(throw");
                self.expression(&throw.argument)?;
                self.token(")");
            }
            Statement::IfStatement(branch) => {
                self.token("(if");
                self.expression(&branch.test)?;
                self.statement(&branch.consequent)?;
                if let Some(alternate) = &branch.alternate {
                    self.token("else");
                    self.statement(alternate)?;
                }
                self.token(")");
            }
            Statement::ForStatement(loop_statement) => {
                self.token("(for");
                match &loop_statement.init {
                    None => self.token("_"),
                    Some(ForStatementInit::VariableDeclaration(_)) => {
                        return Err(UnsupportedShape);
                    }
                    Some(init) => {
                        let expression: &Expression<'_> =
                            init.as_expression().ok_or(UnsupportedShape)?;
                        self.expression(expression)?;
                    }
                }
                match &loop_statement.test {
                    Some(test) => self.expression(test)?,
                    None => self.token("_"),
                }
                match &loop_statement.update {
                    Some(update) => self.expression(update)?,
                    None => self.token("_"),
                }
                self.statement(&loop_statement.body)?;
                self.token(")");
            }
            Statement::WhileStatement(loop_statement) => {
                self.token("(while");
                self.expression(&loop_statement.test)?;
                self.statement(&loop_statement.body)?;
                self.token(")");
            }
            Statement::TryStatement(attempt) => {
                self.token("(try");
                self.statements(&attempt.block.body)?;
                if let Some(handler) = &attempt.handler {
                    self.token("catch");
                    if let Some(param) = &handler.param {
                        let BindingPatternKind::BindingIdentifier(binding) = &param.pattern.kind
                        else {
                            return Err(UnsupportedShape);
                        };
                        self.binding(binding)?;
                    }
                    self.statements(&handler.body.body)?;
                }
                if let Some(finalizer) = &attempt.finalizer {
                    self.token("finally");
                    self.statements(&finalizer.body)?;
                }
                self.token(")");
            }
            Statement::SwitchStatement(switch) => {
                self.token("(switch");
                self.expression(&switch.discriminant)?;
                for case in &switch.cases {
                    self.token("(case");
                    match &case.test {
                        Some(test) => self.expression(test)?,
                        None => self.token("default"),
                    }
                    self.statements(&case.consequent)?;
                    self.token(")");
                }
                self.token(")");
            }
            Statement::BreakStatement(jump) if jump.label.is_none() => self.token("break"),
            Statement::ContinueStatement(jump) if jump.label.is_none() => self.token("continue"),
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Var =>
            {
                self.token("(var");
                for declarator in &declaration.declarations {
                    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
                        return Err(UnsupportedShape);
                    };
                    self.binding(binding)?;
                    match &declarator.init {
                        Some(init) => {
                            self.token("=");
                            self.expression(init)?;
                        }
                        None => self.token("_"),
                    }
                }
                self.token(")");
            }
            Statement::FunctionDeclaration(function) => self.function(function)?,
            _ => return Err(UnsupportedShape),
        }
        self.leave();
        Ok(())
    }

    fn expression(&mut self, expression: &Expression<'_>) -> Result<(), UnsupportedShape> {
        self.enter()?;
        match expression {
            Expression::ParenthesizedExpression(inner) => self.expression(&inner.expression)?,
            Expression::Identifier(reference) => self.reference(reference)?,
            Expression::ThisExpression(_) => self.token("this"),
            Expression::NullLiteral(_) => self.token("null"),
            Expression::BooleanLiteral(literal) => {
                self.token(if literal.value { "true" } else { "false" });
            }
            Expression::NumericLiteral(literal) => {
                let token: String = format!("{}", literal.value);
                self.token(&token);
            }
            Expression::StringLiteral(literal) => {
                let token: String = format!("{:?}", literal.value.as_str());
                self.token(&token);
            }
            Expression::UnaryExpression(unary) => {
                if let Some(folded) = folded_unary(unary) {
                    self.token(folded);
                } else {
                    let token: String = format!("(unary{}", unary.operator.as_str());
                    self.token(&token);
                    self.expression(&unary.argument)?;
                    self.token(")");
                }
            }
            Expression::BinaryExpression(binary) => {
                let token: String = format!("(binary{}", binary.operator.as_str());
                self.token(&token);
                self.expression(&binary.left)?;
                self.expression(&binary.right)?;
                self.token(")");
            }
            Expression::LogicalExpression(logical) => {
                let token: String = format!("(logical{}", logical.operator.as_str());
                self.token(&token);
                self.expression(&logical.left)?;
                self.expression(&logical.right)?;
                self.token(")");
            }
            Expression::ConditionalExpression(conditional) => {
                self.token("(cond");
                self.expression(&conditional.test)?;
                self.expression(&conditional.consequent)?;
                self.expression(&conditional.alternate)?;
                self.token(")");
            }
            Expression::AssignmentExpression(assignment) => {
                let token: String = format!("(assign{}", assignment.operator.as_str());
                self.token(&token);
                self.assignment_target(&assignment.left)?;
                self.expression(&assignment.right)?;
                self.token(")");
            }
            Expression::UpdateExpression(update) => {
                let token: String = format!(
                    "(update{}{}",
                    update.operator.as_str(),
                    if update.prefix { "pre" } else { "post" }
                );
                self.token(&token);
                self.simple_target(&update.argument)?;
                self.token(")");
            }
            Expression::SequenceExpression(sequence) => {
                self.token("(seq");
                for item in &sequence.expressions {
                    self.expression(item)?;
                }
                self.token(")");
            }
            Expression::CallExpression(call) => {
                if call.optional {
                    return Err(UnsupportedShape);
                }
                self.token("(call");
                self.expression(&call.callee)?;
                self.arguments(&call.arguments)?;
                self.token(")");
            }
            Expression::NewExpression(construct) => {
                self.token("(new");
                self.expression(&construct.callee)?;
                self.arguments(&construct.arguments)?;
                self.token(")");
            }
            Expression::StaticMemberExpression(member) => {
                if member.optional {
                    return Err(UnsupportedShape);
                }
                self.static_member(&member.object, member.property.name.as_str())?;
            }
            Expression::ComputedMemberExpression(member) => {
                if member.optional {
                    return Err(UnsupportedShape);
                }
                self.computed_member(&member.object, &member.expression)?;
            }
            Expression::ArrayExpression(array) => {
                self.token("(array");
                for element in &array.elements {
                    match element {
                        ArrayExpressionElement::Elision(_) => self.token("hole"),
                        ArrayExpressionElement::SpreadElement(_) => return Err(UnsupportedShape),
                        other => {
                            let item: &Expression<'_> =
                                other.as_expression().ok_or(UnsupportedShape)?;
                            self.expression(item)?;
                        }
                    }
                }
                self.token(")");
            }
            Expression::ObjectExpression(object) => {
                self.token("(object");
                for property in &object.properties {
                    let ObjectPropertyKind::ObjectProperty(property) = property else {
                        return Err(UnsupportedShape);
                    };
                    if property.computed || property.kind != PropertyKind::Init {
                        return Err(UnsupportedShape);
                    }
                    self.property_key(&property.key)?;
                    self.expression(&property.value)?;
                }
                self.token(")");
            }
            Expression::FunctionExpression(function) => self.function(function)?,
            _ => return Err(UnsupportedShape),
        }
        self.leave();
        Ok(())
    }

    fn static_member(
        &mut self,
        object: &Expression<'_>,
        property: &str,
    ) -> Result<(), UnsupportedShape> {
        self.token("(member");
        self.expression(object)?;
        self.token(property);
        self.token(")");
        Ok(())
    }

    fn computed_member(
        &mut self,
        object: &Expression<'_>,
        key: &Expression<'_>,
    ) -> Result<(), UnsupportedShape> {
        if let Expression::StringLiteral(name) = key {
            return self.static_member(object, name.value.as_str());
        }
        self.token("(index");
        self.expression(object)?;
        self.expression(key)?;
        self.token(")");
        Ok(())
    }

    fn property_key(&mut self, key: &PropertyKey<'_>) -> Result<(), UnsupportedShape> {
        let name: std::borrow::Cow<'_, str> = key.static_name().ok_or(UnsupportedShape)?;
        let token: String = format!("key:{name}");
        self.token(&token);
        Ok(())
    }

    fn arguments(&mut self, arguments: &[Argument<'_>]) -> Result<(), UnsupportedShape> {
        self.token("(");
        for argument in arguments {
            let item: &Expression<'_> = argument.as_expression().ok_or(UnsupportedShape)?;
            self.expression(item)?;
        }
        self.token(")");
        Ok(())
    }

    fn assignment_target(&mut self, target: &AssignmentTarget<'_>) -> Result<(), UnsupportedShape> {
        let simple: &SimpleAssignmentTarget<'_> = target
            .as_simple_assignment_target()
            .ok_or(UnsupportedShape)?;
        self.simple_target(simple)
    }

    fn simple_target(
        &mut self,
        target: &SimpleAssignmentTarget<'_>,
    ) -> Result<(), UnsupportedShape> {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(reference) => {
                self.reference(reference)
            }
            SimpleAssignmentTarget::StaticMemberExpression(member) => {
                self.static_member(&member.object, member.property.name.as_str())
            }
            SimpleAssignmentTarget::ComputedMemberExpression(member) => {
                self.computed_member(&member.object, &member.expression)
            }
            _ => Err(UnsupportedShape),
        }
    }
}

fn folded_unary(unary: &oxc_ast::ast::UnaryExpression<'_>) -> Option<&'static str> {
    match (&unary.operator, &unary.argument) {
        (UnaryOperator::Void, Expression::NumericLiteral(_)) => Some("undefined!"),
        (UnaryOperator::LogicalNot, Expression::NumericLiteral(literal)) => {
            Some(if literal.value.to_bits() == 0 {
                "true"
            } else {
                "false"
            })
        }
        _ => None,
    }
}
