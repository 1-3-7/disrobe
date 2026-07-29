use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, BindingPatternKind, CallExpression, Expression, Function, MemberExpression,
    ObjectPropertyKind, PropertyKind, Statement, VariableDeclaration,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;

use crate::scan_utils::{
    find_brace_close, find_paren_close, find_statement_end, regex_can_follow, skip_regex_literal,
    skip_string, skip_ws,
};

const SELF_DEFENDING_REGEX: &str = "(((.+)+)+)+$";
const CONSOLE_HIJACK_MARKER_CONSOLE: &str = ".console=";
const CONSOLE_HIJACK_MARKER_PROTO: &str = ".__proto__=";
const INTEGRITY_INVOCATION_MARKER_REGEXP: &str = "RegExp(";
const INTEGRITY_INVOCATION_MARKER_TEST: &str = ".test(";
const INTEGRITY_FUNCTION_PATTERN: &str = r"function *\( *\)";
const INTEGRITY_INCREMENT_PATTERN: &str = r"\+\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)";
const RATCHET_FUNCTION_MARKER_LOOP: &str = "while (true) {}";
const RATCHET_FUNCTION_MARKER_CTOR: &str = "constructor";

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    find_paren_close(bytes, open + 1)
}

fn is_protection_payload(statement: &str) -> bool {
    statement.contains(SELF_DEFENDING_REGEX)
        || (statement.contains(CONSOLE_HIJACK_MARKER_CONSOLE)
            && statement.contains(CONSOLE_HIJACK_MARKER_PROTO))
        || (statement.contains(INTEGRITY_INVOCATION_MARKER_REGEXP)
            && statement.contains(INTEGRITY_INVOCATION_MARKER_TEST))
}

const RATCHET_RESIDUAL_MAX_LEN: usize = 220;

const fn is_inert_proxy_value(value: &Expression<'_>) -> bool {
    matches!(
        value,
        Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
    )
}

fn inert_proxy_declaration_name<'a>(declaration: &'a VariableDeclaration<'a>) -> Option<&'a str> {
    if declaration.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = declaration.declarations.first()?;
    let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
        &declarator.id.kind
    else {
        return None;
    };
    let initializer: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::ObjectExpression(object): &Expression<'_> = initializer else {
        return None;
    };
    let inert: bool = object
        .properties
        .iter()
        .all(|property_kind: &ObjectPropertyKind<'_>| {
            let ObjectPropertyKind::ObjectProperty(property): &ObjectPropertyKind<'_> =
                property_kind
            else {
                return false;
            };
            property.kind == PropertyKind::Init
                && !property.computed
                && !property.method
                && !property.shorthand
                && is_inert_proxy_value(&property.value)
        });
    inert.then_some(identifier.name.as_str())
}

enum RatchetPrefix {
    Empty,
    Proxy {
        name: String,
        division_properties: Vec<String>,
    },
}

fn ratchet_prefix_division_proxy(prefix: &str) -> Option<RatchetPrefix> {
    let trimmed: &str = prefix.trim();
    if trimmed.is_empty() {
        return Some(RatchetPrefix::Empty);
    }
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, trimmed, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return None;
    }
    let statement: &Statement<'_> = parsed.program.body.first()?;
    let Statement::VariableDeclaration(declaration): &Statement<'_> = statement else {
        return None;
    };
    let proxy_name: &str = inert_proxy_declaration_name(declaration)?;
    let (_declaration_name, initializer): (&str, &Expression<'_>) =
        single_named_initializer(declaration)?;
    let Expression::ObjectExpression(object): &Expression<'_> = initializer.get_inner_expression()
    else {
        return None;
    };
    let mut division_properties: Vec<String> = Vec::new();
    for property_kind in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property): &ObjectPropertyKind<'_> = property_kind
        else {
            continue;
        };
        let Expression::FunctionExpression(function): &Expression<'_> =
            property.value.get_inner_expression()
        else {
            continue;
        };
        if !proxy_function_is_forward_division(function) {
            continue;
        }
        let property_name: String = match &property.key {
            oxc_ast::ast::PropertyKey::StaticIdentifier(identifier) => {
                identifier.name.as_str().to_owned()
            }
            oxc_ast::ast::PropertyKey::StringLiteral(literal) => literal.value.as_str().to_owned(),
            _ => continue,
        };
        division_properties.push(property_name);
    }
    Some(RatchetPrefix::Proxy {
        name: proxy_name.to_owned(),
        division_properties,
    })
}

fn expression_is_identifier(expression: &Expression<'_>, name: &str) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::Identifier(identifier) if identifier.name == name
    )
}

fn expression_is_number(expression: &Expression<'_>, value: f64) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::NumericLiteral(literal) if literal.value.to_bits() == value.to_bits()
    )
}

fn expression_is_string(expression: &Expression<'_>, value: &str) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::StringLiteral(literal) if literal.value == value
    )
}

fn is_counter_ratio(
    expression: &Expression<'_>,
    parameter_name: &str,
    division_proxy: Option<(&str, &[String])>,
) -> bool {
    if let Expression::BinaryExpression(binary) = expression.get_inner_expression() {
        return binary.operator.as_str() == "/"
            && expression_is_identifier(&binary.left, parameter_name)
            && expression_is_identifier(&binary.right, parameter_name);
    }
    let Some((proxy_name, properties)): Option<(&str, &[String])> = division_proxy else {
        return false;
    };
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    let Some(property_name): Option<&str> = member.static_property_name() else {
        return false;
    };
    if !expression_is_identifier(member.object(), proxy_name)
        || !properties
            .iter()
            .any(|candidate: &String| candidate == property_name)
    {
        return false;
    }
    let Some(first_argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(second_argument): Option<&Expression<'_>> =
        call.arguments.get(1).and_then(Argument::as_expression)
    else {
        return false;
    };
    expression_is_identifier(first_argument, parameter_name)
        && expression_is_identifier(second_argument, parameter_name)
}

fn is_counter_ratio_length(
    expression: &Expression<'_>,
    parameter_name: &str,
    division_proxy: Option<(&str, &[String])>,
) -> bool {
    let Some(member): Option<&MemberExpression<'_>> = expression.get_member_expr() else {
        return false;
    };
    if member.static_property_name() != Some("length") {
        return false;
    }
    let Expression::BinaryExpression(concatenation): &Expression<'_> =
        member.object().get_inner_expression()
    else {
        return false;
    };
    concatenation.operator.as_str() == "+"
        && expression_is_string(&concatenation.left, "")
        && is_counter_ratio(&concatenation.right, parameter_name, division_proxy)
}

fn is_counter_modulo_twenty(expression: &Expression<'_>, parameter_name: &str) -> bool {
    let Expression::BinaryExpression(binary): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    binary.operator.as_str() == "%"
        && expression_is_identifier(&binary.left, parameter_name)
        && expression_is_number(&binary.right, 20.0)
}

fn is_counter_guard(
    expression: &Expression<'_>,
    parameter_name: &str,
    division_proxy: Option<(&str, &[String])>,
) -> bool {
    let Expression::LogicalExpression(logical): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if logical.operator.as_str() != "||" {
        return false;
    }
    let Expression::BinaryExpression(length_check): &Expression<'_> =
        logical.left.get_inner_expression()
    else {
        return false;
    };
    let Expression::BinaryExpression(modulo_check): &Expression<'_> =
        logical.right.get_inner_expression()
    else {
        return false;
    };
    length_check.operator.as_str() == "!=="
        && is_counter_ratio_length(&length_check.left, parameter_name, division_proxy)
        && expression_is_number(&length_check.right, 1.0)
        && modulo_check.operator.as_str() == "==="
        && is_counter_modulo_twenty(&modulo_check.left, parameter_name)
        && expression_is_number(&modulo_check.right, 0.0)
}

fn is_string_typeof_guard(expression: &Expression<'_>, parameter_name: &str) -> bool {
    let Expression::BinaryExpression(binary): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if binary.operator.as_str() != "===" {
        return false;
    }
    let Expression::UnaryExpression(unary): &Expression<'_> = binary.left.get_inner_expression()
    else {
        return false;
    };
    unary.operator.as_str() == "typeof"
        && expression_is_identifier(&unary.argument, parameter_name)
        && expression_is_string(&binary.right, "string")
}

fn single_string_argument<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return None;
    }
    let argument: &Expression<'_> = call.arguments.first()?.as_expression()?;
    let Expression::StringLiteral(literal): &Expression<'_> = argument.get_inner_expression()
    else {
        return None;
    };
    Some(literal.value.as_str())
}

fn is_ordinary_anonymous_function(expression: &Expression<'_>) -> bool {
    let Expression::FunctionExpression(function): &Expression<'_> =
        expression.get_inner_expression()
    else {
        return false;
    };
    function.id.is_none()
        && !function.generator
        && !function.r#async
        && !function.declare
        && function.type_parameters.is_none()
        && function.this_param.is_none()
        && function.return_type.is_none()
        && function.body.is_some()
}

fn is_trap_constructor(call: &CallExpression<'_>, payload: &str) -> bool {
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    member.static_property_name() == Some("constructor")
        && is_ordinary_anonymous_function(member.object())
        && single_string_argument(call) == Some(payload)
}

fn is_trap_invocation(
    expression: &Expression<'_>,
    payload: &str,
    method: &str,
    receiver_argument: &str,
) -> bool {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    if member.static_property_name() != Some(method)
        || single_string_argument(call) != Some(receiver_argument)
    {
        return false;
    }
    let Expression::CallExpression(constructor_call): &Expression<'_> =
        member.object().get_inner_expression()
    else {
        return false;
    };
    is_trap_constructor(constructor_call, payload)
}

fn return_argument<'a>(statement: &'a Statement<'a>) -> Option<&'a Expression<'a>> {
    match statement {
        Statement::ReturnStatement(return_statement) => return_statement.argument.as_ref(),
        Statement::BlockStatement(block) if block.body.len() == 1 => {
            let statement: &Statement<'_> = block.body.first()?;
            let Statement::ReturnStatement(return_statement): &Statement<'_> = statement else {
                return None;
            };
            return_statement.argument.as_ref()
        }
        _ => None,
    }
}

fn expression_statement<'a>(statement: &'a Statement<'a>) -> Option<&'a Expression<'a>> {
    let Statement::ExpressionStatement(expression_statement): &Statement<'_> = statement else {
        return None;
    };
    Some(&expression_statement.expression)
}

fn is_recursive_increment_statement(
    statement: &Statement<'_>,
    inner_name: &str,
    parameter_name: &str,
) -> bool {
    let Some(expression): Option<&Expression<'_>> = expression_statement(statement) else {
        return false;
    };
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if call.optional
        || call.type_parameters.is_some()
        || !expression_is_identifier(&call.callee, inner_name)
        || call.arguments.len() != 1
    {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Expression::UpdateExpression(update): &Expression<'_> = argument.get_inner_expression()
    else {
        return false;
    };
    update.prefix
        && update.operator.as_str() == "++"
        && update.argument.get_identifier() == Some(parameter_name)
}

fn is_generated_counter_branch(
    statement: &Statement<'_>,
    parameter_name: &str,
    division_proxy: Option<(&str, &[String])>,
) -> bool {
    let Statement::IfStatement(if_statement): &Statement<'_> = statement else {
        return false;
    };
    if !is_string_typeof_guard(&if_statement.test, parameter_name) {
        return false;
    }
    let Some(consequent): Option<&Expression<'_>> = return_argument(&if_statement.consequent)
    else {
        return false;
    };
    if !is_trap_invocation(consequent, RATCHET_FUNCTION_MARKER_LOOP, "apply", "counter") {
        return false;
    }
    let Some(alternate): Option<&Statement<'_>> = if_statement.alternate.as_ref() else {
        return false;
    };
    let Some(alternate_expression): Option<&Expression<'_>> = expression_statement(alternate)
    else {
        return false;
    };
    let Expression::ConditionalExpression(conditional): &Expression<'_> =
        alternate_expression.get_inner_expression()
    else {
        return false;
    };
    is_counter_guard(&conditional.test, parameter_name, division_proxy)
        && is_trap_invocation(&conditional.consequent, "debugger", "call", "action")
        && is_trap_invocation(&conditional.alternate, "debugger", "apply", "stateObject")
}

fn simple_function_parameter_name<'a>(function: &'a Function<'a>) -> Option<&'a str> {
    if function.params.rest.is_some() || function.params.items.len() != 1 {
        return None;
    }
    let parameter: &oxc_ast::ast::FormalParameter<'_> = function.params.items.first()?;
    if !parameter.decorators.is_empty()
        || parameter.pattern.optional
        || parameter.pattern.type_annotation.is_some()
    {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
        &parameter.pattern.kind
    else {
        return None;
    };
    Some(identifier.name.as_str())
}

fn is_generated_inner_dispatcher(
    source: &str,
    inner_name: &str,
    division_proxy: Option<(&str, &[String])>,
) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return false;
    }
    let Some(statement): Option<&Statement<'_>> = parsed.program.body.first() else {
        return false;
    };
    let Statement::FunctionDeclaration(function): &Statement<'_> = statement else {
        return false;
    };
    if function
        .id
        .as_ref()
        .is_none_or(|identifier: &oxc_ast::ast::BindingIdentifier<'_>| {
            identifier.name != inner_name
        })
        || function.generator
        || function.r#async
        || function.declare
        || function.type_parameters.is_some()
        || function.this_param.is_some()
        || function.return_type.is_some()
    {
        return false;
    }
    let Some(parameter_name): Option<&str> = simple_function_parameter_name(function) else {
        return false;
    };
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || !(2..=3).contains(&body.statements.len()) {
        return false;
    }
    let offset: usize = if body.statements.len() == 3 {
        let Some(prefix): Option<&Statement<'_>> = body.statements.first() else {
            return false;
        };
        let Statement::VariableDeclaration(declaration): &Statement<'_> = prefix else {
            return false;
        };
        let Some(prefix_name): Option<&str> = inert_proxy_declaration_name(declaration) else {
            return false;
        };
        if prefix_name == inner_name || prefix_name == parameter_name {
            return false;
        }
        1
    } else {
        0
    };
    let Some(branch): Option<&Statement<'_>> = body.statements.get(offset) else {
        return false;
    };
    let Some(recursion): Option<&Statement<'_>> = body.statements.get(offset + 1) else {
        return false;
    };
    is_generated_counter_branch(branch, parameter_name, division_proxy)
        && is_recursive_increment_statement(recursion, inner_name, parameter_name)
}

const fn is_plain_catch_parameter(parameter: Option<&oxc_ast::ast::CatchParameter<'_>>) -> bool {
    let Some(parameter): Option<&oxc_ast::ast::CatchParameter<'_>> = parameter else {
        return true;
    };
    !parameter.pattern.optional
        && parameter.pattern.type_annotation.is_none()
        && matches!(
            &parameter.pattern.kind,
            BindingPatternKind::BindingIdentifier(_)
        )
}

fn is_generated_dispatcher_residual(
    residual: &str,
    inner_name: &str,
    outer_parameter_name: &str,
) -> bool {
    let allocator: Allocator = Allocator::default();
    let wrapped: String = format!("function oracle(){{{residual}}}");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return false;
    }
    let Some(statement): Option<&Statement<'_>> = parsed.program.body.first() else {
        return false;
    };
    let Statement::FunctionDeclaration(function): &Statement<'_> = statement else {
        return false;
    };
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if body.statements.len() != 1 {
        return false;
    }
    let Some(body_statement): Option<&Statement<'_>> = body.statements.first() else {
        return false;
    };
    let Statement::TryStatement(try_statement): &Statement<'_> = body_statement else {
        return false;
    };
    let Some(handler): Option<&oxc_ast::ast::CatchClause<'_>> = try_statement.handler.as_deref()
    else {
        return false;
    };
    if try_statement.finalizer.is_some()
        || try_statement.block.body.len() != 1
        || !handler.body.body.is_empty()
        || !is_plain_catch_parameter(handler.param.as_ref())
    {
        return false;
    }
    let Some(try_body): Option<&Statement<'_>> = try_statement.block.body.first() else {
        return false;
    };
    let Statement::IfStatement(if_statement): &Statement<'_> = try_body else {
        return false;
    };
    if !expression_is_identifier(&if_statement.test, outer_parameter_name) {
        return false;
    }
    let Statement::ReturnStatement(return_statement): &Statement<'_> = &if_statement.consequent
    else {
        return false;
    };
    if !matches!(
        return_statement.argument.as_ref(),
        Some(Expression::Identifier(identifier)) if identifier.name == inner_name
    ) {
        return false;
    }
    let alternate: &Statement<'_> = match if_statement.alternate.as_ref() {
        Some(statement) => statement,
        None => return false,
    };
    let Statement::ExpressionStatement(expression_statement): &Statement<'_> = alternate else {
        return false;
    };
    let Expression::CallExpression(call): &Expression<'_> = &expression_statement.expression else {
        return false;
    };
    if !matches!(&call.callee, Expression::Identifier(identifier) if identifier.name == inner_name)
        || call.arguments.len() != 1
    {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    matches!(argument, Expression::NumericLiteral(literal) if literal.value == 0.0)
}

fn is_ratchet_dispatcher_shape(
    source: &str,
    bytes: &[u8],
    outer_brace_open: usize,
    outer_brace_close: usize,
    outer_parameter_name: &str,
) -> bool {
    let mut search_from: usize = outer_brace_open + 1;
    while search_from < outer_brace_close {
        let Some(rel): Option<usize> = source[search_from..outer_brace_close].find("function ")
        else {
            return false;
        };
        let inner_kw_start: usize = search_from + rel;
        search_from = inner_kw_start + "function ".len();
        if is_ident_byte(bytes[inner_kw_start - 1]) {
            continue;
        }
        let inner_name_start: usize = inner_kw_start + "function ".len();
        let mut inner_name_end: usize = inner_name_start;
        while inner_name_end < bytes.len() && is_ident_byte(bytes[inner_name_end]) {
            inner_name_end += 1;
        }
        if inner_name_end == inner_name_start {
            continue;
        }
        let inner_name: &str = &source[inner_name_start..inner_name_end];
        let inner_paren_open: usize = skip_ws(bytes, inner_name_end);
        if bytes.get(inner_paren_open) != Some(&b'(') {
            continue;
        }
        let Some(inner_paren_close): Option<usize> = find_paren_close(bytes, inner_paren_open + 1)
        else {
            continue;
        };
        let inner_brace_open: usize = skip_ws(bytes, inner_paren_close + 1);
        if bytes.get(inner_brace_open) != Some(&b'{') {
            continue;
        }
        let Some(inner_brace_close): Option<usize> = find_brace_close(bytes, inner_brace_open + 1)
        else {
            continue;
        };
        if inner_brace_close >= outer_brace_close {
            continue;
        }
        let prefix: &str = &source[outer_brace_open + 1..inner_kw_start];
        let Some(division_proxy): Option<RatchetPrefix> = ratchet_prefix_division_proxy(prefix)
        else {
            continue;
        };
        let inner_body: &str = &source[inner_brace_open..=inner_brace_close];
        if !inner_body.contains(RATCHET_FUNCTION_MARKER_LOOP)
            || !inner_body.contains(RATCHET_FUNCTION_MARKER_CTOR)
            || !inner_body.contains(inner_name)
        {
            continue;
        }
        let inner_source: &str = &source[inner_kw_start..=inner_brace_close];
        let division_proxy_view: Option<(&str, &[String])> = match &division_proxy {
            RatchetPrefix::Empty => None,
            RatchetPrefix::Proxy {
                name,
                division_properties,
            } => Some((name.as_str(), division_properties.as_slice())),
        };
        if !is_generated_inner_dispatcher(inner_source, inner_name, division_proxy_view) {
            continue;
        }
        let residual_start: usize = inner_brace_close + 1;
        if residual_start > outer_brace_close {
            continue;
        }
        let residual: &str = source[residual_start..outer_brace_close].trim();
        if residual.len() > RATCHET_RESIDUAL_MAX_LEN {
            continue;
        }
        if is_generated_dispatcher_residual(residual, inner_name, outer_parameter_name) {
            return true;
        }
    }
    false
}

struct RatchetProofVisitor<'a> {
    name: &'a str,
    bindings: usize,
    mutated: bool,
    candidates: Vec<(usize, usize, String)>,
}

impl<'a> Visit<'a> for RatchetProofVisitor<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::BindingIdentifier(identifier) if identifier.name == self.name => {
                self.bindings += 1;
            }
            AstKind::Function(function)
                if function.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration
                    && function.id.as_ref().is_some_and(
                        |identifier: &oxc_ast::ast::BindingIdentifier<'_>| {
                            identifier.name == self.name
                        },
                    )
                    && !function.generator
                    && !function.r#async
                    && !function.declare
                    && function.type_parameters.is_none()
                    && function.this_param.is_none()
                    && function.return_type.is_none() =>
            {
                let Some(parameter_name): Option<&str> = simple_function_parameter_name(function)
                else {
                    return;
                };
                let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref()
                else {
                    return;
                };
                self.candidates.push((
                    body.span.start as usize,
                    body.span.end as usize,
                    parameter_name.to_owned(),
                ));
            }
            AstKind::AssignmentExpression(assignment) => {
                if matches!(
                    &assignment.left,
                    oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier)
                        if identifier.name == self.name
                ) {
                    self.mutated = true;
                }
            }
            AstKind::UpdateExpression(update)
                if update.argument.get_identifier() == Some(self.name) =>
            {
                self.mutated = true;
            }
            AstKind::UnaryExpression(unary)
                if unary.operator.as_str() == "delete"
                    && expression_is_identifier(&unary.argument, self.name) =>
            {
                self.mutated = true;
            }
            _ => {}
        }
    }
}

fn has_proven_ratchet_function(source: &str, name: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return false;
    }
    let mut visitor: RatchetProofVisitor<'_> = RatchetProofVisitor {
        name,
        bindings: 0,
        mutated: false,
        candidates: Vec::new(),
    };
    visitor.visit_program(&parsed.program);
    if visitor.bindings != 1 || visitor.mutated || visitor.candidates.len() != 1 {
        return false;
    }
    let Some((body_start, body_end, parameter_name)): Option<&(usize, usize, String)> =
        visitor.candidates.first()
    else {
        return false;
    };
    let bytes: &[u8] = source.as_bytes();
    let Some(body_close): Option<usize> = body_end.checked_sub(1) else {
        return false;
    };
    bytes.get(*body_start) == Some(&b'{')
        && bytes.get(body_close) == Some(&b'}')
        && is_ratchet_dispatcher_shape(source, bytes, *body_start, body_close, parameter_name)
}

const RETURN_LITERALS: &[&str] = &["![]", "!![]", "true", "false"];

fn remove_discarded_constructor_apply_statements(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(function(){return") {
        let stmt_start: usize = from + rel;
        let after_kw: usize = stmt_start + "(function(){return".len();
        from = after_kw;
        let after_return: usize = skip_ws(bytes, after_kw);
        let Some(ret_lit_end): Option<usize> = RETURN_LITERALS.iter().find_map(|lit: &&str| {
            source[after_return..]
                .starts_with(*lit)
                .then(|| after_return + lit.len())
        }) else {
            continue;
        };
        let semi: usize = skip_ws(bytes, ret_lit_end);
        if bytes.get(semi) != Some(&b';') {
            continue;
        }
        let close_fn_body: usize = skip_ws(bytes, semi + 1);
        if bytes.get(close_fn_body) != Some(&b'}') {
            continue;
        }
        let after_body: usize = close_fn_body + 1;
        let ctor_start: usize = if source[after_body..].starts_with("['constructor']") {
            after_body + "['constructor']".len()
        } else if source[after_body..].starts_with(".constructor") {
            after_body + ".constructor".len()
        } else {
            continue;
        };
        if bytes.get(ctor_start) != Some(&b'(') {
            continue;
        }
        let Some(ctor_close): Option<usize> = find_paren_close(bytes, ctor_start + 1) else {
            continue;
        };
        let after_ctor: usize = ctor_close + 1;
        let invoke_start: usize = if source[after_ctor..].starts_with("['apply']") {
            after_ctor + "['apply']".len()
        } else if source[after_ctor..].starts_with(".apply") {
            after_ctor + ".apply".len()
        } else if source[after_ctor..].starts_with("['call']") {
            after_ctor + "['call']".len()
        } else if source[after_ctor..].starts_with(".call") {
            after_ctor + ".call".len()
        } else {
            continue;
        };
        if bytes.get(invoke_start) != Some(&b'(') {
            continue;
        }
        let Some(invoke_close): Option<usize> = find_paren_close(bytes, invoke_start + 1) else {
            continue;
        };
        let after_invoke: usize = skip_ws(bytes, invoke_close + 1);
        if bytes.get(after_invoke) != Some(&b')') {
            continue;
        }
        let mut end: usize = after_invoke + 1;
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        removals.push((stmt_start, end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        out.push(';');
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct SelfDefendingStats {
    pub(super) checker_blocks: usize,
    pub(super) once_wrappers: usize,
    pub(super) debug_ratchets: usize,
    pub(super) ratchet_functions: usize,
    pub(super) discarded_constructor_calls: usize,
}

pub(super) fn strip_self_defending(source: &str) -> (String, SelfDefendingStats) {
    let mut stats: SelfDefendingStats = SelfDefendingStats::default();
    let (after_checker, checker_names): (String, Vec<String>) = remove_checker_blocks(source);
    stats.checker_blocks = checker_names.len();
    let (after_wrapper, proven_wrapper_names): (String, Vec<String>) =
        remove_once_wrappers(&after_checker, &checker_names);
    stats.once_wrappers = proven_wrapper_names.len();
    let (after_iife, iife_removed): (String, usize) =
        remove_integrity_invocation_iifes(&after_wrapper, &proven_wrapper_names);
    stats.checker_blocks += iife_removed;
    let (after_debug, debug_removed): (String, usize) = remove_debug_ratchets(&after_iife);
    stats.debug_ratchets = debug_removed;
    let (after_ratchet_fn, ratchet_fn_removed): (String, usize) =
        remove_ratchet_functions(&after_debug);
    stats.ratchet_functions = ratchet_fn_removed;
    let (after_ctor_call, ctor_call_removed): (String, usize) =
        remove_discarded_constructor_apply_statements(&after_ratchet_fn);
    stats.discarded_constructor_calls = ctor_call_removed;
    (after_ctor_call, stats)
}

fn enclosing_bare_iife(source: &str, inner_pos: usize) -> Option<(usize, usize)> {
    let mut search_end: usize = inner_pos;
    while let Some(outer_open) = source[..search_end].rfind("(function(") {
        if let Some(container) = bare_iife_at(source, inner_pos, outer_open) {
            return Some(container);
        }
        search_end = outer_open;
    }
    None
}

fn bare_iife_at(source: &str, inner_pos: usize, outer_open: usize) -> Option<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let fn_paren: usize = outer_open + "(function".len();
    if bytes.get(fn_paren) != Some(&b'(') {
        return None;
    }
    let params_close: usize = find_paren_close(bytes, fn_paren + 1)?;
    let brace_open: usize = skip_ws(bytes, params_close + 1);
    if bytes.get(brace_open) != Some(&b'{') {
        return None;
    }
    let brace_close: usize = find_brace_close(bytes, brace_open + 1)?;
    if !(brace_open < inner_pos && inner_pos < brace_close) {
        return None;
    }
    let after_body: usize = skip_ws(bytes, brace_close + 1);
    let final_close: usize = if bytes.get(after_body) == Some(&b'(') {
        let call_close: usize = find_paren_close(bytes, after_body + 1)?;
        let wrap_close: usize = skip_ws(bytes, call_close + 1);
        if bytes.get(wrap_close) != Some(&b')') {
            return None;
        }
        wrap_close
    } else if bytes.get(after_body) == Some(&b')') {
        let call_open: usize = skip_ws(bytes, after_body + 1);
        if bytes.get(call_open) != Some(&b'(') {
            return None;
        }
        find_paren_close(bytes, call_open + 1)?
    } else {
        return None;
    };
    let mut end: usize = final_close + 1;
    if bytes.get(end) == Some(&b';') {
        end += 1;
    }
    Some((outer_open, end))
}

fn generated_integrity_wrapper_names<'a>(
    invocation: &'a Expression<'a>,
    proxy: Option<(&'a VariableDeclaration<'a>, &'a str)>,
) -> Option<(&'a str, &'a str)> {
    let Expression::CallExpression(invoke_wrapper): &Expression<'_> =
        invocation.get_inner_expression()
    else {
        return None;
    };
    if invoke_wrapper.optional
        || invoke_wrapper.type_parameters.is_some()
        || !invoke_wrapper.arguments.is_empty()
    {
        return None;
    }
    let Expression::CallExpression(wrapper_call): &Expression<'_> =
        invoke_wrapper.callee.get_inner_expression()
    else {
        return None;
    };
    if wrapper_call.optional
        || wrapper_call.type_parameters.is_some()
        || wrapper_call.arguments.len() != 2
    {
        return None;
    }
    let Expression::Identifier(wrapper): &Expression<'_> =
        wrapper_call.callee.get_inner_expression()
    else {
        return None;
    };
    let receiver: &Expression<'_> = wrapper_call
        .arguments
        .first()
        .and_then(Argument::as_expression)?;
    let checker: &Expression<'_> = wrapper_call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)?;
    if !matches!(
        receiver.get_inner_expression(),
        Expression::ThisExpression(_)
    ) {
        return None;
    }
    let Expression::FunctionExpression(checker_function): &Expression<'_> =
        checker.get_inner_expression()
    else {
        return None;
    };
    let ratchet_name: &str = generated_integrity_checker_ratchet_name(checker_function, proxy)?;
    Some((wrapper.name.as_str(), ratchet_name))
}

fn generated_integrity_invocation_names(source: &str) -> Option<(String, String)> {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return None;
    }
    let expression: &Expression<'_> = parsed.program.body.first().and_then(expression_statement)?;
    let Expression::CallExpression(iife_call): &Expression<'_> = expression.get_inner_expression()
    else {
        return None;
    };
    if iife_call.optional || iife_call.type_parameters.is_some() || !iife_call.arguments.is_empty()
    {
        return None;
    }
    let Expression::FunctionExpression(iife): &Expression<'_> =
        iife_call.callee.get_inner_expression()
    else {
        return None;
    };
    if iife.id.is_some()
        || iife.generator
        || iife.r#async
        || iife.declare
        || iife.type_parameters.is_some()
        || iife.this_param.is_some()
        || iife.return_type.is_some()
        || !iife.params.items.is_empty()
        || iife.params.rest.is_some()
    {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = iife.body.as_deref()?;
    if !body.directives.is_empty() {
        return None;
    }
    if body.statements.len() == 1 {
        return body
            .statements
            .first()
            .and_then(expression_statement)
            .and_then(|invocation: &Expression<'_>| {
                generated_integrity_wrapper_names(invocation, None)
            })
            .map(|(wrapper_name, ratchet_name): (&str, &str)| {
                (wrapper_name.to_owned(), ratchet_name.to_owned())
            });
    }
    if body.statements.len() != 2 {
        return None;
    }
    let Some(Statement::VariableDeclaration(declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return None;
    };
    let proxy_name: &str = inert_proxy_declaration_name(declaration)?;
    let invocation: &Expression<'_> = body.statements.get(1).and_then(expression_statement)?;
    generated_integrity_wrapper_names(invocation, Some((declaration, proxy_name))).map(
        |(wrapper_name, ratchet_name): (&str, &str)| {
            (wrapper_name.to_owned(), ratchet_name.to_owned())
        },
    )
}

fn has_proven_const_once_wrapper_before(
    source: &str,
    wrapper_name: &str,
    iife_start: usize,
) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let Some(iife_scope): Option<Vec<usize>> = executable_brace_stack_at(bytes, iife_start) else {
        return false;
    };
    let mut search_end: usize = iife_start;
    while let Some(name_start) = source[..search_end].rfind(wrapper_name) {
        search_end = name_start;
        let name_end: usize = name_start + wrapper_name.len();
        if (name_start > 0 && is_ident_byte(bytes[name_start - 1]))
            || bytes
                .get(name_end)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
        {
            continue;
        }
        let Some(binding_scope): Option<Vec<usize>> = executable_brace_stack_at(bytes, name_start)
        else {
            continue;
        };
        if binding_scope != iife_scope {
            continue;
        }
        let mut keyword_end: usize = name_start;
        while keyword_end > 0 && matches!(bytes[keyword_end - 1], b' ' | b'\t' | b'\n' | b'\r') {
            keyword_end -= 1;
        }
        let Some(keyword_start): Option<usize> = keyword_end.checked_sub("const".len()) else {
            continue;
        };
        if source.get(keyword_start..keyword_end) != Some("const")
            || (keyword_start > 0 && is_ident_byte(bytes[keyword_start - 1]))
        {
            continue;
        }
        let Some(statement_end): Option<usize> = find_statement_end(bytes, keyword_start) else {
            continue;
        };
        if statement_end >= iife_start {
            continue;
        }
        let declaration: &str = &source[keyword_start..statement_end];
        if single_declarator_name(declaration) == Some(wrapper_name)
            && is_once_wrapper_shape(declaration)
        {
            return true;
        }
    }
    false
}

fn remove_integrity_invocation_iifes(
    source: &str,
    proven_wrapper_names: &[String],
) -> (String, usize) {
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(this,") {
        let call_open: usize = from + rel;
        from = call_open + "(this,".len();
        let Some((iife_start, iife_end)): Option<(usize, usize)> =
            enclosing_bare_iife(source, call_open)
        else {
            continue;
        };
        let body: &str = &source[iife_start..iife_end];
        if !is_protection_payload(body) {
            continue;
        }
        let Some((wrapper_name, ratchet_name)): Option<(String, String)> =
            generated_integrity_invocation_names(body)
        else {
            continue;
        };
        if has_global_property_mutation_or_escape(
            source,
            "RegExp",
            true,
            true,
            Some((iife_start, iife_end)),
            iife_start,
        ) {
            continue;
        }
        if !has_proven_ratchet_function(source, &ratchet_name) {
            continue;
        }
        let wrapper_was_removed: bool = proven_wrapper_names
            .iter()
            .any(|name: &String| name == &wrapper_name);
        if !wrapper_was_removed
            && !has_proven_const_once_wrapper_before(source, &wrapper_name, iife_start)
        {
            continue;
        }
        removals.push((iife_start, iife_end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    removals.sort_by_key(|r: &(usize, usize)| r.0);
    removals.dedup();
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

fn remove_ratchet_functions(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("function ") {
        let kw_start: usize = from + rel;
        from = kw_start + "function ".len();
        if (kw_start != 0 && is_ident_byte(bytes[kw_start - 1]))
            || has_async_function_prefix(source, bytes, kw_start)
        {
            continue;
        }
        let name_start: usize = kw_start + "function ".len();
        let mut name_end: usize = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            continue;
        }
        let paren_open: usize = skip_ws(bytes, name_end);
        if bytes.get(paren_open) != Some(&b'(') {
            continue;
        }
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let Some(outer_parameter_name): Option<&str> =
            simple_parameter_name(&source[paren_open + 1..paren_close])
        else {
            continue;
        };
        let brace_open: usize = skip_ws(bytes, paren_close + 1);
        if bytes.get(brace_open) != Some(&b'{') {
            continue;
        }
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        if !is_ratchet_dispatcher_shape(
            source,
            bytes,
            brace_open,
            brace_close,
            outer_parameter_name,
        ) {
            continue;
        }
        let mut end: usize = brace_close + 1;
        if bytes.get(end) == Some(&b';') {
            end += 1;
        }
        let outer_name: &str = &source[name_start..name_end];
        if identifier_referenced_outside(source, outer_name, kw_start, end) {
            continue;
        }
        removals.push((kw_start, end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

fn identifier_referenced_outside(
    source: &str,
    name: &str,
    excl_start: usize,
    excl_end: usize,
) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes: &[u8] = source.as_bytes();
    let mut search_from: usize = 0;
    while let Some(rel) = source[search_from..].find(name) {
        let match_start: usize = search_from + rel;
        let match_end: usize = match_start + name.len();
        search_from = match_end;
        if match_start >= excl_start && match_end <= excl_end {
            continue;
        }
        let before_is_boundary: bool = match_start == 0 || !is_ident_byte(bytes[match_start - 1]);
        let after_is_boundary: bool = match_end >= bytes.len() || !is_ident_byte(bytes[match_end]);
        if before_is_boundary && after_is_boundary {
            return true;
        }
    }
    false
}

fn remove_checker_blocks(source: &str) -> (String, Vec<String>) {
    let mut removals: Vec<CheckerRemoval> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("(this,") {
        let call_open: usize = from + rel;
        from = call_open + "(this,".len();
        let Some(removal): Option<CheckerRemoval> = locate_checker(source, call_open) else {
            continue;
        };
        removals.push(removal);
    }
    if removals.is_empty() {
        return (source.to_owned(), Vec::new());
    }
    removals.sort_by_key(|r: &CheckerRemoval| r.start);
    let mut out: String = String::with_capacity(source.len());
    let mut wrapper_names: Vec<String> = Vec::new();
    let mut cursor: usize = 0;
    for removal in &removals {
        if removal.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..removal.start]);
        cursor = removal.end;
        if let Some(w) = &removal.wrapper_name {
            wrapper_names.push(w.clone());
        }
    }
    out.push_str(&source[cursor..]);
    (out, wrapper_names)
}

struct CheckerRemoval {
    start: usize,
    end: usize,
    wrapper_name: Option<String>,
}

fn locate_checker(source: &str, call_open: usize) -> Option<CheckerRemoval> {
    let bytes: &[u8] = source.as_bytes();
    let wrapper_name: Option<String> = read_identifier_before(source, call_open);
    let wrapper_len: usize = wrapper_name.as_deref().map_or(0, str::len);
    let mut eq_cursor: usize = call_open.saturating_sub(wrapper_len);
    while eq_cursor > 0 && matches!(bytes[eq_cursor - 1], b' ' | b'\t') {
        eq_cursor -= 1;
    }
    if eq_cursor == 0 || bytes[eq_cursor - 1] != b'=' {
        return None;
    }
    let checker_name: String = read_identifier_before(source, eq_cursor - 1)?;
    let stmt_start: usize = backtrack_to_decl_start(bytes, eq_cursor - 1);
    if !is_decl_statement(&source[stmt_start..(stmt_start + 6).min(source.len())]) {
        return None;
    }
    let stmt_semi: usize = find_statement_end(bytes, stmt_start)?;
    if !is_protection_payload(&source[stmt_start..stmt_semi]) {
        return None;
    }
    let decl_terminator: usize = stmt_semi + 1;
    let end: usize =
        find_bare_invocation(bytes, stmt_semi, &checker_name).unwrap_or(decl_terminator);
    if any_declared_name_escapes(source, stmt_start, end) {
        return None;
    }
    Some(CheckerRemoval {
        start: stmt_start,
        end,
        wrapper_name,
    })
}

fn any_declared_name_escapes(source: &str, start: usize, end: usize) -> bool {
    declared_names_in_range(source, start, end)
        .iter()
        .any(|name: &String| identifier_referenced_outside(source, name, start, end))
}

fn declared_names_in_range(source: &str, start: usize, end: usize) -> Vec<String> {
    let bytes: &[u8] = source.as_bytes();
    let mut names: Vec<String> = Vec::new();
    let Some(kw_len): Option<usize> = ["const ", "let ", "var "]
        .iter()
        .find(|kw: &&&str| source[start..end.min(source.len())].starts_with(*kw))
        .map(|kw: &&str| kw.len())
    else {
        return names;
    };
    let mut cursor: usize = skip_ws(bytes, start + kw_len);
    loop {
        let name_start: usize = cursor;
        let mut name_end: usize = name_start;
        while name_end < end && name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            break;
        }
        names.push(source[name_start..name_end].to_owned());
        let after_name: usize = skip_ws(bytes, name_end);
        if bytes.get(after_name) != Some(&b'=') {
            break;
        }
        let Some(comma): Option<usize> = find_top_level_comma(bytes, after_name + 1, end) else {
            break;
        };
        cursor = skip_ws(bytes, comma + 1);
        if cursor >= end {
            break;
        }
    }
    names
}

fn find_top_level_comma(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut i: usize = start;
    let (mut paren, mut bracket, mut brace): (i32, i32, i32) = (0, 0, 0);
    while i < limit && i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn backtrack_to_decl_start(bytes: &[u8], pos: usize) -> usize {
    let mut i: usize = pos;
    let mut depth: i32 = 0;
    while i > 0 {
        i -= 1;
        let b: u8 = bytes[i];
        if depth <= 0 {
            if b == b';' || b == b'}' || b == b'{' {
                return skip_ws(bytes, i + 1);
            }
            if is_decl_keyword_at(bytes, i) {
                return i;
            }
        }
        match b {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => depth -= 1,
            _ => {}
        }
    }
    skip_ws(bytes, 0)
}

fn is_decl_keyword_at(bytes: &[u8], i: usize) -> bool {
    if i != 0 && is_ident_byte(bytes[i - 1]) {
        return false;
    }
    [b"const ".as_slice(), b"let ".as_slice(), b"var ".as_slice()]
        .iter()
        .any(|kw: &&[u8]| bytes[i..].starts_with(kw))
}

struct TopLevelStatement {
    start: usize,
    end: usize,
}

struct TopLevelStatements<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> TopLevelStatements<'a> {
    const fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            cursor: 0,
        }
    }
}

impl Iterator for TopLevelStatements<'_> {
    type Item = TopLevelStatement;

    fn next(&mut self) -> Option<Self::Item> {
        let start: usize = skip_ws(self.bytes, self.cursor);
        if start >= self.bytes.len() {
            self.cursor = start;
            return None;
        }
        let end: usize = match find_statement_end(self.bytes, start) {
            Some(semi) => semi,
            None => self.bytes.len(),
        };
        self.cursor = (end + 1).min(self.bytes.len());
        Some(TopLevelStatement { start, end })
    }
}

fn is_decl_statement(statement: &str) -> bool {
    let trimmed: &str = statement.trim_start();
    ["const", "let", "var"].iter().any(|kw: &&str| {
        trimmed
            .strip_prefix(*kw)
            .and_then(|rest: &str| rest.bytes().next())
            .is_some_and(|b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    })
}

fn read_identifier_before(statement: &str, call_pos: usize) -> Option<String> {
    let bytes: &[u8] = statement.as_bytes();
    let mut end: usize = call_pos;
    while end > 0 && !is_ident_byte(bytes[end - 1]) {
        end -= 1;
    }
    let mut start: usize = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    Some(statement[start..end].to_owned())
}

fn find_bare_invocation(bytes: &[u8], decl_end: usize, name: &str) -> Option<usize> {
    let after_semi: usize = if bytes.get(decl_end) == Some(&b';') {
        decl_end + 1
    } else {
        decl_end
    };
    let start: usize = skip_ws(bytes, after_semi);
    let name_bytes: &[u8] = name.as_bytes();
    if !bytes[start..].starts_with(name_bytes) {
        return None;
    }
    let boundary: usize = start + name_bytes.len();
    if bytes.get(boundary).is_some_and(|b: &u8| is_ident_byte(*b)) {
        return None;
    }
    let after_name: usize = skip_ws(bytes, boundary);
    if bytes.get(after_name) != Some(&b'(') {
        return None;
    }
    let close: usize = find_matching_paren(bytes, after_name)?;
    let end: usize = skip_ws(bytes, close + 1);
    if bytes.get(end) == Some(&b';') {
        return Some(end + 1);
    }
    Some(close + 1)
}

fn remove_once_wrappers(source: &str, wrapper_names: &[String]) -> (String, Vec<String>) {
    if wrapper_names.is_empty() {
        return (source.to_owned(), Vec::new());
    }
    let mut removals: Vec<(usize, usize, String)> = Vec::new();
    for name in wrapper_names {
        if let Some((start, end)) = locate_once_wrapper_decl(source, name) {
            removals.push((start, end, name.clone()));
        }
    }
    if removals.is_empty() {
        return (source.to_owned(), Vec::new());
    }
    removals.sort_by_key(|entry: &(usize, usize, String)| entry.0);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut proven_wrapper_names: Vec<String> = Vec::with_capacity(removals.len());
    for (start, end, name) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        proven_wrapper_names.push(name.clone());
    }
    out.push_str(&source[cursor..]);
    (out, proven_wrapper_names)
}

fn locate_once_wrapper_decl(source: &str, name: &str) -> Option<(usize, usize)> {
    for stmt in TopLevelStatements::new(source) {
        let body: &str = &source[stmt.start..stmt.end];
        if !is_decl_statement(body) {
            continue;
        }
        let Some(declared): Option<&str> = single_declarator_name(body) else {
            continue;
        };
        if declared != name {
            continue;
        }
        if !is_once_wrapper_shape(body) {
            continue;
        }
        let end: usize = if source.as_bytes().get(stmt.end) == Some(&b';') {
            stmt.end + 1
        } else {
            stmt.end
        };
        return Some((stmt.start, end));
    }
    None
}

fn single_declarator_name(statement: &str) -> Option<&str> {
    let trimmed: &str = statement.trim_start();
    let after_kw: &str = ["const", "let", "var"]
        .iter()
        .find_map(|kw: &&str| trimmed.strip_prefix(*kw))?
        .trim_start();
    let name_len: usize = after_kw
        .bytes()
        .take_while(|b: &u8| is_ident_byte(*b))
        .count();
    if name_len == 0 {
        return None;
    }
    let name: &str = &after_kw[..name_len];
    let rest: &str = after_kw[name_len..].trim_start();
    if !rest.starts_with('=') {
        return None;
    }
    Some(name)
}

fn plain_formal_parameter_name<'a>(
    parameter: &'a oxc_ast::ast::FormalParameter<'a>,
) -> Option<&'a str> {
    if !parameter.decorators.is_empty()
        || parameter.pattern.optional
        || parameter.pattern.type_annotation.is_some()
        || parameter.accessibility.is_some()
        || parameter.readonly
        || parameter.r#override
    {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
        &parameter.pattern.kind
    else {
        return None;
    };
    Some(identifier.name.as_str())
}

fn is_plain_anonymous_function(function: &Function<'_>, parameter_count: usize) -> bool {
    function.id.is_none()
        && !function.generator
        && !function.r#async
        && !function.declare
        && function.type_parameters.is_none()
        && function.this_param.is_none()
        && function.return_type.is_none()
        && function.params.rest.is_none()
        && function.params.items.len() == parameter_count
        && function
            .params
            .items
            .iter()
            .all(|parameter: &oxc_ast::ast::FormalParameter<'_>| {
                plain_formal_parameter_name(parameter).is_some()
            })
        && function.body.is_some()
}

fn single_named_initializer<'a>(
    declaration: &'a VariableDeclaration<'a>,
) -> Option<(&'a str, &'a Expression<'a>)> {
    if declaration.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = declaration.declarations.first()?;
    named_declarator_initializer(declarator)
}

fn named_declarator_initializer<'a>(
    declarator: &'a oxc_ast::ast::VariableDeclarator<'a>,
) -> Option<(&'a str, &'a Expression<'a>)> {
    if declarator.definite || declarator.id.optional || declarator.id.type_annotation.is_some() {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
        &declarator.id.kind
    else {
        return None;
    };
    let initializer: &Expression<'_> = declarator.init.as_ref()?;
    Some((identifier.name.as_str(), initializer))
}

fn expression_is_empty_array(expression: &Expression<'_>) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::ArrayExpression(array) if array.elements.is_empty()
    )
}

fn expression_is_boolean_state(expression: &Expression<'_>, expected: bool) -> bool {
    match expression.get_inner_expression() {
        Expression::BooleanLiteral(literal) => literal.value == expected,
        Expression::UnaryExpression(unary) if unary.operator.as_str() == "!" && !expected => {
            expression_is_empty_array(&unary.argument)
        }
        Expression::UnaryExpression(outer) if outer.operator.as_str() == "!" && expected => {
            let Expression::UnaryExpression(inner): &Expression<'_> =
                outer.argument.get_inner_expression()
            else {
                return false;
            };
            inner.operator.as_str() == "!" && expression_is_empty_array(&inner.argument)
        }
        _ => false,
    }
}

fn assignment_resets_identifier(expression: &Expression<'_>, name: &str, null_value: bool) -> bool {
    let Expression::AssignmentExpression(assignment): &Expression<'_> =
        expression.get_inner_expression()
    else {
        return false;
    };
    if assignment.operator.as_str() != "=" {
        return false;
    }
    let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier):
        &oxc_ast::ast::AssignmentTarget<'_> = &assignment.left
    else {
        return false;
    };
    if identifier.name != name {
        return false;
    }
    if null_value {
        matches!(
            assignment.right.get_inner_expression(),
            Expression::NullLiteral(_)
        )
    } else {
        expression_is_boolean_state(&assignment.right, false)
    }
}

fn return_resets_then_returns(
    statement: &Statement<'_>,
    reset_name: &str,
    returned_name: &str,
    null_value: bool,
) -> bool {
    let Some(argument): Option<&Expression<'_>> = return_argument(statement) else {
        return false;
    };
    let Expression::SequenceExpression(sequence): &Expression<'_> = argument.get_inner_expression()
    else {
        return false;
    };
    if sequence.expressions.len() != 2 {
        return false;
    }
    let Some(reset): Option<&Expression<'_>> = sequence.expressions.first() else {
        return false;
    };
    let Some(returned): Option<&Expression<'_>> = sequence.expressions.get(1) else {
        return false;
    };
    assignment_resets_identifier(reset, reset_name, null_value)
        && expression_is_identifier(returned, returned_name)
}

fn is_generated_deferred_checker(
    function: &Function<'_>,
    receiver_name: &str,
    checker_name: &str,
) -> bool {
    if !is_plain_anonymous_function(function, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Some(Statement::IfStatement(branch)): Option<&Statement<'_>> = body.statements.first()
    else {
        return false;
    };
    if branch.alternate.is_some() || !expression_is_identifier(&branch.test, checker_name) {
        return false;
    }
    let Statement::BlockStatement(consequent): &Statement<'_> = &branch.consequent else {
        return false;
    };
    checker_apply_reset_body(&consequent.body, receiver_name, checker_name)
}

fn checker_apply_reset_body(
    statements: &[Statement<'_>],
    receiver_name: &str,
    checker_name: &str,
) -> bool {
    if statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(result_declaration)): Option<&Statement<'_>> =
        statements.first()
    else {
        return false;
    };
    let Some((result_name, result_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(result_declaration)
    else {
        return false;
    };
    if matches!(result_name, "arguments" | "eval")
        || result_name == receiver_name
        || result_name == checker_name
    {
        return false;
    }
    let Expression::CallExpression(apply_call): &Expression<'_> =
        result_initializer.get_inner_expression()
    else {
        return false;
    };
    if apply_call.optional
        || apply_call.type_parameters.is_some()
        || apply_call.arguments.len() != 2
    {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = apply_call.callee.get_member_expr() else {
        return false;
    };
    if member.static_property_name() != Some("apply")
        || !expression_is_identifier(member.object(), checker_name)
    {
        return false;
    }
    let Some(receiver): Option<&Expression<'_>> = apply_call
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(arguments): Option<&Expression<'_>> = apply_call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(result_return): Option<&Statement<'_>> = statements.get(1) else {
        return false;
    };
    expression_is_identifier(receiver, receiver_name)
        && expression_is_identifier(arguments, "arguments")
        && return_resets_then_returns(result_return, checker_name, result_name, true)
}

fn is_empty_anonymous_function(function: &Function<'_>) -> bool {
    if !is_plain_anonymous_function(function, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    body.directives.is_empty() && body.statements.is_empty()
}

fn property_key_matches(key: &oxc_ast::ast::PropertyKey<'_>, expected: &str) -> bool {
    match key {
        oxc_ast::ast::PropertyKey::StaticIdentifier(identifier) => identifier.name == expected,
        oxc_ast::ast::PropertyKey::StringLiteral(literal) => literal.value == expected,
        _ => false,
    }
}

fn proxy_function_for_property<'a>(
    declaration: &'a VariableDeclaration<'a>,
    property_name: &str,
) -> Option<&'a Function<'a>> {
    let (_table_name, initializer): (&str, &Expression<'_>) =
        single_named_initializer(declaration)?;
    let Expression::ObjectExpression(object): &Expression<'_> = initializer.get_inner_expression()
    else {
        return None;
    };
    let mut found: Option<&Function<'_>> = None;
    for property_kind in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property): &ObjectPropertyKind<'_> = property_kind
        else {
            continue;
        };
        if !property_key_matches(&property.key, property_name) {
            continue;
        }
        if found.is_some()
            || property.kind != PropertyKind::Init
            || property.computed
            || property.method
            || property.shorthand
        {
            return None;
        }
        let Expression::FunctionExpression(function): &Expression<'_> =
            property.value.get_inner_expression()
        else {
            return None;
        };
        found = Some(function);
    }
    found
}

fn proxy_function_parameter_names<'a>(function: &'a Function<'a>) -> Option<(&'a str, &'a str)> {
    if !is_plain_anonymous_function(function, 2) {
        return None;
    }
    let first: &str = function
        .params
        .items
        .first()
        .and_then(plain_formal_parameter_name)?;
    let second: &str = function
        .params
        .items
        .get(1)
        .and_then(plain_formal_parameter_name)?;
    (first != second).then_some((first, second))
}

fn proxy_function_is_strict_equality(function: &Function<'_>) -> bool {
    let Some((first_name, second_name)): Option<(&str, &str)> =
        proxy_function_parameter_names(function)
    else {
        return false;
    };
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> = body.statements.first().and_then(return_argument)
    else {
        return false;
    };
    let Expression::BinaryExpression(binary): &Expression<'_> = argument.get_inner_expression()
    else {
        return false;
    };
    if binary.operator.as_str() != "===" {
        return false;
    }
    let forward: bool = expression_is_identifier(&binary.left, first_name)
        && expression_is_identifier(&binary.right, second_name);
    let reverse: bool = expression_is_identifier(&binary.left, second_name)
        && expression_is_identifier(&binary.right, first_name);
    forward || reverse
}

fn proxy_function_forwards_strict_equality(
    function: &Function<'_>,
    outer_declaration: &VariableDeclaration<'_>,
    outer_name: &str,
) -> bool {
    let Some((first_name, second_name)): Option<(&str, &str)> =
        proxy_function_parameter_names(function)
    else {
        return false;
    };
    if first_name == outer_name || second_name == outer_name {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> = body.statements.first().and_then(return_argument)
    else {
        return false;
    };
    let Expression::CallExpression(call): &Expression<'_> = argument.get_inner_expression() else {
        return false;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    if !expression_is_identifier(member.object(), outer_name) {
        return false;
    }
    let Some(property_name): Option<&str> = member.static_property_name() else {
        return false;
    };
    let Some(outer_function): Option<&Function<'_>> =
        proxy_function_for_property(outer_declaration, property_name)
    else {
        return false;
    };
    if !proxy_function_is_strict_equality(outer_function) {
        return false;
    }
    let Some(first_argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(second_argument): Option<&Expression<'_>> =
        call.arguments.get(1).and_then(Argument::as_expression)
    else {
        return false;
    };
    let forward: bool = expression_is_identifier(first_argument, first_name)
        && expression_is_identifier(second_argument, second_name);
    let reverse: bool = expression_is_identifier(first_argument, second_name)
        && expression_is_identifier(second_argument, first_name);
    forward || reverse
}

fn proxy_call_is_false_for_distinct_strings(
    expression: &Expression<'_>,
    declaration: &VariableDeclaration<'_>,
    table_name: &str,
    outer: Option<(&VariableDeclaration<'_>, &str)>,
) -> bool {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    if !expression_is_identifier(member.object(), table_name) {
        return false;
    }
    let Some(property_name): Option<&str> = member.static_property_name() else {
        return false;
    };
    let Some(function): Option<&Function<'_>> =
        proxy_function_for_property(declaration, property_name)
    else {
        return false;
    };
    let method_is_equality: bool = proxy_function_is_strict_equality(function)
        || outer.is_some_and(
            |(outer_declaration, outer_name): (&VariableDeclaration<'_>, &str)| {
                proxy_function_forwards_strict_equality(function, outer_declaration, outer_name)
            },
        );
    if !method_is_equality {
        return false;
    }
    let Some(first_argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(second_argument): Option<&Expression<'_>> =
        call.arguments.get(1).and_then(Argument::as_expression)
    else {
        return false;
    };
    let Expression::StringLiteral(first): &Expression<'_> = first_argument.get_inner_expression()
    else {
        return false;
    };
    let Expression::StringLiteral(second): &Expression<'_> = second_argument.get_inner_expression()
    else {
        return false;
    };
    first.value != second.value
}

fn is_regexp_initializer(expression: &Expression<'_>, pattern: &str, flags: Option<&str>) -> bool {
    let Expression::NewExpression(construction): &Expression<'_> =
        expression.get_inner_expression()
    else {
        return false;
    };
    if construction.type_parameters.is_some()
        || !expression_is_identifier(&construction.callee, "RegExp")
        || construction.arguments.len() != 1 + usize::from(flags.is_some())
    {
        return false;
    }
    let Some(pattern_argument): Option<&Expression<'_>> = construction
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return false;
    };
    if !expression_is_string(pattern_argument, pattern) {
        return false;
    }
    flags.is_none_or(|expected: &str| {
        construction
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(|argument: &Expression<'_>| expression_is_string(argument, expected))
    })
}

fn identifier_call_name<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::Identifier(identifier): &Expression<'_> = call.callee.get_inner_expression()
    else {
        return None;
    };
    Some(identifier.name.as_str())
}

fn ratchet_initializer_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return None;
    };
    if single_string_argument(call) != Some("init") {
        return None;
    }
    identifier_call_name(call)
}

fn is_identifier_call_with_string(
    expression: &Expression<'_>,
    callee_name: &str,
    argument: &str,
) -> bool {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    identifier_call_name(call) == Some(callee_name)
        && single_string_argument(call) == Some(argument)
}

fn is_zero_argument_identifier_call(expression: &Expression<'_>, callee_name: &str) -> bool {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    identifier_call_name(call) == Some(callee_name) && call.arguments.is_empty()
}

fn integrity_declaration_parts<'a>(
    declaration: &'a VariableDeclaration<'a>,
) -> Option<(&'a str, &'a str, &'a str, &'a str)> {
    if declaration.kind != oxc_ast::ast::VariableDeclarationKind::Const
        || declaration.declarations.len() != 3
    {
        return None;
    }
    let (first_name, first_initializer): (&str, &Expression<'_>) =
        named_declarator_initializer(declaration.declarations.first()?)?;
    let (second_name, second_initializer): (&str, &Expression<'_>) =
        named_declarator_initializer(declaration.declarations.get(1)?)?;
    let (probe_name, probe_initializer): (&str, &Expression<'_>) =
        named_declarator_initializer(declaration.declarations.get(2)?)?;
    let ratchet_name: &str = ratchet_initializer_name(probe_initializer)?;
    let names: [&str; 4] = [first_name, second_name, probe_name, ratchet_name];
    for (index, name) in names.iter().enumerate() {
        if matches!(*name, "arguments" | "eval" | "RegExp")
            || names[..index].iter().any(|prior: &&str| prior == name)
        {
            return None;
        }
    }
    if !is_regexp_initializer(first_initializer, INTEGRITY_FUNCTION_PATTERN, None)
        || !is_regexp_initializer(second_initializer, INTEGRITY_INCREMENT_PATTERN, Some("i"))
    {
        return None;
    }
    Some((first_name, second_name, probe_name, ratchet_name))
}

fn negated_regex_test_argument<'a>(
    expression: &'a Expression<'a>,
    regex_name: &str,
) -> Option<&'a Expression<'a>> {
    let Expression::UnaryExpression(negation): &Expression<'_> = expression.get_inner_expression()
    else {
        return None;
    };
    if negation.operator.as_str() != "!" {
        return None;
    }
    let Expression::CallExpression(call): &Expression<'_> =
        negation.argument.get_inner_expression()
    else {
        return None;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return None;
    }
    let member: &MemberExpression<'_> = call.callee.get_member_expr()?;
    if member.static_property_name() != Some("test")
        || !expression_is_identifier(member.object(), regex_name)
    {
        return None;
    }
    call.arguments.first()?.as_expression()
}

fn proxy_function_is_forward_binary(function: &Function<'_>, operator: &str) -> bool {
    let Some((first_name, second_name)): Option<(&str, &str)> =
        proxy_function_parameter_names(function)
    else {
        return false;
    };
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> = body.statements.first().and_then(return_argument)
    else {
        return false;
    };
    let Expression::BinaryExpression(binary): &Expression<'_> = argument.get_inner_expression()
    else {
        return false;
    };
    binary.operator.as_str() == operator
        && expression_is_identifier(&binary.left, first_name)
        && expression_is_identifier(&binary.right, second_name)
}

fn proxy_function_is_forward_addition(function: &Function<'_>) -> bool {
    proxy_function_is_forward_binary(function, "+")
}

fn proxy_function_is_forward_division(function: &Function<'_>) -> bool {
    proxy_function_is_forward_binary(function, "/")
}

fn probe_suffix_expression_is_generated(
    expression: &Expression<'_>,
    probe_name: &str,
    suffix: &str,
    proxy: Option<(&VariableDeclaration<'_>, &str)>,
) -> bool {
    let Some((proxy_declaration, proxy_name)): Option<(&VariableDeclaration<'_>, &str)> = proxy
    else {
        let Expression::BinaryExpression(concatenation): &Expression<'_> =
            expression.get_inner_expression()
        else {
            return false;
        };
        return concatenation.operator.as_str() == "+"
            && expression_is_identifier(&concatenation.left, probe_name)
            && expression_is_string(&concatenation.right, suffix);
    };
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    if !expression_is_identifier(member.object(), proxy_name) {
        return false;
    }
    let Some(property_name): Option<&str> = member.static_property_name() else {
        return false;
    };
    let Some(function): Option<&Function<'_>> =
        proxy_function_for_property(proxy_declaration, property_name)
    else {
        return false;
    };
    let Some(first_argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(second_argument): Option<&Expression<'_>> =
        call.arguments.get(1).and_then(Argument::as_expression)
    else {
        return false;
    };
    proxy_function_is_forward_addition(function)
        && expression_is_identifier(first_argument, probe_name)
        && expression_is_string(second_argument, suffix)
}

fn integrity_test_is_generated(
    expression: &Expression<'_>,
    first_regex_name: &str,
    second_regex_name: &str,
    probe_name: &str,
    proxy: Option<(&VariableDeclaration<'_>, &str)>,
) -> bool {
    let Expression::LogicalExpression(disjunction): &Expression<'_> =
        expression.get_inner_expression()
    else {
        return false;
    };
    if disjunction.operator.as_str() != "||" {
        return false;
    }
    let Some(first_argument): Option<&Expression<'_>> =
        negated_regex_test_argument(&disjunction.left, first_regex_name)
    else {
        return false;
    };
    let Some(second_argument): Option<&Expression<'_>> =
        negated_regex_test_argument(&disjunction.right, second_regex_name)
    else {
        return false;
    };
    probe_suffix_expression_is_generated(first_argument, probe_name, "chain", proxy)
        && probe_suffix_expression_is_generated(second_argument, probe_name, "input", proxy)
}

fn canonical_integrity_checker_ratchet_name<'a>(function: &'a Function<'a>) -> Option<&'a str> {
    if !is_plain_anonymous_function(function, 0) {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = function.body.as_deref()?;
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return None;
    }
    let Statement::VariableDeclaration(declaration): &Statement<'_> = body.statements.first()?
    else {
        return None;
    };
    let (first_regex_name, second_regex_name, probe_name, ratchet_name): (&str, &str, &str, &str) =
        integrity_declaration_parts(declaration)?;
    let expression: &Expression<'_> = body.statements.get(1).and_then(expression_statement)?;
    let Expression::ConditionalExpression(conditional): &Expression<'_> =
        expression.get_inner_expression()
    else {
        return None;
    };
    if !integrity_test_is_generated(
        &conditional.test,
        first_regex_name,
        second_regex_name,
        probe_name,
        None,
    ) || !is_identifier_call_with_string(&conditional.consequent, probe_name, "0")
        || !is_zero_argument_identifier_call(&conditional.alternate, ratchet_name)
    {
        return None;
    }
    Some(ratchet_name)
}

fn false_proxy_guard_alternate_expression<'a>(
    statement: &'a Statement<'a>,
    proxy_declaration: &VariableDeclaration<'_>,
    proxy_name: &str,
) -> Option<&'a Expression<'a>> {
    let Statement::BlockStatement(block): &Statement<'_> = statement else {
        return None;
    };
    if block.body.len() != 1 {
        return None;
    }
    let Statement::IfStatement(guard): &Statement<'_> = block.body.first()? else {
        return None;
    };
    if !proxy_call_is_false_for_distinct_strings(&guard.test, proxy_declaration, proxy_name, None) {
        return None;
    }
    let alternate: &Statement<'_> = guard.alternate.as_ref()?;
    if let Some(expression) = expression_statement(alternate) {
        return Some(expression);
    }
    let Statement::BlockStatement(block): &Statement<'_> = alternate else {
        return None;
    };
    if block.body.len() != 1 {
        return None;
    }
    block.body.first().and_then(expression_statement)
}

fn transformed_integrity_checker_ratchet_name<'a>(
    function: &'a Function<'a>,
    outer_declaration: &'a VariableDeclaration<'a>,
    outer_name: &str,
) -> Option<&'a str> {
    if !is_plain_anonymous_function(function, 0) {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = function.body.as_deref()?;
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return None;
    }
    let Statement::VariableDeclaration(inner_declaration): &Statement<'_> =
        body.statements.first()?
    else {
        return None;
    };
    let inner_name: &str = inert_proxy_declaration_name(inner_declaration)?;
    if inner_name == outer_name || matches!(inner_name, "arguments" | "eval" | "RegExp") {
        return None;
    }
    let Statement::IfStatement(outer_guard): &Statement<'_> = body.statements.get(1)? else {
        return None;
    };
    if !proxy_call_is_false_for_distinct_strings(
        &outer_guard.test,
        outer_declaration,
        outer_name,
        None,
    ) {
        return None;
    }
    let Statement::BlockStatement(outer_alternate): &Statement<'_> =
        outer_guard.alternate.as_ref()?
    else {
        return None;
    };
    if outer_alternate.body.len() != 2 {
        return None;
    }
    let Statement::VariableDeclaration(declaration): &Statement<'_> =
        outer_alternate.body.first()?
    else {
        return None;
    };
    let (first_regex_name, second_regex_name, probe_name, ratchet_name): (&str, &str, &str, &str) =
        integrity_declaration_parts(declaration)?;
    let Statement::IfStatement(integrity_guard): &Statement<'_> = outer_alternate.body.get(1)?
    else {
        return None;
    };
    if !integrity_test_is_generated(
        &integrity_guard.test,
        first_regex_name,
        second_regex_name,
        probe_name,
        Some((outer_declaration, outer_name)),
    ) {
        return None;
    }
    let failure: &Expression<'_> = false_proxy_guard_alternate_expression(
        &integrity_guard.consequent,
        outer_declaration,
        outer_name,
    )?;
    let success_statement: &Statement<'_> = integrity_guard.alternate.as_ref()?;
    let success: &Expression<'_> =
        false_proxy_guard_alternate_expression(success_statement, outer_declaration, outer_name)?;
    if !is_identifier_call_with_string(failure, probe_name, "0")
        || !is_zero_argument_identifier_call(success, ratchet_name)
    {
        return None;
    }
    Some(ratchet_name)
}

fn generated_integrity_checker_ratchet_name<'a>(
    function: &'a Function<'a>,
    proxy: Option<(&'a VariableDeclaration<'a>, &'a str)>,
) -> Option<&'a str> {
    let canonical: Option<&str> = canonical_integrity_checker_ratchet_name(function);
    if let Some(ratchet_name) = canonical {
        return Some(ratchet_name);
    }
    let (proxy_declaration, proxy_name): (&VariableDeclaration<'_>, &str) = proxy?;
    transformed_integrity_checker_ratchet_name(function, proxy_declaration, proxy_name)
}

fn is_generated_once_wrapper_function(function: &Function<'_>, flag_name: &str) -> bool {
    if !is_plain_anonymous_function(function, 2) {
        return false;
    }
    let Some(receiver_name): Option<&str> = function
        .params
        .items
        .first()
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    let Some(checker_name): Option<&str> = function
        .params
        .items
        .get(1)
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    if receiver_name == checker_name
        || flag_name == receiver_name
        || flag_name == checker_name
        || matches!(flag_name, "arguments" | "eval")
        || matches!(receiver_name, "arguments" | "eval")
        || matches!(checker_name, "arguments" | "eval")
    {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(selected_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some((selected_name, selected_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(selected_declaration)
    else {
        return false;
    };
    if selected_name == flag_name
        || selected_name == receiver_name
        || selected_name == checker_name
        || matches!(selected_name, "arguments" | "eval")
    {
        return false;
    }
    let Expression::ConditionalExpression(selection): &Expression<'_> =
        selected_initializer.get_inner_expression()
    else {
        return false;
    };
    if !expression_is_identifier(&selection.test, flag_name) {
        return false;
    }
    let Expression::FunctionExpression(deferred): &Expression<'_> =
        selection.consequent.get_inner_expression()
    else {
        return false;
    };
    let Expression::FunctionExpression(empty): &Expression<'_> =
        selection.alternate.get_inner_expression()
    else {
        return false;
    };
    let Some(result_return): Option<&Statement<'_>> = body.statements.get(1) else {
        return false;
    };
    is_generated_deferred_checker(deferred, receiver_name, checker_name)
        && is_empty_anonymous_function(empty)
        && return_resets_then_returns(result_return, flag_name, selected_name, false)
}

fn is_transformed_deferred_checker(
    function: &Function<'_>,
    receiver_name: &str,
    checker_name: &str,
    proxy_declaration: &VariableDeclaration<'_>,
    proxy_name: &str,
    outer_declaration: &VariableDeclaration<'_>,
    outer_name: &str,
) -> bool {
    if !is_plain_anonymous_function(function, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Some(Statement::IfStatement(first_guard)): Option<&Statement<'_>> = body.statements.first()
    else {
        return false;
    };
    if !proxy_call_is_false_for_distinct_strings(
        &first_guard.test,
        proxy_declaration,
        proxy_name,
        Some((outer_declaration, outer_name)),
    ) {
        return false;
    }
    let Some(Statement::BlockStatement(first_alternate)): Option<&Statement<'_>> =
        first_guard.alternate.as_ref()
    else {
        return false;
    };
    if first_alternate.body.len() != 1 {
        return false;
    }
    let Some(Statement::IfStatement(checker_guard)): Option<&Statement<'_>> =
        first_alternate.body.first()
    else {
        return false;
    };
    if checker_guard.alternate.is_some()
        || !expression_is_identifier(&checker_guard.test, checker_name)
    {
        return false;
    }
    let Statement::BlockStatement(checker_consequent): &Statement<'_> = &checker_guard.consequent
    else {
        return false;
    };
    if checker_consequent.body.len() != 1 {
        return false;
    }
    let Some(Statement::IfStatement(second_guard)): Option<&Statement<'_>> =
        checker_consequent.body.first()
    else {
        return false;
    };
    if !proxy_call_is_false_for_distinct_strings(
        &second_guard.test,
        proxy_declaration,
        proxy_name,
        Some((outer_declaration, outer_name)),
    ) {
        return false;
    }
    let Some(Statement::BlockStatement(second_alternate)): Option<&Statement<'_>> =
        second_guard.alternate.as_ref()
    else {
        return false;
    };
    checker_apply_reset_body(&second_alternate.body, receiver_name, checker_name)
}

fn is_transformed_once_wrapper_function(
    function: &Function<'_>,
    flag_name: &str,
    outer_declaration: &VariableDeclaration<'_>,
    outer_name: &str,
) -> bool {
    if !is_plain_anonymous_function(function, 2) {
        return false;
    }
    let Some(receiver_name): Option<&str> = function
        .params
        .items
        .first()
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    let Some(checker_name): Option<&str> = function
        .params
        .items
        .get(1)
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    if receiver_name == checker_name
        || flag_name == receiver_name
        || flag_name == checker_name
        || outer_name == receiver_name
        || outer_name == checker_name
        || matches!(flag_name, "arguments" | "eval")
        || matches!(outer_name, "arguments" | "eval")
        || matches!(receiver_name, "arguments" | "eval")
        || matches!(checker_name, "arguments" | "eval")
    {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(proxy_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some(proxy_name): Option<&str> = inert_proxy_declaration_name(proxy_declaration) else {
        return false;
    };
    if proxy_name == flag_name
        || proxy_name == outer_name
        || proxy_name == receiver_name
        || proxy_name == checker_name
        || matches!(proxy_name, "arguments" | "eval")
    {
        return false;
    }
    let Some(Statement::IfStatement(outer_guard)): Option<&Statement<'_>> = body.statements.get(1)
    else {
        return false;
    };
    if !proxy_call_is_false_for_distinct_strings(
        &outer_guard.test,
        outer_declaration,
        outer_name,
        None,
    ) {
        return false;
    }
    let Some(Statement::BlockStatement(alternate)): Option<&Statement<'_>> =
        outer_guard.alternate.as_ref()
    else {
        return false;
    };
    if alternate.body.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(selected_declaration)): Option<&Statement<'_>> =
        alternate.body.first()
    else {
        return false;
    };
    let Some((selected_name, selected_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(selected_declaration)
    else {
        return false;
    };
    if selected_name == flag_name
        || selected_name == outer_name
        || selected_name == proxy_name
        || selected_name == receiver_name
        || selected_name == checker_name
        || matches!(selected_name, "arguments" | "eval")
    {
        return false;
    }
    let Expression::ConditionalExpression(selection): &Expression<'_> =
        selected_initializer.get_inner_expression()
    else {
        return false;
    };
    if !expression_is_identifier(&selection.test, flag_name) {
        return false;
    }
    let Expression::FunctionExpression(deferred): &Expression<'_> =
        selection.consequent.get_inner_expression()
    else {
        return false;
    };
    let Expression::FunctionExpression(empty): &Expression<'_> =
        selection.alternate.get_inner_expression()
    else {
        return false;
    };
    let Some(result_return): Option<&Statement<'_>> = alternate.body.get(1) else {
        return false;
    };
    is_transformed_deferred_checker(
        deferred,
        receiver_name,
        checker_name,
        proxy_declaration,
        proxy_name,
        outer_declaration,
        outer_name,
    ) && is_empty_anonymous_function(empty)
        && return_resets_then_returns(result_return, flag_name, selected_name, false)
}

fn is_transformed_once_wrapper_shape(region: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, region, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return false;
    }
    let Some(Statement::VariableDeclaration(declaration)): Option<&Statement<'_>> =
        parsed.program.body.first()
    else {
        return false;
    };
    let Some((_wrapper_name, initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(declaration)
    else {
        return false;
    };
    let Expression::CallExpression(iife_call): &Expression<'_> = initializer.get_inner_expression()
    else {
        return false;
    };
    if iife_call.optional || iife_call.type_parameters.is_some() || !iife_call.arguments.is_empty()
    {
        return false;
    }
    let Expression::FunctionExpression(iife): &Expression<'_> =
        iife_call.callee.get_inner_expression()
    else {
        return false;
    };
    if !is_plain_anonymous_function(iife, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = iife.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 3 {
        return false;
    }
    let Some(Statement::VariableDeclaration(outer_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some(outer_name): Option<&str> = inert_proxy_declaration_name(outer_declaration) else {
        return false;
    };
    let Some(Statement::VariableDeclaration(flag_declaration)): Option<&Statement<'_>> =
        body.statements.get(1)
    else {
        return false;
    };
    let Some((flag_name, flag_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(flag_declaration)
    else {
        return false;
    };
    if flag_name == outer_name
        || matches!(flag_name, "arguments" | "eval")
        || matches!(outer_name, "arguments" | "eval")
        || !expression_is_boolean_state(flag_initializer, true)
    {
        return false;
    }
    let Some(wrapper): Option<&Expression<'_>> = body.statements.get(2).and_then(return_argument)
    else {
        return false;
    };
    let Expression::FunctionExpression(wrapper_function): &Expression<'_> =
        wrapper.get_inner_expression()
    else {
        return false;
    };
    is_transformed_once_wrapper_function(wrapper_function, flag_name, outer_declaration, outer_name)
}

fn is_canonical_once_wrapper_shape(region: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, region, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return false;
    }
    let Some(Statement::VariableDeclaration(declaration)): Option<&Statement<'_>> =
        parsed.program.body.first()
    else {
        return false;
    };
    let Some((_wrapper_name, initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(declaration)
    else {
        return false;
    };
    let Expression::CallExpression(iife_call): &Expression<'_> = initializer.get_inner_expression()
    else {
        return false;
    };
    if iife_call.optional || iife_call.type_parameters.is_some() || !iife_call.arguments.is_empty()
    {
        return false;
    }
    let Expression::FunctionExpression(iife): &Expression<'_> =
        iife_call.callee.get_inner_expression()
    else {
        return false;
    };
    if !is_plain_anonymous_function(iife, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = iife.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(flag_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some((flag_name, flag_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(flag_declaration)
    else {
        return false;
    };
    if !expression_is_boolean_state(flag_initializer, true) {
        return false;
    }
    let Some(wrapper): Option<&Expression<'_>> = body.statements.get(1).and_then(return_argument)
    else {
        return false;
    };
    let Expression::FunctionExpression(wrapper_function): &Expression<'_> =
        wrapper.get_inner_expression()
    else {
        return false;
    };
    is_generated_once_wrapper_function(wrapper_function, flag_name)
}

fn is_once_wrapper_shape(region: &str) -> bool {
    is_canonical_once_wrapper_shape(region) || is_transformed_once_wrapper_shape(region)
}

fn is_false_same_string_inequality(expression: &Expression<'_>) -> bool {
    let Expression::BinaryExpression(binary): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    let Expression::StringLiteral(left): &Expression<'_> = binary.left.get_inner_expression()
    else {
        return false;
    };
    let Expression::StringLiteral(right): &Expression<'_> = binary.right.get_inner_expression()
    else {
        return false;
    };
    binary.operator.as_str() == "!==" && left.value == right.value
}

fn is_immediately_inert_hybrid_wrapper_function(function: &Function<'_>, flag_name: &str) -> bool {
    if !is_plain_anonymous_function(function, 2) {
        return false;
    }
    let Some(receiver_name): Option<&str> = function
        .params
        .items
        .first()
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    let Some(checker_name): Option<&str> = function
        .params
        .items
        .get(1)
        .and_then(plain_formal_parameter_name)
    else {
        return false;
    };
    if receiver_name == checker_name
        || flag_name == receiver_name
        || flag_name == checker_name
        || matches!(flag_name, "arguments" | "eval")
        || matches!(receiver_name, "arguments" | "eval")
        || matches!(checker_name, "arguments" | "eval")
    {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = function.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(proxy_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some(proxy_name): Option<&str> = inert_proxy_declaration_name(proxy_declaration) else {
        return false;
    };
    if proxy_name == flag_name
        || proxy_name == receiver_name
        || proxy_name == checker_name
        || matches!(proxy_name, "arguments" | "eval")
    {
        return false;
    }
    let Some(Statement::IfStatement(guard)): Option<&Statement<'_>> = body.statements.get(1) else {
        return false;
    };
    if !is_false_same_string_inequality(&guard.test) {
        return false;
    }
    let Some(Statement::BlockStatement(alternate)): Option<&Statement<'_>> =
        guard.alternate.as_ref()
    else {
        return false;
    };
    if alternate.body.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(selected_declaration)): Option<&Statement<'_>> =
        alternate.body.first()
    else {
        return false;
    };
    let Some((selected_name, selected_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(selected_declaration)
    else {
        return false;
    };
    if selected_name == flag_name
        || selected_name == proxy_name
        || selected_name == receiver_name
        || selected_name == checker_name
        || matches!(selected_name, "arguments" | "eval")
    {
        return false;
    }
    let Expression::ConditionalExpression(selection): &Expression<'_> =
        selected_initializer.get_inner_expression()
    else {
        return false;
    };
    let Some(result_return): Option<&Statement<'_>> = alternate.body.get(1) else {
        return false;
    };
    expression_is_identifier(&selection.test, flag_name)
        && is_ordinary_anonymous_function(&selection.consequent)
        && is_ordinary_anonymous_function(&selection.alternate)
        && return_resets_then_returns(result_return, flag_name, selected_name, false)
}

fn is_immediately_inert_hybrid_once_wrapper_shape(region: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, region, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.program.body.len() != 1 {
        return false;
    }
    let Some(Statement::VariableDeclaration(declaration)): Option<&Statement<'_>> =
        parsed.program.body.first()
    else {
        return false;
    };
    let Some((_wrapper_name, initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(declaration)
    else {
        return false;
    };
    let Expression::CallExpression(iife_call): &Expression<'_> = initializer.get_inner_expression()
    else {
        return false;
    };
    if iife_call.optional || iife_call.type_parameters.is_some() || !iife_call.arguments.is_empty()
    {
        return false;
    }
    let Expression::FunctionExpression(iife): &Expression<'_> =
        iife_call.callee.get_inner_expression()
    else {
        return false;
    };
    if !is_plain_anonymous_function(iife, 0) {
        return false;
    }
    let Some(body): Option<&oxc_ast::ast::FunctionBody<'_>> = iife.body.as_deref() else {
        return false;
    };
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return false;
    }
    let Some(Statement::VariableDeclaration(flag_declaration)): Option<&Statement<'_>> =
        body.statements.first()
    else {
        return false;
    };
    let Some((flag_name, flag_initializer)): Option<(&str, &Expression<'_>)> =
        single_named_initializer(flag_declaration)
    else {
        return false;
    };
    if matches!(flag_name, "arguments" | "eval")
        || !expression_is_boolean_state(flag_initializer, true)
    {
        return false;
    }
    let Some(wrapper): Option<&Expression<'_>> = body.statements.get(1).and_then(return_argument)
    else {
        return false;
    };
    let Expression::FunctionExpression(wrapper_function): &Expression<'_> =
        wrapper.get_inner_expression()
    else {
        return false;
    };
    is_immediately_inert_hybrid_wrapper_function(wrapper_function, flag_name)
}

fn fixed_delay_interval_callback<'a>(
    source: &'a str,
    bytes: &[u8],
    open: usize,
    close: usize,
) -> Option<(&'a str, usize)> {
    let first_comma: usize = find_top_level_comma(bytes, open + 1, close)?;
    if find_top_level_comma(bytes, first_comma + 1, close).is_some() {
        return None;
    }
    let delay: &str = source[first_comma + 1..close].trim();
    if delay != "4000" {
        return None;
    }
    Some((&source[open + 1..first_comma], first_comma))
}

fn is_pure_inline_debugger_callback(source: &str) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let start: usize = skip_ws(bytes, 0);
    if !source[start..].starts_with("function") {
        return false;
    }
    let mut cursor: usize = start + "function".len();
    if bytes
        .get(cursor)
        .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return false;
    }
    cursor = skip_ws(bytes, cursor);
    if bytes.get(cursor) == Some(&b'*') {
        return false;
    }
    while bytes
        .get(cursor)
        .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        cursor += 1;
    }
    cursor = skip_ws(bytes, cursor);
    if bytes.get(cursor) != Some(&b'(') {
        return false;
    }
    let Some(paren_close): Option<usize> = find_paren_close(bytes, cursor + 1) else {
        return false;
    };
    if !source[cursor + 1..paren_close].trim().is_empty() {
        return false;
    }
    let brace_open: usize = skip_ws(bytes, paren_close + 1);
    if bytes.get(brace_open) != Some(&b'{') {
        return false;
    }
    let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
        return false;
    };
    let body: &str = source[brace_open + 1..brace_close].trim();
    matches!(body, "debugger" | "debugger;") && skip_ws(bytes, brace_close + 1) == bytes.len()
}

fn contains_executable_identifier_escape(source: &str, bytes: &[u8]) -> bool {
    let mut from: usize = 0;
    while let Some(relative) = source[from..].find("\\u") {
        let escape_start: usize = from + relative;
        from = escape_start + "\\u".len();
        if is_executable_code_position(bytes, escape_start) {
            return true;
        }
    }
    false
}

fn remove_debug_ratchets(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    if contains_executable_identifier_escape(source, bytes)
        || unqualified_code_identifier_count(source, bytes, "with", 0, source.len()) != 0
    {
        return (source.to_owned(), 0);
    }
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = source[from..].find("setInterval") {
        let pos: usize = from + rel;
        from = pos + "setInterval".len();
        if !is_executable_code_position(bytes, pos) {
            continue;
        }
        let open: usize = skip_ws(bytes, pos + "setInterval".len());
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let Some(arg): Option<usize> = find_matching_paren(bytes, open) else {
            continue;
        };
        let Some((callback_source, callback_end)): Option<(&str, usize)> =
            fixed_delay_interval_callback(source, bytes, open, arg)
        else {
            continue;
        };
        let removal_start: Option<usize> = global_resolver_interval_call_start(source, pos)
            .or_else(|| known_global_interval_call_start(source, bytes, pos));
        let Some(removal_start): Option<usize> = removal_start else {
            continue;
        };
        let Some(removal_end): Option<usize> =
            standalone_interval_statement_end(bytes, removal_start, arg)
        else {
            continue;
        };
        if mentions_executable_debugger(callback_source) {
            if !is_pure_inline_debugger_callback(callback_source) {
                continue;
            }
            removals.push((removal_start, removal_end));
            continue;
        }
        let Some((callback_start, callback)): Option<(usize, &str)> =
            interval_callback_name(source, bytes, open, callback_end)
        else {
            continue;
        };
        if unqualified_code_identifier_count(source, bytes, callback, 0, source.len()) != 2
            || !is_named_ratchet_function(source, callback, callback_start)
        {
            continue;
        }
        removals.push((removal_start, removal_end));
    }
    if removals.is_empty() {
        return (source.to_owned(), 0);
    }
    removals.sort_by_key(|range: &(usize, usize)| range.0);
    removals.dedup();
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    for (start, end) in &removals {
        if *start < cursor {
            continue;
        }
        out.push_str(&source[cursor..*start]);
        cursor = *end;
        count += 1;
    }
    out.push_str(&source[cursor..]);
    (out, count)
}

fn is_executable_code_position(bytes: &[u8], position: usize) -> bool {
    executable_brace_stack_at(bytes, position).is_some()
}

fn executable_brace_depth_at(bytes: &[u8], position: usize) -> Option<usize> {
    executable_brace_stack_at(bytes, position).map(|stack: Vec<usize>| stack.len())
}

fn executable_enclosing_brace_start(bytes: &[u8], position: usize) -> Option<usize> {
    executable_brace_stack_at(bytes, position)?.last().copied()
}

fn executable_brace_stack_at(bytes: &[u8], position: usize) -> Option<Vec<usize>> {
    executable_delimiter_state_at(bytes, position)
        .map(|(braces, _, _): (Vec<usize>, usize, usize)| braces)
}

fn executable_group_depth_at(bytes: &[u8], position: usize) -> Option<usize> {
    executable_delimiter_state_at(bytes, position)
        .map(|(_, parentheses, brackets): (Vec<usize>, usize, usize)| parentheses + brackets)
}

fn control_condition_keyword_before(bytes: &[u8], open: usize) -> bool {
    let mut end: usize = open;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut begin: usize = end;
    while begin > 0 && is_ident_byte(bytes[begin - 1]) {
        begin -= 1;
    }
    if begin > 0 && matches!(bytes[begin - 1], b'.' | b'?' | b'#') {
        return false;
    }
    matches!(&bytes[begin..end], b"for" | b"if" | b"while" | b"with")
}

fn executable_delimiter_state_at(
    bytes: &[u8],
    position: usize,
) -> Option<(Vec<usize>, usize, usize)> {
    let mut cursor: usize = 0;
    let mut previous: Option<u8> = None;
    let mut brace_stack: Vec<usize> = Vec::with_capacity(8);
    let mut paren_stack: Vec<bool> = Vec::with_capacity(8);
    let mut bracket_depth: usize = 0;
    let mut closed_control_condition: bool = false;
    while cursor < position {
        match bytes[cursor] {
            quote @ (b'\'' | b'"' | b'`') => {
                let end: usize = skip_string(bytes, cursor, quote)?;
                if end > position {
                    return None;
                }
                cursor = end;
                previous = Some(quote);
                closed_control_condition = false;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                let mut end: usize = cursor + 2;
                while end < bytes.len() && bytes[end] != b'\n' {
                    end += 1;
                }
                if end > position {
                    return None;
                }
                cursor = end;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                let mut end: usize = cursor + 2;
                while end + 1 < bytes.len() && !(bytes[end] == b'*' && bytes[end + 1] == b'/') {
                    end += 1;
                }
                if end + 1 >= bytes.len() {
                    return None;
                }
                end += 2;
                if end > position {
                    return None;
                }
                cursor = end;
            }
            b'/' if (closed_control_condition
                || previous.is_none_or(regex_can_follow)
                || regex_literal_can_start_after_keyword(bytes, cursor))
                && bytes.get(cursor + 1) != Some(&b'=') =>
            {
                let end: usize = skip_regex_literal(bytes, cursor);
                if end > position {
                    return None;
                }
                cursor = end;
                previous = Some(b'/');
                closed_control_condition = false;
            }
            b'{' => {
                brace_stack.push(cursor);
                previous = Some(b'{');
                closed_control_condition = false;
                cursor += 1;
            }
            b'}' => {
                brace_stack.pop()?;
                previous = Some(b'}');
                closed_control_condition = false;
                cursor += 1;
            }
            b'(' => {
                let control_condition: bool = control_condition_keyword_before(bytes, cursor);
                paren_stack.push(control_condition);
                previous = Some(b'(');
                closed_control_condition = false;
                cursor += 1;
            }
            b')' => {
                closed_control_condition = paren_stack.pop()?;
                previous = Some(b')');
                cursor += 1;
            }
            b'[' => {
                bracket_depth += 1;
                previous = Some(b'[');
                closed_control_condition = false;
                cursor += 1;
            }
            b']' => {
                bracket_depth = bracket_depth.checked_sub(1)?;
                previous = Some(b']');
                closed_control_condition = false;
                cursor += 1;
            }
            byte if byte.is_ascii_whitespace() => {
                cursor += 1;
            }
            byte => {
                previous = Some(byte);
                closed_control_condition = false;
                cursor += 1;
            }
        }
    }
    (cursor == position).then_some((brace_stack, paren_stack.len(), bracket_depth))
}

fn regex_literal_can_start_after_keyword(bytes: &[u8], start: usize) -> bool {
    let mut end: usize = start;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut begin: usize = end;
    while begin > 0 && is_ident_byte(bytes[begin - 1]) {
        begin -= 1;
    }
    if begin > 0 && matches!(bytes[begin - 1], b'.' | b'?' | b'#') {
        return false;
    }
    let token: &[u8] = &bytes[begin..end];
    token == b"await"
        || token == b"case"
        || token == b"default"
        || token == b"delete"
        || token == b"do"
        || token == b"else"
        || token == b"extends"
        || token == b"in"
        || token == b"instanceof"
        || token == b"new"
        || token == b"of"
        || token == b"return"
        || token == b"throw"
        || token == b"typeof"
        || token == b"void"
        || token == b"yield"
}

fn unqualified_code_identifier_count(
    source: &str,
    bytes: &[u8],
    name: &str,
    search_start: usize,
    search_end: usize,
) -> usize {
    let mut cursor: usize = search_start;
    let mut count: usize = 0;
    while cursor < search_end {
        let Some(relative): Option<usize> = source[cursor..search_end].find(name) else {
            break;
        };
        let name_start: usize = cursor + relative;
        let name_end: usize = name_start + name.len();
        cursor = name_end;
        if (name_start > 0
            && (is_ident_byte(bytes[name_start - 1])
                || matches!(bytes[name_start - 1], b'.' | b'?' | b'#')))
            || bytes
                .get(name_end)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
            || !is_executable_code_position(bytes, name_start)
        {
            continue;
        }
        count += 1;
    }
    count
}

fn interval_callback_name<'a>(
    source: &'a str,
    bytes: &[u8],
    open: usize,
    close: usize,
) -> Option<(usize, &'a str)> {
    let start: usize = skip_ws(bytes, open + 1);
    let mut end: usize = start;
    while end < close && is_ident_byte(bytes[end]) {
        end += 1;
    }
    if end == start {
        return None;
    }
    let comma: usize = skip_ws(bytes, end);
    if bytes.get(comma) != Some(&b',') {
        return None;
    }
    Some((start, &source[start..end]))
}

fn is_simple_ascii_identifier(identifier: &str) -> bool {
    let bytes: &[u8] = identifier.as_bytes();
    let Some(first): Option<&u8> = bytes.first() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(*first, b'_' | b'$'))
        && bytes.iter().copied().all(is_ident_byte)
}

fn has_async_function_prefix(source: &str, bytes: &[u8], function_start: usize) -> bool {
    let mut token_end: usize = function_start;
    while token_end > 0 && bytes[token_end - 1].is_ascii_whitespace() {
        token_end -= 1;
    }
    let mut token_start: usize = token_end;
    while token_start > 0 && is_ident_byte(bytes[token_start - 1]) {
        token_start -= 1;
    }
    source[token_start..token_end] == *"async"
        && (token_start == 0 || !is_ident_byte(bytes[token_start - 1]))
}

fn simple_parameter_name(parameters: &str) -> Option<&str> {
    let trimmed: &str = parameters.trim();
    (!trimmed.is_empty() && !trimmed.contains(',') && is_simple_ascii_identifier(trimmed))
        .then_some(trimmed)
}

fn is_named_ratchet_function(source: &str, name: &str, callback_start: usize) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let Some(callback_scope): Option<Vec<usize>> = executable_brace_stack_at(bytes, callback_start)
    else {
        return false;
    };
    let needle: String = format!("function {name}");
    let mut from: usize = 0;
    while let Some(relative) = source[from..].find(&needle) {
        let function_start: usize = from + relative;
        from = function_start + needle.len();
        let Some(function_scope): Option<Vec<usize>> =
            executable_brace_stack_at(bytes, function_start)
        else {
            continue;
        };
        if !callback_scope.starts_with(&function_scope)
            || (function_start != 0 && is_ident_byte(bytes[function_start - 1]))
            || has_async_function_prefix(source, bytes, function_start)
        {
            continue;
        }
        let paren_open: usize = skip_ws(bytes, function_start + needle.len());
        if bytes.get(paren_open) != Some(&b'(') {
            continue;
        }
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let Some(outer_parameter_name): Option<&str> =
            simple_parameter_name(&source[paren_open + 1..paren_close])
        else {
            continue;
        };
        let brace_open: usize = skip_ws(bytes, paren_close + 1);
        if bytes.get(brace_open) != Some(&b'{') {
            continue;
        }
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        if is_ratchet_dispatcher_shape(source, bytes, brace_open, brace_close, outer_parameter_name)
        {
            return true;
        }
    }
    false
}

fn global_resolver_interval_call_start(source: &str, pos: usize) -> Option<usize> {
    if has_global_timer_mutation_or_escape(source, pos) {
        return None;
    }
    let container: (usize, usize) = enclosing_bare_iife(source, pos)?;
    let bytes: &[u8] = source.as_bytes();
    let scope_depth: usize = executable_brace_depth_at(bytes, pos)?;
    let scope_start: usize = executable_enclosing_brace_start(bytes, pos)?.checked_add(1)?;
    if scope_start < container.0 {
        return None;
    }
    let (receiver_start, receiver): (usize, &str) = interval_receiver(source, bytes, pos)?;
    if source.match_indices("Function").count() != 1 || source.match_indices("window").count() != 1
    {
        return None;
    }
    let (binding_start, resolver): (usize, &str) = assigned_zero_arg_call_before(
        source,
        bytes,
        receiver,
        scope_start,
        receiver_start,
        scope_depth,
    )?;
    if !assigned_global_resolver_function_before(
        source,
        bytes,
        resolver,
        scope_start,
        binding_start,
        scope_depth,
    ) {
        return None;
    }
    Some(receiver_start)
}

fn has_simple_declaration_prefix(
    source: &str,
    bytes: &[u8],
    name_start: usize,
    scope_start: usize,
) -> bool {
    let mut keyword_end: usize = name_start;
    while keyword_end > scope_start && bytes[keyword_end - 1].is_ascii_whitespace() {
        keyword_end -= 1;
    }
    let mut keyword_start: usize = keyword_end;
    while keyword_start > scope_start && is_ident_byte(bytes[keyword_start - 1]) {
        keyword_start -= 1;
    }
    if !matches!(
        source.get(keyword_start..keyword_end),
        Some("const" | "let" | "var")
    ) {
        return false;
    }
    let mut statement_start: usize = keyword_start;
    while statement_start > scope_start && bytes[statement_start - 1].is_ascii_whitespace() {
        statement_start -= 1;
    }
    statement_start == scope_start
        || matches!(bytes.get(statement_start - 1), Some(b';' | b'{' | b'}'))
}

fn assigned_zero_arg_call_before<'a>(
    source: &'a str,
    bytes: &[u8],
    name: &str,
    search_start: usize,
    search_end: usize,
    scope_depth: usize,
) -> Option<(usize, &'a str)> {
    let mut cursor: usize = search_start;
    let mut found: Option<(usize, &'a str)> = None;
    while cursor < search_end {
        let Some(relative): Option<usize> = source[cursor..search_end].find(name) else {
            break;
        };
        let name_start: usize = cursor + relative;
        cursor = name_start + name.len();
        if (name_start > 0
            && (is_ident_byte(bytes[name_start - 1])
                || matches!(bytes[name_start - 1], b'.' | b'?' | b'#')))
            || bytes
                .get(cursor)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
        {
            continue;
        }
        let Some(name_depth): Option<usize> = executable_brace_depth_at(bytes, name_start) else {
            continue;
        };
        if name_depth < scope_depth {
            continue;
        }
        if name_depth > scope_depth {
            found = None;
            continue;
        }
        found = None;
        if !has_simple_declaration_prefix(source, bytes, name_start, search_start) {
            continue;
        }
        let equals: usize = skip_ws(bytes, cursor);
        if bytes.get(equals) != Some(&b'=') || matches!(bytes.get(equals + 1), Some(b'=' | b'>')) {
            continue;
        }
        let initializer_start: usize = skip_ws(bytes, equals + 1);
        let statement_end: usize =
            find_statement_end(bytes, initializer_start).unwrap_or(search_end);
        let initializer_end: usize = find_top_level_comma(bytes, initializer_start, statement_end)
            .unwrap_or(statement_end)
            .min(search_end);
        let initializer: &str = source[initializer_start..initializer_end].trim();
        let Some(callee): Option<&str> = simple_zero_arg_callee(initializer) else {
            continue;
        };
        found = Some((name_start, callee));
    }
    found
}

fn simple_zero_arg_callee(initializer: &str) -> Option<&str> {
    let trimmed: &str = initializer.trim();
    let without_close: &str = trimmed.strip_suffix(')')?.trim_end();
    let open: usize = without_close.rfind('(')?;
    if !without_close[open + 1..].trim().is_empty() {
        return None;
    }
    let callee: &str = without_close[..open].trim();
    if callee.is_empty() || !callee.bytes().all(is_ident_byte) {
        return None;
    }
    Some(callee)
}

fn returned_identifier<'a>(
    source: &'a str,
    bytes: &[u8],
    search_start: usize,
    search_end: usize,
) -> Option<(usize, &'a str, usize)> {
    let mut cursor: usize = search_start;
    let mut returned: Option<(usize, &'a str)> = None;
    let mut return_count: usize = 0;
    while cursor < search_end {
        let Some(relative): Option<usize> = source[cursor..search_end].find("return") else {
            break;
        };
        let keyword_start: usize = cursor + relative;
        let keyword_end: usize = keyword_start + "return".len();
        cursor = keyword_end;
        if (keyword_start > 0 && is_ident_byte(bytes[keyword_start - 1]))
            || bytes
                .get(keyword_end)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
            || !is_executable_code_position(bytes, keyword_start)
        {
            continue;
        }
        return_count += 1;
        let value_start: usize = skip_ws(bytes, keyword_end);
        let separator: &[u8] = &bytes[keyword_end..value_start];
        if separator
            .iter()
            .any(|byte: &u8| matches!(*byte, b'\n' | b'\r'))
        {
            returned = None;
            continue;
        }
        let mut value_end: usize = value_start;
        while value_end < search_end && is_ident_byte(bytes[value_end]) {
            value_end += 1;
        }
        if value_end == value_start {
            returned = None;
            continue;
        }
        let statement_end: usize = skip_ws(bytes, value_end);
        if !matches!(bytes.get(statement_end), Some(b';' | b'}')) {
            returned = None;
            continue;
        }
        returned = Some((keyword_start, &source[value_start..value_end]));
    }
    returned.map(|(start, identifier): (usize, &'a str)| (start, identifier, return_count))
}

fn strip_outer_parentheses(mut expression: &str) -> &str {
    loop {
        let trimmed: &str = expression.trim();
        let bytes: &[u8] = trimmed.as_bytes();
        if bytes.first() != Some(&b'(') {
            return trimmed;
        }
        let Some(close): Option<usize> = find_paren_close(bytes, 1) else {
            return trimmed;
        };
        if close + 1 != bytes.len() {
            return trimmed;
        }
        expression = &trimmed[1..close];
    }
}

fn simple_string_literal(expression: &str) -> Option<&str> {
    let trimmed: &str = expression.trim();
    let bytes: &[u8] = trimmed.as_bytes();
    let quote: u8 = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"') || bytes.len() < 2 || bytes.last() != Some(&quote) {
        return None;
    }
    let inner: &str = &trimmed[1..trimmed.len() - 1];
    if inner.contains('\\') {
        return None;
    }
    Some(inner)
}

fn literal_strict_equality_is_false(expression: &str) -> bool {
    let unwrapped: &str = strip_outer_parentheses(expression);
    let Some((left, right)): Option<(&str, &str)> = unwrapped.split_once("===") else {
        return false;
    };
    if right.contains("===") {
        return false;
    }
    let Some(left_value): Option<&str> = simple_string_literal(left) else {
        return false;
    };
    let Some(right_value): Option<&str> = simple_string_literal(right) else {
        return false;
    };
    left_value != right_value
}

fn earlier_returns_are_unreachable(
    source: &str,
    bytes: &[u8],
    brace_open: usize,
    brace_close: usize,
    return_start: usize,
) -> bool {
    let Some(return_scope): Option<Vec<usize>> = executable_brace_stack_at(bytes, return_start)
    else {
        return false;
    };
    let Some(else_open): Option<usize> = return_scope.last().copied() else {
        return false;
    };
    if else_open <= brace_open {
        return false;
    }
    let Some(else_close): Option<usize> = find_brace_close(bytes, else_open + 1) else {
        return false;
    };
    if skip_ws(bytes, else_close + 1) != brace_close
        || return_start <= else_open
        || return_start >= else_close
    {
        return false;
    }
    let mut else_keyword_end: usize = else_open;
    while else_keyword_end > brace_open && bytes[else_keyword_end - 1].is_ascii_whitespace() {
        else_keyword_end -= 1;
    }
    let Some(else_keyword_start): Option<usize> = else_keyword_end.checked_sub("else".len()) else {
        return false;
    };
    if source.get(else_keyword_start..else_keyword_end) != Some("else")
        || (else_keyword_start > 0 && is_ident_byte(bytes[else_keyword_start - 1]))
    {
        return false;
    }
    let if_start: usize = skip_ws(bytes, brace_open + 1);
    if !source[if_start..].starts_with("if")
        || bytes
            .get(if_start + "if".len())
            .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return false;
    }
    let condition_open: usize = skip_ws(bytes, if_start + "if".len());
    if bytes.get(condition_open) != Some(&b'(') {
        return false;
    }
    let Some(condition_close): Option<usize> = find_paren_close(bytes, condition_open + 1) else {
        return false;
    };
    if condition_close >= else_keyword_start {
        return false;
    }
    let consequent_start: usize = skip_ws(bytes, condition_close + 1);
    let switch_end: usize = consequent_start + "switch".len();
    if source.get(consequent_start..switch_end) != Some("switch")
        || bytes
            .get(switch_end)
            .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return false;
    }
    let switch_condition_open: usize = skip_ws(bytes, switch_end);
    if bytes.get(switch_condition_open) != Some(&b'(') {
        return false;
    }
    let Some(switch_condition_close): Option<usize> =
        find_paren_close(bytes, switch_condition_open + 1)
    else {
        return false;
    };
    let switch_body_open: usize = skip_ws(bytes, switch_condition_close + 1);
    if bytes.get(switch_body_open) != Some(&b'{') {
        return false;
    }
    let Some(switch_body_close): Option<usize> = find_brace_close(bytes, switch_body_open + 1)
    else {
        return false;
    };
    if skip_ws(bytes, switch_body_close + 1) != else_keyword_start {
        return false;
    }
    literal_strict_equality_is_false(&source[condition_open + 1..condition_close])
}

fn static_string_concatenation(expression: &str) -> Option<String> {
    let bytes: &[u8] = expression.as_bytes();
    let mut cursor: usize = 0;
    let mut depth: usize = 0;
    let mut expect_value: bool = true;
    let mut saw_value: bool = false;
    let mut value: String = String::new();
    while cursor < bytes.len() {
        match bytes[cursor] {
            byte if byte.is_ascii_whitespace() => cursor += 1,
            b'(' if expect_value => {
                depth += 1;
                cursor += 1;
            }
            b')' if !expect_value && depth > 0 => {
                depth -= 1;
                cursor += 1;
            }
            quote @ (b'\'' | b'"') if expect_value => {
                let content_start: usize = cursor + 1;
                cursor = content_start;
                while cursor < bytes.len() && bytes[cursor] != quote {
                    if bytes[cursor] == b'\\' {
                        return None;
                    }
                    cursor += 1;
                }
                if bytes.get(cursor) != Some(&quote) {
                    return None;
                }
                value.push_str(&expression[content_start..cursor]);
                cursor += 1;
                expect_value = false;
                saw_value = true;
            }
            b'+' if !expect_value => {
                expect_value = true;
                cursor += 1;
            }
            _ => return None,
        }
    }
    (saw_value && !expect_value && depth == 0).then_some(value)
}

fn global_function_invocation_end(source: &str, bytes: &[u8], rhs_start: usize) -> Option<usize> {
    if !source[rhs_start..].starts_with("Function") {
        return None;
    }
    let function_end: usize = rhs_start + "Function".len();
    if bytes
        .get(function_end)
        .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return None;
    }
    let constructor_open: usize = skip_ws(bytes, function_end);
    if bytes.get(constructor_open) != Some(&b'(') {
        return None;
    }
    let constructor_close: usize = find_paren_close(bytes, constructor_open + 1)?;
    let constructor_source: &str = &source[constructor_open + 1..constructor_close];
    if static_string_concatenation(constructor_source).as_deref()
        != Some("return (function() {}.constructor(\"return this\")( ));")
    {
        return None;
    }
    let invocation_open: usize = skip_ws(bytes, constructor_close + 1);
    if bytes.get(invocation_open) != Some(&b'(') {
        return None;
    }
    let invocation_close: usize = find_paren_close(bytes, invocation_open + 1)?;
    if !source[invocation_open + 1..invocation_close]
        .trim()
        .is_empty()
    {
        return None;
    }
    let expression_end: usize = skip_ws(bytes, invocation_close + 1);
    matches!(bytes.get(expression_end), Some(b';' | b'}')).then_some(expression_end)
}

fn window_assignment_end(bytes: &[u8], rhs_start: usize) -> Option<usize> {
    if bytes.get(rhs_start..rhs_start + "window".len()) != Some(b"window") {
        return None;
    }
    let window_end: usize = rhs_start + "window".len();
    if bytes
        .get(window_end)
        .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return None;
    }
    let expression_end: usize = skip_ws(bytes, window_end);
    matches!(bytes.get(expression_end), Some(b';' | b'}')).then_some(expression_end)
}

fn assignment_fills_block(
    bytes: &[u8],
    assignment_start: usize,
    expression_end: usize,
    block_open: usize,
    block_close: usize,
) -> bool {
    if skip_ws(bytes, block_open + 1) != assignment_start {
        return false;
    }
    match bytes.get(expression_end) {
        Some(b';') => skip_ws(bytes, expression_end + 1) == block_close,
        Some(b'}') => expression_end == block_close,
        _ => false,
    }
}

fn try_keyword_before(bytes: &[u8], brace_open: usize, parent_start: usize) -> Option<usize> {
    let mut keyword_end: usize = brace_open;
    while keyword_end > parent_start && bytes[keyword_end - 1].is_ascii_whitespace() {
        keyword_end -= 1;
    }
    let keyword_start: usize = keyword_end.checked_sub("try".len())?;
    if keyword_start < parent_start
        || bytes.get(keyword_start..keyword_end) != Some(b"try")
        || (keyword_start > 0 && is_ident_byte(bytes[keyword_start - 1]))
    {
        return None;
    }
    let mut statement_start: usize = keyword_start;
    while statement_start > parent_start && bytes[statement_start - 1].is_ascii_whitespace() {
        statement_start -= 1;
    }
    (statement_start == parent_start
        || matches!(bytes.get(statement_start - 1), Some(b';' | b'{' | b'}')))
    .then_some(keyword_start)
}

fn assignments_form_unconditional_try_catch(
    source: &str,
    bytes: &[u8],
    return_start: usize,
    function_assignment: (usize, usize),
    window_assignment: (usize, usize),
) -> bool {
    let Some(return_scope): Option<Vec<usize>> = executable_brace_stack_at(bytes, return_start)
    else {
        return false;
    };
    let Some(parent_open): Option<usize> = return_scope.last().copied() else {
        return false;
    };
    let Some(function_scope): Option<Vec<usize>> =
        executable_brace_stack_at(bytes, function_assignment.0)
    else {
        return false;
    };
    let Some(window_scope): Option<Vec<usize>> =
        executable_brace_stack_at(bytes, window_assignment.0)
    else {
        return false;
    };
    if function_scope.len() != return_scope.len() + 1
        || window_scope.len() != return_scope.len() + 1
        || !function_scope.starts_with(&return_scope)
        || !window_scope.starts_with(&return_scope)
    {
        return false;
    }
    let Some(try_open): Option<usize> = function_scope.last().copied() else {
        return false;
    };
    let Some(catch_open): Option<usize> = window_scope.last().copied() else {
        return false;
    };
    if try_keyword_before(bytes, try_open, parent_open + 1).is_none() {
        return false;
    }
    let Some(try_close): Option<usize> = find_brace_close(bytes, try_open + 1) else {
        return false;
    };
    let catch_start: usize = skip_ws(bytes, try_close + 1);
    let catch_end: usize = catch_start + "catch".len();
    if source.get(catch_start..catch_end) != Some("catch")
        || bytes
            .get(catch_end)
            .is_some_and(|byte: &u8| is_ident_byte(*byte))
    {
        return false;
    }
    let mut after_catch: usize = skip_ws(bytes, catch_end);
    if bytes.get(after_catch) == Some(&b'(') {
        let Some(parameter_close): Option<usize> = find_paren_close(bytes, after_catch + 1) else {
            return false;
        };
        after_catch = skip_ws(bytes, parameter_close + 1);
    }
    if after_catch != catch_open {
        return false;
    }
    let Some(catch_close): Option<usize> = find_brace_close(bytes, catch_open + 1) else {
        return false;
    };
    assignment_fills_block(
        bytes,
        function_assignment.0,
        function_assignment.1,
        try_open,
        try_close,
    ) && assignment_fills_block(
        bytes,
        window_assignment.0,
        window_assignment.1,
        catch_open,
        catch_close,
    )
}

fn resolver_returns_global(
    source: &str,
    bytes: &[u8],
    brace_open: usize,
    brace_close: usize,
) -> bool {
    let Some((return_start, result, return_count)): Option<(usize, &str, usize)> =
        returned_identifier(source, bytes, brace_open + 1, brace_close)
    else {
        return false;
    };
    if return_count > 1
        && !earlier_returns_are_unreachable(source, bytes, brace_open, brace_close, return_start)
    {
        return false;
    }
    if unqualified_code_identifier_count(source, bytes, result, brace_open + 1, brace_close) != 4 {
        return false;
    }
    let mut cursor: usize = brace_open + 1;
    let mut assignments: usize = 0;
    let mut function_assignment: Option<(usize, usize)> = None;
    let mut window_assignment: Option<(usize, usize)> = None;
    while cursor < brace_close {
        let Some(relative): Option<usize> = source[cursor..brace_close].find(result) else {
            break;
        };
        let name_start: usize = cursor + relative;
        let name_end: usize = name_start + result.len();
        cursor = name_end;
        if (name_start > 0
            && (is_ident_byte(bytes[name_start - 1])
                || matches!(bytes[name_start - 1], b'.' | b'?' | b'#')))
            || bytes
                .get(name_end)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
            || !is_executable_code_position(bytes, name_start)
        {
            continue;
        }
        let equals: usize = skip_ws(bytes, name_end);
        if bytes.get(equals) != Some(&b'=') || matches!(bytes.get(equals + 1), Some(b'=' | b'>')) {
            continue;
        }
        assignments += 1;
        let rhs_start: usize = skip_ws(bytes, equals + 1);
        let function_end: Option<usize> = global_function_invocation_end(source, bytes, rhs_start);
        let window_end: Option<usize> = window_assignment_end(bytes, rhs_start);
        if function_end.is_some() {
            function_assignment =
                function_end.map(|expression_end: usize| (name_start, expression_end));
        } else if window_end.is_some() {
            window_assignment =
                window_end.map(|expression_end: usize| (name_start, expression_end));
        } else {
            return false;
        }
    }
    let Some(function_assignment): Option<(usize, usize)> = function_assignment else {
        return false;
    };
    let Some(window_assignment): Option<(usize, usize)> = window_assignment else {
        return false;
    };
    assignments == 2
        && assignments_form_unconditional_try_catch(
            source,
            bytes,
            return_start,
            function_assignment,
            window_assignment,
        )
}

fn assigned_global_resolver_function_before(
    source: &str,
    bytes: &[u8],
    name: &str,
    search_start: usize,
    search_end: usize,
    scope_depth: usize,
) -> bool {
    let mut cursor: usize = search_start;
    let mut found: Option<bool> = None;
    while cursor < search_end {
        let Some(relative): Option<usize> = source[cursor..search_end].find(name) else {
            break;
        };
        let name_start: usize = cursor + relative;
        cursor = name_start + name.len();
        if (name_start > 0
            && (is_ident_byte(bytes[name_start - 1])
                || matches!(bytes[name_start - 1], b'.' | b'?' | b'#')))
            || bytes
                .get(cursor)
                .is_some_and(|byte: &u8| is_ident_byte(*byte))
        {
            continue;
        }
        let Some(name_depth): Option<usize> = executable_brace_depth_at(bytes, name_start) else {
            continue;
        };
        if name_depth < scope_depth {
            continue;
        }
        if name_depth > scope_depth {
            found = Some(false);
            continue;
        }
        found = Some(false);
        if !has_simple_declaration_prefix(source, bytes, name_start, search_start) {
            continue;
        }
        let equals: usize = skip_ws(bytes, cursor);
        if bytes.get(equals) != Some(&b'=') || matches!(bytes.get(equals + 1), Some(b'=' | b'>')) {
            continue;
        }
        let function_start: usize = skip_ws(bytes, equals + 1);
        if !source[function_start..].starts_with("function") {
            found = Some(false);
            continue;
        }
        let mut paren_open: usize = skip_ws(bytes, function_start + "function".len());
        while paren_open < search_end && is_ident_byte(bytes[paren_open]) {
            paren_open += 1;
        }
        paren_open = skip_ws(bytes, paren_open);
        if bytes.get(paren_open) != Some(&b'(') {
            found = Some(false);
            continue;
        }
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            found = Some(false);
            continue;
        };
        if !source[paren_open + 1..paren_close].trim().is_empty() {
            found = Some(false);
            continue;
        }
        let brace_open: usize = skip_ws(bytes, paren_close + 1);
        if bytes.get(brace_open) != Some(&b'{') {
            found = Some(false);
            continue;
        }
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            found = Some(false);
            continue;
        };
        if brace_close >= search_end {
            found = Some(false);
            continue;
        }
        let initializer_end: usize = skip_ws(bytes, brace_close + 1);
        if bytes.get(initializer_end) != Some(&b';') {
            found = Some(false);
            continue;
        }
        let body: &str = &source[brace_open + 1..brace_close];
        let function_count: usize =
            unqualified_code_identifier_count(source, bytes, "Function", brace_open, brace_close);
        let window_count: usize =
            unqualified_code_identifier_count(source, bytes, "window", brace_open, brace_close);
        found = Some(
            body.contains("return this")
                && function_count == 1
                && window_count == 1
                && resolver_returns_global(source, bytes, brace_open, brace_close),
        );
    }
    found.unwrap_or(false)
}

fn known_global_interval_call_start(source: &str, bytes: &[u8], pos: usize) -> Option<usize> {
    if source.match_indices("setInterval").count() != 1
        || has_global_timer_mutation_or_escape(source, pos)
    {
        return None;
    }
    let mut cursor: usize = pos;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t' | b'\n' | b'\r') {
        cursor -= 1;
    }
    if cursor == 0 || bytes[cursor - 1] != b'.' {
        return Some(pos);
    }
    let (receiver_start, receiver): (usize, &str) = interval_receiver(source, bytes, pos)?;
    if matches!(receiver, "globalThis" | "window" | "self")
        && source.match_indices(receiver).count() == 1
    {
        return Some(receiver_start);
    }
    None
}

fn expression_is_global_object(expression: &Expression<'_>) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::Identifier(identifier)
            if matches!(identifier.name.as_str(), "globalThis" | "window" | "self")
    ) || matches!(
        expression.get_inner_expression(),
        Expression::ThisExpression(_)
    )
}

fn expression_is_dynamic_function_result(expression: &Expression<'_>) -> bool {
    let Expression::CallExpression(invocation): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if invocation.optional
        || invocation.type_parameters.is_some()
        || !invocation.arguments.is_empty()
    {
        return false;
    }
    let Expression::CallExpression(constructor): &Expression<'_> =
        invocation.callee.get_inner_expression()
    else {
        return false;
    };
    let dynamic_constructor: bool = expression_is_identifier(&constructor.callee, "Function")
        || constructor
            .callee
            .get_member_expr()
            .is_some_and(|member: &MemberExpression<'_>| {
                member.static_property_name() == Some("constructor")
            });
    !constructor.optional && constructor.type_parameters.is_none() && dynamic_constructor
}

fn expression_is_indirect_global_eval_result(expression: &Expression<'_>) -> bool {
    let Expression::CallExpression(call): &Expression<'_> = expression.get_inner_expression()
    else {
        return false;
    };
    if !matches!(
        single_string_argument(call),
        Some("this" | "globalThis" | "window" | "self")
    ) {
        return false;
    }
    let Expression::SequenceExpression(sequence): &Expression<'_> =
        call.callee.get_inner_expression()
    else {
        return false;
    };
    if sequence.expressions.len() < 2 {
        return false;
    }
    let Some(last): Option<&Expression<'_>> = sequence.expressions.last() else {
        return false;
    };
    expression_is_identifier(last, "eval")
}

fn expression_is_global_object_or_alias(expression: &Expression<'_>, aliases: &[String]) -> bool {
    expression_is_global_object(expression)
        || expression_is_dynamic_function_result(expression)
        || expression_is_indirect_global_eval_result(expression)
        || matches!(
            expression.get_inner_expression(),
            Expression::Identifier(identifier)
                if aliases.iter().any(|alias: &String| alias == identifier.name.as_str())
        )
}

fn append_static_string(expression: &Expression<'_>, value: &mut String) -> bool {
    match expression.get_inner_expression() {
        Expression::StringLiteral(literal) => {
            value.push_str(literal.value.as_str());
            true
        }
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            append_static_string(&binary.left, value) && append_static_string(&binary.right, value)
        }
        _ => false,
    }
}

fn expression_may_be_named_property(expression: &Expression<'_>, property_name: &str) -> bool {
    let mut value: String = String::with_capacity(property_name.len());
    !append_static_string(expression, &mut value) || value == property_name
}

fn is_named_write_member(member: &MemberExpression<'_>, property_name: &str) -> bool {
    match member {
        MemberExpression::ComputedMemberExpression(computed) => {
            expression_may_be_named_property(&computed.expression, property_name)
        }
        MemberExpression::StaticMemberExpression(member) => member.property.name == property_name,
        MemberExpression::PrivateFieldExpression(_) => false,
    }
}

fn is_statically_named_member(member: &MemberExpression<'_>, property_name: &str) -> bool {
    match member {
        MemberExpression::ComputedMemberExpression(computed) => {
            let mut value: String = String::with_capacity(property_name.len());
            append_static_string(&computed.expression, &mut value) && value == property_name
        }
        MemberExpression::StaticMemberExpression(member) => member.property.name == property_name,
        MemberExpression::PrivateFieldExpression(_) => false,
    }
}

fn is_safe_global_function_constructor(call: &CallExpression<'_>) -> bool {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return false;
    }
    if !expression_is_identifier(&call.callee, "Function") {
        return false;
    }
    let Some(argument): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let mut body: String = String::new();
    if !append_static_string(argument, &mut body) {
        return false;
    }
    matches!(
        body.as_str(),
        "return this" | "return (function() {}.constructor(\"return this\")( ));"
    )
}

fn is_function_literal_constructor_call(call: &CallExpression<'_>) -> bool {
    if call.optional || call.type_parameters.is_some() {
        return false;
    }
    let Some(member): Option<&MemberExpression<'_>> = call.callee.get_member_expr() else {
        return false;
    };
    is_statically_named_member(member, "constructor")
        && matches!(
            member.object().get_inner_expression(),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        )
}

fn is_reflective_mutation_primitive(member: &MemberExpression<'_>) -> bool {
    let Some(property): Option<&str> = member.static_property_name() else {
        return false;
    };
    let Expression::Identifier(object): &Expression<'_> = member.object().get_inner_expression()
    else {
        return false;
    };
    match object.name.as_str() {
        "Reflect" => matches!(property, "set" | "defineProperty" | "deleteProperty"),
        "Object" => matches!(
            property,
            "defineProperty" | "defineProperties" | "assign" | "setPrototypeOf"
        ),
        _ => false,
    }
}

fn is_reflective_property_write(call: &CallExpression<'_>, property_name: &str) -> bool {
    let property_mutation: bool = call.callee.is_specific_member_access("Reflect", "set")
        || call
            .callee
            .is_specific_member_access("Reflect", "defineProperty")
        || call
            .callee
            .is_specific_member_access("Reflect", "deleteProperty")
        || call
            .callee
            .is_specific_member_access("Object", "defineProperty");
    if property_mutation {
        return call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(|expression: &Expression<'_>| {
                expression_may_be_named_property(expression, property_name)
            });
    }
    call.callee
        .is_specific_member_access("Object", "defineProperties")
        || call.callee.is_specific_member_access("Object", "assign")
        || call
            .callee
            .is_specific_member_access("Object", "setPrototypeOf")
}

fn call_receives_global_object(call: &CallExpression<'_>, aliases: &[String]) -> bool {
    call.arguments.iter().any(|argument: &Argument<'_>| {
        argument
            .as_expression()
            .is_some_and(|value: &Expression<'_>| {
                expression_is_global_object_or_alias(value, aliases)
            })
    })
}

struct OnceWrapperBindingVisitor<'a> {
    name: &'a str,
    call_start: usize,
    bindings: usize,
    mutated: bool,
    candidates: Vec<(usize, usize)>,
}

impl<'a> Visit<'a> for OnceWrapperBindingVisitor<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::BindingIdentifier(identifier) if identifier.name == self.name => {
                self.bindings += 1;
            }
            AstKind::VariableDeclarator(declarator) => {
                let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
                    &declarator.id.kind
                else {
                    return;
                };
                if identifier.name != self.name || declarator.span.end as usize > self.call_start {
                    return;
                }
                let Some(initializer): Option<&Expression<'_>> = declarator.init.as_ref() else {
                    return;
                };
                let span: oxc_span::Span = initializer.span();
                self.candidates
                    .push((span.start as usize, span.end as usize));
            }
            AstKind::AssignmentExpression(assignment)
                if matches!(
                    &assignment.left,
                    oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier)
                        if identifier.name == self.name
                ) =>
            {
                self.mutated = true;
            }
            AstKind::UpdateExpression(update)
                if update.argument.get_identifier() == Some(self.name) =>
            {
                self.mutated = true;
            }
            AstKind::UnaryExpression(unary)
                if unary.operator.as_str() == "delete"
                    && expression_is_identifier(&unary.argument, self.name) =>
            {
                self.mutated = true;
            }
            _ => {}
        }
    }
}

fn has_unique_proven_once_wrapper_binding(
    source: &str,
    wrapper_name: &str,
    call_start: usize,
) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return false;
    }
    let mut visitor: OnceWrapperBindingVisitor<'_> = OnceWrapperBindingVisitor {
        name: wrapper_name,
        call_start,
        bindings: 0,
        mutated: false,
        candidates: Vec::new(),
    };
    visitor.visit_program(&parsed.program);
    if visitor.bindings != 1 || visitor.mutated || visitor.candidates.len() != 1 {
        return false;
    }
    let Some((start, end)): Option<&(usize, usize)> = visitor.candidates.first() else {
        return false;
    };
    let Some(initializer): Option<&str> = source.get(*start..*end) else {
        return false;
    };
    let mut declaration: String =
        String::with_capacity("const wrapper=;".len() + initializer.len());
    declaration.push_str("const wrapper=");
    declaration.push_str(initializer);
    declaration.push(';');
    is_once_wrapper_shape(&declaration)
        || is_immediately_inert_hybrid_once_wrapper_shape(&declaration)
}

fn is_proven_once_wrapper_setup_call(source: &str, call: &CallExpression<'_>) -> bool {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Expression::Identifier(wrapper): &Expression<'_> = call.callee.get_inner_expression()
    else {
        return false;
    };
    let Some(receiver): Option<&Expression<'_>> =
        call.arguments.first().and_then(Argument::as_expression)
    else {
        return false;
    };
    let Some(checker): Option<&Expression<'_>> =
        call.arguments.get(1).and_then(Argument::as_expression)
    else {
        return false;
    };
    matches!(
        receiver.get_inner_expression(),
        Expression::ThisExpression(_)
    ) && is_ordinary_anonymous_function(checker)
        && has_unique_proven_once_wrapper_binding(
            source,
            wrapper.name.as_str(),
            call.span.start as usize,
        )
}

fn array_contains_global_object(
    array: &oxc_ast::ast::ArrayExpression<'_>,
    aliases: &[String],
) -> bool {
    array.elements.iter().any(
        |element: &oxc_ast::ast::ArrayExpressionElement<'_>| match element {
            oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                expression_is_global_object_or_alias(&spread.argument, aliases)
            }
            oxc_ast::ast::ArrayExpressionElement::Elision(_) => false,
            element => element
                .as_expression()
                .is_some_and(|value: &Expression<'_>| {
                    expression_is_global_object_or_alias(value, aliases)
                }),
        },
    )
}

fn object_contains_global_object(
    object: &oxc_ast::ast::ObjectExpression<'_>,
    aliases: &[String],
) -> bool {
    object
        .properties
        .iter()
        .any(|property: &ObjectPropertyKind<'_>| match property {
            ObjectPropertyKind::ObjectProperty(property) => {
                expression_is_global_object_or_alias(&property.value, aliases)
            }
            ObjectPropertyKind::SpreadProperty(spread) => {
                expression_is_global_object_or_alias(&spread.argument, aliases)
            }
        })
}

fn function_is_immediately_invoked(source: &str, span: oxc_span::Span) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let mut cursor: usize = skip_ws(bytes, span.end as usize);
    while bytes.get(cursor) == Some(&b')') {
        cursor = skip_ws(bytes, cursor + 1);
    }
    bytes.get(cursor) == Some(&b'(')
        || source.get(cursor..).is_some_and(|suffix: &str| {
            suffix.starts_with(".call(") || suffix.starts_with(".apply(")
        })
}

fn callable_expression_name(expression: &Expression<'_>) -> Option<String> {
    let inner: &Expression<'_> = expression.get_inner_expression();
    if let Expression::Identifier(identifier) = inner {
        return Some(identifier.name.as_str().to_owned());
    }
    let member: &MemberExpression<'_> = inner.get_member_expr()?;
    if member
        .static_property_name()
        .is_some_and(|property_name: &str| property_name == "call" || property_name == "apply")
    {
        return callable_expression_name(member.object());
    }
    let object_name: String = callable_expression_name(member.object())?;
    let member_suffix: String = match member {
        MemberExpression::ComputedMemberExpression(computed) => {
            match computed.expression.get_inner_expression() {
                Expression::NumericLiteral(literal) if literal.value.is_finite() => {
                    format!("[{}]", literal.value)
                }
                _ => format!(".{}", member.static_property_name()?),
            }
        }
        _ => format!(".{}", member.static_property_name()?),
    };
    Some(format!("{object_name}{member_suffix}"))
}

struct FunctionSpanVisitor<'a> {
    source: &'a str,
    spans: Vec<(usize, usize)>,
    declarations: Vec<(String, usize, usize)>,
    calls: Vec<(String, usize)>,
    aliases: Vec<(String, String)>,
}

impl<'a> Visit<'a> for FunctionSpanVisitor<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::Function(function) => {
                if function_is_immediately_invoked(self.source, function.span) {
                    return;
                }
                let start: usize = function.span.start as usize;
                let end: usize = function.span.end as usize;
                let range: (usize, usize) = (start, end);
                if !self.spans.contains(&range) {
                    self.spans.push(range);
                }
                if function.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration
                    && let Some(identifier) = function.id.as_ref()
                {
                    self.declarations
                        .push((identifier.name.as_str().to_owned(), start, end));
                }
            }
            AstKind::CallExpression(call) => {
                let Some(callee_name): Option<String> = callable_expression_name(&call.callee)
                else {
                    return;
                };
                self.calls.push((callee_name, call.span.start as usize));
            }
            AstKind::NewExpression(construction) => {
                let Some(callee_name): Option<String> =
                    callable_expression_name(&construction.callee)
                else {
                    return;
                };
                self.calls
                    .push((callee_name, construction.span.start as usize));
            }
            AstKind::TaggedTemplateExpression(template) => {
                let Some(callee_name): Option<String> = callable_expression_name(&template.tag)
                else {
                    return;
                };
                self.calls.push((callee_name, template.span.start as usize));
            }
            AstKind::VariableDeclarator(declarator) => {
                let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
                    &declarator.id.kind
                else {
                    return;
                };
                let Some(initializer): Option<&Expression<'_>> = declarator.init.as_ref() else {
                    return;
                };
                if let Expression::ObjectExpression(object) = initializer.get_inner_expression() {
                    let object_name: &str = identifier.name.as_str();
                    for property_kind in &object.properties {
                        let ObjectPropertyKind::ObjectProperty(property): &ObjectPropertyKind<'_> =
                            property_kind
                        else {
                            continue;
                        };
                        if property.kind != PropertyKind::Init {
                            continue;
                        }
                        let property_name: &str = match &property.key {
                            oxc_ast::ast::PropertyKey::StaticIdentifier(property_identifier) => {
                                property_identifier.name.as_str()
                            }
                            oxc_ast::ast::PropertyKey::StringLiteral(literal) => {
                                literal.value.as_str()
                            }
                            _ => continue,
                        };
                        let span: oxc_span::Span = match property.value.get_inner_expression() {
                            Expression::FunctionExpression(function) => function.span,
                            Expression::ArrowFunctionExpression(function) => function.span,
                            _ => continue,
                        };
                        if function_is_immediately_invoked(self.source, span) {
                            continue;
                        }
                        let range: (usize, usize) = (span.start as usize, span.end as usize);
                        if !self.spans.contains(&range) {
                            self.spans.push(range);
                        }
                        self.declarations.push((
                            format!("{object_name}.{property_name}"),
                            range.0,
                            range.1,
                        ));
                    }
                    return;
                }
                if let Expression::ArrayExpression(array) = initializer.get_inner_expression() {
                    if array.elements.iter().any(
                        |element: &oxc_ast::ast::ArrayExpressionElement<'_>| {
                            matches!(
                                element,
                                oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)
                            )
                        },
                    ) {
                        return;
                    }
                    let object_name: &str = identifier.name.as_str();
                    for (index, element) in array.elements.iter().enumerate() {
                        let Some(value): Option<&Expression<'_>> = element.as_expression() else {
                            continue;
                        };
                        let span: oxc_span::Span = match value.get_inner_expression() {
                            Expression::FunctionExpression(function) => function.span,
                            Expression::ArrowFunctionExpression(function) => function.span,
                            _ => continue,
                        };
                        if function_is_immediately_invoked(self.source, span) {
                            continue;
                        }
                        let range: (usize, usize) = (span.start as usize, span.end as usize);
                        if !self.spans.contains(&range) {
                            self.spans.push(range);
                        }
                        self.declarations.push((
                            format!("{object_name}[{index}]"),
                            range.0,
                            range.1,
                        ));
                    }
                    return;
                }
                let span: oxc_span::Span = match initializer.get_inner_expression() {
                    Expression::FunctionExpression(function) => function.span,
                    Expression::ArrowFunctionExpression(function) => function.span,
                    Expression::Identifier(target) => {
                        self.aliases.push((
                            identifier.name.as_str().to_owned(),
                            target.name.as_str().to_owned(),
                        ));
                        return;
                    }
                    _ => return,
                };
                if function_is_immediately_invoked(self.source, span) {
                    return;
                }
                let range: (usize, usize) = (span.start as usize, span.end as usize);
                if !self.spans.contains(&range) {
                    self.spans.push(range);
                }
                self.declarations
                    .push((identifier.name.as_str().to_owned(), range.0, range.1));
            }
            AstKind::AssignmentExpression(assignment) if assignment.operator.as_str() == "=" => {
                let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier):
                    &oxc_ast::ast::AssignmentTarget<'_> = &assignment.left
                else {
                    return;
                };
                let span: oxc_span::Span = match assignment.right.get_inner_expression() {
                    Expression::FunctionExpression(function) => function.span,
                    Expression::ArrowFunctionExpression(function) => function.span,
                    Expression::Identifier(target) => {
                        self.aliases.push((
                            identifier.name.as_str().to_owned(),
                            target.name.as_str().to_owned(),
                        ));
                        return;
                    }
                    _ => return,
                };
                if function_is_immediately_invoked(self.source, span) {
                    return;
                }
                let range: (usize, usize) = (span.start as usize, span.end as usize);
                if !self.spans.contains(&range) {
                    self.spans.push(range);
                }
                self.declarations
                    .push((identifier.name.as_str().to_owned(), range.0, range.1));
            }
            _ => {}
        }
    }
}

const fn range_contains(range: (usize, usize), position: usize) -> bool {
    range.0 <= position && position < range.1
}

fn execution_scopes_match(
    position: usize,
    target_position: usize,
    spans: &[(usize, usize)],
    synchronous: &[(usize, usize)],
) -> bool {
    spans.iter().all(|span: &(usize, usize)| {
        synchronous.contains(span)
            || range_contains(*span, position) == range_contains(*span, target_position)
    })
}

fn callable_alias_reaches(callee: &str, target: &str, aliases: &[(String, String)]) -> bool {
    let mut pending: Vec<String> = vec![callee.to_owned()];
    let mut visited: Vec<String> = Vec::new();
    while let Some(current) = pending.pop() {
        if current == target {
            return true;
        }
        if visited.contains(&current) {
            continue;
        }
        for (alias, value) in aliases {
            if alias == &current && !visited.contains(value) {
                pending.push(value.clone());
            }
        }
        visited.push(current);
    }
    false
}

fn deferred_function_spans(
    target_position: usize,
    spans: &[(usize, usize)],
    declarations: &[(String, usize, usize)],
    calls: &[(String, usize)],
    aliases: &[(String, String)],
) -> Vec<(usize, usize)> {
    let mut synchronous: Vec<(usize, usize)> = Vec::new();
    let mut changed: bool = true;
    while changed {
        changed = false;
        for (callee, call_position) in calls {
            let inside_synchronous: bool = synchronous
                .iter()
                .any(|range: &(usize, usize)| range_contains(*range, *call_position));
            if (*call_position >= target_position && !inside_synchronous)
                || !execution_scopes_match(*call_position, target_position, spans, &synchronous)
            {
                continue;
            }
            for (name, start, end) in declarations {
                let range: (usize, usize) = (*start, *end);
                if callable_alias_reaches(callee, name, aliases) && !synchronous.contains(&range) {
                    synchronous.push(range);
                    changed = true;
                }
            }
        }
    }
    spans
        .iter()
        .copied()
        .filter(|span: &(usize, usize)| !synchronous.contains(span))
        .collect()
}

struct GlobalWriteVisitor<'a> {
    source: &'a str,
    property_name: &'a str,
    reject_binding: bool,
    global_receiver_only: bool,
    excluded: Option<(usize, usize)>,
    aliases: Vec<String>,
    safe_dynamic_references: Vec<(usize, usize)>,
    function_spans: Vec<(usize, usize)>,
    target_position: usize,
    found: bool,
}

impl GlobalWriteVisitor<'_> {
    fn span_is_excluded(&self, span: oxc_span::Span) -> bool {
        self.excluded.is_some_and(|(start, end): (usize, usize)| {
            start <= span.start as usize && span.end as usize <= end
        })
    }

    fn register_alias(&mut self, name: &str) {
        if !self.aliases.iter().any(|alias: &String| alias == name) {
            self.aliases.push(name.to_owned());
        }
    }

    fn register_safe_dynamic_reference(&mut self, call: &CallExpression<'_>) {
        if !is_safe_global_function_constructor(call) {
            return;
        }
        let Expression::Identifier(identifier): &Expression<'_> =
            call.callee.get_inner_expression()
        else {
            return;
        };
        self.safe_dynamic_references
            .push((identifier.span.start as usize, identifier.span.end as usize));
    }

    fn dynamic_reference_is_safe(&self, span: oxc_span::Span) -> bool {
        self.safe_dynamic_references
            .iter()
            .any(|candidate: &(usize, usize)| {
                candidate.0 == span.start as usize && candidate.1 == span.end as usize
            })
    }

    fn dynamic_call_is_in_target_scope(&self, span: oxc_span::Span) -> bool {
        self.function_spans
            .iter()
            .all(|(start, end): &(usize, usize)| {
                let contains_call: bool =
                    *start <= span.start as usize && span.end as usize <= *end;
                let contains_target: bool =
                    *start <= self.target_position && self.target_position < *end;
                contains_call == contains_target
            })
    }

    fn register_declarator_alias(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'_>) {
        let Some(initializer): Option<&Expression<'_>> = declarator.init.as_ref() else {
            return;
        };
        if !expression_is_global_object_or_alias(initializer, &self.aliases) {
            return;
        }
        let BindingPatternKind::BindingIdentifier(identifier): &BindingPatternKind<'_> =
            &declarator.id.kind
        else {
            return;
        };
        self.register_alias(identifier.name.as_str());
    }

    fn register_assignment_alias(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'_>) {
        if !expression_is_global_object_or_alias(&assignment.right, &self.aliases) {
            return;
        }
        let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier):
            &oxc_ast::ast::AssignmentTarget<'_> = &assignment.left
        else {
            return;
        };
        self.register_alias(identifier.name.as_str());
    }
}

impl<'a> Visit<'a> for GlobalWriteVisitor<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        if self.span_is_excluded(kind.span()) {
            return;
        }
        match kind {
            AstKind::CallExpression(call) if is_safe_global_function_constructor(call) => {
                self.register_safe_dynamic_reference(call);
            }
            AstKind::CallExpression(call)
                if is_function_literal_constructor_call(call)
                    && self.dynamic_call_is_in_target_scope(call.span) =>
            {
                self.found = true;
            }
            AstKind::BindingIdentifier(identifier) if identifier.name == "eval" => {
                self.found = true;
            }
            AstKind::IdentifierReference(identifier) if identifier.name == "eval" => {
                self.found = true;
            }
            AstKind::MemberExpression(member) if is_statically_named_member(member, "eval") => {
                self.found = true;
            }
            AstKind::BindingIdentifier(identifier) if identifier.name == "Function" => {
                self.found = true;
            }
            AstKind::IdentifierReference(identifier)
                if identifier.name == "Function"
                    && !self.dynamic_reference_is_safe(identifier.span) =>
            {
                self.found = true;
            }
            AstKind::MemberExpression(member) if is_statically_named_member(member, "Function") => {
                self.found = true;
            }
            AstKind::BindingIdentifier(identifier)
                if self.reject_binding && identifier.name == self.property_name =>
            {
                self.found = true;
            }
            AstKind::VariableDeclarator(declarator) => {
                self.register_declarator_alias(declarator);
            }
            AstKind::ArrayExpression(array)
                if array_contains_global_object(array, &self.aliases) =>
            {
                self.found = true;
            }
            AstKind::ObjectExpression(object)
                if object_contains_global_object(object, &self.aliases) =>
            {
                self.found = true;
            }
            AstKind::AssignmentExpression(assignment) => {
                self.register_assignment_alias(assignment);
                let identifier_write: bool = self.reject_binding
                    && matches!(
                        &assignment.left,
                        oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier)
                            if identifier.name == self.property_name
                    );
                let member_write: bool = assignment.left.as_member_expression().is_some_and(
                    |member: &MemberExpression<'_>| {
                        is_named_write_member(member, self.property_name)
                            && (!self.global_receiver_only
                                || expression_is_global_object_or_alias(
                                    member.object(),
                                    &self.aliases,
                                ))
                    },
                );
                if identifier_write || member_write {
                    self.found = true;
                }
            }
            AstKind::UpdateExpression(update) => {
                let identifier_write: bool = self.reject_binding
                    && update.argument.get_identifier() == Some(self.property_name);
                let member_write: bool = update.argument.as_member_expression().is_some_and(
                    |member: &MemberExpression<'_>| {
                        is_named_write_member(member, self.property_name)
                            && (!self.global_receiver_only
                                || expression_is_global_object_or_alias(
                                    member.object(),
                                    &self.aliases,
                                ))
                    },
                );
                if identifier_write || member_write {
                    self.found = true;
                }
            }
            AstKind::UnaryExpression(unary) if unary.operator.as_str() == "delete" => {
                let identifier_write: bool = self.reject_binding
                    && expression_is_identifier(&unary.argument, self.property_name);
                let member_write: bool = unary.argument.get_member_expr().is_some_and(
                    |member: &MemberExpression<'_>| {
                        is_named_write_member(member, self.property_name)
                            && (!self.global_receiver_only
                                || expression_is_global_object_or_alias(
                                    member.object(),
                                    &self.aliases,
                                ))
                    },
                );
                if identifier_write || member_write {
                    self.found = true;
                }
            }
            AstKind::MemberExpression(member) if is_reflective_mutation_primitive(member) => {
                self.found = true;
            }
            AstKind::CallExpression(call)
                if is_reflective_property_write(call, self.property_name)
                    && (!self.global_receiver_only
                        || call
                            .arguments
                            .first()
                            .and_then(Argument::as_expression)
                            .is_some_and(|target: &Expression<'_>| {
                                expression_is_global_object_or_alias(target, &self.aliases)
                            })) =>
            {
                self.found = true;
            }
            AstKind::CallExpression(call)
                if call_receives_global_object(call, &self.aliases)
                    && !is_proven_once_wrapper_setup_call(self.source, call) =>
            {
                self.found = true;
            }
            _ => {}
        }
    }
}

fn has_global_property_mutation_or_escape(
    source: &str,
    property_name: &str,
    reject_binding: bool,
    global_receiver_only: bool,
    excluded: Option<(usize, usize)>,
    target_position: usize,
) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return true;
    }
    let mut span_visitor: FunctionSpanVisitor<'_> = FunctionSpanVisitor {
        source,
        spans: Vec::new(),
        declarations: Vec::new(),
        calls: Vec::new(),
        aliases: Vec::new(),
    };
    span_visitor.visit_program(&parsed.program);
    let function_spans: Vec<(usize, usize)> = deferred_function_spans(
        target_position,
        &span_visitor.spans,
        &span_visitor.declarations,
        &span_visitor.calls,
        &span_visitor.aliases,
    );
    let mut visitor: GlobalWriteVisitor<'_> = GlobalWriteVisitor {
        source,
        property_name,
        reject_binding,
        global_receiver_only,
        excluded,
        aliases: Vec::new(),
        safe_dynamic_references: Vec::new(),
        function_spans,
        target_position,
        found: false,
    };
    visitor.visit_program(&parsed.program);
    visitor.found
}

fn has_global_timer_mutation_or_escape(source: &str, target_position: usize) -> bool {
    has_global_property_mutation_or_escape(
        source,
        "setInterval",
        false,
        false,
        None,
        target_position,
    )
}

fn interval_receiver<'a>(
    source: &'a str,
    bytes: &[u8],
    interval_start: usize,
) -> Option<(usize, &'a str)> {
    let mut cursor: usize = interval_start;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t' | b'\n' | b'\r') {
        cursor -= 1;
    }
    if cursor == 0 || bytes[cursor - 1] != b'.' {
        return None;
    }
    cursor -= 1;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t' | b'\n' | b'\r') {
        cursor -= 1;
    }
    let receiver_end: usize = cursor;
    while cursor > 0 && is_ident_byte(bytes[cursor - 1]) {
        cursor -= 1;
    }
    if cursor == receiver_end || (cursor > 0 && matches!(bytes[cursor - 1], b'.' | b'?' | b'#')) {
        return None;
    }
    let receiver: &str = &source[cursor..receiver_end];
    Some((cursor, receiver))
}

fn standalone_interval_statement_end(
    bytes: &[u8],
    statement_start: usize,
    call_close: usize,
) -> Option<usize> {
    let scope_start: usize = executable_enclosing_brace_start(bytes, statement_start)
        .map_or(0, |brace_open: usize| brace_open + 1);
    if executable_group_depth_at(bytes, statement_start)?
        != executable_group_depth_at(bytes, scope_start)?
    {
        return None;
    }
    let mut before: usize = statement_start;
    while before > 0 && matches!(bytes[before - 1], b' ' | b'\t' | b'\n' | b'\r') {
        before -= 1;
    }
    if before > 0 && !matches!(bytes[before - 1], b';' | b'{' | b'}') {
        return None;
    }
    let after: usize = skip_ws(bytes, call_close + 1);
    if bytes.get(after) == Some(&b';') {
        return Some(after + 1);
    }
    if after == bytes.len() || bytes.get(after) == Some(&b'}') {
        return Some(after);
    }
    None
}

fn mentions_executable_debugger(region: &str) -> bool {
    let bytes: &[u8] = region.as_bytes();
    let mut cursor: usize = 0;
    while cursor < region.len() {
        let Some(relative): Option<usize> = region[cursor..].find("debugger") else {
            break;
        };
        let start: usize = cursor + relative;
        let end: usize = start + "debugger".len();
        cursor = end;
        if (start > 0
            && (is_ident_byte(bytes[start - 1]) || matches!(bytes[start - 1], b'.' | b'?' | b'#')))
            || bytes.get(end).is_some_and(|byte: &u8| is_ident_byte(*byte))
            || !is_executable_code_position(bytes, start)
        {
            continue;
        }
        let statement_end: usize = skip_ws(bytes, end);
        if statement_end == bytes.len() || matches!(bytes.get(statement_end), Some(b';' | b'}')) {
            return true;
        }
    }
    false
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const CHECKER: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){const _0xc=_0xf?function(){if(_0xb){const _0xd=_0xb['apply'](_0xa,arguments);return _0xb=null,_0xd;}}:function(){};return _0xf=![],_0xc;};}()),_0xck=_0xwrap(this,function(){return _0xck['toString']()['search']('(((.+)+)+)+$')['toString']()['constructor'](_0xck)['search']('(((.+)+)+)+$');});_0xck();const keep=1;";

    const CHECKER_SHARING_CONST_WITH_A_DATA_TABLE_SIBLING: &str = "const bigTable={'a':1,'b':2},wrap=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}()),ck=wrap(this,function(){return ck.toString().search('(((.+)+)+)+$');});ck();console.log(bigTable.a);";

    #[test]
    fn checker_sharing_a_const_statement_with_a_live_sibling_table_is_kept() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(CHECKER_SHARING_CONST_WITH_A_DATA_TABLE_SIBLING);
        assert!(
            out.contains("bigTable={"),
            "the sibling data table sharing the const keyword must survive because it is used after the checker: {out}"
        );
        assert!(
            out.contains("console.log(bigTable.a)"),
            "the real usage site must remain resolvable, not dangling: {out}"
        );
        assert_eq!(
            stats.checker_blocks, 0,
            "removing the checker here would delete bigTable's own declaration and leave console.log(bigTable.a) dangling"
        );
    }

    const DEDUPED_SECOND_LITERAL_CHECKER: &str = "const var_60=(function(){let var_61=!![];return function(var_62,var_63){const var_64=var_61?function(){if(var_63){const var_65=var_63.apply(var_62,arguments);return var_63=null,var_65;}}:function(){};return var_61=![],var_64;};}()),var_66=var_60(this,function(){return var_66.toString().search('(((.+)+)+)+$').toString().constructor(var_66).search(var_33.EOhGV);});var_66();const keep=1;";

    #[test]
    fn checker_with_object_transform_deduped_second_literal_is_removed() {
        let (out, names): (String, Vec<String>) =
            remove_checker_blocks(DEDUPED_SECOND_LITERAL_CHECKER);
        assert!(
            !out.contains("(((.+)+)+)+$"),
            "regex literal must be gone: {out}"
        );
        assert!(
            out.contains("const keep=1;"),
            "trailing code preserved: {out}"
        );
        assert_eq!(names, vec!["var_60".to_owned()]);
    }

    const CONSOLE_HIJACK: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){const _0xc=_0xf?function(){if(_0xb){const _0xd=_0xb.apply(_0xa,arguments);return _0xb=null,_0xd;}}:function(){};return _0xf=![],_0xc;};}()),_0xck=_0xwrap(this,function(){let _0xg;try{const _0xh=Function('return (function() {}.constructor(\"return this\")( ));');_0xg=_0xh();}catch(_0xi){_0xg=window;}const _0xj=_0xg.console=_0xg.console||{},_0xk=['log','warn','info','error','exception','table','trace'];for(let _0xl=0;_0xl<_0xk.length;_0xl++){const _0xm=_0xwrap.constructor.prototype.bind(_0xwrap),_0xn=_0xk[_0xl],_0xo=_0xj[_0xn]||_0xm;_0xm.__proto__=_0xwrap.bind(_0xwrap),_0xm.toString=_0xo.toString.bind(_0xo),_0xj[_0xn]=_0xm;}});_0xck();console.log('real');";

    #[test]
    fn console_output_hijack_payload_is_removed() {
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(CONSOLE_HIJACK);
        assert!(
            !out.contains(".console="),
            "console reassignment must be gone: {out}"
        );
        assert!(
            !out.contains("__proto__"),
            "prototype hijack must be gone: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(
            stats.checker_blocks, 1,
            "the combined wrapper+hijack declarator statement is removed as one checker block"
        );
    }

    const DISCARDED_CONSTRUCTOR_APPLY_WITH_DANGLING_PROXY_ARGS: &str = "function divide(a,b){const proxy={};proxy.op=function(x,y){return x===y;};if(proxy.op(b,0)){if(proxy.op('same','other'))(function(){return![];}['constructor'](KmPGMW.build(KmPGMW.debu,KmPGMW.gger)).apply(KmPGMW.target));else throw new Error('divide by zero');}return a/b;}console.log('real');";

    #[test]
    fn discarded_constructor_apply_call_is_removed_even_with_dangling_proxy_args() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(DISCARDED_CONSTRUCTOR_APPLY_WITH_DANGLING_PROXY_ARGS);
        assert!(
            !out.contains("KmPGMW"),
            "the discarded constructor+apply statement and its dangling proxy args must be gone: {out}"
        );
        assert!(
            out.contains("function divide(a,b)"),
            "the real divide function must survive: {out}"
        );
        assert!(
            out.contains("throw new Error('divide by zero')"),
            "the real throw branch must survive: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code after the function must survive: {out}"
        );
        assert_eq!(stats.discarded_constructor_calls, 1);
    }

    #[test]
    fn discarded_constructor_apply_as_unbraced_if_branch_keeps_valid_syntax() {
        let src: &str = "function f(cond){if(cond)(function(){return!![];}['constructor'](proxy.a(proxy.b,proxy.c)).call(proxy.d));else{real();}}";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert!(
            !out.contains("proxy"),
            "the discarded statement must be gone: {out}"
        );
        assert!(
            out.contains("if(cond);else{real();}") || out.contains("if(cond) ;else{real();}"),
            "the if-branch slot must be replaced with an empty statement, not deleted outright, or the else becomes a syntax error: {out}"
        );
        assert_eq!(stats.discarded_constructor_calls, 1);
    }

    const NESTED_INTEGRITY_INVOCATION_AND_RATCHET_FUNCTION: &str = "function add(a,b){return a+b;}function greet(name){const wrap=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}());(function(){wrap(this,function(){const r1=new RegExp('function *\\\\( *\\\\)'),r2=new RegExp('\\\\+\\\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)','i'),probe=ratchet('init');!r1.test(probe+'chain')||!r2.test(probe+'input')?probe('0'):ratchet();})();}());const banner='hi';return banner+' :: '+name;}function ratchet(seed){function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![];}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log(greet('real'));";

    #[test]
    fn nested_integrity_invocation_and_ratchet_function_are_removed() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(NESTED_INTEGRITY_INVOCATION_AND_RATCHET_FUNCTION);
        assert!(
            !out.contains("while (true) {}"),
            "ratchet loop must be gone: {out}"
        );
        assert!(
            !out.contains("function ratchet"),
            "ratchet function must be gone: {out}"
        );
        assert!(
            !out.contains("RegExp("),
            "integrity invocation must be gone: {out}"
        );
        assert!(
            !out.contains("ratchet("),
            "no dangling call site to the removed ratchet function may remain: {out}"
        );
        assert!(
            out.contains("console.log(greet('real'))"),
            "real code must survive: {out}"
        );
        assert!(
            out.contains("function add(a,b){return a+b;}"),
            "unrelated code preserved: {out}"
        );
        assert_eq!(stats.ratchet_functions, 1);
    }

    #[test]
    fn integrity_invocation_iife_preserves_observable_arguments() {
        let source: &str = "(function(){sink(this,print('live'),RegExp('').test(''))}());";
        let (out, removed): (String, usize) = remove_integrity_invocation_iifes(source, &[]);
        assert_eq!(out, source);
        assert_eq!(removed, 0);
    }

    #[test]
    fn integrity_invocation_iife_preserves_unproven_wrapper_calls() {
        let source: &str = "const w=(a,b)=>(b(),()=>{});(function(){w(this,function(){print('live');RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_eager_wrapper_lookalikes() {
        let source: &str = "const w=(function(){let f=true;return function(a,b){b();f=false;return function(){}}}());(function(){w(this,function(){print('live');RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_immediate_wrapper_side_effects() {
        let source: &str = "const w=(function(){let f=true;return function(a,b){print('live');return function(){b();f=false}}}());(function(){w(this,function(){RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_transformed_deferred_side_effects() {
        let source: &str = "const w=(function(){const outer={eq:function(x,y){return x===y}};let f=true;return function(a,b){const inner={eq:function(x,y){return outer.eq(x,y)}};if(outer.eq('a','b')){}else{const selected=f?function(){if(inner.eq('c','d')){}else{if(b){if(inner.eq('e','f')){}else{print('live');const result=b.apply(a,arguments);return b=null,result}}}}:function(){};return f=false,selected}}}());(function(){w(this,function(){RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_shadowed_once_wrapper_bindings() {
        let source: &str = "const w=(function(){let f=true;return function(a,b){let f=f?function(){if(b){let r=b.apply(a,arguments);return b=null,r}}:function(){};return f=false,f}}());(function(){w(this,function(){RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_checker_prefix_throw() {
        let source: &str = "const w=(function(){let f=true;return function(a,b){let c=f?function(){if(b){let r=b.apply(a,arguments);return b=null,r}}:function(){};return f=false,c}}());(function(){w(this,function(){throw 'live';RegExp('').test('')})()}());";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn integrity_invocation_iife_rejects_mutated_regexp() {
        let source: &str = "globalThis.RegExp=function(){throw 'live'};const w=(function(){let f=true;return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d}}:function(){};return f=false,c}}());(function(){w(this,function(){const r1=new RegExp('function *\\\\( *\\\\)'),r2=new RegExp('\\\\+\\\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)','i'),probe=ratchet('init');!r1.test(probe+'chain')||!r2.test(probe+'input')?probe('0'):ratchet()})()}());function ratchet(seed){function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![]}['constructor']('debugger').call('action'):function(){return![]}['constructor']('debugger').apply('stateObject');tick(++counter)}try{if(seed)return tick;else tick(0)}catch(e){}}";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    const RATCHET_FUNCTION_PRECEDED_BY_PROXY_TABLE: &str = "function ratchet(seed){const table={'a':function(x,y){return x===y;},'b':'divide by zero','c':function(x,y){return x/y;}};function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![]}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log('real');";

    #[test]
    fn integrity_invocation_iife_rejects_indirect_eval_regexp_mutation() {
        let source: String = format!(
            "const g=(1,eval)('this');g.RegExp=function(){{throw 'live'}};{NESTED_INTEGRITY_INVOCATION_AND_RATCHET_FUNCTION}"
        );
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(&source);
        assert_eq!(out, source);
        assert_eq!(stats.checker_blocks, 0);
    }

    #[test]
    fn regexp_guard_accepts_inert_hybrid_wrapper_setup() {
        let source: &str = "const w=(function(){let f=true;return function(a,b){const p={'eq':function(x,y){return x===y}};if('same'!=='same'){b()}else{const c=f?function(){if(b){return b.apply(a,arguments)}}:function(){};return f=false,c}}}());w(this,function(){RegExp('')});";
        assert!(!has_global_property_mutation_or_escape(
            source,
            "RegExp",
            true,
            true,
            None,
            source.len(),
        ));
    }

    #[test]
    fn ratchet_function_preceded_by_object_transform_proxy_table_is_removed() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(RATCHET_FUNCTION_PRECEDED_BY_PROXY_TABLE);
        assert!(
            !out.contains("while (true) {}"),
            "ratchet loop must be gone: {out}"
        );
        assert!(
            !out.contains("function ratchet"),
            "whole ratchet function must be gone: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(stats.ratchet_functions, 1);
    }

    const RATCHET_FUNCTION_REFERENCED_BY_EXTERNAL_SETINTERVAL_CALLBACK: &str = "(function(){const timer=makeTimer();timer.setInterval(watchdog,4000);}());function watchdog(seed){function tick(counter){if(typeof counter==='string')return function(){}['constructor']('while (true) {}').apply('counter');else(''+counter/counter).length!==1||counter%20===0?function(){return!![]}['constructor']('debugger').call('action'):function(){return![];}['constructor']('debugger').apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(e){}}console.log('real');";

    const GLOBAL_RESOLVER_INTERVAL_RATCHET: &str = "(function(){const resolve=function(){let root;try{root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}catch(error){root=window}return root;};const root=resolve();root.setInterval(watchdog,4000);}());function watchdog(seed){function tick(counter){const table={'eq':function(a,b){return a===b;}};if((typeof counter==='string')){return function(value){}['constructor']('while (true) {}').apply('counter')}else((''+(counter/counter)).length!==1)||((counter%20)===0)?function(){return!![]}['constructor'](('debugger')).call('action'):function(){return![];}['constructor'](('debugger')).apply('stateObject');tick(++counter);}try{if(seed)return tick;else tick(0);}catch(error){}}console.log('real');";

    #[test]
    fn ratchet_function_referenced_by_external_setinterval_callback_is_kept() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(RATCHET_FUNCTION_REFERENCED_BY_EXTERNAL_SETINTERVAL_CALLBACK);
        assert!(
            out.contains("function watchdog"),
            "the outer ratchet-shaped function must survive because setInterval still holds a live reference to it by name: {out}"
        );
        assert!(
            out.contains("timer.setInterval(watchdog,4000)"),
            "the external callback reference must remain resolvable, not dangling: {out}"
        );
        assert!(
            out.contains("console.log('real')"),
            "real code must survive: {out}"
        );
        assert_eq!(
            stats.ratchet_functions, 0,
            "deleting watchdog here would leave the setInterval callback argument dangling"
        );
    }

    #[test]
    fn removes_global_resolver_interval_and_its_named_ratchet() {
        let source: &str = GLOBAL_RESOLVER_INTERVAL_RATCHET;
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
        assert!(
            !out.contains("setInterval"),
            "the debugger watchdog must not remain observable: {out}"
        );
        assert!(
            !out.contains("function watchdog"),
            "the unreferenced debugger ratchet must be removed: {out}"
        );
        assert!(out.contains("console.log('real')"), "real code kept: {out}");
        assert_eq!(stats.debug_ratchets, 1);
        assert_eq!(stats.ratchet_functions, 1);
    }

    #[test]
    fn removes_direct_global_receiver_without_leaving_dangling_syntax() {
        let (_, ratchet): (&str, &str) = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .split_once("function watchdog")
            .expect("ratchet fixture must contain its named function");
        let source: String =
            format!("window.setInterval(watchdog,4000);function watchdog{ratchet}");
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(&source);
        assert!(!out.contains("window."), "dangling receiver remains: {out}");
        assert!(out.contains("console.log('real')"), "real code kept: {out}");
        assert_eq!(stats.debug_ratchets, 1);
    }

    #[test]
    fn preserves_live_statements_in_global_resolver_iife() {
        let source: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "root.setInterval(watchdog,4000);",
            "console.log('before');root.setInterval(watchdog,4000);console.log('after');",
        );
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(&source);
        assert!(
            out.contains("console.log('before')"),
            "live prefix removed: {out}"
        );
        assert!(
            out.contains("console.log('after')"),
            "live suffix removed: {out}"
        );
        assert_eq!(stats.debug_ratchets, 1);
    }

    #[test]
    fn preserves_debugger_callback_on_custom_timer_receiver() {
        let source: &str =
            "const timer=makeTimer();timer.setInterval(function(){debugger;},4000);run();";
        let (out, removed): (String, usize) = remove_debug_ratchets(source);
        assert_eq!(out, source);
        assert_eq!(removed, 0);
    }

    #[test]
    fn preserves_global_interval_call_used_as_an_initializer() {
        let (_, ratchet): (&str, &str) = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .split_once("function watchdog")
            .expect("ratchet fixture must contain its named function");
        let source: String = format!(
            "const token=window.setInterval(watchdog,4000);console.log(token);function watchdog{ratchet}"
        );
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(&source);
        assert!(
            out.contains("const token=window.setInterval(watchdog,4000)"),
            "value-producing interval call removed: {out}"
        );
        assert!(
            out.contains("function watchdog"),
            "live interval callback removed: {out}"
        );
        assert_eq!(stats.debug_ratchets, 0);
    }

    #[test]
    fn preserves_setinterval_text_inside_string_and_regex_data() {
        const CASES: &[&str] = &[
            r#"const value=";setInterval(function(){debugger;},4000);";run();"#,
            r"const value=/;setInterval(function(){debugger;},4000);/;run();",
            r"function value(){return /;setInterval(function(){debugger;},4000);/;}run();",
            r"if(flag)/[;setInterval(function(){debugger;},4000);]/.test(value);",
            r"if(flag)work();else /;setInterval(function(){debugger;},4000);/.test(value);",
            r"do /;setInterval(function(){debugger;},4000);/.test(value);while(flag);",
            r"for(const value of /;setInterval(function(){debugger;},4000);/)work(value);",
            r"const present='key' in /;setInterval(function(){debugger;},4000);/;",
            r"class Value extends /;setInterval(function(){debugger;},4000);/.constructor{}",
            r"export default /;setInterval(function(){debugger;},4000);/;",
        ];
        for source in CASES {
            let (out, removed): (String, usize) = remove_debug_ratchets(source);
            assert_eq!(out, *source);
            assert_eq!(removed, 0);
        }
    }

    #[test]
    fn preserves_interval_outside_a_standalone_lexical_statement() {
        const CASES: &[&str] = &[
            "for(;setInterval(function(){debugger;},4000);tick())work();",
            "const timer={setInterval(){log('live')}};with(timer){setInterval(function(){debugger;},4000);}",
            "(function(set\\u0049nterval){setInterval(function(){debugger;},4000)})(customTimer);",
            "globalThis.setInterval=customTimer;setInterval(function(){debugger;},4000);",
            "globalThis['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "const g=globalThis;g['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "const g=[globalThis][0];g['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "const g=Function('return this')();g['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "const g=[]['filter']['constructor']('return this')();g['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "const g=(0,eval)('this');g['set'+'Interval']=function(){live()};setInterval(function(){debugger;},4000);",
            "eval('set'+'Interval=function(){throw 1};0');setInterval(function(){debugger},4000);",
            "Function('set'+'Interval=function(){throw 1};return 0')();setInterval(function(){debugger},4000);",
            "(()=>{}).constructor('set'+'Interval=function(){throw 1};return 0')();setInterval(function(){debugger},4000);",
            "(function(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()})();setInterval(function(){debugger},4000);",
            "function mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}mutate();setInterval(function(){debugger},4000);",
            "var mutate=function(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()};mutate();setInterval(function(){debugger},4000);",
            "function mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}var alias=mutate;alias();setInterval(function(){debugger},4000);",
            "var mutate;mutate=function(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()};mutate();setInterval(function(){debugger},4000);",
            "function mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}mutate.call();setInterval(function(){debugger},4000);",
            "function mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}(0,mutate)();setInterval(function(){debugger},4000);",
            "function Mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}new Mutate;setInterval(function(){debugger},4000);",
            "function mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}mutate``;setInterval(function(){debugger},4000);",
            "var holder={mutate(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}};holder.mutate();setInterval(function(){debugger},4000);",
            "var holders=[function(){(function(){}).constructor('set'+'Interval=function(){throw 1}')()}];holders[0]();setInterval(function(){debugger},4000);",
            "(function(g){g['set'+'Interval']=function(){live()}})(globalThis);setInterval(function(){debugger;},4000);",
            "Reflect.set(globalThis,'set'+'Interval',function(){live()});setInterval(function(){debugger;},4000);",
            "Reflect.set((0,eval)('this'),'set'+'Interval',function(){live()});setInterval(function(){debugger;},4000);",
            "const write=Reflect.set;write((0,eval)('this'),'set'+'Interval',function(){live()});setInterval(function(){debugger;},4000);",
            "Object.defineProperty(globalThis,'set'+'Interval',{value:function(){live()}});setInterval(function(){debugger;},4000);",
            "mutate();setInterval(function(){debugger;},4000);function mutate(){globalThis['set'+'Interval']=function(){live()}}",
            "globalThis.window.setInterval=customTimer;window.setInterval(function(){debugger;},4000);",
        ];
        for source in CASES {
            let (out, removed): (String, usize) = remove_debug_ratchets(source);
            assert_eq!(out, *source);
            assert_eq!(removed, 0);
        }
    }

    #[test]
    fn preserves_interval_when_global_constructor_is_hoisted() {
        const CASES: &[&str] = &[
            "(function(){const customTimer={setInterval(){print('live')}};const resolve=function(){let root;try{root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}catch(error){root=window}return root;};const root=resolve();root.setInterval(function(){debugger;},4000);function Function(){return function(){return customTimer}}}());",
            "(function(){const Funct\\u0069on=function(){return function(){return customTimer}};const resolve=function(){let root;try{root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}catch(error){root=window}return root;};const root=resolve();root.setInterval(function(){debugger;},4000);}());",
            "(function(){const customTimer={setInterval(){print('live')}};{Function=function(){return function(){return customTimer}}}const resolve=function(){let root;try{root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}catch(error){root=window}return root;};const root=resolve();root.setInterval(function(){debugger;},4000)}());",
            "(function(){const customTimer={setInterval(){print('live')}};globalThis.Function=function(){return function(){return customTimer}};const resolve=function(){let root;try{root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}catch(error){root=window}return root;};const root=resolve();root.setInterval(function(){debugger;},4000)}());",
            "(function(){const resolve=function(){let root;if(false){root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()}if(false){root=window}return root;};const root=resolve();root.setInterval(function(){debugger;},4000)}());",
        ];
        for source in CASES {
            let (out, removed): (String, usize) = remove_debug_ratchets(source);
            assert_eq!(out, *source);
            assert_eq!(removed, 0);
        }
    }

    #[test]
    fn preserves_custom_timer_inside_global_resolver_iife() {
        let source: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "const root=resolve();const timer=makeTimer();timer.setInterval(watchdog,4000);",
        );
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(&source);
        assert!(
            out.contains("timer.setInterval(watchdog,4000)"),
            "custom timer call removed: {out}"
        );
        assert!(
            out.contains("function watchdog"),
            "live custom timer callback removed: {out}"
        );
        assert_eq!(stats.debug_ratchets, 0);
    }

    #[test]
    fn preserves_interval_when_resolver_bindings_are_object_properties() {
        let property_bound_receiver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "holder.root=resolve();root.setInterval(watchdog,4000);",
        );
        let property_bound_resolver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .replace("const resolve=function()", "holder.resolve=function()");
        let cases: [String; 2] = [property_bound_receiver, property_bound_resolver];
        for source in &cases {
            let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
            assert!(
                out.contains("setInterval(watchdog,4000)"),
                "property binding must not prove a local resolver: {out}"
            );
            assert!(
                out.contains("function watchdog"),
                "live callback must survive an unproven resolver: {out}"
            );
            assert_eq!(stats.debug_ratchets, 0);
        }
    }

    #[test]
    fn preserves_interval_when_global_bindings_are_shadowed() {
        let shadowed_resolver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "{const resolve=makeTimer;const root=resolve();root.setInterval(watchdog,4000);}",
        );
        let shadowed_window: String = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .replace("const resolve=function()", "const resolve=function(window)");
        let shadowed_function: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const resolve=function()",
            "const resolve=function(Function)",
        );
        let reassigned_receiver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "let root=resolve();root=customTimer;root.setInterval(watchdog,4000);",
        );
        let sibling_scope_receiver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "{const root=resolve();}{let root;root.setInterval(watchdog,4000);}",
        );
        let destructured_receiver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "let root=resolve();({root}=customTimer);root.setInterval(watchdog,4000);",
        );
        let custom_return_resolver: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "return root;};const root=resolve()",
            "return customTimer;};const root=resolve()",
        );
        let conditional_custom_return: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "return root;};const root=resolve()",
            "if(chooseCustom)return customTimer;return root;};const root=resolve()",
        );
        let misleading_function_source: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "root=Function((('return (function() {}.constructor(\"return this\")( )')+');'))()",
            "note='return this';root=Function('return customTimer')()",
        );
        let (_, ratchet): (&str, &str) = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .split_once("function watchdog")
            .expect("ratchet fixture must contain its named function");
        let shadowed_timer: String = format!(
            "function run(setInterval){{setInterval(watchdog,4000);}}run(makeTimer());function watchdog{ratchet}"
        );
        let shadowed_receiver: String = format!(
            "function run(window){{window.setInterval(watchdog,4000);}}run(makeTimer());function watchdog{ratchet}"
        );
        let shadowed_callback: String = format!(
            "function run(watchdog){{window.setInterval(watchdog,4000);}}run(tick);function watchdog{ratchet}"
        );
        let sibling_scope_callback: String =
            format!("{{function watchdog{ratchet}}}{{window.setInterval(watchdog,4000);}}");
        let dangling_else_resolver: String = format!(
            "(function(){{const resolve=function(){{if(('left'==='right'))if(flag)return customTimer;else{{let root;try{{root=Function((('return (function() {{}}.constructor(\"return this\")( )')+');'))()}}catch(error){{root=window}}return root;}}}};const root=resolve();root.setInterval(watchdog,4000);}}());function watchdog{ratchet}"
        );
        let conditional_receiver_assignment: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "const root=resolve();root.setInterval(watchdog,4000);",
            "let root=customTimer;if(false)root=resolve();root.setInterval(watchdog,4000);",
        );
        let shadowed_outer_function: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "(function(){const resolve=function()",
            "(function(){const Function=function(){return function(){return customTimer;};};const resolve=function()",
        );
        let dynamic_callback_binding: String = format!(
            "with({{['watch'+'dog']:realCallback}}){{window.setInterval(watchdog,4000);}}function watchdog{ratchet}"
        );
        let defaulted_callback_parameter: String = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .replace("function watchdog(seed)", "function watchdog(seed=live())");
        let compound_resolver_initializer: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "return root;};const root=resolve()",
            "return root;}&&function(){return customTimer};const root=resolve()",
        );
        let live_named_callback_prefix: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "function watchdog(seed){function tick",
            "function watchdog(seed){live();function tick",
        );
        let live_inner_dispatcher: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "function tick(counter){const table",
            "function tick(counter){live();const table",
        );
        let live_catch_binding: String = GLOBAL_RESOLVER_INTERVAL_RATCHET.replace(
            "catch(error){}}console.log",
            "catch({missing=live()}){}}console.log",
        );
        let accessor_backed_callback_guard: String = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .replacen(
                "(function(){",
                "Object.defineProperty(globalThis,'probe',{get(){live();return false;}});(function(){",
                1,
            )
            .replace("if(seed)return tick", "if(probe)return tick");
        let async_callback: String = GLOBAL_RESOLVER_INTERVAL_RATCHET
            .replace("function watchdog(seed)", "async function watchdog(seed)");
        let mutated_resolved_global: String = format!(
            "globalThis['set'+'Interval']=function(){{live()}};{GLOBAL_RESOLVER_INTERVAL_RATCHET}"
        );
        let cases: [String; 25] = [
            shadowed_resolver,
            shadowed_window,
            shadowed_function,
            reassigned_receiver,
            sibling_scope_receiver,
            destructured_receiver,
            custom_return_resolver,
            conditional_custom_return,
            misleading_function_source,
            dangling_else_resolver,
            shadowed_timer,
            shadowed_receiver,
            shadowed_callback,
            sibling_scope_callback,
            conditional_receiver_assignment,
            shadowed_outer_function,
            dynamic_callback_binding,
            defaulted_callback_parameter,
            compound_resolver_initializer,
            live_named_callback_prefix,
            live_inner_dispatcher,
            live_catch_binding,
            accessor_backed_callback_guard,
            async_callback,
            mutated_resolved_global,
        ];
        for source in &cases {
            let (out, stats): (String, SelfDefendingStats) = strip_self_defending(source);
            assert!(
                out.contains("setInterval(watchdog,4000)"),
                "shadowed timer call must survive: {out}"
            );
            assert!(
                out.contains("function watchdog"),
                "shadowed timer callback must survive: {out}"
            );
            assert_eq!(stats.debug_ratchets, 0);
        }
    }

    const REAL_FUNCTION_WITH_ANONYMOUS_ONCE_WRAPPERS_IS_NOT_A_RATCHET: &str = "function greet(name){const table={'a':function(x,y){return x+y;},'b':' :: hi, '};const once=(function(){let f=!![];return function(a,b){const c=f?function(){if(b){const d=b.apply(a,arguments);return b=null,d;}}:function(){};return f=![],c;};}());const guard=table.a(once,this,function(){return guard.toString();});table.a(guard);const banner=table.a('calc',table.b);return table.a(banner,name);}";

    #[test]
    fn real_function_with_only_anonymous_once_wrappers_is_not_removed_as_a_ratchet() {
        let (out, stats): (String, SelfDefendingStats) =
            strip_self_defending(REAL_FUNCTION_WITH_ANONYMOUS_ONCE_WRAPPERS_IS_NOT_A_RATCHET);
        assert_eq!(
            stats.ratchet_functions, 0,
            "a function whose only nested closures are anonymous once-wrappers, not a named self-recursive dispatcher, must never be deleted whole: {out}"
        );
        assert!(
            out.contains("function greet(name)"),
            "the real function declaration must survive: {out}"
        );
    }

    #[test]
    fn removes_checker_invocation_and_decl() {
        let (out, names): (String, Vec<String>) = remove_checker_blocks(CHECKER);
        assert!(
            !out.contains("(((.+)+)+)+$"),
            "regex literal must be gone: {out}"
        );
        assert!(
            !out.contains("_0xck()"),
            "bare invocation must be gone: {out}"
        );
        assert!(
            out.contains("const keep=1;"),
            "trailing code preserved: {out}"
        );
        assert_eq!(names, vec!["_0xwrap".to_owned()]);
    }

    #[test]
    fn full_strip_removes_wrapper_too() {
        let src: &str = "const _0xwrap=(function(){let _0xf=!![];return function(_0xa,_0xb){const _0xselected=_0xf?function(){if(_0xb){const _0xresult=_0xb.apply(_0xa,arguments);return _0xb=null,_0xresult;}}:function(){};return _0xf=![],_0xselected;};}());const _0xck=_0xwrap(this,function(){return _0xck['toString']()['search']('(((.+)+)+)+$');});_0xck();work();";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert!(!out.contains("(((.+)+)+)+$"), "checker gone: {out}");
        assert!(!out.contains("_0xwrap"), "wrapper gone: {out}");
        assert!(out.contains("work();"), "real code kept: {out}");
        assert_eq!(stats.checker_blocks, 1);
        assert_eq!(stats.once_wrappers, 1);
    }

    #[test]
    fn leaves_unrelated_code_untouched() {
        let src: &str = "function add(a,b){return a+b;}const s='value';add(1,2);";
        let (out, stats): (String, SelfDefendingStats) = strip_self_defending(src);
        assert_eq!(out, src);
        assert_eq!(stats.checker_blocks, 0);
        assert_eq!(stats.once_wrappers, 0);
    }

    #[test]
    fn strips_setinterval_debugger_ratchet() {
        let src: &str = "start();setInterval(function(){debugger;},4000);end();";
        let (out, n): (String, usize) = remove_debug_ratchets(src);
        assert_eq!(n, 1);
        assert!(!out.contains("setInterval"), "{out}");
        assert!(out.contains("start();"));
        assert!(out.contains("end();"));
    }

    #[test]
    fn does_not_remove_benign_setinterval() {
        const CASES: &[&str] = &[
            "setInterval(function(){tick();},1000);",
            "setInterval(function(){console.log('debugger');},4000);",
            "setInterval(function(){return /debugger/.test(value);},4000);",
            "setInterval(function(){/* debugger */tick();},4000);",
            "setInterval(function(){return {debugger: true};},4000);",
            "setInterval(function(){live();debugger;},4000);",
            "setInterval(function(){debugger;live();},4000);",
            "setInterval(function*(){debugger;},4000);",
            "setInterval(function(value=live()){debugger;},4000);",
            "window.setInterval(realCallback,4000,function(){debugger;});",
            "window.setInterval(function(){debugger;},getDelay());",
            "window.setInterval((getCallback(),function(){debugger;}),4000);",
            "window.setInterval(function(){debugger;},4000,getExtra());",
        ];
        for source in CASES {
            let (out, removed): (String, usize) = remove_debug_ratchets(source);
            assert_eq!(removed, 0);
            assert_eq!(out, *source);
        }
    }
}
