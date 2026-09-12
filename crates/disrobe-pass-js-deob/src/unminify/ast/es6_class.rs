use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, Expression, Function, MemberExpression, ObjectPropertyKind, Program, PropertyKey,
    PropertyKind, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ClassRecoveryStats {
    pub(super) babel_helper: usize,
    pub(super) prototype: usize,
    pub(super) with_extends: usize,
    pub(super) static_members: usize,
    pub(super) accessors: usize,
}

struct MethodPiece {
    is_static: bool,
    kind: MethodKind,
    name: String,
    params_src: String,
    body_src: String,
    is_async: bool,
    is_generator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodKind {
    Normal,
    Get,
    Set,
}

struct ClassPlan {
    name: String,
    super_name: Option<String>,
    constructor: Option<(String, String)>,
    methods: Vec<MethodPiece>,
    replace_span: Span,
    is_babel: bool,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ClassRecoveryStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ClassRecoveryStats::default());
    }
    let program: &Program<'_> = &parsed.program;
    let statements: &[Statement<'_>] = program.body.as_slice();

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ClassRecoveryStats = ClassRecoveryStats::default();
    let mut index: usize = 0;
    while index < statements.len() {
        if let Some((plan, consumed)) = match_class(source, statements, index) {
            let rendered: String = render_class(&plan);
            edits.push(Edit {
                start: plan.replace_span.start as usize,
                end: plan.replace_span.end as usize,
                replacement: rendered,
            });
            if plan.is_babel {
                stats.babel_helper += 1;
            } else {
                stats.prototype += 1;
            }
            if plan.super_name.is_some() {
                stats.with_extends += 1;
            }
            stats.static_members += plan.methods.iter().filter(|m| m.is_static).count();
            stats.accessors += plan
                .methods
                .iter()
                .filter(|m| matches!(m.kind, MethodKind::Get | MethodKind::Set))
                .count();
            index += consumed;
            continue;
        }
        index += 1;
    }

    (RuleOutcome { edits }, stats)
}

fn match_class(
    source: &str,
    statements: &[Statement<'_>],
    start: usize,
) -> Option<(ClassPlan, usize)> {
    let Statement::FunctionDeclaration(ctor): &Statement<'_> = &statements[start] else {
        return None;
    };
    let ctor_name: &str = ctor.id.as_ref()?.name.as_str();
    let ctor_body: &Function<'_> = ctor;

    if !function_has_class_call_check(ctor_body, ctor_name) {
        return match_prototype_class(source, statements, start, ctor_name, ctor_body);
    }
    match_babel_class(source, statements, start, ctor_name, ctor_body)
}

fn function_has_class_call_check(func: &Function<'_>, ctor_name: &str) -> bool {
    let Some(body): Option<&oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>>> =
        func.body.as_ref()
    else {
        return false;
    };
    body.statements
        .iter()
        .any(|stmt| stmt_is_class_call_check(stmt, ctor_name))
}

fn stmt_is_class_call_check(stmt: &Statement<'_>, ctor_name: &str) -> bool {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return false;
    };
    let Expression::CallExpression(call): &Expression<'_> = &expr_stmt.expression else {
        return false;
    };
    let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
        return false;
    };
    if callee.name.as_str() != "_classCallCheck" || call.arguments.len() != 2 {
        return false;
    }
    matches!(&call.arguments[1], Argument::Identifier(second) if second.name.as_str() == ctor_name)
}

fn statement_helper_call<'a, 'b>(
    stmt: &'b Statement<'a>,
) -> Option<&'b oxc_ast::ast::CallExpression<'a>> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return None;
    };
    let Expression::CallExpression(call): &Expression<'_> = &expr_stmt.expression else {
        return None;
    };
    Some(call)
}

fn match_babel_class(
    source: &str,
    statements: &[Statement<'_>],
    start: usize,
    ctor_name: &str,
    ctor_body: &Function<'_>,
) -> Option<(ClassPlan, usize)> {
    let mut super_name: Option<String> = None;
    let mut create_call_index: Option<usize> = None;
    let mut create_methods: Vec<MethodPiece> = Vec::new();

    let mut cursor: usize = start + 1;
    while cursor < statements.len() {
        let Some(call): Option<&oxc_ast::ast::CallExpression<'_>> =
            statement_helper_call(&statements[cursor])
        else {
            break;
        };
        let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
            break;
        };
        match callee.name.as_str() {
            "_inherits" => {
                super_name = Some(inherits_super(call, ctor_name)?);
            }
            "_createClass" => {
                create_methods = parse_create_class(source, call, ctor_name)?;
                create_call_index = Some(cursor);
            }
            _ => break,
        }
        cursor += 1;
    }

    let end_index: usize = create_call_index?;
    let constructor: Option<(String, String)> =
        babel_constructor(source, ctor_body, ctor_name, super_name.is_some());

    let replace_span: Span = Span::new(
        statements[start].span().start,
        statements[end_index].span().end,
    );

    Some((
        ClassPlan {
            name: ctor_name.to_owned(),
            super_name,
            constructor,
            methods: create_methods,
            replace_span,
            is_babel: true,
        },
        end_index - start + 1,
    ))
}

fn inherits_super(call: &oxc_ast::ast::CallExpression<'_>, ctor_name: &str) -> Option<String> {
    if call.arguments.len() != 2 {
        return None;
    }
    let Argument::Identifier(first): &Argument<'_> = &call.arguments[0] else {
        return None;
    };
    if first.name.as_str() != ctor_name {
        return None;
    }
    let Argument::Identifier(second): &Argument<'_> = &call.arguments[1] else {
        return None;
    };
    Some(second.name.as_str().to_owned())
}

fn parse_create_class(
    source: &str,
    call: &oxc_ast::ast::CallExpression<'_>,
    ctor_name: &str,
) -> Option<Vec<MethodPiece>> {
    if call.arguments.is_empty() {
        return None;
    }
    let Argument::Identifier(target): &Argument<'_> = &call.arguments[0] else {
        return None;
    };
    if target.name.as_str() != ctor_name {
        return None;
    }
    let mut methods: Vec<MethodPiece> = Vec::new();
    if let Some(proto_arg) = call.arguments.get(1) {
        collect_descriptor_array(source, proto_arg, false, &mut methods)?;
    }
    if let Some(static_arg) = call.arguments.get(2) {
        collect_descriptor_array(source, static_arg, true, &mut methods)?;
    }
    Some(methods)
}

fn collect_descriptor_array(
    source: &str,
    arg: &Argument<'_>,
    is_static: bool,
    out: &mut Vec<MethodPiece>,
) -> Option<()> {
    let Argument::ArrayExpression(array): &Argument<'_> = arg else {
        if matches!(arg, Argument::Identifier(_)) {
            return Some(());
        }
        return None;
    };
    for element in &array.elements {
        let oxc_ast::ast::ArrayExpressionElement::ObjectExpression(obj) = element else {
            return None;
        };
        let piece: MethodPiece = descriptor_to_method(source, obj, is_static)?;
        out.push(piece);
    }
    Some(())
}

fn descriptor_to_method(
    source: &str,
    obj: &oxc_ast::ast::ObjectExpression<'_>,
    is_static: bool,
) -> Option<MethodPiece> {
    let mut name: Option<String> = None;
    let mut value_func: Option<&Function<'_>> = None;
    let mut kind: MethodKind = MethodKind::Normal;

    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p): &ObjectPropertyKind<'_> = prop else {
            return None;
        };
        if p.kind != PropertyKind::Init {
            return None;
        }
        let key_name: &str = match &p.key {
            PropertyKey::StaticIdentifier(id) => id.name.as_str(),
            _ => return None,
        };
        match key_name {
            "key" => {
                name = string_literal_value(&p.value);
            }
            "value" => {
                if let Expression::FunctionExpression(func) = &p.value {
                    value_func = Some(func);
                } else {
                    return None;
                }
            }
            "get" => {
                if let Expression::FunctionExpression(func) = &p.value {
                    value_func = Some(func);
                    kind = MethodKind::Get;
                } else {
                    return None;
                }
            }
            "set" => {
                if let Expression::FunctionExpression(func) = &p.value {
                    value_func = Some(func);
                    kind = MethodKind::Set;
                } else {
                    return None;
                }
            }
            "enumerable" | "configurable" | "writable" => {}
            _ => return None,
        }
    }

    let method_name: String = name?;
    let func: &Function<'_> = value_func?;
    let (params_src, body_src): (String, String) = function_param_body(source, func)?;
    Some(MethodPiece {
        is_static,
        kind,
        name: method_name,
        params_src,
        body_src,
        is_async: func.r#async,
        is_generator: func.generator,
    })
}

fn string_literal_value(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::StringLiteral(lit) => Some(lit.value.as_str().to_owned()),
        _ => None,
    }
}

fn function_param_body(source: &str, func: &Function<'_>) -> Option<(String, String)> {
    let params_src: String = slice_params(source, func);
    let body: &oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>> = func.body.as_ref()?;
    let body_src: String = body.span.source_text(source).to_owned();
    Some((params_src, body_src))
}

fn slice_params(source: &str, func: &Function<'_>) -> String {
    let span: Span = func.params.span;
    let raw: &str = span.source_text(source);
    raw.trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_owned()
}

fn babel_constructor(
    source: &str,
    ctor: &Function<'_>,
    ctor_name: &str,
    has_super: bool,
) -> Option<(String, String)> {
    let body: &oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>> = ctor.body.as_ref()?;
    let params_src: String = slice_params(source, ctor);
    let mut kept: Vec<String> = Vec::new();
    for stmt in &body.statements {
        if stmt_is_class_call_check(stmt, ctor_name) {
            continue;
        }
        if let Some(super_call) = rewrite_super_return(source, stmt, ctor_name, has_super) {
            kept.push(super_call);
            continue;
        }
        kept.push(stmt.span().source_text(source).to_owned());
    }
    Some((params_src, wrap_block(&kept)))
}

fn rewrite_super_return(
    source: &str,
    stmt: &Statement<'_>,
    ctor_name: &str,
    has_super: bool,
) -> Option<String> {
    if !has_super {
        return None;
    }
    let Statement::ReturnStatement(ret): &Statement<'_> = stmt else {
        return None;
    };
    let arg: &Expression<'_> = ret.argument.as_ref()?;
    let Expression::CallExpression(call): &Expression<'_> = arg else {
        return None;
    };
    let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "_possibleConstructorReturn" {
        return None;
    }
    let inner: &Argument<'_> = call.arguments.get(1)?;
    let Argument::CallExpression(super_call): &Argument<'_> = inner else {
        return None;
    };
    let rendered_args: Vec<&str> = super_call
        .arguments
        .iter()
        .skip(1)
        .map(|argument| argument.span().source_text(source))
        .collect();
    let _ = ctor_name;
    Some(format!("super({});", rendered_args.join(", ")))
}

fn match_prototype_class(
    source: &str,
    statements: &[Statement<'_>],
    start: usize,
    ctor_name: &str,
    ctor_body: &Function<'_>,
) -> Option<(ClassPlan, usize)> {
    let mut methods: Vec<MethodPiece> = Vec::new();
    let mut super_name: Option<String> = None;
    let mut cursor: usize = start + 1;
    let mut last_consumed: usize = start;

    while cursor < statements.len() {
        let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = &statements[cursor] else {
            break;
        };
        let Expression::AssignmentExpression(assign): &Expression<'_> = &expr_stmt.expression
        else {
            break;
        };
        let Some(piece): Option<PrototypeAssign> =
            classify_prototype_assign(source, assign, ctor_name)
        else {
            break;
        };
        match piece {
            PrototypeAssign::Method(method) => methods.push(method),
            PrototypeAssign::Super(base) => {
                if super_name.is_some() {
                    return None;
                }
                super_name = Some(base);
            }
        }
        last_consumed = cursor;
        cursor += 1;
    }

    if methods.is_empty() {
        return None;
    }

    let constructor: Option<(String, String)> =
        prototype_constructor(source, ctor_body, super_name.as_deref());
    let replace_span: Span = Span::new(
        statements[start].span().start,
        statements[last_consumed].span().end,
    );

    Some((
        ClassPlan {
            name: ctor_name.to_owned(),
            super_name,
            constructor,
            methods,
            replace_span,
            is_babel: false,
        },
        last_consumed - start + 1,
    ))
}

enum PrototypeAssign {
    Method(MethodPiece),
    Super(String),
}

fn classify_prototype_assign(
    source: &str,
    assign: &oxc_ast::ast::AssignmentExpression<'_>,
    ctor_name: &str,
) -> Option<PrototypeAssign> {
    if assign.operator != oxc_ast::ast::AssignmentOperator::Assign {
        return None;
    }
    let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) = &assign.left else {
        return None;
    };
    let method_name: &str = member.property.name.as_str();
    let Expression::StaticMemberExpression(proto): &Expression<'_> = &member.object else {
        if let Some(base) = match_object_create_super(assign, ctor_name) {
            return Some(PrototypeAssign::Super(base));
        }
        return None;
    };
    if proto.property.name.as_str() != "prototype" {
        return None;
    }
    let Expression::Identifier(base): &Expression<'_> = &proto.object else {
        return None;
    };
    if base.name.as_str() != ctor_name {
        return None;
    }
    let Expression::FunctionExpression(func): &Expression<'_> = &assign.right else {
        return None;
    };
    if method_name == "constructor" {
        return None;
    }
    let (params_src, body_src): (String, String) = function_param_body(source, func)?;
    Some(PrototypeAssign::Method(MethodPiece {
        is_static: false,
        kind: MethodKind::Normal,
        name: method_name.to_owned(),
        params_src,
        body_src,
        is_async: func.r#async,
        is_generator: func.generator,
    }))
}

fn match_object_create_super(
    assign: &oxc_ast::ast::AssignmentExpression<'_>,
    ctor_name: &str,
) -> Option<String> {
    let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) = &assign.left else {
        return None;
    };
    if member.property.name.as_str() != "prototype" {
        return None;
    }
    let Expression::Identifier(target): &Expression<'_> = &member.object else {
        return None;
    };
    if target.name.as_str() != ctor_name {
        return None;
    }
    let Expression::CallExpression(call): &Expression<'_> = &assign.right else {
        return None;
    };
    let create_member: &MemberExpression<'_> = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(create): &MemberExpression<'_> = create_member
    else {
        return None;
    };
    if create.property.name.as_str() != "create" {
        return None;
    }
    let Expression::Identifier(object_ident): &Expression<'_> = &create.object else {
        return None;
    };
    if object_ident.name.as_str() != "Object" {
        return None;
    }
    let Argument::StaticMemberExpression(proto): &Argument<'_> = call.arguments.first()? else {
        return None;
    };
    if proto.property.name.as_str() != "prototype" {
        return None;
    }
    let Expression::Identifier(base): &Expression<'_> = &proto.object else {
        return None;
    };
    Some(base.name.as_str().to_owned())
}

fn prototype_constructor(
    source: &str,
    ctor: &Function<'_>,
    super_name: Option<&str>,
) -> Option<(String, String)> {
    let body: &oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>> = ctor.body.as_ref()?;
    let params_src: String = slice_params(source, ctor);
    let mut kept: Vec<String> = Vec::with_capacity(body.statements.len());
    for stmt in &body.statements {
        if let Some(base) = super_name
            && let Some(super_call) = rewrite_base_call_super(source, stmt, base)
        {
            kept.push(super_call);
            continue;
        }
        kept.push(stmt.span().source_text(source).to_owned());
    }
    if super_name.is_some() && !kept.iter().any(|s| s.starts_with("super(")) {
        return None;
    }
    if kept.is_empty() && params_src.is_empty() {
        return None;
    }
    Some((params_src, wrap_block(&kept)))
}

fn rewrite_base_call_super(source: &str, stmt: &Statement<'_>, base: &str) -> Option<String> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return None;
    };
    let Expression::CallExpression(call): &Expression<'_> = &expr_stmt.expression else {
        return None;
    };
    let member: &MemberExpression<'_> = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(call_member): &MemberExpression<'_> = member
    else {
        return None;
    };
    if call_member.property.name.as_str() != "call" {
        return None;
    }
    let Expression::Identifier(base_ident): &Expression<'_> = &call_member.object else {
        return None;
    };
    if base_ident.name.as_str() != base {
        return None;
    }
    let Some(Argument::ThisExpression(_)): Option<&Argument<'_>> = call.arguments.first() else {
        return None;
    };
    let rendered_args: Vec<&str> = call
        .arguments
        .iter()
        .skip(1)
        .map(|argument| argument.span().source_text(source))
        .collect();
    Some(format!("super({});", rendered_args.join(", ")))
}

fn wrap_block(statements: &[String]) -> String {
    if statements.is_empty() {
        return "{}".to_owned();
    }
    let mut out: String = String::from("{\n");
    for stmt in statements {
        out.push_str("    ");
        out.push_str(stmt.trim());
        out.push('\n');
    }
    out.push_str("  }");
    out
}

fn render_class(plan: &ClassPlan) -> String {
    let mut out: String = String::with_capacity(128);
    out.push_str("class ");
    out.push_str(&plan.name);
    if let Some(base) = plan.super_name.as_ref() {
        out.push_str(" extends ");
        out.push_str(base);
    }
    out.push_str(" {\n");

    if let Some((params, body)) = plan.constructor.as_ref() {
        out.push_str("  constructor(");
        out.push_str(params);
        out.push_str(") ");
        out.push_str(&reindent_body(body));
        out.push('\n');
    }

    for method in &plan.methods {
        out.push_str("  ");
        if method.is_static {
            out.push_str("static ");
        }
        if method.is_async {
            out.push_str("async ");
        }
        match method.kind {
            MethodKind::Get => out.push_str("get "),
            MethodKind::Set => out.push_str("set "),
            MethodKind::Normal => {}
        }
        if method.is_generator {
            out.push('*');
        }
        out.push_str(&method.name);
        out.push('(');
        out.push_str(&method.params_src);
        out.push_str(") ");
        out.push_str(&reindent_body(&method.body_src));
        out.push('\n');
    }

    out.push('}');
    out
}

fn reindent_body(body: &str) -> String {
    let trimmed: &str = body.trim();
    if trimmed.is_empty() {
        return "{}".to_owned();
    }
    trimmed.to_owned()
}
