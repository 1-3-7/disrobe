use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    BinaryOperator, BindingPatternKind, Expression, ForStatement, ForStatementInit, Statement,
    TryStatement, UnaryOperator, UpdateOperator, VariableDeclaration, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ForOfStats {
    pub(super) loops_converted: usize,
    pub(super) helper_loops_converted: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ForOfStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ForOfStats::default());
    }

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
        helper_loops_converted: 0,
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), ForOfStats::default());
    }
    let helper_loops_converted: usize = collector.helper_loops_converted;
    let loops_converted: usize = collector.edits.len() - helper_loops_converted;
    (
        RuleOutcome {
            edits: collector.edits,
        },
        ForOfStats {
            loops_converted,
            helper_loops_converted,
        },
    )
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
    helper_loops_converted: usize,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_for_statement(&mut self, for_stmt: &ForStatement<'a>) {
        if let Some(edit) = try_convert(for_stmt, self.source) {
            self.edits.push(edit);
            return;
        }
        if let Some(edit) = try_convert_direct(for_stmt, self.source) {
            self.edits.push(edit);
            return;
        }
        oxc_ast::visit::walk::walk_for_statement(self, for_stmt);
    }

    fn visit_statements(&mut self, statements: &oxc_allocator::Vec<'a, Statement<'a>>) {
        let slice: &[Statement<'a>] = statements.as_slice();
        let mut index: usize = 0;
        while index < slice.len() {
            if let Some(values_edits) = try_convert_values_at(slice, index, self.source) {
                self.edits.extend(values_edits);
                self.helper_loops_converted += 1;
                index += 1;
                continue;
            }
            if index + 1 < slice.len()
                && let Some((edit, consumed)) =
                    try_convert_helper_sequence(&slice[index..], self.source)
            {
                self.edits.push(edit);
                self.helper_loops_converted += 1;
                index += consumed;
                continue;
            }
            oxc_ast::visit::walk::walk_statement(self, &slice[index]);
            index += 1;
        }
    }
}

struct Match<'a> {
    iterable: &'a Expression<'a>,
    element_kind: VariableDeclarationKind,
    element_name: &'a str,
    remaining: &'a [Statement<'a>],
    index_name: &'a str,
    array_name: &'a str,
}

fn try_convert(for_stmt: &ForStatement<'_>, source: &str) -> Option<Edit> {
    let m: Match<'_> = match_loop(for_stmt)?;
    if body_uses(m.remaining, m.index_name) || body_uses(m.remaining, m.array_name) {
        return None;
    }
    let kind: &str = if m.element_kind == VariableDeclarationKind::Var {
        "var"
    } else if body_reassigns(m.remaining, m.element_name) {
        "let"
    } else {
        "const"
    };
    let iterable_src: &str = m.iterable.span().source_text(source);
    let body_src: String = remaining_body_source(m.remaining, source);
    Some(Edit {
        start: for_stmt.span.start as usize,
        end: for_stmt.span.end as usize,
        replacement: format!(
            "for ({kind} {name} of {iterable_src}) {{{body_src}}}",
            name = m.element_name
        ),
    })
}

struct DirectMatch<'a> {
    iterable: &'a Expression<'a>,
    element_kind: VariableDeclarationKind,
    element_name: &'a str,
    remaining: &'a [Statement<'a>],
    index_name: &'a str,
    length_cache_name: Option<&'a str>,
}

fn try_convert_direct(for_stmt: &ForStatement<'_>, source: &str) -> Option<Edit> {
    let m: DirectMatch<'_> = match_direct_loop(for_stmt, source)?;
    if body_uses(m.remaining, m.index_name) {
        return None;
    }
    if let Some(cache) = m.length_cache_name
        && body_uses(m.remaining, cache)
    {
        return None;
    }
    let kind: &str = if m.element_kind == VariableDeclarationKind::Var {
        "var"
    } else if body_reassigns(m.remaining, m.element_name) {
        "let"
    } else {
        "const"
    };
    let iterable_src: &str = m.iterable.span().source_text(source);
    let body_src: String = remaining_body_source(m.remaining, source);
    Some(Edit {
        start: for_stmt.span.start as usize,
        end: for_stmt.span.end as usize,
        replacement: format!(
            "for ({kind} {name} of {iterable_src}) {{{body_src}}}",
            name = m.element_name
        ),
    })
}

fn match_direct_loop<'a>(for_stmt: &'a ForStatement<'a>, source: &str) -> Option<DirectMatch<'a>> {
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_stmt.init else {
        return None;
    };
    let index_name: &str = declarator_name(init, 0)?;
    if !is_zero(init.declarations[0].init.as_ref()?) {
        return None;
    }
    if !matches_update(for_stmt.update.as_ref()?, index_name) {
        return None;
    }

    let Statement::BlockStatement(block) = &for_stmt.body else {
        return None;
    };
    let first: &Statement<'_> = block.body.first()?;
    let remaining: &[Statement<'_>] = &block.body.as_slice()[1..];

    let (iterable, element_kind, element_name, length_cache_name): (
        &Expression<'_>,
        VariableDeclarationKind,
        &str,
        Option<&str>,
    ) = match init.declarations.len() {
        1 => {
            let iterable: &Expression<'_> =
                test_length_object(for_stmt.test.as_ref()?, index_name)?;
            let iterable_src: &str = iterable.span().source_text(source);
            let (kind, name): (VariableDeclarationKind, &str) =
                element_from_iterable_access(first, iterable_src, index_name, source)?;
            (iterable, kind, name, None)
        }
        2 => {
            let cache_name: &str = declarator_name(init, 1)?;
            let iterable: &Expression<'_> =
                length_init_object(init.declarations[1].init.as_ref()?)?;
            if !matches_cache_test(for_stmt.test.as_ref()?, index_name, cache_name) {
                return None;
            }
            let iterable_src: &str = iterable.span().source_text(source);
            let (kind, name): (VariableDeclarationKind, &str) =
                element_from_iterable_access(first, iterable_src, index_name, source)?;
            (iterable, kind, name, Some(cache_name))
        }
        _ => return None,
    };

    Some(DirectMatch {
        iterable,
        element_kind,
        element_name,
        remaining,
        index_name,
        length_cache_name,
    })
}

fn test_length_object<'a>(
    test: &'a Expression<'a>,
    index_name: &str,
) -> Option<&'a Expression<'a>> {
    let Expression::BinaryExpression(bin) = test else {
        return None;
    };
    if bin.operator != BinaryOperator::LessThan {
        return None;
    }
    if !matches!(&bin.left, Expression::Identifier(id) if id.name == index_name) {
        return None;
    }
    let Expression::StaticMemberExpression(member) = &bin.right else {
        return None;
    };
    if member.property.name != "length" {
        return None;
    }
    Some(&member.object)
}

fn matches_cache_test(test: &Expression<'_>, index_name: &str, cache_name: &str) -> bool {
    let Expression::BinaryExpression(bin) = test else {
        return false;
    };
    if bin.operator != BinaryOperator::LessThan {
        return false;
    }
    if !matches!(&bin.left, Expression::Identifier(id) if id.name == index_name) {
        return false;
    }
    matches!(&bin.right, Expression::Identifier(id) if id.name == cache_name)
}

fn length_init_object<'a>(init: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    let Expression::StaticMemberExpression(member) = init else {
        return None;
    };
    if member.property.name != "length" {
        return None;
    }
    Some(&member.object)
}

fn element_from_iterable_access<'a>(
    stmt: &'a Statement<'a>,
    iterable_src: &str,
    index_name: &str,
    source: &str,
) -> Option<(VariableDeclarationKind, &'a str)> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::ComputedMemberExpression(member) = init else {
        return None;
    };
    if member.object.span().source_text(source) != iterable_src {
        return None;
    }
    if !matches!(&member.expression, Expression::Identifier(id) if id.name == index_name) {
        return None;
    }
    Some((decl.kind, binding.name.as_str()))
}

fn match_loop<'a>(for_stmt: &'a ForStatement<'a>) -> Option<Match<'a>> {
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_stmt.init else {
        return None;
    };
    if init.declarations.len() != 2 {
        return None;
    }
    let index_name: &str = declarator_name(init, 0)?;
    if !is_zero(init.declarations[0].init.as_ref()?) {
        return None;
    }
    let array_name: &str = declarator_name(init, 1)?;
    let iterable: &Expression<'_> = init.declarations[1].init.as_ref()?;

    if !matches_test(for_stmt.test.as_ref()?, index_name, array_name) {
        return None;
    }
    if !matches_update(for_stmt.update.as_ref()?, index_name) {
        return None;
    }

    let Statement::BlockStatement(block) = &for_stmt.body else {
        return None;
    };
    let first: &Statement<'_> = block.body.first()?;
    let (element_kind, element_name): (VariableDeclarationKind, &str) =
        element_from_index_access(first, array_name, index_name)?;

    Some(Match {
        iterable,
        element_kind,
        element_name,
        remaining: &block.body.as_slice()[1..],
        index_name,
        array_name,
    })
}

struct HelperMatch<'a> {
    iterable: &'a Expression<'a>,
    element_kind: VariableDeclarationKind,
    element: ElementBinding<'a>,
    body: &'a [Statement<'a>],
    consumed_end: u32,
    sequence_start: u32,
    consumed_count: usize,
}

fn binding_kind(
    element_kind: VariableDeclarationKind,
    binding: &ElementBinding<'_>,
    body: &[Statement<'_>],
) -> &'static str {
    if element_kind == VariableDeclarationKind::Var {
        return "var";
    }
    if binding
        .bound_names
        .iter()
        .any(|name: &&str| body_reassigns(body, name))
    {
        "let"
    } else {
        "const"
    }
}

fn try_convert_helper_sequence(
    statements: &[Statement<'_>],
    source: &str,
) -> Option<(Edit, usize)> {
    let m: HelperMatch<'_> = match_helper_sequence(statements)?;
    let kind: &str = binding_kind(m.element_kind, &m.element, m.body);
    let iterable_src: &str = m.iterable.span().source_text(source);
    let body_src: String = remaining_body_source(m.body, source);
    let edit: Edit = Edit {
        start: m.sequence_start as usize,
        end: m.consumed_end as usize,
        replacement: format!(
            "for ({kind} {name} of {iterable_src}) {{{body_src}}}",
            name = m.element.text
        ),
    };
    Some((edit, m.consumed_count))
}

fn match_helper_sequence<'a>(statements: &'a [Statement<'a>]) -> Option<HelperMatch<'a>> {
    let Statement::VariableDeclaration(first_decl) = statements.first()? else {
        return None;
    };
    let sequence_start: u32 = first_decl.span.start;

    let (helper_name, iterable, step_name_from_decl, try_index): (
        &str,
        &Expression<'_>,
        Option<&str>,
        usize,
    ) = match first_decl.declarations.len() {
        2 => {
            let helper_name: &str = declarator_name(first_decl, 0)?;
            let iterable: &Expression<'_> =
                helper_call_argument(first_decl.declarations[0].init.as_ref()?)?;
            if first_decl.declarations[1].init.is_some() {
                return None;
            }
            let step_name: &str = declarator_name(first_decl, 1)?;
            (helper_name, iterable, Some(step_name), 1)
        }
        1 => {
            let helper_name: &str = declarator_name(first_decl, 0)?;
            let iterable: &Expression<'_> = first_decl.declarations[0]
                .init
                .as_ref()
                .and_then(helper_call_argument)?;
            (helper_name, iterable, None, 2)
        }
        _ => return None,
    };

    let step_name: &str = if let Some(name) = step_name_from_decl {
        name
    } else {
        let Statement::VariableDeclaration(step_decl) = statements.get(1)? else {
            return None;
        };
        if step_decl.declarations.len() != 1 || step_decl.declarations[0].init.is_some() {
            return None;
        }
        declarator_name(step_decl, 0)?
    };

    let Some(Statement::TryStatement(try_stmt)) = statements.get(try_index) else {
        return None;
    };
    let (element_kind, element, body): (
        VariableDeclarationKind,
        ElementBinding<'_>,
        &[Statement<'_>],
    ) = extract_helper_loop(try_stmt, helper_name, step_name)?;

    let tail: &[Statement<'_>] = statements.get(try_index + 1..).unwrap_or(&[]);
    if body_uses(tail, helper_name) || body_uses(tail, step_name) {
        return None;
    }

    Some(HelperMatch {
        iterable,
        element_kind,
        element,
        body,
        consumed_end: try_stmt.span.end,
        sequence_start,
        consumed_count: try_index + 1,
    })
}

fn try_convert_values_at(
    statements: &[Statement<'_>],
    try_index: usize,
    source: &str,
) -> Option<Vec<Edit>> {
    let Some(Statement::TryStatement(try_stmt)) = statements.get(try_index) else {
        return None;
    };

    let (iterable, iter_name, step_name): (&Expression<'_>, &str, &str) =
        match_values_for_init(try_stmt)?;
    let (element_kind, element, body): (
        VariableDeclarationKind,
        ElementBinding<'_>,
        &[Statement<'_>],
    ) = extract_values_loop(try_stmt, iter_name, step_name)?;
    if !try_cleanup_references(try_stmt, iter_name, step_name) {
        return None;
    }

    let tail: &[Statement<'_>] = statements.get(try_index + 1..).unwrap_or(&[]);
    if body_uses(tail, iter_name) || body_uses(tail, step_name) {
        return None;
    }

    let kind: &str = binding_kind(element_kind, &element, body);
    let element_text: &str = element.text.as_str();
    let iterable_src: &str = iterable.span().source_text(source);
    let body_src: String = remaining_body_source(body, source);
    let mut edits: Vec<Edit> = vec![Edit {
        start: try_stmt.span.start as usize,
        end: try_stmt.span.end as usize,
        replacement: format!("for ({kind} {element_text} of {iterable_src}) {{{body_src}}}"),
    }];

    edits.extend(scaffold_deletions(
        &statements[..try_index],
        try_stmt,
        tail,
        body,
    ));
    Some(edits)
}

fn scaffold_deletions(
    preceding: &[Statement<'_>],
    try_stmt: &TryStatement<'_>,
    tail: &[Statement<'_>],
    body: &[Statement<'_>],
) -> Vec<Edit> {
    let mut edits: Vec<Edit> = Vec::new();
    for stmt in preceding {
        let Statement::VariableDeclaration(decl) = stmt else {
            continue;
        };
        if decl.kind != VariableDeclarationKind::Var {
            continue;
        }
        let Some(names) = declarator_names(decl) else {
            continue;
        };
        if names.is_empty() {
            continue;
        }
        let all_scaffold: bool = decl
            .declarations
            .iter()
            .all(|d: &oxc_ast::ast::VariableDeclarator<'_>| d.init.is_none())
            && names.iter().all(|name: &&str| {
                try_handlers_use(try_stmt, name) && !body_uses(tail, name) && !body_uses(body, name)
            });
        if all_scaffold {
            edits.push(Edit {
                start: decl.span.start as usize,
                end: decl.span.end as usize,
                replacement: String::new(),
            });
        }
    }
    edits
}

fn try_handlers_use(try_stmt: &TryStatement<'_>, name: &str) -> bool {
    let handler_uses: bool = try_stmt
        .handler
        .as_ref()
        .is_some_and(|h| body_uses(&h.body.body, name));
    let finalizer_uses: bool = try_stmt
        .finalizer
        .as_ref()
        .is_some_and(|f| body_uses(&f.body, name));
    handler_uses || finalizer_uses
}

fn match_values_for_init<'a>(
    try_stmt: &'a TryStatement<'a>,
) -> Option<(&'a Expression<'a>, &'a str, &'a str)> {
    if try_stmt.block.body.len() != 1 {
        return None;
    }
    let Statement::ForStatement(for_stmt) = &try_stmt.block.body[0] else {
        return None;
    };
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_stmt.init else {
        return None;
    };
    if init.declarations.len() != 2 {
        return None;
    }
    let iter_name: &str = declarator_name(init, 0)?;
    let iterable: &Expression<'_> = values_call_argument(init.declarations[0].init.as_ref()?)?;
    let step_name: &str = declarator_name(init, 1)?;
    if !is_next_call(init.declarations[1].init.as_ref()?, iter_name) {
        return None;
    }
    if !is_done_negation_test(for_stmt.test.as_ref()?, step_name) {
        return None;
    }
    if !is_step_next_update(for_stmt.update.as_ref()?, iter_name, step_name) {
        return None;
    }
    Some((iterable, iter_name, step_name))
}

fn extract_values_loop<'a>(
    try_stmt: &'a TryStatement<'a>,
    iter_name: &str,
    step_name: &str,
) -> Option<(
    VariableDeclarationKind,
    ElementBinding<'a>,
    &'a [Statement<'a>],
)> {
    let Statement::ForStatement(for_stmt) = &try_stmt.block.body[0] else {
        return None;
    };
    let Statement::BlockStatement(loop_block) = &for_stmt.body else {
        return None;
    };
    let (element_kind, element, consumed): (VariableDeclarationKind, ElementBinding<'_>, usize) =
        element_from_step_value(loop_block.body.as_slice(), step_name)?;
    let body: &[Statement<'_>] = &loop_block.body.as_slice()[consumed..];
    if body_uses(body, iter_name) || body_uses(body, step_name) {
        return None;
    }
    if element
        .temp_ref
        .is_some_and(|name: &str| body_uses(body, name))
    {
        return None;
    }
    Some((element_kind, element, body))
}

fn values_call_argument<'a>(init: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    let Expression::CallExpression(call) = init else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if !is_values_helper_name(callee.name.as_str()) {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    call.arguments[0].as_expression()
}

fn is_values_helper_name(name: &str) -> bool {
    matches!(name, "__values" | "_values" | "__values__")
}

fn is_next_call(expr: &Expression<'_>, iter_name: &str) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    if !call.arguments.is_empty() {
        return false;
    }
    is_member_call(&call.callee, iter_name, "next")
}

fn is_member_call(callee: &Expression<'_>, object_name: &str, method: &str) -> bool {
    let Expression::StaticMemberExpression(member) = callee else {
        return false;
    };
    member.property.name == method
        && matches!(&member.object, Expression::Identifier(id) if id.name == object_name)
}

fn is_done_negation_test(test: &Expression<'_>, step_name: &str) -> bool {
    let Expression::UnaryExpression(unary) = test else {
        return false;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return false;
    }
    let Expression::StaticMemberExpression(member) = &unary.argument else {
        return false;
    };
    member.property.name == "done"
        && matches!(&member.object, Expression::Identifier(id) if id.name == step_name)
}

fn is_step_next_update(update: &Expression<'_>, iter_name: &str, step_name: &str) -> bool {
    let Expression::AssignmentExpression(assign) = update else {
        return false;
    };
    if assign
        .left
        .get_identifier()
        .is_none_or(|name: &str| name != step_name)
    {
        return false;
    }
    is_next_call(&assign.right, iter_name)
}

fn try_cleanup_references(try_stmt: &TryStatement<'_>, iter_name: &str, step_name: &str) -> bool {
    let Some(finalizer) = &try_stmt.finalizer else {
        return false;
    };
    if try_stmt.handler.is_none() {
        return false;
    }
    let uses_iter: bool = body_uses(&finalizer.body, iter_name);
    let uses_step: bool = body_uses(&finalizer.body, step_name);
    uses_iter && uses_step
}

fn declarator_names<'a>(decl: &'a VariableDeclaration<'a>) -> Option<Vec<&'a str>> {
    let mut names: Vec<&str> = Vec::with_capacity(decl.declarations.len());
    for declarator in &decl.declarations {
        let BindingPatternKind::BindingIdentifier(ident) = &declarator.id.kind else {
            return None;
        };
        names.push(ident.name.as_str());
    }
    Some(names)
}

fn helper_call_argument<'a>(init: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    let Expression::CallExpression(call) = init else {
        return None;
    };
    if call.arguments.len() != 1 {
        return None;
    }
    call.arguments[0].as_expression()
}

fn extract_helper_loop<'a>(
    try_stmt: &'a TryStatement<'a>,
    helper_name: &str,
    step_name: &str,
) -> Option<(
    VariableDeclarationKind,
    ElementBinding<'a>,
    &'a [Statement<'a>],
)> {
    if try_stmt.block.body.len() != 1 {
        return None;
    }
    let Statement::ForStatement(for_stmt) = &try_stmt.block.body[0] else {
        return None;
    };
    if for_stmt.update.is_some() {
        return None;
    }
    let Some(ForStatementInit::CallExpression(init_call)) = &for_stmt.init else {
        return None;
    };
    if !is_helper_method_call(init_call, helper_name, "s") {
        return None;
    }
    let test: &Expression<'_> = for_stmt.test.as_ref()?;
    if !is_helper_test(test, helper_name, step_name) {
        return None;
    }
    if !catch_calls_helper(try_stmt, helper_name, "e") {
        return None;
    }
    if !finalizer_calls_helper(try_stmt, helper_name, "f") {
        return None;
    }

    let Statement::BlockStatement(loop_block) = &for_stmt.body else {
        return None;
    };
    let (element_kind, element, consumed): (VariableDeclarationKind, ElementBinding<'_>, usize) =
        element_from_step_value(loop_block.body.as_slice(), step_name)?;

    let body: &[Statement<'_>] = &loop_block.body.as_slice()[consumed..];
    if body_uses(body, helper_name) || body_uses(body, step_name) {
        return None;
    }
    if element
        .temp_ref
        .is_some_and(|name: &str| body_uses(body, name))
    {
        return None;
    }
    Some((element_kind, element, body))
}

fn is_helper_method_call(
    call: &oxc_ast::ast::CallExpression<'_>,
    helper_name: &str,
    method: &str,
) -> bool {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return false;
    };
    member.property.name == method
        && matches!(&member.object, Expression::Identifier(id) if id.name == helper_name)
}

fn is_helper_test(test: &Expression<'_>, helper_name: &str, step_name: &str) -> bool {
    let Expression::UnaryExpression(unary) = test else {
        return false;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return false;
    }
    let Expression::StaticMemberExpression(member) = &unary.argument else {
        return false;
    };
    if member.property.name != "done" {
        return false;
    }
    let Expression::ParenthesizedExpression(paren) = &member.object else {
        return false;
    };
    let Expression::AssignmentExpression(assign) = &paren.expression else {
        return false;
    };
    if assign
        .left
        .get_identifier()
        .is_none_or(|name: &str| name != step_name)
    {
        return false;
    }
    let Expression::CallExpression(next_call) = &assign.right else {
        return false;
    };
    is_helper_method_call(next_call, helper_name, "n")
}

fn catch_calls_helper(try_stmt: &TryStatement<'_>, helper_name: &str, method: &str) -> bool {
    let Some(handler) = &try_stmt.handler else {
        return false;
    };
    statements_call_helper(&handler.body.body, helper_name, method)
}

fn finalizer_calls_helper(try_stmt: &TryStatement<'_>, helper_name: &str, method: &str) -> bool {
    let Some(finalizer) = &try_stmt.finalizer else {
        return false;
    };
    statements_call_helper(&finalizer.body, helper_name, method)
}

fn statements_call_helper(
    statements: &oxc_allocator::Vec<'_, Statement<'_>>,
    helper_name: &str,
    method: &str,
) -> bool {
    statements.iter().any(|stmt: &Statement<'_>| {
        let Statement::ExpressionStatement(expr_stmt) = stmt else {
            return false;
        };
        let Expression::CallExpression(call) = &expr_stmt.expression else {
            return false;
        };
        is_helper_method_call(call, helper_name, method)
    })
}

struct ElementBinding<'a> {
    text: String,
    temp_ref: Option<&'a str>,
    bound_names: Vec<&'a str>,
}

fn element_from_step_value<'a>(
    statements: &'a [Statement<'a>],
    step_name: &str,
) -> Option<(VariableDeclarationKind, ElementBinding<'a>, usize)> {
    let stmt: &Statement<'_> = statements.first()?;
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if let Some((binding, consumed)) = element_from_sliced_destructure(statements, step_name) {
        return Some((decl.kind, binding, consumed));
    }
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    if !init_is_step_value(declarator.init.as_ref()?, step_name) {
        return None;
    }
    let name: &str = binding.name.as_str();
    Some((
        decl.kind,
        ElementBinding {
            text: name.to_owned(),
            temp_ref: None,
            bound_names: vec![name],
        },
        1,
    ))
}

fn init_is_step_value(init: &Expression<'_>, step_name: &str) -> bool {
    let Expression::StaticMemberExpression(member) = init else {
        return false;
    };
    member.property.name == "value"
        && matches!(&member.object, Expression::Identifier(id) if id.name == step_name)
}

fn element_from_sliced_destructure<'a>(
    statements: &'a [Statement<'a>],
    step_name: &str,
) -> Option<(ElementBinding<'a>, usize)> {
    let Statement::VariableDeclaration(head_decl) = statements.first()? else {
        return None;
    };
    let head_kind: VariableDeclarationKind = head_decl.kind;
    let head: &oxc_ast::ast::VariableDeclarator<'_> = head_decl.declarations.first()?;
    let BindingPatternKind::BindingIdentifier(ref_binding) = &head.id.kind else {
        return None;
    };
    let ref_name: &str = ref_binding.name.as_str();
    let Expression::CallExpression(call) = head.init.as_ref()? else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "_slicedToArray" || call.arguments.len() != 2 {
        return None;
    }
    let source_arg: &Expression<'_> = call.arguments[0].as_expression()?;
    if !init_is_step_value(source_arg, step_name) {
        return None;
    }
    let Expression::NumericLiteral(count) = call.arguments[1].as_expression()? else {
        return None;
    };
    let n: usize = count.value as usize;
    if n == 0 || (count.value - n as f64).abs() > f64::EPSILON || n > 16 {
        return None;
    }

    let mut names: Vec<&str> = Vec::with_capacity(n);
    let mut consumed: usize = 1;
    let inline_tails: usize = head_decl.declarations.len() - 1;
    for declarator in head_decl.declarations.iter().skip(1) {
        collect_ref_index_name(declarator, ref_name, names.len(), &mut names)?;
    }
    while names.len() < n {
        let Statement::VariableDeclaration(decl) = statements.get(consumed)? else {
            return None;
        };
        if decl.kind != head_kind || decl.declarations.len() != 1 {
            return None;
        }
        collect_ref_index_name(&decl.declarations[0], ref_name, names.len(), &mut names)?;
        consumed += 1;
    }
    if names.len() != n || (inline_tails != 0 && inline_tails != n) {
        return None;
    }
    Some((
        ElementBinding {
            text: format!("[{}]", names.join(", ")),
            temp_ref: Some(ref_name),
            bound_names: names,
        },
        consumed,
    ))
}

fn collect_ref_index_name<'a>(
    declarator: &'a oxc_ast::ast::VariableDeclarator<'a>,
    ref_name: &str,
    expected_index: usize,
    names: &mut Vec<&'a str>,
) -> Option<()> {
    let BindingPatternKind::BindingIdentifier(name_binding) = &declarator.id.kind else {
        return None;
    };
    if ref_index_read(declarator.init.as_ref()?, ref_name)? != expected_index {
        return None;
    }
    names.push(name_binding.name.as_str());
    Some(())
}

fn ref_index_read(init: &Expression<'_>, ref_name: &str) -> Option<usize> {
    let Expression::ComputedMemberExpression(member) = init else {
        return None;
    };
    if !matches!(&member.object, Expression::Identifier(id) if id.name == ref_name) {
        return None;
    }
    let Expression::NumericLiteral(index) = &member.expression else {
        return None;
    };
    let value: usize = index.value as usize;
    if (index.value - value as f64).abs() > f64::EPSILON {
        return None;
    }
    Some(value)
}

fn declarator_name<'a>(decl: &'a VariableDeclaration<'a>, index: usize) -> Option<&'a str> {
    match &decl.declarations.get(index)?.id.kind {
        BindingPatternKind::BindingIdentifier(ident) => Some(ident.name.as_str()),
        _ => None,
    }
}

fn is_zero(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::NumericLiteral(num) if num.value == 0.0)
}

fn matches_test(test: &Expression<'_>, index_name: &str, array_name: &str) -> bool {
    let Expression::BinaryExpression(bin) = test else {
        return false;
    };
    if bin.operator != BinaryOperator::LessThan {
        return false;
    }
    if !matches!(&bin.left, Expression::Identifier(id) if id.name == index_name) {
        return false;
    }
    let Expression::StaticMemberExpression(member) = &bin.right else {
        return false;
    };
    member.property.name == "length"
        && matches!(&member.object, Expression::Identifier(id) if id.name == array_name)
}

fn matches_update(update: &Expression<'_>, index_name: &str) -> bool {
    let Expression::UpdateExpression(upd) = update else {
        return false;
    };
    upd.operator == UpdateOperator::Increment
        && upd
            .argument
            .get_identifier()
            .is_some_and(|name: &str| name == index_name)
}

fn element_from_index_access<'a>(
    stmt: &'a Statement<'a>,
    array_name: &str,
    index_name: &str,
) -> Option<(VariableDeclarationKind, &'a str)> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::ComputedMemberExpression(member) = init else {
        return None;
    };
    if !matches!(&member.object, Expression::Identifier(id) if id.name == array_name) {
        return None;
    }
    if !matches!(&member.expression, Expression::Identifier(id) if id.name == index_name) {
        return None;
    }
    Some((decl.kind, binding.name.as_str()))
}

fn body_uses(statements: &[Statement<'_>], name: &str) -> bool {
    let mut probe: UseProbe = UseProbe { name, found: false };
    for stmt in statements {
        probe.visit_statement(stmt);
    }
    probe.found
}

fn body_reassigns(statements: &[Statement<'_>], name: &str) -> bool {
    let mut probe: AssignProbe = AssignProbe { name, found: false };
    for stmt in statements {
        probe.visit_statement(stmt);
    }
    probe.found
}

fn remaining_body_source(statements: &[Statement<'_>], source: &str) -> String {
    let Some(first) = statements.first() else {
        return String::new();
    };
    let last: &Statement<'_> = statements.last().unwrap_or(first);
    let start: usize = first.span().start as usize;
    let end: usize = last.span().end as usize;
    format!(" {} ", &source[start..end])
}

struct UseProbe<'a> {
    name: &'a str,
    found: bool,
}

impl<'a> Visit<'a> for UseProbe<'_> {
    fn visit_identifier_reference(&mut self, ident: &oxc_ast::ast::IdentifierReference<'a>) {
        if ident.name == self.name {
            self.found = true;
        }
    }
}

struct AssignProbe<'a> {
    name: &'a str,
    found: bool,
}

impl<'a> Visit<'a> for AssignProbe<'_> {
    fn visit_assignment_expression(&mut self, assign: &oxc_ast::ast::AssignmentExpression<'a>) {
        if assign
            .left
            .get_identifier()
            .is_some_and(|n: &str| n == self.name)
        {
            self.found = true;
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assign);
    }

    fn visit_update_expression(&mut self, update: &oxc_ast::ast::UpdateExpression<'a>) {
        if update
            .argument
            .get_identifier()
            .is_some_and(|n: &str| n == self.name)
        {
            self.found = true;
        }
        oxc_ast::visit::walk::walk_update_expression(self, update);
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ForOfStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn ts_index_loop_becomes_for_of_const() {
        let source: &str = "for (var _i = 0, _arr = items; _i < _arr.length; _i++) { let x = _arr[_i]; print(x); }";
        let out: String = apply(source);
        assert!(out.contains("for (const x of items)"), "got: {out}");
        assert!(out.contains("print(x);"), "got: {out}");
        assert!(!out.contains("_arr[_i]"), "got: {out}");
    }

    #[test]
    fn reassigned_element_uses_let() {
        let source: &str = "for (var _i = 0, _a = list; _i < _a.length; _i++) { let e = _a[_i]; e = e + 1; print(e); }";
        let out: String = apply(source);
        assert!(out.contains("for (let e of list)"), "got: {out}");
    }

    #[test]
    fn var_element_stays_var() {
        let source: &str =
            "for (var _i = 0, _a = xs; _i < _a.length; _i++) { var v = _a[_i]; sink(v); }";
        let out: String = apply(source);
        assert!(out.contains("for (var v of xs)"), "got: {out}");
    }

    #[test]
    fn direct_index_loop_becomes_for_of() {
        let source: &str = "for (var _i2 = 0; _i2 < items.length; _i2++) { var item = items[_i2]; out.push(item.toUpperCase()); }";
        let out: String = apply(source);
        assert!(out.contains("for (var item of items)"), "got: {out}");
        assert!(!out.contains("items[_i2]"), "got: {out}");
    }

    #[test]
    fn direct_block_scoped_index_loop_becomes_for_of() {
        let source: &str = "for (let _i = 0; _i < items.length; _i++) { const item = items[_i]; out.push(item.toUpperCase()); }";
        let out: String = apply(source);
        assert!(out.contains("for (const item of items)"), "got: {out}");
    }

    #[test]
    fn length_cache_loop_becomes_for_of() {
        let source: &str = "for (var _i = 0, _len = arr.length; _i < _len; _i++) { var item = arr[_i]; sink(item); }";
        let out: String = apply(source);
        assert!(out.contains("for (var item of arr)"), "got: {out}");
        assert!(!out.contains("arr[_i]"), "got: {out}");
    }

    #[test]
    fn direct_member_iterable_recovers() {
        let source: &str = "for (var _i = 0; _i < obj.items.length; _i++) { var item = obj.items[_i]; sink(item); }";
        let out: String = apply(source);
        assert!(out.contains("for (var item of obj.items)"), "got: {out}");
    }

    #[test]
    fn direct_index_used_in_body_blocks_conversion() {
        let source: &str = "for (var _i = 0; _i < arr.length; _i++) { var item = arr[_i]; sink(_i + ':' + item); }";
        let (outcome, _stats): (RuleOutcome, super::ForOfStats) = recover(source);
        assert!(outcome.edits.is_empty(), "index used in body must block");
    }

    #[test]
    fn length_cache_used_in_body_blocks_conversion() {
        let source: &str = "for (var _i = 0, _len = arr.length; _i < _len; _i++) { var item = arr[_i]; sink(_len); }";
        let (outcome, _stats): (RuleOutcome, super::ForOfStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "length cache used in body must block"
        );
    }

    #[test]
    fn index_used_in_body_blocks_conversion() {
        let source: &str = "for (var _i = 0, _a = xs; _i < _a.length; _i++) { var v = _a[_i]; print(_i + ':' + v); }";
        let (outcome, stats): (RuleOutcome, super::ForOfStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.loops_converted, 0);
    }

    #[test]
    fn temp_array_used_in_body_blocks_conversion() {
        let source: &str =
            "for (var _i = 0, _a = xs; _i < _a.length; _i++) { var v = _a[_i]; print(_a.length); }";
        let (outcome, _stats): (RuleOutcome, super::ForOfStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn ordinary_counter_loop_is_not_matched() {
        let source: &str = "for (var i = 0; i < 10; i++) { print(i); }";
        let (outcome, _stats): (RuleOutcome, super::ForOfStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }
}
