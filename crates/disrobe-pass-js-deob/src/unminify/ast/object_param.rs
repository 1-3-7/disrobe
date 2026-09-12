use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryOperator, BindingIdentifier, BindingPatternKind, Expression, FormalParameter, Function,
    FunctionType, LogicalOperator, Statement, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Reference, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::{GetSpan, SourceType, Span};
use std::collections::BTreeSet;

use super::rename_scope::is_reserved_binding_name;
use super::{Edit, RuleOutcome, edit_overlaps_comments};

#[derive(Debug, Clone, Default)]
pub(super) struct ObjectParamStats {
    pub(super) params_restructured: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ObjectParamStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return (RuleOutcome::empty(), ObjectParamStats::default());
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), ObjectParamStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ObjectParamStats = ObjectParamStats::default();

    for node in nodes.iter() {
        let AstKind::Function(func) = node.kind() else {
            continue;
        };
        let Some(plan) = plan_function(func, source, symbols, nodes) else {
            continue;
        };
        let parameter_edit: Edit = Edit {
            start: plan.param_span.start as usize,
            end: plan.param_span.end as usize,
            replacement: plan.pattern_text,
        };
        let declaration_edit: Edit = Edit {
            start: plan.declaration_span.start as usize,
            end: plan.declaration_span.end as usize,
            replacement: String::new(),
        };
        if edit_overlaps_comments(&parameter_edit, &parsed.program.comments)
            || edit_overlaps_comments(&declaration_edit, &parsed.program.comments)
        {
            continue;
        }
        edits.push(parameter_edit);
        edits.push(declaration_edit);
        stats.params_restructured += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), ObjectParamStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct ParamPlan {
    param_span: Span,
    pattern_text: String,
    declaration_span: Span,
    field_symbol_ids: Vec<SymbolId>,
}

struct Field {
    key: String,
    binding: FieldBinding,
}

enum FieldBinding {
    Local { name: String, symbol_id: SymbolId },
    Nested(Vec<Field>),
}

struct ParamCandidate<'a> {
    param_span: Span,
    symbol_id: SymbolId,
    default_expression: Option<&'a Expression<'a>>,
    declaration_index: usize,
}

fn plan_function(
    func: &Function<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
    if let Some(plan) = plan_raw_arguments_function(func, source, symbols, nodes) {
        return Some(plan);
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = func.body.as_ref()?;
    let mut found: Option<ParamPlan> = None;
    for (param_index, param) in func.params.items.iter().enumerate() {
        if param.pattern.type_annotation.is_some() {
            continue;
        }
        let Some((binding, default_expression)): Option<(
            &BindingIdentifier<'_>,
            Option<&Expression<'_>>,
        )> = synthetic_parameter(&param.pattern.kind) else {
            continue;
        };
        let Some(symbol_id) = binding.symbol_id.get() else {
            continue;
        };
        if !following_parameters_are_plain(func, param_index) {
            continue;
        }
        let candidate: ParamCandidate<'_> = ParamCandidate {
            param_span: param.span,
            symbol_id,
            default_expression,
            declaration_index: 0,
        };
        let plan: Option<ParamPlan> = if binding.name == "_a" && default_expression.is_none() {
            plan_direct_index_array_param(func, candidate, body, source, symbols, nodes)
        } else if is_synthetic_destructure_name(binding.name.as_str()) {
            plan_param(func, candidate, body, source, symbols, nodes)
        } else {
            None
        };
        let Some(plan): Option<ParamPlan> = plan else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(plan);
    }
    found
}

fn plan_direct_index_array_param<'a>(
    func: &Function<'_>,
    candidate: ParamCandidate<'a>,
    body: &oxc_ast::ast::FunctionBody<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
    if !matches!(
        func.r#type,
        FunctionType::FunctionDeclaration | FunctionType::FunctionExpression
    ) || func.r#async
        || func.generator
        || func.declare
        || func.this_param.is_some()
        || func.type_parameters.is_some()
        || func.return_type.is_some()
        || !body.directives.is_empty()
        || body_has_dynamic_scope_hazard(body)
        || parameters_have_dynamic_scope_hazard(func)
        || !func.params.items.iter().all(plain_parameter)
        || !plain_parameter_names_are_unique(func)
    {
        return None;
    }
    let ParamCandidate {
        param_span,
        symbol_id,
        default_expression: None,
        declaration_index,
    }: ParamCandidate<'a> = candidate
    else {
        return None;
    };
    let (declaration_span, declaration): (Span, &oxc_ast::ast::VariableDeclaration<'_>) =
        candidate_declaration(body, symbol_id, declaration_index, symbols, nodes)?;
    if declaration.kind != VariableDeclarationKind::Var {
        return None;
    }
    let fields: Vec<Field> = collect_array_fields(declaration, symbol_id, symbols)?;
    let mut seen: IndexSet<&str> = IndexSet::new();
    for field in &fields {
        let FieldBinding::Local { name, .. } = &field.binding else {
            return None;
        };
        if !is_valid_identifier(name)
            || is_reserved_binding_name(name)
            || !seen.insert(name.as_str())
        {
            return None;
        }
    }
    if fields_collide_with_parameters(&fields, func, param_span, symbols)
        || parameter_initializers_capture_fields(&fields, func, param_span, symbols)
    {
        return None;
    }
    let mut field_symbol_ids: Vec<SymbolId> = Vec::with_capacity(fields.len());
    collect_field_symbol_ids(&fields, &mut field_symbol_ids);
    if duplicate_body_bindings(body, declaration.span, &field_symbol_ids) {
        return None;
    }
    let names: Vec<&str> = fields
        .iter()
        .map(|field: &Field| match &field.binding {
            FieldBinding::Local { name, .. } => Some(name.as_str()),
            FieldBinding::Nested(_) => None,
        })
        .collect::<Option<Vec<&str>>>()?;
    Some(ParamPlan {
        param_span,
        pattern_text: format!("[{}]", names.join(", ")),
        declaration_span: declaration_removal_span(declaration_span, source),
        field_symbol_ids,
    })
}

fn following_parameters_are_plain(func: &Function<'_>, candidate_index: usize) -> bool {
    func.params.rest.is_none()
        && func
            .params
            .items
            .iter()
            .skip(candidate_index + 1)
            .all(plain_parameter)
}

fn plain_parameter(parameter: &FormalParameter<'_>) -> bool {
    parameter.decorators.is_empty()
        && parameter.accessibility.is_none()
        && !parameter.readonly
        && !parameter.r#override
        && !parameter.pattern.optional
        && parameter.pattern.type_annotation.is_none()
        && matches!(
            &parameter.pattern.kind,
            BindingPatternKind::BindingIdentifier(_)
        )
}

fn plan_raw_arguments_function(
    func: &Function<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
    if !matches!(
        func.r#type,
        FunctionType::FunctionDeclaration | FunctionType::FunctionExpression
    ) || func.r#async
        || func.generator
        || func.declare
        || func.this_param.is_some()
        || func.type_parameters.is_some()
        || func.return_type.is_some()
        || func.params.rest.is_some()
        || !func.params.items.iter().all(plain_parameter)
        || !plain_parameter_names_are_unique(func)
    {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = func.body.as_ref()?;
    if !body.directives.is_empty() || body.statements.len() < 2 {
        return None;
    }
    let Statement::VariableDeclaration(scaffold) = &body.statements[0] else {
        return None;
    };
    let Statement::VariableDeclaration(extraction) = &body.statements[1] else {
        return None;
    };
    if scaffold.kind != VariableDeclarationKind::Var
        || extraction.kind != VariableDeclarationKind::Var
        || scaffold.declarations.len() != 1
    {
        return None;
    }
    let declarator: &VariableDeclarator<'_> = &scaffold.declarations[0];
    if declarator.id.type_annotation.is_some() {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    if !is_synthetic_destructure_name(binding.name.as_str()) {
        return None;
    }
    let symbol_id: SymbolId = binding.symbol_id.get()?;
    let expected_index: usize = func.params.items.len();
    let default_expression: &Expression<'_> =
        raw_babel_default(declarator.init.as_ref()?, expected_index, symbols)?;
    if body_has_raw_recovery_hazard(body)
        || default_binding_resolution_changes(default_expression, body, symbols, nodes)
    {
        return None;
    }
    let insert_at: u32 = func.params.span.end.checked_sub(1)?;
    let mut plan: ParamPlan = plan_param(
        func,
        ParamCandidate {
            param_span: Span::new(insert_at, insert_at),
            symbol_id,
            default_expression: Some(default_expression),
            declaration_index: 1,
        },
        body,
        source,
        symbols,
        nodes,
    )?;
    let expected_extraction: Span = declaration_removal_span(extraction.span, source);
    if plan.declaration_span != expected_extraction
        || duplicate_body_bindings(body, extraction.span, &plan.field_symbol_ids)
    {
        return None;
    }
    let separator: &str = match func.params.items.last() {
        None => "",
        Some(last) => {
            let tail: &str = source.get(last.span.end as usize..insert_at as usize)?;
            match tail.trim() {
                "" => ", ",
                "," => " ",
                _ => return None,
            }
        }
    };
    plan.pattern_text = format!("{separator}{}", plan.pattern_text);
    plan.declaration_span =
        declaration_removal_span(Span::new(scaffold.span.start, extraction.span.end), source);
    Some(plan)
}

fn plain_parameter_names_are_unique(func: &Function<'_>) -> bool {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    func.params
        .items
        .iter()
        .all(|parameter: &FormalParameter<'_>| {
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                return false;
            };
            names.insert(binding.name.as_str())
        })
}

fn duplicate_body_bindings(
    body: &oxc_ast::ast::FunctionBody<'_>,
    extraction_span: Span,
    field_symbol_ids: &[SymbolId],
) -> bool {
    let mut probe: DuplicateBindingProbe<'_> = DuplicateBindingProbe {
        extraction_span,
        field_symbol_ids,
        duplicate: false,
    };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    probe.duplicate
}

struct DuplicateBindingProbe<'a> {
    extraction_span: Span,
    field_symbol_ids: &'a [SymbolId],
    duplicate: bool,
}

impl<'a> Visit<'a> for DuplicateBindingProbe<'_> {
    fn visit_variable_declaration(&mut self, declaration: &oxc_ast::ast::VariableDeclaration<'a>) {
        if declaration.span == self.extraction_span {
            return;
        }
        oxc_ast::visit::walk::walk_variable_declaration(self, declaration);
    }

    fn visit_binding_identifier(&mut self, binding: &oxc_ast::ast::BindingIdentifier<'a>) {
        if binding
            .symbol_id
            .get()
            .is_some_and(|symbol_id: SymbolId| self.field_symbol_ids.contains(&symbol_id))
        {
            self.duplicate = true;
        }
    }

    fn visit_function(&mut self, function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
        if let Some(binding) = &function.id {
            self.visit_binding_identifier(binding);
        }
    }
}

fn raw_babel_default<'a>(
    expression: &'a Expression<'a>,
    expected_index: usize,
    symbols: &SymbolTable,
) -> Option<&'a Expression<'a>> {
    let Expression::ConditionalExpression(conditional) = expression else {
        return None;
    };
    let Expression::LogicalExpression(guard) = &conditional.test else {
        return None;
    };
    if guard.operator != LogicalOperator::And {
        return None;
    }
    let Expression::BinaryExpression(length_check) = &guard.left else {
        return None;
    };
    if length_check.operator != BinaryOperator::GreaterThan
        || !is_arguments_length(&length_check.left, symbols)
        || !is_numeric_index(&length_check.right, expected_index)
    {
        return None;
    }
    let Expression::BinaryExpression(undefined_check) = &guard.right else {
        return None;
    };
    if undefined_check.operator != BinaryOperator::StrictInequality
        || !is_arguments_index(&undefined_check.left, expected_index, symbols)
        || !is_unbound_identifier(&undefined_check.right, "undefined", symbols)
        || !is_arguments_index(&conditional.consequent, expected_index, symbols)
    {
        return None;
    }
    Some(&conditional.alternate)
}

fn is_arguments_length(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::StaticMemberExpression(member) = expression else {
        return false;
    };
    member.property.name == "length" && is_unbound_arguments(&member.object, symbols)
}

fn is_arguments_index(
    expression: &Expression<'_>,
    expected_index: usize,
    symbols: &SymbolTable,
) -> bool {
    let Expression::ComputedMemberExpression(member) = expression else {
        return false;
    };
    is_unbound_arguments(&member.object, symbols)
        && is_numeric_index(&member.expression, expected_index)
}

fn is_unbound_arguments(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    is_unbound_identifier(expression, "arguments", symbols)
}

fn is_unbound_identifier(
    expression: &Expression<'_>,
    expected_name: &str,
    symbols: &SymbolTable,
) -> bool {
    let Expression::Identifier(identifier) = expression else {
        return false;
    };
    if identifier.name != expected_name {
        return false;
    }
    let Some(reference_id) = identifier.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id().is_none()
}

fn is_numeric_index(expression: &Expression<'_>, expected_index: usize) -> bool {
    let Expression::NumericLiteral(number) = expression else {
        return false;
    };
    number.value.fract() == 0.0
        && number.value >= 0.0
        && number.value <= usize::MAX as f64
        && number.value as usize == expected_index
}

fn body_has_raw_recovery_hazard(body: &oxc_ast::ast::FunctionBody<'_>) -> bool {
    let mut probe: RawRecoveryHazardProbe = RawRecoveryHazardProbe {
        arguments_uses: 0,
        unsafe_construct: false,
    };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    probe.arguments_uses != 3 || probe.unsafe_construct
}

struct RawRecoveryHazardProbe {
    arguments_uses: usize,
    unsafe_construct: bool,
}

impl<'a> Visit<'a> for RawRecoveryHazardProbe {
    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        if identifier.name == "arguments" {
            self.arguments_uses = self.arguments_uses.saturating_add(1);
        } else if identifier.name == "eval" {
            self.unsafe_construct = true;
        }
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        self.unsafe_construct = true;
    }

    fn visit_with_statement(&mut self, _statement: &oxc_ast::ast::WithStatement<'a>) {
        self.unsafe_construct = true;
    }
}

fn default_binding_resolution_changes(
    expression: &Expression<'_>,
    body: &oxc_ast::ast::FunctionBody<'_>,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> bool {
    let mut probe: DefaultBindingProbe<'_> = DefaultBindingProbe {
        body_span: body.span,
        symbols,
        nodes,
        changes: false,
    };
    probe.visit_expression(expression);
    probe.changes
}

struct DefaultBindingProbe<'a> {
    body_span: Span,
    symbols: &'a SymbolTable,
    nodes: &'a AstNodes<'a>,
    changes: bool,
}

impl<'a> Visit<'a> for DefaultBindingProbe<'a> {
    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        if identifier.name == "eval" {
            self.changes = true;
            return;
        }
        let Some(reference_id) = identifier.reference_id.get() else {
            return;
        };
        let reference: &Reference = self.symbols.get_reference(reference_id);
        let Some(symbol_id) = reference.symbol_id() else {
            return;
        };
        let declaration: NodeId = self.symbols.get_declaration(symbol_id);
        let declaration_span: Span = self.nodes.get_node(declaration).kind().span();
        if self.body_span.start <= declaration_span.start
            && declaration_span.end <= self.body_span.end
        {
            self.changes = true;
        }
    }
}

fn plan_param<'a>(
    func: &Function<'_>,
    candidate: ParamCandidate<'a>,
    body: &oxc_ast::ast::FunctionBody<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
    let ParamCandidate {
        param_span,
        symbol_id,
        default_expression,
        declaration_index,
    }: ParamCandidate<'a> = candidate;
    let (declaration_span, declaration): (Span, &oxc_ast::ast::VariableDeclaration<'_>) =
        candidate_declaration(body, symbol_id, declaration_index, symbols, nodes)?;
    let fields: Vec<Field> = collect_fields(declaration, symbol_id, symbols)?;

    let mut seen: IndexSet<&str> = IndexSet::new();
    if !valid_fields(&fields, &mut seen) {
        return None;
    }
    let has_nested_fields: bool = fields_contain_nested(&fields);
    if has_nested_fields
        && (func.generator
            || !body.directives.is_empty()
            || body_has_dynamic_scope_hazard(body)
            || parameters_have_dynamic_scope_hazard(func))
    {
        return None;
    }
    if fields_collide_with_parameters(&fields, func, param_span, symbols) {
        return None;
    }
    if parameter_initializers_capture_fields(&fields, func, param_span, symbols) {
        return None;
    }
    if let Some(default_expression) = default_expression
        && default_initializer_captures_field(default_expression, &fields, symbols)
    {
        return None;
    }

    let mut pattern_text: String = build_pattern(&fields);
    if let Some(default_expression) = default_expression {
        let default_text: &str = default_expression.span().source_text(source);
        pattern_text.push_str(" = ");
        pattern_text.push_str(default_text);
    }
    let removal: Span = declaration_removal_span(declaration_span, source);
    let mut field_symbol_ids: Vec<SymbolId> = Vec::new();
    collect_field_symbol_ids(&fields, &mut field_symbol_ids);
    if has_nested_fields && duplicate_body_bindings(body, declaration.span, &field_symbol_ids) {
        return None;
    }
    Some(ParamPlan {
        param_span,
        pattern_text,
        declaration_span: removal,
        field_symbol_ids,
    })
}

fn candidate_declaration<'a>(
    body: &'a oxc_ast::ast::FunctionBody<'a>,
    symbol_id: SymbolId,
    declaration_index: usize,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<(Span, &'a oxc_ast::ast::VariableDeclaration<'a>)> {
    let references: &Vec<oxc_semantic::ReferenceId> = symbols.get_resolved_reference_ids(symbol_id);
    if references.is_empty() {
        return None;
    }
    let mut declaration_span: Option<Span> = None;
    for &reference_id in references {
        let reference: &Reference = symbols.get_reference(reference_id);
        if !reference.is_read() || reference.is_write() {
            return None;
        }
        let span: Span = enclosing_declaration_span(reference.node_id(), nodes)?;
        match declaration_span {
            None => declaration_span = Some(span),
            Some(existing) if existing == span => {}
            Some(_) => return None,
        }
    }
    let span: Span = declaration_span?;
    Some((span, declaration_at(body, span, declaration_index)?))
}

fn synthetic_parameter<'a>(
    kind: &'a BindingPatternKind<'a>,
) -> Option<(&'a BindingIdentifier<'a>, Option<&'a Expression<'a>>)> {
    match kind {
        BindingPatternKind::BindingIdentifier(binding) => Some((binding, None)),
        BindingPatternKind::AssignmentPattern(assignment) => {
            if assignment.left.optional || assignment.left.type_annotation.is_some() {
                return None;
            }
            let BindingPatternKind::BindingIdentifier(binding) = &assignment.left.kind else {
                return None;
            };
            Some((binding, Some(&assignment.right)))
        }
        _ => None,
    }
}

fn fields_collide_with_parameters(
    fields: &[Field],
    func: &Function<'_>,
    candidate_span: Span,
    symbols: &SymbolTable,
) -> bool {
    let mut collector: BindingSymbolCollector = BindingSymbolCollector {
        symbol_ids: Vec::new(),
    };
    for parameter in &func.params.items {
        if parameter.span != candidate_span {
            collector.visit_binding_pattern(&parameter.pattern);
        }
    }
    collector.symbol_ids.iter().any(|&symbol_id: &SymbolId| {
        let parameter_name: &str = symbols.get_name(symbol_id);
        fields_contain_name(fields, parameter_name)
    })
}

fn parameter_initializers_capture_fields(
    fields: &[Field],
    func: &Function<'_>,
    candidate_span: Span,
    symbols: &SymbolTable,
) -> bool {
    let mut probe: DefaultCaptureProbe<'_> = DefaultCaptureProbe {
        fields,
        symbols,
        captured: false,
    };
    for parameter in &func.params.items {
        if parameter.span != candidate_span {
            probe.visit_binding_pattern(&parameter.pattern);
        }
    }
    probe.captured
}

fn valid_fields<'a>(fields: &'a [Field], seen: &mut IndexSet<&'a str>) -> bool {
    fields.iter().all(|field: &'a Field| {
        if !is_valid_identifier(&field.key) {
            return false;
        }
        match &field.binding {
            FieldBinding::Local { name, .. } => {
                is_valid_identifier(name)
                    && !is_reserved_binding_name(name)
                    && seen.insert(name.as_str())
            }
            FieldBinding::Nested(nested) => valid_fields(nested, seen),
        }
    })
}

fn fields_contain_nested(fields: &[Field]) -> bool {
    fields
        .iter()
        .any(|field: &Field| matches!(field.binding, FieldBinding::Nested(_)))
}

fn body_has_dynamic_scope_hazard(body: &oxc_ast::ast::FunctionBody<'_>) -> bool {
    let mut probe: DynamicScopeProbe = DynamicScopeProbe { found: false };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    probe.found
}

fn parameters_have_dynamic_scope_hazard(func: &Function<'_>) -> bool {
    let mut probe: DynamicScopeProbe = DynamicScopeProbe { found: false };
    for parameter in &func.params.items {
        probe.visit_binding_pattern(&parameter.pattern);
    }
    probe.found
}

struct DynamicScopeProbe {
    found: bool,
}

impl<'a> Visit<'a> for DynamicScopeProbe {
    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        if identifier.name == "eval" {
            self.found = true;
        }
    }

    fn visit_with_statement(&mut self, _statement: &oxc_ast::ast::WithStatement<'a>) {
        self.found = true;
    }
}

fn fields_contain_name(fields: &[Field], expected: &str) -> bool {
    fields.iter().any(|field: &Field| match &field.binding {
        FieldBinding::Local { name, .. } => name == expected,
        FieldBinding::Nested(nested) => fields_contain_name(nested, expected),
    })
}

fn collect_field_symbol_ids(fields: &[Field], symbols: &mut Vec<SymbolId>) {
    for field in fields {
        match &field.binding {
            FieldBinding::Local { symbol_id, .. } => symbols.push(*symbol_id),
            FieldBinding::Nested(nested) => collect_field_symbol_ids(nested, symbols),
        }
    }
}

struct BindingSymbolCollector {
    symbol_ids: Vec<SymbolId>,
}

impl<'a> Visit<'a> for BindingSymbolCollector {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        if let Some(symbol_id) = identifier.symbol_id.get() {
            self.symbol_ids.push(symbol_id);
        }
    }
}

fn default_initializer_captures_field(
    default_expression: &Expression<'_>,
    fields: &[Field],
    symbols: &SymbolTable,
) -> bool {
    let mut probe: DefaultCaptureProbe<'_> = DefaultCaptureProbe {
        fields,
        symbols,
        captured: false,
    };
    probe.visit_expression(default_expression);
    probe.captured
}

struct DefaultCaptureProbe<'a> {
    fields: &'a [Field],
    symbols: &'a SymbolTable,
    captured: bool,
}

impl<'a> Visit<'a> for DefaultCaptureProbe<'_> {
    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        let Some(reference_id) = identifier.reference_id.get() else {
            return;
        };
        let reference: &Reference = self.symbols.get_reference(reference_id);
        if reference.is_value()
            && field_name_resolves_elsewhere(
                self.fields,
                identifier.name.as_str(),
                reference.symbol_id(),
            )
        {
            self.captured = true;
        }
    }
}

fn field_name_resolves_elsewhere(
    fields: &[Field],
    name: &str,
    symbol_id: Option<SymbolId>,
) -> bool {
    fields.iter().any(|field: &Field| match &field.binding {
        FieldBinding::Local {
            name: field_name,
            symbol_id: field_symbol_id,
        } => field_name == name && symbol_id != Some(*field_symbol_id),
        FieldBinding::Nested(nested) => field_name_resolves_elsewhere(nested, name, symbol_id),
    })
}

fn enclosing_declaration_span(node_id: NodeId, nodes: &AstNodes<'_>) -> Option<Span> {
    let member_node: &oxc_semantic::AstNode<'_> = nodes.parent_node(node_id)?;
    if !matches!(member_node.kind(), AstKind::MemberExpression(_)) {
        return None;
    }
    let declarator_node: &oxc_semantic::AstNode<'_> = nodes.parent_node(member_node.id())?;
    if !matches!(declarator_node.kind(), AstKind::VariableDeclarator(_)) {
        return None;
    }
    let declaration_node: &oxc_semantic::AstNode<'_> = nodes.parent_node(declarator_node.id())?;
    if !matches!(declaration_node.kind(), AstKind::VariableDeclaration(_)) {
        return None;
    }
    Some(declaration_node.kind().span())
}

fn declaration_at<'a>(
    body: &'a oxc_ast::ast::FunctionBody<'a>,
    declaration_span: Span,
    declaration_index: usize,
) -> Option<&'a oxc_ast::ast::VariableDeclaration<'a>> {
    let Statement::VariableDeclaration(declaration) = body.statements.get(declaration_index)?
    else {
        return None;
    };
    (declaration.span == declaration_span).then_some(declaration.as_ref())
}

fn collect_fields(
    declaration: &oxc_ast::ast::VariableDeclaration<'_>,
    symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> Option<Vec<Field>> {
    let mut fields: Vec<Field> = Vec::with_capacity(declaration.declarations.len());
    for declarator in &declaration.declarations {
        let Some(field): Option<Field> = declarator_field(declarator, symbol_id, symbols) else {
            return collect_nested_fields(declaration, symbol_id, symbols);
        };
        fields.push(field);
    }
    Some(fields)
}

fn collect_array_fields(
    declaration: &oxc_ast::ast::VariableDeclaration<'_>,
    symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> Option<Vec<Field>> {
    if declaration.declarations.is_empty() {
        return None;
    }
    declaration
        .declarations
        .iter()
        .enumerate()
        .map(
            |(expected_index, declarator): (usize, &VariableDeclarator<'_>)| {
                if declarator.id.type_annotation.is_some() {
                    return None;
                }
                let BindingPatternKind::BindingIdentifier(local) = &declarator.id.kind else {
                    return None;
                };
                let Expression::ComputedMemberExpression(member) = declarator.init.as_ref()? else {
                    return None;
                };
                let Expression::NumericLiteral(index) = &member.expression else {
                    return None;
                };
                if index.value.total_cmp(&(expected_index as f64)).is_ne() {
                    return None;
                }
                let Expression::Identifier(object) = &member.object else {
                    return None;
                };
                if !resolves_to(object, symbol_id, symbols) {
                    return None;
                }
                Some(Field {
                    key: expected_index.to_string(),
                    binding: FieldBinding::Local {
                        name: local.name.as_str().to_owned(),
                        symbol_id: local.symbol_id.get()?,
                    },
                })
            },
        )
        .collect()
}

fn collect_nested_fields(
    declaration: &oxc_ast::ast::VariableDeclaration<'_>,
    root_symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> Option<Vec<Field>> {
    if !matches!(
        declaration.kind,
        VariableDeclarationKind::Var | VariableDeclarationKind::Let
    ) {
        return None;
    }
    let (key, nested_symbol_id): (String, SymbolId) =
        nested_declarator(declaration.declarations.first()?, root_symbol_id, symbols)?;
    let references: &Vec<oxc_semantic::ReferenceId> =
        symbols.get_resolved_reference_ids(nested_symbol_id);
    if references.len() != declaration.declarations.len().checked_sub(1)?
        || references.iter().any(|&reference_id| {
            let reference: &Reference = symbols.get_reference(reference_id);
            !reference.is_read() || reference.is_write()
        })
    {
        return None;
    }
    let nested: Vec<Field> = declaration
        .declarations
        .iter()
        .skip(1)
        .map(|declarator: &VariableDeclarator<'_>| {
            declarator_field(declarator, nested_symbol_id, symbols)
        })
        .collect::<Option<Vec<Field>>>()?;
    (!nested.is_empty()).then_some(vec![Field {
        key,
        binding: FieldBinding::Nested(nested),
    }])
}

fn nested_declarator(
    declarator: &VariableDeclarator<'_>,
    root_symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> Option<(String, SymbolId)> {
    if declarator.id.type_annotation.is_some() {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(nested) = &declarator.id.kind else {
        return None;
    };
    let nested_symbol_id: SymbolId = nested.symbol_id.get()?;
    let root_name: &str = symbols.get_name(root_symbol_id);
    let prefix: String = format!("{root_name}$");
    if !nested.name.as_str().starts_with(&prefix) || nested.name.as_str().len() == prefix.len() {
        return None;
    }
    let key: String = member_key(declarator.init.as_ref()?, root_symbol_id, symbols)?;
    Some((key, nested_symbol_id))
}

fn declarator_field(
    declarator: &VariableDeclarator<'_>,
    symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> Option<Field> {
    if declarator.id.type_annotation.is_some() {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(local) = &declarator.id.kind else {
        return None;
    };
    let local_symbol_id: SymbolId = local.symbol_id.get()?;
    let key: String = member_key(declarator.init.as_ref()?, symbol_id, symbols)?;
    Some(Field {
        key,
        binding: FieldBinding::Local {
            name: local.name.as_str().to_owned(),
            symbol_id: local_symbol_id,
        },
    })
}

fn member_key(init: &Expression<'_>, symbol_id: SymbolId, symbols: &SymbolTable) -> Option<String> {
    let (object, key): (&Expression<'_>, String) = match init {
        Expression::StaticMemberExpression(member) => {
            (&member.object, member.property.name.as_str().to_owned())
        }
        Expression::ComputedMemberExpression(member) => {
            let Expression::StringLiteral(lit) = &member.expression else {
                return None;
            };
            (&member.object, lit.value.as_str().to_owned())
        }
        _ => return None,
    };
    let Expression::Identifier(object_ident) = object else {
        return None;
    };
    if !resolves_to(object_ident, symbol_id, symbols) {
        return None;
    }
    Some(key)
}

fn resolves_to(
    ident: &oxc_ast::ast::IdentifierReference<'_>,
    symbol_id: SymbolId,
    symbols: &SymbolTable,
) -> bool {
    let Some(reference_id) = ident.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id() == Some(symbol_id)
}

fn build_pattern(fields: &[Field]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(fields.len());
    for field in fields {
        match &field.binding {
            FieldBinding::Local { name, .. } if field.key == *name => {
                parts.push(field.key.clone());
            }
            FieldBinding::Local { name, .. } => {
                parts.push(format!("{}: {name}", field.key));
            }
            FieldBinding::Nested(nested) => {
                parts.push(format!("{}: {}", field.key, build_pattern(nested)));
            }
        }
    }
    format!("{{ {} }}", parts.join(", "))
}

fn declaration_removal_span(declaration: Span, source: &str) -> Span {
    let bytes: &[u8] = source.as_bytes();
    let mut start: usize = declaration.start as usize;
    let mut end: usize = declaration.end as usize;
    while end < bytes.len() && matches!(bytes.get(end), Some(b' ' | b'\t')) {
        end += 1;
    }
    while start > 0 && matches!(bytes.get(start - 1), Some(b' ' | b'\t')) {
        start -= 1;
    }
    Span::new(start as u32, end as u32)
}

fn is_synthetic_destructure_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("_ref") else {
        return false;
    };
    rest.is_empty() || rest.chars().all(|c: char| c.is_ascii_digit())
}

fn is_valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse((edit.start, edit.end)));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn shorthand_destructure_recovers() {
        let out: String = apply("function f(_ref) { var x = _ref.x, y = _ref.y; return x + y; }");
        assert!(out.contains("function f({ x, y })"), "got: {out}");
        assert!(!out.contains("_ref"), "got: {out}");
    }

    #[test]
    fn renamed_destructure_emits_key_colon_local() {
        let out: String = apply("function f(_ref) { var a = _ref.x, b = _ref.y; return a + b; }");
        assert!(out.contains("function f({ x: a, y: b })"), "got: {out}");
    }

    #[test]
    fn computed_string_key_recovers() {
        let out: String = apply("function f(_ref) { var x = _ref[\"x\"]; return x; }");
        assert!(out.contains("function f({ x })"), "got: {out}");
    }

    #[test]
    fn second_synthetic_name_matches() {
        let out: String = apply("function f(_ref2) { var p = _ref2.p; return p; }");
        assert!(out.contains("function f({ p })"), "got: {out}");
    }

    #[test]
    fn whole_object_use_blocks_recovery() {
        let source: &str = "function f(_ref) { var x = _ref.x; return _ref; }";
        let (outcome, stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        assert!(outcome.edits.is_empty(), "got edits");
        assert_eq!(stats.params_restructured, 0);
    }

    #[test]
    fn reassigning_param_blocks_recovery() {
        let source: &str = "function f(_ref) { _ref = {}; var x = _ref.x; return x; }";
        let (outcome, _stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        assert!(outcome.edits.is_empty(), "reassigning _ref must block");
    }

    #[test]
    fn ordinary_param_is_untouched() {
        let source: &str = "function f(opts) { var x = opts.x; return x; }";
        let (outcome, _stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        assert!(outcome.edits.is_empty(), "non-synthetic name must be left");
    }

    #[test]
    fn member_access_not_in_declarator_blocks() {
        let source: &str = "function f(_ref) { return _ref.x + 1; }";
        let (outcome, _stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        assert!(outcome.edits.is_empty(), "non-extraction member must block");
    }

    #[test]
    fn extra_non_field_declarator_in_same_decl_blocks() {
        let source: &str = "function f(_ref) { var x = _ref.x, y = 9; return x + y; }";
        let (outcome, _stats): (RuleOutcome, super::ObjectParamStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "a non-extraction declarator in the same decl must block whole-decl removal"
        );
    }

    #[test]
    fn write_only_default_capture_is_left_byte_identical() {
        let source: &str = "var value; function read(_ref = (value = { value: 11 })) { var value = _ref.value; return value; }";
        assert_eq!(apply(source), source);
    }

    #[test]
    fn later_non_plain_parameters_block_recovery() {
        let sources: [&str; 4] = [
            "function f(_ref, x = side()) { var value = _ref.value; return value; }",
            "function f(_ref, { x }) { var value = _ref.value; return value + x; }",
            "function f(_ref, [x]) { var value = _ref.value; return value + x; }",
            "function f(_ref, ...rest) { var value = _ref.value; return value + rest.length; }",
        ];
        for source in sources {
            assert_eq!(apply(source), source);
        }
    }

    #[test]
    fn plain_parameters_before_and_after_candidate_allow_recovery() {
        let source: &str = "function f(before, _ref, after) { var value = _ref.value; return before + value + after; }";
        assert!(apply(source).contains("function f(before, { value }, after)"));
    }
}
