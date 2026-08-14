use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingIdentifier, BindingPatternKind, Expression, FormalParameter, Function, Statement,
    VariableDeclarator,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Reference, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::{GetSpan, SourceType, Span};

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
}

struct Field {
    key: String,
    local: String,
    local_symbol_id: SymbolId,
}

fn plan_function(
    func: &Function<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
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
        if !is_synthetic_destructure_name(binding.name.as_str()) {
            continue;
        }
        let Some(symbol_id) = binding.symbol_id.get() else {
            continue;
        };
        if !following_parameters_are_plain(func, param_index) {
            continue;
        }
        let Some(plan) = plan_param(
            func,
            param.span,
            symbol_id,
            default_expression,
            body,
            source,
            symbols,
            nodes,
        ) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(plan);
    }
    found
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

fn plan_param(
    func: &Function<'_>,
    param_span: Span,
    symbol_id: SymbolId,
    default_expression: Option<&Expression<'_>>,
    body: &oxc_ast::ast::FunctionBody<'_>,
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<ParamPlan> {
    let refs: &Vec<oxc_semantic::ReferenceId> = symbols.get_resolved_reference_ids(symbol_id);
    if refs.is_empty() {
        return None;
    }
    let mut declaration_span: Option<Span> = None;
    for &reference_id in refs {
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
    let declaration_span: Span = declaration_span?;

    let declaration: &oxc_ast::ast::VariableDeclaration<'_> =
        leading_declaration(body, declaration_span)?;
    let fields: Vec<Field> = collect_fields(declaration, symbol_id, symbols)?;
    if fields.len() != declaration.declarations.len() {
        return None;
    }

    let mut seen: IndexSet<&str> = IndexSet::new();
    for field in &fields {
        if !is_valid_identifier(&field.key) {
            return None;
        }
        if !is_valid_identifier(&field.local) || is_reserved_binding_name(&field.local) {
            return None;
        }
        if !seen.insert(field.local.as_str()) {
            return None;
        }
    }
    if fields_collide_with_parameters(&fields, func, param_span, symbols) {
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
    Some(ParamPlan {
        param_span,
        pattern_text,
        declaration_span: removal,
    })
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
        fields
            .iter()
            .any(|field: &Field| field.local == parameter_name)
    })
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
            && self.fields.iter().any(|field: &Field| {
                field.local == identifier.name.as_str()
                    && reference.symbol_id() != Some(field.local_symbol_id)
            })
        {
            self.captured = true;
        }
    }
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

fn leading_declaration<'a>(
    body: &'a oxc_ast::ast::FunctionBody<'a>,
    declaration_span: Span,
) -> Option<&'a oxc_ast::ast::VariableDeclaration<'a>> {
    let Statement::VariableDeclaration(declaration) = body.statements.first()? else {
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
        let field: Field = declarator_field(declarator, symbol_id, symbols)?;
        fields.push(field);
    }
    Some(fields)
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
    let init: &Expression<'_> = declarator.init.as_ref()?;
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
    Some(Field {
        key,
        local: local.name.as_str().to_owned(),
        local_symbol_id,
    })
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
        if field.key == field.local {
            parts.push(field.key.clone());
        } else {
            parts.push(format!("{}: {}", field.key, field.local));
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
