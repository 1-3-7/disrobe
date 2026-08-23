use std::collections::{BTreeMap, BTreeSet};

use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    AssignmentOperator, BinaryOperator, BindingIdentifier, BindingPatternKind, Expression,
    ForStatement, ForStatementInit, Function, Statement, TryStatement, UnaryOperator,
    UpdateOperator, VariableDeclaration, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::babel_materializer::{MaterializerFacts, MaterializerScope};
use super::{Edit, RuleOutcome, edit_overlaps_comments};

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

    let mut binding_collector: LooseHelperBindingCollector = LooseHelperBindingCollector {
        counts: BTreeMap::new(),
    };
    binding_collector.visit_program(&parsed.program);
    let mut helper_collector: LooseHelperCollector<'_> = LooseHelperCollector {
        source,
        binding_counts: &binding_collector.counts,
        valid: BTreeSet::new(),
    };
    helper_collector.visit_program(&parsed.program);
    let mut string_subjects: StringSubjectCollector = StringSubjectCollector::default();
    string_subjects.visit_program(&parsed.program);
    let mut array_subjects: ArraySubjectCollector = ArraySubjectCollector::default();
    array_subjects.visit_program(&parsed.program);
    let materializer_facts: MaterializerFacts = MaterializerFacts::collect(source, &parsed.program);
    let materializer_scope: MaterializerScope<'_> = materializer_facts.scope();
    let mut collector: Collector = Collector {
        source,
        string_subjects: &string_subjects.evidence,
        array_subjects: &array_subjects.evidence,
        materializer_scope,
        edits: Vec::new(),
        helper_loops_converted: 0,
        loose_helpers: helper_collector.valid,
        comments: &parsed.program.comments,
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
    string_subjects: &'s BTreeMap<String, StringEvidence>,
    array_subjects: &'s BTreeMap<String, ArrayEvidence>,
    materializer_scope: MaterializerScope<'s>,
    edits: Vec<Edit>,
    helper_loops_converted: usize,
    loose_helpers: BTreeSet<String>,
    comments: &'s [oxc_ast::ast::Comment],
}

struct LooseHelperCollector<'s> {
    source: &'s str,
    binding_counts: &'s BTreeMap<String, usize>,
    valid: BTreeSet<String>,
}

struct LooseHelperBindingCollector {
    counts: BTreeMap<String, usize>,
}

impl<'a> Visit<'a> for LooseHelperBindingCollector {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        let name: &str = identifier.name.as_str();
        if is_loose_helper_name(name) {
            let count: &mut usize = self.counts.entry(name.to_owned()).or_default();
            *count = count.saturating_add(1);
        }
    }
}

impl<'a> Visit<'a> for LooseHelperCollector<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        if let Some(id) = &func.id {
            let name: &str = id.name.as_str();
            if is_loose_helper_name(name) && self.binding_counts.get(name).copied() == Some(1) {
                let body_text: &str = func.span.source_text(self.source);
                if is_babel_loose_helper(body_text, name) {
                    self.valid.insert(name.to_owned());
                }
            }
        }
        oxc_ast::visit::walk::walk_function(self, func, flags);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum StringEvidence {
    #[default]
    None,
    BasicPlane,
    Opaque,
}

impl StringEvidence {
    const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::None, value) | (value, Self::None) => value,
            (Self::BasicPlane, Self::BasicPlane) => Self::BasicPlane,
            _ => Self::Opaque,
        }
    }

    const fn blocks_index_resugar(self) -> bool {
        matches!(self, Self::Opaque)
    }
}

fn literal_string_evidence(value: &str) -> StringEvidence {
    if value.chars().any(|unit: char| unit as u32 > 0xffff) {
        StringEvidence::Opaque
    } else {
        StringEvidence::BasicPlane
    }
}

fn is_string_only_method(name: &str) -> bool {
    matches!(
        name,
        "toString"
            | "join"
            | "charAt"
            | "substring"
            | "substr"
            | "toUpperCase"
            | "toLowerCase"
            | "toLocaleUpperCase"
            | "toLocaleLowerCase"
            | "trim"
            | "trimStart"
            | "trimEnd"
            | "padStart"
            | "padEnd"
            | "normalize"
            | "replace"
            | "replaceAll"
            | "repeat"
    )
}

fn string_evidence(
    expr: &Expression<'_>,
    bindings: &BTreeMap<String, StringEvidence>,
) -> StringEvidence {
    match expr.get_inner_expression() {
        Expression::StringLiteral(literal) => literal_string_evidence(literal.value.as_str()),
        Expression::TemplateLiteral(template) => {
            if !template.expressions.is_empty() || template.quasis.len() != 1 {
                return StringEvidence::Opaque;
            }
            template.quasis.first().map_or(
                StringEvidence::Opaque,
                |quasi: &oxc_ast::ast::TemplateElement<'_>| {
                    quasi
                        .value
                        .cooked
                        .as_ref()
                        .map_or(StringEvidence::Opaque, |cooked: &oxc_span::Atom<'_>| {
                            literal_string_evidence(cooked.as_str())
                        })
                },
            )
        }
        Expression::Identifier(identifier) => bindings
            .get(identifier.name.as_str())
            .copied()
            .unwrap_or_default(),
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            let left: StringEvidence = string_evidence(&binary.left, bindings);
            let right: StringEvidence = string_evidence(&binary.right, bindings);
            if left == StringEvidence::None && right == StringEvidence::None {
                StringEvidence::None
            } else {
                StringEvidence::Opaque
            }
        }
        Expression::CallExpression(call) => match call.callee.get_inner_expression() {
            Expression::Identifier(identifier) if identifier.name.as_str() == "String" => {
                StringEvidence::Opaque
            }
            Expression::StaticMemberExpression(member)
                if is_string_only_method(member.property.name.as_str()) =>
            {
                StringEvidence::Opaque
            }
            _ => StringEvidence::None,
        },
        _ => StringEvidence::None,
    }
}

fn subject_blocks_index_resugar(
    iterable: &Expression<'_>,
    bindings: &BTreeMap<String, StringEvidence>,
) -> bool {
    string_evidence(iterable, bindings).blocks_index_resugar()
}

#[derive(Debug, Default)]
struct StringSubjectCollector {
    evidence: BTreeMap<String, StringEvidence>,
}

impl StringSubjectCollector {
    fn record(&mut self, name: &str, evidence: StringEvidence) {
        let slot: &mut StringEvidence = self.evidence.entry(name.to_owned()).or_default();
        *slot = slot.join(evidence);
    }
}

impl<'a> Visit<'a> for StringSubjectCollector {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        if let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind
            && let Some(init) = &declarator.init
        {
            let evidence: StringEvidence = string_evidence(init, &BTreeMap::new());
            if evidence != StringEvidence::None {
                self.record(binding.name.as_str(), evidence);
            }
        }
        oxc_ast::visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left
        {
            let evidence: StringEvidence = string_evidence(&assignment.right, &BTreeMap::new());
            if evidence != StringEvidence::None {
                self.record(target.name.as_str(), evidence);
            }
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assignment);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ArrayEvidence {
    #[default]
    None,
    PlainArray,
    Opaque,
}

impl ArrayEvidence {
    const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::None, value) | (value, Self::None) => value,
            (Self::PlainArray, Self::PlainArray) => Self::PlainArray,
            _ => Self::Opaque,
        }
    }

    const fn proves_plain_array(self) -> bool {
        matches!(self, Self::PlainArray)
    }
}

fn is_array_producing_static(object: &str, property: &str) -> bool {
    matches!(
        (object, property),
        ("Array", "from" | "of") | ("Object", "keys" | "values" | "entries")
    )
}

fn array_evidence(
    expr: &Expression<'_>,
    bindings: &BTreeMap<String, ArrayEvidence>,
) -> ArrayEvidence {
    match expr.get_inner_expression() {
        Expression::ArrayExpression(_) => ArrayEvidence::PlainArray,
        Expression::Identifier(identifier) => bindings
            .get(identifier.name.as_str())
            .copied()
            .unwrap_or_default(),
        Expression::CallExpression(call) => match call.callee.get_inner_expression() {
            Expression::StaticMemberExpression(member) => {
                match member.object.get_inner_expression() {
                    Expression::Identifier(object)
                        if is_array_producing_static(
                            object.name.as_str(),
                            member.property.name.as_str(),
                        ) =>
                    {
                        ArrayEvidence::PlainArray
                    }
                    _ => ArrayEvidence::None,
                }
            }
            _ => ArrayEvidence::None,
        },
        _ => ArrayEvidence::None,
    }
}

#[derive(Debug, Default)]
struct ArraySubjectCollector {
    evidence: BTreeMap<String, ArrayEvidence>,
}

impl ArraySubjectCollector {
    fn record(&mut self, name: &str, evidence: ArrayEvidence) {
        let observed: ArrayEvidence = if matches!(evidence, ArrayEvidence::None) {
            ArrayEvidence::Opaque
        } else {
            evidence
        };
        let slot: &mut ArrayEvidence = self.evidence.entry(name.to_owned()).or_default();
        *slot = slot.join(observed);
    }
}

impl<'a> Visit<'a> for ArraySubjectCollector {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        if let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind {
            let evidence: ArrayEvidence = declarator
                .init
                .as_ref()
                .map_or(ArrayEvidence::Opaque, |init: &Expression<'a>| {
                    array_evidence(init, &BTreeMap::new())
                });
            self.record(binding.name.as_str(), evidence);
        }
        oxc_ast::visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left
        {
            let evidence: ArrayEvidence = array_evidence(&assignment.right, &BTreeMap::new());
            self.record(target.name.as_str(), evidence);
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assignment);
    }

    fn visit_formal_parameter(&mut self, parameter: &oxc_ast::ast::FormalParameter<'a>) {
        for name in bound_names(&parameter.pattern.kind) {
            self.record(name, ArrayEvidence::Opaque);
        }
        oxc_ast::visit::walk::walk_formal_parameter(self, parameter);
    }

    fn visit_catch_parameter(&mut self, parameter: &oxc_ast::ast::CatchParameter<'a>) {
        for name in bound_names(&parameter.pattern.kind) {
            self.record(name, ArrayEvidence::Opaque);
        }
        oxc_ast::visit::walk::walk_catch_parameter(self, parameter);
    }
}

fn bound_names<'a>(kind: &'a BindingPatternKind<'a>) -> Vec<&'a str> {
    let mut names: Vec<&'a str> = Vec::new();
    collect_bound_names(kind, &mut names);
    names
}

fn collect_bound_names<'a>(kind: &'a BindingPatternKind<'a>, names: &mut Vec<&'a str>) {
    match kind {
        BindingPatternKind::BindingIdentifier(binding) => names.push(binding.name.as_str()),
        BindingPatternKind::ObjectPattern(pattern) => {
            for property in &pattern.properties {
                collect_bound_names(&property.value.kind, names);
            }
            if let Some(rest) = &pattern.rest {
                collect_bound_names(&rest.argument.kind, names);
            }
        }
        BindingPatternKind::ArrayPattern(pattern) => {
            for element in pattern.elements.iter().flatten() {
                collect_bound_names(&element.kind, names);
            }
            if let Some(rest) = &pattern.rest {
                collect_bound_names(&rest.argument.kind, names);
            }
        }
        BindingPatternKind::AssignmentPattern(pattern) => {
            collect_bound_names(&pattern.left.kind, names);
        }
    }
}

fn is_mutating_array_method(name: &str) -> bool {
    matches!(
        name,
        "push"
            | "pop"
            | "shift"
            | "unshift"
            | "splice"
            | "sort"
            | "reverse"
            | "fill"
            | "copyWithin"
    )
}

struct MutationProbe<'n> {
    name: &'n str,
    found: bool,
}

impl MutationProbe<'_> {
    fn names_subject(&self, expr: &Expression<'_>) -> bool {
        matches!(
            expr.get_inner_expression(),
            Expression::Identifier(identifier) if identifier.name == self.name
        )
    }

    fn target_names_subject(&self, target: &oxc_ast::ast::AssignmentTarget<'_>) -> bool {
        match target {
            oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                identifier.name == self.name
            }
            oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(member) => {
                self.names_subject(&member.object)
            }
            oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) => {
                self.names_subject(&member.object)
            }
            _ => false,
        }
    }
}

impl<'a> Visit<'a> for MutationProbe<'_> {
    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        if self.target_names_subject(&assignment.left) {
            self.found = true;
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assignment);
    }

    fn visit_update_expression(&mut self, update: &oxc_ast::ast::UpdateExpression<'a>) {
        match &update.argument {
            oxc_ast::ast::SimpleAssignmentTarget::ComputedMemberExpression(member)
                if self.names_subject(&member.object) =>
            {
                self.found = true;
            }
            oxc_ast::ast::SimpleAssignmentTarget::StaticMemberExpression(member)
                if self.names_subject(&member.object) =>
            {
                self.found = true;
            }
            _ => {}
        }
        oxc_ast::visit::walk::walk_update_expression(self, update);
    }

    fn visit_unary_expression(&mut self, unary: &oxc_ast::ast::UnaryExpression<'a>) {
        if unary.operator == UnaryOperator::Delete {
            match unary.argument.get_inner_expression() {
                Expression::ComputedMemberExpression(member)
                    if self.names_subject(&member.object) =>
                {
                    self.found = true;
                }
                Expression::StaticMemberExpression(member)
                    if self.names_subject(&member.object) =>
                {
                    self.found = true;
                }
                _ => {}
            }
        }
        oxc_ast::visit::walk::walk_unary_expression(self, unary);
    }

    fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
        if let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression()
            && self.names_subject(&member.object)
            && is_mutating_array_method(member.property.name.as_str())
        {
            self.found = true;
        }
        for argument in &call.arguments {
            if argument
                .as_expression()
                .is_some_and(|expr: &Expression<'a>| self.names_subject(expr))
            {
                self.found = true;
            }
        }
        oxc_ast::visit::walk::walk_call_expression(self, call);
    }
}

fn subject_mutated(statements: &[Statement<'_>], name: &str) -> bool {
    let mut probe: MutationProbe<'_> = MutationProbe { name, found: false };
    for stmt in statements {
        probe.visit_statement(stmt);
    }
    probe.found
}

fn materializing_helper_argument<'a>(
    expr: &'a Expression<'a>,
    scope: MaterializerScope<'_>,
) -> Option<&'a Expression<'a>> {
    let Expression::CallExpression(call) = expr.get_inner_expression() else {
        return None;
    };
    if call.arguments.len() != 1 {
        return None;
    }
    let recognized: bool = match call.callee.get_inner_expression() {
        Expression::Identifier(identifier) => scope.valid.contains(identifier.name.as_str()),
        Expression::StaticMemberExpression(member) => {
            !scope.array_rebound
                && matches!(
                    member.object.get_inner_expression(),
                    Expression::Identifier(object) if object.name == "Array"
                )
                && matches!(member.property.name.as_str(), "from" | "of")
        }
        _ => false,
    };
    if !recognized {
        return None;
    }
    call.arguments.first()?.as_expression()
}

fn snapshot_subject_source<'s>(
    iterable: &Expression<'_>,
    array_subjects: &BTreeMap<String, ArrayEvidence>,
    scope: MaterializerScope<'_>,
    remaining: &[Statement<'_>],
    source: &'s str,
) -> Option<&'s str> {
    let inner: &Expression<'_> = materializing_helper_argument(iterable, scope)?;
    let Expression::Identifier(subject) = inner.get_inner_expression() else {
        return None;
    };
    if !array_evidence(inner, array_subjects).proves_plain_array() {
        return None;
    }
    if subject_mutated(remaining, subject.name.as_str()) {
        return None;
    }
    Some(inner.span().source_text(source))
}

fn is_loose_helper_name(name: &str) -> bool {
    matches!(
        name,
        "_createForOfIteratorHelperLoose" | "createForOfIteratorHelperLoose"
    )
}

fn is_babel_loose_helper(source: &str, name: &str) -> bool {
    let compact: String = source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect();
    let expected: String = format!(
        "function{name}(o){{varit=typeofSymbol!==\"undefined\"&&o[Symbol.iterator]||o[\"@@iterator\"];if(it)return(it=it.call(o)).next.bind(it);if(Array.isArray(o)){{vari=0;returnfunction(){{if(i>=o.length)return{{done:true}};return{{done:false,value:o[i++]}};}};}}thrownewTypeError(\"notiterable\");}}"
    );
    compact == expected
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_for_statement(&mut self, for_stmt: &ForStatement<'a>) {
        if let Some(edit) = try_convert(
            for_stmt,
            self.source,
            self.string_subjects,
            self.array_subjects,
            self.materializer_scope,
        ) {
            if !edit_overlaps_comments(&edit, self.comments) {
                self.edits.push(edit);
            }
            return;
        }
        if let Some(edit) = try_convert_direct(
            for_stmt,
            self.source,
            self.string_subjects,
            self.array_subjects,
            self.materializer_scope,
        ) {
            if !edit_overlaps_comments(&edit, self.comments) {
                self.edits.push(edit);
            }
            return;
        }
        oxc_ast::visit::walk::walk_for_statement(self, for_stmt);
    }

    fn visit_statements(&mut self, statements: &oxc_allocator::Vec<'a, Statement<'a>>) {
        let slice: &[Statement<'a>] = statements.as_slice();
        let mut index: usize = 0;
        while index < slice.len() {
            if let Statement::ForStatement(for_stmt) = &slice[index]
                && let Some(edit) = try_convert_loose(
                    for_stmt,
                    &slice[index + 1..],
                    self.source,
                    &self.loose_helpers,
                )
            {
                if !edit_overlaps_comments(&edit, self.comments) {
                    self.edits.push(edit);
                    self.helper_loops_converted += 1;
                }
                index += 1;
                continue;
            }
            if let Some(values_edits) = try_convert_values_at(slice, index, self.source) {
                if values_edits
                    .iter()
                    .all(|edit: &Edit| !edit_overlaps_comments(edit, self.comments))
                {
                    self.edits.extend(values_edits);
                    self.helper_loops_converted += 1;
                }
                index += 1;
                continue;
            }
            if index + 1 < slice.len()
                && let Some((edit, consumed)) =
                    try_convert_helper_sequence(&slice[index..], self.source)
            {
                if !edit_overlaps_comments(&edit, self.comments) {
                    self.edits.push(edit);
                    self.helper_loops_converted += 1;
                }
                index += consumed;
                continue;
            }
            oxc_ast::visit::walk::walk_statement(self, &slice[index]);
            index += 1;
        }
    }
}

struct LooseMatch<'a> {
    iterable: &'a Expression<'a>,
    iterator_name: &'a str,
    step_name: &'a str,
    element_kind: VariableDeclarationKind,
    element: ElementBinding<'a>,
    body: &'a [Statement<'a>],
}

fn try_convert_loose(
    for_stmt: &ForStatement<'_>,
    tail: &[Statement<'_>],
    source: &str,
    loose_helpers: &BTreeSet<String>,
) -> Option<Edit> {
    let matched: LooseMatch<'_> = match_loose_loop(for_stmt, loose_helpers)?;
    if body_uses(matched.body, matched.iterator_name)
        || body_uses(matched.body, matched.step_name)
        || body_uses(tail, matched.iterator_name)
        || body_uses(tail, matched.step_name)
        || matched
            .element
            .temp_ref
            .is_some_and(|name: &str| body_uses(matched.body, name) || body_uses(tail, name))
    {
        return None;
    }
    let kind: &str = binding_kind(matched.element_kind, &matched.element, matched.body)?;
    let iterable_src: &str = matched.iterable.span().source_text(source);
    let body_src: String = remaining_body_source(matched.body, source);
    Some(Edit {
        start: for_stmt.span.start as usize,
        end: for_stmt.span.end as usize,
        replacement: format!(
            "for ({kind} {element} of {iterable_src}) {{{body_src}}}",
            element = matched.element.text
        ),
    })
}

fn match_loose_loop<'a>(
    for_stmt: &'a ForStatement<'a>,
    loose_helpers: &BTreeSet<String>,
) -> Option<LooseMatch<'a>> {
    if for_stmt.update.is_some() {
        return None;
    }
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_stmt.init else {
        return None;
    };
    if init.declarations.len() != 2 || init.declarations[1].init.is_some() {
        return None;
    }
    let iterator_name: &str = declarator_name(init, 0)?;
    let step_name: &str = declarator_name(init, 1)?;
    let iterable: &Expression<'_> =
        loose_helper_argument(init.declarations[0].init.as_ref()?, loose_helpers)?;
    if !is_loose_helper_test(for_stmt.test.as_ref()?, iterator_name, step_name) {
        return None;
    }
    let Statement::BlockStatement(block) = &for_stmt.body else {
        return None;
    };
    let (element_kind, element, consumed): (VariableDeclarationKind, ElementBinding<'_>, usize) =
        element_from_step_value(block.body.as_slice(), step_name)?;
    Some(LooseMatch {
        iterable,
        iterator_name,
        step_name,
        element_kind,
        element,
        body: &block.body.as_slice()[consumed..],
    })
}

fn loose_helper_argument<'a>(
    init: &'a Expression<'a>,
    loose_helpers: &BTreeSet<String>,
) -> Option<&'a Expression<'a>> {
    let Expression::CallExpression(call) = init else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if !loose_helpers.contains(callee.name.as_str()) || call.arguments.len() != 1 {
        return None;
    }
    call.arguments[0].as_expression()
}

fn is_loose_helper_test(test: &Expression<'_>, iterator_name: &str, step_name: &str) -> bool {
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
    if assign.operator != AssignmentOperator::Assign {
        return false;
    }
    if assign
        .left
        .get_identifier()
        .is_none_or(|name: &str| name != step_name)
    {
        return false;
    }
    let Expression::CallExpression(call) = &assign.right else {
        return false;
    };
    call.arguments.is_empty()
        && matches!(&call.callee, Expression::Identifier(id) if id.name == iterator_name)
}

struct Match<'a> {
    iterable: &'a Expression<'a>,
    element_kind: VariableDeclarationKind,
    element: ElementBinding<'a>,
    remaining: &'a [Statement<'a>],
    index_name: &'a str,
    array_name: &'a str,
}

fn try_convert(
    for_stmt: &ForStatement<'_>,
    source: &str,
    string_subjects: &BTreeMap<String, StringEvidence>,
    array_subjects: &BTreeMap<String, ArrayEvidence>,
    materializer_scope: MaterializerScope<'_>,
) -> Option<Edit> {
    let m: Match<'_> = match_loop(for_stmt, source)?;
    if subject_blocks_index_resugar(m.iterable, string_subjects) {
        return None;
    }
    if body_uses(m.remaining, m.index_name)
        || body_uses(m.remaining, m.array_name)
        || m.element.binds_name(m.index_name)
        || m.element.binds_name(m.array_name)
        || binding_shadows_expression(&m.element, m.iterable)
        || m.element.references_name(m.index_name)
        || m.element.references_name(m.array_name)
    {
        return None;
    }
    let kind: &str = binding_kind(m.element_kind, &m.element, m.remaining)?;
    let iterable_src: &str = snapshot_subject_source(
        m.iterable,
        array_subjects,
        materializer_scope,
        m.remaining,
        source,
    )
    .unwrap_or_else(|| m.iterable.span().source_text(source));
    let body_src: String = remaining_body_source(m.remaining, source);
    Some(Edit {
        start: for_stmt.span.start as usize,
        end: for_stmt.span.end as usize,
        replacement: format!(
            "for ({kind} {element} of {iterable_src}) {{{body_src}}}",
            element = m.element.text
        ),
    })
}

struct DirectMatch<'a> {
    iterable: &'a Expression<'a>,
    element_kind: VariableDeclarationKind,
    element: ElementBinding<'a>,
    remaining: &'a [Statement<'a>],
    index_name: &'a str,
    length_cache_name: Option<&'a str>,
}

fn try_convert_direct(
    for_stmt: &ForStatement<'_>,
    source: &str,
    string_subjects: &BTreeMap<String, StringEvidence>,
    array_subjects: &BTreeMap<String, ArrayEvidence>,
    materializer_scope: MaterializerScope<'_>,
) -> Option<Edit> {
    let m: DirectMatch<'_> = match_direct_loop(for_stmt, source)?;
    if subject_blocks_index_resugar(m.iterable, string_subjects) {
        return None;
    }
    if body_uses(m.remaining, m.index_name)
        || m.element.binds_name(m.index_name)
        || m.element.references_name(m.index_name)
    {
        return None;
    }
    if let Some(cache) = m.length_cache_name
        && (body_uses(m.remaining, cache)
            || m.element.binds_name(cache)
            || m.element.references_name(cache))
    {
        return None;
    }
    let kind: &str = binding_kind(m.element_kind, &m.element, m.remaining)?;
    let iterable_src: &str = snapshot_subject_source(
        m.iterable,
        array_subjects,
        materializer_scope,
        m.remaining,
        source,
    )
    .unwrap_or_else(|| m.iterable.span().source_text(source));
    let body_src: String = remaining_body_source(m.remaining, source);
    Some(Edit {
        start: for_stmt.span.start as usize,
        end: for_stmt.span.end as usize,
        replacement: format!(
            "for ({kind} {element} of {iterable_src}) {{{body_src}}}",
            element = m.element.text
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

    let (iterable, element_kind, element, length_cache_name): (
        &Expression<'_>,
        VariableDeclarationKind,
        ElementBinding<'_>,
        Option<&str>,
    ) = match init.declarations.len() {
        1 => {
            let iterable: &Expression<'_> =
                test_length_object(for_stmt.test.as_ref()?, index_name)?;
            let iterable_src: &str = iterable.span().source_text(source);
            let (kind, element): (VariableDeclarationKind, ElementBinding<'_>) =
                element_from_iterable_access(first, iterable_src, index_name, source)?;
            (iterable, kind, element, None)
        }
        2 => {
            let cache_name: &str = declarator_name(init, 1)?;
            let iterable: &Expression<'_> =
                length_init_object(init.declarations[1].init.as_ref()?)?;
            if !matches_cache_test(for_stmt.test.as_ref()?, index_name, cache_name) {
                return None;
            }
            let iterable_src: &str = iterable.span().source_text(source);
            let (kind, element): (VariableDeclarationKind, ElementBinding<'_>) =
                element_from_iterable_access(first, iterable_src, index_name, source)?;
            (iterable, kind, element, Some(cache_name))
        }
        _ => return None,
    };

    Some(DirectMatch {
        iterable,
        element_kind,
        element,
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
) -> Option<(VariableDeclarationKind, ElementBinding<'a>)> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
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
    Some((decl.kind, element_binding(&declarator.id, source)?))
}

fn match_loop<'a>(for_stmt: &'a ForStatement<'a>, source: &str) -> Option<Match<'a>> {
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
    let (element_kind, element): (VariableDeclarationKind, ElementBinding<'_>) =
        element_from_index_access(first, array_name, index_name, source)?;

    Some(Match {
        iterable,
        element_kind,
        element,
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
) -> Option<&'static str> {
    match element_kind {
        VariableDeclarationKind::Var => Some("var"),
        VariableDeclarationKind::Const => Some("const"),
        VariableDeclarationKind::Let => Some(
            if binding
                .bound_names
                .iter()
                .any(|name: &&str| body_reassigns(body, name))
            {
                "let"
            } else {
                "const"
            },
        ),
        _ => None,
    }
}

fn try_convert_helper_sequence(
    statements: &[Statement<'_>],
    source: &str,
) -> Option<(Edit, usize)> {
    let m: HelperMatch<'_> = match_helper_sequence(statements)?;
    let kind: &str = binding_kind(m.element_kind, &m.element, m.body)?;
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

    let kind: &str = binding_kind(element_kind, &element, body)?;
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
    referenced_names: Vec<&'a str>,
}

struct BindingNameCollector<'a> {
    names: Vec<&'a str>,
    references: Vec<&'a str>,
}

impl<'a> Visit<'a> for BindingNameCollector<'a> {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        self.names.push(identifier.name.as_str());
    }

    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        self.references.push(identifier.name.as_str());
    }
}

impl ElementBinding<'_> {
    fn binds_name(&self, name: &str) -> bool {
        self.bound_names.contains(&name)
    }

    fn references_name(&self, name: &str) -> bool {
        self.referenced_names.contains(&name)
    }
}

fn binding_shadows_expression(binding: &ElementBinding<'_>, expression: &Expression<'_>) -> bool {
    let mut collector: BindingNameCollector<'_> = BindingNameCollector {
        names: Vec::new(),
        references: Vec::new(),
    };
    collector.visit_expression(expression);
    binding
        .bound_names
        .iter()
        .any(|name: &&str| collector.references.contains(name))
}

fn element_binding<'a>(
    pattern: &'a oxc_ast::ast::BindingPattern<'a>,
    source: &str,
) -> Option<ElementBinding<'a>> {
    let mut collector: BindingNameCollector<'a> = BindingNameCollector {
        names: Vec::new(),
        references: Vec::new(),
    };
    collector.visit_binding_pattern(pattern);
    if collector.names.is_empty() {
        return None;
    }
    Some(ElementBinding {
        text: pattern.span().source_text(source).to_owned(),
        temp_ref: None,
        bound_names: collector.names,
        referenced_names: collector.references,
    })
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
            referenced_names: Vec::new(),
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
            referenced_names: Vec::new(),
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
    source: &str,
) -> Option<(VariableDeclarationKind, ElementBinding<'a>)> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator = &decl.declarations[0];
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
    Some((decl.kind, element_binding(&declarator.id, source)?))
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
        if assignment_target_rebinds(&assign.left, self.name) {
            self.found = true;
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assign);
    }

    fn visit_update_expression(&mut self, update: &oxc_ast::ast::UpdateExpression<'a>) {
        if matches!(
            &update.argument,
            oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier)
                if identifier.name == self.name
        ) {
            self.found = true;
        }
        oxc_ast::visit::walk::walk_update_expression(self, update);
    }
}

fn assignment_target_rebinds(target: &oxc_ast::ast::AssignmentTarget<'_>, name: &str) -> bool {
    match target {
        oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            identifier.name == name
        }
        oxc_ast::ast::AssignmentTarget::ArrayAssignmentTarget(array) => {
            array
                .elements
                .iter()
                .flatten()
                .any(|element| assignment_target_maybe_default_rebinds(element, name))
                || array
                    .rest
                    .as_ref()
                    .is_some_and(|rest| assignment_target_rebinds(&rest.target, name))
        }
        oxc_ast::ast::AssignmentTarget::ObjectAssignmentTarget(object) => {
            object.properties.iter().any(|property| match property {
                oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(
                    property,
                ) => property.binding.name == name,
                oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyProperty(
                    property,
                ) => assignment_target_maybe_default_rebinds(&property.binding, name),
            }) || object
                .rest
                .as_ref()
                .is_some_and(|rest| assignment_target_rebinds(&rest.target, name))
        }
        _ => false,
    }
}

fn assignment_target_maybe_default_rebinds(
    target: &oxc_ast::ast::AssignmentTargetMaybeDefault<'_>,
    name: &str,
) -> bool {
    match target {
        oxc_ast::ast::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(default) => {
            assignment_target_rebinds(&default.binding, name)
        }
        target => target
            .as_assignment_target()
            .is_some_and(|target| assignment_target_rebinds(target, name)),
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
