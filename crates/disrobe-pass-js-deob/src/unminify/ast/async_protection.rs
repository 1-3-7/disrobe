use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentOperator, BindingPatternKind, CallExpression, Expression, Function,
    IdentifierReference, ImportDeclarationSpecifier, Program, Statement,
};
use oxc_ast::{Visit, visit::walk};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, ReferenceId, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::{GetSpan, SourceType, Span};

use super::Edit;

#[derive(Debug, Clone)]
pub(super) enum AsyncProtection {
    None,
    Global,
    Ranges(Vec<Span>),
}

impl AsyncProtection {
    pub(super) fn blocks_edits(&self, edits: &[Edit]) -> bool {
        match self {
            Self::None => false,
            Self::Global => !edits.is_empty(),
            Self::Ranges(ranges) => edits.iter().any(|edit: &Edit| {
                ranges
                    .iter()
                    .copied()
                    .any(|range: Span| edit_intersects_range(edit, range))
            }),
        }
    }

    pub(super) const fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }
}

struct WrapperPair {
    public_symbol: SymbolId,
    helper_symbol: SymbolId,
    helper_reference: ReferenceId,
    public_span: Span,
    helper_span: Span,
}

struct DirectHelperBinding {
    symbol: SymbolId,
    helper_reference: ReferenceId,
    declaration_span: Span,
}

enum TrustedHelperImports {
    None,
    Invalid,
    Trusted(BTreeSet<SymbolId>, Vec<Span>),
}

pub(super) fn analyze(source: &str) -> AsyncProtection {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = match SourceType::from_path("input.js") {
        Ok(value) => value,
        Err(_) => return AsyncProtection::Global,
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return AsyncProtection::Global;
    }
    let program: &Program<'_> = &parsed.program;
    let semantic_return: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program);
    if !semantic_return.errors.is_empty() {
        return AsyncProtection::Global;
    }
    let semantic: Semantic<'_> = semantic_return.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    if has_exact_babel_async_helper_specifier_call(program) {
        return AsyncProtection::Global;
    }
    let (trusted_helpers, mut ranges): (BTreeSet<SymbolId>, Vec<Span>) =
        match trusted_helper_imports(program, symbols) {
            TrustedHelperImports::None => return AsyncProtection::None,
            TrustedHelperImports::Invalid => return AsyncProtection::Global,
            TrustedHelperImports::Trusted(helpers, ranges) => (helpers, ranges),
        };
    if trusted_helpers.is_empty() {
        return AsyncProtection::None;
    }

    let statements: &[Statement<'_>] = program.body.as_slice();
    let mut helper_references: Vec<ReferenceId> = Vec::new();
    let mut index: usize = 0;
    while index < statements.len() {
        if let Some(pair) = wrapper_pair(statements, index, symbols, &trusted_helpers) {
            ranges.push(pair.public_span);
            ranges.push(pair.helper_span);
            append_symbol_ranges(&mut ranges, pair.public_symbol, symbols, semantic.nodes());
            append_symbol_ranges(&mut ranges, pair.helper_symbol, symbols, semantic.nodes());
            helper_references.push(pair.helper_reference);
            index += 2;
            continue;
        }
        for binding in direct_helper_bindings(&statements[index], symbols, &trusted_helpers) {
            ranges.push(binding.declaration_span);
            append_symbol_ranges(&mut ranges, binding.symbol, symbols, semantic.nodes());
            helper_references.push(binding.helper_reference);
        }
        index += 1;
    }

    for helper_symbol in trusted_helpers {
        if symbols
            .get_resolved_reference_ids(helper_symbol)
            .iter()
            .any(|reference_id: &ReferenceId| !helper_references.contains(reference_id))
        {
            return AsyncProtection::Global;
        }
    }
    if helper_references.is_empty() {
        return AsyncProtection::None;
    }
    if ranges.is_empty() {
        return AsyncProtection::None;
    }
    ranges.sort_by_key(|span: &Span| (span.start, span.end));
    ranges.dedup_by(|left: &mut Span, right: &mut Span| left == right);
    AsyncProtection::Ranges(ranges)
}

fn trusted_helper_imports(program: &Program<'_>, symbols: &SymbolTable) -> TrustedHelperImports {
    let mut trusted_helpers: BTreeSet<SymbolId> = BTreeSet::new();
    let mut ranges: Vec<Span> = Vec::new();
    let mut found_import: bool = false;
    for statement in &program.body {
        let Statement::ImportDeclaration(import) = statement else {
            continue;
        };
        if !is_babel_async_helper_import(import.source.value.as_str()) {
            continue;
        }
        found_import = true;
        let Some(specifiers) = import.specifiers.as_ref() else {
            return TrustedHelperImports::Invalid;
        };
        if specifiers.len() != 1 {
            return TrustedHelperImports::Invalid;
        }
        let ImportDeclarationSpecifier::ImportDefaultSpecifier(default) = &specifiers[0] else {
            return TrustedHelperImports::Invalid;
        };
        let Some(symbol_id): Option<SymbolId> = default.local.symbol_id.get() else {
            return TrustedHelperImports::Invalid;
        };
        if symbols.symbol_is_mutated(symbol_id) {
            return TrustedHelperImports::Invalid;
        }
        trusted_helpers.insert(symbol_id);
        ranges.push(import.span);
    }
    if !found_import {
        return TrustedHelperImports::None;
    }
    TrustedHelperImports::Trusted(trusted_helpers, ranges)
}

fn is_babel_async_helper_import(source: &str) -> bool {
    matches!(
        source,
        "@babel/runtime/helpers/asyncToGenerator"
            | "@babel/runtime/helpers/asyncToGenerator.js"
            | "@babel/runtime/helpers/esm/asyncToGenerator"
            | "@babel/runtime/helpers/esm/asyncToGenerator.js"
    )
}

struct ExactBabelAsyncHelperSpecifierCallVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for ExactBabelAsyncHelperSpecifierCallVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'ast>) {
        if is_exact_babel_async_helper_specifier_call(call) {
            self.found = true;
        }
        walk::walk_call_expression(self, call);
    }
}

fn has_exact_babel_async_helper_specifier_call(program: &Program<'_>) -> bool {
    let mut visitor: ExactBabelAsyncHelperSpecifierCallVisitor =
        ExactBabelAsyncHelperSpecifierCallVisitor { found: false };
    visitor.visit_program(program);
    visitor.found
}

fn is_exact_babel_async_helper_specifier_call(call: &CallExpression<'_>) -> bool {
    if call.arguments.len() != 1 {
        return false;
    }
    let Argument::StringLiteral(source) = &call.arguments[0] else {
        return false;
    };
    is_babel_async_helper_import(source.value.as_str())
}

fn wrapper_pair(
    statements: &[Statement<'_>],
    start: usize,
    symbols: &SymbolTable,
    trusted_helpers: &BTreeSet<SymbolId>,
) -> Option<WrapperPair> {
    let Statement::FunctionDeclaration(public_fn): &Statement<'_> = statements.get(start)? else {
        return None;
    };
    let public_symbol: SymbolId = public_fn.id.as_ref()?.symbol_id.get()?;
    let helper_reference: &IdentifierReference<'_> = wrapper_returns_apply(public_fn)?;
    let helper_fn: &Function<'_> = statements.get(start + 1).and_then(function_declaration)?;
    let helper_symbol: SymbolId = helper_fn.id.as_ref()?.symbol_id.get()?;
    if !reference_resolves_to(helper_reference, helper_symbol, symbols) {
        return None;
    }
    let helper_reference_id: ReferenceId =
        cached_helper_reference(helper_fn, helper_symbol, symbols, trusted_helpers)?;
    Some(WrapperPair {
        public_symbol,
        helper_symbol,
        helper_reference: helper_reference_id,
        public_span: public_fn.span,
        helper_span: helper_fn.span,
    })
}

fn direct_helper_bindings(
    statement: &Statement<'_>,
    symbols: &SymbolTable,
    trusted_helpers: &BTreeSet<SymbolId>,
) -> Vec<DirectHelperBinding> {
    let Statement::VariableDeclaration(declaration) = statement else {
        return Vec::new();
    };
    let mut bindings: Vec<DirectHelperBinding> = Vec::new();
    for declarator in &declaration.declarations {
        let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
            continue;
        };
        let Some(symbol): Option<SymbolId> = binding.symbol_id.get() else {
            continue;
        };
        let Some(init): Option<&Expression<'_>> = declarator.init.as_ref() else {
            continue;
        };
        let Some(helper_reference): Option<ReferenceId> =
            trusted_helper_call(init, symbols, trusted_helpers)
        else {
            continue;
        };
        bindings.push(DirectHelperBinding {
            symbol,
            helper_reference,
            declaration_span: declaration.span,
        });
    }
    bindings
}

fn wrapper_returns_apply<'a, 'b>(func: &'b Function<'a>) -> Option<&'b IdentifierReference<'a>> {
    let body: &'b oxc_allocator::Box<'a, oxc_ast::ast::FunctionBody<'a>> = func.body.as_ref()?;
    if body.directives.is_empty() && body.statements.len() == 1 {
        let Statement::ReturnStatement(ret): &Statement<'a> = &body.statements[0] else {
            return None;
        };
        return apply_target(ret.argument.as_ref()?);
    }
    None
}

fn function_declaration<'a, 'b>(statement: &'b Statement<'a>) -> Option<&'b Function<'a>> {
    let Statement::FunctionDeclaration(function) = statement else {
        return None;
    };
    Some(function)
}

fn cached_helper_reference(
    helper: &Function<'_>,
    helper_symbol: SymbolId,
    symbols: &SymbolTable,
    trusted_helpers: &BTreeSet<SymbolId>,
) -> Option<ReferenceId> {
    let body: &oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>> = helper.body.as_ref()?;
    if !body.directives.is_empty() || body.statements.len() != 2 {
        return None;
    }
    let Statement::ExpressionStatement(expression) = &body.statements[0] else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = &expression.expression else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign {
        return None;
    }
    let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(lhs) = &assignment.left else {
        return None;
    };
    if !reference_resolves_to(lhs, helper_symbol, symbols) {
        return None;
    }
    let helper_reference: ReferenceId =
        trusted_helper_call(&assignment.right, symbols, trusted_helpers)?;
    let Statement::ReturnStatement(ret) = &body.statements[1] else {
        return None;
    };
    let target: &IdentifierReference<'_> = apply_target(ret.argument.as_ref()?)?;
    if !reference_resolves_to(target, helper_symbol, symbols) {
        return None;
    }
    Some(helper_reference)
}

fn trusted_helper_call(
    expression: &Expression<'_>,
    symbols: &SymbolTable,
    trusted_helpers: &BTreeSet<SymbolId>,
) -> Option<ReferenceId> {
    let Expression::CallExpression(call) = expression else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    let reference_id: ReferenceId = callee.reference_id.get()?;
    let symbol_id: SymbolId = symbols.get_reference(reference_id).symbol_id()?;
    trusted_helpers.contains(&symbol_id).then_some(reference_id)
}

fn apply_target<'a, 'b>(expression: &'b Expression<'a>) -> Option<&'b IdentifierReference<'a>> {
    let Expression::CallExpression(call): &'b Expression<'a> = expression else {
        return None;
    };
    let member: &oxc_ast::ast::MemberExpression<'a> = call.callee.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(static_member): &oxc_ast::ast::MemberExpression<'a> =
        member
    else {
        return None;
    };
    if static_member.property.name.as_str() != "apply" || call.arguments.len() != 2 {
        return None;
    }
    let Expression::Identifier(target): &Expression<'a> = &static_member.object else {
        return None;
    };
    if !matches!(&call.arguments[0], Argument::ThisExpression(_)) {
        return None;
    }
    let Argument::Identifier(arguments): &Argument<'a> = &call.arguments[1] else {
        return None;
    };
    (arguments.name.as_str() == "arguments").then_some(target)
}

fn reference_resolves_to(
    reference: &IdentifierReference<'_>,
    symbol: SymbolId,
    symbols: &SymbolTable,
) -> bool {
    let Some(reference_id): Option<ReferenceId> = reference.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id() == Some(symbol)
}

fn append_symbol_ranges(
    ranges: &mut Vec<Span>,
    symbol: SymbolId,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) {
    for &reference_id in symbols.get_resolved_reference_ids(symbol) {
        let reference: &oxc_semantic::Reference = symbols.get_reference(reference_id);
        ranges.push(nodes.get_node(reference.node_id()).kind().span());
    }
}

fn edit_intersects_range(edit: &Edit, range: Span) -> bool {
    let Ok(range_start): Result<usize, _> = usize::try_from(range.start) else {
        return true;
    };
    let Ok(range_end): Result<usize, _> = usize::try_from(range.end) else {
        return true;
    };
    if edit.start == edit.end {
        return range_start <= edit.start && edit.start <= range_end;
    }
    edit.start < range_end && range_start < edit.end
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHED_WRAPPER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
function load() { return _load.apply(this, arguments); }
function _load() {
  _load = babelAsync(function* () { return yield Promise.resolve(1); });
  return _load.apply(this, arguments);
}";

    const DIRECT_BINDING: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator';
const load = babelAsync(function* () { return yield Promise.resolve(1); });";

    const ESCAPED_CACHED_WRAPPER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGener\u0061tor';
function load() { return _load.apply(this, arguments); }
function _load() {
  _load = babelAsync(function* () { return yield Promise.resolve(1); });
  return _load.apply(this, arguments);
}";

    const SUFFIXED_CACHED_WRAPPER: &str = r"
import babelAsync from '@babel/runtime/helpers/asyncToGenerator.js';
function load() { return _load.apply(this, arguments); }
function _load() {
  _load = babelAsync(function* () { return yield Promise.resolve(1); });
  return _load.apply(this, arguments);
}";

    const SUFFIXED_ESM_DIRECT_BINDING: &str = r"
import babelAsync from '@babel/runtime/helpers/esm/asyncToGenerator.js';
const load = babelAsync(function* () { return yield Promise.resolve(1); });";

    #[test]
    fn classifies_helper_bindings_and_unsupported_forms() {
        assert!(matches!(analyze("var value = 1;"), AsyncProtection::None));
        assert!(matches!(
            analyze(CACHED_WRAPPER),
            AsyncProtection::Ranges(_)
        ));
        assert!(matches!(
            analyze(DIRECT_BINDING),
            AsyncProtection::Ranges(_)
        ));
        assert!(matches!(
            analyze(ESCAPED_CACHED_WRAPPER),
            AsyncProtection::Ranges(_)
        ));
        assert!(matches!(
            analyze(SUFFIXED_CACHED_WRAPPER),
            AsyncProtection::Ranges(_)
        ));
        assert!(matches!(
            analyze(SUFFIXED_ESM_DIRECT_BINDING),
            AsyncProtection::Ranges(_)
        ));
        assert!(matches!(
            analyze(
                "import babelAsync from '@babel/runtime/helpers/asyncToGenerator'; babelAsync;"
            ),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze("const babelAsync = require('@babel/runtime/helpers/asyncToGenerator');"),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze("const babelAsync = require('@babel/runtime/helpers/asyncToGener\\u0061tor');"),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze("const babelAsync = require('@babel/runtime/helpers/asyncToGenerator.js');"),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze(
                "function require(path) { return path; } const path = require('@babel/runtime/helpers/asyncToGenerator');"
            ),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze(
                "function require(path) { return path; } const path = (require)('@babel/runtime/helpers/asyncToGenerator');"
            ),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze(
                "function load(path) { return path; } const path = load('@babel/runtime/helpers/asyncToGenerator');"
            ),
            AsyncProtection::Global
        ));
        assert!(matches!(
            analyze(
                "const path = load('@babel/runtime/helpers/asyncToGenerator-extra'); var untouched = 1;"
            ),
            AsyncProtection::None
        ));
    }

    #[test]
    fn protects_range_boundaries_and_rejects_mixed_outcomes() {
        let protection: AsyncProtection = AsyncProtection::Ranges(vec![Span::new(3, 6)]);
        let at_start: Edit = Edit {
            start: 3,
            end: 3,
            replacement: String::new(),
        };
        let at_end: Edit = Edit {
            start: 6,
            end: 6,
            replacement: String::new(),
        };
        let outside: Edit = Edit {
            start: 7,
            end: 8,
            replacement: String::new(),
        };
        assert!(protection.blocks_edits(&[at_start]));
        assert!(protection.blocks_edits(&[at_end]));
        assert!(!protection.blocks_edits(&[outside]));
        assert!(protection.blocks_edits(&[
            Edit {
                start: 7,
                end: 8,
                replacement: String::new(),
            },
            Edit {
                start: 4,
                end: 5,
                replacement: String::new(),
            }
        ]));
    }
}
