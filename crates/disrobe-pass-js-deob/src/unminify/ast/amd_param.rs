use indexmap::{IndexMap, IndexSet};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpression, BindingPatternKind, CallExpression, Expression, FormalParameters,
    FunctionBody,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, ReferenceId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::SourceType;

use super::import_rename::push_reference_edits;
use super::rename_scope::{RenameSafety, collect_reserved_names};
use super::require_alias::{derive_module_names, is_minified_local};
use super::{Edit, RuleOutcome, edit_overlaps_comments};

#[derive(Debug, Clone, Default)]
pub(super) struct AmdParamStats {
    pub(super) parameters_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, AmdParamStats) {
    let allocator: Allocator = Allocator::default();
    let Ok(source_type): Result<SourceType, _> = SourceType::from_path("input.js") else {
        return (RuleOutcome::empty(), AmdParamStats::default());
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AmdParamStats = AmdParamStats::default();

    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some((dependencies, parameters)): Option<(
            &ArrayExpression<'_>,
            &FormalParameters<'_>,
        )> = amd_factory(call, symbols) else {
            continue;
        };
        for (parameter, dependency) in parameters.items.iter().zip(&dependencies.elements) {
            let Some(Expression::StringLiteral(specifier)) = dependency.as_expression() else {
                continue;
            };
            let specifier: &str = specifier.value.as_str();
            if is_amd_runtime_dependency(specifier) || specifier.contains('!') {
                continue;
            }
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                continue;
            };
            let local_name: &str = binding.name.as_str();
            if !is_minified_local(local_name) {
                continue;
            }
            let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                continue;
            };
            let Some(preferred): Option<String> = derive_module_names(specifier).into_iter().next()
            else {
                continue;
            };
            if preferred == local_name {
                continue;
            }
            let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
            let Some(new_name): Option<String> = choose_name(
                &safety,
                symbol_id,
                owner_scope,
                local_name,
                &preferred,
                &reserved,
                &mut next_suffixes,
            ) else {
                continue;
            };
            let mut candidate_edits: Vec<Edit> = vec![Edit {
                start: binding.span.start as usize,
                end: binding.span.end as usize,
                replacement: new_name.clone(),
            }];
            push_reference_edits(symbols, nodes, symbol_id, &new_name, &mut candidate_edits);
            if candidate_edits
                .iter()
                .any(|edit: &Edit| edit_overlaps_comments(edit, &parsed.program.comments))
            {
                continue;
            }
            reserved.insert(new_name);
            edits.extend(candidate_edits);
            stats.parameters_renamed += 1;
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }
    (RuleOutcome { edits }, stats)
}

fn amd_factory<'a>(
    call: &'a CallExpression<'a>,
    symbols: &SymbolTable,
) -> Option<(&'a ArrayExpression<'a>, &'a FormalParameters<'a>)> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "define" {
        return None;
    }
    let reference_id: ReferenceId = callee.reference_id.get()?;
    if symbols.get_reference(reference_id).symbol_id().is_some() {
        return None;
    }
    let (dependencies, factory): (&Argument<'_>, &Argument<'_>) = match call.arguments.as_slice() {
        [dependencies, factory] => (dependencies, factory),
        [Argument::StringLiteral(_module_id), dependencies, factory] => (dependencies, factory),
        _ => return None,
    };
    let Argument::ArrayExpression(dependencies) = dependencies else {
        return None;
    };
    let (parameters, body): (&FormalParameters<'_>, &FunctionBody<'_>) = match factory {
        Argument::FunctionExpression(factory) => (&factory.params, factory.body.as_ref()?),
        Argument::ArrowFunctionExpression(factory) => (&factory.params, &factory.body),
        _ => return None,
    };
    if body_has_dynamic_scope(body) {
        return None;
    }
    if parameters.rest.is_some()
        || parameters.items.iter().any(|parameter| {
            !matches!(
                parameter.pattern.kind,
                BindingPatternKind::BindingIdentifier(_)
            )
        })
    {
        return None;
    }
    let all_dependencies_are_static: bool = dependencies
        .elements
        .iter()
        .all(|element| matches!(element.as_expression(), Some(Expression::StringLiteral(_))));
    if !all_dependencies_are_static {
        return None;
    }
    Some((dependencies, parameters))
}

fn is_amd_runtime_dependency(specifier: &str) -> bool {
    matches!(specifier, "require" | "exports" | "module")
}

fn body_has_dynamic_scope(body: &FunctionBody<'_>) -> bool {
    let mut probe: DynamicScopeProbe = DynamicScopeProbe { found: false };
    for statement in &body.statements {
        probe.visit_statement(statement);
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

fn choose_name(
    safety: &RenameSafety<'_>,
    symbol_id: SymbolId,
    owner_scope: ScopeId,
    local_name: &str,
    preferred: &str,
    reserved: &IndexSet<String>,
    next_suffixes: &mut IndexMap<String, u32>,
) -> Option<String> {
    if safety.rename_is_safe(symbol_id, owner_scope, preferred, reserved, local_name) {
        return Some(preferred.to_owned());
    }
    let mut suffix: u32 = next_suffixes
        .get(preferred)
        .copied()
        .map_or(1, core::convert::identity);
    let attempts: usize = safety
        .symbols
        .len()
        .saturating_add(reserved.len())
        .saturating_add(1);
    for _ in 0..attempts {
        let candidate: String = format!("{preferred}_{suffix}");
        suffix = suffix.checked_add(1)?;
        if safety.rename_is_safe(symbol_id, owner_scope, &candidate, reserved, local_name) {
            next_suffixes.insert(preferred.to_owned(), suffix);
            return Some(candidate);
        }
    }
    None
}
