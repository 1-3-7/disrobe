use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BindingPatternKind, Expression, IdentifierReference, VariableDeclarationKind,
    VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, Reference, ReferenceId, ScopeTree, Semantic, SemanticBuilder, SymbolId,
    SymbolTable,
};
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct AliasInlineStats {
    pub(super) aliases_inlined: usize,
    pub(super) references_rewritten: usize,
}

struct Alias {
    target_name: String,
    target_symbol: Option<SymbolId>,
    kind: VariableDeclarationKind,
    removal: Span,
    declaration_parent: NodeId,
}

struct Program<'n, 'a> {
    symbols: &'n SymbolTable,
    scopes: &'n ScopeTree,
    nodes: &'n AstNodes<'a>,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, AliasInlineStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return (RuleOutcome::empty(), AliasInlineStats::default());
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), AliasInlineStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let program: Program<'_, '_> = Program {
        symbols: semantic.symbols(),
        scopes: semantic.scopes(),
        nodes: semantic.nodes(),
    };

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AliasInlineStats = AliasInlineStats::default();

    for symbol_id in program.symbols.symbol_ids() {
        if program.symbols.symbol_is_mutated(symbol_id)
            || !program.symbols.get_redeclarations(symbol_id).is_empty()
        {
            continue;
        }
        let Some(alias) = candidate_alias(&program, symbol_id) else {
            continue;
        };
        if !target_is_stable(&program, &alias) {
            continue;
        }
        let refs: &Vec<ReferenceId> = program.symbols.get_resolved_reference_ids(symbol_id);
        if refs.is_empty() {
            continue;
        }
        let mut local_edits: Vec<Edit> = Vec::new();
        let mut all_safe: bool = true;
        for &reference_id in refs {
            let reference: &Reference = program.symbols.get_reference(reference_id);
            let node_id: NodeId = reference.node_id();
            let span: Span = program.nodes.get_node(node_id).kind().span();
            if !reference.is_read()
                || reference.is_write()
                || is_shorthand_property(program.nodes, node_id)
                || span.start < alias.removal.end
                || !resolves_to_target(&program, &alias, node_id)
                || (alias.kind == VariableDeclarationKind::Var
                    && crosses_a_function(program.nodes, node_id, alias.declaration_parent))
            {
                all_safe = false;
                break;
            }
            local_edits.push(Edit {
                start: span.start as usize,
                end: span.end as usize,
                replacement: alias.target_name.clone(),
            });
        }
        if !all_safe || local_edits.is_empty() {
            continue;
        }
        let rewritten: usize = local_edits.len();
        edits.extend(local_edits);
        edits.push(Edit {
            start: alias.removal.start as usize,
            end: alias.removal.end as usize,
            replacement: String::new(),
        });
        stats.aliases_inlined += 1;
        stats.references_rewritten += rewritten;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn candidate_alias(program: &Program<'_, '_>, symbol_id: SymbolId) -> Option<Alias> {
    let decl_span: Span = program.symbols.get_span(symbol_id);
    let (declarator, removal, declaration_parent): (&VariableDeclarator<'_>, Span, NodeId) =
        find_single_declarator(program.nodes, decl_span)?;
    let BindingPatternKind::BindingIdentifier(_) = &declarator.id.kind else {
        return None;
    };
    let target: &IdentifierReference<'_> = pure_identifier(declarator.init.as_ref()?)?;
    if declarator.kind == VariableDeclarationKind::Var
        && !matches!(
            program.nodes.kind(declaration_parent),
            AstKind::Program(_) | AstKind::FunctionBody(_)
        )
    {
        return None;
    }
    let target_symbol: Option<SymbolId> =
        target
            .reference_id
            .get()
            .and_then(|reference_id: ReferenceId| {
                program.symbols.get_reference(reference_id).symbol_id()
            });
    Some(Alias {
        target_name: target.name.to_string(),
        target_symbol,
        kind: declarator.kind,
        removal,
        declaration_parent,
    })
}

fn target_is_stable(program: &Program<'_, '_>, alias: &Alias) -> bool {
    alias.target_symbol.map_or_else(
        || global_is_stable(program, &alias.target_name),
        |target: SymbolId| {
            !program.symbols.symbol_is_mutated(target)
                && program.symbols.get_redeclarations(target).is_empty()
        },
    )
}

fn global_is_stable(program: &Program<'_, '_>, name: &str) -> bool {
    let declared_somewhere: bool = program
        .symbols
        .symbol_ids()
        .any(|symbol: SymbolId| program.symbols.get_name(symbol) == name);
    let written: bool = program
        .scopes
        .root_unresolved_references()
        .get(name)
        .is_some_and(|references: &Vec<ReferenceId>| {
            references.iter().any(|reference_id: &ReferenceId| {
                program.symbols.get_reference(*reference_id).is_write()
            })
        });
    !declared_somewhere && !written
}

fn resolves_to_target(program: &Program<'_, '_>, alias: &Alias, node_id: NodeId) -> bool {
    let scope = program.nodes.get_node(node_id).scope_id();
    program.scopes.find_binding(scope, &alias.target_name) == alias.target_symbol
}

fn crosses_a_function(nodes: &AstNodes<'_>, node_id: NodeId, declaration_parent: NodeId) -> bool {
    for ancestor in nodes.ancestor_ids(node_id).skip(1) {
        if ancestor == declaration_parent {
            return false;
        }
        if matches!(
            nodes.kind(ancestor),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            return true;
        }
    }
    true
}

fn find_single_declarator<'a>(
    nodes: &'a AstNodes<'a>,
    decl_span: Span,
) -> Option<(&'a VariableDeclarator<'a>, Span, NodeId)> {
    nodes.iter().find_map(|node: &oxc_semantic::AstNode<'a>| {
        let AstKind::VariableDeclaration(declaration) = node.kind() else {
            return None;
        };
        if declaration.declarations.len() != 1 {
            return None;
        }
        let declarator: &VariableDeclarator<'a> = &declaration.declarations[0];
        let BindingPatternKind::BindingIdentifier(ident) = &declarator.id.kind else {
            return None;
        };
        if ident.span != decl_span {
            return None;
        }
        let parent: NodeId = nodes.parent_id(node.id())?;
        Some((declarator, declaration.span, parent))
    })
}

fn pure_identifier<'e, 'a>(expr: &'e Expression<'a>) -> Option<&'e IdentifierReference<'a>> {
    match expr {
        Expression::Identifier(ident)
            if !matches!(
                ident.name.as_str(),
                "undefined" | "NaN" | "Infinity" | "eval" | "arguments"
            ) =>
        {
            Some(ident)
        }
        Expression::ParenthesizedExpression(paren) => pure_identifier(&paren.expression),
        _ => None,
    }
}

fn is_shorthand_property(nodes: &AstNodes<'_>, node_id: NodeId) -> bool {
    let Some(parent) = nodes.parent_node(node_id) else {
        return false;
    };
    match parent.kind() {
        AstKind::ObjectProperty(prop) => prop.shorthand,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::AliasInlineStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn inlines_an_alias_of_a_stable_binding() {
        assert_eq!(
            apply("function g() {} var p = g; p(); p();"),
            "function g() {}  g(); g();"
        );
    }

    #[test]
    fn keeps_an_alias_whose_target_changes_or_is_shadowed() {
        for source in [
            "var a = 1; var b = a; a--; log(b);",
            "var a = 1; var b = a; var a = 2; log(b);",
            "var a = 1; var b = a; function f(a) { return b; } log(f(2));",
            "var o = { m: 1 }; var b = o.m; o.m = 2; log(b);",
            "var a = 1; if (c) { var b = a; } log(b);",
            "log(f()); var b = a; function f() { return b; }",
            "Math = 1; var b = Math; log(b);",
        ] {
            assert_eq!(apply(source), source);
        }
    }
}
