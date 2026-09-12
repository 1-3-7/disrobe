use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPatternKind, Expression, VariableDeclarationKind, VariableDeclarator};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Reference, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct AliasInlineStats {
    pub(super) aliases_inlined: usize,
    pub(super) references_rewritten: usize,
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
    let symbols: &SymbolTable = semantic.symbols();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AliasInlineStats = AliasInlineStats::default();

    for symbol_id in symbols.symbol_ids() {
        if symbols.symbol_is_mutated(symbol_id) {
            continue;
        }
        let Some((alias_text, decl_span)) = candidate_alias(source, symbols, nodes, symbol_id)
        else {
            continue;
        };
        let refs: &Vec<oxc_semantic::ReferenceId> = symbols.get_resolved_reference_ids(symbol_id);
        if refs.is_empty() {
            continue;
        }
        let mut local_edits: Vec<Edit> = Vec::new();
        let mut all_reads: bool = true;
        for &reference_id in refs {
            let reference: &Reference = symbols.get_reference(reference_id);
            if !reference.is_read() || reference.is_write() {
                all_reads = false;
                break;
            }
            let node_id: NodeId = reference.node_id();
            if is_shorthand_property(nodes, node_id) {
                all_reads = false;
                break;
            }
            let span: Span = identifier_span(nodes, node_id);
            local_edits.push(Edit {
                start: span.start as usize,
                end: span.end as usize,
                replacement: alias_text.clone(),
            });
        }
        if !all_reads || local_edits.is_empty() {
            continue;
        }
        let rewritten: usize = local_edits.len();
        edits.extend(local_edits);
        edits.push(Edit {
            start: decl_span.start as usize,
            end: decl_span.end as usize,
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

fn candidate_alias(
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    symbol_id: SymbolId,
) -> Option<(String, Span)> {
    let decl_span: Span = symbols.get_span(symbol_id);
    let (declarator, removal_span): (&VariableDeclarator<'_>, Span) =
        find_single_declarator(nodes, decl_span)?;
    if !matches!(
        declarator.kind,
        VariableDeclarationKind::Const
            | VariableDeclarationKind::Let
            | VariableDeclarationKind::Var
    ) {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(_) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    if !is_pure_reference(init) {
        return None;
    }
    let span: Span = init.span();
    let text: &str = source.get(span.start as usize..span.end as usize)?;
    Some((text.to_owned(), removal_span))
}

fn find_single_declarator<'a>(
    nodes: &'a AstNodes<'a>,
    decl_span: Span,
) -> Option<(&'a VariableDeclarator<'a>, Span)> {
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
        Some((declarator, declaration.span))
    })
}

fn is_pure_reference(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(ident) => !matches!(
            ident.name.as_str(),
            "undefined" | "NaN" | "Infinity" | "eval" | "arguments"
        ),
        Expression::StaticMemberExpression(member) => is_pure_reference(&member.object),
        Expression::ParenthesizedExpression(paren) => is_pure_reference(&paren.expression),
        _ => false,
    }
}

fn identifier_span(nodes: &AstNodes<'_>, node_id: NodeId) -> Span {
    nodes.get_node(node_id).kind().span()
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
