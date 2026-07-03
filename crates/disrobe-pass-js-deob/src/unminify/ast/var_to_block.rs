use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPatternKind, VariableDeclaration, VariableDeclarationKind};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNode, AstNodes, NodeId, Reference, ScopeId, ScopeTree, Semantic, SemanticBuilder,
    SymbolFlags, SymbolId, SymbolTable,
};
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct VarToBlockStats {
    pub(super) promoted_to_const: usize,
    pub(super) promoted_to_let: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, VarToBlockStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return (RuleOutcome::empty(), VarToBlockStats::default());
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), VarToBlockStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: VarToBlockStats = VarToBlockStats::default();

    for node in nodes.iter() {
        let AstKind::VariableDeclaration(decl) = node.kind() else {
            continue;
        };
        if decl.kind != VariableDeclarationKind::Var || decl.declare {
            continue;
        }
        if is_for_loop_head(nodes, node.id()) {
            continue;
        }
        let Some(symbol_ids): Option<Vec<SymbolId>> = collect_simple_bindings(decl, symbols) else {
            continue;
        };
        if symbol_ids.is_empty() {
            continue;
        }
        let decl_lexical_scope: ScopeId = node.scope_id();
        if symbol_ids
            .iter()
            .any(|&symbol_id| symbols.get_scope_id(symbol_id) != decl_lexical_scope)
        {
            continue;
        }
        if !symbol_ids
            .iter()
            .all(|&symbol_id| references_are_safe(symbol_id, symbols, scopes, nodes, decl.span))
        {
            continue;
        }
        let keyword: &str = choose_keyword(decl, symbols, &symbol_ids);
        let Some(var_span): Option<(usize, usize)> = leading_var_keyword(source, decl) else {
            continue;
        };
        edits.push(Edit {
            start: var_span.0,
            end: var_span.1,
            replacement: keyword.to_owned(),
        });
        if keyword == "const" {
            stats.promoted_to_const += 1;
        } else {
            stats.promoted_to_let += 1;
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn is_for_loop_head(nodes: &AstNodes<'_>, node_id: NodeId) -> bool {
    let Some(parent): Option<&AstNode<'_>> = nodes.parent_node(node_id) else {
        return false;
    };
    matches!(
        parent.kind(),
        AstKind::ForStatementInit(_) | AstKind::ForInStatement(_) | AstKind::ForOfStatement(_)
    )
}

fn references_are_safe(
    symbol_id: SymbolId,
    symbols: &SymbolTable,
    scopes: &ScopeTree,
    nodes: &AstNodes<'_>,
    decl_span: Span,
) -> bool {
    let decl_scope: ScopeId = symbols.get_scope_id(symbol_id);
    for &reference_id in symbols.get_resolved_reference_ids(symbol_id) {
        let reference: &Reference = symbols.get_reference(reference_id);
        let node: &AstNode<'_> = nodes.get_node(reference.node_id());
        let ref_span: Span = node.kind().span();
        if ref_span.start < decl_span.end {
            return false;
        }
        let ref_scope: ScopeId = node.scope_id();
        if ref_scope != decl_scope && !scopes.ancestors(ref_scope).any(|sid| sid == decl_scope) {
            return false;
        }
    }
    true
}

fn collect_simple_bindings(
    decl: &VariableDeclaration<'_>,
    symbols: &SymbolTable,
) -> Option<Vec<SymbolId>> {
    let mut ids: Vec<SymbolId> = Vec::with_capacity(decl.declarations.len());
    for declarator in &decl.declarations {
        let BindingPatternKind::BindingIdentifier(ident) = &declarator.id.kind else {
            return None;
        };
        let symbol_id: SymbolId = ident.symbol_id.get()?;
        if !symbols
            .get_flags(symbol_id)
            .contains(SymbolFlags::FunctionScopedVariable)
        {
            return None;
        }
        if !symbols.get_redeclarations(symbol_id).is_empty() {
            return None;
        }
        ids.push(symbol_id);
    }
    Some(ids)
}

fn choose_keyword(
    decl: &VariableDeclaration<'_>,
    symbols: &SymbolTable,
    symbol_ids: &[SymbolId],
) -> &'static str {
    let all_initialized: bool = decl
        .declarations
        .iter()
        .all(|declarator| declarator.init.is_some());
    if !all_initialized {
        return "let";
    }
    let any_mutated: bool = symbol_ids
        .iter()
        .any(|&symbol_id| symbols.symbol_is_mutated(symbol_id));
    if any_mutated { "let" } else { "const" }
}

fn leading_var_keyword(source: &str, decl: &VariableDeclaration<'_>) -> Option<(usize, usize)> {
    let start: usize = decl.span.start as usize;
    let end: usize = decl.span.end as usize;
    let slice: &str = source.get(start..end)?;
    if !slice.starts_with("var") {
        return None;
    }
    let after: char = slice[3..].chars().next()?;
    if after.is_ascii_alphanumeric() || after == '_' || after == '$' {
        return None;
    }
    Some((start, start + 3))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{RuleOutcome, VarToBlockStats, recover};

    fn rewrite(source: &str) -> (String, VarToBlockStats) {
        let (outcome, stats): (RuleOutcome, VarToBlockStats) = recover(source);
        let mut out: String = source.to_owned();
        let mut sorted: Vec<&super::Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        (out, stats)
    }

    #[test]
    fn initialized_never_reassigned_becomes_const() {
        let src: &str = "var x = 1; console.log(x);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_const, 1, "got: {out}");
        assert_eq!(stats.promoted_to_let, 0);
        assert_eq!(out, "const x = 1; console.log(x);");
    }

    #[test]
    fn reassigned_becomes_let() {
        let src: &str = "var x = 1; x = 2; console.log(x);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_let, 1, "got: {out}");
        assert_eq!(stats.promoted_to_const, 0);
        assert_eq!(out, "let x = 1; x = 2; console.log(x);");
    }

    #[test]
    fn uninitialized_becomes_let_not_const() {
        let src: &str = "var x; x = 9; console.log(x);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_let, 1, "got: {out}");
        assert_eq!(stats.promoted_to_const, 0);
        assert!(out.starts_with("let x;"), "got: {out}");
    }

    #[test]
    fn for_loop_head_is_skipped() {
        let src: &str = "for (var i = 0; i < 3; i++) { console.log(i); }";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_const, 0, "got: {out}");
        assert_eq!(stats.promoted_to_let, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn for_in_head_is_skipped() {
        let src: &str = "for (var k in obj) { console.log(k); }";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn redeclared_var_is_skipped() {
        let src: &str = "var x = 1; var x = 2; console.log(x);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn multi_declarator_const_when_all_pure() {
        let src: &str = "var a = 1, b = 2; console.log(a + b);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_const, 1, "got: {out}");
        assert_eq!(out, "const a = 1, b = 2; console.log(a + b);");
    }

    #[test]
    fn multi_declarator_let_when_any_reassigned() {
        let src: &str = "var a = 1, b = 2; b = 5; console.log(a + b);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_let, 1, "got: {out}");
        assert_eq!(out, "let a = 1, b = 2; b = 5; console.log(a + b);");
    }

    #[test]
    fn destructuring_var_is_skipped() {
        let src: &str = "var { a, b } = obj; console.log(a, b);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn function_scoped_var_inside_body_promotes() {
        let src: &str = "function f() { var t = compute(); return t; }";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(stats.promoted_to_const, 1, "got: {out}");
        assert!(out.contains("const t = compute()"), "got: {out}");
    }

    #[test]
    fn already_let_or_const_is_untouched() {
        let src: &str = "let a = 1; const b = 2; a = 3; console.log(a + b);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn use_before_declaration_is_skipped() {
        let src: &str = "console.log(x); var x = 1;";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn var_hoisted_out_of_block_is_skipped() {
        let src: &str = "if (cond) { var y = 1; } console.log(y);";
        let (out, stats): (String, VarToBlockStats) = rewrite(src);
        assert_eq!(
            stats.promoted_to_const + stats.promoted_to_let,
            0,
            "got: {out}"
        );
        assert_eq!(out, src);
    }

    #[test]
    fn parse_error_returns_empty() {
        let src: &str = "var = @@@ broken";
        let (_outcome, stats): (RuleOutcome, VarToBlockStats) = recover(src);
        assert_eq!(stats.promoted_to_const + stats.promoted_to_let, 0);
    }
}
