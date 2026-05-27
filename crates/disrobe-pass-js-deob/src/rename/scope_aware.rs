use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};
use regex::Regex;
use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScopeAwareStats {
    pub idents_renamed: usize,
    pub references_rewritten: usize,
}

#[allow(clippy::unnecessary_wraps)]
pub(super) fn rename(source: &str) -> Result<(String, ScopeAwareStats)> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Ok((source.to_owned(), ScopeAwareStats::default()));
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return Ok((source.to_owned(), ScopeAwareStats::default()));
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;

    let Ok(hex_pattern): core::result::Result<Regex, regex::Error> =
        Regex::new(r"^_0x[0-9a-fA-F]+$")
    else {
        return Ok((source.to_owned(), ScopeAwareStats::default()));
    };

    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let root_scope: ScopeId = scopes.root_scope_id();

    let mut reserved: IndexSet<String> = IndexSet::new();
    for name in scopes.get_bindings(root_scope).keys() {
        reserved.insert(name.as_str().to_owned());
    }

    let mut targets: Vec<(SymbolId, u32)> = scopes
        .get_bindings(root_scope)
        .iter()
        .filter(|(name, _)| hex_pattern.is_match(name.as_str()))
        .map(|(_, &symbol_id)| (symbol_id, symbols.get_span(symbol_id).start))
        .collect();
    targets.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let mut counter: u32 = 0;
    let mut plan: Vec<(SymbolId, String)> = Vec::with_capacity(targets.len());
    for (symbol_id, _) in targets {
        let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
        let original_name: String = symbols.get_name(symbol_id).to_owned();
        let new_name: String = loop {
            counter = counter.saturating_add(1);
            let candidate: String = format!("var_{counter}");
            if is_conflict_free(scopes, owner_scope, &candidate, &reserved) {
                break candidate;
            }
        };
        reserved.insert(new_name.clone());
        reserved.shift_remove(original_name.as_str());
        plan.push((symbol_id, new_name));
    }

    let mut stats: ScopeAwareStats = ScopeAwareStats::default();
    let mut edits: Vec<(Span, String)> = Vec::new();
    for (symbol_id, new_name) in &plan {
        stats.idents_renamed += 1;
        edits.push((symbols.get_span(*symbol_id), new_name.clone()));
        stats.references_rewritten += 1;
        for &reference_id in symbols.get_resolved_reference_ids(*symbol_id) {
            let node_id: NodeId = symbols.get_reference(reference_id).node_id();
            if let AstKind::IdentifierReference(ident) = nodes.kind(node_id) {
                edits.push((ident.span, new_name.clone()));
                stats.references_rewritten += 1;
            }
        }
    }

    edits.sort_by(|a, b| {
        b.0.start
            .cmp(&a.0.start)
            .then_with(|| b.0.end.cmp(&a.0.end))
    });
    let mut out: String = source.to_owned();
    for (span, replacement) in edits {
        let start: usize = span.start as usize;
        let end: usize = span.end as usize;
        if start <= end
            && end <= out.len()
            && out.is_char_boundary(start)
            && out.is_char_boundary(end)
        {
            out.replace_range(start..end, &replacement);
        } else {
            return Ok((source.to_owned(), ScopeAwareStats::default()));
        }
    }

    Ok((out, stats))
}

fn is_conflict_free(
    scopes: &ScopeTree,
    owner: ScopeId,
    name: &str,
    reserved: &IndexSet<String>,
) -> bool {
    if reserved.contains(name) {
        return false;
    }
    if is_js_reserved(name) {
        return false;
    }
    if scopes.has_binding(owner, name) {
        return false;
    }
    if scopes
        .ancestors(owner)
        .any(|sid| scopes.has_binding(sid, name))
    {
        return false;
    }
    if scopes
        .iter_all_child_ids(owner)
        .any(|sid| scopes.has_binding(sid, name))
    {
        return false;
    }
    true
}

fn is_js_reserved(name: &str) -> bool {
    matches!(
        name,
        "arguments"
            | "as"
            | "async"
            | "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "eval"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "from"
            | "function"
            | "if"
            | "implements"
            | "import"
            | "in"
            | "instanceof"
            | "interface"
            | "let"
            | "new"
            | "null"
            | "of"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "static"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "undefined"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn renames_unique_top_level_bindings() {
        let src: &str = "var _0xab = 1; var _0xcd = _0xab + 2; console.log(_0xcd);";
        let (out, stats): (String, ScopeAwareStats) = rename(src).expect("rename succeeds");
        assert_eq!(stats.idents_renamed, 2, "got: {out}");
        assert!(out.contains("var_1"), "missing var_1 in {out}");
        assert!(out.contains("var_2"), "missing var_2 in {out}");
        assert!(!out.contains("_0xab"), "_0xab leaked in {out}");
        assert!(!out.contains("_0xcd"), "_0xcd leaked in {out}");
        assert!(
            stats.references_rewritten >= 4,
            "too few rewrites: {stats:?}"
        );
    }

    #[test]
    fn preserves_member_expression_fields() {
        let src: &str = "var _0xabc = 1; obj._0xabc = _0xabc + 1; foo._0xabc;";
        let (out, stats): (String, ScopeAwareStats) = rename(src).expect("rename succeeds");
        assert_eq!(stats.idents_renamed, 1, "got out: {out}");
        assert!(
            out.contains("var var_1 = 1"),
            "binding not renamed in {out}"
        );
        assert!(
            out.contains("obj._0xabc"),
            "member expression `obj._0xabc` was rewritten — should be preserved. got: {out}"
        );
        assert!(
            out.contains("foo._0xabc"),
            "member expression `foo._0xabc` was rewritten. got: {out}"
        );
        assert!(
            out.contains("= var_1 + 1"),
            "value-position reference to _0xabc not rewritten. got: {out}"
        );
    }

    #[test]
    fn handles_nested_scope_collision() {
        let src: &str = "var _0xabc = 1; function f() { var var_1 = 2; return var_1 + _0xabc; }";
        let (out, stats): (String, ScopeAwareStats) = rename(src).expect("rename succeeds");
        assert_eq!(stats.idents_renamed, 1, "got out: {out}");
        assert!(
            out.contains("var var_2 = 1"),
            "expected outer rename to var_2 to avoid shadowing inner var_1. got: {out}"
        );
        assert!(
            out.contains("var var_1 = 2"),
            "inner var_1 must be preserved verbatim. got: {out}"
        );
        assert!(
            out.contains("return var_1 + var_2"),
            "inner ref to var_1 + outer ref renamed. got: {out}"
        );
    }

    #[test]
    fn returns_original_on_parse_error() {
        let src: &str = "var _0xab = ; this is not valid javascript @@@";
        let (out, stats): (String, ScopeAwareStats) =
            rename(src).expect("function never returns Err");
        assert_eq!(out, src, "parse error path must return original verbatim");
        assert_eq!(stats.idents_renamed, 0);
        assert_eq!(stats.references_rewritten, 0);
    }
}
