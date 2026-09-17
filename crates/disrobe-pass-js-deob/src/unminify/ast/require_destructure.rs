use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, BindingPatternKind, BindingProperty, CallExpression, Expression, ObjectPattern,
    PropertyKey, VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};

use super::rename_scope::{RenameSafety, collect_reserved_names, is_reserved_binding_name};
use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct RequireDestructureStats {
    pub(super) members_unaliased: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, RequireDestructureStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), RequireDestructureStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), RequireDestructureStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let candidates: Vec<MemberCandidate> = collect_candidates(&semantic);
    if candidates.is_empty() {
        return (RuleOutcome::empty(), RequireDestructureStats::default());
    }

    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut stats: RequireDestructureStats = RequireDestructureStats::default();
    let mut edits: Vec<Edit> = Vec::new();
    for candidate in candidates {
        let owner_scope: ScopeId = symbols.get_scope_id(candidate.symbol_id);
        if !safety.rename_is_safe(
            candidate.symbol_id,
            owner_scope,
            candidate.key_name.as_str(),
            &reserved,
            candidate.local_name.as_str(),
        ) {
            continue;
        }

        reserved.insert(candidate.key_name.clone());
        reserved.shift_remove(candidate.local_name.as_str());

        edits.push(Edit {
            start: candidate.property_span.start as usize,
            end: candidate.property_span.end as usize,
            replacement: candidate.key_name.clone(),
        });
        push_reference_edits(
            symbols,
            nodes,
            candidate.symbol_id,
            &candidate.key_name,
            &mut edits,
        );
        stats.members_unaliased += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), RequireDestructureStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct MemberCandidate {
    symbol_id: SymbolId,
    local_name: String,
    key_name: String,
    property_span: Span,
}

fn collect_candidates(semantic: &Semantic<'_>) -> Vec<MemberCandidate> {
    let nodes: &AstNodes<'_> = semantic.nodes();
    let mut candidates: Vec<MemberCandidate> = Vec::new();
    for node in nodes.iter() {
        let AstKind::VariableDeclarator(declarator) = node.kind() else {
            continue;
        };
        collect_from_declarator(declarator, &mut candidates);
    }
    candidates
}

fn collect_from_declarator(
    declarator: &VariableDeclarator<'_>,
    candidates: &mut Vec<MemberCandidate>,
) {
    let BindingPatternKind::ObjectPattern(pattern) = &declarator.id.kind else {
        return;
    };
    let Some(init): Option<&Expression<'_>> = declarator.init.as_ref() else {
        return;
    };
    let Expression::CallExpression(call): &Expression<'_> = init else {
        return;
    };
    if !is_static_require(call) {
        return;
    }
    collect_from_pattern(pattern, candidates);
}

fn collect_from_pattern(pattern: &ObjectPattern<'_>, candidates: &mut Vec<MemberCandidate>) {
    if pattern.rest.is_some() {
        return;
    }
    for property in &pattern.properties {
        if let Some(candidate) = candidate_from_property(property) {
            candidates.push(candidate);
        }
    }
}

fn candidate_from_property(property: &BindingProperty<'_>) -> Option<MemberCandidate> {
    if property.shorthand || property.computed {
        return None;
    }
    let PropertyKey::StaticIdentifier(key): &PropertyKey<'_> = &property.key else {
        return None;
    };
    let key_name: &str = key.name.as_str();
    let BindingPatternKind::BindingIdentifier(binding) = &property.value.kind else {
        return None;
    };
    let local_name: &str = binding.name.as_str();
    if key_name == local_name {
        return None;
    }
    if is_reserved_binding_name(key_name) {
        return None;
    }
    if !is_readable_identifier(key_name) {
        return None;
    }
    if !is_minified_local(local_name) {
        return None;
    }
    if key_name.chars().count() <= local_name.chars().count() {
        return None;
    }
    let symbol_id: SymbolId = binding.symbol_id.get()?;
    Some(MemberCandidate {
        symbol_id,
        local_name: local_name.to_owned(),
        key_name: key_name.to_owned(),
        property_span: property.span,
    })
}

fn is_static_require(call: &CallExpression<'_>) -> bool {
    let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
        return false;
    };
    if callee.name.as_str() != "require" || call.arguments.len() != 1 {
        return false;
    }
    matches!(&call.arguments[0], Argument::StringLiteral(_))
}

fn is_minified_local(name: &str) -> bool {
    let char_count: usize = name.chars().count();
    if char_count == 0 || char_count > 3 {
        return false;
    }
    let stripped: &str = name.trim_start_matches(['_', '$']);
    stripped.chars().count() <= 2
}

fn is_readable_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    name.chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn push_reference_edits(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    symbol_id: SymbolId,
    new_name: &str,
    edits: &mut Vec<Edit>,
) {
    for &reference_id in symbols.get_resolved_reference_ids(symbol_id) {
        let node_id: NodeId = symbols.get_reference(reference_id).node_id();
        if let AstKind::IdentifierReference(ident) = nodes.kind(node_id) {
            edits.push(Edit {
                start: ident.span.start as usize,
                end: ident.span.end as usize,
                replacement: new_name.to_owned(),
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn aliased_member_collapses_to_shorthand() {
        let source: &str = "const { readFile: e } = require('fs');\ne('x');\nconsole.log(e);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 1);
        let out: String = apply(source);
        assert!(
            out.contains("const { readFile } = require('fs');"),
            "got: {out}"
        );
        assert!(out.contains("readFile('x');"), "got: {out}");
        assert!(out.contains("console.log(readFile);"), "got: {out}");
    }

    #[test]
    fn multiple_members_all_recover() {
        let source: &str =
            "const { readFile: e, writeFile: i } = require('fs');\ne('a');\ni('b', 1);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 2);
        let out: String = apply(source);
        assert!(
            out.contains("const { readFile, writeFile } = require('fs');"),
            "got: {out}"
        );
        assert!(out.contains("readFile('a');"), "got: {out}");
        assert!(out.contains("writeFile('b', 1);"), "got: {out}");
    }

    #[test]
    fn already_shorthand_is_untouched() {
        let source: &str = "const { readFile } = require('fs');\nreadFile('x');";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn meaningful_local_alias_is_untouched() {
        let source: &str = "const { readFile: reader } = require('fs');\nreader('x');";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(
            stats.members_unaliased, 0,
            "intentional descriptive alias must be preserved"
        );
    }

    #[test]
    fn collision_with_existing_binding_blocks_rename() {
        let source: &str = "const { readFile: e } = require('fs');\nconst readFile = 1;\nconsole.log(e, readFile);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn inner_scope_capture_blocks_rename() {
        let source: &str = "const { readFile: e } = require('fs');\nfunction g() { const readFile = 2; return readFile + e('x'); }\ng();";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn free_global_of_target_name_blocks_rename() {
        let source: &str = "const { open: e } = require('fs');\nconsole.log(e, open.x);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn dynamic_require_is_untouched() {
        let source: &str = "const m = './n';\nconst { readFile: e } = require(m);\ne();";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn non_require_destructure_is_untouched() {
        let source: &str = "const { readFile: e } = fs;\ne('x');";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn rest_pattern_is_untouched() {
        let source: &str =
            "const { readFile: e, ...rest } = require('fs');\ne('x');\nconsole.log(rest);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn defaulted_member_is_untouched() {
        let source: &str = "const { readFile: e = null } = require('fs');\nconsole.log(e);";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }

    #[test]
    fn short_readable_key_still_recovers_over_single_char_local() {
        let source: &str = "const { fs: e } = require('./x');\ne();";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 1);
        let out: String = apply(source);
        assert!(out.contains("const { fs } = require('./x');"), "got: {out}");
    }

    #[test]
    fn long_local_is_not_treated_as_minified() {
        let source: &str = "const { readFile: helper } = require('fs');\nhelper('x');";
        let (_outcome, stats): (RuleOutcome, super::RequireDestructureStats) = recover(source);
        assert_eq!(stats.members_unaliased, 0);
    }
}
