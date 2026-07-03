use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{Argument, BindingPatternKind, CallExpression, Expression, VariableDeclarator};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};

use super::rename_scope::{RenameSafety, collect_reserved_names, is_reserved_binding_name};
use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct RequireMemberStats {
    pub(super) members_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, RequireMemberStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), RequireMemberStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), RequireMemberStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let candidates: Vec<MemberCandidate> = collect_candidates(&semantic);
    if candidates.is_empty() {
        return (RuleOutcome::empty(), RequireMemberStats::default());
    }

    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut claimed: IndexSet<String> = IndexSet::new();
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut stats: RequireMemberStats = RequireMemberStats::default();
    let mut edits: Vec<Edit> = Vec::new();
    for candidate in candidates {
        if claimed.contains(&candidate.property_name) {
            continue;
        }
        let owner_scope: ScopeId = symbols.get_scope_id(candidate.symbol_id);
        if !safety.rename_is_safe(
            candidate.symbol_id,
            owner_scope,
            candidate.property_name.as_str(),
            &reserved,
            candidate.local_name.as_str(),
        ) {
            continue;
        }

        reserved.insert(candidate.property_name.clone());
        reserved.shift_remove(candidate.local_name.as_str());
        claimed.insert(candidate.property_name.clone());

        edits.push(Edit {
            start: candidate.binding_span.start as usize,
            end: candidate.binding_span.end as usize,
            replacement: candidate.property_name.clone(),
        });
        push_reference_edits(
            symbols,
            nodes,
            candidate.symbol_id,
            &candidate.property_name,
            &mut edits,
        );
        stats.members_renamed += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), RequireMemberStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct MemberCandidate {
    symbol_id: SymbolId,
    local_name: String,
    property_name: String,
    binding_span: Span,
}

fn collect_candidates(semantic: &Semantic<'_>) -> Vec<MemberCandidate> {
    let nodes: &AstNodes<'_> = semantic.nodes();
    let mut candidates: Vec<MemberCandidate> = Vec::new();
    for node in nodes.iter() {
        let AstKind::VariableDeclarator(declarator) = node.kind() else {
            continue;
        };
        if let Some(candidate) = candidate_from_declarator(declarator) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn candidate_from_declarator(declarator: &VariableDeclarator<'_>) -> Option<MemberCandidate> {
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let local_name: &str = binding.name.as_str();
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let property_name: &str = require_member_property(init)?;
    if property_name == local_name {
        return None;
    }
    if is_reserved_binding_name(property_name) {
        return None;
    }
    if !is_minified_local(local_name) {
        return None;
    }
    if property_name.chars().count() <= local_name.chars().count() {
        return None;
    }
    let symbol_id: SymbolId = binding.symbol_id.get()?;
    Some(MemberCandidate {
        symbol_id,
        local_name: local_name.to_owned(),
        property_name: property_name.to_owned(),
        binding_span: binding.span,
    })
}

fn require_member_property<'a>(init: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::StaticMemberExpression(member): &Expression<'_> = init else {
        return None;
    };
    let Expression::CallExpression(call): &Expression<'_> = &member.object else {
        return None;
    };
    if !is_static_require(call) {
        return None;
    }
    let property: &str = member.property.name.as_str();
    if !is_readable_identifier(property) {
        return None;
    }
    Some(property)
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
        let (outcome, _stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn chained_member_off_require_recovers_property_name() {
        let source: &str = "const e = require('react').useState;\ne(0);\nconsole.log(e);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("const useState = require('react').useState;"),
            "got: {out}"
        );
        assert!(out.contains("useState(0);"), "got: {out}");
        assert!(out.contains("console.log(useState);"), "got: {out}");
    }

    #[test]
    fn multiple_chained_members_all_recover() {
        let source: &str = "const a = require('react').useState;\nconst b = require('react').useEffect;\na(0);\nb(1);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 2);
        let out: String = apply(source);
        assert!(
            out.contains("const useState = require('react').useState;"),
            "got: {out}"
        );
        assert!(
            out.contains("const useEffect = require('react').useEffect;"),
            "got: {out}"
        );
    }

    #[test]
    fn matching_local_is_untouched() {
        let source: &str = "const useState = require('react').useState;\nuseState(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn descriptive_local_is_untouched() {
        let source: &str = "const hook = require('react').useState;\nhook(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn dynamic_require_is_untouched() {
        let source: &str = "const m = 'react';\nconst e = require(m).useState;\ne(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn non_require_member_is_untouched() {
        let source: &str = "const e = react.useState;\ne(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn computed_member_is_untouched() {
        let source: &str = "const e = require('react')['useState'];\ne(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn collision_with_existing_binding_blocks_rename() {
        let source: &str =
            "const e = require('react').useState;\nconst useState = 1;\nconsole.log(e, useState);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn free_global_of_target_name_blocks_rename() {
        let source: &str = "const e = require('react').useState;\nconsole.log(e, useState.x);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn inner_scope_capture_blocks_rename() {
        let source: &str = "const e = require('react').useState;\nfunction g() { const useState = 2; return useState + e(0); }\ng();";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }

    #[test]
    fn long_local_is_not_treated_as_minified() {
        let source: &str = "const helper = require('react').useState;\nhelper(0);";
        let (_outcome, stats): (RuleOutcome, super::RequireMemberStats) = recover(source);
        assert_eq!(stats.members_renamed, 0);
    }
}
