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
pub(super) struct RequireAliasStats {
    pub(super) requires_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, RequireAliasStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), RequireAliasStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), RequireAliasStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let candidates: Vec<RequireCandidate> = collect_candidates(&semantic);
    if candidates.is_empty() {
        return (RuleOutcome::empty(), RequireAliasStats::default());
    }

    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut claimed: IndexSet<String> = IndexSet::new();
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut stats: RequireAliasStats = RequireAliasStats::default();
    let mut edits: Vec<Edit> = Vec::new();
    for candidate in candidates {
        let owner_scope: ScopeId = symbols.get_scope_id(candidate.symbol_id);
        let mut target: Option<String> = None;
        for name in candidate.derive_names() {
            if claimed.contains(&name) {
                continue;
            }
            if safety.rename_is_safe(
                candidate.symbol_id,
                owner_scope,
                &name,
                &reserved,
                candidate.local_name.as_str(),
            ) {
                target = Some(name);
                break;
            }
        }
        let Some(new_name): Option<String> = target else {
            continue;
        };

        reserved.insert(new_name.clone());
        reserved.shift_remove(candidate.local_name.as_str());
        claimed.insert(new_name.clone());

        edits.push(Edit {
            start: candidate.binding_span.start as usize,
            end: candidate.binding_span.end as usize,
            replacement: new_name.clone(),
        });
        push_reference_edits(symbols, nodes, candidate.symbol_id, &new_name, &mut edits);
        stats.requires_renamed += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), RequireAliasStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct RequireCandidate {
    symbol_id: SymbolId,
    local_name: String,
    specifier: String,
    binding_span: Span,
}

impl RequireCandidate {
    fn derive_names(&self) -> Vec<String> {
        derive_module_names(&self.specifier)
    }
}

fn collect_candidates(semantic: &Semantic<'_>) -> Vec<RequireCandidate> {
    let nodes: &AstNodes<'_> = semantic.nodes();
    let mut candidates: Vec<RequireCandidate> = Vec::new();
    for node in nodes.iter() {
        let AstKind::VariableDeclarator(declarator) = node.kind() else {
            continue;
        };
        let Some(candidate) = candidate_from_declarator(declarator) else {
            continue;
        };
        candidates.push(candidate);
    }
    candidates
}

fn candidate_from_declarator(declarator: &VariableDeclarator<'_>) -> Option<RequireCandidate> {
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let local_name: &str = binding.name.as_str();
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::CallExpression(call): &Expression<'_> = init else {
        return None;
    };
    let specifier: &str = require_specifier(call)?;
    if !is_minified_local(local_name) {
        return None;
    }
    if !derive_module_names(specifier)
        .iter()
        .any(|name: &String| name.len() > local_name.len())
    {
        return None;
    }
    let symbol_id: SymbolId = binding.symbol_id.get()?;
    Some(RequireCandidate {
        symbol_id,
        local_name: local_name.to_owned(),
        specifier: specifier.to_owned(),
        binding_span: binding.span,
    })
}

fn require_specifier<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "require" || call.arguments.len() != 1 {
        return None;
    }
    let Argument::StringLiteral(spec): &Argument<'_> = &call.arguments[0] else {
        return None;
    };
    Some(spec.value.as_str())
}

fn is_minified_local(name: &str) -> bool {
    let char_count: usize = name.chars().count();
    if char_count == 0 || char_count > 3 {
        return false;
    }
    let stripped: &str = name.trim_start_matches(['_', '$']);
    stripped.chars().count() <= 2
}

fn derive_module_names(specifier: &str) -> Vec<String> {
    let trimmed: &str = specifier.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let base: &str = module_base_segment(trimmed);
    let stem: &str = base.rsplit_once('.').map_or(base, |(head, _ext)| head);
    let mut names: IndexSet<String> = IndexSet::new();
    if let Some(camel) = to_camel_identifier(stem) {
        names.insert(camel);
    }
    if let Some(scoped) = scoped_package_name(trimmed)
        && let Some(camel) = to_camel_identifier(&scoped)
    {
        names.insert(camel);
    }
    names
        .into_iter()
        .filter(|name: &String| !is_reserved_binding_name(name))
        .collect()
}

fn module_base_segment(specifier: &str) -> &str {
    let no_query: &str = specifier
        .split_once('?')
        .map_or(specifier, |(head, _query)| head);
    let normalized: &str = no_query.trim_end_matches('/');
    let mut segments: Vec<&str> = normalized
        .split(['/', '\\'])
        .filter(|segment: &&str| !segment.is_empty() && *segment != "." && *segment != "..")
        .collect();
    while segments.len() > 1 {
        let last: &str = segments[segments.len() - 1];
        let stem: &str = last.rsplit_once('.').map_or(last, |(head, _ext)| head);
        if stem.eq_ignore_ascii_case("index") {
            segments.pop();
        } else {
            break;
        }
    }
    segments.last().copied().unwrap_or(normalized)
}

fn scoped_package_name(specifier: &str) -> Option<String> {
    let rest: &str = specifier.strip_prefix('@')?;
    let (scope, package): (&str, &str) = rest.split_once('/')?;
    let package: &str = package.split(['/', '?']).next().unwrap_or(package);
    if scope.is_empty() || package.is_empty() {
        return None;
    }
    Some(format!("{scope}_{package}"))
}

fn to_camel_identifier(raw: &str) -> Option<String> {
    let mut out: String = String::with_capacity(raw.len());
    let mut upper_next: bool = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if upper_next && ch.is_ascii_lowercase() {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
            upper_next = false;
        } else {
            upper_next = !out.is_empty();
        }
    }
    if out.is_empty() {
        return None;
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    Some(out)
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
    use super::{derive_module_names, recover};
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn relative_require_alias_recovers_module_name() {
        let source: &str =
            "const a = require('./math');\nconst total = a.add(1, 2);\nconsole.log(a, total);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("const math = require('./math');"),
            "got: {out}"
        );
        assert!(out.contains("math.add(1, 2)"), "got: {out}");
        assert!(out.contains("console.log(math, total);"), "got: {out}");
    }

    #[test]
    fn bare_package_require_alias_recovers() {
        let source: &str = "var e = require('lodash');\nconsole.log(e.map);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("var lodash = require('lodash');"),
            "got: {out}"
        );
        assert!(out.contains("lodash.map"), "got: {out}");
    }

    #[test]
    fn dashed_package_becomes_camel_case() {
        let source: &str = "const r = require('node-fetch');\nr('https://x');";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("const nodeFetch = require('node-fetch');"),
            "got: {out}"
        );
        assert!(out.contains("nodeFetch('https://x');"), "got: {out}");
    }

    #[test]
    fn scoped_package_uses_scope_and_name() {
        let source: &str = "const c = require('@babel/core');\nc.transform();";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 1);
        let out: String = apply(source);
        assert!(out.contains("require('@babel/core')"), "got: {out}");
        assert!(
            out.contains("core.transform();") || out.contains("babelCore.transform();"),
            "got: {out}"
        );
    }

    #[test]
    fn already_meaningful_name_is_untouched() {
        let source: &str = "const lodash = require('lodash');\nconsole.log(lodash);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 0);
    }

    #[test]
    fn collision_with_existing_binding_blocks_rename() {
        let source: &str = "const a = require('./math');\nconst math = 1;\nconsole.log(a, math);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(
            stats.requires_renamed, 0,
            "renaming `a`->`math` collides with local `math`"
        );
    }

    #[test]
    fn inner_scope_capture_blocks_rename() {
        let source: &str = "const a = require('./math');\nfunction g() { const math = 2; return math + a.x; }\nconsole.log(g());";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(
            stats.requires_renamed, 0,
            "inner `const math` would capture the reference"
        );
    }

    #[test]
    fn free_global_of_target_name_blocks_rename() {
        let source: &str = "const a = require('./fs');\nconsole.log(a, fs.x);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(
            stats.requires_renamed, 0,
            "free `fs` reference would collide"
        );
    }

    #[test]
    fn dynamic_require_specifier_is_untouched() {
        let source: &str = "const m = './n';\nconst a = require(m);\nconsole.log(a);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 0);
    }

    #[test]
    fn destructured_require_is_untouched() {
        let source: &str = "const { add } = require('./math');\nconsole.log(add);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 0);
    }

    #[test]
    fn long_local_name_is_not_treated_as_minified() {
        let source: &str = "const helper = require('./math');\nconsole.log(helper);";
        let (_outcome, stats): (RuleOutcome, super::RequireAliasStats) = recover(source);
        assert_eq!(stats.requires_renamed, 0);
    }

    #[test]
    fn derive_handles_paths_extensions_and_index() {
        assert!(derive_module_names("./util/index.js").contains(&"util".to_owned()));
        assert!(derive_module_names("../lib/string-utils.mjs").contains(&"stringUtils".to_owned()));
        assert!(derive_module_names("fs").contains(&"fs".to_owned()));
        assert!(derive_module_names("@scope/my-pkg").contains(&"myPkg".to_owned()));
    }
}
