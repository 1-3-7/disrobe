use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{ImportDeclarationSpecifier, ModuleExportName};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};

use super::rename_scope::{RenameSafety, collect_reserved_names, is_reserved_binding_name};
use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ImportRenameStats {
    pub(super) imports_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ImportRenameStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    if !source_type.is_module() {
        return (RuleOutcome::empty(), ImportRenameStats::default());
    }
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ImportRenameStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), ImportRenameStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);

    let candidates: Vec<ImportCandidate> = collect_candidates(&semantic);
    if candidates.is_empty() {
        return (RuleOutcome::empty(), ImportRenameStats::default());
    }

    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut stats: ImportRenameStats = ImportRenameStats::default();
    let mut edits: Vec<Edit> = Vec::new();
    for candidate in candidates {
        let owner_scope: ScopeId = symbols.get_scope_id(candidate.symbol_id);
        let imported: &str = candidate.imported_name.as_str();
        if !safety.rename_is_safe(
            candidate.symbol_id,
            owner_scope,
            imported,
            &reserved,
            candidate.local_name.as_str(),
        ) {
            continue;
        }

        reserved.insert(candidate.imported_name.clone());
        reserved.shift_remove(candidate.local_name.as_str());

        edits.push(Edit {
            start: candidate.specifier_span.start as usize,
            end: candidate.specifier_span.end as usize,
            replacement: candidate.imported_name.clone(),
        });
        push_reference_edits(
            symbols,
            nodes,
            candidate.symbol_id,
            &candidate.imported_name,
            &mut edits,
        );
        stats.imports_renamed += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), ImportRenameStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct ImportCandidate {
    symbol_id: SymbolId,
    local_name: String,
    imported_name: String,
    specifier_span: Span,
}

fn collect_candidates(semantic: &Semantic<'_>) -> Vec<ImportCandidate> {
    let nodes: &AstNodes<'_> = semantic.nodes();
    let mut candidates: Vec<ImportCandidate> = Vec::new();
    for node in nodes.iter() {
        let AstKind::ImportDeclaration(import) = node.kind() else {
            continue;
        };
        let Some(specifiers) = &import.specifiers else {
            continue;
        };
        for specifier in specifiers {
            let ImportDeclarationSpecifier::ImportSpecifier(named) = specifier else {
                continue;
            };
            let ModuleExportName::IdentifierName(imported) = &named.imported else {
                continue;
            };
            let local_name: &str = named.local.name.as_str();
            let imported_name: &str = imported.name.as_str();
            if imported_name == local_name {
                continue;
            }
            if is_reserved_binding_name(imported_name) {
                continue;
            }
            if suffix_rank(imported_name, imported_name) >= suffix_rank(local_name, imported_name) {
                continue;
            }
            let Some(symbol_id) = named.local.symbol_id.get() else {
                continue;
            };
            candidates.push(ImportCandidate {
                symbol_id,
                local_name: local_name.to_owned(),
                imported_name: imported_name.to_owned(),
                specifier_span: named.span,
            });
        }
    }
    candidates
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

fn suffix_rank(name: &str, base: &str) -> u32 {
    if name == base {
        return 0;
    }
    if let Some(rest) = name.strip_prefix(base)
        && let Some(digits) = rest.strip_prefix('_')
    {
        return digits.parse::<u32>().unwrap_or(u32::MAX);
    }
    u32::MAX
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn aliased_import_restores_original_name() {
        let source: &str =
            "import { mapState as a } from 'vuex';\nconst x = a();\nconsole.log(a, x);";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(stats.imports_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("import { mapState } from 'vuex';"),
            "got: {out}"
        );
        assert!(out.contains("const x = mapState();"), "got: {out}");
        assert!(out.contains("console.log(mapState, x);"), "got: {out}");
        assert!(!out.contains(" a "), "stray alias left: {out}");
    }

    #[test]
    fn collision_with_existing_binding_blocks_rename() {
        let source: &str =
            "import { mapState as a } from 'vuex';\nconst mapState = 1;\nconsole.log(a, mapState);";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(
            stats.imports_renamed, 0,
            "renaming `a`->`mapState` would collide with the local `mapState`"
        );
    }

    #[test]
    fn inner_scope_shadow_blocks_rename() {
        let source: &str = "import { foo as a } from 'm';\nfunction g() { let foo = 2; return foo + a; }\nconsole.log(g());";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(
            stats.imports_renamed, 0,
            "renaming `a`->`foo` would be captured by the inner `let foo`"
        );
    }

    #[test]
    fn unresolved_reference_collision_blocks_rename() {
        let source: &str = "import { process as a } from 'm';\nconsole.log(a, process.env);";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(
            stats.imports_renamed, 0,
            "renaming `a`->`process` would collide with the free `process` reference"
        );
    }

    #[test]
    fn already_named_import_is_untouched() {
        let source: &str = "import { foo } from 'm';\nconsole.log(foo());";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(stats.imports_renamed, 0);
    }

    #[test]
    fn default_and_namespace_imports_are_untouched() {
        let source: &str = "import d from 'm';\nimport * as ns from 'n';\nconsole.log(d, ns);";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(stats.imports_renamed, 0);
    }

    #[test]
    fn member_property_named_like_local_is_preserved() {
        let source: &str =
            "import { foo as a } from 'm';\nconst o = { a: 1 };\nconsole.log(a(), o.a);";
        let (_outcome, stats): (RuleOutcome, super::ImportRenameStats) = recover(source);
        assert_eq!(stats.imports_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("o.a"),
            "object property `a` must be preserved: {out}"
        );
        assert!(out.contains("foo()"), "import call must be renamed: {out}");
    }
}
