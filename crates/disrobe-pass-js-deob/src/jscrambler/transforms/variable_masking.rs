use core::ops::Range;
use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPatternKind, Expression, VariableDeclaration, VariableDeclarator};
use oxc_parser::Parser;
use oxc_semantic::{
    NodeId, ScopeFlags, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};
use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(proxy_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return TransformOutput::noop(source);
    }
    let built: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    if !built.errors.is_empty() {
        return TransformOutput::noop(source);
    }
    let semantic: Semantic<'_> = built.semantic;
    let mut stats: TransformStats = TransformStats::default();
    let mut candidates: Vec<(MaskedAlias, Span)> = Vec::new();
    for node in semantic.nodes().iter() {
        let AstKind::VariableDeclaration(declaration) = node.kind() else {
            continue;
        };
        for (index, declarator) in declaration.declarations.iter().enumerate() {
            if let Some(mask) = masked_alias(&semantic, node.scope_id(), declarator) {
                candidates.push((mask, declarator_removal_span(declaration, index)));
            }
        }
    }
    let aliases: BTreeSet<SymbolId> = candidates
        .iter()
        .map(|(mask, _): &(MaskedAlias, Span)| mask.alias)
        .collect();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for (mask, removal) in candidates {
        stats.matched += 1;
        if mask
            .target_binding
            .is_some_and(|target: SymbolId| aliases.contains(&target))
        {
            stats.skipped += 1;
            continue;
        }
        let Some(uses) = mask.replaceable_uses(&semantic) else {
            stats.skipped += 1;
            continue;
        };
        edits.push((removal.start as usize..removal.end as usize, None));
        for span in uses {
            edits.push((
                span.start as usize..span.end as usize,
                Some(mask.target.clone()),
            ));
        }
        stats.reversed += 1;
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (rewritten, _applied): (String, usize) = apply_splice_edits(source, &mut edits);
    TransformOutput {
        source: rewritten,
        stats,
    }
}

struct MaskedAlias {
    alias: SymbolId,
    target: String,
    target_binding: Option<SymbolId>,
    function_scope: ScopeId,
}

impl MaskedAlias {
    fn replaceable_uses(&self, semantic: &Semantic<'_>) -> Option<Vec<Span>> {
        let symbols: &SymbolTable = semantic.symbols();
        let scopes: &ScopeTree = semantic.scopes();
        let mut uses: Vec<Span> = Vec::new();
        for &reference_id in symbols.get_resolved_reference_ids(self.alias) {
            let reference: &oxc_semantic::Reference = symbols.get_reference(reference_id);
            if reference.is_write() {
                return None;
            }
            let node_id: NodeId = reference.node_id();
            let scope: ScopeId = semantic.nodes().get_node(node_id).scope_id();
            if scopes.find_binding(scope, &self.target) != self.target_binding {
                return None;
            }
            if self.target == ARGUMENTS && enclosing_function(scopes, scope) != self.function_scope
            {
                return None;
            }
            if matches!(
                semantic.nodes().parent_kind(node_id),
                Some(AstKind::ObjectProperty(_) | AstKind::ExportSpecifier(_))
            ) {
                return None;
            }
            let AstKind::IdentifierReference(identifier) = semantic.nodes().kind(node_id) else {
                return None;
            };
            uses.push(identifier.span);
        }
        Some(uses)
    }
}

const ARGUMENTS: &str = "arguments";

fn masked_alias(
    semantic: &Semantic<'_>,
    scope: ScopeId,
    declarator: &VariableDeclarator<'_>,
) -> Option<MaskedAlias> {
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let Some(Expression::Identifier(target)) = &declarator.init else {
        return None;
    };
    let alias: SymbolId = binding.symbol_id.get()?;
    let scopes: &ScopeTree = semantic.scopes();
    let target_binding: Option<SymbolId> = scopes.find_binding(scope, &target.name);
    if target_binding == Some(alias) || target_is_written(semantic, target_binding, &target.name) {
        return None;
    }
    Some(MaskedAlias {
        alias,
        target: target.name.to_string(),
        target_binding,
        function_scope: enclosing_function(scopes, scope),
    })
}

fn target_is_written(semantic: &Semantic<'_>, binding: Option<SymbolId>, name: &str) -> bool {
    let symbols: &SymbolTable = semantic.symbols();
    let references: &[oxc_semantic::ReferenceId] = match binding {
        Some(symbol) => symbols.get_resolved_reference_ids(symbol),
        None => semantic
            .scopes()
            .root_unresolved_references()
            .get(name)
            .map_or(&[], Vec::as_slice),
    };
    references
        .iter()
        .any(|&reference_id: &oxc_semantic::ReferenceId| {
            symbols.get_reference(reference_id).is_write()
        })
}

fn enclosing_function(scopes: &ScopeTree, scope: ScopeId) -> ScopeId {
    let mut current: ScopeId = scope;
    loop {
        let flags: ScopeFlags = scopes.get_flags(current);
        if flags.is_function() && !flags.is_arrow() {
            return current;
        }
        match scopes.get_parent_id(current) {
            Some(parent) => current = parent,
            None => return current,
        }
    }
}

fn declarator_removal_span(declaration: &VariableDeclaration<'_>, index: usize) -> Span {
    if declaration.declarations.len() == 1 {
        return declaration.span;
    }
    let this_span: Span = declaration.declarations[index].span;
    if index == 0 {
        Span::new(this_span.start, declaration.declarations[1].span.start)
    } else {
        Span::new(declaration.declarations[index - 1].span.end, this_span.end)
    }
}

const fn proxy_pattern() -> &'static str {
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_alias_decl() {
        let src: &str = "var alias = console; alias.log('x');";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn rewrites_alias_to_target() {
        let src: &str = "var alias = console; alias.log('x'); alias.warn('y');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("console.log"));
        assert!(out.source.contains("console.warn"));
        assert!(!out.source.contains("alias"));
    }

    #[test]
    fn every_alias_declaration_is_removed_from_the_current_text() {
        let src: &str =
            "function f(){var a=arguments;return a[0]+a[1];}function g(){var b=console;b.log(1);}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.source,
            "function f(){return arguments[0]+arguments[1];}function g(){console.log(1);}"
        );
    }

    #[test]
    fn an_assigned_alias_or_literal_target_is_not_a_mask() {
        let src: &str = "function f(){var r=false;try{r=g();}catch(e){}return r;}function h(){var o=x;x=2;return o;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn a_same_named_variable_in_another_scope_is_not_rewritten() {
        let src: &str = "function f(){var s=console;s.log(1);}function g(s){return s+1;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.source,
            "function f(){console.log(1);}function g(s){return s+1;}"
        );
    }

    #[test]
    fn this_and_arguments_keep_their_meaning_inside_callbacks() {
        let this_alias: &str =
            "function f(){var self=this;return [1].map(function(v){return self.k+v;});}";
        let out: TransformOutput = reverse(this_alias, &TransformOpts::default());
        assert_eq!(out.source, this_alias);
        let nested: &str = "function f(){var a=arguments;return function(){return a[0];};}";
        let out: TransformOutput = reverse(nested, &TransformOpts::default());
        assert_eq!(out.source, nested);
        let arrow: &str = "function f(){var a=arguments;return ()=>a[0];}";
        let out: TransformOutput = reverse(arrow, &TransformOpts::default());
        assert_eq!(out.source, "function f(){return ()=>arguments[0];}");
    }

    #[test]
    fn a_target_shadowed_at_the_use_site_keeps_the_alias() {
        let src: &str = "var a=console;function g(console){return a.log(console);}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn a_chained_alias_keeps_its_declaration_and_reads_the_root_target() {
        let src: &str = "var a=console;var b=a;b.log(1);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, "var b=console;b.log(1);");
    }

    #[test]
    fn no_op_when_no_alias() {
        let src: &str = "console.log('x');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
