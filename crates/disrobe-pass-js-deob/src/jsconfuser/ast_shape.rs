use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpressionElement, BindingPatternKind, Expression, Statement, VariableDeclaration,
    VariableDeclarator,
};
use oxc_parser::{Parser, ParserReturn};
use oxc_semantic::{ScopeTree, Semantic, SemanticBuilder, SemanticBuilderReturn, SymbolTable};
use oxc_span::SourceType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RgfShape {
    pub(super) array_id: String,
    pub(super) declaration: Range<usize>,
    pub(super) entries: Range<usize>,
    pub(super) references: usize,
}

pub(super) fn detect_rgf_shapes(source: &str) -> Vec<RgfShape> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("jsconfuser-rgf.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return Vec::new();
    }
    let built: SemanticBuilderReturn<'_> = SemanticBuilder::new().build(&parsed.program);
    if !built.errors.is_empty() {
        return Vec::new();
    }
    let semantic: Semantic<'_> = built.semantic;
    let scopes: &ScopeTree = semantic.scopes();
    let symbols: &SymbolTable = semantic.symbols();
    parsed
        .program
        .body
        .iter()
        .filter_map(|stmt: &Statement<'_>| match stmt {
            Statement::VariableDeclaration(decl) => rgf_declaration(decl, scopes, symbols),
            _ => None,
        })
        .collect()
}

fn rgf_declaration(
    decl: &VariableDeclaration<'_>,
    scopes: &ScopeTree,
    symbols: &SymbolTable,
) -> Option<RgfShape> {
    let [declarator]: &[VariableDeclarator<'_>] = decl.declarations.as_slice() else {
        return None;
    };
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let Some(Expression::ArrayExpression(array)) = &declarator.init else {
        return None;
    };
    if array.elements.is_empty() || !array.elements.iter().all(is_new_function) {
        return None;
    }
    let symbol: oxc_semantic::SymbolId =
        scopes.get_binding(scopes.root_scope_id(), binding.name.as_str())?;
    Some(RgfShape {
        array_id: binding.name.to_string(),
        declaration: span_range(decl.span.start, decl.span.end)?,
        entries: span_range(
            array.span.start.checked_add(1)?,
            array.span.end.checked_sub(1)?,
        )?,
        references: symbols.get_resolved_reference_ids(symbol).len(),
    })
}

fn span_range(start: u32, end: u32) -> Option<Range<usize>> {
    Some(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

fn is_new_function(element: &ArrayExpressionElement<'_>) -> bool {
    let ArrayExpressionElement::NewExpression(new_expr) = element else {
        return false;
    };
    matches!(&new_expr.callee, Expression::Identifier(ident) if ident.name == "Function")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_rgf_under_a_minified_identifier() {
        let src: &str = "var a = [new Function('return 1'), new Function('return 2')]; a[1].apply(this, [a, arguments]);";
        let shapes: Vec<RgfShape> = detect_rgf_shapes(src);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].array_id, "a");
        assert_eq!(
            &src[shapes[0].entries.clone()],
            "new Function('return 1'), new Function('return 2')"
        );
        assert_eq!(
            &src[shapes[0].declaration.clone()],
            "var a = [new Function('return 1'), new Function('return 2')];"
        );
        assert_eq!(shapes[0].references, 2);
    }

    #[test]
    fn ignores_arrays_that_are_not_all_new_function() {
        assert!(detect_rgf_shapes("var data = [1, 2, 3, 4];").is_empty());
        assert!(detect_rgf_shapes("var a = [new Function('return 1'), 2];").is_empty());
    }

    #[test]
    fn ignores_multi_declarator_statements() {
        assert!(detect_rgf_shapes("var a = [new Function('return 1')], b = 2;").is_empty());
    }

    #[test]
    fn rejects_malformed_source_safely() {
        assert!(detect_rgf_shapes("var x = @@@ broken;").is_empty());
    }
}
