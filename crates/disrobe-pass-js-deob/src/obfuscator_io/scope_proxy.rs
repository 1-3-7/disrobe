use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, Expression, FunctionBody, ObjectPropertyKind, PropertyKey, Statement,
    VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Semantic, SemanticBuilder, SymbolId, SymbolTable};
use oxc_span::{GetSpan, SourceType, Span};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ScopeProxyResult {
    pub objects_merged: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

#[derive(Debug, Clone)]
enum PropValue {
    StringLiteral(String),
    BinaryProxy { op: String, left: u8, right: u8 },
    CallForward { arity: usize },
}

#[must_use]
pub(super) fn merge_scope_proxies(source: &str) -> ScopeProxyResult {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return passthrough(source);
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return passthrough(source);
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let nodes: &AstNodes<'_> = semantic.nodes();

    let mut edits: Vec<(Span, String)> = Vec::new();
    let mut objects_merged: usize = 0;
    let mut call_sites_inlined: usize = 0;
    let mut consumed_spans: Vec<Span> = Vec::new();

    for symbol_id in symbols.symbol_ids() {
        let Some((props, decl_span)): Option<(
            std::collections::BTreeMap<String, PropValue>,
            Span,
        )> = candidate_object(source, symbols, nodes, symbol_id) else {
            continue;
        };
        let refs: &Vec<oxc_semantic::ReferenceId> = symbols.get_resolved_reference_ids(symbol_id);
        let mut local_edits: Vec<(Span, String)> = Vec::new();
        let mut local_inlined: usize = 0;
        let mut unresolved: usize = 0;
        let mut all_reads: bool = true;

        for &reference_id in refs {
            let reference: &oxc_semantic::Reference = symbols.get_reference(reference_id);
            if reference.is_write() {
                all_reads = false;
                break;
            }
            let node_id: NodeId = reference.node_id();
            match resolve_member_inline(source, nodes, node_id, &props) {
                Some((span, text)) => {
                    local_edits.push((span, text));
                    local_inlined += 1;
                }
                None => unresolved += 1,
            }
        }

        if !all_reads || local_inlined == 0 {
            continue;
        }
        if overlaps_consumed(decl_span, &consumed_spans) {
            continue;
        }
        let (kept, dropped): (Vec<(Span, String)>, usize) = drop_overlapping(local_edits);
        if kept.is_empty() {
            continue;
        }
        let applied: usize = kept.len();
        edits.extend(kept);
        if unresolved == 0 && dropped == 0 {
            edits.push((decl_span, String::new()));
            consumed_spans.push(decl_span);
        }
        objects_merged += 1;
        call_sites_inlined += applied;
    }

    if edits.is_empty() {
        return passthrough(source);
    }
    let rewritten: String = apply_span_edits(source, edits);
    ScopeProxyResult {
        objects_merged,
        call_sites_inlined,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> ScopeProxyResult {
    ScopeProxyResult {
        objects_merged: 0,
        call_sites_inlined: 0,
        rewritten_source: source.to_owned(),
    }
}

fn candidate_object(
    source: &str,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    symbol_id: SymbolId,
) -> Option<(std::collections::BTreeMap<String, PropValue>, Span)> {
    if symbols.symbol_is_mutated(symbol_id) {
        return None;
    }
    let decl_span: Span = symbols.get_span(symbol_id);
    let (declarator, removal_span): (&oxc_ast::ast::VariableDeclarator<'_>, Span) =
        find_declarator(nodes, decl_span)?;
    if !matches!(
        declarator.kind,
        VariableDeclarationKind::Const | VariableDeclarationKind::Var
    ) {
        return None;
    }
    let Some(Expression::ObjectExpression(object)): Option<&Expression<'_>> =
        declarator.init.as_ref()
    else {
        return None;
    };
    if object.properties.is_empty() {
        return None;
    }
    let mut props: std::collections::BTreeMap<String, PropValue> =
        std::collections::BTreeMap::new();
    for prop_kind in &object.properties {
        let ObjectPropertyKind::ObjectProperty(prop): &ObjectPropertyKind<'_> = prop_kind else {
            return None;
        };
        let key: String = property_key_name(&prop.key)?;
        if key.len() != 5 || !key.chars().all(|c: char| c.is_ascii_alphabetic()) {
            return None;
        }
        if let Some(value) = classify_value(source, &prop.value) {
            props.insert(key, value);
        }
    }
    if props.is_empty() {
        return None;
    }
    Some((props, removal_span))
}

fn find_declarator<'a>(
    nodes: &'a AstNodes<'a>,
    decl_span: Span,
) -> Option<(&'a oxc_ast::ast::VariableDeclarator<'a>, Span)> {
    nodes.iter().find_map(|node: &oxc_semantic::AstNode<'a>| {
        let AstKind::VariableDeclaration(declaration): AstKind<'_> = node.kind() else {
            return None;
        };
        if declaration.declarations.len() != 1 {
            return None;
        }
        let declarator: &oxc_ast::ast::VariableDeclarator<'a> = &declaration.declarations[0];
        let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident): &oxc_ast::ast::BindingPatternKind<'_> =
            &declarator.id.kind
        else {
            return None;
        };
        if ident.span != decl_span {
            return None;
        }
        Some((declarator, declaration.span))
    })
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(ident) => Some(ident.name.to_string()),
        PropertyKey::StringLiteral(lit) => Some(lit.value.to_string()),
        _ => None,
    }
}

fn classify_value(source: &str, value: &Expression<'_>) -> Option<PropValue> {
    if let Expression::StringLiteral(_) = value {
        let span: Span = value.span();
        let text: &str = source.get(span.start as usize..span.end as usize)?;
        return Some(PropValue::StringLiteral(text.to_owned()));
    }
    let Expression::FunctionExpression(func): &Expression<'_> = value else {
        return None;
    };
    let body: &FunctionBody<'_> = func.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(ret): &Statement<'_> = &body.statements[0] else {
        return None;
    };
    let argument: &Expression<'_> = ret.argument.as_ref()?;
    let params: Vec<String> = func
        .params
        .items
        .iter()
        .filter_map(|p: &oxc_ast::ast::FormalParameter<'_>| {
            if let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) = &p.pattern.kind {
                Some(ident.name.to_string())
            } else {
                None
            }
        })
        .collect();
    if params.len() != func.params.items.len() {
        return None;
    }
    classify_proxy_return(&params, argument)
}

fn classify_proxy_return(params: &[String], argument: &Expression<'_>) -> Option<PropValue> {
    if let Expression::BinaryExpression(bin) = argument
        && params.len() == 2
    {
        let left: u8 = param_index(params, &bin.left)?;
        let right: u8 = param_index(params, &bin.right)?;
        return Some(PropValue::BinaryProxy {
            op: bin.operator.as_str().to_owned(),
            left,
            right,
        });
    }
    if let Expression::LogicalExpression(log) = argument
        && params.len() == 2
    {
        let left: u8 = param_index(params, &log.left)?;
        let right: u8 = param_index(params, &log.right)?;
        return Some(PropValue::BinaryProxy {
            op: log.operator.as_str().to_owned(),
            left,
            right,
        });
    }
    if let Expression::CallExpression(call) = argument
        && !params.is_empty()
    {
        if param_index(params, &call.callee)? != 0 {
            return None;
        }
        if call.arguments.len() + 1 != params.len() {
            return None;
        }
        for (i, arg) in call.arguments.iter().enumerate() {
            if matches!(arg, Argument::SpreadElement(_)) {
                return None;
            }
            let expr: &Expression<'_> = arg.as_expression()?;
            let idx: u8 = param_index(params, expr)?;
            if usize::from(idx) != i + 1 {
                return None;
            }
        }
        return Some(PropValue::CallForward {
            arity: params.len(),
        });
    }
    None
}

const fn is_short_circuit(op: &str) -> bool {
    matches!(op.as_bytes(), b"&&" | b"||" | b"??")
}

fn operand_is_pure(operand: &str) -> bool {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return false;
    }
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("operand.js").unwrap_or_default();
    let wrapped: String = format!("({trimmed});");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return false;
    }
    let Some(Statement::ExpressionStatement(stmt)) = parsed.program.body.first() else {
        return false;
    };
    expression_is_pure(&stmt.expression)
}

fn expression_is_pure(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::ThisExpression(_) => true,
        Expression::ParenthesizedExpression(p) => expression_is_pure(&p.expression),
        Expression::UnaryExpression(u) => {
            !matches!(u.operator, oxc_ast::ast::UnaryOperator::Delete)
                && expression_is_pure(&u.argument)
        }
        Expression::StaticMemberExpression(m) => expression_is_pure(&m.object),
        Expression::ComputedMemberExpression(m) => {
            expression_is_pure(&m.object) && expression_is_pure(&m.expression)
        }
        Expression::BinaryExpression(b) => {
            expression_is_pure(&b.left) && expression_is_pure(&b.right)
        }
        Expression::LogicalExpression(l) => {
            expression_is_pure(&l.left) && expression_is_pure(&l.right)
        }
        Expression::ConditionalExpression(c) => {
            expression_is_pure(&c.test)
                && expression_is_pure(&c.consequent)
                && expression_is_pure(&c.alternate)
        }
        _ => false,
    }
}

fn param_index(params: &[String], expr: &Expression<'_>) -> Option<u8> {
    let Expression::Identifier(ident): &Expression<'_> = expr else {
        return None;
    };
    let position: usize = params
        .iter()
        .position(|p: &String| p == ident.name.as_str())?;
    u8::try_from(position).ok()
}

fn resolve_member_inline(
    source: &str,
    nodes: &AstNodes<'_>,
    reference_node: NodeId,
    props: &std::collections::BTreeMap<String, PropValue>,
) -> Option<(Span, String)> {
    let parent: &oxc_semantic::AstNode<'_> = nodes.parent_node(reference_node)?;
    let AstKind::MemberExpression(member): AstKind<'_> = parent.kind() else {
        return None;
    };
    let member_span: Span = member.span();
    let key: String = member.static_property_name()?.to_owned();
    let value: &PropValue = props.get(&key)?;
    let member_node: NodeId = nodes.parent_id(reference_node)?;
    match value {
        PropValue::StringLiteral(text) => {
            if is_call_callee(nodes, member_node, member_span) {
                return None;
            }
            Some((member_span, text.clone()))
        }
        PropValue::BinaryProxy { op, left, right } => {
            let call: &oxc_ast::ast::CallExpression<'_> =
                enclosing_call(nodes, member_node, member_span)?;
            let args: Vec<String> = call_arg_texts(source, call)?;
            let l: &String = args.get(usize::from(*left))?;
            let r: &String = args.get(usize::from(*right))?;
            if is_short_circuit(op) && !operand_is_pure(r) {
                return None;
            }
            Some((call.span, format!("({l} {op} {r})")))
        }
        PropValue::CallForward { arity } => {
            let call: &oxc_ast::ast::CallExpression<'_> =
                enclosing_call(nodes, member_node, member_span)?;
            let args: Vec<String> = call_arg_texts(source, call)?;
            if args.len() != *arity || args.is_empty() {
                return None;
            }
            let callee: &String = &args[0];
            let forwarded: String = args[1..].join(", ");
            Some((call.span, format!("{callee}({forwarded})")))
        }
    }
}

fn is_call_callee(nodes: &AstNodes<'_>, member_node: NodeId, member_span: Span) -> bool {
    nodes
        .parent_node(member_node)
        .is_some_and(|p: &oxc_semantic::AstNode<'_>| {
            matches!(p.kind(), AstKind::CallExpression(call) if call.callee.span() == member_span)
        })
}

fn enclosing_call<'a>(
    nodes: &'a AstNodes<'a>,
    member_node: NodeId,
    member_span: Span,
) -> Option<&'a oxc_ast::ast::CallExpression<'a>> {
    let parent: &oxc_semantic::AstNode<'a> = nodes.parent_node(member_node)?;
    let AstKind::CallExpression(call): AstKind<'_> = parent.kind() else {
        return None;
    };
    if call.callee.span() == member_span {
        Some(call)
    } else {
        None
    }
}

fn call_arg_texts(source: &str, call: &oxc_ast::ast::CallExpression<'_>) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(call.arguments.len());
    for arg in &call.arguments {
        let expr: &Expression<'_> = arg.as_expression()?;
        let span: Span = expr.span();
        out.push(
            source
                .get(span.start as usize..span.end as usize)?
                .to_owned(),
        );
    }
    Some(out)
}

fn overlaps_consumed(span: Span, consumed: &[Span]) -> bool {
    consumed
        .iter()
        .any(|c: &Span| span.start >= c.start && span.end <= c.end)
}

fn drop_overlapping(mut edits: Vec<(Span, String)>) -> (Vec<(Span, String)>, usize) {
    edits.sort_by(|a: &(Span, String), b: &(Span, String)| {
        a.0.start
            .cmp(&b.0.start)
            .then_with(|| b.0.end.cmp(&a.0.end))
    });
    let mut kept: Vec<(Span, String)> = Vec::with_capacity(edits.len());
    let mut dropped: usize = 0;
    let mut last_end: u32 = 0;
    let mut have_last: bool = false;
    for (span, text) in edits {
        if have_last && span.start < last_end {
            dropped += 1;
            continue;
        }
        last_end = span.end;
        have_last = true;
        kept.push((span, text));
    }
    (kept, dropped)
}

fn apply_span_edits(source: &str, mut edits: Vec<(Span, String)>) -> String {
    edits.sort_by(|a: &(Span, String), b: &(Span, String)| {
        b.0.start
            .cmp(&a.0.start)
            .then_with(|| b.0.end.cmp(&a.0.end))
    });
    let mut out: String = source.to_owned();
    let mut last_start: usize = source.len() + 1;
    for (span, replacement) in edits {
        let start: usize = span.start as usize;
        let end: usize = span.end as usize;
        if end > last_start {
            continue;
        }
        if start <= end
            && end <= out.len()
            && out.is_char_boundary(start)
            && out.is_char_boundary(end)
        {
            out.replace_range(start..end, &replacement);
            last_start = start;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn merges_binary_proxy_inside_iife() {
        let src: &str = "(function(){const _0x1={'WOfoz':function(a,b){return a+b;}};return _0x1['WOfoz'](x,y);}());";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 1, "got: {}", r.rewritten_source);
        assert!(
            r.rewritten_source.contains("(x + y)"),
            "got: {}",
            r.rewritten_source
        );
        assert!(!r.rewritten_source.contains("WOfoz"));
    }

    #[test]
    fn merges_call_forward_proxy() {
        let src: &str = "function f(g,z){const _0x2={'NiLKX':function(a,b){return a(b);}};return _0x2['NiLKX'](g,z);}";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 1, "got: {}", r.rewritten_source);
        assert!(
            r.rewritten_source.contains("g(z)"),
            "got: {}",
            r.rewritten_source
        );
    }

    #[test]
    fn merges_string_literal_proxy() {
        let src: &str = "function f(){const _0x3={'aBcDe':'hello world'};return _0x3['aBcDe'];}";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 1, "got: {}", r.rewritten_source);
        assert!(r.rewritten_source.contains("'hello world'"));
    }

    #[test]
    fn skips_reassigned_object() {
        let src: &str =
            "let _0x4={'WOfoz':function(a,b){return a+b;}};_0x4=other;_0x4['WOfoz'](1,2);";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 0);
    }

    #[test]
    fn leaves_real_config_object_alone() {
        let src: &str = "const config={'name':'test','value':42};console.log(config.name);";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 0);
    }

    #[test]
    fn does_not_drop_side_effecting_arg_under_logical_proxy() {
        let src: &str = "function f(){const _0x6={'WOfoz':function(a,b){return a||b;}};return _0x6['WOfoz'](flag,side());}";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert!(
            r.rewritten_source.contains("side()") && r.rewritten_source.contains("_0x6['WOfoz']"),
            "folding (flag || side()) would skip side() when flag is truthy; call must survive: {}",
            r.rewritten_source
        );
    }

    #[test]
    fn folds_logical_proxy_when_args_are_pure() {
        let src: &str = "function f(){const _0x7={'WOfoz':function(a,b){return a||b;}};return _0x7['WOfoz'](flag,fallback);}";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert_eq!(r.objects_merged, 1, "got: {}", r.rewritten_source);
        assert!(
            r.rewritten_source.contains("(flag || fallback)"),
            "pure args are safe to fold under ||: {}",
            r.rewritten_source
        );
    }

    #[test]
    fn merged_output_reparses_without_errors() {
        let src: &str = "(function(){const _0x5={'AaBbC':function(a,b){return a+b;},'CcDdE':function(a,b){return a(b);}};return _0x5['AaBbC'](_0x5['CcDdE'](f,g),h);}());";
        let r: ScopeProxyResult = merge_scope_proxies(src);
        assert!(r.objects_merged >= 1, "got: {}", r.rewritten_source);
        let allocator: Allocator = Allocator::default();
        let st: SourceType = SourceType::from_path("o.js").unwrap_or_default();
        let reparsed: oxc_parser::ParserReturn<'_> =
            Parser::new(&allocator, &r.rewritten_source, st).parse();
        assert!(
            reparsed.errors.is_empty() && !reparsed.panicked,
            "merged output must reparse cleanly: {}",
            r.rewritten_source
        );
    }
}
