use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast as oast;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct IntegritySelfCheckResult {
    pub wrappers_unwrapped: usize,
    pub residual_reason: Option<String>,
    pub rewritten_source: String,
}

fn integrity_residual_reason() -> String {
    "jsconfuser integrity/lock: the integrity hash is a one-way digest with no static preimage, and lock values are runtime host state (hostname / userAgent / Date.now) never serialized into the file".to_owned()
}

struct Unwrap {
    body_span: Range<usize>,
    replacement: String,
}

#[must_use]
pub fn strip_integrity_self_check(source: &str) -> IntegritySelfCheckResult {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return passthrough(source);
    }
    let mut unwraps: Vec<Unwrap> = Vec::new();
    collect_unwraps(&parsed.program.body, source, &mut unwraps);
    if unwraps.is_empty() {
        return passthrough(source);
    }
    let mut edits: Vec<(Range<usize>, Option<String>)> = unwraps
        .iter()
        .map(|u: &Unwrap| (u.body_span.clone(), Some(u.replacement.clone())))
        .collect();
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    if !reparses(&rewritten) {
        return passthrough(source);
    }
    IntegritySelfCheckResult {
        wrappers_unwrapped: applied,
        residual_reason: Some(integrity_residual_reason()),
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> IntegritySelfCheckResult {
    IntegritySelfCheckResult {
        wrappers_unwrapped: 0,
        residual_reason: None,
        rewritten_source: source.to_owned(),
    }
}

fn reparses(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

fn collect_unwraps(stmts: &[oast::Statement<'_>], source: &str, out: &mut Vec<Unwrap>) {
    for stmt in stmts {
        match stmt {
            oast::Statement::FunctionDeclaration(func) => {
                if let Some(unwrap) = match_integrity_wrapper(func) {
                    out.push(unwrap);
                } else if let Some(body) = &func.body {
                    collect_unwraps(&body.statements, source, out);
                }
            }
            oast::Statement::BlockStatement(block) => collect_unwraps(&block.body, source, out),
            oast::Statement::IfStatement(if_stmt) => {
                collect_unwraps_one(&if_stmt.consequent, source, out);
                if let Some(alt) = &if_stmt.alternate {
                    collect_unwraps_one(alt, source, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_unwraps_one(stmt: &oast::Statement<'_>, source: &str, out: &mut Vec<Unwrap>) {
    collect_unwraps(std::slice::from_ref(stmt), source, out);
}

fn match_integrity_wrapper(func: &oast::Function<'_>) -> Option<Unwrap> {
    let wrapper_name: &str = func.id.as_ref()?.name.as_str();
    let body: &oast::FunctionBody<'_> = func.body.as_ref()?;
    let stmts: Vec<&oast::Statement<'_>> = body
        .statements
        .iter()
        .filter(|s: &&oast::Statement<'_>| !matches!(s, oast::Statement::EmptyStatement(_)))
        .collect();
    if stmts.len() != 2 {
        return None;
    }
    let hash_var: &str = match_hash_var_decl(stmts[0], wrapper_name)?;
    let real_fn: &str = match_integrity_if(stmts[1], hash_var)?;
    let body_span: Range<usize> = body.span.start as usize..body.span.end as usize;
    let replacement: String = format!("{{ return {real_fn}(...arguments); }}");
    Some(Unwrap {
        body_span,
        replacement,
    })
}

fn match_hash_var_decl<'a>(stmt: &'a oast::Statement<'a>, wrapper_name: &str) -> Option<&'a str> {
    let oast::Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oast::VariableDeclarator<'a> = decl.declarations.first()?;
    let var_name: &str = match &declarator.id.kind {
        oast::BindingPatternKind::BindingIdentifier(id) => id.name.as_str(),
        _ => return None,
    };
    let oast::Expression::LogicalExpression(logical) = declarator.init.as_ref()? else {
        return None;
    };
    if logical.operator != oast::LogicalOperator::Or {
        return None;
    }
    if !is_wrapper_property_read(&logical.left, wrapper_name) {
        return None;
    }
    let assigns_hash: bool = match &logical.right {
        oast::Expression::ParenthesizedExpression(p) => {
            assignment_targets_wrapper_property(&p.expression, wrapper_name)
        }
        other => assignment_targets_wrapper_property(other, wrapper_name),
    };
    if !assigns_hash {
        return None;
    }
    Some(var_name)
}

fn is_wrapper_property_read(expr: &oast::Expression<'_>, wrapper_name: &str) -> bool {
    match expr {
        oast::Expression::StaticMemberExpression(m) => {
            matches!(&m.object, oast::Expression::Identifier(id) if id.name == wrapper_name)
        }
        oast::Expression::ComputedMemberExpression(m) => {
            matches!(&m.object, oast::Expression::Identifier(id) if id.name == wrapper_name)
        }
        _ => false,
    }
}

fn assignment_targets_wrapper_property(expr: &oast::Expression<'_>, wrapper_name: &str) -> bool {
    let oast::Expression::AssignmentExpression(assign) = expr else {
        return false;
    };
    let Some(member): Option<&oast::MemberExpression<'_>> = assign.left.as_member_expression()
    else {
        return false;
    };
    member_object_is(member, wrapper_name) && call_returns_hash(&assign.right)
}

fn member_object_is(member: &oast::MemberExpression<'_>, wrapper_name: &str) -> bool {
    let object: &oast::Expression<'_> = match member {
        oast::MemberExpression::StaticMemberExpression(m) => &m.object,
        oast::MemberExpression::ComputedMemberExpression(m) => &m.object,
        oast::MemberExpression::PrivateFieldExpression(m) => &m.object,
    };
    matches!(object, oast::Expression::Identifier(id) if id.name == wrapper_name)
}

const fn call_returns_hash(expr: &oast::Expression<'_>) -> bool {
    matches!(expr, oast::Expression::CallExpression(_))
}

fn match_integrity_if<'a>(stmt: &'a oast::Statement<'a>, hash_var: &str) -> Option<&'a str> {
    let oast::Statement::IfStatement(if_stmt) = stmt else {
        return None;
    };
    if !test_compares_hash(&if_stmt.test, hash_var) {
        return None;
    }
    let real_fn: &str = consequent_returns_real_fn(&if_stmt.consequent)?;
    let alt: &oast::Statement<'a> = if_stmt.alternate.as_ref()?;
    if !is_tamper_trap(alt) {
        return None;
    }
    Some(real_fn)
}

fn test_compares_hash(test: &oast::Expression<'_>, hash_var: &str) -> bool {
    let oast::Expression::BinaryExpression(bin) = test else {
        return false;
    };
    if !matches!(
        bin.operator,
        oast::BinaryOperator::StrictEquality | oast::BinaryOperator::Equality
    ) {
        return false;
    }
    let left_is_hash: bool =
        matches!(&bin.left, oast::Expression::Identifier(id) if id.name == hash_var);
    let right_is_lit: bool = matches!(&bin.right, oast::Expression::NumericLiteral(_));
    let right_is_hash: bool =
        matches!(&bin.right, oast::Expression::Identifier(id) if id.name == hash_var);
    let left_is_lit: bool = matches!(&bin.left, oast::Expression::NumericLiteral(_));
    (left_is_hash && right_is_lit) || (right_is_hash && left_is_lit)
}

fn consequent_returns_real_fn<'a>(consequent: &'a oast::Statement<'a>) -> Option<&'a str> {
    let stmt: &oast::Statement<'a> = match consequent {
        oast::Statement::BlockStatement(block) => block
            .body
            .iter()
            .find(|s: &&oast::Statement<'a>| !matches!(s, oast::Statement::EmptyStatement(_)))?,
        other => other,
    };
    let oast::Statement::ReturnStatement(ret) = stmt else {
        return None;
    };
    let oast::Expression::CallExpression(call) = ret.argument.as_ref()? else {
        return None;
    };
    if call.arguments.len() != 1 {
        return None;
    }
    let spreads_arguments: bool = matches!(
        call.arguments.first()?,
        oast::Argument::SpreadElement(spread)
            if matches!(&spread.argument, oast::Expression::Identifier(id) if id.name == "arguments")
    );
    if !spreads_arguments {
        return None;
    }
    match &call.callee {
        oast::Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn is_tamper_trap(stmt: &oast::Statement<'_>) -> bool {
    let inner: &oast::Statement<'_> = match stmt {
        oast::Statement::BlockStatement(block) => {
            let non_empty: Vec<&oast::Statement<'_>> = block
                .body
                .iter()
                .filter(|s: &&oast::Statement<'_>| !matches!(s, oast::Statement::EmptyStatement(_)))
                .collect();
            if non_empty.len() != 1 {
                return false;
            }
            non_empty[0]
        }
        other => other,
    };
    match inner {
        oast::Statement::WhileStatement(ws) => {
            matches!(&ws.test, oast::Expression::BooleanLiteral(b) if b.value)
        }
        oast::Statement::ForStatement(fs) => fs.test.is_none() && fs.init.is_none(),
        oast::Statement::ThrowStatement(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAPPER: &str = "function add(){var h=add.P||(add.P=hashfn(real,123));if(h===456){return real(...arguments)}else{while(true){}}}\nfunction real(a,b){return a+b}\nconsole.log(add(2,3));";

    #[test]
    fn unwraps_integrity_self_check() {
        let r: IntegritySelfCheckResult = strip_integrity_self_check(WRAPPER);
        assert_eq!(r.wrappers_unwrapped, 1);
        assert!(
            r.rewritten_source.contains("return real(...arguments)"),
            "wrapper must delegate to the real function:\n{}",
            r.rewritten_source
        );
        assert!(
            !r.rewritten_source.contains("while (true)")
                && !r.rewritten_source.contains("while(true)"),
            "the tamper trap must be gone:\n{}",
            r.rewritten_source
        );
        assert!(!r.rewritten_source.contains("hashfn"));
    }

    #[test]
    fn leaves_plain_function_alone() {
        let src: &str = "function add(a,b){ return a + b; }\nconsole.log(add(2,3));";
        let r: IntegritySelfCheckResult = strip_integrity_self_check(src);
        assert_eq!(r.wrappers_unwrapped, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn leaves_real_memoized_getter_alone() {
        let src: &str = "function f(){var v=f.cache||(f.cache=compute());if(v===null){return def(...arguments)}else{return v;}}\nconsole.log(f());";
        let r: IntegritySelfCheckResult = strip_integrity_self_check(src);
        assert_eq!(
            r.wrappers_unwrapped, 0,
            "an else-branch that is not a tamper trap must not be unwrapped:\n{}",
            r.rewritten_source
        );
    }
}
