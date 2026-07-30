use std::collections::BTreeSet;
use std::fmt;

use disrobe_pass_beam::body_lift::expr::{BinSegment, CaseArm, CatchArm, Expr, IfArm, Stmt};
use disrobe_pass_beam::core_erlang::{CoreClause, CoreFunction, CoreModule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundReference {
    pub function: String,
    pub arity: u32,
    pub clause: usize,
    pub variable: String,
}

impl fmt::Display for UnboundReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} clause {} reads {} with nothing binding it in the emitted head or an earlier \
             statement",
            self.function, self.arity, self.clause, self.variable
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct Site<'a> {
    function: &'a str,
    arity: u32,
    clause: usize,
}

#[must_use]
pub fn unbound_references(core: &CoreModule) -> Vec<UnboundReference> {
    let mut out: Vec<UnboundReference> = Vec::new();
    for f in &core.functions {
        if f.name == "module_info" && (f.arity == 0 || f.arity == 1) {
            continue;
        }
        for (index, clause) in f.clauses.iter().enumerate() {
            let site: Site<'_> = Site {
                function: &f.name,
                arity: f.arity,
                clause: index,
            };
            check_clause(f, clause, site, &mut out);
        }
    }
    out
}

#[must_use]
pub fn clause_count(core: &CoreModule) -> usize {
    core.functions
        .iter()
        .filter(|f: &&CoreFunction| !(f.name == "module_info" && (f.arity == 0 || f.arity == 1)))
        .map(|f: &CoreFunction| f.clauses.len())
        .sum()
}

fn check_clause(
    f: &CoreFunction,
    clause: &CoreClause,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    let mut bound: BTreeSet<String> = BTreeSet::new();
    if clause.patterns.len() == f.arity as usize {
        for pattern in &clause.patterns {
            bind_pattern(pattern, &mut bound, site, out);
        }
    } else {
        for index in 0..f.arity {
            bound.insert(format!("X{index}"));
        }
    }
    if let Some(guard) = &clause.guard {
        check_expr(guard, &bound, site, out);
    }
    check_stmts(&clause.body.stmts, &mut bound, site, out);
}

fn check_stmts(
    stmts: &[Stmt],
    bound: &mut BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::Bind { pattern, value } | Stmt::Match { pattern, value } => {
                let exported: BTreeSet<String> = check_expr(value, bound, site, out);
                bound.extend(exported);
                bind_pattern(pattern, bound, site, out);
            }
            Stmt::Send { dest, msg } => {
                let from_dest: BTreeSet<String> = check_expr(dest, bound, site, out);
                bound.extend(from_dest);
                let from_msg: BTreeSet<String> = check_expr(msg, bound, site, out);
                bound.extend(from_msg);
            }
            Stmt::Expr(expr) | Stmt::Return(expr) => {
                let exported: BTreeSet<String> = check_expr(expr, bound, site, out);
                bound.extend(exported);
            }
            Stmt::Comment(_) => {}
        }
    }
}

fn check_each(
    exprs: &[Expr],
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    for expr in exprs {
        check_expr(expr, bound, site, out);
    }
}

fn check_pairs(
    pairs: &[(Expr, Expr)],
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    for (key, value) in pairs {
        check_expr(key, bound, site, out);
        check_expr(value, bound, site, out);
    }
}

fn check_segments(
    segments: &[BinSegment],
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    for segment in segments {
        check_expr(&segment.value, bound, site, out);
        if let Some(size) = &segment.size {
            check_expr(size, bound, site, out);
        }
    }
}

fn check_expr(
    expr: &Expr,
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) -> BTreeSet<String> {
    match expr {
        Expr::Var(name) => {
            if !bound.contains(name) {
                push_unbound(name, site, out);
            }
            BTreeSet::new()
        }
        Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_) => BTreeSet::new(),
        Expr::Tuple(items) => {
            check_each(items, bound, site, out);
            BTreeSet::new()
        }
        Expr::List { elements, tail } => {
            check_each(elements, bound, site, out);
            check_expr(tail, bound, site, out);
            BTreeSet::new()
        }
        Expr::Cons { head, tail } => {
            check_expr(head, bound, site, out);
            check_expr(tail, bound, site, out);
            BTreeSet::new()
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => {
            check_pairs(pairs, bound, site, out);
            BTreeSet::new()
        }
        Expr::MapUpdate { base, pairs, .. } => {
            check_expr(base, bound, site, out);
            check_pairs(pairs, bound, site, out);
            BTreeSet::new()
        }
        Expr::TupleElement { tuple, .. } => {
            check_expr(tuple, bound, site, out);
            BTreeSet::new()
        }
        Expr::RecordUpdate { base, updates } => {
            check_expr(base, bound, site, out);
            for (_, value) in updates {
                check_expr(value, bound, site, out);
            }
            BTreeSet::new()
        }
        Expr::Call { args, .. } | Expr::Guard { args, .. } => {
            check_each(args, bound, site, out);
            BTreeSet::new()
        }
        Expr::BinOp { lhs, rhs, .. } => {
            check_expr(lhs, bound, site, out);
            check_expr(rhs, bound, site, out);
            BTreeSet::new()
        }
        Expr::UnOp { operand, .. } => {
            check_expr(operand, bound, site, out);
            BTreeSet::new()
        }
        Expr::MakeFun { env, .. } => {
            check_each(env, bound, site, out);
            BTreeSet::new()
        }
        Expr::CallFun { fun, args } => {
            check_expr(fun, bound, site, out);
            check_each(args, bound, site, out);
            BTreeSet::new()
        }
        Expr::BinaryConstruct(segments) => {
            check_segments(segments, bound, site, out);
            BTreeSet::new()
        }
        Expr::Catch(inner) => {
            check_expr(inner, bound, site, out);
            BTreeSet::new()
        }
        Expr::Case { subject, arms } => {
            check_expr(subject, bound, site, out);
            arms_export(arms, bound, site, out)
        }
        Expr::If { arms } => if_arms_export(arms, bound, site, out),
        Expr::Receive { arms, after } => {
            let mut exported: Option<BTreeSet<String>> = None;
            for arm in arms {
                intersect_into(&mut exported, arm_bindings(arm, bound, site, out));
            }
            if let Some(after) = after {
                check_expr(&after.timeout, bound, site, out);
                let mut inner: BTreeSet<String> = bound.clone();
                check_stmts(&after.body, &mut inner, site, out);
                intersect_into(&mut exported, added(&inner, bound));
            }
            exported.unwrap_or_default()
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            let mut inner: BTreeSet<String> = bound.clone();
            check_stmts(body, &mut inner, site, out);
            for arm in of_arms {
                arm_bindings(arm, &inner, site, out);
            }
            for arm in catch_arms {
                check_catch_arm(arm, bound, site, out);
            }
            let mut after_scope: BTreeSet<String> = bound.clone();
            check_stmts(after, &mut after_scope, site, out);
            BTreeSet::new()
        }
        Expr::Block(stmts) => {
            let mut inner: BTreeSet<String> = bound.clone();
            check_stmts(stmts, &mut inner, site, out);
            added(&inner, bound)
        }
        Expr::Raw(text) => {
            check_fragment(text, bound, site, out);
            BTreeSet::new()
        }
    }
}

fn arms_export(
    arms: &[CaseArm],
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) -> BTreeSet<String> {
    let mut exported: Option<BTreeSet<String>> = None;
    for arm in arms {
        intersect_into(&mut exported, arm_bindings(arm, bound, site, out));
    }
    exported.unwrap_or_default()
}

fn if_arms_export(
    arms: &[IfArm],
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) -> BTreeSet<String> {
    let mut exported: Option<BTreeSet<String>> = None;
    for arm in arms {
        check_expr(&arm.guard, bound, site, out);
        let mut inner: BTreeSet<String> = bound.clone();
        check_stmts(&arm.body, &mut inner, site, out);
        intersect_into(&mut exported, added(&inner, bound));
    }
    exported.unwrap_or_default()
}

fn arm_bindings(
    arm: &CaseArm,
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) -> BTreeSet<String> {
    let mut inner: BTreeSet<String> = bound.clone();
    bind_pattern(&arm.pattern, &mut inner, site, out);
    if let Some(guard) = &arm.guard {
        check_expr(guard, &inner, site, out);
    }
    check_stmts(&arm.body, &mut inner, site, out);
    added(&inner, bound)
}

fn check_catch_arm(
    arm: &CatchArm,
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    let mut inner: BTreeSet<String> = bound.clone();
    if is_variable_name(&arm.class) {
        inner.insert(arm.class.clone());
    }
    bind_pattern(&arm.pattern, &mut inner, site, out);
    if let Some(stacktrace) = &arm.stacktrace {
        inner.insert(stacktrace.clone());
    }
    check_stmts(&arm.body, &mut inner, site, out);
}

fn is_variable_name(name: &str) -> bool {
    name.starts_with(|first: char| first.is_ascii_uppercase() || first == '_')
}

fn bind_pattern(
    pattern: &Expr,
    bound: &mut BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    match pattern {
        Expr::Var(name) => {
            if name != "_" {
                bound.insert(name.clone());
            }
        }
        Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_) => {}
        Expr::Tuple(items) => {
            for item in items {
                bind_pattern(item, bound, site, out);
            }
        }
        Expr::List { elements, tail } => {
            for element in elements {
                bind_pattern(element, bound, site, out);
            }
            bind_pattern(tail, bound, site, out);
        }
        Expr::Cons { head, tail } => {
            bind_pattern(head, bound, site, out);
            bind_pattern(tail, bound, site, out);
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => {
            for (key, value) in pairs {
                check_expr(key, &bound.clone(), site, out);
                bind_pattern(value, bound, site, out);
            }
        }
        Expr::BinaryConstruct(segments) => {
            for segment in segments {
                if let Some(size) = &segment.size {
                    check_expr(size, &bound.clone(), site, out);
                }
                bind_pattern(&segment.value, bound, site, out);
            }
        }
        other => {
            check_expr(other, &bound.clone(), site, out);
        }
    }
}

fn added(inner: &BTreeSet<String>, outer: &BTreeSet<String>) -> BTreeSet<String> {
    inner.difference(outer).cloned().collect()
}

fn intersect_into(accumulator: &mut Option<BTreeSet<String>>, next: BTreeSet<String>) {
    match accumulator {
        Some(current) => {
            *current = current.intersection(&next).cloned().collect();
        }
        None => *accumulator = Some(next),
    }
}

fn push_unbound(name: &str, site: Site<'_>, out: &mut Vec<UnboundReference>) {
    let already: bool = out.iter().any(|found: &UnboundReference| {
        found.function == site.function && found.clause == site.clause && found.variable == name
    });
    if already {
        return;
    }
    out.push(UnboundReference {
        function: site.function.to_owned(),
        arity: site.arity,
        clause: site.clause,
        variable: name.to_owned(),
    });
}

fn check_fragment(
    text: &str,
    bound: &BTreeSet<String>,
    site: Site<'_>,
    out: &mut Vec<UnboundReference>,
) {
    let scan: FragmentScan = scan_fragment(text);
    for (_, name) in &scan.variables {
        if bound.contains(name) || scan.generator_bound.contains(name) {
            continue;
        }
        push_unbound(name, site, out);
    }
}

struct FragmentScan {
    variables: Vec<(usize, String)>,
    generator_bound: BTreeSet<String>,
}

fn scan_fragment(text: &str) -> FragmentScan {
    let bytes: &[u8] = text.as_bytes();
    let mut variables: Vec<(usize, String)> = Vec::new();
    let mut arrows: Vec<(usize, u32)> = Vec::new();
    let mut separators: Vec<(usize, u32)> = Vec::new();
    let mut depth: u32 = 0;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let byte: u8 = bytes[cursor];
        if byte == b'"' || byte == b'\'' {
            cursor = skip_delimited(bytes, cursor, byte);
            continue;
        }
        if byte == b'%' {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if byte == b'$' {
            let escaped: bool = bytes.get(cursor + 1) == Some(&b'\\');
            cursor += if escaped { 3 } else { 2 };
            continue;
        }
        if bytes[cursor..].starts_with(b"<<") {
            depth += 1;
            cursor += 2;
            continue;
        }
        if bytes[cursor..].starts_with(b">>") {
            depth = depth.saturating_sub(1);
            cursor += 2;
            continue;
        }
        if bytes[cursor..].starts_with(b"||") {
            separators.push((cursor, depth));
            cursor += 2;
            continue;
        }
        if bytes[cursor..].starts_with(b"<-") || bytes[cursor..].starts_with(b"<=") {
            arrows.push((cursor, depth));
            cursor += 2;
            continue;
        }
        if matches!(byte, b'(' | b'[' | b'{') {
            depth += 1;
            cursor += 1;
            continue;
        }
        if matches!(byte, b')' | b']' | b'}') {
            depth = depth.saturating_sub(1);
            cursor += 1;
            continue;
        }
        if byte == b',' {
            separators.push((cursor, depth));
            cursor += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start: usize = cursor;
            while cursor < bytes.len() && is_name_byte(bytes[cursor]) {
                cursor += 1;
            }
            let name: &str = &text[start..cursor];
            if (byte.is_ascii_uppercase() || byte == b'_') && name != "_" {
                variables.push((start, name.to_owned()));
            }
            continue;
        }
        cursor += 1;
    }
    let mut generator_bound: BTreeSet<String> = BTreeSet::new();
    for (arrow, arrow_depth) in &arrows {
        let start: usize = separators
            .iter()
            .filter(|(position, separator_depth): &&(usize, u32)| {
                position < arrow && separator_depth <= arrow_depth
            })
            .map(|(position, _): &(usize, u32)| *position)
            .max()
            .unwrap_or(0);
        for (position, name) in &variables {
            if *position > start && *position < *arrow {
                generator_bound.insert(name.clone());
            }
        }
    }
    FragmentScan {
        variables,
        generator_bound,
    }
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'@'
}

fn skip_delimited(bytes: &[u8], open: usize, delimiter: u8) -> usize {
    let mut cursor: usize = open + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor += 2;
            continue;
        }
        if bytes[cursor] == delimiter {
            return cursor + 1;
        }
        cursor += 1;
    }
    bytes.len()
}
