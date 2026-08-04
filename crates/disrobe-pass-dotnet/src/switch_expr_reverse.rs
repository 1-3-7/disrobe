use std::fmt::Write as _;

use crate::structurize::StructuredMethod;

#[derive(Debug, Clone)]
struct SwitchArm {
    pattern: String,
    value: String,
}

#[derive(Debug, Clone)]
struct LadderMatch {
    decl_index: usize,
    discriminant: String,
    arms: Vec<SwitchArm>,
    default_value: String,
    return_index: usize,
    body_indent: usize,
}

pub fn reconstruct_switch_expressions(methods: &mut [StructuredMethod]) -> u32 {
    let mut rewritten: u32 = 0;
    for m in methods.iter_mut() {
        if let Some(updated) = rewrite_body(&m.body) {
            m.body = updated;
            rewritten = rewritten.saturating_add(1);
        }
    }
    rewritten
}

fn rewrite_body(body: &str) -> Option<String> {
    let lines: Vec<&str> = body.lines().collect();
    let m: LadderMatch = detect_ladder(&lines)
        .or_else(|| detect_type_ladder(&lines))
        .or_else(|| detect_relational_switch(&lines))
        .or_else(|| detect_guarded_switch(&lines))?;
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        if i == m.decl_index {
            continue;
        }
        if i == m.decl_index + 1 && line.trim().is_empty() {
            continue;
        }
        if i > m.decl_index && i < m.return_index {
            continue;
        }
        if i == m.return_index {
            out.push(render_switch_return(&m));
            continue;
        }
        out.push((*line).to_owned());
    }
    let mut joined: String = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    Some(joined)
}

fn render_switch_return(m: &LadderMatch) -> String {
    let pad: String = " ".repeat(m.body_indent);
    let arm_pad: String = " ".repeat(m.body_indent + 4);
    let mut text: String = String::new();
    let _ = writeln!(text, "{pad}return {} switch", m.discriminant);
    let _ = writeln!(text, "{pad}{{");
    for arm in &m.arms {
        let _ = writeln!(text, "{arm_pad}{} => {},", arm.pattern, arm.value);
    }
    let _ = writeln!(text, "{arm_pad}_ => {},", m.default_value);
    let _ = write!(text, "{pad}}};");
    text
}

fn detect_ladder(lines: &[&str]) -> Option<LadderMatch> {
    let decl_index: usize = find_single_local_decl(lines)?;
    let decl_line: &str = lines[decl_index];
    let assigned: String = local_decl_name(decl_line)?;
    let body_indent: usize = indent_of(decl_line);

    let mut cursor: usize = next_nonblank(lines, decl_index + 1)?;
    let mut discriminant: Option<String> = None;
    let mut arms: Vec<SwitchArm> = Vec::new();

    let default_value: String = loop {
        let level_indent: usize = indent_of(lines[cursor]);
        if level_indent < body_indent {
            return None;
        }
        let (pattern, value, next): (String, String, usize) =
            parse_if_arm(lines, cursor, level_indent, &assigned)?;
        let disc: String = pattern_discriminant(&pattern)?;
        match &discriminant {
            Some(prev) if prev != &disc => return None,
            _ => discriminant = Some(disc),
        }
        let literal: String = pattern_literal(&pattern)?;
        arms.push(SwitchArm {
            pattern: literal,
            value,
        });
        let else_open: usize = expect_else_block(lines, next, level_indent)?;
        let inner: usize = next_nonblank(lines, else_open + 1)?;
        if line_is_assignment_to(lines[inner], &assigned) {
            break assignment_value(lines[inner], &assigned)?;
        }
        cursor = inner;
    };

    let return_index: usize =
        lines
            .iter()
            .enumerate()
            .skip(decl_index)
            .find_map(|(i, l): (usize, &&str)| {
                (indent_of(l) == body_indent && line_is_return_of(l, &assigned)).then_some(i)
            })?;
    let discriminant: String = discriminant?;
    if arms.len() < 2 {
        return None;
    }
    Some(LadderMatch {
        decl_index,
        discriminant,
        arms,
        default_value,
        return_index,
        body_indent,
    })
}

fn detect_type_ladder(lines: &[&str]) -> Option<LadderMatch> {
    let decl_index: usize = find_single_local_decl(lines)?;
    let decl_line: &str = lines[decl_index];
    let assigned: String = local_decl_name(decl_line)?;
    let body_indent: usize = indent_of(decl_line);

    let mut cursor: usize = next_nonblank(lines, decl_index + 1)?;
    let mut discriminant: Option<String> = None;
    let mut arms: Vec<SwitchArm> = Vec::new();

    let default_value: String = loop {
        let level_indent: usize = indent_of(lines[cursor]);
        if level_indent < body_indent {
            return None;
        }
        let (cond, value, next): (String, String, usize) =
            parse_if_arm(lines, cursor, level_indent, &assigned)?;
        let disc: String = type_discriminant(&cond, lines, decl_index)?;
        match &discriminant {
            Some(prev) if prev != &disc => return None,
            _ => discriminant = Some(disc),
        }
        let pattern: String = type_pattern(&cond)?;
        arms.push(SwitchArm { pattern, value });
        let else_open: usize = expect_else_block(lines, next, level_indent)?;
        let inner: usize = next_nonblank(lines, else_open + 1)?;
        if line_is_assignment_to(lines[inner], &assigned) {
            break assignment_value(lines[inner], &assigned)?;
        }
        cursor = inner;
    };

    let return_index: usize =
        lines
            .iter()
            .enumerate()
            .skip(decl_index)
            .find_map(|(i, l): (usize, &&str)| {
                (indent_of(l) == body_indent && line_is_return_of(l, &assigned)).then_some(i)
            })?;
    let discriminant: String = discriminant?;
    if arms.len() < 2 {
        return None;
    }
    Some(LadderMatch {
        decl_index,
        discriminant,
        arms,
        default_value,
        return_index,
        body_indent,
    })
}

fn type_discriminant(cond: &str, lines: &[&str], before: usize) -> Option<String> {
    let (lhs, _rhs): (&str, &str) = type_test_parts(cond)?;
    if cond.contains(" is ") {
        return (is_identifier(lhs) && object_parameter_exists(lines, before, lhs))
            .then(|| lhs.to_owned());
    }
    is_simple_discriminant(lhs).then(|| lhs.to_owned())
}

fn type_pattern(cond: &str) -> Option<String> {
    let (_lhs, ty): (&str, &str) = type_test_parts(cond)?;
    is_type_name(ty).then(|| keyword_type(ty).to_owned())
}

fn type_test_parts(cond: &str) -> Option<(&str, &str)> {
    let as_parts: Option<(&str, &str)> = cond.split_once(" as ");
    if let Some((lhs, rhs)) = as_parts {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs): (&str, &str) = cond.split_once(" is ")?;
    let discriminant: &str = lhs
        .trim()
        .strip_prefix("((object)")?
        .strip_suffix(')')?
        .trim();
    Some((discriminant, rhs.trim()))
}

fn is_type_name(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_identifier)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .next()
            .is_some_and(|byte: u8| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn object_parameter_exists(lines: &[&str], before: usize, name: &str) -> bool {
    method_parameters(lines, before).is_some_and(|parameters: &str| {
        parameters
            .split(',')
            .any(|parameter: &str| object_parameter_matches(parameter, name))
    })
}

fn method_parameters<'a>(lines: &[&'a str], before: usize) -> Option<&'a str> {
    let body_open: usize = lines
        .iter()
        .take(before)
        .position(|line: &&str| line.trim() == "{")?;
    let declaration_index: usize = (0..body_open)
        .rev()
        .find(|index: &usize| !lines[*index].trim().is_empty())?;
    let declaration: &str = lines[declaration_index].trim();
    let open: usize = declaration.find('(')?;
    let close: usize = declaration.rfind(')')?;
    if close <= open || close != declaration.len().saturating_sub(1) {
        return None;
    }
    let prefix: &str = declaration.get(..open)?.trim();
    let method_name: &str = prefix
        .rsplit_once(' ')
        .map_or(prefix, |(_, name): (&str, &str)| name);
    if !is_identifier(method_name) {
        return None;
    }
    declaration.get(open + 1..close)
}

fn object_parameter_matches(parameter: &str, name: &str) -> bool {
    let Some((ty, parameter_name)): Option<(&str, &str)> = parameter.trim().rsplit_once(' ') else {
        return false;
    };
    parameter_name == name && matches!(ty.trim(), "object" | "System.Object")
}

fn keyword_type(ty: &str) -> &str {
    let system_type: Option<&str> = ty.strip_prefix("System.");
    let short: &str = match system_type {
        Some(system_type) if !system_type.contains('.') => system_type,
        Some(_) => return ty,
        None if ty.contains('.') => return ty,
        None => ty,
    };
    match short {
        "Boolean" => "bool",
        "Byte" => "byte",
        "SByte" => "sbyte",
        "Char" => "char",
        "Int16" => "short",
        "UInt16" => "ushort",
        "Int32" => "int",
        "UInt32" => "uint",
        "Int64" => "long",
        "UInt64" => "ulong",
        "Single" => "float",
        "Double" => "double",
        "Decimal" => "decimal",
        "String" => "string",
        "Object" => "object",
        _ => ty,
    }
}

fn find_single_local_decl(lines: &[&str]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        if local_decl_name(line).is_some() {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

fn local_decl_name(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    if inner.contains('=') || inner.contains('(') || inner.contains('{') {
        return None;
    }
    let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
    if is_statement_keyword(ty.split_whitespace().next().unwrap_or(ty)) {
        return None;
    }
    let valid_name: bool = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    (valid_name && !ty.trim().is_empty()).then(|| name.to_owned())
}

fn parse_if_arm(
    lines: &[&str],
    start: usize,
    level_indent: usize,
    assigned: &str,
) -> Option<(String, String, usize)> {
    let head: &str = lines.get(start)?;
    if indent_of(head) != level_indent {
        return None;
    }
    let cond: &str = if_condition(head.trim())?;
    let open: usize = next_nonblank(lines, start + 1)?;
    if !is_open_brace(lines[open], level_indent) {
        return None;
    }
    let stmt: usize = next_nonblank(lines, open + 1)?;
    let value: String = assignment_value(lines[stmt], assigned)?;
    let close: usize = next_nonblank(lines, stmt + 1)?;
    if !is_close_brace(lines[close], level_indent) {
        return None;
    }
    Some((cond.to_owned(), value, close + 1))
}

fn if_condition(t: &str) -> Option<&str> {
    let rest: &str = t.strip_prefix("if (")?;
    let inner: &str = rest.strip_suffix(')')?;
    (!inner.is_empty()).then_some(inner)
}

fn pattern_discriminant(cond: &str) -> Option<String> {
    let (lhs, _rhs): (&str, &str) = cond.split_once(" == ")?;
    let lhs: &str = lhs.trim();
    is_simple_discriminant(lhs).then(|| lhs.to_owned())
}

fn pattern_literal(cond: &str) -> Option<String> {
    let (_lhs, rhs): (&str, &str) = cond.split_once(" == ")?;
    let rhs: &str = rhs.trim();
    is_constant_pattern(rhs).then(|| rhs.to_owned())
}

fn is_simple_discriminant(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn is_constant_pattern(s: &str) -> bool {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return !s[1..s.len() - 1].contains('"');
    }
    if s.len() >= 3 && s.starts_with('\'') && s.ends_with('\'') {
        return true;
    }
    s.bytes().all(|b: u8| b.is_ascii_digit()) && !s.is_empty()
}

fn expect_else_block(lines: &[&str], idx: usize, level_indent: usize) -> Option<usize> {
    let else_line: usize = next_nonblank(lines, idx)?;
    if lines[else_line].trim() != "else" || indent_of(lines[else_line]) != level_indent {
        return None;
    }
    let open: usize = next_nonblank(lines, else_line + 1)?;
    is_open_brace(lines[open], level_indent).then_some(open)
}

fn line_is_assignment_to(line: &str, name: &str) -> bool {
    assignment_value(line, name).is_some()
}

fn assignment_value(line: &str, name: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" = ")?;
    (lhs.trim() == name).then(|| rhs.trim().to_owned())
}

fn line_is_return_of(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    t.strip_suffix(';')
        .and_then(|s: &str| s.strip_prefix("return "))
        .is_some_and(|v: &str| v.trim() == name)
}

fn is_open_brace(line: &str, body_indent: usize) -> bool {
    line.trim() == "{" && indent_of(line) >= body_indent
}

fn is_close_brace(line: &str, body_indent: usize) -> bool {
    line.trim() == "}" && indent_of(line) >= body_indent
}

fn is_statement_keyword(token: &str) -> bool {
    matches!(
        token,
        "return"
            | "throw"
            | "yield"
            | "break"
            | "continue"
            | "goto"
            | "if"
            | "else"
            | "while"
            | "for"
            | "foreach"
            | "switch"
            | "do"
            | "case"
    )
}

fn indent_of(line: &str) -> usize {
    line.bytes().take_while(|b: &u8| *b == b' ').count()
}

fn next_nonblank(lines: &[&str], start: usize) -> Option<usize> {
    (start..lines.len()).find(|&i: &usize| !lines[i].trim().is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
struct RelLeaf {
    lower: Option<i64>,
    value: String,
}

fn detect_relational_switch(lines: &[&str]) -> Option<LadderMatch> {
    let decl_index: usize = find_single_local_decl(lines)?;
    let decl_line: &str = lines[decl_index];
    let assigned: String = local_decl_name(decl_line)?;
    let body_indent: usize = indent_of(decl_line);

    let return_index: usize =
        lines
            .iter()
            .enumerate()
            .skip(decl_index)
            .find_map(|(i, l): (usize, &&str)| {
                (indent_of(l) == body_indent && line_is_return_of(l, &assigned)).then_some(i)
            })?;

    let tree_start: usize = next_nonblank(lines, decl_index + 1)?;
    if tree_start >= return_index {
        return None;
    }

    let mut discriminant: Option<String> = None;
    let mut leaves: Vec<RelLeaf> = Vec::new();
    let consumed: usize = parse_rel_node(
        lines,
        tree_start,
        body_indent,
        &assigned,
        &mut discriminant,
        &mut leaves,
    )?;
    if next_nonblank(lines, consumed).is_some_and(|i: usize| i < return_index) {
        return None;
    }

    let discriminant: String = discriminant?;
    let bounded: Vec<&RelLeaf> = leaves
        .iter()
        .filter(|l: &&RelLeaf| l.lower.is_some())
        .collect();
    if bounded.len() < 2 {
        return None;
    }
    if leaves
        .iter()
        .filter(|l: &&RelLeaf| l.lower.is_none())
        .count()
        != 1
    {
        return None;
    }
    let default_value: String = leaves
        .iter()
        .find(|l: &&RelLeaf| l.lower.is_none())
        .map(|l: &RelLeaf| l.value.clone())?;

    let mut sorted: Vec<&RelLeaf> = bounded;
    sorted.sort_by_key(|l: &&RelLeaf| std::cmp::Reverse(l.lower));
    let mut seen: Vec<i64> = Vec::new();
    let arms: Vec<SwitchArm> = sorted
        .iter()
        .map(|leaf: &&RelLeaf| {
            let bound: i64 = leaf.lower.unwrap_or_default();
            seen.push(bound);
            SwitchArm {
                pattern: format!(">= {bound}"),
                value: leaf.value.clone(),
            }
        })
        .collect();
    if seen.windows(2).any(|w: &[i64]| w[0] == w[1]) {
        return None;
    }

    Some(LadderMatch {
        decl_index,
        discriminant,
        arms,
        default_value,
        return_index,
        body_indent,
    })
}

fn parse_rel_node(
    lines: &[&str],
    start: usize,
    indent: usize,
    assigned: &str,
    discriminant: &mut Option<String>,
    leaves: &mut Vec<RelLeaf>,
) -> Option<usize> {
    let node: usize = next_nonblank(lines, start)?;
    if indent_of(lines[node]) != indent {
        return None;
    }
    if let Some(value) = assignment_value(lines[node], assigned) {
        leaves.push(RelLeaf { lower: None, value });
        return Some(node + 1);
    }
    let (disc, relation, literal): (String, Relation, i64) = parse_rel_condition(lines[node])?;
    match discriminant {
        Some(prev) if prev != &disc => return None,
        _ => *discriminant = Some(disc),
    }
    let then_open: usize = next_nonblank(lines, node + 1)?;
    if !is_open_brace(lines[then_open], indent) {
        return None;
    }
    let inner_indent: usize = indent + 4;
    let then_end: usize = parse_rel_branch(
        lines,
        then_open + 1,
        inner_indent,
        assigned,
        discriminant,
        leaves,
        relation,
        literal,
        true,
    )?;
    let then_close: usize = next_nonblank(lines, then_end)?;
    if !is_close_brace(lines[then_close], indent) {
        return None;
    }
    let else_kw: usize = next_nonblank(lines, then_close + 1)?;
    if lines[else_kw].trim() != "else" || indent_of(lines[else_kw]) != indent {
        return None;
    }
    let else_open: usize = next_nonblank(lines, else_kw + 1)?;
    if !is_open_brace(lines[else_open], indent) {
        return None;
    }
    let else_end: usize = parse_rel_branch(
        lines,
        else_open + 1,
        inner_indent,
        assigned,
        discriminant,
        leaves,
        relation,
        literal,
        false,
    )?;
    let else_close: usize = next_nonblank(lines, else_end)?;
    if !is_close_brace(lines[else_close], indent) {
        return None;
    }
    Some(else_close + 1)
}

#[allow(clippy::too_many_arguments)]
fn parse_rel_branch(
    lines: &[&str],
    start: usize,
    indent: usize,
    assigned: &str,
    discriminant: &mut Option<String>,
    leaves: &mut Vec<RelLeaf>,
    relation: Relation,
    literal: i64,
    taken: bool,
) -> Option<usize> {
    let before: usize = leaves.len();
    let consumed: usize = parse_rel_node(lines, start, indent, assigned, discriminant, leaves)?;
    let lower: Option<i64> = branch_lower_bound(relation, literal, taken);
    for leaf in leaves.iter_mut().skip(before) {
        leaf.lower = tighten_lower(leaf.lower, lower);
    }
    Some(consumed)
}

const fn branch_lower_bound(relation: Relation, literal: i64, taken: bool) -> Option<i64> {
    match (relation, taken) {
        (Relation::Ge, true) | (Relation::Lt, false) => Some(literal),
        (Relation::Gt, true) | (Relation::Le, false) => literal.checked_add(1),
        _ => None,
    }
}

fn tighten_lower(current: Option<i64>, incoming: Option<i64>) -> Option<i64> {
    match (current, incoming) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

fn parse_rel_condition(line: &str) -> Option<(String, Relation, i64)> {
    let cond: &str = if_condition(line.trim())?;
    for (token, relation) in [
        (" >= ", Relation::Ge),
        (" <= ", Relation::Le),
        (" > ", Relation::Gt),
        (" < ", Relation::Lt),
    ] {
        if let Some((lhs, rhs)) = cond.split_once(token) {
            let lhs: &str = lhs.trim();
            let rhs: &str = rhs.trim();
            if !is_simple_discriminant(lhs) {
                return None;
            }
            let literal: i64 = parse_int_literal(rhs)?;
            return Some((lhs.to_owned(), relation, literal));
        }
    }
    None
}

fn parse_int_literal(s: &str) -> Option<i64> {
    let digits: &str = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

const GUARD_VAR: &str = "x";

const fn invert_relation(relation: Relation) -> Relation {
    match relation {
        Relation::Lt => Relation::Ge,
        Relation::Le => Relation::Gt,
        Relation::Gt => Relation::Le,
        Relation::Ge => Relation::Lt,
    }
}

const fn relation_token(relation: Relation) -> &'static str {
    match relation {
        Relation::Lt => "<",
        Relation::Le => "<=",
        Relation::Gt => ">",
        Relation::Ge => ">=",
    }
}

fn detect_guarded_switch(lines: &[&str]) -> Option<LadderMatch> {
    let decl_index: usize = first_local_decl(lines)?;
    let body_indent: usize = indent_of(lines[decl_index]);

    let mut after_decls: usize = decl_index;
    while let Some(next) = next_nonblank(lines, after_decls + 1) {
        if local_decl_name(lines[next]).is_some() {
            after_decls = next;
        } else {
            break;
        }
    }
    let copy_index: usize = next_nonblank(lines, after_decls + 1)?;
    let (value_local, discriminant): (String, String) = discriminant_copy(lines[copy_index])?;
    if discriminant == GUARD_VAR {
        return None;
    }

    let (return_index, return_local): (usize, String) = lines
        .iter()
        .enumerate()
        .skip(copy_index)
        .find_map(|(i, l): (usize, &&str)| {
        if indent_of(l) != body_indent {
            return None;
        }
        returned_local(l).map(|name: String| (i, name))
    })?;
    if return_local == discriminant {
        return None;
    }

    let spine_start: usize = next_nonblank(lines, copy_index + 1)?;
    if spine_start >= return_index {
        return None;
    }

    let mut arms: Vec<SwitchArm> = Vec::new();
    let (default_value, consumed): (String, usize) = parse_guard_spine(
        lines,
        spine_start,
        body_indent,
        &value_local,
        &return_local,
        &mut arms,
    )?;
    if next_nonblank(lines, consumed).is_some_and(|i: usize| i < return_index) {
        return None;
    }
    if arms.len() < 2 {
        return None;
    }

    Some(LadderMatch {
        decl_index,
        discriminant,
        arms,
        default_value,
        return_index,
        body_indent,
    })
}

fn returned_local(line: &str) -> Option<String> {
    let name: &str = line
        .trim()
        .strip_suffix(';')?
        .strip_prefix("return ")?
        .trim();
    is_simple_discriminant(name).then(|| name.to_owned())
}

fn first_local_decl(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .position(|line: &&str| local_decl_name(line).is_some())
}

fn discriminant_copy(line: &str) -> Option<(String, String)> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" = ")?;
    let lhs: &str = lhs.trim();
    let rhs: &str = rhs.trim();
    if !is_simple_discriminant(lhs) || !is_simple_discriminant(rhs) {
        return None;
    }
    Some((lhs.to_owned(), rhs.to_owned()))
}

fn parse_guard_spine(
    lines: &[&str],
    start: usize,
    indent: usize,
    value_local: &str,
    return_local: &str,
    arms: &mut Vec<SwitchArm>,
) -> Option<(String, usize)> {
    let node: usize = next_nonblank(lines, start)?;
    if indent_of(lines[node]) != indent {
        return None;
    }
    let (disc, body_relation, literal): (String, Relation, i64) = parse_rel_condition(lines[node])?;
    if disc != value_local {
        return None;
    }
    let guard: Relation = invert_relation(body_relation);

    let then_open: usize = next_nonblank(lines, node + 1)?;
    if !is_open_brace(lines[then_open], indent) {
        return None;
    }
    let inner_indent: usize = indent + 4;
    let arm_slot: usize = arms.len();
    arms.push(SwitchArm {
        pattern: format!(
            "var {GUARD_VAR} when {GUARD_VAR} {} {literal}",
            relation_token(guard)
        ),
        value: String::new(),
    });

    let then_start: usize = next_nonblank(lines, then_open + 1)?;
    let (default_value, then_end): (String, usize) =
        if parse_rel_condition(lines[then_start]).is_some() {
            parse_guard_spine(
                lines,
                then_start,
                inner_indent,
                value_local,
                return_local,
                arms,
            )?
        } else {
            let value: String = leaf_assignment(lines[then_start], inner_indent, return_local)?;
            (value, then_start + 1)
        };
    let then_close: usize = next_nonblank(lines, then_end)?;
    if !is_close_brace(lines[then_close], indent) {
        return None;
    }
    let else_kw: usize = next_nonblank(lines, then_close + 1)?;
    if lines[else_kw].trim() != "else" || indent_of(lines[else_kw]) != indent {
        return None;
    }
    let else_open: usize = next_nonblank(lines, else_kw + 1)?;
    if !is_open_brace(lines[else_open], indent) {
        return None;
    }
    let else_value_line: usize = next_nonblank(lines, else_open + 1)?;
    let arm_value: String = leaf_assignment(lines[else_value_line], inner_indent, return_local)?;
    let else_close: usize = next_nonblank(lines, else_value_line + 1)?;
    if !is_close_brace(lines[else_close], indent) {
        return None;
    }
    arms.get_mut(arm_slot)?.value = arm_value;
    Some((default_value, else_close + 1))
}

fn leaf_assignment(line: &str, indent: usize, return_local: &str) -> Option<String> {
    if indent_of(line) != indent {
        return None;
    }
    assignment_value(line, return_local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(body: &str) -> StructuredMethod {
        StructuredMethod {
            token: 0,
            signature: "// Sample.Constructs\npublic static string Classify(string kind)"
                .to_owned(),
            body: body.to_owned(),
            statement_count: 0,
            recovered_locals: 0,
            recovered_branches: 0,
            typed_locals: 0,
            named_params: 0,
        }
    }

    const LADDER: &str = "// Sample.Constructs\npublic static string Classify(string kind)\n{\n    string local0;\n\n    if (kind == \"alpha\")\n    {\n        local0 = \"first\";\n    }\n    else\n    {\n        if (kind == \"beta\")\n        {\n            local0 = \"second\";\n        }\n        else\n        {\n            if (kind == \"gamma\")\n            {\n                local0 = \"third\";\n            }\n            else\n            {\n                local0 = \"unknown\";\n            }\n        }\n    }\n    return local0;\n}\n";

    #[test]
    fn rewrites_string_equality_ladder() {
        let mut methods: Vec<StructuredMethod> = vec![method(LADDER)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return kind switch"), "body:\n{body}");
        assert!(body.contains("\"alpha\" => \"first\","), "body:\n{body}");
        assert!(body.contains("\"beta\" => \"second\","), "body:\n{body}");
        assert!(body.contains("\"gamma\" => \"third\","), "body:\n{body}");
        assert!(body.contains("_ => \"unknown\","), "body:\n{body}");
        assert!(!body.contains("string local0;"), "body:\n{body}");
        assert!(!body.contains("if (kind"), "body:\n{body}");
    }

    #[test]
    fn leaves_unrelated_if_else_untouched() {
        let unrelated: &str = "// Sample.X\npublic static int F(int n)\n{\n    int local0;\n\n    if (n == 1)\n    {\n        local0 = 2;\n    }\n    else\n    {\n        return 9;\n    }\n    return local0;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(unrelated)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 0);
        assert!(methods[0].body.contains("if (n == 1)"));
    }

    #[test]
    fn requires_at_least_two_arms() {
        let single: &str = "// Sample.X\npublic static int F(int n)\n{\n    int local0;\n\n    if (n == 1)\n    {\n        local0 = 2;\n    }\n    else\n    {\n        local0 = 3;\n    }\n    return local0;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(single)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 0);
    }

    const REL_BST: &str = "// Sample.Shapes\npublic string Grade(int score)\n{\n    string local0;\n\n    if (score < 80)\n    {\n        if (score >= 70)\n        {\n            local0 = \"C\";\n        }\n        else\n        {\n            local0 = \"F\";\n        }\n    }\n    else\n    {\n        if (score >= 90)\n        {\n            local0 = \"A\";\n        }\n        else\n        {\n            local0 = \"B\";\n        }\n    }\n    return local0;\n}\n";

    #[test]
    fn rewrites_relational_binary_search_tree() {
        let mut methods: Vec<StructuredMethod> = vec![method(REL_BST)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return score switch"), "body:\n{body}");
        assert!(body.contains(">= 90 => \"A\","), "body:\n{body}");
        assert!(body.contains(">= 80 => \"B\","), "body:\n{body}");
        assert!(body.contains(">= 70 => \"C\","), "body:\n{body}");
        assert!(body.contains("_ => \"F\","), "body:\n{body}");
        assert!(!body.contains("if (score"), "body:\n{body}");
        let arm_a: Option<usize> = body.find(">= 90");
        let arm_b: Option<usize> = body.find(">= 80");
        let arm_c: Option<usize> = body.find(">= 70");
        assert!(
            matches!((arm_a, arm_b, arm_c), (Some(a), Some(b), Some(c)) if a < b && b < c),
            "descending arm order:\n{body}"
        );
    }

    #[test]
    fn ignores_relational_tree_without_default() {
        let no_default: &str = "// Sample.X\npublic static int G(int n)\n{\n    int local0;\n\n    if (n >= 10)\n    {\n        local0 = 1;\n    }\n    else\n    {\n        if (n >= 5)\n        {\n            local0 = 2;\n        }\n        else\n        {\n            if (n >= 0)\n            {\n                local0 = 3;\n            }\n            else\n            {\n                if (n >= -5)\n                {\n                    local0 = 4;\n                }\n                else\n                {\n                    local0 = 5;\n                }\n            }\n        }\n    }\n    return local0;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(no_default)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains(">= 10 => 1,"), "body:\n{body}");
        assert!(body.contains(">= -5 => 4,"), "body:\n{body}");
        assert!(body.contains("_ => 5,"), "body:\n{body}");
    }

    const GUARD_TIER: &str = "// Sample.Guards\npublic string Tier(int score)\n{\n    int local0;\n    string local1;\n\n    local0 = score;\n    if (local0 <= 100)\n    {\n        if (local0 <= 50)\n        {\n            if (local0 <= 0)\n            {\n                local1 = \"none\";\n            }\n            else\n            {\n                local1 = \"silver\";\n            }\n        }\n        else\n        {\n            local1 = \"gold\";\n        }\n    }\n    else\n    {\n        local1 = \"platinum\";\n    }\n    return local1;\n}\n";

    #[test]
    fn rewrites_when_guard_switch() {
        let mut methods: Vec<StructuredMethod> = vec![method(GUARD_TIER)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return score switch"), "body:\n{body}");
        assert!(
            body.contains("var x when x > 100 => \"platinum\","),
            "body:\n{body}"
        );
        assert!(
            body.contains("var x when x > 50 => \"gold\","),
            "body:\n{body}"
        );
        assert!(
            body.contains("var x when x > 0 => \"silver\","),
            "body:\n{body}"
        );
        assert!(body.contains("_ => \"none\","), "body:\n{body}");
        assert!(!body.contains("local0 = score;"), "body:\n{body}");
        assert!(!body.contains("if (local0"), "body:\n{body}");
        let platinum: Option<usize> = body.find("> 100");
        let gold: Option<usize> = body.find("> 50");
        let silver: Option<usize> = body.find("> 0 ");
        assert!(
            matches!(
                (platinum, gold, silver),
                (Some(first), Some(second), Some(third)) if first < second && second < third
            ),
            "top-down arm order:\n{body}"
        );
    }

    const GUARD_MIXED: &str = "// Sample.Guards\npublic string Sign(int n)\n{\n    int local0;\n    string local1;\n\n    local0 = n;\n    if (local0 <= 0)\n    {\n        if (local0 >= 0)\n        {\n            local1 = \"zero\";\n        }\n        else\n        {\n            local1 = \"negative\";\n        }\n    }\n    else\n    {\n        local1 = \"positive\";\n    }\n    return local1;\n}\n";

    #[test]
    fn rewrites_mixed_relation_guard_switch() {
        let mut methods: Vec<StructuredMethod> = vec![method(GUARD_MIXED)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return n switch"), "body:\n{body}");
        assert!(
            body.contains("var x when x > 0 => \"positive\","),
            "body:\n{body}"
        );
        assert!(
            body.contains("var x when x < 0 => \"negative\","),
            "body:\n{body}"
        );
        assert!(body.contains("_ => \"zero\","), "body:\n{body}");
    }

    const TYPE_LADDER: &str = "// Sample.Probe\npublic string Describe(object o)\n{\n    string local0;\n\n    if (o as Int32)\n    {\n        local0 = \"int\";\n    }\n    else\n    {\n        if (o as String)\n        {\n            local0 = \"str\";\n        }\n        else\n        {\n            if (o as Box)\n            {\n                local0 = \"box\";\n            }\n            else\n            {\n                local0 = \"other\";\n            }\n        }\n    }\n    return local0;\n}\n";

    #[test]
    fn rewrites_type_pattern_ladder() {
        let mut methods: Vec<StructuredMethod> = vec![method(TYPE_LADDER)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return o switch"), "body:\n{body}");
        assert!(body.contains("int => \"int\","), "body:\n{body}");
        assert!(body.contains("string => \"str\","), "body:\n{body}");
        assert!(body.contains("Box => \"box\","), "body:\n{body}");
        assert!(body.contains("_ => \"other\","), "body:\n{body}");
        assert!(!body.contains("o as Int32"), "body:\n{body}");
        assert!(!body.contains("string local0;"), "body:\n{body}");
    }

    const TYPED_IS_LADDER: &str = "// Sample.Probe\npublic string Describe(object value)\n{\n    string local0;\n\n    if (((object)value) is Int32)\n    {\n        local0 = \"int\";\n    }\n    else\n    {\n        if (((object)value) is String)\n        {\n            local0 = \"text\";\n        }\n        else\n        {\n            local0 = \"other\";\n        }\n    }\n    return local0;\n}\n";

    #[test]
    fn rewrites_typed_is_pattern_ladder() {
        let mut methods: Vec<StructuredMethod> = vec![method(TYPED_IS_LADDER)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("return value switch"), "body:\n{body}");
        assert!(body.contains("int => \"int\","), "body:\n{body}");
        assert!(body.contains("string => \"text\","), "body:\n{body}");
        assert!(body.contains("_ => \"other\","), "body:\n{body}");
    }

    #[test]
    fn refuses_unwrapped_typed_is_ladder() {
        let source: String = TYPED_IS_LADDER.replace("((object)value)", "value");
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
        assert_eq!(methods[0].body, source);
    }

    #[test]
    fn refuses_typed_is_property_ladder() {
        let source: String = TYPED_IS_LADDER
            .replacen("object value", "Holder holder", 1)
            .replace("((object)value)", "((object)holder.Value)");
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn refuses_typed_is_call_ladder() {
        let source: String = TYPED_IS_LADDER.replace("((object)value)", "((object)getValue())");
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn refuses_typed_is_ladder_for_non_object_parameter() {
        let source: String = TYPED_IS_LADDER.replacen("object value", "int value", 1);
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn refuses_comment_spoofed_object_parameter() {
        let source: String = TYPED_IS_LADDER
            .replacen("object value", "int value", 1)
            .replacen("// Sample.Probe", "// Marker(object value)", 1);
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn refuses_typed_is_ladder_with_malformed_type() {
        let source: String = TYPED_IS_LADDER.replacen(" is Int32", " is Acme.", 1);
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn preserves_namespaced_type_patterns() {
        let source: String =
            TYPED_IS_LADDER
                .replacen("Int32", "Acme.Int32", 1)
                .replacen("String", "Acme.String", 1);
        let mut methods: Vec<StructuredMethod> = vec![method(&source)];
        let rewritten: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(rewritten, 1);
        let body: &str = &methods[0].body;
        assert!(body.contains("Acme.Int32 => \"int\","), "body:\n{body}");
        assert!(body.contains("Acme.String => \"text\","), "body:\n{body}");
        assert!(!body.contains("int => \"int\","), "body:\n{body}");
        assert!(!body.contains("string => \"text\","), "body:\n{body}");
    }

    #[test]
    fn ignores_single_arm_type_test() {
        let single: &str = "// Sample.X\npublic string F(object o)\n{\n    string local0;\n\n    if (o as Int32)\n    {\n        local0 = \"int\";\n    }\n    else\n    {\n        local0 = \"other\";\n    }\n    return local0;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(single)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 0);
    }

    #[test]
    fn ignores_type_test_with_inconsistent_discriminant() {
        let mixed: &str = "// Sample.X\npublic string F(object o, object p)\n{\n    string local0;\n\n    if (o as Int32)\n    {\n        local0 = \"a\";\n    }\n    else\n    {\n        if (p as String)\n        {\n            local0 = \"b\";\n        }\n        else\n        {\n            local0 = \"c\";\n        }\n    }\n    return local0;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(mixed)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 0);
    }

    #[test]
    fn maps_primitive_type_keywords() {
        assert_eq!(keyword_type("Int32"), "int");
        assert_eq!(keyword_type("System.String"), "string");
        assert_eq!(keyword_type("Boolean"), "bool");
        assert_eq!(keyword_type("Box"), "Box");
        assert_eq!(keyword_type("Sample.Box"), "Sample.Box");
        assert!(!is_type_name("Foo."));
    }

    #[test]
    fn ignores_guard_shape_with_one_arm() {
        let single: &str = "// Sample.X\npublic string F(int n)\n{\n    int local0;\n    string local1;\n\n    local0 = n;\n    if (local0 <= 0)\n    {\n        local1 = \"b\";\n    }\n    else\n    {\n        local1 = \"a\";\n    }\n    return local1;\n}\n";
        let mut methods: Vec<StructuredMethod> = vec![method(single)];
        let n: u32 = reconstruct_switch_expressions(&mut methods);
        assert_eq!(n, 0);
    }
}
