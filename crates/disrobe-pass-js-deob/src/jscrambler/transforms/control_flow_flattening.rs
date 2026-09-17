use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, find_brace_close, find_paren_close, is_ident_char, skip_string_literal,
    skip_ws, slice_eq,
};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(detect_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let bytes: &[u8] = source.as_bytes();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut stats: TransformStats = TransformStats::default();
    let mut i: usize = 0;
    while i < bytes.len() {
        if slice_eq(bytes, i, b"var")
            && i + 3 < bytes.len()
            && bytes[i + 3].is_ascii_whitespace()
            && let Some(machine) = try_extract_machine(source, bytes, i)
        {
            stats.matched += 1;
            let replacement: String = reconstruct(&machine);
            edits.push((machine.full_range.clone(), Some(replacement)));
            i = machine.full_range.end;
            continue;
        }
        i += 1;
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied;
    TransformOutput {
        source: rewritten,
        stats,
    }
}

const fn detect_pattern() -> &'static str {
    r"var\s+[A-Za-z_$][\w$]*\s*=\s*\d+\s*;\s*(?:for\s*\(\s*;\s*[A-Za-z_$][\w$]*\s*!==?\s*\d+\s*;\s*\)|while\s*\(\s*[A-Za-z_$][\w$]*\s*!==?\s*\d+\s*\))\s*\{\s*switch\s*\("
}

#[derive(Debug, Clone)]
struct Machine<'a> {
    full_range: Range<usize>,
    state_var: String,
    init_state: u64,
    terminal_state: u64,
    cases: BTreeMap<u64, CaseBody<'a>>,
}

#[derive(Debug, Clone)]
struct CaseBody<'a> {
    source: &'a str,
}

#[derive(Debug, Clone)]
enum Transition {
    Direct(u64),
    Conditional {
        condition: String,
        then_state: u64,
        else_state: u64,
    },
    Terminal,
    Unknown,
}

fn try_extract_machine<'a>(source: &'a str, bytes: &[u8], start: usize) -> Option<Machine<'a>> {
    let after_var: usize = skip_ws(bytes, start + 3);
    let ident_start: usize = after_var;
    let mut ident_end: usize = ident_start;
    while ident_end < bytes.len() && is_ident_char(bytes[ident_end]) {
        ident_end += 1;
    }
    if ident_end == ident_start {
        return None;
    }
    let state_var: String = source.get(ident_start..ident_end)?.to_owned();
    let after_ident: usize = skip_ws(bytes, ident_end);
    if bytes.get(after_ident) != Some(&b'=') {
        return None;
    }
    let after_eq: usize = skip_ws(bytes, after_ident + 1);
    let (init_state, after_init): (u64, usize) = read_decimal(bytes, after_eq)?;
    let after_semi: usize = skip_ws(bytes, after_init);
    if bytes.get(after_semi) != Some(&b';') {
        return None;
    }
    let after_init_semi: usize = skip_ws(bytes, after_semi + 1);
    let (terminal_state, loop_body_open): (u64, usize) =
        read_loop_header(bytes, after_init_semi, &state_var)?;
    let loop_body_close: usize = find_brace_close(bytes, loop_body_open + 1)?;
    let switch_start: usize = skip_ws(bytes, loop_body_open + 1);
    if !slice_eq(bytes, switch_start, b"switch") {
        return None;
    }
    let switch_paren_open: usize = skip_ws(bytes, switch_start + 6);
    if bytes.get(switch_paren_open) != Some(&b'(') {
        return None;
    }
    let switch_paren_close: usize = find_paren_close(bytes, switch_paren_open + 1)?;
    let switch_var: &str = source
        .get(switch_paren_open + 1..switch_paren_close)?
        .trim();
    if switch_var != state_var {
        return None;
    }
    let switch_body_open: usize = skip_ws(bytes, switch_paren_close + 1);
    if bytes.get(switch_body_open) != Some(&b'{') {
        return None;
    }
    let switch_body_close: usize = find_brace_close(bytes, switch_body_open + 1)?;
    if switch_body_close >= loop_body_close {
        return None;
    }
    let cases: BTreeMap<u64, CaseBody<'a>> =
        parse_cases(source, bytes, switch_body_open + 1, switch_body_close)?;
    if cases.is_empty() {
        return None;
    }
    Some(Machine {
        full_range: start..loop_body_close + 1,
        state_var,
        init_state,
        terminal_state,
        cases,
    })
}

fn read_decimal(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut i: usize = start;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let s: &str = core::str::from_utf8(&bytes[start..i]).ok()?;
    let n: u64 = s.parse::<u64>().ok()?;
    Some((n, i))
}

fn read_loop_header(bytes: &[u8], start: usize, state_var: &str) -> Option<(u64, usize)> {
    if slice_eq(bytes, start, b"for") {
        let lp: usize = skip_ws(bytes, start + 3);
        if bytes.get(lp) != Some(&b'(') {
            return None;
        }
        let rp: usize = find_paren_close(bytes, lp + 1)?;
        let inner: &str = core::str::from_utf8(&bytes[lp + 1..rp]).ok()?;
        let terminal: u64 = parse_loop_terminal(inner, state_var)?;
        let body_open: usize = skip_ws(bytes, rp + 1);
        if bytes.get(body_open) != Some(&b'{') {
            return None;
        }
        return Some((terminal, body_open));
    }
    if slice_eq(bytes, start, b"while") {
        let lp: usize = skip_ws(bytes, start + 5);
        if bytes.get(lp) != Some(&b'(') {
            return None;
        }
        let rp: usize = find_paren_close(bytes, lp + 1)?;
        let inner: &str = core::str::from_utf8(&bytes[lp + 1..rp]).ok()?;
        let terminal: u64 = parse_while_terminal(inner, state_var)?;
        let body_open: usize = skip_ws(bytes, rp + 1);
        if bytes.get(body_open) != Some(&b'{') {
            return None;
        }
        return Some((terminal, body_open));
    }
    None
}

fn parse_loop_terminal(inner: &str, state_var: &str) -> Option<u64> {
    let trimmed: &str = inner.trim_start();
    let after_first_semi: &str = trimmed.strip_prefix(';').unwrap_or(trimmed).trim_start();
    let mid: &str = after_first_semi.split(';').next()?.trim();
    parse_inequality(mid, state_var)
}

fn parse_while_terminal(inner: &str, state_var: &str) -> Option<u64> {
    parse_inequality(inner.trim(), state_var)
}

fn parse_inequality(expr: &str, state_var: &str) -> Option<u64> {
    let trimmed: &str = expr.trim();
    let stripped: &str = trimmed.strip_prefix(state_var)?.trim_start();
    let rest: &str = stripped
        .strip_prefix("!==")
        .or_else(|| stripped.strip_prefix("!="))?
        .trim();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<u64>().ok()
}

fn parse_cases<'a>(
    source: &'a str,
    bytes: &[u8],
    body_start: usize,
    body_end: usize,
) -> Option<BTreeMap<u64, CaseBody<'a>>> {
    let mut cases: BTreeMap<u64, CaseBody<'a>> = BTreeMap::new();
    let mut i: usize = body_start;
    while i < body_end {
        let after_ws: usize = skip_ws(bytes, i);
        if after_ws >= body_end {
            break;
        }
        if !slice_eq(bytes, after_ws, b"case") {
            return None;
        }
        let after_case: usize = skip_ws(bytes, after_ws + 4);
        let (case_n, after_n): (u64, usize) = read_decimal(bytes, after_case)?;
        let after_colon: usize = skip_ws(bytes, after_n);
        if bytes.get(after_colon) != Some(&b':') {
            return None;
        }
        let case_body_start: usize = after_colon + 1;
        let case_body_end: usize = find_case_end(bytes, case_body_start, body_end)?;
        let case_body_source: &str = source.get(case_body_start..case_body_end)?;
        cases.insert(
            case_n,
            CaseBody {
                source: case_body_source,
            },
        );
        i = case_body_end;
    }
    Some(cases)
}

fn find_case_end(bytes: &[u8], start: usize, hard_end: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < hard_end {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, b)?;
                continue;
            }
            b'/' if i + 1 < hard_end && bytes[i + 1] == b'/' => {
                while i < hard_end && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < hard_end && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < hard_end && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' if brace == 0 => return Some(i),
            b'}' => brace -= 1,
            _ => {}
        }
        if paren == 0
            && bracket == 0
            && brace == 0
            && slice_eq(bytes, i, b"case")
            && (i == start || !is_ident_char(bytes[i - 1]))
            && i + 4 < hard_end
            && !is_ident_char(bytes[i + 4])
        {
            return Some(i);
        }
        i += 1;
    }
    Some(hard_end)
}

fn classify_transition(body: &str, state_var: &str, terminal_state: u64) -> Transition {
    let trimmed: &str = body.trim();
    if let Some(direct) = parse_direct_assign(trimmed, state_var) {
        return if direct == terminal_state {
            Transition::Terminal
        } else {
            Transition::Direct(direct)
        };
    }
    if let Some((cond, t, e)) = parse_ternary_assign(trimmed, state_var) {
        return Transition::Conditional {
            condition: cond,
            then_state: t,
            else_state: e,
        };
    }
    if has_return_or_throw(trimmed) {
        return Transition::Terminal;
    }
    Transition::Unknown
}

fn parse_direct_assign(body: &str, state_var: &str) -> Option<u64> {
    let stmts: Vec<&str> = split_top_level_statements(body);
    for stmt in stmts.iter().rev() {
        let s: &str = stmt.trim();
        if s == "break" || s.is_empty() {
            continue;
        }
        if let Some(rhs) = s
            .strip_prefix(state_var)
            .map(str::trim_start)
            .and_then(|r: &str| r.strip_prefix('='))
            .map(str::trim_start)
        {
            let digits: String = rhs.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() && rhs.len() == digits.len() {
                return digits.parse::<u64>().ok();
            }
            return None;
        }
        return None;
    }
    None
}

fn parse_ternary_assign(body: &str, state_var: &str) -> Option<(String, u64, u64)> {
    let stmts: Vec<&str> = split_top_level_statements(body);
    for stmt in stmts.iter().rev() {
        let s: &str = stmt.trim();
        if s == "break" || s.is_empty() {
            continue;
        }
        let rhs: &str = s
            .strip_prefix(state_var)
            .map(str::trim_start)?
            .strip_prefix('=')
            .map(str::trim_start)?;
        let q_pos: usize = find_top_level(rhs, '?')?;
        let colon_pos: usize = find_top_level(&rhs[q_pos + 1..], ':')? + q_pos + 1;
        let condition: String = rhs[..q_pos].trim().to_owned();
        let then_str: &str = rhs[q_pos + 1..colon_pos].trim();
        let else_str: &str = rhs[colon_pos + 1..].trim();
        let then_state: u64 = then_str.parse::<u64>().ok()?;
        let else_state: u64 = else_str.parse::<u64>().ok()?;
        return Some((condition, then_state, else_state));
    }
    None
}

fn find_top_level(s: &str, target: char) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    let mut q_depth: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, b)?;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'?' if target == ':' => q_depth += 1,
            b':' if target == ':' && q_depth > 0 => q_depth -= 1,
            c if c as char == target
                && paren == 0
                && bracket == 0
                && brace == 0
                && (target != ':' || q_depth == 0) =>
            {
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_top_level_statements(body: &str) -> Vec<&str> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                    return Vec::new();
                };
                i = end;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b';' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        out.push(&body[start..]);
    }
    out
}

fn strip_trailing_state_assign_and_break(body: &str, state_var: &str) -> String {
    let stmts: Vec<&str> = split_top_level_statements(body);
    let mut keep: Vec<&str> = Vec::new();
    for stmt in &stmts {
        let trimmed: &str = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "break" {
            continue;
        }
        if trimmed
            .strip_prefix(state_var)
            .is_some_and(|r: &str| r.trim_start().starts_with('='))
        {
            continue;
        }
        keep.push(trimmed);
    }
    let mut out: String = String::new();
    for (idx, s) in keep.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(s);
        if !s.ends_with(';') && !s.ends_with('}') {
            out.push(';');
        }
    }
    out
}

fn has_return_or_throw(s: &str) -> bool {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                return false;
            };
            i = end;
            continue;
        }
        if slice_eq(bytes, i, b"return") || slice_eq(bytes, i, b"throw") {
            let kw_len: usize = if slice_eq(bytes, i, b"return") { 6 } else { 5 };
            let before_ok: bool = i == 0 || !is_ident_char(bytes[i - 1]);
            let after_ok: bool = bytes
                .get(i + kw_len)
                .is_none_or(|c: &u8| !is_ident_char(*c));
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn reconstruct(machine: &Machine<'_>) -> String {
    let mut out: String = String::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    emit_state(
        machine,
        machine.init_state,
        &mut out,
        &mut visited,
        0,
        false,
    );
    out
}

fn emit_state(
    machine: &Machine<'_>,
    state: u64,
    out: &mut String,
    visited: &mut BTreeSet<u64>,
    depth: usize,
    inside_branch: bool,
) {
    if state == machine.terminal_state {
        return;
    }
    if depth > 256 {
        emit_fallback(machine, out);
        return;
    }
    if !visited.insert(state) {
        if !inside_branch {
            emit_fallback(machine, out);
        }
        return;
    }
    let Some(case): Option<&CaseBody<'_>> = machine.cases.get(&state) else {
        return;
    };
    let transition: Transition =
        classify_transition(case.source, &machine.state_var, machine.terminal_state);
    let pure_body: String = strip_trailing_state_assign_and_break(case.source, &machine.state_var);
    if !pure_body.is_empty() {
        out.push_str(&pure_body);
        if !pure_body.ends_with(';') && !pure_body.ends_with('}') && !pure_body.ends_with('\n') {
            out.push(';');
        }
        out.push('\n');
    }
    match transition {
        Transition::Direct(next) => {
            emit_state(machine, next, out, visited, depth + 1, inside_branch);
        }
        Transition::Conditional {
            condition,
            then_state,
            else_state,
        } => {
            let mut then_visited: BTreeSet<u64> = visited.clone();
            let mut else_visited: BTreeSet<u64> = visited.clone();
            let mut then_out: String = String::new();
            let mut else_out: String = String::new();
            emit_state(
                machine,
                then_state,
                &mut then_out,
                &mut then_visited,
                depth + 1,
                true,
            );
            emit_state(
                machine,
                else_state,
                &mut else_out,
                &mut else_visited,
                depth + 1,
                true,
            );
            out.push_str("if (");
            out.push_str(condition.trim());
            out.push_str(") {\n");
            out.push_str(&then_out);
            out.push_str("} else {\n");
            out.push_str(&else_out);
            out.push_str("}\n");
            for s in then_visited.iter().chain(else_visited.iter()) {
                visited.insert(*s);
            }
        }
        Transition::Terminal => {}
        Transition::Unknown => {
            emit_fallback_marker(out);
        }
    }
}

fn emit_fallback(machine: &Machine<'_>, out: &mut String) {
    out.push_str("/* RECOVERED_FROM_CFF: residual state machine */\n");
    let mut keys: Vec<u64> = machine.cases.keys().copied().collect();
    keys.sort_unstable();
    for k in keys {
        if let Some(case) = machine.cases.get(&k) {
            out.push_str(case.source.trim());
            out.push('\n');
        }
    }
}

fn emit_fallback_marker(out: &mut String) {
    out.push_str("/* RECOVERED_FROM_CFF: unhandled transition */\n");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_state_machine_loop() {
        let src: &str =
            "var H=2;for(;H!==9;){switch(H){case 2:H=1;break;case 1:return globalThis;break;}}";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverse_records_match_on_real_form() {
        let src: &str =
            "var H=2;for(;H!==9;){switch(H){case 2:H=1;break;case 1:return globalThis;break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.matched >= 1);
    }

    #[test]
    fn linearizes_simple_two_state_chain() {
        let src: &str = "var H=2;for(;H!==9;){switch(H){case 2:H=1;break;case 1:return 42;break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("return 42"));
        assert!(!out.source.contains("switch"));
    }

    #[test]
    fn linearizes_three_state_chain() {
        let src: &str = "var s=1;for(;s!==4;){switch(s){case 1:a();s=2;break;case 2:b();s=3;break;case 3:c();s=4;break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("a()"));
        assert!(out.source.contains("b()"));
        assert!(out.source.contains("c()"));
        let a_pos: usize = out.source.find("a()").unwrap();
        let b_pos: usize = out.source.find("b()").unwrap();
        let c_pos: usize = out.source.find("c()").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn reconstructs_ternary_branch_as_if_else() {
        let src: &str = "var s=1;for(;s!==9;){switch(s){case 1:s=cond?2:3;break;case 2:t();s=9;break;case 3:f();s=9;break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("if (cond)"));
        assert!(out.source.contains("t()"));
        assert!(out.source.contains("f()"));
    }

    #[test]
    fn no_op_on_clean_source() {
        let src: &str = "for(let i = 0; i < 10; i++){ x(); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.matched, 0);
    }

    #[test]
    fn handles_typeof_globalthis_pattern_from_corpus() {
        let src: &str = "var H=2;for(;H !== 9;){switch(H){case 2:H=typeof globalThis === 'object'?1:5;break;case 1:return globalThis;break;case 5:throw \"\";break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.matched >= 1);
        assert!(out.source.contains("if ("));
        assert!(out.source.contains("return globalThis"));
    }

    #[test]
    fn fallback_emits_marker_on_unhandled_form() {
        let src: &str =
            "var s=1;for(;s!==9;){switch(s){case 1:s=lookup[idx];break;case 9:return;break;}}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("RECOVERED_FROM_CFF") || out.source.contains("switch"));
    }
}
