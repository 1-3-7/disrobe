use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, scan_balanced_brace, skip_whitespace};

#[derive(Debug, Clone, Serialize)]
pub struct StateSumReversalResult {
    pub machines_linearized: usize,
    pub blocks_recovered: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_state_sum(source: &str) -> StateSumReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut machines: usize = 0;
    let mut blocks: usize = 0;
    for machine in find_state_sum_machines(source) {
        let Some(linear): Option<Linearized> = linearize(source, &machine) else {
            continue;
        };
        blocks += linear.block_count;
        machines += 1;
        edits.push((machine.loop_range, Some(linear.body)));
    }
    if edits.is_empty() {
        return StateSumReversalResult {
            machines_linearized: 0,
            blocks_recovered: 0,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, _): (String, usize) = apply_splice_edits(source, &mut edits);
    StateSumReversalResult {
        machines_linearized: machines,
        blocks_recovered: blocks,
        rewritten_source: rewritten,
    }
}

#[derive(Debug, Clone)]
struct StateSumMachine {
    state_vars: Vec<String>,
    terminal: i64,
    initial: BTreeMap<String, i64>,
    switch_body: String,
    loop_range: Range<usize>,
}

#[derive(Debug, Clone)]
struct Linearized {
    body: String,
    block_count: usize,
}

#[derive(Debug, Clone)]
struct CaseArm {
    label: LabelExpr,
    action: String,
    transitions: Vec<(String, i64)>,
    terminates: bool,
}

#[derive(Debug, Clone)]
enum LabelExpr {
    Literal(i64),
    VarOffset { var: String, offset: i64 },
}

fn find_state_sum_machines(source: &str) -> Vec<StateSumMachine> {
    let Ok(while_re): Result<Regex, regex::Error> = Regex::new(
        r"(?ms)while\s*\(\s*([A-Za-z_$][\w$]*(?:\s*\+\s*[A-Za-z_$][\w$]*)+)\s*(!==|!=|===|==)\s*(-?\d+)\s*\)\s*\{",
    ) else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let mut out: Vec<StateSumMachine> = Vec::new();
    for caps in while_re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(sum_text): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(terminal): Option<i64> = caps
            .get(3)
            .and_then(|m: regex::Match<'_>| m.as_str().parse::<i64>().ok())
        else {
            continue;
        };
        let state_vars: Vec<String> = parse_sum_vars(sum_text);
        if state_vars.len() < 2 {
            continue;
        }
        let loop_open: usize = whole.end() - 1;
        let Some(loop_close): Option<usize> = scan_balanced_brace(source, loop_open + 1) else {
            continue;
        };
        let Some(switch_body): Option<String> =
            extract_switch(source, loop_open + 1, loop_close, &state_vars)
        else {
            continue;
        };
        let Some(initial): Option<BTreeMap<String, i64>> =
            collect_initial_state(source, &state_vars, whole.start())
        else {
            continue;
        };
        if initial.len() != state_vars.len() {
            continue;
        }
        let stmt_end: usize = consume_loop_tail(bytes, loop_close + 1);
        out.push(StateSumMachine {
            state_vars,
            terminal,
            initial,
            switch_body,
            loop_range: whole.start()..stmt_end,
        });
    }
    out
}

fn consume_loop_tail(bytes: &[u8], after_brace: usize) -> usize {
    let mut i: usize = skip_whitespace(bytes, after_brace);
    if i < bytes.len() && bytes[i] == b';' {
        i += 1;
    }
    i
}

fn parse_sum_vars(text: &str) -> Vec<String> {
    text.split('+')
        .map(|p: &str| p.trim().to_owned())
        .filter(|p: &String| !p.is_empty())
        .collect()
}

fn extract_switch(
    source: &str,
    loop_inner_start: usize,
    loop_close: usize,
    state_vars: &[String],
) -> Option<String> {
    let region: &str = source.get(loop_inner_start..loop_close)?;
    let sum_alt: String = state_vars
        .iter()
        .map(|v: &String| regex::escape(v))
        .collect::<Vec<String>>()
        .join(r"\s*\+\s*");
    let switch_re: Regex = Regex::new(&format!(r"(?ms)switch\s*\(\s*{sum_alt}\s*\)\s*\{{")).ok()?;
    let mat: regex::Match<'_> = switch_re.find(region)?;
    let switch_open_abs: usize = loop_inner_start + mat.end() - 1;
    let switch_close_abs: usize = scan_balanced_brace(source, switch_open_abs + 1)?;
    let body: String = source
        .get(switch_open_abs + 1..switch_close_abs)?
        .to_owned();
    Some(body)
}

fn collect_initial_state(
    source: &str,
    state_vars: &[String],
    before: usize,
) -> Option<BTreeMap<String, i64>> {
    let head: &str = source.get(..before)?;
    let mut initial: BTreeMap<String, i64> = BTreeMap::new();
    for var in state_vars {
        let pattern: String = format!(
            r"(?:(?:var|let|const)\s+|,\s*){}\s*=\s*(-?\d+)\s*[;,]",
            regex::escape(var)
        );
        let re: Regex = Regex::new(&pattern).ok()?;
        let cap: regex::Captures<'_> = re.captures_iter(head).last()?;
        let value: i64 = cap.get(1)?.as_str().parse::<i64>().ok()?;
        initial.insert(var.clone(), value);
    }
    Some(initial)
}

fn parse_case_arms(body: &str, state_vars: &[String]) -> Vec<CaseArm> {
    let case_re: Regex = match Regex::new(r"(?ms)case\s+([^:]+?)\s*:") {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    let markers: Vec<(usize, usize, String)> = case_re
        .captures_iter(body)
        .filter_map(|cap: regex::Captures<'_>| {
            let whole: regex::Match<'_> = cap.get(0)?;
            let label: regex::Match<'_> = cap.get(1)?;
            Some((whole.start(), whole.end(), label.as_str().trim().to_owned()))
        })
        .collect();
    let mut arms: Vec<CaseArm> = Vec::new();
    for (idx, (_start, body_start, label_text)) in markers.iter().enumerate() {
        let body_end: usize = markers
            .get(idx + 1)
            .map_or(body.len(), |m: &(usize, usize, String)| m.0);
        let Some(label): Option<LabelExpr> = parse_label(label_text, state_vars) else {
            continue;
        };
        let segment: &str = &body[*body_start..body_end];
        let (action, transitions, terminates): (String, Vec<(String, i64)>, bool) =
            split_case_segment(segment, state_vars);
        arms.push(CaseArm {
            label,
            action,
            transitions,
            terminates,
        });
    }
    arms
}

fn parse_label(text: &str, state_vars: &[String]) -> Option<LabelExpr> {
    let trimmed: &str = text.trim();
    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(LabelExpr::Literal(value));
    }
    let offset_re: Regex = Regex::new(r"^([A-Za-z_$][\w$]*)\s*([+\-])\s*(-?\d+)$").ok()?;
    let cap: regex::Captures<'_> = offset_re.captures(trimmed)?;
    let var: String = cap.get(1)?.as_str().to_owned();
    if !state_vars.iter().any(|v: &String| v == &var) {
        return None;
    }
    let sign: i64 = if cap.get(2)?.as_str() == "-" { -1 } else { 1 };
    let magnitude: i64 = cap.get(3)?.as_str().parse::<i64>().ok()?;
    Some(LabelExpr::VarOffset {
        var,
        offset: sign * magnitude,
    })
}

fn split_case_segment(segment: &str, state_vars: &[String]) -> (String, Vec<(String, i64)>, bool) {
    let statements: Vec<String> = split_top_level_statements(segment);
    let mut action_parts: Vec<String> = Vec::new();
    let mut transitions: Vec<(String, i64)> = Vec::new();
    let mut terminates: bool = false;
    for stmt in statements {
        let trimmed: &str = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "break" {
            continue;
        }
        if trimmed == "return" || trimmed.starts_with("return ") || trimmed.starts_with("return(") {
            action_parts.push(format!("{trimmed};"));
            terminates = true;
            continue;
        }
        if let Some((var, delta)) = parse_compound_add(trimmed, state_vars) {
            transitions.push((var, delta));
            continue;
        }
        action_parts.push(format!("{trimmed};"));
    }
    (action_parts.join("\n"), transitions, terminates)
}

fn parse_compound_add(stmt: &str, state_vars: &[String]) -> Option<(String, i64)> {
    let re: Regex = Regex::new(r"^([A-Za-z_$][\w$]*)\s*\+=\s*(.+)$").ok()?;
    let cap: regex::Captures<'_> = re.captures(stmt.trim())?;
    let var: String = cap.get(1)?.as_str().to_owned();
    if !state_vars.iter().any(|v: &String| v == &var) {
        return None;
    }
    let rhs: &str = cap.get(2)?.as_str().trim();
    let delta: i64 = eval_const_int(rhs)?;
    Some((var, delta))
}

fn eval_const_int(expr: &str) -> Option<i64> {
    let trimmed: &str = expr.trim();
    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(value);
    }
    let binop_re: Regex = Regex::new(r"^(-?\d+)\s*([+\-])\s*(-?\d+)$").ok()?;
    let cap: regex::Captures<'_> = binop_re.captures(trimmed)?;
    let lhs: i64 = cap.get(1)?.as_str().parse::<i64>().ok()?;
    let rhs: i64 = cap.get(3)?.as_str().parse::<i64>().ok()?;
    match cap.get(2)?.as_str() {
        "+" => Some(lhs + rhs),
        "-" => Some(lhs - rhs),
        _ => None,
    }
}

fn split_top_level_statements(segment: &str) -> Vec<String> {
    let bytes: &[u8] = segment.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let Some(after): Option<usize> = super::scanner::skip_string_literal(bytes, i, b)
                else {
                    break;
                };
                i = after;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b';' | b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(segment[start..i].to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < segment.len() {
        out.push(segment[start..].to_owned());
    }
    out
}

fn linearize(source: &str, machine: &StateSumMachine) -> Option<Linearized> {
    let _ = source;
    let arms: Vec<CaseArm> = parse_case_arms(&machine.switch_body, &machine.state_vars);
    if arms.is_empty() {
        return None;
    }
    let mut state: BTreeMap<String, i64> = machine.initial.clone();
    let mut body_parts: Vec<String> = Vec::new();
    let mut visited: BTreeSet<i64> = BTreeSet::new();
    let mut block_count: usize = 0;
    let max_steps: usize = arms.len().saturating_mul(4).max(16);
    for _ in 0..max_steps {
        let sum: i64 = state.values().sum();
        if sum == machine.terminal {
            break;
        }
        if !visited.insert(sum) {
            return None;
        }
        let arm: &CaseArm = select_arm(&arms, &state, sum)?;
        if !arm.action.is_empty() {
            body_parts.push(arm.action.clone());
        }
        block_count += 1;
        if arm.terminates {
            break;
        }
        if arm.transitions.is_empty() {
            return None;
        }
        for (var, delta) in &arm.transitions {
            let entry: &mut i64 = state.get_mut(var)?;
            *entry += *delta;
        }
    }
    if block_count == 0 {
        return None;
    }
    Some(Linearized {
        body: body_parts.join("\n"),
        block_count,
    })
}

fn select_arm<'a>(
    arms: &'a [CaseArm],
    state: &BTreeMap<String, i64>,
    sum: i64,
) -> Option<&'a CaseArm> {
    arms.iter().find(|arm: &&CaseArm| match &arm.label {
        LabelExpr::Literal(value) => *value == sum,
        LabelExpr::VarOffset { var, offset } => state
            .get(var)
            .is_some_and(|base: &i64| *base + *offset == sum),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn linearizes_three_var_literal_state_sum() {
        let src: &str = "var s0 = 1; var s1 = 2; var s2 = 0;\nwhile (s0 + s1 + s2 !== 99) {\nswitch (s0 + s1 + s2) {\ncase 3: a(); s0 += 2, s1 += 1, s2 += 0; break;\ncase 6: b(); s0 += 1, s1 += 2, s2 += 0; break;\ncase 9: c(); return; }\n}";
        let r: StateSumReversalResult = reverse_state_sum(src);
        assert_eq!(r.machines_linearized, 1);
        assert_eq!(r.blocks_recovered, 3);
        let out: &str = &r.rewritten_source;
        let pa: Option<usize> = out.find("a()");
        let pb: Option<usize> = out.find("b()");
        let pc: Option<usize> = out.find("c()");
        assert!(pa.is_some() && pb.is_some() && pc.is_some());
        assert!(pa < pb);
        assert!(pb < pc);
        assert!(!out.contains("switch"));
    }

    #[test]
    fn resolves_var_offset_case_labels() {
        let src: &str = "var p = 100; var q = 5;\nwhile (p + q !== 999) {\nswitch (p + q) {\ncase p + 5: first(); p += 40, q += 50; break;\ncase q - -140: second(); return; }\n}";
        let r: StateSumReversalResult = reverse_state_sum(src);
        assert_eq!(r.machines_linearized, 1);
        let out: &str = &r.rewritten_source;
        assert!(out.find("first()") < out.find("second()"));
    }

    #[test]
    fn leaves_single_var_switch_alone() {
        let src: &str = "var s = 0;\nwhile (s !== 2) { switch (s) { case 0: a(); s = 1; break; } }";
        let r: StateSumReversalResult = reverse_state_sum(src);
        assert_eq!(r.machines_linearized, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn bails_on_unresolvable_successor() {
        let src: &str = "var s0 = 1; var s1 = 2;\nwhile (s0 + s1 !== 99) {\nswitch (s0 + s1) {\ncase 3: a(); s0 += external(); break; } }";
        let r: StateSumReversalResult = reverse_state_sum(src);
        assert_eq!(r.machines_linearized, 0);
    }
}
