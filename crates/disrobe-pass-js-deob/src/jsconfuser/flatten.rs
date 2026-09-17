use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, find_paren_close, scan_balanced_brace, skip_whitespace};

#[derive(Debug, Clone, Serialize)]
pub struct FlattenReversalResult {
    pub dispatches_collapsed: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_flatten(source: &str) -> FlattenReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"(?ms)while\s*\(\s*(!\!\[\]|true|1)\s*\)\s*\{\s*switch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{",
    ) else {
        return passthrough(source);
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(state_var): Option<&str> = caps.get(2).map(|m: regex::Match<'_>| m.as_str())
        else {
            continue;
        };
        let switch_open: usize = whole.end() - 1;
        let Some(switch_close): Option<usize> = scan_balanced_brace(source, switch_open + 1) else {
            continue;
        };
        let outer_after: usize = skip_whitespace(bytes, switch_close + 1);
        if outer_after >= bytes.len() || bytes[outer_after] != b'}' {
            continue;
        }
        let switch_body: &str = &source[switch_open + 1..switch_close];
        let cases: BTreeMap<i64, String> = parse_switch_cases(switch_body);
        if cases.is_empty() {
            continue;
        }
        let Some(initial_state): Option<i64> =
            extract_initial_state(source, state_var, whole.start())
        else {
            continue;
        };
        let Some(sequence): Option<Vec<String>> = unroll_sequence(&cases, state_var, initial_state)
        else {
            continue;
        };
        let replacement: String = sequence.join("\n");
        let Some(decl_range): Option<Range<usize>> =
            locate_state_decl(source, state_var, whole.start())
        else {
            continue;
        };
        edits.push((decl_range, Some(String::new())));
        edits.push((whole.start()..outer_after + 1, Some(replacement)));
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let dispatches: usize = edits
        .iter()
        .filter(|(_, repl): &&(Range<usize>, Option<String>)| {
            repl.as_ref().is_some_and(|s: &String| !s.is_empty())
        })
        .count();
    let (rewritten, _): (String, usize) = apply_splice_edits(source, &mut edits);
    FlattenReversalResult {
        dispatches_collapsed: dispatches,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> FlattenReversalResult {
    FlattenReversalResult {
        dispatches_collapsed: 0,
        rewritten_source: source.to_owned(),
    }
}

fn parse_switch_cases(body: &str) -> BTreeMap<i64, String> {
    let mut out: BTreeMap<i64, String> = BTreeMap::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"(?ms)case\s+(-?\d+)\s*:") else {
        return out;
    };
    let matches: Vec<regex::Match<'_>> = re.find_iter(body).collect();
    if matches.is_empty() {
        return out;
    }
    for (idx, mat) in matches.iter().enumerate() {
        let Some(key_match): Option<regex::Captures<'_>> =
            re.captures(&body[mat.start()..mat.end()])
        else {
            continue;
        };
        let Some(key_str): Option<&str> = key_match.get(1).map(|m: regex::Match<'_>| m.as_str())
        else {
            continue;
        };
        let Ok(key): Result<i64, std::num::ParseIntError> = key_str.parse() else {
            continue;
        };
        let body_start: usize = mat.end();
        let body_end: usize = matches
            .get(idx + 1)
            .map_or(body.len(), |m: &regex::Match<'_>| m.start());
        let case_body: &str = body[body_start..body_end].trim();
        out.insert(key, case_body.to_owned());
    }
    out
}

fn extract_initial_state(source: &str, state_var: &str, before: usize) -> Option<i64> {
    let head: &str = source.get(..before)?;
    let pattern: String = format!(
        r"(?:var|let|const)\s+{}\s*=\s*(-?\d+)\s*[;,]",
        regex::escape(state_var)
    );
    let re: Regex = Regex::new(&pattern).ok()?;
    let last: regex::Captures<'_> = re.captures_iter(head).last()?;
    last.get(1)?.as_str().parse().ok()
}

fn locate_state_decl(source: &str, state_var: &str, before: usize) -> Option<Range<usize>> {
    let head: &str = source.get(..before)?;
    let pattern: String = format!(
        r"(?:var|let|const)\s+{}\s*=\s*-?\d+\s*;",
        regex::escape(state_var)
    );
    let re: Regex = Regex::new(&pattern).ok()?;
    let mat: regex::Match<'_> = re.find_iter(head).last()?;
    Some(mat.start()..mat.end())
}

fn unroll_sequence(
    cases: &BTreeMap<i64, String>,
    state_var: &str,
    initial: i64,
) -> Option<Vec<String>> {
    let assign_re: Regex = Regex::new(&format!(
        r"{}\s*=\s*(-?\d+)\s*;?\s*(?:break\s*;?\s*)?\s*$",
        regex::escape(state_var)
    ))
    .ok()?;
    let mut current: i64 = initial;
    let mut visited: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    while !visited.contains(&current) {
        visited.insert(current);
        let Some(case_body): Option<&String> = cases.get(&current) else {
            return Some(out);
        };
        let assign_cap: Option<regex::Captures<'_>> = assign_re.captures(case_body);
        let (action, next_state): (String, Option<i64>) = if let Some(cap) = assign_cap {
            let action_text: String = case_body
                [..cap.get(0).map_or(0, |m: regex::Match<'_>| m.start())]
                .trim()
                .trim_end_matches(';')
                .to_owned();
            let next: i64 = cap.get(1)?.as_str().parse().ok()?;
            (action_text, Some(next))
        } else {
            let cleaned: String = case_body
                .trim()
                .trim_end_matches("break;")
                .trim()
                .trim_end_matches("return")
                .trim_end_matches(';')
                .to_owned();
            (cleaned, None)
        };
        if !action.is_empty() {
            out.push(format!("{action};"));
        }
        match next_state {
            Some(n) if n != current => current = n,
            _ => break,
        }
    }
    Some(out)
}

#[allow(dead_code)]
fn try_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_paren_close(bytes, start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_three_state_switch_dispatcher() {
        let src: &str = "var _s = 0;\nwhile (!![]) { switch (_s) { case 0: console.log('a'); _s = 1; break; case 1: console.log('b'); _s = 2; break; case 2: console.log('c'); return; } }";
        let r: FlattenReversalResult = reverse_flatten(src);
        assert_eq!(r.dispatches_collapsed, 1);
        let pos_a: Option<usize> = r.rewritten_source.find("console.log('a')");
        let pos_b: Option<usize> = r.rewritten_source.find("console.log('b')");
        let pos_c: Option<usize> = r.rewritten_source.find("console.log('c')");
        assert!(pos_a.is_some() && pos_b.is_some() && pos_c.is_some());
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn leaves_normal_switch_alone() {
        let src: &str = "switch (x) { case 0: doA(); break; case 1: doB(); break; }";
        let r: FlattenReversalResult = reverse_flatten(src);
        assert_eq!(r.dispatches_collapsed, 0);
        assert_eq!(r.rewritten_source, src);
    }
}
