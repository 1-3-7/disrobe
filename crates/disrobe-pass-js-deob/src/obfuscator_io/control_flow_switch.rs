use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use crate::scan_utils::{find_brace_close, literal_and_comment_ranges, skip_string, span_is_code};

#[derive(Debug, Clone, Serialize)]
pub(super) struct ControlFlowSwitchResult {
    pub switches_unflattened: usize,
    pub rewritten_source: String,
}

#[must_use]
pub(super) fn unflatten_control_flow_switch(source: &str) -> ControlFlowSwitchResult {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"])([0-9]+(?:\|[0-9]+)*)['"]\s*\[\s*['"]split['"]\s*\]\s*\(\s*(['"])\|['"]\s*\)\s*[;,]"#,
    ) else {
        return passthrough(source);
    };
    let bytes: &[u8] = source.as_bytes();
    let skips: Vec<Range<usize>> = literal_and_comment_ranges(source);
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut count: usize = 0;

    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        if !span_is_code(&skips, whole.start(), whole.end()) {
            continue;
        }
        let Some(seq_name): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(seq_str): Option<&str> = caps.get(3).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let block_start: usize = whole.start();
        let Some((iter_name, switch_open, after_iter)): Option<(String, usize, usize)> =
            locate_switch(source, seq_name, whole.end())
        else {
            continue;
        };
        let _ = after_iter;
        let Some(switch_close): Option<usize> = find_brace_close(bytes, switch_open + 1) else {
            continue;
        };
        let switch_body: &str = &source[switch_open + 1..switch_close];
        let cases: BTreeMap<String, String> =
            parse_switch_cases(switch_body, switch_open + 1, &skips);
        if cases.is_empty() {
            continue;
        }
        let Some(loop_end): Option<usize> = locate_loop_end(source, switch_close) else {
            continue;
        };
        let mut ordered: Vec<String> = Vec::new();
        let mut ok: bool = true;
        for key in seq_str.split('|') {
            let Some(body): Option<&String> = cases.get(key) else {
                ok = false;
                break;
            };
            ordered.push(body.clone());
        }
        if !ok {
            continue;
        }
        let _ = iter_name;
        let replacement: String = ordered.join("\n");
        edits.push((block_start..loop_end, Some(replacement)));
        count += 1;
    }

    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, _): (String, usize) = apply_edits(source, &mut edits);
    ControlFlowSwitchResult {
        switches_unflattened: count,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> ControlFlowSwitchResult {
    ControlFlowSwitchResult {
        switches_unflattened: 0,
        rewritten_source: source.to_owned(),
    }
}

fn locate_switch(source: &str, seq_name: &str, after_seq: usize) -> Option<(String, usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let iter_re: Regex = Regex::new(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]+;").ok()?;
    let head: &str = source.get(after_seq..)?;
    let iter_cap: regex::Captures<'_> = iter_re.captures(head)?;
    let iter_name: String = iter_cap.get(1)?.as_str().to_owned();
    let iter_end: usize = after_seq + iter_cap.get(0)?.end();

    let switch_re: Regex = Regex::new(&format!(
        r"switch\s*\(\s*{}\s*\[\s*{}\s*\+\+\s*\]\s*\)\s*\{{",
        regex::escape(seq_name),
        regex::escape(&iter_name)
    ))
    .ok()?;
    let rest: &str = source.get(iter_end..)?;
    let sw: regex::Match<'_> = switch_re.find(rest)?;
    let switch_open_abs: usize = iter_end + sw.end() - 1;
    if bytes.get(switch_open_abs) != Some(&b'{') {
        return None;
    }
    Some((iter_name, switch_open_abs, iter_end))
}

fn parse_switch_cases(body: &str, base: usize, skips: &[Range<usize>]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r#"case\s*['"]([0-9]+)['"]\s*:"#) else {
        return out;
    };
    let matches: Vec<regex::Match<'_>> = re
        .find_iter(body)
        .filter(|found: &regex::Match<'_>| {
            span_is_code(skips, base + found.start(), base + found.end())
        })
        .collect();
    if matches.is_empty() {
        return out;
    }
    for (idx, mat) in matches.iter().enumerate() {
        let Some(cap): Option<regex::Captures<'_>> = re.captures(&body[mat.start()..mat.end()])
        else {
            continue;
        };
        let Some(key): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let body_start: usize = mat.end();
        let body_end: usize = matches
            .get(idx + 1)
            .map_or(body.len(), |m: &regex::Match<'_>| m.start());
        let case_body: String = strip_trailing_continue(body[body_start..body_end].trim());
        out.insert(key.to_owned(), case_body);
    }
    out
}

fn strip_trailing_continue(body: &str) -> String {
    let trimmed: &str = body.trim();
    let without: &str = trimmed
        .strip_suffix("continue;")
        .or_else(|| trimmed.strip_suffix("continue"))
        .unwrap_or(trimmed);
    without.trim_end().to_owned()
}

fn locate_loop_end(source: &str, switch_close: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = switch_close + 1;
    let mut depth: i32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                if depth == 0 {
                    return Some(i + 1);
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn apply_edits(source: &str, edits: &mut [(Range<usize>, Option<String>)]) -> (String, usize) {
    edits.sort_by_key(|e: &(Range<usize>, Option<String>)| e.0.start);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut applied: usize = 0;
    for (range, replacement) in edits.iter() {
        if range.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..range.start]);
        if let Some(s) = replacement {
            out.push_str(s);
            applied += 1;
        }
        cursor = range.end;
    }
    out.push_str(&source[cursor..]);
    (out, applied)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unflattens_split_sequence_switch() {
        let src: &str = "const _s='2|0|1'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':console.log('b');continue;case '1':console.log('c');continue;case '2':console.log('a');continue;}break;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 1);
        let out: &str = &r.rewritten_source;
        let a: Option<usize> = out.find("console.log('a')");
        let b: Option<usize> = out.find("console.log('b')");
        let c: Option<usize> = out.find("console.log('c')");
        assert!(a.is_some() && b.is_some() && c.is_some());
        assert!(a < b && b < c, "order wrong: {out}");
        assert!(!out.contains("switch"));
    }

    #[test]
    fn leaves_normal_switch_alone() {
        let src: &str = "switch(x){case 0:doA();break;case 1:doB();break;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn a_dispatcher_shape_quoted_in_a_literal_never_starts_a_splice() {
        let src: &str = "console.log(\"var _s = '0|1'['split']('|'); var _i = 0;\");\nconst _s='1|0'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':console.log('a');continue;case '1':console.log('b');continue;}break;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 1);
        let out: &str = &r.rewritten_source;
        assert!(
            out.contains("console.log(\"var _s = '0|1'['split']('|'); var _i = 0;\");"),
            "quoted dispatcher text was spliced: {out}"
        );
        let a: Option<usize> = out.find("console.log('a')");
        let b: Option<usize> = out.find("console.log('b')");
        assert!(b < a, "order wrong: {out}");
    }

    #[test]
    fn a_quoted_dispatcher_that_binds_to_a_later_iterator_never_starts_a_splice() {
        let src: &str = "var _s;\n_s='1|0'['split']('|');\nconsole.log(\"var _s = '0|1'['split']('|');\");\nlet _i=0;while(!![]){switch(_s[_i++]){case '0':console.log('a');continue;case '1':console.log('b');continue;}break;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn a_case_label_quoted_inside_a_case_body_does_not_invent_a_case() {
        let src: &str = "const _s='0|1'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':console.log(\"case '1':\");continue;case '1':console.log('b');continue;}break;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 1);
        let out: &str = &r.rewritten_source;
        let quoted: Option<usize> = out.find("console.log(\"case '1':\")");
        let b: Option<usize> = out.find("console.log('b')");
        assert!(quoted.is_some() && b.is_some(), "case bodies lost: {out}");
        assert!(quoted < b, "order wrong: {out}");
    }
}
