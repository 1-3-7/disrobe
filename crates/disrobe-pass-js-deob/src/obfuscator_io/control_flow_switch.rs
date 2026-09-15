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
        let span: Range<usize> = block_start..loop_end;
        let scope: Range<usize> = enclosing_function_body(source, &skips, block_start);
        if identifier_escapes(source, &skips, seq_name, &scope, &span)
            || identifier_escapes(source, &skips, &iter_name, &scope, &span)
        {
            continue;
        }
        let replacement: String = ordered.join("\n");
        edits.push((span, Some(replacement)));
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

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

const fn trim_whitespace_back(bytes: &[u8], end: usize) -> usize {
    let mut index: usize = end;
    while index > 0 && matches!(bytes[index - 1], b' ' | b'\t' | b'\r' | b'\n') {
        index -= 1;
    }
    index
}

const fn trim_identifier_back(bytes: &[u8], end: usize) -> usize {
    let mut index: usize = end;
    while index > 0 && is_identifier_byte(bytes[index - 1]) {
        index -= 1;
    }
    index
}

const fn find_paren_open(bytes: &[u8], close: usize) -> Option<usize> {
    if close >= bytes.len() {
        return None;
    }
    let mut depth: i32 = 0;
    let mut index: usize = close;
    loop {
        match bytes[index] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        if index == 0 {
            return None;
        }
        index -= 1;
    }
}

fn opens_function_body(source: &str, open: usize) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let before_brace: usize = trim_whitespace_back(bytes, open);
    if before_brace >= 2 && bytes[before_brace - 1] == b'>' && bytes[before_brace - 2] == b'=' {
        return true;
    }
    if before_brace == 0 || bytes[before_brace - 1] != b')' {
        return false;
    }
    let Some(paren_open): Option<usize> = find_paren_open(bytes, before_brace - 1) else {
        return false;
    };
    let after_name: usize = trim_whitespace_back(bytes, paren_open);
    let before_name: usize = trim_identifier_back(bytes, after_name);
    let mut keyword_end: usize = trim_whitespace_back(bytes, before_name);
    if keyword_end > 0 && bytes[keyword_end - 1] == b'*' {
        keyword_end = trim_whitespace_back(bytes, keyword_end - 1);
    }
    let head: &str = &source[..keyword_end];
    if !head.ends_with("function") {
        return false;
    }
    let keyword_start: usize = keyword_end - "function".len();
    keyword_start == 0 || !is_identifier_byte(bytes[keyword_start - 1])
}

fn enclosing_function_body(source: &str, skips: &[Range<usize>], position: usize) -> Range<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut open_stack: Vec<usize> = Vec::new();
    let mut skip_cursor: usize = 0;
    let mut index: usize = 0;
    while index < position && index < bytes.len() {
        while skips
            .get(skip_cursor)
            .is_some_and(|range: &Range<usize>| range.end <= index)
        {
            skip_cursor += 1;
        }
        if let Some(range) = skips.get(skip_cursor)
            && range.start <= index
            && index < range.end
        {
            index = range.end;
            continue;
        }
        match bytes[index] {
            b'{' => open_stack.push(index),
            b'}' => {
                open_stack.pop();
            }
            _ => {}
        }
        index += 1;
    }
    while let Some(open) = open_stack.pop() {
        if !opens_function_body(source, open) {
            continue;
        }
        let Some(close): Option<usize> = find_brace_close(bytes, open + 1) else {
            continue;
        };
        let body_end: usize = close.saturating_add(1);
        return open..body_end;
    }
    0..source.len()
}

fn identifier_escapes(
    source: &str,
    skips: &[Range<usize>],
    name: &str,
    scope: &Range<usize>,
    span: &Range<usize>,
) -> bool {
    let bytes: &[u8] = source.as_bytes();
    source
        .match_indices(name)
        .any(|(start, matched): (usize, &str)| {
            let end: usize = start + matched.len();
            if start < scope.start || end > scope.end || span.contains(&start) {
                return false;
            }
            let attached_before: bool = start > 0 && is_identifier_byte(bytes[start - 1]);
            let attached_after: bool = bytes
                .get(end)
                .is_some_and(|byte: &u8| is_identifier_byte(*byte));
            !attached_before && !attached_after && span_is_code(skips, start, end)
        })
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
    fn a_dispatcher_whose_sequence_is_read_after_the_loop_is_left_alone() {
        let src: &str = "function f(){var acc=0;const _s='0|1'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':acc=acc+5;continue;case '1':acc=acc*3;continue;}break;}return acc+_s.length+_i;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn the_same_dispatcher_names_in_a_sibling_function_still_unflatten() {
        let src: &str = "function f(){var acc=1;const _s='0|1'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':acc=acc+5;continue;case '1':acc=acc*3;continue;}break;}return acc;}\nfunction g(){var acc=1;const _s='1|0'['split']('|');let _i=0;while(!![]){switch(_s[_i++]){case '0':acc=acc+5;continue;case '1':acc=acc*3;continue;}break;}return acc;}";
        let r: ControlFlowSwitchResult = unflatten_control_flow_switch(src);
        assert_eq!(r.switches_unflattened, 2);
        assert!(!r.rewritten_source.contains("switch"));
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
