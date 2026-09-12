use std::collections::BTreeMap;

use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct UnflattenStats {
    pub(super) blocks_unflattened: usize,
    pub(super) cases_inlined: usize,
}

pub(super) fn unflatten(source: &str) -> (String, UnflattenStats) {
    let mut stats: UnflattenStats = UnflattenStats::default();
    let Ok(prelude_re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)(?:var|let|const)\s+(\w+)\s*=\s*['"]([\d|]+)['"]\s*\.\s*split\s*\(\s*['"]\|['"]\s*\)\s*,\s*(\w+)\s*=\s*0\s*;"#,
    ) else {
        return (source.to_owned(), stats);
    };

    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let Ok(close_re): Result<Regex, regex::Error> = Regex::new(r"^\s*break\s*;?\s*\}") else {
        return (source.to_owned(), stats);
    };
    for prelude in prelude_re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = prelude.get(0) else {
            continue;
        };
        let Some(seq_var): Option<&str> = prelude.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(seq_str): Option<&str> = prelude.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(idx_var): Option<&str> = prelude.get(3).map(|m| m.as_str()) else {
            continue;
        };

        let tail: &str = &source[whole.end()..];
        let seq_esc: String = regex::escape(seq_var);
        let idx_esc: String = regex::escape(idx_var);
        let loop_re_src: String = format!(
            r"^\s*while\s*\(\s*(?:!\[\]|true)\s*\)\s*\{{\s*switch\s*\(\s*{seq_esc}\s*\[\s*{idx_esc}\+\+\s*\]\s*\)\s*\{{",
        );
        let Ok(loop_re): Result<Regex, regex::Error> = Regex::new(&loop_re_src) else {
            continue;
        };
        let Some(loop_head): Option<regex::Match<'_>> = loop_re.find(tail) else {
            continue;
        };
        let switch_body_start: usize = whole.end() + loop_head.end();

        let Some((switch_body, switch_body_end)): Option<(&str, usize)> =
            scan_balanced_block(source, switch_body_start)
        else {
            continue;
        };
        let after_switch: &str = &source[switch_body_end..];
        let Some(close_match): Option<regex::Match<'_>> = close_re.find(after_switch) else {
            continue;
        };
        let block_end: usize = switch_body_end + close_match.end();

        let order: Vec<&str> = seq_str.split('|').collect();
        let Some(map): Option<BTreeMap<String, String>> = parse_cases(switch_body) else {
            continue;
        };
        let mut emitted: String = String::new();
        let mut local_inlined: usize = 0;
        for label in &order {
            if let Some(body) = map.get(*label) {
                emitted.push_str(body.trim());
                if !emitted.ends_with(';') && !emitted.ends_with('}') {
                    emitted.push(';');
                }
                emitted.push('\n');
                local_inlined += 1;
            }
        }
        if local_inlined == 0 {
            continue;
        }
        out.push_str(&source[cursor..whole.start()]);
        out.push_str(&emitted);
        cursor = block_end;
        stats.blocks_unflattened += 1;
        stats.cases_inlined += local_inlined;
    }
    out.push_str(&source[cursor..]);
    (out, stats)
}

fn scan_balanced_block(source: &str, body_start: usize) -> Option<(&str, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 1;
    let mut i: usize = body_start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&source[body_start..i], i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_cases(body: &str) -> Option<BTreeMap<String, String>> {
    let head_re: Regex = Regex::new(r#"(?ms)case\s+['"](\d+)['"]\s*:"#).ok()?;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let heads: Vec<Captures<'_>> = head_re.captures_iter(body).collect();
    for (idx, cap) in heads.iter().enumerate() {
        let label: String = cap.get(1)?.as_str().to_owned();
        let whole: regex::Match<'_> = cap.get(0)?;
        let body_start: usize = whole.end();
        let body_end: usize = heads
            .get(idx + 1)
            .and_then(|next| next.get(0))
            .map_or(body.len(), |m| m.start());
        let raw_body: &str = &body[body_start..body_end];
        let trimmed: String = strip_trailing_continue_or_break(raw_body);
        map.insert(label, trimmed);
    }
    if map.is_empty() { None } else { Some(map) }
}

fn strip_trailing_continue_or_break(body: &str) -> String {
    let trimmed: &str = body.trim();
    trimmed
        .trim_end_matches(';')
        .trim_end()
        .strip_suffix("continue")
        .or_else(|| {
            trimmed
                .trim_end_matches(';')
                .trim_end()
                .strip_suffix("break")
        })
        .map_or_else(
            || trimmed.to_owned(),
            |s| s.trim_end_matches(';').trim_end().to_owned(),
        )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_cases() {
        let body: &str =
            "case \"0\": a(); continue; case \"1\": b(); continue; case \"2\": c(); break;";
        let Some(map): Option<BTreeMap<String, String>> = parse_cases(body) else {
            panic!("must parse three cases");
        };
        assert_eq!(map.len(), 3);
        assert!(matches!(map.get("0"), Some(s) if s.contains("a()")));
        assert!(matches!(map.get("1"), Some(s) if s.contains("b()")));
        assert!(matches!(map.get("2"), Some(s) if s.contains("c()")));
    }

    #[test]
    fn unflattens_basic_switch_state_machine() {
        let src: &str = r#"var seq = "2|0|1".split("|"), i = 0;
while (true) {
    switch (seq[i++]) {
        case "0": a(); continue;
        case "1": b(); continue;
        case "2": c(); continue;
    }
    break;
}"#;
        let (out, stats): (String, UnflattenStats) = unflatten(src);
        assert_eq!(stats.blocks_unflattened, 1);
        assert_eq!(stats.cases_inlined, 3);
        let Some(pos_c): Option<usize> = out.find("c()") else {
            panic!("c() must appear");
        };
        let Some(pos_a): Option<usize> = out.find("a()") else {
            panic!("a() must appear");
        };
        let Some(pos_b): Option<usize> = out.find("b()") else {
            panic!("b() must appear");
        };
        assert!(
            pos_c < pos_a,
            "c() should come before a() in the unflattened order"
        );
        assert!(pos_a < pos_b, "a() should come before b()");
    }

    #[test]
    fn no_match_leaves_source_alone() {
        let src: &str = "var x = 1; while (x < 10) { x++; }";
        let (out, stats): (String, UnflattenStats) = unflatten(src);
        assert_eq!(out, src);
        assert_eq!(stats.blocks_unflattened, 0);
    }

    #[test]
    fn handles_negated_array_truthy_loop_form() {
        let src: &str = r#"var s = "1|0".split("|"), j = 0;
while (![]) {
    switch (s[j++]) {
        case "0": x(); continue;
        case "1": y(); continue;
    }
    break;
}"#;
        let (out, stats): (String, UnflattenStats) = unflatten(src);
        assert_eq!(stats.blocks_unflattened, 1);
        assert!(out.contains("y()"));
        assert!(out.contains("x()"));
    }
}
