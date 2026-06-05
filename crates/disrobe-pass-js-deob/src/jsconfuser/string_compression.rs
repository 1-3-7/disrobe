use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct StringCompressionResult {
    pub blocks_reversed: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_string_compression(source: &str) -> StringCompressionResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    collect_split_string_arrays(source, &mut edits);
    collect_string_fromcharcode_runs(source, &mut edits);
    if edits.is_empty() {
        return StringCompressionResult {
            blocks_reversed: 0,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, reversed): (String, usize) = apply_splice_edits(source, &mut edits);
    StringCompressionResult {
        blocks_reversed: reversed,
        rewritten_source: rewritten,
    }
}

fn collect_split_string_arrays(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*['"]([^'"]+)['"]\.split\(\s*['"]([^'"]{1,2})['"]\s*\)"#,
    ) else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(payload): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(separator): Option<&str> = caps.get(2).map(|m: regex::Match<'_>| m.as_str())
        else {
            continue;
        };
        if !payload.contains(separator) {
            continue;
        }
        let words: Vec<&str> = payload.split(separator).collect();
        let array_literal: String = format!(
            "[{}]",
            words
                .iter()
                .map(|w: &&str| format!("\"{}\"", w.replace('"', "\\\"")))
                .collect::<Vec<String>>()
                .join(", ")
        );
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(eq_pos): Option<usize> = source[whole.start()..whole.end()].find('=') else {
            continue;
        };
        let prefix_end: usize = whole.start() + eq_pos + 1;
        edits.push((prefix_end..whole.end(), Some(format!(" {array_literal}"))));
    }
}

fn collect_string_fromcharcode_runs(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"String\.fromCharCode\(\s*((?:\s*\d+\s*,){2,}\s*\d+\s*)\)")
    else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(arg_text): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let codepoints: Vec<u32> = arg_text
            .split(',')
            .filter_map(|s: &str| s.trim().parse::<u32>().ok())
            .collect();
        let mut decoded: String = String::with_capacity(codepoints.len());
        for cp in codepoints {
            let Some(ch): Option<char> = char::from_u32(cp) else {
                decoded.clear();
                break;
            };
            decoded.push(ch);
        }
        if decoded.is_empty() {
            continue;
        }
        let escaped: String = decoded
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        edits.push((whole.start()..whole.end(), Some(format!("\"{escaped}\""))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_split_string_array() {
        let src: &str = "var dict = 'alpha|beta|gamma'.split('|');\nuse(dict[1]);";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 1);
        assert!(
            r.rewritten_source
                .contains("[\"alpha\", \"beta\", \"gamma\"]")
        );
    }

    #[test]
    fn folds_string_fromcharcode_run() {
        let src: &str = "var s = String.fromCharCode(104, 101, 108, 108, 111);";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 1);
        assert!(r.rewritten_source.contains("\"hello\""));
    }

    #[test]
    fn leaves_simple_split_alone() {
        let src: &str = "x.split(',');";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 0);
    }
}
