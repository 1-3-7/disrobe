use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{apply_splice_edits, js_quote};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(table_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(table_pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let Some(cap): Option<regex::Captures<'_>> = re.captures(source) else {
        return TransformOutput::noop(source);
    };
    stats.matched = 1;
    let Some(whole) = cap.get(0) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let Some(name) = cap.get(1) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let Some(body) = cap.get(2) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let entries: Vec<&str> = body
        .as_str()
        .split(',')
        .map(|s: &str| s.trim().trim_matches(|c: char| c == '\'' || c == '"'))
        .collect();
    let table_name: &str = name.as_str();
    let mut working: String = String::with_capacity(source.len());
    working.push_str(&source[..whole.start()]);
    working.push_str(&source[whole.end()..]);
    let Ok(idx_re): core::result::Result<Regex, regex::Error> = Regex::new(&format!(
        r"\b{}\s*\[\s*(\d+)\s*\]",
        regex::escape(table_name)
    )) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for cap2 in idx_re.captures_iter(&working) {
        let Some(m) = cap2.get(0) else { continue };
        let Some(idx_cap) = cap2.get(1) else { continue };
        let Ok(idx): Result<usize, _> = idx_cap.as_str().parse::<usize>() else {
            continue;
        };
        let Some(value): Option<&&str> = entries.get(idx) else {
            continue;
        };
        edits.push((m.range(), Some(js_quote(value, '"'))));
    }
    if edits.is_empty() {
        stats.skipped = 1;
        return TransformOutput {
            source: working,
            stats,
        };
    }
    let (out, applied): (String, usize) = apply_splice_edits(&working, &mut edits);
    stats.reversed = applied;
    TransformOutput { source: out, stats }
}

const fn table_pattern() -> &'static str {
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*((?:['\x22][^'\x22]*['\x22]\s*,?\s*){2,})\]\s*;"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_literal_table() {
        let src: &str = "var T = ['alpha', 'beta', 'gamma']; console.log(T[1]);";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn inlines_literal_table_references() {
        let src: &str = "var T = ['alpha', 'beta', 'gamma']; console.log(T[0], T[2]);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 2);
        assert!(out.source.contains("\"alpha\""));
        assert!(out.source.contains("\"gamma\""));
    }

    #[test]
    fn no_op_when_no_table() {
        let src: &str = "var x = 1; console.log(x);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
