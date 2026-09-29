use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

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
    let (Some(whole), Some(name), Some(body)): (
        Option<regex::Match<'_>>,
        Option<regex::Match<'_>>,
        Option<regex::Match<'_>>,
    ) = (cap.get(0), cap.get(1), cap.get(2)) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let (Ok(literal_re), Ok(idx_re), Ok(any_use_re)): (
        core::result::Result<Regex, regex::Error>,
        core::result::Result<Regex, regex::Error>,
        core::result::Result<Regex, regex::Error>,
    ) = (
        Regex::new(r#"'([^']*)'|"([^"]*)""#),
        Regex::new(&format!(
            r"\b{}\s*\[\s*(\d+)\s*\]",
            regex::escape(name.as_str())
        )),
        Regex::new(&format!(
            r"(?:^|[^\w$.]){}(?:[^\w$]|$)",
            regex::escape(name.as_str())
        )),
    ) else {
        return TransformOutput::noop(source);
    };
    let entries: Vec<String> = literal_re
        .captures_iter(body.as_str())
        .filter_map(|literal: regex::Captures<'_>| literal.get(1).or_else(|| literal.get(2)))
        .map(|inner: regex::Match<'_>| crate::js_string::unescape_string_literal(inner.as_str()))
        .collect();
    let table: Range<usize> = whole.range();
    let mut edits: Vec<(Range<usize>, Option<String>)> =
        index_edits(source, &idx_re, &entries, &table);
    if edits.is_empty() {
        stats.skipped = 1;
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let references: usize = any_use_re
        .find_iter(source)
        .filter(|found: &regex::Match<'_>| found.end() <= table.start || found.start() >= table.end)
        .count();
    let removes_table: bool = references == edits.len();
    if removes_table {
        edits.push((table, None));
    }
    let (out, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied.saturating_sub(usize::from(removes_table));
    TransformOutput { source: out, stats }
}

fn index_edits(
    source: &str,
    idx_re: &Regex,
    entries: &[String],
    table: &Range<usize>,
) -> Vec<(Range<usize>, Option<String>)> {
    idx_re
        .captures_iter(source)
        .filter_map(|found: regex::Captures<'_>| {
            let whole: regex::Match<'_> = found.get(0)?;
            if whole.end() > table.start && whole.start() < table.end {
                return None;
            }
            let idx: usize = found.get(1)?.as_str().parse::<usize>().ok()?;
            let value: &String = entries.get(idx)?;
            Some((
                whole.range(),
                Some(crate::js_string::quote_string(value, '"')),
            ))
        })
        .collect()
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

    #[test]
    fn a_table_with_another_use_keeps_its_declaration() {
        let src: &str = "var T = ['alpha', 'beta']; console.log(T[0], T.length);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(
            out.source.contains("var T = ['alpha', 'beta'];"),
            "{}",
            out.source
        );
        assert!(
            out.source.contains("console.log(\"alpha\", T.length)"),
            "{}",
            out.source
        );
    }

    #[test]
    fn an_entry_holding_a_comma_stays_whole() {
        let src: &str = "var T = ['a, b', 'c']; f(T[0], T[1]);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source.trim(), "f(\"a, b\", \"c\");");
    }

    #[test]
    fn a_table_used_only_by_constant_index_is_removed() {
        let src: &str = "var T = ['x', 'y']; g(T[1]);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source.trim(), "g(\"y\");");
        assert_eq!(out.stats.reversed, 1);
    }
}
