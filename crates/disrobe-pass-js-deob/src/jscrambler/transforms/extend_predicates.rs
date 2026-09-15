use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let mut count: usize = 0;
    for (pat, _) in pattern_replacements() {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            continue;
        };
        count += re.find_iter(source).count();
    }
    count
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let mut current: String = source.to_owned();
    let mut stats: TransformStats = TransformStats::default();
    for (pat, replacement) in pattern_replacements() {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            stats.errors.push(format!("compile fail: {pat}"));
            continue;
        };
        let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
        for m in re.find_iter(&current) {
            stats.matched += 1;
            edits.push((m.range(), Some(replacement.to_owned())));
        }
        if !edits.is_empty() {
            let (out, applied): (String, usize) = apply_splice_edits(&current, &mut edits);
            current = out;
            stats.reversed += applied;
        }
    }
    TransformOutput {
        source: current,
        stats,
    }
}

const fn pattern_replacements() -> [(&'static str, &'static str); 6] {
    [
        (r"\b2\s*>\s*1\b", "true"),
        (r"\b1\s*<\s*2\b", "true"),
        (r"\b1\s*===?\s*1\b", "true"),
        (r"\b0\s*===?\s*0\b", "true"),
        (r"\btypeof\s+'[^']*'\s*===?\s*'string'", "true"),
        (r"\btypeof\s+\d+\s*===?\s*'number'", "true"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_always_true_predicate() {
        let src: &str = "if (2 > 1) { x(); }";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn folds_always_true_predicate() {
        let src: &str = "if (2 > 1) { x(); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("if (true)"));
    }

    #[test]
    fn folds_typeof_string_predicate() {
        let src: &str = "if (typeof 'abc' === 'string') { run(); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("if (true)"));
    }

    #[test]
    fn no_op_on_clean() {
        let src: &str = "if (cond) { x(); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
