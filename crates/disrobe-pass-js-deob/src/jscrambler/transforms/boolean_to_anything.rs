use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let mut count: usize = 0;
    for pat in patterns() {
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
            stats.errors.push(format!("regex compile failed: {pat}"));
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

const fn patterns() -> [&'static str; 6] {
    [
        r"!\[\]",
        r"!!\[\]",
        r"\b1\s*===?\s*1\b",
        r"\b0\s*===?\s*1\b",
        r"\b!!\s*1\b",
        r"\b!1\b",
    ]
}

const fn pattern_replacements() -> [(&'static str, &'static str); 4] {
    [
        (r"!!\[\]", "true"),
        (r"!\[\]", "false"),
        (r"\b!!\s*1\b", "true"),
        (r"\b!1\b", "false"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_falsy_array_pattern() {
        let src: &str = "if (![]) { x(); }";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn reverses_truthy_array_to_true() {
        let src: &str = "while (!![]) { break; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("true"));
        assert_eq!(out.stats.reversed, 1);
    }

    #[test]
    fn reverses_falsy_array_to_false() {
        let src: &str = "if (![]) { x; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("false"));
    }

    #[test]
    fn no_op_on_clean_source() {
        let src: &str = "const x = true;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.reversed, 0);
    }
}
