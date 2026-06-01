use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{apply_splice_edits, js_quote};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut stats: TransformStats = TransformStats::default();
    for cap in re.captures_iter(source) {
        stats.matched += 1;
        let Some(whole) = cap.get(0) else {
            stats.skipped += 1;
            continue;
        };
        let Some(digits) = cap.get(1) else {
            stats.skipped += 1;
            continue;
        };
        let Ok(code): core::result::Result<u32, _> = digits.as_str().parse::<u32>() else {
            stats.skipped += 1;
            continue;
        };
        let Some(ch): Option<char> = char::from_u32(code) else {
            stats.skipped += 1;
            continue;
        };
        let literal: String = js_quote(&ch.to_string(), '"');
        edits.push((whole.range(), Some(literal)));
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied;
    TransformOutput {
        source: rewritten,
        stats,
    }
}

const fn pattern() -> &'static str {
    r"String\.fromCharCode\(\s*(\d+)\s*\)"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_from_char_code() {
        let src: &str = "var s = String.fromCharCode(65);";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_single_char_code_to_literal() {
        let src: &str = "var s = String.fromCharCode(65);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("\"A\""));
    }

    #[test]
    fn reverses_multiple_calls() {
        let src: &str = "var s = String.fromCharCode(72) + String.fromCharCode(105);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 2);
        assert!(out.source.contains("\"H\""));
        assert!(out.source.contains("\"i\""));
    }

    #[test]
    fn no_op_on_clean_source() {
        let src: &str = "var s = 'hello';";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
