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
    let mut stats: TransformStats = TransformStats::default();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for re_src in patterns() {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(re_src) else {
            stats.errors.push(format!("compile fail: {re_src}"));
            continue;
        };
        for cap in re.captures_iter(source) {
            stats.matched += 1;
            let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
                continue;
            };
            let Some(payload): Option<regex::Match<'_>> = cap.get(1) else {
                continue;
            };
            let payload_str: &str = payload.as_str();
            let base: u32 = detect_radix(re_src);
            let cleaned: String = payload_str.replace(['"', '\''], "");
            let Ok(value): Result<i64, _> = i64::from_str_radix(&cleaned, base) else {
                stats.skipped += 1;
                continue;
            };
            edits.push((whole.range(), Some(value.to_string())));
        }
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

const fn patterns() -> [&'static str; 3] {
    [
        r"parseInt\(\s*['\x22]([0-9a-fA-F]+)['\x22]\s*,\s*16\s*\)",
        r"parseInt\(\s*['\x22]([01]+)['\x22]\s*,\s*2\s*\)",
        r"parseInt\(\s*['\x22]([0-7]+)['\x22]\s*,\s*8\s*\)",
    ]
}

fn detect_radix(re_src: &str) -> u32 {
    if re_src.contains(",\\s*16") {
        16
    } else if re_src.contains(",\\s*2") {
        2
    } else {
        8
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_parse_int() {
        let src: &str = r#"var x = parseInt("ff", 16);"#;
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_hex_string_to_number() {
        let src: &str = r#"var x = parseInt("ff", 16);"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("255"));
    }

    #[test]
    fn reverses_binary_string_to_number() {
        let src: &str = r#"var x = parseInt("1011", 2);"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("11"));
    }

    #[test]
    fn no_op_on_plain_numbers() {
        let src: &str = "var x = 42;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
