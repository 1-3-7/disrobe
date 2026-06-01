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
    for pat in patterns() {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            stats.errors.push(format!("compile fail: {pat}"));
            continue;
        };
        let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
        for m in re.find_iter(&current) {
            stats.matched += 1;
            edits.push((m.range(), Some(String::new())));
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

const fn patterns() -> [&'static str; 4] {
    [
        r"if\s*\(\s*false\s*\)\s*\{[^{}]*\}",
        r"if\s*\(\s*0\s*\)\s*\{[^{}]*\}",
        r"if\s*\(\s*!1\s*\)\s*\{[^{}]*\}",
        r"if\s*\(\s*!!\s*0\s*\)\s*\{[^{}]*\}",
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_dead_if_false() {
        let src: &str = "if (false) { x(); } y();";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn strips_dead_branch() {
        let src: &str = "if (false) { x(); } y();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(!out.source.contains("x()"));
        assert!(out.source.contains("y()"));
    }

    #[test]
    fn no_op_on_real_branches() {
        let src: &str = "if (cond) { x(); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
