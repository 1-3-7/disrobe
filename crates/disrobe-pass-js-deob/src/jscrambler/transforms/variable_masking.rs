use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(proxy_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Ok(decl_re): core::result::Result<Regex, regex::Error> = Regex::new(proxy_pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let mut working: String = source.to_owned();
    for cap in decl_re.captures_iter(source) {
        stats.matched += 1;
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(alias): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(target): Option<regex::Match<'_>> = cap.get(2) else {
            continue;
        };
        let alias_name: String = alias.as_str().to_owned();
        let target_name: String = target.as_str().to_owned();
        let Ok(usage_re): core::result::Result<Regex, regex::Error> =
            Regex::new(&format!(r"\b{}\b", regex::escape(&alias_name)))
        else {
            continue;
        };
        let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
        for m in usage_re.find_iter(&working) {
            if m.range() == whole.range() {
                continue;
            }
            edits.push((m.range(), Some(target_name.clone())));
        }
        let decl_range: Range<usize> = whole.range();
        let after_remove: String = {
            let mut s: String = String::with_capacity(working.len());
            s.push_str(&working[..decl_range.start]);
            s.push_str(&working[decl_range.end..]);
            s
        };
        if edits.is_empty() {
            working = after_remove;
            stats.skipped += 1;
            continue;
        }
        let Ok(usage_re2): core::result::Result<Regex, regex::Error> =
            Regex::new(&format!(r"\b{}\b", regex::escape(&alias_name)))
        else {
            continue;
        };
        let mut edits2: Vec<(Range<usize>, Option<String>)> = Vec::new();
        for m in usage_re2.find_iter(&after_remove) {
            edits2.push((m.range(), Some(target_name.clone())));
        }
        let (rewritten, applied): (String, usize) = apply_splice_edits(&after_remove, &mut edits2);
        working = rewritten;
        stats.reversed += applied;
    }
    TransformOutput {
        source: working,
        stats,
    }
}

const fn proxy_pattern() -> &'static str {
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_alias_decl() {
        let src: &str = "var alias = console; alias.log('x');";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn rewrites_alias_to_target() {
        let src: &str = "var alias = console; alias.log('x'); alias.warn('y');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("console.log"));
        assert!(out.source.contains("console.warn"));
        assert!(!out.source.contains("alias"));
    }

    #[test]
    fn no_op_when_no_alias() {
        let src: &str = "console.log('x');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
