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
    let Ok(decl_re): core::result::Result<Regex, regex::Error> = Regex::new(table_pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let Some(cap): Option<regex::Captures<'_>> = decl_re.captures(source) else {
        return TransformOutput::noop(source);
    };
    stats.matched = 1;
    let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let Some(global_var): Option<regex::Match<'_>> = cap.get(1) else {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    let global_var_name: &str = global_var.as_str();
    let mut working: String = String::with_capacity(source.len());
    working.push_str(&source[..whole.start()]);
    working.push_str(&source[whole.end()..]);
    let Ok(usage_re): core::result::Result<Regex, regex::Error> = Regex::new(&format!(
        r"\b{}\b(\s*[\.\[])",
        regex::escape(global_var_name)
    )) else {
        return TransformOutput {
            source: working,
            stats,
        };
    };
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for cap2 in usage_re.captures_iter(&working) {
        let Some(m): Option<regex::Match<'_>> = cap2.get(0) else {
            continue;
        };
        let Some(tail): Option<regex::Match<'_>> = cap2.get(1) else {
            continue;
        };
        edits.push((m.range(), Some(format!("globalThis{}", tail.as_str()))));
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
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:globalThis|window|global|self)\s*;"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_indirection_table() {
        let src: &str = "var g = globalThis; g.x = 1;";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn rewrites_g_to_global_this() {
        let src: &str = "var g = globalThis; g.x = 1; g.y[0] = 2;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 2);
        assert!(out.source.contains("globalThis.x = 1"));
        assert!(out.source.contains("globalThis.y[0] = 2"));
    }

    #[test]
    fn no_op_when_no_indirection() {
        let src: &str = "var x = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
