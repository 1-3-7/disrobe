use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

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
    let mut stats: TransformStats = TransformStats::default();
    let mut counter: usize = 0;
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for m in re.find_iter(source) {
        stats.matched += 1;
        let original: &str = m.as_str();
        let mapped: String = match seen
            .iter()
            .find(|(orig, _): &&(String, String)| orig == original)
        {
            Some((_, replacement)) => replacement.clone(),
            None => {
                counter += 1;
                let replacement: String = format!("v_{counter}");
                seen.push((original.to_owned(), replacement.clone()));
                replacement
            }
        };
        edits.push((m.range(), Some(mapped)));
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (out, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied;
    TransformOutput { source: out, stats }
}

const fn pattern() -> &'static str {
    r"\b[a-z]\d{0,2}_0x[0-9a-fA-F]{4,6}\b"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_idents() {
        let src: &str = "var a0_0xabcd = 1; var a1_0xbeef = 2;";
        assert_eq!(detect(src), 2);
    }

    #[test]
    fn renames_hex_idents_to_v_n_stable() {
        let src: &str = "var a0_0xabcd = 1; var a0_0xabcd = 2; var a1_0xbeef = 3;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("v_1"));
        assert!(out.source.contains("v_2"));
        let v1_count: usize = out.source.matches("v_1").count();
        assert!(v1_count >= 2, "v_1 should be stable across occurrences");
    }

    #[test]
    fn no_op_on_clean_idents() {
        let src: &str = "var foo = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
