use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(arith_pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(arith_pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for cap in re.captures_iter(source) {
        stats.matched += 1;
        let Some(whole) = cap.get(0) else { continue };
        let Some(a) = cap.get(1) else { continue };
        let Some(op) = cap.get(2) else { continue };
        let Some(b) = cap.get(3) else { continue };
        let Ok(av): Result<f64, _> = a.as_str().parse::<f64>() else {
            continue;
        };
        let Ok(bv): Result<f64, _> = b.as_str().parse::<f64>() else {
            continue;
        };
        let folded: f64 = match op.as_str() {
            "+" => av + bv,
            "-" => av - bv,
            "*" => av * bv,
            "/" if bv != 0.0 => av / bv,
            _ => continue,
        };
        if folded.fract() == 0.0 && folded.abs() < 1.0e15 {
            edits.push((whole.range(), Some(format!("{}", folded as i64))));
        } else {
            edits.push((whole.range(), Some(format!("{folded}"))));
        }
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

const fn arith_pattern() -> &'static str {
    r"\b(\d+)\s*([+\-*/])\s*(\d+)\b"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_arith_expr() {
        let src: &str = "var x = 2 + 3;";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn folds_addition() {
        let src: &str = "var x = 2 + 3;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains('5'));
    }

    #[test]
    fn folds_multiplication() {
        let src: &str = "var x = 6 * 7;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("42"));
    }

    #[test]
    fn no_op_on_variable_expr() {
        let src: &str = "var x = a + b;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
