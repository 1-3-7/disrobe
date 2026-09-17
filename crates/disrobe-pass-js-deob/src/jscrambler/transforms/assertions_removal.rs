use super::{TransformOpts, TransformOutput, TransformStats};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    if source.contains("assert(") || source.contains("console.assert") {
        return 0;
    }
    usize::from(source.contains("/*assert-strip*/"))
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let warned: usize = detect(source);
    TransformOutput {
        source: source.to_owned(),
        stats: TransformStats {
            matched: warned,
            ..TransformStats::default()
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_is_zero_when_no_strip_marker() {
        let src: &str = "function f(){ return 1; }";
        assert_eq!(detect(src), 0);
    }

    #[test]
    fn reverse_is_noop_with_warning_match() {
        let src: &str = "function f(){ /*assert-strip*/ return 1; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert!(out.stats.matched >= 1);
    }
}
