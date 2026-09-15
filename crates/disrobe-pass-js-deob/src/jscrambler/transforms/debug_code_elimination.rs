use super::{TransformOpts, TransformOutput, TransformStats};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    usize::from(source.contains("/*debug-strip*/"))
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
    fn detects_strip_marker() {
        let src: &str = "function f(){ /*debug-strip*/ return 1; }";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn no_op_on_clean() {
        let src: &str = "function f(){ return 1; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
