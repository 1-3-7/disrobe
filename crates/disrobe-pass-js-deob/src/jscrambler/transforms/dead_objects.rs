use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::apply_splice_edits;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pattern()) else {
        return 0;
    };
    re.find_iter(source).count()
}

pub(in crate::jscrambler) fn reverse(source: &str, opts: &TransformOpts) -> TransformOutput {
    if !opts.i_have_authorization {
        let warned: usize = detect(source);
        return TransformOutput {
            source: source.to_owned(),
            stats: TransformStats {
                matched: warned,
                skipped: warned,
                errors: vec!["authorization required to strip deadObjects".to_owned()],
                ..TransformStats::default()
            },
        };
    }
    let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pattern()) else {
        return TransformOutput::noop(source);
    };
    let mut stats: TransformStats = TransformStats::default();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for m in re.find_iter(source) {
        stats.matched += 1;
        edits.push((m.range(), Some(String::new())));
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

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired {
            transform: "deadObjects",
        });
    }
    Ok(reverse(source, opts))
}

const fn pattern() -> &'static str {
    r"(?:var|let|const)\s+__dead\w*\s*=\s*\{[^}]*\}\s*;"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_dead_object_decl() {
        let src: &str = "var __deadObj = {a: 1, b: 2};";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn strict_requires_authorization() {
        let src: &str = "var __deadObj = {};";
        let err: Error = reverse_strict(src, &TransformOpts::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }

    #[test]
    fn strips_when_authorized() {
        let src: &str = "var __deadObj = {a: 1}; var x = 2;";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert!(!out.source.contains("__deadObj"));
        assert!(out.source.contains("var x = 2"));
    }
}
