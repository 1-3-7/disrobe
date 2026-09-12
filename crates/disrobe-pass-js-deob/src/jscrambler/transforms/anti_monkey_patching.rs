use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
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

pub(in crate::jscrambler) fn reverse(source: &str, opts: &TransformOpts) -> TransformOutput {
    if !opts.i_have_authorization {
        let warned: usize = detect(source);
        return TransformOutput {
            source: source.to_owned(),
            stats: TransformStats {
                matched: warned,
                skipped: warned,
                errors: vec!["authorization required to strip antiMonkeyPatching".to_owned()],
                ..TransformStats::default()
            },
        };
    }
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

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired {
            transform: "antiMonkeyPatching",
        });
    }
    Ok(reverse(source, opts))
}

const fn patterns() -> [&'static str; 2] {
    [
        r"Object\s*\.\s*freeze\s*\(\s*[A-Za-z_$][\w$]*\s*\.\s*prototype\s*\)\s*;?",
        r"Object\s*\.\s*defineProperty\s*\(\s*Object\s*\.\s*prototype[^)]+\)\s*;?",
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_freeze_prototype() {
        let src: &str = "Object.freeze(Array.prototype);";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn strict_requires_authorization() {
        let src: &str = "Object.freeze(Array.prototype);";
        let err: Error = reverse_strict(src, &TransformOpts::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }

    #[test]
    fn strips_freeze_call_when_authorized() {
        let src: &str = "Object.freeze(Array.prototype); var x = 1;";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert!(!out.source.contains("Object.freeze"));
        assert!(out.source.contains("var x = 1"));
    }
}
