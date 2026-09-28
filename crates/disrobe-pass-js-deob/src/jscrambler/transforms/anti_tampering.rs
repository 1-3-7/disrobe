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
                errors: vec!["authorization required to strip antiTampering".to_owned()],
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
            match expected_probe_value(&current, m.range()) {
                Some(value) => edits.push((m.range(), Some(value))),
                None => stats.skipped += 1,
            }
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
            transform: "antiTampering",
        });
    }
    Ok(reverse(source, opts))
}

const EQUALITY: &str = r"(?:!==|!=|===|==)";

fn expected_probe_value(source: &str, probe: Range<usize>) -> Option<String> {
    let before: &str = source.get(..probe.start)?;
    let after: &str = source.get(probe.end..)?;
    let compared_after: Regex = Regex::new(&format!(r"^\s*{EQUALITY}\s*(\d+)\b")).ok()?;
    if let Some(caps) = compared_after.captures(after) {
        return Some(caps.get(1)?.as_str().to_owned());
    }
    let compared_before: Regex = Regex::new(&format!(r"\b(\d+)\s*{EQUALITY}\s*$")).ok()?;
    if let Some(caps) = compared_before.captures(before) {
        return Some(caps.get(1)?.as_str().to_owned());
    }
    let declarator: Regex = Regex::new(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*$").ok()?;
    let name: &str = declarator.captures(before)?.get(1)?.as_str();
    let terminated: Regex = Regex::new(r"^\s*[;,]").ok()?;
    if !terminated.is_match(after) {
        return None;
    }
    let name: String = regex::escape(name);
    let comparison: Regex = Regex::new(&format!(
        r"(?:^|[^\w$.])(?:{name}\s*{EQUALITY}\s*(\d+)\b|(\d+)\s*{EQUALITY}\s*{name}(?:[^\w$]|$))"
    ))
    .ok()?;
    let caps: regex::Captures<'_> = comparison.captures(after)?;
    Some(caps.get(1).or_else(|| caps.get(2))?.as_str().to_owned())
}

const fn patterns() -> [&'static str; 2] {
    [
        r"[A-Za-z_$][\w$]*\s*\.\s*toString\s*\(\s*\)\s*\.\s*replace\s*\(\s*/[^/]*/[gi]*\s*,\s*['\x22]\s*['\x22]\s*\)\s*\.\s*length",
        r"Function\s*\.\s*prototype\s*\.\s*toString\s*\(\s*\)",
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_tostring_replace_length() {
        let src: &str = "var n = fn.toString().replace(/ /g,'').length;";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn strict_requires_authorization() {
        let src: &str = "var n = fn.toString().replace(/ /g,'').length;";
        let err: Error = reverse_strict(src, &TransformOpts::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }

    #[test]
    fn strips_when_authorized() {
        let src: &str = "var n = fn.toString().replace(/ /g,'').length; if (n !== 100) tamper();";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert_eq!(out.source, "var n = 100; if (n !== 100) tamper();");
        assert_eq!(out.stats.reversed, 1);
    }

    #[test]
    fn an_inline_probe_takes_the_value_it_is_compared_with() {
        let src: &str = "if (100 != fn.toString().replace(/ /g,'').length) tamper();";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert_eq!(out.source, "if (100 != 100) tamper();");
    }

    #[test]
    fn a_probe_without_a_compared_value_is_left_in_place() {
        let src: &str = "var n = fn.toString().replace(/ /g,'').length; report(n);";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert_eq!(out.source, src);
        assert_eq!(out.stats.skipped, 1);
        assert_eq!(out.stats.reversed, 0);
    }
}
