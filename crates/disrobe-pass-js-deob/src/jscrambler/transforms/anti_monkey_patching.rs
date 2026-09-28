use core::ops::Range;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::{apply_splice_edits, find_paren_close, skip_ws};

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
            match call_statement(&current, m.range()) {
                Some(statement) => edits.push((statement, Some(String::new()))),
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
            transform: "antiMonkeyPatching",
        });
    }
    Ok(reverse(source, opts))
}

fn call_statement(source: &str, head: Range<usize>) -> Option<Range<usize>> {
    let bytes: &[u8] = source.as_bytes();
    let open: usize = head.start + source.get(head.clone())?.find('(')?;
    let close: usize = find_paren_close(bytes, open + 1)?;
    let semicolon: usize = skip_ws(bytes, close + 1);
    if bytes.get(semicolon) != Some(&b';') {
        return None;
    }
    let before: &str = source.get(..head.start)?.trim_end();
    let statement_start: bool = before.is_empty()
        || before.ends_with([';', '{', '}'])
        || Regex::new(r"(?:\bcase\s[^;:?]*|\bdefault\s*):$")
            .ok()?
            .is_match(before);
    statement_start.then_some(head.start..semicolon + 1)
}

const fn patterns() -> [&'static str; 2] {
    [
        r"Object\s*\.\s*freeze\s*\(\s*[A-Za-z_$][\w$]*\s*\.\s*prototype\s*\)",
        r"Object\s*\.\s*defineProperty\s*\(\s*Object\s*\.\s*prototype\b",
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

    #[test]
    fn strips_a_whole_define_property_statement_with_nested_parens() {
        let src: &str = "switch(J){case 2:Object.defineProperty(Object.prototype,k,{get:function(){return this;},configurable:true});j=k;break;}";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert_eq!(out.source, "switch(J){case 2:j=k;break;}");
    }

    #[test]
    fn leaves_a_patching_call_used_as_a_value_in_place() {
        let src: &str = "var frozen = Object.freeze(Array.prototype);";
        let opts: TransformOpts = TransformOpts {
            i_have_authorization: true,
        };
        let out: TransformOutput = reverse(src, &opts);
        assert_eq!(out.source, src);
        assert_eq!(out.stats.skipped, 1);
    }
}
