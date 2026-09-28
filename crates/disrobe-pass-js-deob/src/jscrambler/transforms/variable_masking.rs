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
    let mut cursor: usize = 0;
    while let Some(cap) = decl_re.captures_at(&working, cursor) {
        stats.matched += 1;
        let (Some(whole), Some(alias), Some(target)): (
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
            Option<regex::Match<'_>>,
        ) = (cap.get(0), cap.get(1), cap.get(2)) else {
            break;
        };
        let decl_range: Range<usize> = whole.range();
        let alias_name: String = alias.as_str().to_owned();
        let target_name: String = target.as_str().to_owned();
        let Ok(usage_re): core::result::Result<Regex, regex::Error> =
            Regex::new(&format!(r"\b{}\b", regex::escape(&alias_name)))
        else {
            cursor = decl_range.end;
            continue;
        };
        let mut after_remove: String = String::with_capacity(working.len());
        after_remove.push_str(&working[..decl_range.start]);
        after_remove.push_str(&working[decl_range.end..]);
        if LITERAL_KEYWORDS.contains(&target_name.as_str())
            || is_reassigned(&after_remove, &alias_name)
            || is_reassigned(&after_remove, &target_name)
        {
            stats.skipped += 1;
            cursor = decl_range.end;
            continue;
        }
        let mut edits: Vec<(Range<usize>, Option<String>)> = usage_re
            .find_iter(&after_remove)
            .map(|m: regex::Match<'_>| (m.range(), Some(target_name.clone())))
            .collect();
        let uses_before: usize = edits
            .iter()
            .filter(|(range, _): &&(Range<usize>, Option<String>)| range.end <= decl_range.start)
            .count();
        cursor =
            decl_range.start - uses_before * alias_name.len() + uses_before * target_name.len();
        if edits.is_empty() {
            working = after_remove;
            stats.skipped += 1;
            continue;
        }
        let (rewritten, applied): (String, usize) = apply_splice_edits(&after_remove, &mut edits);
        working = rewritten;
        stats.reversed += applied;
    }
    TransformOutput {
        source: working,
        stats,
    }
}

const LITERAL_KEYWORDS: [&str; 4] = ["false", "null", "this", "true"];

fn is_reassigned(text: &str, name: &str) -> bool {
    let name: String = regex::escape(name);
    let pattern: String = format!(
        r"(?:^|[^\w$.])(?:{name}\s*(?:=[^=]|\+\+|--|(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)=)|(?:\+\+|--)\s*{name}(?:[^\w$]|$))"
    );
    Regex::new(&pattern).is_ok_and(|re: Regex| re.is_match(text))
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
    fn every_alias_declaration_is_removed_from_the_current_text() {
        let src: &str =
            "function f(){var a=arguments;return a[0]+a[1];}function g(){var b=console;b.log(1);}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.source,
            "function f(){return arguments[0]+arguments[1];}function g(){console.log(1);}"
        );
    }

    #[test]
    fn an_assigned_alias_or_literal_target_is_not_a_mask() {
        let src: &str = "function f(){var r=false;try{r=g();}catch(e){}return r;}function h(){var o=x;x=2;return o;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.skipped, 2);
    }

    #[test]
    fn no_op_when_no_alias() {
        let src: &str = "console.log('x');";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
