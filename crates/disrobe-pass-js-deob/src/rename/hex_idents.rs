use std::ops::Range;

use indexmap::IndexMap;
use regex::{Captures, Regex};

use super::RenameStats;
use crate::scan_utils::{literal_and_comment_ranges, replace_in_code, span_is_code};

pub(super) fn rename(source: &str) -> (String, RenameStats) {
    let mut stats: RenameStats = RenameStats::default();
    let Ok(ident_re): Result<Regex, regex::Error> = Regex::new(r"\b_0x[0-9a-fA-F]+\b") else {
        return (source.to_owned(), stats);
    };

    let skips: Vec<Range<usize>> = literal_and_comment_ranges(source);
    let mut order: IndexMap<String, String> = IndexMap::new();
    for cap in ident_re.captures_iter(source) {
        let Some(matched): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        if !span_is_code(&skips, matched.start(), matched.end()) {
            continue;
        }
        let name: String = matched.as_str().to_owned();
        if !order.contains_key(&name) {
            let new: String = format!("var_{}", order.len() + 1);
            order.insert(name, new);
        }
    }
    stats.idents_renamed = order.len();

    let (rewritten, rewrites): (String, usize) =
        replace_in_code(source, &ident_re, |caps: &Captures<'_>| {
            caps.get(0)
                .and_then(|matched: regex::Match<'_>| order.get(matched.as_str()))
                .cloned()
        });
    stats.references_rewritten = rewrites;
    (rewritten, stats)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn renames_unique_hex_idents_to_var_n() {
        let src: &str = "var _0xab = 1; var _0xcd = _0xab + 2; console.log(_0xcd);";
        let (out, stats): (String, RenameStats) = rename(src);
        assert_eq!(stats.idents_renamed, 2);
        assert_eq!(stats.references_rewritten, 4);
        assert!(out.contains("var_1"));
        assert!(out.contains("var_2"));
        assert!(!out.contains("_0xab"));
        assert!(!out.contains("_0xcd"));
    }

    #[test]
    fn preserves_non_hex_identifiers() {
        let src: &str = "var greeting = 'hi'; console.log(greeting);";
        let (out, stats): (String, RenameStats) = rename(src);
        assert_eq!(stats.idents_renamed, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn determ_order_by_first_appearance() {
        let src1: &str = "var _0xff = 1; var _0xaa = 2;";
        let src2: &str = "var _0xff = 1; var _0xaa = 2;";
        let (out1, _): (String, RenameStats) = rename(src1);
        let (out2, _): (String, RenameStats) = rename(src2);
        assert_eq!(out1, out2);
        assert!(out1.starts_with("var var_1 = 1"));
    }

    #[test]
    fn handles_member_expression_field_overshoot() {
        let src: &str = "obj._0xabc = 1; var _0xabc = obj._0xabc;";
        let (out, stats): (String, RenameStats) = rename(src);
        assert_eq!(stats.idents_renamed, 1);
        assert!(out.contains("var_1"));
    }

    #[test]
    fn leaves_hex_names_inside_literals_and_comments_untouched() {
        for src in [
            r#"var doc = "var _0xdead = 1;";"#,
            "var doc = `var _0xdead = 1;`;",
            r"var re = /_0xdead/;",
            "// var _0xdead = 1;\nvar keep = 1;",
            "/* var _0xdead = 1; */ var keep = 1;",
        ] {
            let (out, stats): (String, RenameStats) = rename(src);
            assert_eq!(
                out, src,
                "{src}: a name inside quoted text is data, not a binding"
            );
            assert_eq!(stats.idents_renamed, 0);
            assert_eq!(stats.references_rewritten, 0);
        }
    }

    #[test]
    fn renames_code_occurrences_while_a_literal_keeps_the_original_spelling() {
        let src: &str = r#"var _0xab = 1; var doc = "_0xab"; console.log(_0xab, doc);"#;
        let (out, stats): (String, RenameStats) = rename(src);
        assert_eq!(stats.idents_renamed, 1);
        assert_eq!(stats.references_rewritten, 2);
        assert_eq!(
            out,
            r#"var var_1 = 1; var doc = "_0xab"; console.log(var_1, doc);"#
        );
    }
}
