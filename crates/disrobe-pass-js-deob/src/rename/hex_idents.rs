use indexmap::IndexMap;
use regex::{Captures, Regex};

use super::RenameStats;

pub(super) fn rename(source: &str) -> (String, RenameStats) {
    let mut stats: RenameStats = RenameStats::default();
    let Ok(ident_re): Result<Regex, regex::Error> = Regex::new(r"\b_0x[0-9a-fA-F]+\b") else {
        return (source.to_owned(), stats);
    };

    let mut order: IndexMap<String, String> = IndexMap::new();
    for cap in ident_re.captures_iter(source) {
        let Some(name): Option<String> = cap.get(0).map(|m| m.as_str().to_owned()) else {
            continue;
        };
        if !order.contains_key(&name) {
            let new: String = format!("var_{}", order.len() + 1);
            order.insert(name, new);
        }
    }
    stats.idents_renamed = order.len();

    let rewritten: std::borrow::Cow<'_, str> =
        ident_re.replace_all(source, |caps: &Captures<'_>| {
            if let Some(m) = caps.get(0)
                && let Some(new) = order.get(m.as_str())
            {
                stats.references_rewritten += 1;
                return new.clone();
            }
            caps[0].to_owned()
        });
    (rewritten.into_owned(), stats)
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
}
