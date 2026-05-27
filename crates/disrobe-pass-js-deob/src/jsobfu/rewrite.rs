use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JsObfuRewriteStats {
    pub bracket_to_dot_rewrites: usize,
    pub array_join_folded: usize,
}

static KNOWN_GLOBAL_LHS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "Array",
        "ArrayBuffer",
        "Boolean",
        "console",
        "Date",
        "document",
        "Error",
        "globalThis",
        "JSON",
        "localStorage",
        "Map",
        "Math",
        "navigator",
        "Number",
        "Object",
        "Promise",
        "Reflect",
        "RegExp",
        "Set",
        "sessionStorage",
        "String",
        "Symbol",
        "TypeError",
        "Uint8Array",
        "URL",
        "WeakMap",
        "WeakSet",
        "window",
    ]
    .into_iter()
    .collect()
});

fn try_regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

pub fn rewrite_bracket_access(source: &str) -> (String, JsObfuRewriteStats) {
    let mut stats: JsObfuRewriteStats = JsObfuRewriteStats::default();
    let after_join: String = fold_array_join(source, &mut stats);
    let after_bracket: String = fold_bracket_to_dot(&after_join, &mut stats);
    (after_bracket, stats)
}

fn fold_bracket_to_dot(source: &str, stats: &mut JsObfuRewriteStats) -> String {
    let Some(re): Option<Regex> = try_regex(
        r#"([A-Za-z_$][A-Za-z0-9_$]*)\[(?:'([A-Za-z_$][A-Za-z0-9_$]*)'|"([A-Za-z_$][A-Za-z0-9_$]*)")\]"#,
    ) else {
        return source.to_owned();
    };
    let replaced: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let Some(lhs): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            return caps[0].to_owned();
        };
        if !KNOWN_GLOBAL_LHS.contains(lhs) {
            return caps[0].to_owned();
        }
        let Some(prop): Option<&str> = caps.get(2).or_else(|| caps.get(3)).map(|m| m.as_str())
        else {
            return caps[0].to_owned();
        };
        stats.bracket_to_dot_rewrites += 1;
        format!("{lhs}.{prop}")
    });
    replaced.into_owned()
}

fn fold_array_join(source: &str, stats: &mut JsObfuRewriteStats) -> String {
    let Some(re): Option<Regex> = try_regex(
        r#"\[\s*((?:'[^'\\]'|"[^"\\]")(?:\s*,\s*(?:'[^'\\]'|"[^"\\]"))*)\s*\]\s*\[\s*(?:'join'|"join")\s*\]\s*\(\s*(?:''|"")\s*\)"#,
    ) else {
        return source.to_owned();
    };
    let Some(char_re): Option<Regex> = try_regex(r#"'([^'\\])'|"([^"\\])""#) else {
        return source.to_owned();
    };
    let replaced: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let Some(body): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            return caps[0].to_owned();
        };
        let mut s: String = String::new();
        for ch_cap in char_re.captures_iter(body) {
            if let Some(m) = ch_cap.get(1).or_else(|| ch_cap.get(2)) {
                s.push_str(m.as_str());
            }
        }
        stats.array_join_folded += 1;
        format!("'{s}'")
    });
    replaced.into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_known_global_bracket_to_dot() {
        let src: &str = "console['log'](Math['floor'](1.5));";
        let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(src);
        assert!(out.contains("console.log"));
        assert!(out.contains("Math.floor"));
        assert!(stats.bracket_to_dot_rewrites >= 2);
    }

    #[test]
    fn skips_unknown_lhs() {
        let src: &str = "myObj['secret']();";
        let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(src);
        assert_eq!(out, src);
        assert_eq!(stats.bracket_to_dot_rewrites, 0);
    }

    #[test]
    fn folds_array_join_to_literal() {
        let src: &str = "var s = ['h','e','l','l','o']['join']('');";
        let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(src);
        assert!(out.contains("'hello'"), "got: {out}");
        assert_eq!(stats.array_join_folded, 1);
    }

    #[test]
    fn combined_rewrite_pipeline() {
        let src: &str = "window['eval'](['a','l','e','r','t','(','1',')']['join'](''));";
        let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(src);
        assert!(out.contains("window.eval"));
        assert!(out.contains("'alert(1)'"));
        assert!(stats.bracket_to_dot_rewrites >= 1);
        assert_eq!(stats.array_join_folded, 1);
    }
}
