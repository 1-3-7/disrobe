use regex::{Captures, Regex};
use serde::Serialize;

use crate::scan_utils::replace_in_code;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct ProtectionStripStats {
    pub(super) if_true_inlined: usize,
    pub(super) if_false_eliminated: usize,
    pub(super) debugger_loops_removed: usize,
    pub(super) set_interval_watchdogs_removed: usize,
    pub(super) function_debugger_removed: usize,
    pub(super) self_defending_iifes_removed: usize,
}

pub(super) fn strip_protection(source: &str) -> (String, ProtectionStripStats) {
    let mut stats: ProtectionStripStats = ProtectionStripStats::default();
    let mut current: String = source.to_owned();

    let (next, n): (String, usize) = remove_if_true_blocks(&current);
    current = next;
    stats.if_true_inlined += n;

    let (next, n): (String, usize) = remove_if_false_blocks(&current);
    current = next;
    stats.if_false_eliminated += n;

    let (next, n): (String, usize) = remove_debugger_setinterval(&current);
    current = next;
    stats.set_interval_watchdogs_removed += n;

    let (next, n): (String, usize) = remove_function_debugger_call(&current);
    current = next;
    stats.function_debugger_removed += n;

    let (next, n): (String, usize) = remove_lone_debugger_iife(&current);
    current = next;
    stats.debugger_loops_removed += n;

    let (next, n): (String, usize) = remove_self_defending_iife(&current);
    current = next;
    stats.self_defending_iifes_removed += n;

    (current, stats)
}

fn remove_if_true_blocks(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?ms)\bif\s*\(\s*true\s*\)\s*\{([^{}]*)\}(\s*else\s*\{[^{}]*\})?")
    else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        Some(caps.get(1)?.as_str().trim().to_owned())
    })
}

fn remove_if_false_blocks(source: &str) -> (String, usize) {
    let mut count: usize = 0;
    let Ok(with_else): Result<Regex, regex::Error> =
        Regex::new(r"(?ms)\bif\s*\(\s*false\s*\)\s*\{[^{}]*\}\s*else\s*\{([^{}]*)\}")
    else {
        return (source.to_owned(), 0);
    };
    let (intermediate, with_else_count): (String, usize) =
        replace_in_code(source, &with_else, |caps: &Captures<'_>| {
            Some(caps.get(1)?.as_str().trim().to_owned())
        });
    count += with_else_count;

    let Ok(without_else): Result<Regex, regex::Error> =
        Regex::new(r"(?ms)\bif\s*\(\s*false\s*\)\s*\{[^{}]*\}")
    else {
        return (intermediate, count);
    };
    let (stage2, without_else_count): (String, usize) =
        replace_in_code(&intermediate, &without_else, |_: &Captures<'_>| {
            Some(String::new())
        });
    (stage2, count + without_else_count)
}

fn remove_debugger_setinterval(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"(?ms)setInterval\s*\(\s*function\s*\(\s*\)\s*\{\s*debugger\s*;?\s*\}\s*,\s*[^)]+\)\s*;?",
    ) else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |_: &Captures<'_>| Some(String::new()))
}

fn remove_function_debugger_call(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)Function\s*\(\s*['"]debu['"]\s*\+\s*['"]gger['"]\s*\)\s*\.\s*call\s*\([^)]*\)\s*;?"#,
    ) else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |_: &Captures<'_>| Some(String::new()))
}

fn remove_lone_debugger_iife(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?ms)\(\s*function\s*\(\s*\)\s*\{\s*debugger\s*;?\s*\}\s*\)\s*\(\s*\)\s*;?")
    else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |_: &Captures<'_>| Some(String::new()))
}

fn remove_self_defending_iife(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)\(\s*function\s*\([^)]*\)\s*\{[^{}]*RegExp[^{}]*\.\s*test\s*\([^{}]*['"](?:init|updateProtect)['"][^{}]*\}\s*\)\s*\([^;]*\)\s*;?"#,
    ) else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |_: &Captures<'_>| Some(String::new()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn guard_shaped_text_inside_a_literal_or_comment_survives() {
        let quoted: &str =
            r#"var doc = "setInterval(function () { debugger; }, 4000); if (false) { dead(); }";"#;
        let (out, stats): (String, ProtectionStripStats) = strip_protection(quoted);
        assert_eq!(out, quoted);
        assert_eq!(stats, ProtectionStripStats::default());
        let commented: &str = "/* setInterval(function(){debugger;}, 1000); */\nreal();";
        let (out, stats): (String, ProtectionStripStats) = strip_protection(commented);
        assert_eq!(out, commented);
        assert_eq!(stats.set_interval_watchdogs_removed, 0);
    }

    #[test]
    fn if_true_inlines_body() {
        let (out, n): (String, usize) =
            remove_if_true_blocks("if (true) { foo(); } else { bar(); }\nbaz();");
        assert!(out.contains("foo();"));
        assert!(!out.contains("bar();"));
        assert!(out.contains("baz();"));
        assert_eq!(n, 1);
    }

    #[test]
    fn if_false_with_else_picks_else() {
        let (out, n): (String, usize) =
            remove_if_false_blocks("if (false) { foo(); } else { bar(); }");
        assert!(out.contains("bar();"));
        assert!(!out.contains("foo();"));
        assert_eq!(n, 1);
    }

    #[test]
    fn if_false_without_else_drops_block() {
        let (out, n): (String, usize) =
            remove_if_false_blocks("before();\nif (false) { dead(); }\nafter();");
        assert!(!out.contains("dead();"));
        assert!(out.contains("before();"));
        assert!(out.contains("after();"));
        assert_eq!(n, 1);
    }

    #[test]
    fn debugger_setinterval_removed() {
        let src: &str = "var x = 1;\nsetInterval(function(){debugger;}, 4000);\nvar y = 2;";
        let (out, n): (String, usize) = remove_debugger_setinterval(src);
        assert_eq!(n, 1);
        assert!(!out.contains("setInterval"));
        assert!(out.contains("var x = 1;"));
        assert!(out.contains("var y = 2;"));
    }

    #[test]
    fn function_debugger_concat_call_removed() {
        let src: &str = r#"a();Function("debu"+"gger").call(this);b();"#;
        let (out, n): (String, usize) = remove_function_debugger_call(src);
        assert_eq!(n, 1);
        assert!(!out.contains("debugger"));
        assert!(!out.contains("Function(\"debu\""));
        assert!(out.contains("a();"));
        assert!(out.contains("b();"));
    }

    #[test]
    fn lone_debugger_iife_removed() {
        let (out, n): (String, usize) =
            remove_lone_debugger_iife("(function(){debugger;})();\nrest();");
        assert_eq!(n, 1);
        assert!(!out.contains("debugger"));
        assert!(out.contains("rest();"));
    }

    #[test]
    fn full_pipeline_excises_all() {
        let src: &str = r#"
            if (true) { console.log('keep'); }
            if (false) { console.log('drop'); }
            setInterval(function(){debugger;}, 1000);
            Function("debu"+"gger").call(this);
            real_work();
        "#;
        let (out, stats): (String, ProtectionStripStats) = strip_protection(src);
        assert!(out.contains("'keep'"));
        assert!(!out.contains("'drop'"));
        assert!(!out.contains("debugger"));
        assert!(out.contains("real_work()"));
        assert!(stats.if_true_inlined + stats.if_false_eliminated >= 2);
        assert!(stats.set_interval_watchdogs_removed >= 1);
        assert!(stats.function_debugger_removed >= 1);
    }
}
