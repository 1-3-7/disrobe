use regex::{Captures, Regex};

use crate::scan_utils::{SpanScope, replace_in_code, replace_in_scope};

pub(super) fn reverse_bool_shorthand(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"!(0|1)\b") else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        let digit: &str = caps.get(1)?.as_str();
        Some(if digit == "0" { "true" } else { "false" }.to_owned())
    })
}

pub(super) fn reverse_void_undefined(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\bvoid\s+0\b") else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |_: &Captures<'_>| Some("undefined".to_owned()))
}

pub(super) fn reverse_double_not(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"!!\s*([a-zA-Z_$][\w$]*)") else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        Some(caps.get(1)?.as_str().to_owned())
    })
}

pub(super) fn merge_string_concat(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"'([^'\\]*(?:\\.[^'\\]*)*)'\s*\+\s*'([^'\\]*(?:\\.[^'\\]*)*)'")
    else {
        return (source.to_owned(), 0);
    };
    replace_in_scope(
        source,
        &re,
        SpanScope::CodeOrWholeLiteral,
        |caps: &Captures<'_>| {
            let lhs: &str = caps.get(1)?.as_str();
            let rhs: &str = caps.get(2)?.as_str();
            Some(format!("'{lhs}{rhs}'"))
        },
    )
}

pub(super) fn dot_member_access(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"([\w$\)\]])\[\s*(?:'([A-Za-z_$][\w$]*)'|"([A-Za-z_$][\w$]*)")\s*\]"#)
    else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        let lead: &str = caps.get(1)?.as_str();
        let prop: &str = caps.get(2).or_else(|| caps.get(3))?.as_str();
        Some(format!("{lead}.{prop}"))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bool_shorthand_basic() {
        let (out, n): (String, usize) =
            reverse_bool_shorthand("if (!0) console.log('hi'); else if (!1) bye();");
        assert_eq!(out, "if (true) console.log('hi'); else if (false) bye();");
        assert_eq!(n, 2);
    }

    #[test]
    fn bool_shorthand_no_false_positive_on_neq() {
        let (out, n): (String, usize) = reverse_bool_shorthand("a !== 0");
        assert_eq!(out, "a !== 0");
        assert_eq!(n, 0);
    }

    #[test]
    fn void_zero_reversal() {
        let (out, n): (String, usize) = reverse_void_undefined("var x = void 0;");
        assert_eq!(out, "var x = undefined;");
        assert_eq!(n, 1);
    }

    #[test]
    fn double_not_strips_around_identifier() {
        let (out, n): (String, usize) = reverse_double_not("return !!ok && !!ready;");
        assert_eq!(out, "return ok && ready;");
        assert_eq!(n, 2);
    }

    #[test]
    fn string_concat_merge() {
        let (out, n): (String, usize) = merge_string_concat("var s = 'foo' + 'bar';");
        assert_eq!(out, "var s = 'foobar';");
        assert_eq!(n, 1);
    }

    #[test]
    fn dot_member_basic() {
        let (out, n): (String, usize) = dot_member_access("obj['toString']()");
        assert_eq!(out, "obj.toString()");
        assert_eq!(n, 1);
    }

    #[test]
    fn dot_member_after_call_and_index() {
        let (out, n): (String, usize) = dot_member_access("foo()['bar'] + arr[0]['baz']");
        assert_eq!(out, "foo().bar + arr[0].baz");
        assert_eq!(n, 2);
    }

    #[test]
    fn dot_member_leaves_array_literal_alone() {
        let (out, n): (String, usize) = dot_member_access("var a = ['x', 'y'];");
        assert_eq!(out, "var a = ['x', 'y'];");
        assert_eq!(n, 0);
    }

    #[test]
    fn dot_member_leaves_numeric_and_dynamic_index() {
        let (out, n): (String, usize) = dot_member_access("a['0'] + b[key] + c['has-dash']");
        assert_eq!(out, "a['0'] + b[key] + c['has-dash']");
        assert_eq!(n, 0);
    }

    #[test]
    fn dot_member_chained_fix_point() {
        let mut s: String = "a['b']['c']['d']".to_owned();
        for _ in 0..4 {
            let (out, n): (String, usize) = dot_member_access(&s);
            s = out;
            if n == 0 {
                break;
            }
        }
        assert_eq!(s, "a.b.c.d");
    }

    #[test]
    fn peepholes_leave_matching_text_inside_a_string_literal_untouched() {
        let quoted: &str = r#"var s = "if (!0) obj['toString']() + void 0 + !!ok";"#;
        for rewrite in [
            reverse_bool_shorthand,
            reverse_void_undefined,
            reverse_double_not,
            dot_member_access,
        ] {
            let (out, n): (String, usize) = rewrite(quoted);
            assert_eq!(out, quoted);
            assert_eq!(n, 0);
        }
    }

    #[test]
    fn peepholes_leave_matching_text_inside_a_comment_or_regex_literal_untouched() {
        let commented: &str = "// if (!0) obj['toString']()\nvar keep = 1;";
        let (out, n): (String, usize) = dot_member_access(commented);
        assert_eq!(out, commented);
        assert_eq!(n, 0);
        let pattern: &str = r"var re = /obj\['toString'\]/;";
        let (out, n): (String, usize) = dot_member_access(pattern);
        assert_eq!(out, pattern);
        assert_eq!(n, 0);
    }

    #[test]
    fn concat_merge_leaves_a_nested_quotation_untouched() {
        let nested: &str = r#"var s = "the source reads 'foo' + 'bar' verbatim";"#;
        let (out, n): (String, usize) = merge_string_concat(nested);
        assert_eq!(out, nested);
        assert_eq!(n, 0);
    }

    #[test]
    fn string_concat_chained_fix_point() {
        let mut s: String = "var s = 'a' + 'b' + 'c';".to_owned();
        let mut total: usize = 0;
        for _ in 0..4 {
            let (out, n): (String, usize) = merge_string_concat(&s);
            s = out;
            total += n;
            if n == 0 {
                break;
            }
        }
        assert_eq!(s, "var s = 'abc';");
        assert_eq!(total, 2);
    }
}
