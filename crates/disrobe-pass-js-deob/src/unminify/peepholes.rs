use regex::{Captures, Regex};

pub(super) fn reverse_bool_shorthand(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"!(0|1)\b") else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        count += 1;
        if &caps[1] == "0" { "true" } else { "false" }.to_owned()
    });
    (out.into_owned(), count)
}

pub(super) fn reverse_void_undefined(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\bvoid\s+0\b") else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |_: &Captures<'_>| {
        count += 1;
        "undefined".to_owned()
    });
    (out.into_owned(), count)
}

pub(super) fn reverse_double_not(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"!!\s*([a-zA-Z_$][\w$]*)") else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        count += 1;
        caps[1].to_owned()
    });
    (out.into_owned(), count)
}

pub(super) fn merge_string_concat(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"'([^'\\]*(?:\\.[^'\\]*)*)'\s*\+\s*'([^'\\]*(?:\\.[^'\\]*)*)'")
    else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        count += 1;
        let lhs: &str = &caps[1];
        let rhs: &str = &caps[2];
        format!("'{lhs}{rhs}'")
    });
    (out.into_owned(), count)
}

pub(super) fn dot_member_access(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"([\w$\)\]])\[\s*(?:'([A-Za-z_$][\w$]*)'|"([A-Za-z_$][\w$]*)")\s*\]"#)
    else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let Some(lead): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            return caps[0].to_owned();
        };
        let Some(prop): Option<&str> = caps.get(2).or_else(|| caps.get(3)).map(|m| m.as_str())
        else {
            return caps[0].to_owned();
        };
        count += 1;
        format!("{lead}.{prop}")
    });
    (out.into_owned(), count)
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
