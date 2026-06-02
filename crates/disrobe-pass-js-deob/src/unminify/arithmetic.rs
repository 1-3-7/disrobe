use regex::{Captures, Regex};

const MAX_PASSES: usize = 16;

pub(super) fn fold_binary(source: &str) -> (String, usize) {
    let mut total: usize = 0;
    let mut current: String = source.to_owned();
    for _ in 0..MAX_PASSES {
        let (after_mul, mul_n): (String, usize) = fold_mul_div(&current);
        current = after_mul;
        total += mul_n;
        let (after_add, add_n): (String, usize) = fold_add_sub(&current);
        current = after_add;
        total += add_n;
        if mul_n == 0 && add_n == 0 {
            break;
        }
    }
    (current, total)
}

fn fold_mul_div(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(-?(?:0x[0-9a-fA-F]+|\d+))\s*([*/])\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let Some(lhs): Option<i64> = parse_int(&caps[1]) else {
            return caps[0].to_owned();
        };
        let Some(rhs): Option<i64> = parse_int(&caps[3]) else {
            return caps[0].to_owned();
        };
        let result: Option<i64> = match &caps[2] {
            "*" => lhs.checked_mul(rhs),
            "/" => {
                if rhs == 0 || lhs % rhs != 0 {
                    return caps[0].to_owned();
                }
                lhs.checked_div(rhs)
            }
            _ => None,
        };
        result.map_or_else(
            || caps[0].to_owned(),
            |v| {
                count += 1;
                v.to_string()
            },
        )
    });
    (out.into_owned(), count)
}

fn fold_add_sub(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(-?(?:0x[0-9a-fA-F]+|\d+))\s*([+\-])\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let Some(lhs): Option<i64> = parse_int(&caps[1]) else {
            return caps[0].to_owned();
        };
        let Some(rhs): Option<i64> = parse_int(&caps[3]) else {
            return caps[0].to_owned();
        };
        let result: Option<i64> = match &caps[2] {
            "+" => lhs.checked_add(rhs),
            "-" => lhs.checked_sub(rhs),
            _ => None,
        };
        result.map_or_else(
            || caps[0].to_owned(),
            |v| {
                count += 1;
                v.to_string()
            },
        )
    });
    (out.into_owned(), count)
}

pub(super) fn reverse_function_call(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"([a-zA-Z_$][\w$]*)\s*\.\s*call\s*\(\s*(null|undefined|this|0)\s*(,\s*([^)]*))?\)",
    ) else {
        return (source.to_owned(), 0);
    };
    let mut count: usize = 0;
    let out: std::borrow::Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        count += 1;
        let fn_name: &str = &caps[1];
        let rest: &str = caps.get(4).map_or("", |m| m.as_str());
        format!("{fn_name}({rest})")
    });
    (out.into_owned(), count)
}

fn parse_int(s: &str) -> Option<i64> {
    let trimmed: &str = s.trim();
    let Some(hex): Option<&str> = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("-0x"))
    else {
        return trimmed.parse::<i64>().ok();
    };
    let sign: i64 = if trimmed.starts_with('-') { -1 } else { 1 };
    i64::from_str_radix(hex, 16).ok().map(|v| sign * v)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fold_simple_add() {
        let (out, n): (String, usize) = fold_binary("var x = 5 + 3;");
        assert_eq!(out, "var x = 8;");
        assert_eq!(n, 1);
    }

    #[test]
    fn fold_with_precedence() {
        let (out, n): (String, usize) = fold_binary("var x = 5 + 3 * 2;");
        assert_eq!(out, "var x = 11;");
        assert!(n >= 2);
    }

    #[test]
    fn fold_obfuscator_io_pattern() {
        let (out, n): (String, usize) = fold_binary("var i = -0x1a70 + 0x93d + 0x275 * 0x7;");
        assert_eq!(out, "var i = 0;");
        assert!(n >= 2);
    }

    #[test]
    fn fold_subtract() {
        let (out, n): (String, usize) = fold_binary("var d = 100 - 42;");
        assert_eq!(out, "var d = 58;");
        assert_eq!(n, 1);
    }

    #[test]
    fn fold_preserves_non_int_args() {
        let (out, n): (String, usize) = fold_binary("var s = 'a' + 'b';");
        assert_eq!(out, "var s = 'a' + 'b';");
        assert_eq!(n, 0);
    }

    #[test]
    fn function_call_reversal_null_this() {
        let (out, n): (String, usize) = reverse_function_call("var k = f.call(null, 1, 2);");
        assert_eq!(out, "var k = f(1, 2);");
        assert_eq!(n, 1);
    }

    #[test]
    fn function_call_reversal_no_args() {
        let (out, n): (String, usize) = reverse_function_call("var k = greet.call(undefined);");
        assert_eq!(out, "var k = greet();");
        assert_eq!(n, 1);
    }

    #[test]
    fn function_call_no_match_on_non_literal_this() {
        let (out, n): (String, usize) = reverse_function_call("var k = f.call(obj, 1, 2);");
        assert_eq!(out, "var k = f.call(obj, 1, 2);");
        assert_eq!(n, 0);
    }
}
