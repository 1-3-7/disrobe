use std::ops::Range;

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

fn replace_in_code(
    source: &str,
    re: &Regex,
    mut fold: impl FnMut(&Captures<'_>) -> Option<String>,
) -> (String, usize) {
    let skips: Vec<Range<usize>> = skip_ranges(source);
    let mut out: String = String::with_capacity(source.len());
    let mut last: usize = 0;
    let mut count: usize = 0;
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        if overlaps_skip(&skips, whole.start(), whole.end()) {
            continue;
        }
        let Some(replacement): Option<String> = fold(&caps) else {
            continue;
        };
        out.push_str(&source[last..whole.start()]);
        out.push_str(&replacement);
        last = whole.end();
        count += 1;
    }
    out.push_str(&source[last..]);
    (out, count)
}

fn overlaps_skip(skips: &[Range<usize>], start: usize, end: usize) -> bool {
    skips.iter().any(|r| start < r.end && r.start < end)
}

fn skip_ranges(source: &str) -> Vec<Range<usize>> {
    let bytes: &[u8] = source.as_bytes();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut i: usize = 0;
    let mut prev_significant: u8 = b';';
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_quoted(bytes, i, b);
                ranges.push(i..end);
                prev_significant = b;
                i = end;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                let end: usize = skip_line_comment(bytes, i);
                ranges.push(i..end);
                i = end;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let end: usize = skip_block_comment(bytes, i);
                ranges.push(i..end);
                i = end;
                continue;
            }
            b'/' if regex_allowed(prev_significant) => {
                let end: usize = skip_regex(bytes, i);
                ranges.push(i..end);
                prev_significant = b'/';
                i = end;
                continue;
            }
            _ => {}
        }
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            prev_significant = b;
        }
        i += 1;
    }
    ranges
}

fn fold_mul_div(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(-?(?:0x[0-9a-fA-F]+|\d+))\s*([*/])\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        let whole: regex::Match<'_> = caps.get(0)?;
        if !fold_pair_is_safe(
            source.as_bytes(),
            whole.start(),
            whole.end(),
            &caps[1],
            false,
        ) {
            return None;
        }
        let lhs: i64 = parse_int(&caps[1])?;
        let rhs: i64 = parse_int(&caps[3])?;
        let result: Option<i64> = match &caps[2] {
            "*" => lhs.checked_mul(rhs),
            "/" => {
                if rhs == 0 || lhs % rhs != 0 {
                    return None;
                }
                lhs.checked_div(rhs)
            }
            _ => None,
        };
        result.map(|v: i64| v.to_string())
    })
}

fn fold_add_sub(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(-?(?:0x[0-9a-fA-F]+|\d+))\s*([+\-])\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        let whole: regex::Match<'_> = caps.get(0)?;
        if !fold_pair_is_safe(
            source.as_bytes(),
            whole.start(),
            whole.end(),
            &caps[1],
            true,
        ) {
            return None;
        }
        let lhs: i64 = parse_int(&caps[1])?;
        let rhs: i64 = parse_int(&caps[3])?;
        let result: Option<i64> = match &caps[2] {
            "+" => lhs.checked_add(rhs),
            "-" => lhs.checked_sub(rhs),
            _ => None,
        };
        result.map(|v: i64| v.to_string())
    })
}

pub(super) fn reverse_function_call(source: &str) -> (String, usize) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"([a-zA-Z_$][\w$]*)\s*\.\s*call\s*\(\s*(null|undefined|this|0)\s*(,\s*([^)]*))?\)",
    ) else {
        return (source.to_owned(), 0);
    };
    replace_in_code(source, &re, |caps: &Captures<'_>| {
        let fn_name: &str = &caps[1];
        let rest: &str = caps.get(4).map_or("", |m: regex::Match<'_>| m.as_str());
        Some(format!("{fn_name}({rest})"))
    })
}

pub(super) fn decimalize_radix_literals(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut count: usize = 0;
    let mut i: usize = 0;
    let mut prev_significant: u8 = b';';
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_quoted(bytes, i, b);
                out.push_str(&source[i..end]);
                prev_significant = b;
                i = end;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                let end: usize = skip_line_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let end: usize = skip_block_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
                continue;
            }
            b'/' if regex_allowed(prev_significant) => {
                let end: usize = skip_regex(bytes, i);
                out.push_str(&source[i..end]);
                prev_significant = b'/';
                i = end;
                continue;
            }
            _ => {}
        }
        if b == b'0'
            && i + 1 < bytes.len()
            && matches!(bytes[i + 1], b'x' | b'X' | b'o' | b'O' | b'b' | b'B')
            && !is_ident_byte(prev_significant)
            && prev_significant != b'.'
            && let Some((end, decimal)) = read_radix_literal(bytes, i)
        {
            out.push_str(&decimal);
            count += 1;
            prev_significant = b'0';
            i = end;
            continue;
        }
        out.push(b as char);
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            prev_significant = b;
        }
        i += 1;
    }
    (out, count)
}

fn read_radix_literal(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    let radix: u32 = match bytes[start + 1] {
        b'x' | b'X' => 16,
        b'o' | b'O' => 8,
        _ => 2,
    };
    let mut j: usize = start + 2;
    let digit_start: usize = j;
    while j < bytes.len() && is_radix_digit(bytes[j], radix) {
        j += 1;
    }
    if j == digit_start {
        return None;
    }
    if j < bytes.len() && (is_ident_byte(bytes[j]) || bytes[j] == b'n' || bytes[j] == b'.') {
        return None;
    }
    let digits: &str = std::str::from_utf8(&bytes[digit_start..j]).ok()?;
    let value: i64 = i64::from_str_radix(digits, radix).ok()?;
    Some((j, value.to_string()))
}

const fn is_radix_digit(b: u8, radix: u32) -> bool {
    match radix {
        16 => b.is_ascii_hexdigit(),
        8 => b.is_ascii_digit() && b <= b'7',
        _ => b == b'0' || b == b'1',
    }
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

const fn regex_allowed(prev: u8) -> bool {
    matches!(
        prev,
        b'(' | b','
            | b'='
            | b':'
            | b'['
            | b'!'
            | b'&'
            | b'|'
            | b'?'
            | b'{'
            | b'}'
            | b';'
            | b'+'
            | b'-'
            | b'*'
            | b'%'
            | b'<'
            | b'>'
            | b'~'
            | b'^'
            | b'\n'
            | b'\r'
    )
}

fn skip_quoted(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_regex(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 1;
    let mut in_class: bool = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                return i;
            }
            b'\n' => return start + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn fold_pair_is_safe(bytes: &[u8], start: usize, end: usize, lhs: &str, additive: bool) -> bool {
    if let Some(prev) = start.checked_sub(1)
        && let Some(&b) = bytes.get(prev)
        && (is_ident_byte(b) || b == b'.')
    {
        return false;
    }
    if let Some(&b) = bytes.get(end)
        && (is_ident_byte(b) || b == b'.')
    {
        return false;
    }
    let before_sig: Option<u8> = significant_left(bytes, start);
    let (after_sig, after_sig2): (Option<u8>, Option<u8>) = significant_right(bytes, end);
    let signed: bool = matches!(lhs.trim_start().as_bytes().first(), Some(b'-' | b'+'));
    if signed
        && let Some(b) = before_sig
        && is_value_end(b)
    {
        return false;
    }
    if additive {
        if matches!(before_sig, Some(b'+' | b'-' | b'*' | b'/' | b'%')) {
            return false;
        }
        if matches!(after_sig, Some(b'*' | b'/' | b'%')) {
            return false;
        }
    } else {
        if matches!(before_sig, Some(b'*' | b'/' | b'%')) {
            return false;
        }
        if after_sig == Some(b'*') && after_sig2 == Some(b'*') {
            return false;
        }
    }
    true
}

fn significant_left(bytes: &[u8], start: usize) -> Option<u8> {
    let mut i: usize = start;
    while i > 0 {
        i -= 1;
        let b: u8 = bytes[i];
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            return Some(b);
        }
    }
    None
}

fn significant_right(bytes: &[u8], end: usize) -> (Option<u8>, Option<u8>) {
    let mut i: usize = end;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    (bytes.get(i).copied(), bytes.get(i + 1).copied())
}

const fn is_value_end(b: u8) -> bool {
    is_ident_byte(b) || matches!(b, b')' | b']' | b'}' | b'.' | b'`' | b'\'' | b'"')
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

    #[test]
    fn fold_leaves_regex_char_class_untouched() {
        let (out, n): (String, usize) = fold_binary("var s = w.replace(/[^a-z0-9]/gi, '');");
        assert_eq!(out, "var s = w.replace(/[^a-z0-9]/gi, '');");
        assert_eq!(n, 0);
    }

    #[test]
    fn fold_leaves_arithmetic_inside_string_literal_untouched() {
        let (out, n): (String, usize) = fold_binary("var s = '5 + 3';");
        assert_eq!(out, "var s = '5 + 3';");
        assert_eq!(n, 0);
    }

    #[test]
    fn fold_still_applies_to_real_code_beside_a_regex() {
        let (out, n): (String, usize) = fold_binary("var re = /a-z0-9/; var x = 5 + 3;");
        assert_eq!(out, "var re = /a-z0-9/; var x = 8;");
        assert_eq!(n, 1);
    }

    #[test]
    fn fold_leaves_higher_precedence_neighbor_untouched() {
        for input in [
            "var y = 2 + 3 * x;",
            "var y = x * 2 + 1;",
            "var y = 2 + 3 % x;",
            "var y = 2 + 3 ** x;",
            "var y = x % 2 + 3;",
        ] {
            let (out, n): (String, usize) = fold_binary(input);
            assert_eq!(out, input, "must not cross multiplicative precedence");
            assert_eq!(n, 0);
        }
    }

    #[test]
    fn fold_preserves_left_associativity_with_variable() {
        for input in [
            "var y = x - 2 + 3;",
            "var y = a + 2 + 3;",
            "var y = x / 2 * 4;",
        ] {
            let (out, n): (String, usize) = fold_binary(input);
            assert_eq!(out, input, "must not re-associate around a variable");
            assert_eq!(n, 0);
        }
    }

    #[test]
    fn fold_does_not_read_binary_minus_as_a_sign() {
        let (out, n): (String, usize) = fold_binary("var y = x-2+3;");
        assert_eq!(out, "var y = x-2+3;");
        assert_eq!(n, 0);
    }

    #[test]
    fn fold_does_not_split_an_identifier_ending_in_digits() {
        let (out, n): (String, usize) = fold_binary("var z = x2 + 3;");
        assert_eq!(out, "var z = x2 + 3;");
        assert_eq!(n, 0);
    }

    #[test]
    fn fold_does_not_absorb_a_decimal_or_exponent_tail() {
        for input in ["var y = 2 + 3.5;", "var y = 2 * 3e5;", "var y = 2 + 3n;"] {
            let (out, n): (String, usize) = fold_binary(input);
            assert_eq!(
                out, input,
                "must not fold across a fractional/exponent/bigint tail"
            );
            assert_eq!(n, 0);
        }
    }

    #[test]
    fn fold_still_collapses_leftmost_safe_pair() {
        let (out, n): (String, usize) = fold_binary("var y = 8 / 2 * x;");
        assert_eq!(out, "var y = 4 * x;");
        assert_eq!(n, 1);
    }

    #[test]
    fn fold_still_folds_when_outer_operator_is_looser() {
        let (out, n): (String, usize) = fold_binary("var y = x << 2 + 3;");
        assert_eq!(out, "var y = x << 5;");
        assert_eq!(n, 1);
    }
}
