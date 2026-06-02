use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sign {
    Pos,
    Neg,
}

#[must_use]
fn eval_int_term(term: &str) -> Option<i64> {
    let t: &str = term.trim();
    if let Some(rest) = t.strip_prefix("\\") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            return digits.parse::<i64>().ok();
        }
    }
    t.parse::<i64>().ok()
}

#[must_use]
pub fn eval_arith_expr(expr: &str) -> Option<i64> {
    let s: &str = expr.trim();
    let bytes: &[u8] = s.as_bytes();
    let mut acc: i64 = 0;
    let mut i: usize = 0;
    let mut sign: Sign = Sign::Pos;
    let mut have_term: bool = false;

    while i < bytes.len() {
        let ch: u8 = bytes[i];
        match ch {
            b' ' | b'\t' => {
                i += 1;
            }
            b'+' => {
                sign = Sign::Pos;
                i += 1;
            }
            b'-' => {
                sign = match sign {
                    Sign::Pos => Sign::Neg,
                    Sign::Neg => Sign::Pos,
                };
                i += 1;
            }
            b'(' => {
                let mut depth: i32 = 1;
                let start: usize = i + 1;
                let mut j: usize = start;
                while j < bytes.len() && depth > 0 {
                    match bytes[j] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                if depth != 0 {
                    return None;
                }
                let inner: &str = &s[start..j - 1];
                let value: i64 = eval_arith_expr(inner)?;
                let signed: i64 = match sign {
                    Sign::Pos => value,
                    Sign::Neg => value.checked_neg()?,
                };
                acc = acc.checked_add(signed)?;
                have_term = true;
                sign = Sign::Pos;
                i = j;
            }
            _ => {
                let start: usize = i;
                while i < bytes.len()
                    && !matches!(bytes[i], b'+' | b'-' | b'(' | b')' | b' ' | b'\t')
                {
                    i += 1;
                }
                let term: &str = &s[start..i];
                let value: i64 = eval_int_term(term)?;
                let signed: i64 = match sign {
                    Sign::Pos => value,
                    Sign::Neg => value.checked_neg()?,
                };
                acc = acc.checked_add(signed)?;
                have_term = true;
                sign = Sign::Pos;
            }
        }
    }
    if have_term { Some(acc) } else { None }
}

#[must_use]
fn unescape_lua_key(raw: &str) -> Option<char> {
    let t: &str = raw.trim();
    if let Some(stripped) = t.strip_prefix('"').and_then(|s: &str| s.strip_suffix('"')) {
        let inner: &str = stripped;
        if let Some(num) = inner.strip_prefix('\\') {
            let digits: String = num.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                let code: u32 = digits.parse::<u32>().ok()?;
                return char::from_u32(code);
            }
        }
        return inner.chars().next();
    }
    if t.chars().count() == 1 {
        return t.chars().next();
    }
    None
}

#[must_use]
pub fn parse_alphabet_table(table_body: &str) -> Option<BTreeMap<char, u8>> {
    let mut map: BTreeMap<char, u8> = BTreeMap::new();
    for entry in split_top_level(table_body) {
        let entry: &str = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key_part, value_part): (&str, &str) = split_key_value(entry)?;
        let key_char: char = if let Some(bracket) = key_part
            .trim()
            .strip_prefix('[')
            .and_then(|s: &str| s.strip_suffix(']'))
        {
            unescape_lua_key(bracket)?
        } else {
            let k: &str = key_part.trim();
            if k.len() == 1 {
                k.chars().next()?
            } else {
                continue;
            }
        };
        let value: i64 = eval_arith_expr(value_part)?;
        if (0..64).contains(&value) {
            map.insert(key_char, value as u8);
        }
    }
    if map.is_empty() { None } else { Some(map) }
}

#[must_use]
fn split_key_value(entry: &str) -> Option<(&str, &str)> {
    let bytes: &[u8] = entry.as_bytes();
    let mut depth: i32 = 0;
    let mut in_string: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => depth -= 1,
            b'=' if !in_string && depth == 0 => {
                if entry.as_bytes().get(i + 1) == Some(&b'=') {
                    i += 2;
                    continue;
                }
                return Some((&entry[..i], &entry[i + 1..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[must_use]
fn split_top_level(body: &str) -> Vec<&str> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut in_string: bool = false;
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'[' | b'(' | b'{' if !in_string => depth += 1,
            b']' | b')' | b'}' if !in_string => depth -= 1,
            b',' | b';' if !in_string && depth == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < body.len() {
        out.push(&body[start..]);
    }
    out
}

#[must_use]
pub fn parse_permutation_table(text: &str) -> Option<Vec<(usize, usize)>> {
    let marker: &str = "for p,W in ipairs({";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &str = &text[start..];
    let end: usize = match_outer_brace(rest)?;
    let body: &str = &rest[..end];
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for group in split_top_level(body) {
        let group: &str = group.trim();
        let inner: &str = group
            .strip_prefix('{')
            .and_then(|s: &str| s.strip_suffix('}'))?;
        let operands: Vec<&str> = split_top_level(inner);
        if operands.len() != 2 {
            return None;
        }
        let a: i64 = eval_arith_expr(operands[0])?;
        let b: i64 = eval_arith_expr(operands[1])?;
        if a < 1 || b < 1 {
            return None;
        }
        pairs.push((a as usize, b as usize));
    }
    if pairs.is_empty() { None } else { Some(pairs) }
}

#[must_use]
fn match_outer_brace(s: &str) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    let mut depth: i32 = 1;
    let mut in_string: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub fn apply_permutation<T>(pool: &mut [T], pairs: &[(usize, usize)]) {
    for &(a1, b1) in pairs {
        if a1 == 0 || b1 == 0 || a1 > pool.len() || b1 > pool.len() {
            continue;
        }
        let mut a: usize = a1 - 1;
        let mut b: usize = b1 - 1;
        while a < b {
            pool.swap(a, b);
            a += 1;
            b -= 1;
        }
    }
}

#[must_use]
pub fn decode_base64_variant(input: &str, alphabet: &BTreeMap<char, u8>) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut count: u32 = 0;
    let mut pad: u32 = 0;
    for ch in input.chars() {
        if ch == '=' {
            acc = acc.checked_shl(6)?;
            count += 1;
            pad += 1;
        } else {
            let v: u8 = *alphabet.get(&ch)?;
            acc = (acc << 6) | u32::from(v);
            count += 1;
        }
        if count == 4 {
            out.push(((acc >> 16) & 0xFF) as u8);
            if pad < 2 {
                out.push(((acc >> 8) & 0xFF) as u8);
            }
            if pad < 1 {
                out.push((acc & 0xFF) as u8);
            }
            acc = 0;
            count = 0;
            pad = 0;
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn eval_simple_addition() {
        assert_eq!(eval_arith_expr("-420555+420557"), Some(2));
        assert_eq!(eval_arith_expr("647705+-647658"), Some(47));
        assert_eq!(eval_arith_expr("-738443-(-738448)"), Some(5));
        assert_eq!(eval_arith_expr("978445-978405"), Some(40));
    }

    #[test]
    fn eval_nested_parens() {
        assert_eq!(eval_arith_expr("-1028400+1028449"), Some(49));
        assert_eq!(eval_arith_expr("-86280+86322"), Some(42));
        assert_eq!(eval_arith_expr("1-(2-(3))"), Some(2));
    }

    #[test]
    fn eval_rejects_garbage() {
        assert_eq!(eval_arith_expr(""), None);
        assert_eq!(eval_arith_expr("hello"), None);
    }

    #[test]
    fn parse_small_alphabet() {
        let body: &str = "Q=-420555+420557;[\"\\057\"]=-738443-(-738448);q=647705+-647658";
        let map: BTreeMap<char, u8> = parse_alphabet_table(body).expect("parse");
        assert_eq!(map.get(&'Q'), Some(&2));
        assert_eq!(map.get(&'9'), Some(&5));
        assert_eq!(map.get(&'q'), Some(&47));
    }

    #[test]
    fn base64_variant_standard_alphabet_decodes() {
        let std_alpha: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut map: BTreeMap<char, u8> = BTreeMap::new();
        for (i, ch) in std_alpha.chars().enumerate() {
            map.insert(ch, i as u8);
        }
        let decoded: Vec<u8> = decode_base64_variant("SGVsbG8=", &map).expect("decode");
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn base64_variant_two_pad() {
        let std_alpha: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut map: BTreeMap<char, u8> = BTreeMap::new();
        for (i, ch) in std_alpha.chars().enumerate() {
            map.insert(ch, i as u8);
        }
        let decoded: Vec<u8> = decode_base64_variant("TWE=", &map).expect("decode");
        assert_eq!(&decoded, b"Ma");
    }

    #[test]
    fn split_handles_nested_braces_and_strings() {
        let parts: Vec<&str> = split_top_level("a=1;[\"x;y\"]=2,b={1,2}");
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn parse_real_permutation_pairs() {
        let block: &str = "for p,W in ipairs({{-770075+770076,397966+-397911};{-961273+961274;-341840+341852},{-1025667-(-1025680);-317609+317664}})do";
        let pairs: Vec<(usize, usize)> = parse_permutation_table(block).expect("parse");
        assert_eq!(pairs, vec![(1, 55), (1, 12), (13, 55)]);
    }

    #[test]
    fn permutation_reverses_segments() {
        let mut pool: Vec<u32> = (1u32..=6).collect();
        apply_permutation(&mut pool, &[(1, 6)]);
        assert_eq!(pool, vec![6, 5, 4, 3, 2, 1]);
        let mut pool2: Vec<u32> = (1u32..=6).collect();
        apply_permutation(&mut pool2, &[(2, 5)]);
        assert_eq!(pool2, vec![1, 5, 4, 3, 2, 6]);
    }
}
