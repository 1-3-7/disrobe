use std::collections::BTreeMap;

use disrobe_core::codec::{Base64Alphabet, Base64Padding, base64_decode};

struct ArithParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ArithParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn parse_additive(&mut self) -> Option<i64> {
        let mut acc: i64 = self.parse_mul()?;
        loop {
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b'+') => {
                    self.pos += 1;
                    let rhs: i64 = self.parse_mul()?;
                    acc = acc.checked_add(rhs)?;
                }
                Some(b'-') => {
                    self.pos += 1;
                    let rhs: i64 = self.parse_mul()?;
                    acc = acc.checked_sub(rhs)?;
                }
                _ => return Some(acc),
            }
        }
    }

    fn parse_mul(&mut self) -> Option<i64> {
        let mut acc: i64 = self.parse_unary()?;
        loop {
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b'%') => {
                    self.pos += 1;
                    let rhs: i64 = self.parse_unary()?;
                    acc = lua_floor_mod(acc, rhs)?;
                }
                Some(b'*') => {
                    self.pos += 1;
                    let rhs: i64 = self.parse_unary()?;
                    acc = acc.checked_mul(rhs)?;
                }
                _ => return Some(acc),
            }
        }
    }

    fn parse_unary(&mut self) -> Option<i64> {
        self.skip_ws();
        match self.bytes.get(self.pos) {
            Some(b'-') => {
                self.pos += 1;
                self.parse_unary()?.checked_neg()
            }
            Some(b'+') => {
                self.pos += 1;
                self.parse_unary()
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Option<i64> {
        self.skip_ws();
        match self.bytes.get(self.pos) {
            Some(b'(') => {
                self.pos += 1;
                let inner: i64 = self.parse_additive()?;
                self.skip_ws();
                if self.bytes.get(self.pos) != Some(&b')') {
                    return None;
                }
                self.pos += 1;
                Some(inner)
            }
            Some(b'\\') => {
                self.pos += 1;
                self.parse_digits()
            }
            Some(c) if c.is_ascii_digit() => self.parse_digits(),
            _ => None,
        }
    }

    fn parse_digits(&mut self) -> Option<i64> {
        let start: usize = self.pos;
        while matches!(self.bytes.get(self.pos), Some(d) if d.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        core::str::from_utf8(&self.bytes[start..self.pos])
            .ok()?
            .parse::<i64>()
            .ok()
    }
}

#[must_use]
fn lua_floor_mod(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        return None;
    }
    let r: i64 = a.checked_rem(b)?;
    if r != 0 && (r < 0) != (b < 0) {
        r.checked_add(b)
    } else {
        Some(r)
    }
}

#[must_use]
pub fn eval_arith_expr(expr: &str) -> Option<i64> {
    let s: &str = expr.trim();
    if s.is_empty() {
        return None;
    }
    let mut parser: ArithParser<'_> = ArithParser::new(s);
    let value: i64 = parser.parse_additive()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return None;
    }
    Some(value)
}

#[must_use]
fn unescape_lua_key(raw: &str) -> Option<char> {
    let t: &str = raw.trim();
    if let Some(inner) = t
        .strip_prefix('"')
        .and_then(|s: &str| s.strip_suffix('"'))
        .or_else(|| {
            t.strip_prefix('\'')
                .and_then(|s: &str| s.strip_suffix('\''))
        })
    {
        if let Some(escaped) = inner.strip_prefix('\\') {
            let digits: String = escaped.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                let code: u32 = digits.parse::<u32>().ok()?;
                return char::from_u32(code);
            }
            return escaped.chars().next().map(|c: char| match c {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'a' => '\x07',
                'b' => '\x08',
                'f' => '\x0C',
                'v' => '\x0B',
                other => other,
            });
        }
        return inner.chars().next();
    }
    if t.chars().count() == 1 {
        return t.chars().next();
    }
    None
}

#[must_use]
pub fn extract_named_table_body<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let marker: String = format!("local {name}={{");
    let start: usize = text.find(&marker)? + marker.len();
    let rest: &str = &text[start..];
    let end: usize = match_outer_brace_escaped(rest)?;
    Some(&rest[..end])
}

#[must_use]
pub fn first_wrapped_table_name(text: &str) -> Option<char> {
    let marker: &str = "return(function(...)local ";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &str = &text[start..];
    let mut chars: core::str::Chars<'_> = rest.chars();
    let name: char = chars.next()?;
    if !name.is_ascii_alphabetic() {
        return None;
    }
    if chars.next() != Some('=') || chars.next() != Some('{') {
        return None;
    }
    Some(name)
}

#[must_use]
pub fn discover_base64_alphabets(text: &str) -> Vec<(char, BTreeMap<char, u8>)> {
    let mut out: Vec<(char, BTreeMap<char, u8>)> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let needle: &[u8] = b"local ";
    let mut i: usize = 0;
    while i + needle.len() + 2 < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let name_b: u8 = bytes[i + needle.len()];
            let eq_b: u8 = bytes[i + needle.len() + 1];
            let brace_b: u8 = bytes[i + needle.len() + 2];
            if name_b.is_ascii_alphabetic() && eq_b == b'=' && brace_b == b'{' {
                let name: char = name_b as char;
                if let Some(body) = extract_named_table_body(text, &name.to_string())
                    && let Some(map) = parse_alphabet_table(body)
                    && is_full_base64_permutation(&map)
                {
                    out.push((name, map));
                }
            }
        }
        i += 1;
    }
    out
}

#[must_use]
fn is_full_base64_permutation(map: &BTreeMap<char, u8>) -> bool {
    is_full_radix_permutation(map, 64)
}

#[must_use]
fn is_full_radix_permutation(map: &BTreeMap<char, u8>, radix: usize) -> bool {
    if map.len() != radix {
        return false;
    }
    let mut seen: Vec<bool> = vec![false; radix];
    for &v in map.values() {
        let idx: usize = v as usize;
        if idx >= radix || seen[idx] {
            return false;
        }
        seen[idx] = true;
    }
    seen.iter().all(|b: &bool| *b)
}

#[must_use]
pub fn discover_base85_alphabets(text: &str) -> Vec<(char, BTreeMap<char, u8>)> {
    let mut out: Vec<(char, BTreeMap<char, u8>)> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let needle: &[u8] = b"local ";
    let mut i: usize = 0;
    while i + needle.len() + 2 < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let name_b: u8 = bytes[i + needle.len()];
            let eq_b: u8 = bytes[i + needle.len() + 1];
            let brace_b: u8 = bytes[i + needle.len() + 2];
            if name_b.is_ascii_alphabetic() && eq_b == b'=' && brace_b == b'{' {
                let name: char = name_b as char;
                if let Some(body) = extract_named_table_body(text, &name.to_string())
                    && let Some(map) = parse_alphabet_table(body)
                    && is_full_radix_permutation(&map, 85)
                {
                    out.push((name, map));
                }
            }
        }
        i += 1;
    }
    out
}

#[must_use]
pub fn decode_base85_variant(input: &str, alphabet: &BTreeMap<char, u8>) -> Option<Vec<u8>> {
    let chars: Vec<char> = input.chars().collect();
    let mut out: Vec<u8> = Vec::with_capacity(chars.len() * 4 / 5 + 4);
    let mut idx: usize = 0;
    while idx < chars.len() {
        let remain: usize = chars.len() - idx;
        let count: usize = remain.min(5);
        if count < 2 {
            break;
        }
        let mut value: u64 = 0;
        for j in 0..5 {
            let code: u64 = if j < count {
                u64::from(*alphabet.get(&chars[idx + j])?)
            } else {
                84
            };
            value = value * 85 + code;
        }
        if value > u64::from(u32::MAX) {
            return None;
        }
        let b1: u8 = ((value >> 24) & 0xFF) as u8;
        let b2: u8 = ((value >> 16) & 0xFF) as u8;
        let b3: u8 = ((value >> 8) & 0xFF) as u8;
        let b4: u8 = (value & 0xFF) as u8;
        let group: [u8; 4] = [b1, b2, b3, b4];
        out.extend_from_slice(&group[..count - 1]);
        idx += count;
    }
    Some(out)
}

#[must_use]
fn match_outer_brace_escaped(s: &str) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    let mut depth: i32 = 1;
    let mut in_string: bool = false;
    let mut escaped: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[must_use]
pub fn parse_lua_string_literals(body: &str) -> Vec<String> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut s: String = String::new();
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    let digits: String = body[i + 1..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .take(3)
                        .collect();
                    if digits.is_empty() {
                        if let Some(&c) = bytes.get(i + 1) {
                            s.push(c as char);
                        }
                        i += 2;
                    } else {
                        if let Ok(code) = digits.parse::<u32>()
                            && let Some(c) = char::from_u32(code)
                        {
                            s.push(c);
                        }
                        i += 1 + digits.len();
                    }
                } else {
                    s.push(bytes[i] as char);
                    i += 1;
                }
            }
            out.push(s);
        }
        i += 1;
    }
    out
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
        if (0..85).contains(&value) {
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
    let mut escaped: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => depth -= 1,
            b'=' if depth == 0 => {
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
    let mut escaped: bool = false;
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'(' | b'{' => depth += 1,
            b']' | b')' | b'}' => depth -= 1,
            b',' | b';' if depth == 0 => {
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
pub fn parse_constarray_rotation(text: &str) -> Option<Vec<(usize, usize)>> {
    let bytes: &[u8] = text.as_bytes();
    let head: &[u8] = b" in ipairs({{";
    let mut search: usize = 0;
    while let Some(rel) = find_subslice(&bytes[search..], head) {
        let open: usize = search + rel + head.len() - 1;
        let rest: &str = &text[open..];
        if let Some(end) = match_outer_brace(rest) {
            let body: &str = &rest[..end];
            if let Some(pairs) = parse_pair_groups(body)
                && pairs.len() == 3
            {
                return Some(pairs);
            }
        }
        search = search + rel + head.len();
    }
    None
}

#[must_use]
fn parse_pair_groups(body: &str) -> Option<Vec<(usize, usize)>> {
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
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

pub fn apply_segment_reversals<T>(pool: &mut [T], pairs: &[(usize, usize)]) {
    for &(a1, b1) in pairs {
        if a1 == 0 || b1 == 0 || a1 > pool.len() || b1 > pool.len() || a1 > b1 {
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

#[must_use]
pub fn extract_string_char_arrays(text: &str) -> Vec<Vec<u8>> {
    let needle: &str = "string.char(";
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut search_from: usize = 0;
    while let Some(rel) = text[search_from..].find(needle) {
        let open: usize = search_from + rel + needle.len();
        let Some(close_rel): Option<usize> = text[open..].find(')') else {
            break;
        };
        let body: &str = &text[open..open + close_rel];
        if let Some(bytes) = parse_byte_list(body)
            && !bytes.is_empty()
        {
            out.push(bytes);
        }
        search_from = open + close_rel + 1;
    }
    out
}

#[must_use]
fn parse_byte_list(body: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for tok in body.split(',') {
        let t: &str = tok.trim();
        if t.is_empty() {
            continue;
        }
        let value: i64 = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).ok()?
        } else {
            t.parse::<i64>().ok()?
        };
        if !(0..=255).contains(&value) {
            return None;
        }
        bytes.push(value as u8);
    }
    Some(bytes)
}

#[must_use]
pub fn xor_decode_fixed(encoded: &[u8], key: u8) -> Vec<u8> {
    encoded.iter().map(|b: &u8| b ^ key).collect()
}

#[must_use]
pub fn xor_decode_rolling(encoded: &[u8], key: u8) -> Vec<u8> {
    encoded
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key.wrapping_add((i & 0xFF) as u8))
        .collect()
}

#[must_use]
pub fn xor_decode_repeating(encoded: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return encoded.to_vec();
    }
    encoded
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

const STD_BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[must_use]
fn std_base64_value(c: u8) -> Option<u8> {
    STD_BASE64
        .iter()
        .position(|&a: &u8| a == c)
        .map(|p: usize| p as u8)
}

#[must_use]
pub fn decode_base64_standard(input: &str) -> Option<Vec<u8>> {
    base64_decode(
        input.as_bytes(),
        Base64Alphabet::Standard,
        Base64Padding::Required,
    )
    .ok()
}

#[must_use]
pub fn longest_base64_literal(text: &str) -> Option<String> {
    let mut best: Option<String> = None;
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote: u8 = bytes[i];
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != quote {
                if bytes[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if let Some(literal) = text.get(start..j.min(bytes.len())) {
                let joined: String = join_wrapped_base64(literal);
                if is_base64ish(&joined)
                    && joined.len() >= 8
                    && best
                        .as_ref()
                        .is_none_or(|b: &String| b.len() < joined.len())
                {
                    best = Some(joined);
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    best
}

#[must_use]
fn join_wrapped_base64(literal: &str) -> String {
    if !literal
        .bytes()
        .any(|b: u8| matches!(b, b'\n' | b'\r' | b'\t' | b' '))
    {
        return literal.to_owned();
    }
    literal
        .bytes()
        .filter(|b: &u8| !matches!(b, b'\n' | b'\r' | b'\t' | b' '))
        .map(char::from)
        .collect()
}

#[must_use]
fn is_base64ish(s: &str) -> bool {
    if !s.len().is_multiple_of(4) {
        return false;
    }
    let mut seen_pad: bool = false;
    for c in s.bytes() {
        match c {
            b'=' => seen_pad = true,
            _ if seen_pad => return false,
            _ if std_base64_value(c).is_some() => {}
            _ => return false,
        }
    }
    true
}

#[must_use]
pub fn extract_byte_table(text: &str) -> Vec<u8> {
    let bytes: &[u8] = text.as_bytes();
    let needle: &[u8] = b"={";
    let mut i: usize = 0;
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let open: usize = i + needle.len() - 1;
            let rest: &str = &text[open + 1..];
            if let Some(end) = match_outer_brace(rest)
                && let Some(table) = parse_pure_byte_table(&rest[..end])
            {
                return table;
            }
        }
        i += 1;
    }
    Vec::new()
}

#[must_use]
fn parse_pure_byte_table(body: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for tok in body.split(',') {
        let t: &str = tok.trim();
        if t.is_empty() {
            continue;
        }
        let value: i64 = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).ok()?
        } else {
            t.parse::<i64>().ok()?
        };
        if !(0..=255).contains(&value) {
            return None;
        }
        out.push(value as u8);
    }
    if out.len() >= 2 { Some(out) } else { None }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderRecovery {
    pub plaintext: Vec<u8>,
    pub key: Vec<u8>,
    pub base64_len: usize,
}

#[must_use]
pub fn has_loadstring_invocation(text: &str) -> bool {
    text.contains("loadstring(") || text.contains("load(") || text.contains("loadstring (")
}

#[must_use]
pub fn structural_xor_base64_loader(text: &str) -> Option<LoaderRecovery> {
    if !has_loadstring_invocation(text) {
        return None;
    }
    let recovery: LoaderRecovery = recover_xor_base64_loader(text)?;
    let already_plaintext: bool =
        decode_base64_standard(&longest_base64_literal(text).unwrap_or_default())
            .is_some_and(|raw: Vec<u8>| looks_like_lua(&raw));
    if already_plaintext {
        return None;
    }
    Some(recovery)
}

#[must_use]
pub fn recover_xor_base64_loader(text: &str) -> Option<LoaderRecovery> {
    let literal: String = longest_base64_literal(text)?;
    let cipher: Vec<u8> = decode_base64_standard(&literal)?;
    if cipher.is_empty() {
        return None;
    }
    let mut hinted: Vec<Vec<u8>> = Vec::new();
    let table: Vec<u8> = extract_byte_table(text);
    if !table.is_empty() {
        hinted.push(table);
    }
    if let Some(single) = find_single_byte_key_literal(text) {
        hinted.push(vec![single]);
    }
    for key in &hinted {
        let plain: Vec<u8> = xor_decode_repeating(&cipher, key);
        if looks_like_lua(&plain) {
            return Some(LoaderRecovery {
                plaintext: plain,
                key: key.clone(),
                base64_len: literal.len(),
            });
        }
    }
    let mut best: Option<(usize, u8, Vec<u8>)> = None;
    for byte in 0u16..=255 {
        let key: u8 = byte as u8;
        let plain: Vec<u8> = xor_decode_fixed(&cipher, key);
        if !looks_like_lua(&plain) {
            continue;
        }
        let score: usize = lua_plausibility_score(&plain);
        if best
            .as_ref()
            .is_none_or(|(s, _, _): &(usize, u8, Vec<u8>)| *s < score)
        {
            best = Some((score, key, plain));
        }
    }
    best.map(|(_, key, plain): (usize, u8, Vec<u8>)| LoaderRecovery {
        plaintext: plain,
        key: vec![key],
        base64_len: literal.len(),
    })
}

#[must_use]
fn is_lua_bytecode_chunk(plain: &[u8]) -> bool {
    plain.starts_with(b"\x1bLua") || plain.starts_with(b"\x1bLJ") || plain.starts_with(b"\x1bLuaQ")
}

const SCORE_TOKENS: [&str; 16] = [
    "function", "local ", "return", "end", "then", "print", "for ", "while ", "if ", "do ", "..",
    "(", ")", "=", "\"", "'",
];

const LUA_KEYWORDS: [&str; 10] = [
    "function", "local ", "return", "end", "then", "print", "for ", "while ", "if ", "do",
];

#[must_use]
fn lua_plausibility_score(plain: &[u8]) -> usize {
    if is_lua_bytecode_chunk(plain) {
        return usize::MAX;
    }
    let Ok(text): core::result::Result<&str, _> = core::str::from_utf8(plain) else {
        return 0;
    };
    let keyword_hits: usize = SCORE_TOKENS
        .iter()
        .map(|k: &&str| text.matches(*k).count())
        .sum();
    let printable: usize = text
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || matches!(c, ' ' | '\n' | '\t'))
        .count();
    keyword_hits * 4 + printable
}

#[must_use]
fn find_single_byte_key_literal(text: &str) -> Option<u8> {
    for marker in ["MS_KEY", "MOONSEC_KEY", "xor_key", "XOR_KEY", "key"] {
        if let Some(pos) = text.find(marker) {
            let rest: &str = &text[pos + marker.len()..];
            if let Some(after_eq) = rest.trim_start().strip_prefix('=') {
                let token: String = after_eq
                    .trim_start()
                    .chars()
                    .take_while(|c: &char| c.is_ascii_hexdigit() || *c == 'x' || *c == 'X')
                    .collect();
                let value: Option<i64> = if let Some(hex) = token
                    .strip_prefix("0x")
                    .or_else(|| token.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16).ok()
                } else {
                    token.parse::<i64>().ok()
                };
                if let Some(v) = value
                    && let Ok(b) = u8::try_from(v)
                {
                    return Some(b);
                }
            }
        }
    }
    None
}

#[must_use]
pub fn looks_like_lua(plain: &[u8]) -> bool {
    if is_lua_bytecode_chunk(plain) {
        return true;
    }
    let Ok(text): core::result::Result<&str, _> = core::str::from_utf8(plain) else {
        return false;
    };
    let printable: usize = text
        .chars()
        .filter(|c: &char| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
        .count();
    if printable * 10 < text.chars().count() * 9 {
        return false;
    }
    LUA_KEYWORDS
        .iter()
        .filter(|k: &&&str| text.contains(*k))
        .count()
        >= 2
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
        assert_eq!(eval_arith_expr("7%0"), None);
        assert_eq!(eval_arith_expr("3+"), None);
    }

    #[test]
    fn eval_modulo_binds_tighter_than_additive() {
        assert_eq!(eval_arith_expr("237862555%940168"), Some(51));
        assert_eq!(eval_arith_expr("10+7%3"), Some(11));
        assert_eq!(eval_arith_expr("7%3+10"), Some(11));
        assert_eq!(
            eval_arith_expr("433272212%3050841-2081613624%11694162"),
            Some(
                eval_arith_expr("433272212%3050841").unwrap()
                    - eval_arith_expr("2081613624%11694162").unwrap()
            )
        );
    }

    #[test]
    fn eval_modulo_nested_parens() {
        assert_eq!(
            eval_arith_expr("594691279%(2204078958%11963999)"),
            Some(594_691_279_i64.rem_euclid(2_204_078_958_i64.rem_euclid(11_963_999)))
        );
        assert_eq!(eval_arith_expr("((26861730653-172811)%208281526)"), {
            let inner: i64 = 26_861_730_653 - 172_811;
            Some(inner.rem_euclid(208_281_526))
        });
    }

    #[test]
    fn eval_lua_floor_mod_negative_operands() {
        assert_eq!(eval_arith_expr("-1%3"), Some(2));
        assert_eq!(eval_arith_expr("5%-3"), Some(-1));
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
    fn split_handles_escaped_quote_inside_string_key() {
        let parts: Vec<&str> = split_top_level("[\"\\\"\"]=1;[\"\\\\\"]=2,[\"\\'\"]=3");
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn unescape_distinguishes_escaped_punctuation_keys() {
        assert_eq!(unescape_lua_key("\"\\\"\""), Some('"'));
        assert_eq!(unescape_lua_key("\"\\\\\""), Some('\\'));
        assert_eq!(unescape_lua_key("\"\\'\""), Some('\''));
        assert_eq!(unescape_lua_key("\"\\047\""), Some('/'));
        assert_eq!(unescape_lua_key("\"\\n\""), Some('\n'));
    }

    #[test]
    fn alphabet_table_keeps_escaped_quote_backslash_apostrophe_distinct() {
        let body: &str = "[\"\\\"\"]=10;[\"\\\\\"]=20,[\"\\'\"]=30";
        let map: BTreeMap<char, u8> = parse_alphabet_table(body).expect("parse");
        assert_eq!(map.len(), 3, "three distinct punctuation keys must survive");
        assert_eq!(map.get(&'"'), Some(&10));
        assert_eq!(map.get(&'\\'), Some(&20));
        assert_eq!(map.get(&'\''), Some(&30));
    }

    fn std_base85_alphabet() -> BTreeMap<char, u8> {
        let mut map: BTreeMap<char, u8> = BTreeMap::new();
        for code in 0u8..85 {
            map.insert(char::from(0x21 + code), code);
        }
        map
    }

    fn encode_base85_reference(bytes: &[u8], alpha: &BTreeMap<char, u8>) -> String {
        let inverse: BTreeMap<u8, char> =
            alpha.iter().map(|(c, v): (&char, &u8)| (*v, *c)).collect();
        let mut out: String = String::new();
        let mut pos: usize = 0;
        while pos < bytes.len() {
            let count: usize = (bytes.len() - pos).min(4);
            let mut value: u64 = 0;
            for i in 0..4 {
                let b: u64 = u64::from(bytes.get(pos + i).copied().unwrap_or(0));
                value = (value << 8) | b;
            }
            let mut digits: [char; 5] = ['!'; 5];
            let mut v: u64 = value;
            for slot in (0..5).rev() {
                digits[slot] = inverse[&((v % 85) as u8)];
                v /= 85;
            }
            for d in digits.iter().take(count + 1) {
                out.push(*d);
            }
            pos += count;
        }
        out
    }

    #[test]
    fn base85_variant_round_trips_full_groups() {
        let alpha: BTreeMap<char, u8> = std_base85_alphabet();
        let plain: &[u8] = b"Hello, base85 world!";
        let encoded: String = encode_base85_reference(plain, &alpha);
        let decoded: Vec<u8> = decode_base85_variant(&encoded, &alpha).expect("decode");
        assert_eq!(&decoded, plain);
    }

    #[test]
    fn base85_variant_round_trips_partial_tails() {
        let alpha: BTreeMap<char, u8> = std_base85_alphabet();
        for plain in [b"a".as_slice(), b"ab", b"abc", b"abcd", b"abcde"] {
            let encoded: String = encode_base85_reference(plain, &alpha);
            let decoded: Vec<u8> = decode_base85_variant(&encoded, &alpha).expect("decode");
            assert_eq!(
                &decoded,
                plain,
                "tail length {} must round-trip",
                plain.len()
            );
        }
    }

    #[test]
    fn base85_variant_rejects_unknown_symbol() {
        let alpha: BTreeMap<char, u8> = std_base85_alphabet();
        assert_eq!(decode_base85_variant("AB\u{00A0}DE", &alpha), None);
    }

    #[test]
    fn segment_reversals_right_rotate_via_three_reverses() {
        let mut pool: Vec<u32> = (1u32..=6).collect();
        apply_segment_reversals(&mut pool, &[(1, 6), (1, 2), (3, 6)]);
        assert_eq!(pool, vec![5, 6, 1, 2, 3, 4]);
    }

    #[test]
    fn constarray_rotation_parses_three_pair_form_any_loop_vars() {
        let block: &str = "for k,v in ipairs({{339591+-339590,-812166+812212},{(127031-269591)+((935957-185428)+-607968),(-234784+1203008)-968196},{-549377+549406,1191682963%9688479}})do while v[2]<v[1]do end end";
        let pairs: Vec<(usize, usize)> = parse_constarray_rotation(block).expect("parse rotation");
        assert_eq!(pairs, vec![(1, 46), (1, 28), (29, 46)]);
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

    #[test]
    fn extract_decimal_string_char_array() {
        let text: &str = "local s = string.char(72, 101, 108, 108, 111) print(s)";
        let arrays: Vec<Vec<u8>> = extract_string_char_arrays(text);
        assert_eq!(arrays, vec![b"Hello".to_vec()]);
    }

    #[test]
    fn extract_hex_and_multiple_arrays() {
        let text: &str =
            "a=string.char(0x4d,0x6f,0x6f,0x6e);b=string.char(83, 101, 99) ;c=string.char()";
        let arrays: Vec<Vec<u8>> = extract_string_char_arrays(text);
        assert_eq!(arrays, vec![b"Moon".to_vec(), b"Sec".to_vec()]);
    }

    #[test]
    fn fixed_xor_round_trips_against_known_key() {
        let plain: &[u8] = b"MoonSec";
        let key: u8 = 0x5A;
        let encoded: Vec<u8> = plain.iter().map(|b: &u8| b ^ key).collect();
        assert_eq!(xor_decode_fixed(&encoded, key), plain);
    }

    #[test]
    fn rolling_xor_recovers_index_keyed_pool() {
        let encoded: Vec<u8> = vec![0x48 ^ 0x10, 0x69 ^ 0x11, 0x21 ^ 0x12];
        assert_eq!(xor_decode_rolling(&encoded, 0x10), b"Hi!".to_vec());
    }

    fn std_b64_encode(data: &[u8]) -> String {
        let mut out: String = String::new();
        for chunk in data.chunks(3) {
            let b0: u32 = u32::from(chunk[0]);
            let b1: u32 = chunk.get(1).map_or(0, |b: &u8| u32::from(*b));
            let b2: u32 = chunk.get(2).map_or(0, |b: &u8| u32::from(*b));
            let n: u32 = (b0 << 16) | (b1 << 8) | b2;
            out.push(STD_BASE64[((n >> 18) & 0x3F) as usize] as char);
            out.push(STD_BASE64[((n >> 12) & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                STD_BASE64[((n >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                STD_BASE64[(n & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn standard_base64_round_trips_all_tail_lengths() {
        for len in 1..=64usize {
            let data: Vec<u8> = (0..len).map(|i: usize| (i * 7 + 3) as u8).collect();
            let encoded: String = std_b64_encode(&data);
            let decoded: Vec<u8> = decode_base64_standard(&encoded).expect("decode");
            assert_eq!(decoded, data, "length {len} must round-trip");
        }
    }

    #[test]
    fn standard_base64_keeps_padded_final_group() {
        let decoded: Vec<u8> = decode_base64_standard("aGVsbG8=").expect("decode");
        assert_eq!(&decoded, b"hello");
    }

    #[test]
    fn repeating_xor_round_trips_multibyte_key() {
        let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
        let plain: &[u8] = b"return print(1)";
        let cipher: Vec<u8> = xor_decode_repeating(plain, key);
        assert_eq!(xor_decode_repeating(&cipher, key), plain.to_vec());
    }

    #[test]
    fn extract_byte_table_reads_first_pure_table() {
        let text: &str = "local MS_KEY={77,111,111,110}\nlocal DATA=\"x\"";
        assert_eq!(extract_byte_table(text), vec![77, 111, 111, 110]);
    }

    #[test]
    fn longest_base64_literal_picks_blob_over_short_strings() {
        let text: &str = "local a=\"hi\" local DATA=\"cmV0dXJuIHByaW50KDEp\" local b=\"end\"";
        assert_eq!(
            longest_base64_literal(text).as_deref(),
            Some("cmV0dXJuIHByaW50KDEp")
        );
    }

    #[test]
    fn loader_recovery_decrypts_multibyte_table_key() {
        let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
        let original: &[u8] = b"local function f() return 7 end\nprint(f())\n";
        let cipher: Vec<u8> = xor_decode_repeating(original, key);
        let blob: String = std_b64_encode(&cipher);
        let text: String =
            format!("-- MoonSec v1\nlocal MS_KEY={{77,111,111,110}}\nlocal DATA=\"{blob}\"\n");
        let rec: LoaderRecovery = recover_xor_base64_loader(&text).expect("recover");
        assert_eq!(rec.key, key);
        assert_eq!(rec.plaintext, original);
    }

    #[test]
    fn lua_bytecode_signature_needs_full_magic_not_lone_esc() {
        assert!(!looks_like_lua(&[0x1B, 0x00, 0x00]));
        assert!(looks_like_lua(b"\x1bLua\x54\x00"));
    }

    #[test]
    fn longest_base64_literal_joins_line_wrapped_blob() {
        let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
        let original: &[u8] = b"local function f() return 7 end\nprint(f())\nprint(1+2+3+4+5)\n";
        let cipher: Vec<u8> = xor_decode_repeating(original, key);
        let flat: String = std_b64_encode(&cipher);
        let wrapped: String = flat
            .as_bytes()
            .chunks(16)
            .map(|c: &[u8]| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<String>>()
            .join("\n");
        let text: String = format!("local DATA=\"{wrapped}\"\nreturn loadstring(DATA)()\n");
        assert_eq!(
            longest_base64_literal(&text).as_deref(),
            Some(flat.as_str())
        );
    }

    #[test]
    fn structural_loader_recovers_from_line_wrapped_blob() {
        let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
        let original: &[u8] = b"local function f() return 7 end\nprint(f())\nprint(1+2+3+4+5)\n";
        let cipher: Vec<u8> = xor_decode_repeating(original, key);
        let flat: String = std_b64_encode(&cipher);
        let wrapped: String = flat
            .as_bytes()
            .chunks(24)
            .map(|c: &[u8]| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<String>>()
            .join("\n");
        let text: String = format!(
            "local MS_KEY={{77,111,111,110}}\nlocal DATA=\"{wrapped}\"\nreturn loadstring(DATA)()\n"
        );
        let rec: LoaderRecovery = structural_xor_base64_loader(&text).expect("structural recover");
        assert_eq!(rec.key, key);
        assert_eq!(rec.plaintext, original);
    }

    #[test]
    fn structural_loader_fires_on_markerless_single_byte_loadstring() {
        let key: u8 = 0x5B;
        let original: &[u8] = b"local x=10\nlocal y=20\nprint(x+y)\nreturn x*y\n";
        let cipher: Vec<u8> = xor_decode_fixed(original, key);
        let blob: String = std_b64_encode(&cipher);
        let text: String = format!("local D=\"{blob}\"\nreturn loadstring(D)()\n");
        let rec: LoaderRecovery = structural_xor_base64_loader(&text).expect("recover");
        assert_eq!(rec.plaintext, original);
    }

    #[test]
    fn structural_loader_no_false_positive_on_clean_lua() {
        let clean: &str = "local function fib(n)\n  if n < 2 then return n end\n  return fib(n-1) + fib(n-2)\nend\nfor i = 1, 10 do print(fib(i)) end\n";
        assert!(structural_xor_base64_loader(clean).is_none());
    }

    #[test]
    fn structural_loader_no_false_positive_on_plain_base64_of_source() {
        let original: &[u8] = b"local x=1\nprint(x)\nreturn function() return x end\n";
        let blob: String = std_b64_encode(original);
        let text: String = format!("local D=\"{blob}\"\nreturn loadstring(D)()\n");
        assert!(
            structural_xor_base64_loader(&text).is_none(),
            "a plain (un-encrypted) base64 of source is not an xor-loader; must not claim recovery"
        );
    }

    #[test]
    fn structural_loader_requires_loadstring_invocation() {
        let key: u8 = 0x33;
        let original: &[u8] = b"local function g() return 99 end\nprint(g())\n";
        let cipher: Vec<u8> = xor_decode_fixed(original, key);
        let blob: String = std_b64_encode(&cipher);
        let text_no_load: String = format!("local D=\"{blob}\"\nlocal y=D\n");
        assert!(
            structural_xor_base64_loader(&text_no_load).is_none(),
            "without a loadstring/load invocation this is just data, not a loader"
        );
    }
}
