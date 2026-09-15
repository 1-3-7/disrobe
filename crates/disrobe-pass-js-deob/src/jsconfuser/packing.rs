use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, find_paren_close, scan_balanced_brace, skip_whitespace};

#[derive(Debug, Clone, Serialize)]
pub struct PackingReversalResult {
    pub blocks_expanded: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_packing(source: &str) -> PackingReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)\s*\{",
    ) else {
        return passthrough(source);
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let body_open: usize = mat.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let after_body: usize = skip_whitespace(bytes, body_close + 1);
        if after_body >= bytes.len() || bytes[after_body] != b'(' {
            continue;
        }
        let Some(args_close): Option<usize> = find_paren_close(bytes, after_body + 1) else {
            continue;
        };
        let args_text: &str = &source[after_body + 1..args_close];
        let mut tail: usize = skip_whitespace(bytes, args_close + 1);
        if tail >= bytes.len() || bytes[tail] != b')' {
            continue;
        }
        tail += 1;
        if bytes.get(tail) == Some(&b';') {
            tail += 1;
        }
        let Some(unpacked): Option<String> = unpack(args_text) else {
            continue;
        };
        edits.push((mat.start()..tail, Some(unpacked)));
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, expanded): (String, usize) = apply_splice_edits(source, &mut edits);
    PackingReversalResult {
        blocks_expanded: expanded,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> PackingReversalResult {
    PackingReversalResult {
        blocks_expanded: 0,
        rewritten_source: source.to_owned(),
    }
}

fn unpack(args: &str) -> Option<String> {
    let parts: Vec<&str> = split_top_level(args);
    if parts.len() < 4 {
        return None;
    }
    let payload: String = strip_string_literal(parts[0])?;
    let radix: u32 = parts[1].trim().parse().ok()?;
    let count: usize = parts[2].trim().parse().ok()?;
    let dict_raw: &str = parts[3].trim();
    let words: Vec<String> = extract_word_list(dict_raw)?;
    if words.len() < count {
        return None;
    }
    let mut out: String = String::with_capacity(payload.len() * 2);
    let mut current_word: String = String::new();
    for ch in payload.chars() {
        if is_word_char(ch) {
            current_word.push(ch);
        } else {
            if !current_word.is_empty() {
                flush_word(&mut out, &current_word, &words, radix);
                current_word.clear();
            }
            out.push(ch);
        }
    }
    if !current_word.is_empty() {
        flush_word(&mut out, &current_word, &words, radix);
    }
    Some(out)
}

fn flush_word(out: &mut String, token: &str, words: &[String], radix: u32) {
    let Some(index): Option<usize> = decode_base(token, radix) else {
        out.push_str(token);
        return;
    };
    if let Some(repl) = words.get(index)
        && !repl.is_empty()
    {
        out.push_str(repl);
    } else {
        out.push_str(token);
    }
}

const fn is_word_char(ch: char) -> bool {
    matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '$')
}

fn decode_base(token: &str, radix: u32) -> Option<usize> {
    let mut value: u64 = 0;
    for ch in token.chars() {
        let code: u32 = ch as u32;
        let digit: u64 = match ch {
            '0'..='9' => u64::from(code - u32::from(b'0')),
            'a'..='z' => u64::from(code - u32::from(b'a') + 10),
            'A'..='Z' => u64::from(code - u32::from(b'A') + 36),
            _ => return None,
        };
        if digit >= u64::from(radix) {
            return None;
        }
        value = value.checked_mul(u64::from(radix))?.checked_add(digit)?;
    }
    usize::try_from(value).ok()
}

fn strip_string_literal(raw: &str) -> Option<String> {
    let t: &str = raw.trim();
    let bytes: &[u8] = t.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote: u8 = bytes[0];
    if !matches!(quote, b'\'' | b'"') || bytes[bytes.len() - 1] != quote {
        return None;
    }
    let inner: &str = t.get(1..t.len() - 1)?;
    let mut out: String = String::with_capacity(inner.len());
    let mut i: usize = 0;
    let raw_bytes: &[u8] = inner.as_bytes();
    while i < raw_bytes.len() {
        let b: u8 = raw_bytes[i];
        if b == b'\\' && i + 1 < raw_bytes.len() {
            let esc: u8 = raw_bytes[i + 1];
            let decoded: char = match esc {
                b'n' => '\n',
                b't' => '\t',
                b'r' => '\r',
                other => other as char,
            };
            out.push(decoded);
            i += 2;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    Some(out)
}

fn extract_word_list(raw: &str) -> Option<Vec<String>> {
    let t: &str = raw.trim();
    if let Some(rest) = t.strip_prefix('\'') {
        let end: usize = rest.find('\'')?;
        return Some(split_words(&rest[..end]));
    }
    if let Some(rest) = t.strip_prefix('"') {
        let end: usize = rest.find('"')?;
        return Some(split_words(&rest[..end]));
    }
    None
}

fn split_words(body: &str) -> Vec<String> {
    body.split('|').map(|s: &str| s.to_owned()).collect()
}

fn split_top_level(text: &str) -> Vec<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut depth_paren: i32 = 0;
    let mut depth_bracket: i32 = 0;
    let mut depth_brace: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => quote = Some(b),
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b',' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 => {
                out.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail: &str = text[start..].trim();
    if !tail.is_empty() || !out.is_empty() {
        out.push(tail);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_minimal_dean_edwards_payload() {
        let src: &str = "var keep = 1; eval(function(p,a,c,k,e,d){return p}('alert(1)',62,1,'alert'.split('|'),0,{})); var more = 2;";
        let r: PackingReversalResult = reverse_packing(src);
        assert_eq!(r.blocks_expanded, 1);
        assert!(r.rewritten_source.contains("alert(1)"));
        assert!(!r.rewritten_source.contains("eval(function"));
    }

    #[test]
    fn substitutes_word_indices_via_radix() {
        let src: &str =
            "eval(function(p,a,c,k,e,d){return p}('1 0',10,2,'hi|bye'.split('|'),0,{}));";
        let r: PackingReversalResult = reverse_packing(src);
        assert_eq!(r.blocks_expanded, 1);
        assert!(r.rewritten_source.contains("bye hi"));
    }

    #[test]
    fn leaves_unrelated_eval_alone() {
        let src: &str = "eval('var x = 1;');";
        let r: PackingReversalResult = reverse_packing(src);
        assert_eq!(r.blocks_expanded, 0);
        assert_eq!(r.rewritten_source, src);
    }
}
