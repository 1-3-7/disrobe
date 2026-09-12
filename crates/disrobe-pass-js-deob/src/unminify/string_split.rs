use serde::Serialize;

const MAX_PASSES: usize = 32;
const MAX_CHAIN: usize = 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub(super) struct StringSplitStats {
    pub(super) literals_merged: usize,
    pub(super) passes: u32,
}

#[must_use]
pub(super) fn fold_string_concat(source: &str) -> (String, StringSplitStats) {
    let mut stats: StringSplitStats = StringSplitStats::default();
    let mut current: String = source.to_owned();
    for _ in 0..MAX_PASSES {
        let (out, merged): (String, usize) = single_pass(&current);
        stats.passes = stats.passes.saturating_add(1);
        stats.literals_merged += merged;
        if merged == 0 {
            current = out;
            break;
        }
        current = out;
    }
    (current, stats)
}

fn single_pass(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut merged: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i = skip_line_comment(bytes, i);
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let Some(after): Option<usize> = skip_block_comment(bytes, i) else {
                    i += 2;
                    continue;
                };
                i = after;
            }
            b'`' => {
                let Some(after): Option<usize> = skip_template_literal(bytes, i) else {
                    i += 1;
                    continue;
                };
                i = after;
            }
            b'\'' | b'"' => {
                let Some(first_end): Option<usize> = scan_string_end(bytes, i, b) else {
                    i += 1;
                    continue;
                };
                let Some((chain, after_chain, count)): Option<(Vec<StringSpan>, usize, usize)> =
                    collect_chain(bytes, i, first_end)
                else {
                    i = first_end;
                    continue;
                };
                if count < 2 {
                    i = first_end;
                    continue;
                }
                out.push_str(&source[cursor..i]);
                let folded: String = merge_literals(bytes, &chain);
                out.push_str(&folded);
                cursor = after_chain;
                i = after_chain;
                merged += count - 1;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push_str(&source[cursor..]);
    (out, merged)
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

fn skip_template_literal(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'`' {
            return Some(i + 1);
        }
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            i += 2;
            let mut depth: i32 = 1;
            while i < bytes.len() && depth > 0 {
                let inner: u8 = bytes[i];
                match inner {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    b'\'' | b'"' => {
                        i = scan_string_end(bytes, i, inner)?;
                        continue;
                    }
                    b'`' => {
                        i = skip_template_literal(bytes, i)?;
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    None
}

fn scan_string_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            if i + 1 >= bytes.len() {
                return None;
            }
            i += 2;
            continue;
        }
        if b == b'\n' {
            return None;
        }
        if b == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

type StringSpan = (usize, usize, u8);

fn collect_chain(
    bytes: &[u8],
    first_start: usize,
    first_end: usize,
) -> Option<(Vec<StringSpan>, usize, usize)> {
    let mut spans: Vec<StringSpan> = Vec::with_capacity(4);
    spans.push((first_start, first_end, bytes[first_start]));
    let mut cursor: usize = first_end;
    while let Some((next_start, next_end, quote)) = peek_concat(bytes, cursor) {
        spans.push((next_start, next_end, quote));
        cursor = next_end;
        if spans.len() >= MAX_CHAIN {
            break;
        }
    }
    let count: usize = spans.len();
    if count < 2 {
        None
    } else {
        Some((spans, cursor, count))
    }
}

fn peek_concat(bytes: &[u8], from: usize) -> Option<StringSpan> {
    let mut i: usize = from;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'+' {
        return None;
    }
    i += 1;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote: u8 = bytes[i];
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let end: usize = scan_string_end(bytes, i, quote)?;
    Some((i, end, quote))
}

fn merge_literals(source_bytes: &[u8], spans: &[StringSpan]) -> String {
    let mut combined: Vec<char> = Vec::with_capacity(spans.iter().map(|s| s.1 - s.0).sum());
    for &(start, end, _) in spans {
        decode_segment(source_bytes, start + 1, end - 1, &mut combined);
    }
    let target_quote: u8 = pick_quote(&combined);
    let mut out: String = String::with_capacity(combined.len() + 2);
    out.push(target_quote as char);
    for ch in combined {
        emit_char(ch, target_quote, &mut out);
    }
    out.push(target_quote as char);
    out
}

fn decode_segment(bytes: &[u8], start: usize, end: usize, out: &mut Vec<char>) {
    let mut i: usize = start;
    while i < end {
        let b: u8 = bytes[i];
        if b != b'\\' {
            out.push(b as char);
            i += 1;
            continue;
        }
        if i + 1 >= end {
            out.push('\\');
            i += 1;
            continue;
        }
        i = decode_escape(bytes, i, end, out);
    }
}

fn decode_escape(bytes: &[u8], at: usize, end: usize, out: &mut Vec<char>) -> usize {
    let esc: u8 = bytes[at + 1];
    match esc {
        b'n' => push_and_advance(out, '\n', at, 2),
        b't' => push_and_advance(out, '\t', at, 2),
        b'r' => push_and_advance(out, '\r', at, 2),
        b'\\' => push_and_advance(out, '\\', at, 2),
        b'\'' => push_and_advance(out, '\'', at, 2),
        b'"' => push_and_advance(out, '"', at, 2),
        b'`' => push_and_advance(out, '`', at, 2),
        b'0' => push_and_advance(out, '\0', at, 2),
        b'b' => push_and_advance(out, '\u{0008}', at, 2),
        b'f' => push_and_advance(out, '\u{000C}', at, 2),
        b'v' => push_and_advance(out, '\u{000B}', at, 2),
        b'x' if at + 3 < end => decode_hex2(bytes, at, esc, out),
        b'u' if at + 5 < end && bytes[at + 2] != b'{' => decode_hex4(bytes, at, esc, out),
        other => push_and_advance(out, other as char, at, 2),
    }
}

fn push_and_advance(out: &mut Vec<char>, ch: char, at: usize, step: usize) -> usize {
    out.push(ch);
    at + step
}

fn decode_hex2(bytes: &[u8], at: usize, esc: u8, out: &mut Vec<char>) -> usize {
    let (Some(h), Some(l)): (Option<u32>, Option<u32>) =
        (hex_nibble(bytes[at + 2]), hex_nibble(bytes[at + 3]))
    else {
        return push_and_advance(out, esc as char, at, 2);
    };
    if let Some(ch) = char::from_u32((h << 4) | l) {
        out.push(ch);
    }
    at + 4
}

fn decode_hex4(bytes: &[u8], at: usize, esc: u8, out: &mut Vec<char>) -> usize {
    let (Some(a), Some(b2), Some(c), Some(d)): (
        Option<u32>,
        Option<u32>,
        Option<u32>,
        Option<u32>,
    ) = (
        hex_nibble(bytes[at + 2]),
        hex_nibble(bytes[at + 3]),
        hex_nibble(bytes[at + 4]),
        hex_nibble(bytes[at + 5]),
    ) else {
        return push_and_advance(out, esc as char, at, 2);
    };
    let cp: u32 = (a << 12) | (b2 << 8) | (c << 4) | d;
    if let Some(ch) = char::from_u32(cp) {
        out.push(ch);
    }
    at + 6
}

const fn hex_nibble(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a' + 10) as u32),
        b'A'..=b'F' => Some((b - b'A' + 10) as u32),
        _ => None,
    }
}

fn pick_quote(chars: &[char]) -> u8 {
    let has_single: bool = chars.contains(&'\'');
    let has_double: bool = chars.contains(&'"');
    if has_single && !has_double {
        b'"'
    } else {
        b'\''
    }
}

fn emit_char(ch: char, quote: u8, out: &mut String) {
    match ch {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\t' => out.push_str("\\t"),
        '\r' => out.push_str("\\r"),
        '\0' => out.push_str("\\0"),
        '\'' if quote == b'\'' => out.push_str("\\'"),
        '"' if quote == b'"' => out.push_str("\\\""),
        c => out.push(c),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn folds_simple_double_quote_chain() {
        let (out, stats): (String, StringSplitStats) =
            fold_string_concat(r#"var s = "he" + "llo";"#);
        assert_eq!(stats.literals_merged, 1);
        assert!(out.contains("'hello'"), "expected fold, got: {out}");
    }

    #[test]
    fn folds_three_segment_mixed_quote_chain() {
        let (out, stats): (String, StringSplitStats) =
            fold_string_concat(r#"var s = 'foo' + "bar" + 'baz';"#);
        assert_eq!(stats.literals_merged, 2);
        assert!(out.contains("'foobarbaz'"), "expected fold, got: {out}");
    }

    #[test]
    fn skips_chain_with_identifier_operand() {
        let src: &str = r#"var s = "a" + x + "b";"#;
        let (out, stats): (String, StringSplitStats) = fold_string_concat(src);
        assert_eq!(stats.literals_merged, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn does_not_fold_inside_template_literal() {
        let src: &str = r#"var s = `${"a" + "b"}`;"#;
        let (out, _stats): (String, StringSplitStats) = fold_string_concat(src);
        assert_eq!(out, src, "template-literal interior must be untouched");
    }

    #[test]
    fn handles_escape_sequences_in_literals() {
        let (out, stats): (String, StringSplitStats) =
            fold_string_concat(r#"var s = "a\n" + "b\t";"#);
        assert_eq!(stats.literals_merged, 1);
        assert!(
            out.contains("'a\\nb\\t'"),
            "expected escapes preserved: {out}"
        );
    }

    #[test]
    fn preserves_existing_apostrophes_via_double_quote_target() {
        let (out, stats): (String, StringSplitStats) =
            fold_string_concat(r#"var s = 'don' + "'t";"#);
        assert_eq!(stats.literals_merged, 1);
        assert!(
            out.contains("\"don't\""),
            "expected double-quote target for apostrophe content: {out}"
        );
    }

    #[test]
    fn fixed_point_chain_of_six() {
        let (out, stats): (String, StringSplitStats) =
            fold_string_concat(r#"var s = "a" + "b" + "c" + "d" + "e" + "f";"#);
        assert!(
            stats.literals_merged >= 5,
            "merged: {}",
            stats.literals_merged
        );
        assert!(out.contains("'abcdef'"), "expected full fold: {out}");
    }

    #[test]
    fn comment_with_string_in_it_does_not_throw() {
        let src: &str = r#"
        var x = "real" + "literal";
        "#;
        let (out, stats): (String, StringSplitStats) = fold_string_concat(src);
        assert_eq!(stats.literals_merged, 1);
        assert!(out.contains("'realliteral'"));
    }

    #[test]
    fn leaves_clean_js_alone() {
        let src: &str = "var x = 1 + 2; var y = obj.method(); function f() { return x; }";
        let (out, stats): (String, StringSplitStats) = fold_string_concat(src);
        assert_eq!(stats.literals_merged, 0);
        assert_eq!(out, src);
    }
}
