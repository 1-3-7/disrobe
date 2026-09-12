use serde::Serialize;

use crate::esoteric::eval_to_string;

const FROM_CHAR_CODE: &str = "String.fromCharCode";
const FROM_CHAR_CODE_LEN: usize = FROM_CHAR_CODE.len();
const MAX_FOLD_PASSES: usize = 8;
const MAX_CALL_BYTES: usize = 64 * 1024;
const MAX_RESULT_CHARS: usize = 4096;

const MAX_IIFE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CharFoldStats {
    pub from_char_code_calls_folded: usize,
    pub string_iifes_folded: usize,
    pub passes_run: usize,
}

#[must_use]
pub fn fold_char_constructors(source: &str) -> (String, CharFoldStats) {
    let mut current: String = source.to_owned();
    let mut stats: CharFoldStats = CharFoldStats::default();
    for _ in 0..MAX_FOLD_PASSES {
        stats.passes_run += 1;
        let normalized: String = normalize_string_member(&current);
        let (after_chars, folded): (String, usize) = fold_one_pass(&normalized);
        stats.from_char_code_calls_folded += folded;
        let (next, iifes): (String, usize) = fold_string_iifes(&after_chars);
        stats.string_iifes_folded += iifes;
        if folded == 0 && iifes == 0 && normalized == current {
            current = next;
            break;
        }
        current = next;
    }
    (current, stats)
}

fn fold_string_iifes(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut folded: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_string(bytes, i, b);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end: usize = skip_line_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end: usize = skip_block_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            _ => {
                if let Some((iife_end, literal)) = try_fold_iife(source, bytes, i) {
                    out.push_str(&literal);
                    folded += 1;
                    i = iife_end;
                } else {
                    out.push(b as char);
                    i += 1;
                }
            }
        }
    }
    (out, folded)
}

fn try_fold_iife(source: &str, bytes: &[u8], pos: usize) -> Option<(usize, String)> {
    if bytes.get(pos) != Some(&b'(') {
        return None;
    }
    let mut j: usize = pos + 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if source.get(j..j + 8) != Some("function") {
        return None;
    }
    let fn_outer_end: usize = match_balanced_paren(bytes, pos)?;
    let mut k: usize = fn_outer_end;
    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
        k += 1;
    }
    if bytes.get(k) != Some(&b'(') {
        return None;
    }
    let call_end: usize = match_balanced_paren(bytes, k)?;
    if call_end - pos > MAX_IIFE_BYTES {
        return None;
    }
    let iife_src: &str = source.get(pos..call_end)?;
    if !is_pure_string_iife(iife_src) {
        return None;
    }
    let value: String = eval_to_string(iife_src)?;
    if !is_safe_literal_body(&value) {
        return None;
    }
    Some((call_end, quote_literal(&value)))
}

const IIFE_BANNED_TOKENS: [&str; 12] = [
    "while",
    "for",
    "this",
    "arguments",
    "new ",
    "=>",
    "eval",
    "Function",
    "+=",
    "++",
    "--",
    "delete",
];

fn is_pure_string_iife(iife: &str) -> bool {
    if !iife.contains("return ") {
        return false;
    }
    !IIFE_BANNED_TOKENS
        .iter()
        .any(|needle: &&str| iife.contains(needle))
}

fn normalize_string_member(source: &str) -> String {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_string(bytes, i, b);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end: usize = skip_line_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end: usize = skip_block_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            _ => {
                if let Some((member_end, prop)) = try_string_index(source, bytes, i) {
                    out.push_str("String.");
                    out.push_str(&prop);
                    i = member_end;
                } else {
                    out.push(b as char);
                    i += 1;
                }
            }
        }
    }
    out
}

fn try_string_index(source: &str, bytes: &[u8], pos: usize) -> Option<(usize, String)> {
    let head: &str = source.get(pos..pos + 6)?;
    if head != "String" {
        return None;
    }
    if pos > 0 && is_ident_byte(bytes[pos - 1]) {
        return None;
    }
    let mut j: usize = pos + 6;
    if bytes.get(j) != Some(&b'[') {
        return None;
    }
    j += 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let mut had_paren: bool = false;
    if bytes.get(j) == Some(&b'(') {
        had_paren = true;
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
    }
    let quote: u8 = *bytes.get(j)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let str_end: usize = skip_string(bytes, j, quote);
    let prop: &str = source.get(j + 1..str_end - 1)?;
    if !prop.chars().all(is_ident_char) || prop.is_empty() {
        return None;
    }
    let mut k: usize = str_end;
    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
        k += 1;
    }
    if had_paren {
        if bytes.get(k) != Some(&b')') {
            return None;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
    }
    if bytes.get(k) != Some(&b']') {
        return None;
    }
    k += 1;
    Some((k, prop.to_owned()))
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

fn fold_one_pass(source: &str) -> (String, usize) {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut folded: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_string(bytes, i, b);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end: usize = skip_line_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end: usize = skip_block_comment(bytes, i);
                out.push_str(&source[i..end]);
                i = end;
            }
            _ => {
                if let Some((call_end, literal)) = try_fold_at(source, bytes, i) {
                    out.push_str(&literal);
                    folded += 1;
                    i = call_end;
                } else {
                    out.push(b as char);
                    i += 1;
                }
            }
        }
    }
    (out, folded)
}

fn try_fold_at(source: &str, bytes: &[u8], pos: usize) -> Option<(usize, String)> {
    let head: &str = source.get(pos..pos + FROM_CHAR_CODE_LEN)?;
    if head != FROM_CHAR_CODE {
        return None;
    }
    if pos > 0 && is_ident_byte(bytes[pos - 1]) {
        return None;
    }
    let mut j: usize = pos + FROM_CHAR_CODE_LEN;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if bytes.get(j) != Some(&b'(') {
        return None;
    }
    let call_end: usize = match_balanced_paren(bytes, j)?;
    if call_end - pos > MAX_CALL_BYTES {
        return None;
    }
    let call_src: &str = source.get(pos..call_end)?;
    let value: String = eval_to_string(call_src)?;
    if !is_safe_literal_body(&value) {
        return None;
    }
    Some((call_end, quote_literal(&value)))
}

fn match_balanced_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth: usize = 0;
    let mut i: usize = open;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => i = skip_string(bytes, i, b),
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn is_safe_literal_body(value: &str) -> bool {
    if value.is_empty() || value.chars().count() > MAX_RESULT_CHARS {
        return false;
    }
    value.chars().all(|c: char| {
        !c.is_control() && c != '\\' && c != '\'' && c != '"' && c != '`' && c != '$'
    })
}

fn quote_literal(value: &str) -> String {
    let mut lit: String = String::with_capacity(value.len() + 2);
    lit.push('\'');
    lit.push_str(value);
    lit.push('\'');
    lit
}

fn skip_string(bytes: &[u8], start: usize, quote: u8) -> usize {
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

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn folds_octal_hex_decimal_chain() {
        let src: &str =
            "var n=String.fromCharCode(0146,0x72,0157,0155,0x43,0x68,0x61,114,0103,0157,100,101);";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.from_char_code_calls_folded, 1);
        assert!(out.contains("'fromCharCode'"), "got {out}");
    }

    #[test]
    fn folds_length_arithmetic_args() {
        let src: &str = "x[String.fromCharCode((01*0117+29),('R'.length*0x4e+23))];";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.from_char_code_calls_folded, 1);
        assert!(out.contains("'le'"), "got {out}");
    }

    #[test]
    fn ignores_member_named_fromcharcode_on_other_object() {
        let src: &str = "myString.fromCharCode(65);";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.from_char_code_calls_folded, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn leaves_string_literals_untouched() {
        let src: &str = "var s = 'String.fromCharCode(65)';";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.from_char_code_calls_folded, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn folds_nested_indirection_to_fixpoint() {
        let src: &str = "String[String.fromCharCode(0146,0x72,0157,0155,0103,0150,0x61,0x72,67,0157,0144,0x65)](65);";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert!(stats.from_char_code_calls_folded >= 2);
        assert!(
            out.contains("'A'"),
            "nested String[fromCharCode-chain](65) must fully resolve to the char: got {out}"
        );
    }

    #[test]
    fn rejects_unsafe_quote_bearing_result() {
        let src: &str = "String.fromCharCode(39);";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.from_char_code_calls_folded, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn folds_string_fragment_iife_to_literal() {
        let src: &str = "x[(function () { const m=\"l\",Y=\"e\",E=\"n\",G=\"gt\",_=\"h\"; return m+Y+E+G+_ })()];";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.string_iifes_folded, 1);
        assert!(out.contains("'length'"), "got {out}");
    }

    #[test]
    fn folds_mixed_iife_with_inner_fromcharcode() {
        let src: &str = "(function(){var $=(function () { var Js='X'; return Js })(),U=String.fromCharCode(97);return $+U;})();";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert!(stats.string_iifes_folded >= 1, "stats={stats:?} out={out}");
        assert!(out.contains("'Xa'"), "got {out}");
    }

    #[test]
    fn does_not_fold_side_effecting_iife() {
        let src: &str = "(function(){var n=0;for(var i=0;i<3;i++){n+=i;}return ''+n;})();";
        let (out, stats): (String, CharFoldStats) = fold_char_constructors(src);
        assert_eq!(stats.string_iifes_folded, 0);
        assert_eq!(out, src);
    }
}
