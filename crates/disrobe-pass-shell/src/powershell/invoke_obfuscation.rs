#![allow(clippy::collapsible_if)]
use std::io::Read;
use std::sync::LazyLock;

use disrobe_core::codec::{Base64Alphabet, Base64Padding, base64_decode};
use flate2::read::GzDecoder;
use lazy_regex::regex;
use regex::Regex;
use serde::Serialize;

use crate::error::{Error, Result, base64_error};

const MAX_DECOMPRESSED: u64 = 16 * 1024 * 1024;
const MAX_BASE64_INPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InvokeObfuscationLevel {
    Token,
    Ast,
    String,
    Encoding,
    Compress,
    Launcher,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReverseReport {
    pub level: InvokeObfuscationLevel,
    pub transformations: Vec<String>,
    pub output: String,
}

#[must_use]
pub fn reverse_token(input: &str) -> ReverseReport {
    let mut out: String = input.to_owned();
    let mut transformations: Vec<String> = Vec::new();
    if let Some(unticked) = strip_backtick_escapes(&out) {
        if unticked != out {
            transformations.push("strip-backtick-escapes".to_owned());
            out = unticked;
        }
    }
    if let Some(decased) = normalize_invoke_expression_aliases(&out) {
        if decased != out {
            transformations.push("normalize-iex-aliases".to_owned());
            out = decased;
        }
    }
    if let Some(charrun) = decode_char_array_concatenations(&out) {
        if charrun != out {
            transformations.push("decode-char-array".to_owned());
            out = charrun;
        }
    }
    if let Some(folded) = fold_plain_literals(&out) {
        if folded != out {
            transformations.push("fold-plain-literals".to_owned());
            out = folded;
        }
    }
    if let Some(decoded) = decode_multikey_xor_pipeline(&out) {
        if decoded != out {
            transformations.push("decode-multikey-xor-pipeline".to_owned());
            out = decoded;
        }
    }
    if let Some(decoded) = decode_numeric_char_pipeline(&out) {
        if decoded != out {
            transformations.push("decode-numeric-char-pipeline".to_owned());
            out = decoded;
        }
    }
    if let Some(canon) = canonicalise_iex_indirection(&out) {
        if canon != out {
            transformations.push("canonicalise-iex-indirection".to_owned());
            out = canon;
        }
    }
    if let Some(splatted) = collapse_splatting(&out) {
        if splatted != out {
            transformations.push("collapse-splatting".to_owned());
            out = splatted;
        }
    }
    ReverseReport {
        level: InvokeObfuscationLevel::Token,
        transformations,
        output: out,
    }
}

#[must_use]
pub fn reverse_ast(input: &str) -> ReverseReport {
    let mut out: String = input.to_owned();
    let mut transformations: Vec<String> = Vec::new();
    if let Some(direct) = unwrap_getcommand_indirection(&out) {
        if direct != out {
            transformations.push("unwrap-getcommand".to_owned());
            out = direct;
        }
    }
    if let Some(typed) = inline_typeresolve(&out) {
        if typed != out {
            transformations.push("inline-typeresolve".to_owned());
            out = typed;
        }
    }
    ReverseReport {
        level: InvokeObfuscationLevel::Ast,
        transformations,
        output: out,
    }
}

#[must_use]
pub fn reverse_string(input: &str) -> ReverseReport {
    let mut out: String = input.to_owned();
    let mut transformations: Vec<String> = Vec::new();
    if let Some(concatted) = fold_string_concatenations(&out) {
        if concatted != out {
            transformations.push("fold-concatenations".to_owned());
            out = concatted;
        }
    }
    if let Some(formatted) = fold_format_strings(&out) {
        if formatted != out {
            transformations.push("fold-format-strings".to_owned());
            out = formatted;
        }
    }
    if let Some(folded) = fold_literal_string_ops(&out) {
        if folded != out {
            transformations.push("fold-literal-string-ops".to_owned());
            out = folded;
        }
    }
    if let Some(folded) = fold_literal_subexpressions(&out) {
        if folded != out {
            transformations.push("fold-literal-subexpressions".to_owned());
            out = folded;
        }
    }
    if let Some(ascii) = decode_ascii_chains(&out) {
        if ascii != out {
            transformations.push("decode-ascii-chains".to_owned());
            out = ascii;
        }
    }
    if let Some(reversed) = fold_reversed_index_joins(&out) {
        if reversed != out {
            transformations.push("fold-reversed-index-joins".to_owned());
            out = reversed;
        }
    }
    ReverseReport {
        level: InvokeObfuscationLevel::String,
        transformations,
        output: out,
    }
}

pub fn reverse_encoding(input: &str) -> Result<ReverseReport> {
    let mut transformations: Vec<String> = Vec::new();
    let captured: Option<String> = extract_encoded_command(input);
    let Some(b64): Option<String> = captured else {
        return Ok(ReverseReport {
            level: InvokeObfuscationLevel::Encoding,
            transformations,
            output: input.to_owned(),
        });
    };
    transformations.push("extract-encodedcommand".to_owned());
    let bytes: Vec<u8> = decode_base64_bounded("encoded command", b64.trim())?;
    transformations.push("base64-decode".to_owned());
    let decoded: String = decode_utf16_le(&bytes).unwrap_or_else(|| decode_ascii_lossy(&bytes));
    transformations.push("utf16-le-decode".to_owned());
    Ok(ReverseReport {
        level: InvokeObfuscationLevel::Encoding,
        transformations,
        output: decoded,
    })
}

pub fn reverse_compress(input: &str) -> Result<ReverseReport> {
    let mut transformations: Vec<String> = Vec::new();
    let Some(b64): Option<String> = extract_compressed_payload(input) else {
        return Ok(ReverseReport {
            level: InvokeObfuscationLevel::Compress,
            transformations,
            output: input.to_owned(),
        });
    };
    transformations.push("extract-compress-payload".to_owned());
    let compressed: Vec<u8> = decode_base64_bounded("compressed payload", b64.trim())?;
    transformations.push("base64-decode".to_owned());
    let reserve: usize = compressed
        .len()
        .saturating_mul(4)
        .min(MAX_DECOMPRESSED as usize);
    let decoder: GzDecoder<&[u8]> = GzDecoder::new(&compressed[..]);
    let mut out: Vec<u8> = Vec::with_capacity(reserve);
    let produced: u64 = decoder
        .take(MAX_DECOMPRESSED.saturating_add(1))
        .read_to_end(&mut out)
        .map(|n: usize| n as u64)?;
    if produced > MAX_DECOMPRESSED {
        out.truncate(MAX_DECOMPRESSED as usize);
        transformations.push("gzip-inflate-capped".to_owned());
    } else {
        transformations.push("gzip-inflate".to_owned());
    }
    let utf16: Option<String> = decode_utf16_le(&out);
    let text: String = utf16.unwrap_or_else(|| decode_ascii_lossy(&out));
    Ok(ReverseReport {
        level: InvokeObfuscationLevel::Compress,
        transformations,
        output: text,
    })
}

fn decode_base64_bounded(what: &'static str, b64: &str) -> Result<Vec<u8>> {
    if b64.len() > MAX_BASE64_INPUT {
        return Err(Error::InputTooLarge {
            what,
            max_bytes: MAX_BASE64_INPUT,
        });
    }
    base64_decode(
        b64.as_bytes(),
        Base64Alphabet::Standard,
        Base64Padding::Required,
    )
    .map_err(|source: disrobe_core::codec::DecodeError| base64_error(b64.as_bytes(), source))
}

#[must_use]
pub fn reverse_launcher(input: &str) -> ReverseReport {
    let mut out: String = input.to_owned();
    let mut transformations: Vec<String> = Vec::new();
    if let Some(no_wmic) = strip_wmic_proxy(&out) {
        if no_wmic != out {
            transformations.push("strip-wmic-proxy".to_owned());
            out = no_wmic;
        }
    }
    if let Some(canonical) = canonicalise_powershell_flags(&out) {
        if canonical != out {
            transformations.push("canonicalise-flags".to_owned());
            out = canonical;
        }
    }
    ReverseReport {
        level: InvokeObfuscationLevel::Launcher,
        transformations,
        output: out,
    }
}

fn ps_double_quoted(value: &str) -> String {
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '`' => out.push_str("``"),
            '"' => out.push_str("`\""),
            '$' => out.push_str("`$"),
            '\n' => out.push_str("`n"),
            '\r' => out.push_str("`r"),
            '\t' => out.push_str("`t"),
            '\0' => out.push_str("`0"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn strip_backtick_escapes(s: &str) -> Option<String> {
    if !s.contains('`') {
        return None;
    }
    let mut out: String = String::with_capacity(s.len());
    let mut chars: std::str::Chars<'_> = s.chars();
    while let Some(c) = chars.next() {
        if c == '`' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

static IEX_ALIAS: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\b(?:IEX|\.\s*Invoke|&\s*\(\s*'IEX'\s*\)|&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand[^)]*\))\b"
    )
});

fn normalize_invoke_expression_aliases(s: &str) -> Option<String> {
    if !IEX_ALIAS.is_match(s) {
        return None;
    }
    Some(IEX_ALIAS.replace_all(s, "Invoke-Expression").into_owned())
}

static CHAR_ARRAY: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"\[(?i)char\]\s*(?:0[xX][0-9A-Fa-f]{1,4}|\d{1,5})\b(?:\s*\+\s*\[(?i)char\]\s*(?:0[xX][0-9A-Fa-f]{1,4}|\d{1,5})\b)*"
    )
});

static CHAR_LIT: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"\[(?i)char\]\s*(?:0[xX]([0-9A-Fa-f]{1,4})|(\d{1,5}))\b"));

fn decode_char_array_concatenations(s: &str) -> Option<String> {
    if !CHAR_ARRAY.is_match(s) {
        return None;
    }
    let mut out: String = String::with_capacity(s.len());
    let mut last: usize = 0;
    for m in CHAR_ARRAY.find_iter(s) {
        out.push_str(&s[last..m.start()]);
        let matched: &str = m.as_str();
        let mut decoded: String = String::new();
        let mut complete: bool = true;
        for cap in CHAR_LIT.captures_iter(matched) {
            let code: Option<u32> = match (cap.get(1), cap.get(2)) {
                (Some(hex), _) => u32::from_str_radix(hex.as_str(), 16).ok(),
                (None, Some(dec)) => dec.as_str().parse::<u32>().ok(),
                (None, None) => None,
            };
            match code.filter(|n: &u32| *n <= 0xFFFF).and_then(char::from_u32) {
                Some(c) => decoded.push(c),
                None => complete = false,
            }
        }
        if decoded.is_empty() || !complete {
            out.push_str(matched);
        } else {
            out.push_str(&ps_double_quoted(&decoded));
        }
        last = m.end();
    }
    out.push_str(&s[last..]);
    Some(out)
}

static STRING_CAST_OF_LITERAL: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"\[(?i)string\]\s*('(?:[^']|'')*'|"[^"`$]*")"#));

static PLAIN_LITERAL_SUM: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"('(?:[^']|'')*'|"[^"`$]*")\s*\+\s*('(?:[^']|'')*'|"[^"`$]*")"#));

fn plain_literal_value(literal: &str) -> String {
    match literal.as_bytes().first() {
        Some(b'\'') => literal[1..literal.len() - 1].replace("''", "'"),
        _ => literal[1..literal.len() - 1].to_owned(),
    }
}

fn ps_literal(value: &str) -> String {
    if value.chars().any(char::is_control) {
        ps_double_quoted(value)
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

fn binds_tighter_than_addition(neighbour: Option<char>) -> bool {
    matches!(neighbour, Some('+' | '-' | '*' | '/' | '%' | '.' | '['))
}

fn fold_plain_literals(s: &str) -> Option<String> {
    let mut current: String = STRING_CAST_OF_LITERAL.replace_all(s, "$1").into_owned();
    for _ in 0..64usize {
        let Some((range, joined)): Option<(std::ops::Range<usize>, String)> = PLAIN_LITERAL_SUM
            .captures_iter(&current)
            .find_map(|c: regex::Captures<'_>| {
                let (whole, left, right) = (c.get(0)?, c.get(1)?, c.get(2)?);
                let before: Option<char> = current[..whole.start()].trim_end().chars().last();
                let after: Option<char> = current[whole.end()..].trim_start().chars().next();
                (!binds_tighter_than_addition(before)
                    && !matches!(after, Some('*' | '/' | '%' | '.' | '[')))
                .then(|| {
                    (
                        whole.range(),
                        format!(
                            "{}{}",
                            plain_literal_value(left.as_str()),
                            plain_literal_value(right.as_str())
                        ),
                    )
                })
            })
        else {
            break;
        };
        current.replace_range(range, &ps_literal(&joined));
    }
    (current != s).then_some(current)
}

static NUMERIC_PIPELINE: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?is)\(\s*((?:0x)?[0-9A-Fa-f]{1,4}(?:\s*,\s*(?:0x)?[0-9A-Fa-f]{1,4}){1,})\s*\)?\s*\|\s*(?:%|ForEach(?:-Object)?)\s*\{[^}]*?\[char\][^}]*?\}\s*\)?\s*-join\s*''"
    )
});

static PIPELINE_BXOR: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)-b\s*xor\s+(0x[0-9A-Fa-f]+|\d+)"));

static MULTIKEY_XOR_PIPELINE: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?is)\(\s*((?:0x)?[0-9A-Fa-f]{1,4}(?:\s*,\s*(?:0x)?[0-9A-Fa-f]{1,4}){1,})\s*\)?\s*\|\s*(?:%|ForEach(?:-Object)?)\s*\{[^}]*?\[char\][^}]*?-b\s*xor\s+(?:\$[A-Za-z_][A-Za-z0-9_]*|@?\(?\s*(?:0x)?[0-9A-Fa-f]+(?:\s*,\s*(?:0x)?[0-9A-Fa-f]+)+\s*\)?)[^}]*?\}\s*\)?\s*-join\s*''"
    )
});

static KEY_ARRAY_DECL: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(r"(?i)@?\(\s*((?:0x)?[0-9A-Fa-f]{1,4}(?:\s*,\s*(?:0x)?[0-9A-Fa-f]{1,4})+)\s*\)")
});

static PIPELINE_BASE: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)toint(?:16|32|64)\s*\(\s*\$_\s*,\s*(\d+)\s*\)"));

fn decode_numeric_char_pipeline(s: &str) -> Option<String> {
    if !NUMERIC_PIPELINE.is_match(s) {
        return None;
    }
    let result: std::borrow::Cow<'_, str> =
        NUMERIC_PIPELINE.replace_all(s, |c: &regex::Captures<'_>| {
            let whole: &str = c.get(0).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            let list: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            let xor_key: Option<u32> = PIPELINE_BXOR
                .captures(whole)
                .and_then(|x: regex::Captures<'_>| x.get(1))
                .and_then(|m: regex::Match<'_>| parse_int_token(m.as_str()));
            let radix: u32 = PIPELINE_BASE
                .captures(whole)
                .and_then(|x: regex::Captures<'_>| x.get(1))
                .and_then(|m: regex::Match<'_>| m.as_str().parse::<u32>().ok())
                .filter(|r: &u32| matches!(*r, 2 | 8 | 16))
                .unwrap_or(0);
            let mut decoded: String = String::new();
            for tok in list.split(',') {
                let raw: &str = tok.trim();
                let value: Option<u32> = if radix == 0 {
                    parse_int_token(raw)
                } else {
                    u32::from_str_radix(
                        raw.trim_start_matches("0x").trim_start_matches("0X"),
                        radix,
                    )
                    .ok()
                };
                let Some(mut n): Option<u32> = value else {
                    return whole.to_owned();
                };
                if let Some(k) = xor_key {
                    n ^= k;
                }
                match char::from_u32(n) {
                    Some(ch) => decoded.push(ch),
                    None => return whole.to_owned(),
                }
            }
            ps_double_quoted(&decoded)
        });
    Some(result.into_owned())
}

fn parse_int_token(tok: &str) -> Option<u32> {
    let t: &str = tok.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

fn decode_multikey_xor_pipeline(s: &str) -> Option<String> {
    if !MULTIKEY_XOR_PIPELINE.is_match(s) {
        return None;
    }
    let mut changed: bool = false;
    let result: std::borrow::Cow<'_, str> =
        MULTIKEY_XOR_PIPELINE.replace_all(s, |c: &regex::Captures<'_>| {
            let whole: &str = c.get(0).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            let list: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            let preceding: &str = &s[..c.get(0).map_or(0, |m: regex::Match<'_>| m.start())];
            let inline_key: Option<Vec<u32>> = KEY_ARRAY_DECL
                .captures_iter(whole)
                .last()
                .and_then(|k: regex::Captures<'_>| k.get(1))
                .map(|m: regex::Match<'_>| parse_int_list(m.as_str()));
            let key: Vec<u32> = inline_key
                .filter(|k: &Vec<u32>| !k.is_empty())
                .or_else(|| {
                    KEY_ARRAY_DECL
                        .captures_iter(preceding)
                        .last()
                        .and_then(|k: regex::Captures<'_>| k.get(1))
                        .map(|m: regex::Match<'_>| parse_int_list(m.as_str()))
                })
                .unwrap_or_default();
            if key.is_empty() {
                return whole.to_owned();
            }
            let bytes: Vec<u32> = parse_int_list(list);
            if bytes.is_empty() {
                return whole.to_owned();
            }
            let mut decoded: String = String::with_capacity(bytes.len());
            for (i, b) in bytes.iter().enumerate() {
                let k: u32 = key[i % key.len()];
                match char::from_u32(b ^ k) {
                    Some(ch) => decoded.push(ch),
                    None => return whole.to_owned(),
                }
            }
            changed = true;
            ps_double_quoted(&decoded)
        });
    if changed {
        Some(result.into_owned())
    } else {
        None
    }
}

fn parse_int_list(list: &str) -> Vec<u32> {
    list.split(',')
        .filter_map(|tok: &str| parse_int_token(tok.trim()))
        .collect()
}

static IEX_INDIRECT: LazyLock<Vec<&'static Regex>> = LazyLock::new(|| {
    vec![
        regex!(
            r"(?i)&?\s*\(\s*\$env:ComSpec\s*\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\]\s*-Join\s*''\s*\)"
        ),
        regex!(
            r"(?i)&?\s*\(\s*\(\s*(?:Get-Variable|GV|Variable)\s+'?\*mdr\*'?\s*\)\.Name\s*\[[\d,\s]+\]\s*-Join\s*''\s*\)"
        ),
        regex!(
            r"(?i)&?\s*\(\s*\$VerbosePreference\.ToString\s*\(\s*\)\s*\[[\d,\s]+\]\s*-Join\s*''\s*\)"
        ),
        regex!(r"(?i)&?\s*\(\s*\$ShellId\s*\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\]\s*-Join\s*''\s*\)"),
    ]
});

fn canonicalise_iex_indirection(s: &str) -> Option<String> {
    let mut out: String = s.to_owned();
    let mut touched: bool = false;
    for re in IEX_INDIRECT.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, "Invoke-Expression").into_owned();
            touched = true;
        }
    }
    if touched { Some(out) } else { None }
}

static SPLAT: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"@\(\s*([^()]*?)\s*\)\s*-join\s*''"));

fn collapse_splatting(s: &str) -> Option<String> {
    if !SPLAT.is_match(s) {
        return None;
    }
    let result: std::borrow::Cow<'_, str> = SPLAT.replace_all(s, |c: &regex::Captures<'_>| {
        let parts: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
        let pieces: Vec<&str> = parts.split(',').map(|p: &str| p.trim()).collect();
        let mut joined: String = String::with_capacity(parts.len());
        for piece in pieces {
            let stripped: &str = piece.trim_matches(|c: char| c == '"' || c == '\'');
            joined.push_str(stripped);
        }
        ps_double_quoted(&joined)
    });
    Some(result.into_owned())
}

static GETCOMMAND: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand\s*\(\s*'([A-Za-z\-]+)'\s*,\s*'[A-Za-z]+'\s*\)\s*\)"
    )
});

static GETCOMMAND_CMDLET: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(r"(?i)&\s*\(\s*(?:Get-Command|gcm)\s+(?:\(\s*)?'([A-Za-z\-]+)'(?:\s*\))?\s*\)")
});

fn unwrap_getcommand_indirection(s: &str) -> Option<String> {
    if !GETCOMMAND.is_match(s) && !GETCOMMAND_CMDLET.is_match(s) {
        return None;
    }
    let command_name = |c: &regex::Captures<'_>| -> String {
        c.get(1)
            .map(|m: regex::Match<'_>| m.as_str())
            .unwrap_or("")
            .to_owned()
    };
    let direct: String = GETCOMMAND.replace_all(s, command_name).into_owned();
    Some(
        GETCOMMAND_CMDLET
            .replace_all(&direct, command_name)
            .into_owned(),
    )
}

static TYPERESOLVE: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)\[type\]\s*\(\s*'([A-Za-z0-9\.\+]+)'\s*\)"));

fn inline_typeresolve(s: &str) -> Option<String> {
    if !TYPERESOLVE.is_match(s) {
        return None;
    }
    Some(
        TYPERESOLVE
            .replace_all(s, |c: &regex::Captures<'_>| {
                let t: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                format!("[{t}]")
            })
            .into_owned(),
    )
}

static CONCAT: LazyLock<&'static Regex> = LazyLock::new(|| regex!(r#"'([^']*)'\s*\+\s*'([^']*)'"#));

fn fold_string_concatenations(s: &str) -> Option<String> {
    if !CONCAT.is_match(s) {
        return None;
    }
    let mut current: String = s.to_owned();
    for _ in 0..32usize {
        let next: std::borrow::Cow<'_, str> =
            CONCAT.replace_all(&current, |c: &regex::Captures<'_>| {
                let a: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                let b: &str = c.get(2).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                format!("'{a}{b}'")
            });
        if next == current {
            break;
        }
        current = next.into_owned();
    }
    Some(current)
}

static FORMAT_STR: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"\(\s*['"]([^'"]*)['"]\s*-f\s*((?:\([^()]*\)|[^()])+)\)"#));

static LITERAL_REPLACE: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\(\s*'((?:[^']|'')*)'\s*-(c?)replace\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*\)"
    )
});

static LITERAL_SPLIT_JOIN: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\(\s*'((?:[^']|'')*)'\s*-(c?)split\s*'((?:[^']|'')*)'\s*\)\s*-join\s*'((?:[^']|'')*)'"
    )
});

static STATIC_JOIN: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\[string\]::join\(\s*'((?:[^']|'')*)'\s*,\s*\(\s*((?:'(?:[^']|'')*'\s*,\s*)*'(?:[^']|'')*')\s*\)\s*\)"
    )
});

static SINGLE_QUOTED: LazyLock<&'static Regex> = LazyLock::new(|| regex!(r"'((?:[^']|'')*)'"));

static CHAR_ARRAY_JOIN: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)-join\s*\[char\[\]\]\s*\(\s*((?:0x[0-9a-f]{1,4}|\d{1,5})(?:\s*,\s*(?:0x[0-9a-f]{1,4}|\d{1,5}))*)\s*\)"
    )
});

static INDEX_REVERSE_JOIN: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(r"\(\s*'((?:[^']|'')*)'\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*'((?:[^']|'')*)'\s*\)")
});

static LITERAL_SUBEXPRESSION: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"\$\(\s*'((?:[^']|'')*)'\s*\)"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    Code,
    Single,
    Double,
}

fn quote_state_at(text: &str, position: usize) -> QuoteState {
    let mut state: QuoteState = QuoteState::Code;
    let mut chars: std::iter::Peekable<std::str::CharIndices<'_>> = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if at >= position {
            break;
        }
        state = match (state, c) {
            (QuoteState::Code, '\'') => QuoteState::Single,
            (QuoteState::Code, '"') => QuoteState::Double,
            (QuoteState::Single, '\'') if chars.peek().is_some_and(|(_, n)| *n == '\'') => {
                chars.next();
                QuoteState::Single
            }
            (QuoteState::Single, '\'') | (QuoteState::Double, '"') => QuoteState::Code,
            (QuoteState::Double | QuoteState::Code, '`') => {
                chars.next();
                state
            }
            (other, _) => other,
        };
    }
    state
}

fn double_quoted_body(value: &str) -> Option<String> {
    let quoted: String = ps_double_quoted(value);
    quoted
        .strip_prefix('"')
        .and_then(|inner: &str| inner.strip_suffix('"'))
        .map(str::to_owned)
}

fn fold_literal_subexpressions(s: &str) -> Option<String> {
    if !LITERAL_SUBEXPRESSION.is_match(s) {
        return None;
    }
    let folded: String = LITERAL_SUBEXPRESSION
        .replace_all(s, |c: &regex::Captures<'_>| {
            let Some(whole): Option<regex::Match<'_>> = c.get(0) else {
                return String::new();
            };
            let value: String =
                single_quoted_value(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
            match quote_state_at(s, whole.start()) {
                QuoteState::Double => {
                    double_quoted_body(&value).unwrap_or_else(|| whole.as_str().to_owned())
                }
                QuoteState::Code => ps_literal(&value),
                QuoteState::Single => whole.as_str().to_owned(),
            }
        })
        .into_owned();
    (folded != s).then_some(folded)
}

fn single_quoted_value(raw: &str) -> String {
    raw.replace("''", "'")
}

fn is_plain_pattern(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.chars().any(|c: char| "\\^$.|?*+()[]{}".contains(c))
}

fn literal_positions(text: &str, pattern: &str, case_sensitive: bool) -> Option<Vec<usize>> {
    if !case_sensitive && !(text.is_ascii() && pattern.is_ascii()) {
        return None;
    }
    let haystack: String = if case_sensitive {
        text.to_owned()
    } else {
        text.to_ascii_lowercase()
    };
    let needle: String = if case_sensitive {
        pattern.to_owned()
    } else {
        pattern.to_ascii_lowercase()
    };
    Some(
        haystack
            .match_indices(&needle)
            .map(|(at, _): (usize, &str)| at)
            .collect(),
    )
}

fn literal_replace(text: &str, pattern: &str, with: &str, case_sensitive: bool) -> Option<String> {
    if !is_plain_pattern(pattern) || with.contains('$') {
        return None;
    }
    let mut out: String = String::with_capacity(text.len());
    let mut last: usize = 0;
    for at in literal_positions(text, pattern, case_sensitive)? {
        out.push_str(&text[last..at]);
        out.push_str(with);
        last = at + pattern.len();
    }
    out.push_str(&text[last..]);
    Some(out)
}

fn literal_split(text: &str, pattern: &str, case_sensitive: bool) -> Option<Vec<String>> {
    if !is_plain_pattern(pattern) {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut last: usize = 0;
    for at in literal_positions(text, pattern, case_sensitive)? {
        parts.push(text[last..at].to_owned());
        last = at + pattern.len();
    }
    parts.push(text[last..].to_owned());
    Some(parts)
}

fn unary_join_position(before: &str) -> bool {
    before
        .trim_end()
        .chars()
        .last()
        .is_none_or(|c: char| matches!(c, '(' | '=' | ',' | ';' | '|' | '{'))
}

fn fold_literal_string_ops(s: &str) -> Option<String> {
    let mut current: String = s.to_owned();
    for _ in 0..16usize {
        let before: String = current.clone();
        current = LITERAL_REPLACE
            .replace_all(&current, |c: &regex::Captures<'_>| {
                let whole: &str = c.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
                let text: String =
                    single_quoted_value(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
                let case_sensitive: bool =
                    c.get(2).is_some_and(|m: regex::Match<'_>| !m.is_empty());
                let pattern: String =
                    single_quoted_value(c.get(3).map_or("", |m: regex::Match<'_>| m.as_str()));
                let with: String =
                    single_quoted_value(c.get(4).map_or("", |m: regex::Match<'_>| m.as_str()));
                literal_replace(&text, &pattern, &with, case_sensitive)
                    .map_or_else(|| whole.to_owned(), |v: String| ps_literal(&v))
            })
            .into_owned();
        current = LITERAL_SPLIT_JOIN
            .replace_all(&current, |c: &regex::Captures<'_>| {
                let whole: &str = c.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
                let text: String =
                    single_quoted_value(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
                let case_sensitive: bool =
                    c.get(2).is_some_and(|m: regex::Match<'_>| !m.is_empty());
                let pattern: String =
                    single_quoted_value(c.get(3).map_or("", |m: regex::Match<'_>| m.as_str()));
                let glue: String =
                    single_quoted_value(c.get(4).map_or("", |m: regex::Match<'_>| m.as_str()));
                literal_split(&text, &pattern, case_sensitive).map_or_else(
                    || whole.to_owned(),
                    |parts: Vec<String>| ps_literal(&parts.join(&glue)),
                )
            })
            .into_owned();
        current = STATIC_JOIN
            .replace_all(&current, |c: &regex::Captures<'_>| {
                let glue: String =
                    single_quoted_value(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
                let items: Vec<String> = SINGLE_QUOTED
                    .captures_iter(c.get(2).map_or("", |m: regex::Match<'_>| m.as_str()))
                    .map(|item: regex::Captures<'_>| {
                        single_quoted_value(
                            item.get(1).map_or("", |m: regex::Match<'_>| m.as_str()),
                        )
                    })
                    .collect();
                ps_literal(&items.join(&glue))
            })
            .into_owned();
        let snapshot: String = current.clone();
        current = CHAR_ARRAY_JOIN
            .replace_all(&snapshot, |c: &regex::Captures<'_>| {
                let Some(whole): Option<regex::Match<'_>> = c.get(0) else {
                    return String::new();
                };
                let decoded: Option<String> = c
                    .get(1)
                    .map_or("", |m: regex::Match<'_>| m.as_str())
                    .split(',')
                    .map(|item: &str| {
                        let item: &str = item.trim();
                        let code: Option<u32> = match item.get(..2) {
                            Some(prefix) if prefix.eq_ignore_ascii_case("0x") => {
                                u32::from_str_radix(&item[2..], 16).ok()
                            }
                            _ => item.parse::<u32>().ok(),
                        };
                        code.filter(|n: &u32| *n <= 0xFFFF).and_then(char::from_u32)
                    })
                    .collect();
                match decoded {
                    Some(text) if unary_join_position(&snapshot[..whole.start()]) => {
                        ps_literal(&text)
                    }
                    _ => whole.as_str().to_owned(),
                }
            })
            .into_owned();
        current = INDEX_REVERSE_JOIN
            .replace_all(&current, |c: &regex::Captures<'_>| {
                let whole: &str = c.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
                let text: String =
                    single_quoted_value(c.get(1).map_or("", |m: regex::Match<'_>| m.as_str()));
                let count: Option<usize> = c
                    .get(2)
                    .and_then(|m: regex::Match<'_>| m.as_str().parse::<usize>().ok());
                let glue: String =
                    single_quoted_value(c.get(3).map_or("", |m: regex::Match<'_>| m.as_str()));
                if count != Some(text.chars().count()) {
                    return whole.to_owned();
                }
                let reversed: Vec<String> = text.chars().rev().map(String::from).collect();
                ps_literal(&reversed.join(&glue))
            })
            .into_owned();
        if current == before {
            break;
        }
    }
    (current != s).then_some(current)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FormatArg {
    Literal(String),
    Expression(String),
}

fn split_format_args(args_raw: &str) -> Vec<FormatArg> {
    let trimmed: &str = args_raw.trim();
    let args_raw: &str = trimmed
        .strip_prefix('(')
        .and_then(|inner: &str| inner.strip_suffix(')'))
        .filter(|inner: &&str| !inner.contains(['(', ')']))
        .unwrap_or(trimmed);
    let mut fields: Vec<String> = Vec::new();
    let mut current: String = String::new();
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = args_raw.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => {
                if q == '\'' && chars.peek() == Some(&'\'') {
                    chars.next();
                    current.push('\'');
                } else if q == '"' && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    quote = None;
                    current.push(c);
                }
            }
            Some(_) => current.push(c),
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    current.push(c);
                }
                ',' => {
                    fields.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            },
        }
    }
    fields.push(current);
    fields
        .into_iter()
        .map(|field: String| classify_format_arg(field.trim()))
        .collect()
}

fn format_with_literals(template: &str, args: &[FormatArg]) -> Option<String> {
    let mut out: String = String::with_capacity(template.len());
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut num: String = String::new();
                for nc in chars.by_ref() {
                    if nc == '}' {
                        break;
                    }
                    num.push(nc);
                }
                let index: usize = num.trim().parse::<usize>().ok()?;
                match args.get(index)? {
                    FormatArg::Literal(value) => out.push_str(value),
                    FormatArg::Expression(_) => return None,
                }
            }
            '}' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

fn classify_format_arg(field: &str) -> FormatArg {
    let bytes: &[u8] = field.as_bytes();
    if bytes.len() >= 2 {
        let first: u8 = bytes[0];
        let last: u8 = bytes[bytes.len() - 1];
        let inner: &str = &field[1..field.len() - 1];
        if first == last && first == b'\'' {
            return FormatArg::Literal(inner.to_owned());
        }
        if first == last && first == b'"' && !inner.contains(['$', '`']) {
            return FormatArg::Literal(inner.to_owned());
        }
    }
    if !field.is_empty() && field.bytes().all(|b: u8| b.is_ascii_digit()) {
        return FormatArg::Literal(field.to_owned());
    }
    FormatArg::Expression(field.to_owned())
}

fn fold_format_strings(s: &str) -> Option<String> {
    if !FORMAT_STR.is_match(s) {
        return None;
    }
    Some(
        FORMAT_STR
            .replace_all(s, |c: &regex::Captures<'_>| {
                let whole: &str = c.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
                let template: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
                let args_raw: &str = c.get(2).map_or("", |m: regex::Match<'_>| m.as_str());
                let args: Vec<FormatArg> = split_format_args(args_raw);
                format_with_literals(template, &args)
                    .map_or_else(|| whole.to_owned(), |out: String| ps_double_quoted(&out))
            })
            .into_owned(),
    )
}

static REVERSED_INDEX_JOIN: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"-join\s*\(\s*'([^']*)'\s*\[\s*-1\s*\.\.\s*-\s*(\d+)\s*\]\s*\)"));

fn fold_reversed_index_joins(s: &str) -> Option<String> {
    if !REVERSED_INDEX_JOIN.is_match(s) {
        return None;
    }
    Some(
        REVERSED_INDEX_JOIN
            .replace_all(s, |c: &regex::Captures<'_>| {
                let whole: &str = c.get(0).map_or("", |m: regex::Match<'_>| m.as_str());
                let literal: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
                let count: Option<usize> = c
                    .get(2)
                    .and_then(|m: regex::Match<'_>| m.as_str().parse::<usize>().ok());
                let chars: Vec<char> = literal.chars().collect();
                match count {
                    Some(n) if n == chars.len() => {
                        ps_double_quoted(&chars.iter().rev().collect::<String>())
                    }
                    _ => whole.to_owned(),
                }
            })
            .into_owned(),
    )
}

static ASCII_CHAIN: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"\[(?i)char\]\s*\[(?i)byte\]\s*0x([0-9A-Fa-f]{2})"));

fn decode_ascii_chains(s: &str) -> Option<String> {
    if !ASCII_CHAIN.is_match(s) {
        return None;
    }
    Some(
        ASCII_CHAIN
            .replace_all(s, |c: &regex::Captures<'_>| {
                let hex: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                u8::from_str_radix(hex, 16).map_or_else(
                    |_| format!("[char][byte]0x{hex}"),
                    |b: u8| ps_double_quoted(&(b as char).to_string()),
                )
            })
            .into_owned(),
    )
}

static ENCODED_FLAG: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]+)"));

fn extract_encoded_command(s: &str) -> Option<String> {
    ENCODED_FLAG.captures(s).and_then(|c: regex::Captures<'_>| {
        c.get(1).map(|m: regex::Match<'_>| m.as_str().to_owned())
    })
}

static FROM_B64: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"#));

fn extract_compressed_payload(s: &str) -> Option<String> {
    FROM_B64.captures(s).and_then(|c: regex::Captures<'_>| {
        c.get(1).map(|m: regex::Match<'_>| m.as_str().to_owned())
    })
}

fn decode_utf16_le(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&words).ok()
}

fn decode_ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

static FLAG_NORM: LazyLock<Vec<(&'static Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (regex!(r"(?i)-w\s+hidden"), "-WindowStyle Hidden"),
        (regex!(r"(?i)-w(?:indowstyle)?\s+1"), "-WindowStyle Hidden"),
        (regex!(r"(?i)-nop\b"), "-NoProfile"),
        (regex!(r"(?i)-noni\b"), "-NonInteractive"),
        (regex!(r"(?i)-exec\s+bypass"), "-ExecutionPolicy Bypass"),
        (regex!(r"(?i)-ep\s+bypass"), "-ExecutionPolicy Bypass"),
    ]
});

fn canonicalise_powershell_flags(s: &str) -> Option<String> {
    let mut out: String = s.to_owned();
    let mut touched: bool = false;
    for (re, rep) in FLAG_NORM.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *rep).into_owned();
            touched = true;
        }
    }
    if touched { Some(out) } else { None }
}

static WMIC_PROXY: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(r#"(?i)wmic\s+process\s+call\s+create\s+['"]?(?P<cmd>powershell[^'"]*)['"]?"#)
});

fn strip_wmic_proxy(s: &str) -> Option<String> {
    if !WMIC_PROXY.is_match(s) {
        return None;
    }
    Some(
        WMIC_PROXY
            .replace_all(s, |c: &regex::Captures<'_>| {
                c.name("cmd")
                    .map(|m: regex::Match<'_>| m.as_str())
                    .unwrap_or("")
                    .to_owned()
            })
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;

    #[test]
    fn token_strips_backticks() {
        let r: ReverseReport = reverse_token("I`E`X 'Get-Process'");
        assert!(r.output.contains("Invoke-Expression") || r.output.contains("IEX"));
        assert!(
            r.transformations
                .contains(&"strip-backtick-escapes".to_owned())
        );
    }

    #[test]
    fn token_decodes_char_array() {
        let r: ReverseReport = reverse_token("[char]73 + [char]69 + [char]88");
        assert!(r.output.contains("\"IEX\""));
    }

    #[test]
    fn token_char_array_escapes_quote_backtick_dollar() {
        let quote: ReverseReport = reverse_token("[char]72 + [char]34 + [char]105");
        assert_eq!(quote.output, "\"H`\"i\"", "embedded double-quote output");

        let dollar: ReverseReport = reverse_token("[char]36 + [char]120");
        assert_eq!(dollar.output, "\"`$x\"", "dollar output");

        let backtick: ReverseReport = reverse_token("[char]96 + [char]97");
        assert_eq!(backtick.output, "\"``a\"", "backtick output");

        let newline: ReverseReport = reverse_token("[char]65 + [char]10 + [char]66");
        assert_eq!(newline.output, "\"A`nB\"", "newline output");
    }

    #[test]
    fn ascii_chain_escapes_special_chars() {
        let r: ReverseReport = reverse_string("[char][byte]0x22");
        assert_eq!(r.output, "\"`\"\"", "0x22 is a double-quote");
    }

    #[test]
    fn token_decodes_ascii_numeric_pipeline() {
        let r: ReverseReport = reverse_token("(72,101,108,108,111 | %{[char]$_}) -join ''");
        assert!(r.output.contains("\"Hello\""), "out: {}", r.output);
        assert!(
            r.transformations
                .contains(&"decode-numeric-char-pipeline".to_owned())
        );
    }

    #[test]
    fn token_decodes_bxor_numeric_pipeline() {
        let plain: &str = "IEX";
        let key: u32 = 42;
        let encoded: String = plain
            .bytes()
            .map(|b: u8| (u32::from(b) ^ key).to_string())
            .collect::<Vec<String>>()
            .join(",");
        let src: String =
            format!("({encoded} | ForEach-Object {{[char]($_ -bxor {key})}}) -join ''");
        let r: ReverseReport = reverse_token(&src);
        assert!(r.output.contains("\"IEX\""), "out: {}", r.output);
    }

    #[test]
    fn token_decodes_hex_numeric_pipeline() {
        let r: ReverseReport =
            reverse_token("(0x48,0x69 | %{[char][Convert]::ToInt16($_,16)}) -join ''");
        assert!(r.output.contains("\"Hi\""), "out: {}", r.output);
    }

    #[test]
    fn token_decodes_multikey_xor_pipeline() {
        let plain: &str = "Invoke-Mimikatz";
        let key: [u32; 3] = [0x11, 0x37, 0x5A];
        let encoded: String = plain
            .bytes()
            .enumerate()
            .map(|(i, b): (usize, u8)| (u32::from(b) ^ key[i % key.len()]).to_string())
            .collect::<Vec<String>>()
            .join(",");
        let src: String = format!(
            "$k=@(17,55,90); ({encoded} | ForEach-Object {{[char]($_ -bxor $k[$i++ % $k.Count])}}) -join ''"
        );
        let r: ReverseReport = reverse_token(&src);
        assert!(
            r.output.contains("\"Invoke-Mimikatz\""),
            "multi-key xor output: {}",
            r.output
        );
        assert!(
            r.transformations
                .contains(&"decode-multikey-xor-pipeline".to_owned())
        );
    }

    #[test]
    fn token_multikey_xor_with_inline_key_array() {
        let plain: &str = "calc";
        let key: [u32; 2] = [0x2A, 0x4B];
        let encoded: String = plain
            .bytes()
            .enumerate()
            .map(|(i, b): (usize, u8)| (u32::from(b) ^ key[i % key.len()]).to_string())
            .collect::<Vec<String>>()
            .join(",");
        let src: String =
            format!("({encoded} | %{{[char]($_ -bxor @(42,75)[$i++ % 2])}}) -join ''");
        let r: ReverseReport = reverse_token(&src);
        assert!(
            r.output.contains("\"calc\""),
            "inline-key output: {}",
            r.output
        );
    }

    #[test]
    fn token_canonicalises_comspec_indirection() {
        let r: ReverseReport = reverse_token("&( $env:ComSpec[4,15,25]-Join'')( 'Get-Process' )");
        assert!(r.output.contains("Invoke-Expression"), "out: {}", r.output);
    }

    #[test]
    fn token_canonicalises_mdr_variable_indirection() {
        let r: ReverseReport = reverse_token("((Variable '*mdr*').Name[3,11,2]-Join'')( $sc )");
        assert!(r.output.contains("Invoke-Expression"), "out: {}", r.output);
    }

    #[test]
    fn string_folds_concatenation() {
        let r: ReverseReport = reverse_string("'Get-' + 'Process'");
        assert_eq!(r.output, "'Get-Process'");
    }

    #[test]
    fn string_folds_format() {
        let r: ReverseReport = reverse_string("('{0}-{1}' -f 'Get','Process')");
        assert_eq!(r.output, "\"Get-Process\"");
    }

    #[test]
    fn string_format_preserves_comma_inside_quoted_fragment() {
        let r: ReverseReport = reverse_string("(\"{0}{1}{2}\" -f 'a,','b',',c')");
        assert_eq!(
            r.output, "\"a,b,c\"",
            "commas inside quoted -f fragments must not split arguments"
        );
    }

    #[test]
    fn string_format_reorder_with_comma_fragment() {
        let r: ReverseReport = reverse_string("(\"{1}{0}\" -f ',World','Hello')");
        assert_eq!(r.output, "\"Hello,World\"");
    }

    #[test]
    fn string_format_single_arg_containing_comma() {
        let r: ReverseReport = reverse_string("(\"{0}\" -f 'x,y')");
        assert_eq!(r.output, "\"x,y\"");
    }

    #[test]
    fn string_format_undoubles_single_quote_escape() {
        let r: ReverseReport = reverse_string("(\"{0}{1}\" -f 'it''s ','here')");
        assert_eq!(r.output, "\"it's here\"");
    }

    #[test]
    fn split_format_args_keeps_variable_argument_verbatim() {
        let args: Vec<FormatArg> = split_format_args("'Host: ',$ComputerName");
        assert_eq!(
            args,
            vec![
                FormatArg::Literal("Host: ".to_owned()),
                FormatArg::Expression("$ComputerName".to_owned())
            ]
        );
    }

    #[test]
    fn literal_replace_split_join_and_reversal_fold_to_their_values() {
        for (input, expected) in [
            ("('WrXite-XHost' -replace 'X','')", "'Write-Host'"),
            ("('Write' -replace 'RIT','xyz')", "'Wxyze'"),
            ("('Write' -creplace 'RIT','xyz')", "'Write'"),
            ("[String]::Join('-', ('a','b'))", "'a-b'"),
            ("x = -join [char[]](72,0x69)", "x = 'Hi'"),
            ("('a,b' -split ',') -join '+'", "'a+b'"),
            ("('cba'[-1..-3] -join '')", "'abc'"),
        ] {
            assert_eq!(reverse_string(input).output, expected, "{input}");
        }
        for kept in [
            "('a.b' -replace '.','x')",
            "('ab' -replace 'a','$0')",
            "$s -join [char[]](72,105)",
            "('cba'[-1..-2] -join '')",
        ] {
            assert_eq!(reverse_string(kept).output, kept, "{kept}");
        }
    }

    #[test]
    fn a_literal_subexpression_folds_in_its_quoting_context() {
        assert_eq!(reverse_string("\"Wr$('ite')\"").output, "\"Write\"");
        assert_eq!(reverse_string("x = $('Host')").output, "x = 'Host'");
        assert_eq!(reverse_string("\"a$('$b')\"").output, "\"a`$b\"");
        let kept: &str = "'$(''x'')'";
        assert_eq!(reverse_string(kept).output, kept);
    }

    #[test]
    fn a_format_over_a_variable_or_a_format_spec_is_left_for_powershell() {
        for kept in [
            "('{0}{1}' -f 'Host: ',$ComputerName)",
            "('{0,5}' -f 'ab')",
            "('{0:X}' -f 255)",
            "('{2}' -f 'a','b')",
        ] {
            assert_eq!(reverse_string(kept).output, kept, "{kept}");
        }
        assert_eq!(
            reverse_string("('{0}{1}' -f ('Wr','ite'))").output,
            "\"Write\""
        );
    }

    #[test]
    fn encoding_decodes_utf16_base64() -> Result<()> {
        assert_eq!(decode_base64_bounded("encoded command", "Zg==")?, b"f");
        let expected_result: std::result::Result<Vec<u8>, base64::DecodeError> =
            BASE64_STD.decode("Zg");
        let Err(expected_source): std::result::Result<Vec<u8>, base64::DecodeError> =
            expected_result
        else {
            return Err(Error::InvalidUtf16Le);
        };
        let expected: String = Error::Base64(expected_source).to_string();
        let error_result: Result<Vec<u8>> = decode_base64_bounded("encoded command", "Zg");
        let Err(error): Result<Vec<u8>> = error_result else {
            return Err(Error::InvalidUtf16Le);
        };
        assert!(matches!(&error, Error::Base64(_)));
        assert_eq!(error.to_string(), expected);
        let payload: &str = "Get-Process";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        let b64: String = BASE64_STD.encode(utf16);
        let cmd: String = format!("powershell -nop -e {b64}");
        let r: ReverseReport = reverse_encoding(&cmd)?;
        assert_eq!(r.output, payload);
        Ok(())
    }

    #[test]
    fn encoding_rejects_oversized_base64_input() {
        let oversized: String = "A".repeat(MAX_BASE64_INPUT + 1);
        let cmd: String = format!("powershell -nop -e {oversized}");
        let result: Result<ReverseReport> = reverse_encoding(&cmd);
        assert!(matches!(
            result,
            Err(crate::error::Error::InputTooLarge {
                what: "encoded command",
                max_bytes: MAX_BASE64_INPUT
            })
        ));
    }

    #[test]
    fn compress_decodes_gzip_base64() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let payload: &str = "Write-Host 'hello compressed'";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&utf16)?;
        let compressed: Vec<u8> = gz.finish()?;
        let b64: String = BASE64_STD.encode(&compressed);
        let snippet: String = format!(
            "$d = [IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('{b64}')), [IO.Compression.CompressionMode]::Decompress)"
        );
        let r: ReverseReport = reverse_compress(&snippet)?;
        assert!(r.output.contains("hello compressed"));
        Ok(())
    }

    #[test]
    fn compress_rejects_oversized_base64_input() {
        let oversized: String = "A".repeat(MAX_BASE64_INPUT + 1);
        let snippet: String = format!("[Convert]::FromBase64String('{oversized}')");
        let result: Result<ReverseReport> = reverse_compress(&snippet);
        assert!(matches!(
            result,
            Err(crate::error::Error::InputTooLarge {
                what: "compressed payload",
                max_bytes: MAX_BASE64_INPUT
            })
        ));
    }

    #[test]
    fn compress_gzip_bomb_is_capped_not_oom() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let bomb: Vec<u8> = vec![0u8; (MAX_DECOMPRESSED as usize) + (4 * 1024 * 1024)];
        let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(&bomb)?;
        let compressed: Vec<u8> = gz.finish()?;
        let b64: String = BASE64_STD.encode(&compressed);
        let snippet: String = format!("[Convert]::FromBase64String('{b64}')");
        let r: ReverseReport = reverse_compress(&snippet)?;
        assert!(
            r.output.len() <= MAX_DECOMPRESSED as usize,
            "output {} exceeds cap",
            r.output.len()
        );
        assert!(
            r.transformations
                .contains(&"gzip-inflate-capped".to_owned())
        );
        Ok(())
    }

    #[test]
    fn launcher_canonicalises_flags() {
        let r: ReverseReport = reverse_launcher("powershell -w hidden -nop -exec bypass -c whoami");
        assert!(r.output.contains("-WindowStyle Hidden"));
        assert!(r.output.contains("-NoProfile"));
        assert!(r.output.contains("-ExecutionPolicy Bypass"));
    }

    #[test]
    fn launcher_strips_wmic_proxy() {
        let r: ReverseReport =
            reverse_launcher("wmic process call create 'powershell -nop -c calc.exe'");
        assert!(r.output.starts_with("powershell"));
    }

    #[test]
    fn ast_unwraps_getcommand_indirection() {
        let r: ReverseReport =
            reverse_ast("& ($ExecutionContext.InvokeCommand.GetCommand('Get-Process','Cmdlet'))");
        assert_eq!(r.output, "Get-Process");
    }

    #[test]
    fn ast_unwraps_get_command_cmdlet_indirection() {
        let r: ReverseReport =
            reverse_ast("& (Get-Command ('Write-Host')) -Object 'hi'; & (gcm 'Get-Date')");
        assert_eq!(r.output, "Write-Host -Object 'hi'; Get-Date");
    }

    #[test]
    fn unused_error_variant_is_constructible() {
        let e: crate::error::Error = crate::error::Error::UnknownObfuscationLevel;
        assert_eq!(format!("{e}"), "invoke-obfuscation level not recognized");
    }
}
