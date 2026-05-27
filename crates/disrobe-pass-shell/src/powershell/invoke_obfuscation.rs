#![allow(clippy::collapsible_if)]

use std::io::Read;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;

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
    if let Some(decased) = normalise_invoke_expression_aliases(&out) {
        if decased != out {
            transformations.push("normalise-iex-aliases".to_owned());
            out = decased;
        }
    }
    if let Some(charrun) = decode_char_array_concatenations(&out) {
        if charrun != out {
            transformations.push("decode-char-array".to_owned());
            out = charrun;
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
    if let Some(ascii) = decode_ascii_chains(&out) {
        if ascii != out {
            transformations.push("decode-ascii-chains".to_owned());
            out = ascii;
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
    let bytes: Vec<u8> = BASE64_STD.decode(b64.trim())?;
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
    let compressed: Vec<u8> = BASE64_STD.decode(b64.trim())?;
    transformations.push("base64-decode".to_owned());
    let mut decoder: GzDecoder<&[u8]> = GzDecoder::new(&compressed[..]);
    let mut out: Vec<u8> = Vec::with_capacity(compressed.len() * 4);
    decoder.read_to_end(&mut out)?;
    transformations.push("gzip-inflate".to_owned());
    let utf16: Option<String> = decode_utf16_le(&out);
    let text: String = utf16.unwrap_or_else(|| decode_ascii_lossy(&out));
    Ok(ReverseReport {
        level: InvokeObfuscationLevel::Compress,
        transformations,
        output: text,
    })
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

static IEX_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r"(?i)\b(?:IEX|\.\s*Invoke|&\s*\(\s*'IEX'\s*\)|&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand[^)]*\))\b",
    )
});

fn normalise_invoke_expression_aliases(s: &str) -> Option<String> {
    if !IEX_ALIAS.is_match(s) {
        return None;
    }
    Some(IEX_ALIAS.replace_all(s, "Invoke-Expression").into_owned())
}

static CHAR_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"\[(?i)char\]\s*(\d{1,3})(?:\s*\+\s*\[(?i)char\]\s*(\d{1,3}))*")
});

static CHAR_LIT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"\[(?i)char\]\s*(\d{1,3})"));

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
        for cap in CHAR_LIT.captures_iter(matched) {
            if let Some(num) = cap.get(1) {
                if let Ok(n) = num.as_str().parse::<u32>() {
                    if let Some(c) = char::from_u32(n) {
                        decoded.push(c);
                    }
                }
            }
        }
        if decoded.is_empty() {
            out.push_str(matched);
        } else {
            out.push('"');
            out.push_str(&decoded);
            out.push('"');
        }
        last = m.end();
    }
    out.push_str(&s[last..]);
    Some(out)
}

static SPLAT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"@\(\s*([^()]*?)\s*\)\s*-join\s*''"));

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
        format!("\"{joined}\"")
    });
    Some(result.into_owned())
}

static GETCOMMAND: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r"(?i)&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand\s*\(\s*'([A-Za-z\-]+)'\s*,\s*'[A-Za-z]+'\s*\)\s*\)",
    )
});

fn unwrap_getcommand_indirection(s: &str) -> Option<String> {
    if !GETCOMMAND.is_match(s) {
        return None;
    }
    Some(
        GETCOMMAND
            .replace_all(s, |c: &regex::Captures<'_>| {
                c.get(1)
                    .map(|m: regex::Match<'_>| m.as_str())
                    .unwrap_or("")
                    .to_owned()
            })
            .into_owned(),
    )
}

static TYPERESOLVE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)\[type\]\s*\(\s*'([A-Za-z0-9\.\+]+)'\s*\)")
});

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

static CONCAT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"'([^']*)'\s*\+\s*'([^']*)'"#));

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

static FORMAT_STR: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"\(\s*['"]([^'"]*)['"]\s*-f\s*([^)]+)\)"#));

fn fold_format_strings(s: &str) -> Option<String> {
    if !FORMAT_STR.is_match(s) {
        return None;
    }
    Some(
        FORMAT_STR
            .replace_all(s, |c: &regex::Captures<'_>| {
                let template: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                let args_raw: &str = c.get(2).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
                let args: Vec<String> = args_raw
                    .split(',')
                    .map(|a: &str| {
                        a.trim()
                            .trim_matches(|c: char| c == '"' || c == '\'')
                            .to_owned()
                    })
                    .collect();
                let mut out: String = String::with_capacity(template.len());
                let mut chars: std::str::Chars<'_> = template.chars();
                while let Some(c) = chars.next() {
                    if c == '{' {
                        let mut num: String = String::new();
                        for nc in chars.by_ref() {
                            if nc == '}' {
                                break;
                            }
                            num.push(nc);
                        }
                        if let Ok(idx) = num.parse::<usize>() {
                            if let Some(v) = args.get(idx) {
                                out.push_str(v);
                                continue;
                            }
                        }
                        out.push('{');
                        out.push_str(&num);
                        out.push('}');
                    } else {
                        out.push(c);
                    }
                }
                format!("\"{out}\"")
            })
            .into_owned(),
    )
}

static ASCII_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"\[(?i)char\]\s*\[(?i)byte\]\s*0x([0-9A-Fa-f]{2})")
});

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
                    |b: u8| format!("\"{}\"", b as char),
                )
            })
            .into_owned(),
    )
}

static ENCODED_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]+)")
});

fn extract_encoded_command(s: &str) -> Option<String> {
    ENCODED_FLAG.captures(s).and_then(|c: regex::Captures<'_>| {
        c.get(1).map(|m: regex::Match<'_>| m.as_str().to_owned())
    })
}

static FROM_B64: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"#)
});

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

static FLAG_NORM: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let pairs: Vec<(&'static str, &'static str)> = vec![
        (r"(?i)-w\s+hidden", "-WindowStyle Hidden"),
        (r"(?i)-w(?:indowstyle)?\s+1", "-WindowStyle Hidden"),
        (r"(?i)-nop\b", "-NoProfile"),
        (r"(?i)-noni\b", "-NonInteractive"),
        (r"(?i)-exec\s+bypass", "-ExecutionPolicy Bypass"),
        (r"(?i)-ep\s+bypass", "-ExecutionPolicy Bypass"),
    ];
    pairs
        .into_iter()
        .map(|(p, r): (&'static str, &'static str)| (crate::regex_util::safe_regex(p), r))
        .collect()
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

static WMIC_PROXY: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)wmic\s+process\s+call\s+create\s+['"]?(?P<cmd>powershell[^'"]*)['"]?"#,
    )
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
    fn encoding_decodes_utf16_base64() -> Result<()> {
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
    fn unused_error_variant_is_constructible() {
        let e: crate::error::Error = crate::error::Error::UnknownObfuscationLevel;
        assert_eq!(format!("{e}"), "invoke-obfuscation level not recognised");
    }
}
