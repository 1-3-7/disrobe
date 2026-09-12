use serde::Serialize;

use super::sandbox::{eval_to_source, eval_to_string};

const JJ_SIG_PRIMARY: &str = "=~[]";
const JJ_SIG_INIT: &str = "{___:++";
const JJ_SIG_ALT_INIT: &str = "{ ___:++";
const MIN_LEN: usize = 80;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JjEncodeDetection {
    pub matched: bool,
    pub global_var: Option<String>,
    pub charset_size: usize,
    pub signature_hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct JjEncodeDecode {
    pub detection: JjEncodeDetection,
    pub recovered: Option<String>,
}

#[must_use]
pub fn detect_jjencode(source: &str) -> JjEncodeDetection {
    let trimmed: &str = source.trim();
    if trimmed.len() < MIN_LEN {
        return JjEncodeDetection::default();
    }
    let mut hits: usize = 0;
    if trimmed.contains(JJ_SIG_PRIMARY) {
        hits += 1;
    }
    if trimmed.contains(JJ_SIG_INIT) || trimmed.contains(JJ_SIG_ALT_INIT) {
        hits += 1;
    }
    if trimmed.contains("$.___") || trimmed.contains("[$.___]") {
        hits += 1;
    }
    let matched: bool = hits >= 2;
    let global: Option<String> = if matched {
        extract_global(trimmed)
    } else {
        None
    };
    let charset: usize = if matched { count_charset(trimmed) } else { 0 };
    JjEncodeDetection {
        matched,
        global_var: global,
        charset_size: charset,
        signature_hits: hits,
    }
}

#[must_use]
pub fn decode_jjencode(source: &str) -> JjEncodeDecode {
    let detection: JjEncodeDetection = detect_jjencode(source);
    if !detection.matched {
        return JjEncodeDecode {
            detection,
            recovered: None,
        };
    }
    let recovered: Option<String> = eval_to_source(source)
        .map(|s| normalize_recovered(&s))
        .or_else(|| {
            let intercepted: String = wrap_with_eval_capture(source);
            eval_to_string(&intercepted).map(|s| normalize_recovered(&s))
        });
    JjEncodeDecode {
        detection,
        recovered,
    }
}

fn normalize_recovered(captured: &str) -> String {
    let trimmed: &str = captured.trim_start();
    let Some(after_return): Option<&str> = trimmed.strip_prefix("return") else {
        return captured.to_owned();
    };
    let after: &str = after_return.trim_start();
    let bytes: &[u8] = after.as_bytes();
    let Some(&quote): Option<&u8> = bytes.first() else {
        return captured.to_owned();
    };
    if quote != b'"' && quote != b'\'' {
        return captured.to_owned();
    }
    decode_js_string_literal(after, quote).unwrap_or_else(|| captured.to_owned())
}

fn decode_js_string_literal(input: &str, quote: u8) -> Option<String> {
    let chars: Vec<char> = input.chars().collect();
    if chars.first().copied()? as u32 != u32::from(quote) {
        return None;
    }
    let mut out: String = String::with_capacity(input.len());
    let mut i: usize = 1;
    while i < chars.len() {
        let c: char = chars[i];
        if c as u32 == u32::from(quote) {
            return Some(out);
        }
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&esc): Option<&char> = chars.get(i) else {
            break;
        };
        match esc {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            'v' => out.push('\u{000B}'),
            '0'..='7' => {
                let (value, consumed): (u32, usize) = read_octal(&chars, i);
                if let Some(ch) = char::from_u32(value) {
                    out.push(ch);
                }
                i += consumed - 1;
            }
            'x' => {
                let value: Option<u32> = read_hex(&chars, i + 1, 2);
                if let Some(v) = value
                    && let Some(ch) = char::from_u32(v)
                {
                    out.push(ch);
                    i += 2;
                }
            }
            'u' => {
                if chars.get(i + 1).copied() == Some('{') {
                    let mut j: usize = i + 2;
                    let mut value: u32 = 0;
                    while let Some(&h) = chars.get(j) {
                        if h == '}' {
                            break;
                        }
                        value = (value << 4) | h.to_digit(16)?;
                        j += 1;
                    }
                    if let Some(ch) = char::from_u32(value) {
                        out.push(ch);
                    }
                    i = j;
                } else if let Some(v) = read_hex(&chars, i + 1, 4) {
                    if let Some(ch) = char::from_u32(v) {
                        out.push(ch);
                    }
                    i += 4;
                } else {
                    let (value, consumed): (u32, usize) = read_lenient_hex(&chars, i + 1);
                    if consumed > 0
                        && let Some(ch) = char::from_u32(value)
                    {
                        out.push(ch);
                        i += consumed;
                    }
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    Some(out)
}

fn read_octal(chars: &[char], start: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut consumed: usize = 0;
    while consumed < 3 {
        let Some(&c): Option<&char> = chars.get(start + consumed) else {
            break;
        };
        let Some(d): Option<u32> = c.to_digit(8) else {
            break;
        };
        value = value * 8 + d;
        consumed += 1;
    }
    (value, consumed.max(1))
}

fn read_hex(chars: &[char], start: usize, len: usize) -> Option<u32> {
    let mut value: u32 = 0;
    for offset in 0..len {
        let c: char = chars.get(start + offset).copied()?;
        value = (value << 4) | c.to_digit(16)?;
    }
    Some(value)
}

fn read_lenient_hex(chars: &[char], start: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut consumed: usize = 0;
    while consumed < 4 {
        let Some(&c): Option<&char> = chars.get(start + consumed) else {
            break;
        };
        let Some(d): Option<u32> = c.to_digit(16) else {
            break;
        };
        value = (value << 4) | d;
        consumed += 1;
    }
    (value, consumed)
}

fn wrap_with_eval_capture(source: &str) -> String {
    let mut wrapped: String = String::with_capacity(source.len() + 512);
    wrapped.push_str("(function(){");
    wrapped.push_str("var __DR_CAPTURE__ = '';");
    wrapped
        .push_str("var Function = function(s){__DR_CAPTURE__ = String(s); return function(){};};");
    wrapped.push_str("var eval = function(s){__DR_CAPTURE__ = String(s); return undefined;};");
    wrapped.push_str("try{");
    wrapped.push_str(source);
    wrapped.push_str("}catch(e){}");
    wrapped.push_str("return __DR_CAPTURE__;");
    wrapped.push_str("})()");
    wrapped
}

fn extract_global(source: &str) -> Option<String> {
    let idx: usize = source.find(JJ_SIG_PRIMARY)?;
    let head: &str = source[..idx].trim_end();
    let identifier_end: usize = head.len();
    let bytes: &[u8] = head.as_bytes();
    let mut start: usize = identifier_end;
    while start > 0 {
        let prev: u8 = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    let name: &str = &head[start..identifier_end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn count_charset(source: &str) -> usize {
    let mut seen: std::collections::BTreeSet<char> = std::collections::BTreeSet::new();
    for ch in source.chars() {
        if matches!(
            ch,
            '$' | '_'
                | '+'
                | '!'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '='
                | ','
                | ';'
                | '~'
                | '.'
                | '"'
                | '\\'
                | '/'
                | ':'
        ) {
            seen.insert(ch);
        }
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_normal_javascript() {
        let det: JjEncodeDetection = detect_jjencode("function foo(){return 42;}");
        assert!(!det.matched);
    }

    #[test]
    fn detects_signature_shape() {
        let src: &str = "$=~[];$={___:++$,$$$$:(![]+\"\")[$],__$:++$,$_$_:(![]+\"\")[$],_$_:++$,$_$$:({}+\"\")[$]};$.___;$.___;";
        let det: JjEncodeDetection = detect_jjencode(src);
        assert!(det.matched, "should detect jjencode signature");
        assert_eq!(det.global_var.as_deref(), Some("$"));
        assert!(det.charset_size >= 8);
    }

    #[test]
    fn normalize_decodes_octal_function_body() {
        let body: &str = "return\"\\150\\145\\154\\154\\157\"";
        assert_eq!(normalize_recovered(body), "hello");
    }

    #[test]
    fn normalize_decodes_lenient_unicode_escape() {
        let body: &str = "return\"caf\\ue9\"";
        assert_eq!(normalize_recovered(body), "caf\u{e9}");
    }

    #[test]
    fn normalize_passes_through_plain_source() {
        let plain: &str = "console.log(1)";
        assert_eq!(normalize_recovered(plain), plain);
    }

    #[test]
    fn decode_literal_handles_hex_and_named_escapes() {
        let decoded: Option<String> = decode_js_string_literal("\"a\\x42\\n\\tc\"", b'"');
        assert_eq!(decoded.as_deref(), Some("aB\n\tc"));
    }

    #[test]
    fn decode_literal_handles_braced_unicode() {
        let decoded: Option<String> = decode_js_string_literal("\"\\u{1f600}\"", b'"');
        assert_eq!(decoded.as_deref(), Some("\u{1f600}"));
    }
}
