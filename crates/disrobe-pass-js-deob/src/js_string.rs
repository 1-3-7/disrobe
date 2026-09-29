#[must_use]
pub(crate) fn unescape_string_literal(input: &str) -> Option<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out: String = String::with_capacity(input.len());
    let mut index: usize = 0;
    while let Some(&ch) = chars.get(index) {
        index += 1;
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(&escape): Option<&char> = chars.get(index) else {
            out.push('\\');
            break;
        };
        index += 1;
        match escape {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'v' => out.push('\u{000B}'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            '0' => out.push('\0'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            '/' => out.push('/'),
            '\\' => out.push('\\'),
            '\n' | '\u{2028}' | '\u{2029}' => {}
            '\r' => {
                if chars.get(index) == Some(&'\n') {
                    index += 1;
                }
            }
            'x' => index = decode_hex_escape(&chars, index, &mut out),
            'u' => index = decode_unicode_escape(&chars, index, &mut out)?,
            other => out.push(other),
        }
    }
    Some(out)
}

fn decode_hex_escape(chars: &[char], at: usize, out: &mut String) -> usize {
    let high: Option<u32> = chars.get(at).and_then(|c: &char| c.to_digit(16));
    let low: Option<u32> = chars.get(at + 1).and_then(|c: &char| c.to_digit(16));
    let Some((high, low)): Option<(u32, u32)> = high.zip(low) else {
        out.push('x');
        return at;
    };
    if let Some(decoded) = char::from_u32((high << 4) | low) {
        out.push(decoded);
    }
    at + 2
}

fn decode_unicode_escape(chars: &[char], at: usize, out: &mut String) -> Option<usize> {
    if chars.get(at) == Some(&'{') {
        return decode_code_point_escape(chars, at, out);
    }
    let Some(leading): Option<u32> = read_hex4(chars, at) else {
        out.push('u');
        return Some(at);
    };
    let after_leading: usize = at + 4;
    if (0xD800..=0xDBFF).contains(&leading)
        && chars.get(after_leading) == Some(&'\\')
        && chars.get(after_leading + 1) == Some(&'u')
        && let Some(trailing) = read_hex4(chars, after_leading + 2)
        && (0xDC00..=0xDFFF).contains(&trailing)
    {
        let code: u32 = 0x1_0000 + ((leading - 0xD800) << 10) + (trailing - 0xDC00);
        out.push(char::from_u32(code)?);
        return Some(after_leading + 6);
    }
    out.push(char::from_u32(leading)?);
    Some(after_leading)
}

fn decode_code_point_escape(chars: &[char], at: usize, out: &mut String) -> Option<usize> {
    let mut end: usize = at + 1;
    let mut code: Option<u32> = Some(0);
    while let Some(digit) = chars.get(end).and_then(|c: &char| c.to_digit(16)) {
        code = code.and_then(|value: u32| value.checked_mul(16)?.checked_add(digit));
        end += 1;
    }
    if end == at + 1 || chars.get(end) != Some(&'}') {
        out.push('u');
        return Some(at);
    }
    out.push(char::from_u32(code?)?);
    Some(end + 1)
}

fn read_hex4(chars: &[char], at: usize) -> Option<u32> {
    let mut code: u32 = 0;
    for offset in 0..4_usize {
        let digit: u32 = chars.get(at + offset)?.to_digit(16)?;
        code = (code << 4) | digit;
    }
    Some(code)
}

pub(crate) fn escape_string_body(value: &str, quote: char) -> String {
    let mut out: String = String::with_capacity(value.len());
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0b}' => out.push_str("\\v"),
            '\u{0c}' => out.push_str("\\f"),
            '\0' if !chars.peek().is_some_and(char::is_ascii_digit) => out.push_str("\\0"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => match u8::try_from(u32::from(c)) {
                Ok(byte) => {
                    out.push_str("\\x");
                    disrobe_core::codec::hex::push_byte(&mut out, byte);
                }
                Err(_) => out.push(c),
            },
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn quote_string(value: &str, quote: char) -> String {
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push(quote);
    out.push_str(&escape_string_body(value, quote));
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::{quote_string, unescape_string_literal};

    #[test]
    fn a_quoted_string_reads_back_as_the_same_value() {
        for value in [
            "plain",
            "it's",
            "say \"hi\"",
            "back\\slash",
            "line\nbreak\ttab\r",
            "nul\u{0}7 and nul\u{0}x",
            "bell\u{7} esc\u{1b} del\u{7f}",
            "sep\u{2028}para\u{2029}",
            "caf\u{e9} \u{65e5}\u{672c} \u{1f600}",
        ] {
            for quote in ['\'', '"'] {
                let quoted: String = quote_string(value, quote);
                let body: &str = &quoted[1..quoted.len() - 1];
                assert_eq!(
                    unescape_string_literal(body).as_deref(),
                    Some(value),
                    "{quoted}"
                );
                assert!(
                    !body.contains('\n') && !body.contains('\u{2028}'),
                    "{quoted}"
                );
            }
        }
        assert_eq!(quote_string("\u{0}1", '\''), "'\\x001'");
    }

    fn with_backslashes(template: &str) -> String {
        template.replace('~', "\\")
    }

    #[test]
    fn simple_control_escapes() {
        assert_eq!(
            unescape_string_literal(r"a\nb\tc\rd").as_deref(),
            Some("a\nb\tc\rd")
        );
        assert_eq!(
            unescape_string_literal(r"\b\f\v").as_deref(),
            Some("\u{0008}\u{000C}\u{000B}")
        );
        assert_eq!(unescape_string_literal(r"\0").as_deref(), Some("\0"));
    }

    #[test]
    fn quote_and_solidus_escapes() {
        assert_eq!(
            unescape_string_literal(r#"\'\"\\\/"#).as_deref(),
            Some("'\"\\/")
        );
    }

    #[test]
    fn hex_escapes_decode_latin1_range() {
        assert_eq!(
            unescape_string_literal(r"\x41\x42\x43").as_deref(),
            Some("ABC")
        );
        assert_eq!(
            unescape_string_literal(r"\xff").as_deref(),
            Some("\u{00FF}")
        );
    }

    #[test]
    fn malformed_hex_escape_is_preserved_not_dropped() {
        assert_eq!(unescape_string_literal(r"\xZZ").as_deref(), Some("xZZ"));
        assert_eq!(unescape_string_literal(r"\x4").as_deref(), Some("x4"));
    }

    #[test]
    fn unicode_escapes_decode_bmp() {
        let input: String = with_backslashes("A~u20ACz");
        assert_eq!(
            unescape_string_literal(&input).as_deref(),
            Some("A\u{20AC}z")
        );
    }

    #[test]
    fn surrogate_pair_is_combined_into_one_scalar() {
        let pair: String = with_backslashes("~uD83D~uDE00");
        assert_eq!(unescape_string_literal(&pair).as_deref(), Some("\u{1F600}"));
        let embedded: String = with_backslashes("a~uD83D~uDE00b");
        assert_eq!(
            unescape_string_literal(&embedded).as_deref(),
            Some("a\u{1F600}b")
        );
    }

    #[test]
    fn a_lone_surrogate_has_no_scalar_so_the_literal_is_not_decoded() {
        for template in [
            "a~uD83Db",
            "~uDE00",
            "~uD83D~u0041",
            "~u{D800}",
            "~u{110000}",
        ] {
            let lone: String = with_backslashes(template);
            assert_eq!(unescape_string_literal(&lone), None, "{template}");
        }
    }

    #[test]
    fn braced_code_point_escape_decodes() {
        assert_eq!(
            unescape_string_literal(r"\u{41}\u{1f600}").as_deref(),
            Some("A\u{1F600}")
        );
    }

    #[test]
    fn malformed_unicode_escape_is_preserved_not_dropped() {
        assert_eq!(unescape_string_literal(r"\uZZZZ").as_deref(), Some("uZZZZ"));
        assert_eq!(unescape_string_literal(r"\u{}").as_deref(), Some("u{}"));
        assert_eq!(unescape_string_literal(r"\u{41").as_deref(), Some("u{41"));
    }

    #[test]
    fn line_continuation_produces_nothing() {
        assert_eq!(unescape_string_literal("a\\\nb").as_deref(), Some("ab"));
        assert_eq!(unescape_string_literal("a\\\r\nb").as_deref(), Some("ab"));
        assert_eq!(
            unescape_string_literal("a\\\u{2028}b").as_deref(),
            Some("ab")
        );
    }

    #[test]
    fn unknown_escape_passes_the_escaped_character_through() {
        assert_eq!(unescape_string_literal(r"\q\w\-").as_deref(), Some("qw-"));
    }

    #[test]
    fn trailing_backslash_is_kept() {
        assert_eq!(unescape_string_literal("abc\\").as_deref(), Some("abc\\"));
        assert_eq!(unescape_string_literal("\\").as_deref(), Some("\\"));
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(unescape_string_literal("").as_deref(), Some(""));
    }

    #[test]
    fn non_escaped_multibyte_text_survives() {
        assert_eq!(
            unescape_string_literal("héllo \u{1F600}").as_deref(),
            Some("héllo \u{1F600}")
        );
    }
}
