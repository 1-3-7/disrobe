#[must_use]
pub(crate) fn unescape_string_literal(input: &str) -> String {
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
            'u' => index = decode_unicode_escape(&chars, index, &mut out),
            other => out.push(other),
        }
    }
    out
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

fn decode_unicode_escape(chars: &[char], at: usize, out: &mut String) -> usize {
    if chars.get(at) == Some(&'{') {
        return decode_code_point_escape(chars, at, out);
    }
    let Some(leading): Option<u32> = read_hex4(chars, at) else {
        out.push('u');
        return at;
    };
    let after_leading: usize = at + 4;
    if (0xD800..=0xDBFF).contains(&leading)
        && chars.get(after_leading) == Some(&'\\')
        && chars.get(after_leading + 1) == Some(&'u')
        && let Some(trailing) = read_hex4(chars, after_leading + 2)
        && (0xDC00..=0xDFFF).contains(&trailing)
    {
        let code: u32 = 0x1_0000 + ((leading - 0xD800) << 10) + (trailing - 0xDC00);
        if let Some(decoded) = char::from_u32(code) {
            out.push(decoded);
        }
        return after_leading + 6;
    }
    if let Some(decoded) = char::from_u32(leading) {
        out.push(decoded);
    }
    after_leading
}

fn decode_code_point_escape(chars: &[char], at: usize, out: &mut String) -> usize {
    let mut end: usize = at + 1;
    let mut code: Option<u32> = Some(0);
    while let Some(digit) = chars.get(end).and_then(|c: &char| c.to_digit(16)) {
        code = code.and_then(|value: u32| value.checked_mul(16)?.checked_add(digit));
        end += 1;
    }
    if end == at + 1 || chars.get(end) != Some(&'}') {
        out.push('u');
        return at;
    }
    if let Some(value) = code
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
    }
    end + 1
}

fn read_hex4(chars: &[char], at: usize) -> Option<u32> {
    let mut code: u32 = 0;
    for offset in 0..4_usize {
        let digit: u32 = chars.get(at + offset)?.to_digit(16)?;
        code = (code << 4) | digit;
    }
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::unescape_string_literal;

    fn with_backslashes(template: &str) -> String {
        template.replace('~', "\\")
    }

    #[test]
    fn simple_control_escapes() {
        assert_eq!(unescape_string_literal(r"a\nb\tc\rd"), "a\nb\tc\rd");
        assert_eq!(
            unescape_string_literal(r"\b\f\v"),
            "\u{0008}\u{000C}\u{000B}"
        );
        assert_eq!(unescape_string_literal(r"\0"), "\0");
    }

    #[test]
    fn quote_and_solidus_escapes() {
        assert_eq!(unescape_string_literal(r#"\'\"\\\/"#), "'\"\\/");
    }

    #[test]
    fn hex_escapes_decode_latin1_range() {
        assert_eq!(unescape_string_literal(r"\x41\x42\x43"), "ABC");
        assert_eq!(unescape_string_literal(r"\xff"), "\u{00FF}");
    }

    #[test]
    fn malformed_hex_escape_is_preserved_not_dropped() {
        assert_eq!(unescape_string_literal(r"\xZZ"), "xZZ");
        assert_eq!(unescape_string_literal(r"\x4"), "x4");
    }

    #[test]
    fn unicode_escapes_decode_bmp() {
        let input: String = with_backslashes("A~u20ACz");
        assert_eq!(unescape_string_literal(&input), "A\u{20AC}z");
    }

    #[test]
    fn surrogate_pair_is_combined_into_one_scalar() {
        let pair: String = with_backslashes("~uD83D~uDE00");
        assert_eq!(unescape_string_literal(&pair), "\u{1F600}");
        let embedded: String = with_backslashes("a~uD83D~uDE00b");
        assert_eq!(unescape_string_literal(&embedded), "a\u{1F600}b");
    }

    #[test]
    fn lone_surrogate_has_no_scalar_and_is_dropped() {
        let lone: String = with_backslashes("a~uD83Db");
        assert_eq!(unescape_string_literal(&lone), "ab");
    }

    #[test]
    fn braced_code_point_escape_decodes() {
        assert_eq!(unescape_string_literal(r"\u{41}\u{1f600}"), "A\u{1F600}");
    }

    #[test]
    fn malformed_unicode_escape_is_preserved_not_dropped() {
        assert_eq!(unescape_string_literal(r"\uZZZZ"), "uZZZZ");
        assert_eq!(unescape_string_literal(r"\u{}"), "u{}");
        assert_eq!(unescape_string_literal(r"\u{41"), "u{41");
    }

    #[test]
    fn line_continuation_produces_nothing() {
        assert_eq!(unescape_string_literal("a\\\nb"), "ab");
        assert_eq!(unescape_string_literal("a\\\r\nb"), "ab");
        assert_eq!(unescape_string_literal("a\\\u{2028}b"), "ab");
    }

    #[test]
    fn unknown_escape_passes_the_escaped_character_through() {
        assert_eq!(unescape_string_literal(r"\q\w\-"), "qw-");
    }

    #[test]
    fn trailing_backslash_is_kept() {
        assert_eq!(unescape_string_literal("abc\\"), "abc\\");
        assert_eq!(unescape_string_literal("\\"), "\\");
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(unescape_string_literal(""), "");
    }

    #[test]
    fn non_escaped_multibyte_text_survives() {
        assert_eq!(
            unescape_string_literal("héllo \u{1F600}"),
            "héllo \u{1F600}"
        );
    }
}
