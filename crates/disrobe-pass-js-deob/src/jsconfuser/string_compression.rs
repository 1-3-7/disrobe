use std::collections::BTreeMap;
use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct StringCompressionResult {
    pub blocks_reversed: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_string_compression(source: &str) -> StringCompressionResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    collect_lzstring_code_strings(source, &mut edits);
    collect_lzstring_calls(source, &mut edits);
    collect_split_string_arrays(source, &mut edits);
    collect_string_fromcharcode_runs(source, &mut edits);
    if edits.is_empty() {
        return StringCompressionResult {
            blocks_reversed: 0,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, reversed): (String, usize) = apply_splice_edits(source, &mut edits);
    StringCompressionResult {
        blocks_reversed: reversed,
        rewritten_source: rewritten,
    }
}

fn collect_lzstring_code_strings(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'\'' | b'"') {
            let Some((end, units)): Option<(usize, Vec<u16>)> =
                read_js_string_literal_at(source, i)
            else {
                i += 1;
                continue;
            };
            if units.len() <= MAX_LZSTRING_INPUT_UNITS
                && let Ok(decoded) = String::from_utf16(&units)
                && decoded.contains("decompressFrom")
                && decoded.contains("_decompress")
            {
                let nested: StringCompressionResult = reverse_string_compression(&decoded);
                if nested.blocks_reversed > 0 {
                    edits.push((
                        i..end,
                        Some(format!(
                            "\"{}\"",
                            escape_js_string(&nested.rewritten_source)
                        )),
                    ));
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
}

const MAX_LZSTRING_INPUT_UNITS: usize = 1 << 20;
const MAX_LZSTRING_OUTPUT_UNITS: usize = 4 << 20;
const MAX_LZSTRING_DICT_ENTRIES: usize = 1 << 20;

fn collect_lzstring_calls(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let assigned_literals: BTreeMap<String, Vec<u16>> = collect_static_string_assignments(source);
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)(?:\b[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*(?:\.\s*|\[\s*["']))?\b(?P<method>decompressFromBase64|decompressFromEncodedURIComponent|decompressFromUTF16|decompress)(?:["']\s*\])?\s*\("#,
    ) else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(method): Option<&str> = caps.name("method").map(|m: regex::Match<'_>| m.as_str())
        else {
            continue;
        };
        let Some((call_end, units)): Option<(usize, Vec<u16>)> =
            read_lzstring_call_arg(source, whole.end(), &assigned_literals)
        else {
            continue;
        };
        let Some(decoded): Option<String> = lzstring_decompress_method(method, &units) else {
            continue;
        };
        edits.push((
            whole.start()..call_end,
            Some(format!("\"{}\"", escape_js_string(&decoded))),
        ));
    }
}

fn collect_static_string_assignments(source: &str) -> BTreeMap<String, Vec<u16>> {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"(?ms)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
    else {
        return BTreeMap::new();
    };
    let mut assignments: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    for literal_match in re.find_iter(source) {
        let Some(eq_pos): Option<usize> = previous_non_ws(source, literal_match.start()) else {
            continue;
        };
        if source.as_bytes().get(eq_pos) != Some(&b'=')
            || assignment_operator_is_comparison(source, eq_pos)
        {
            continue;
        }
        let Some(lhs_start): Option<usize> = find_assignment_lhs_start(source, eq_pos) else {
            continue;
        };
        let lhs: &str = source[lhs_start..eq_pos].trim();
        let Some(key): Option<String> = normalize_assignment_lhs(lhs) else {
            continue;
        };
        let Some(units): Option<Vec<u16>> = decode_js_string_units(literal_match.as_str()) else {
            continue;
        };
        if units.len() <= MAX_LZSTRING_INPUT_UNITS {
            assignments.insert(key, units);
        }
    }
    assignments
}

fn previous_non_ws(source: &str, end: usize) -> Option<usize> {
    source[..end]
        .char_indices()
        .rev()
        .find_map(|(idx, ch): (usize, char)| (!ch.is_whitespace()).then_some(idx))
}

fn assignment_operator_is_comparison(source: &str, eq_pos: usize) -> bool {
    let bytes: &[u8] = source.as_bytes();
    matches!(
        eq_pos.checked_sub(1).and_then(|idx: usize| bytes.get(idx)),
        Some(b'=' | b'!' | b'<' | b'>')
    ) || matches!(bytes.get(eq_pos + 1), Some(b'=' | b'>'))
}

fn find_assignment_lhs_start(source: &str, eq_pos: usize) -> Option<usize> {
    let mut depth: usize = 0;
    let mut start: usize = 0;
    for (idx, ch) in source[..eq_pos].char_indices().rev() {
        match ch {
            ']' => depth = depth.saturating_add(1),
            '[' => depth = depth.checked_sub(1)?,
            ',' | ';' | '{' | '(' | '\n' | '\r' if depth == 0 => {
                start = idx + ch.len_utf8();
                break;
            }
            _ => {}
        }
    }
    Some(start)
}

fn normalize_assignment_lhs(lhs: &str) -> Option<String> {
    let trimmed: &str = lhs.trim();
    let expr: &str = trimmed
        .strip_prefix("var ")
        .or_else(|| trimmed.strip_prefix("let "))
        .or_else(|| trimmed.strip_prefix("const "))
        .unwrap_or(trimmed)
        .trim();
    if !starts_with_js_identifier(expr) || expr.contains("=>") {
        return None;
    }
    Some(normalize_js_expr(expr))
}

fn read_lzstring_call_arg(
    source: &str,
    arg_start: usize,
    assigned_literals: &BTreeMap<String, Vec<u16>>,
) -> Option<(usize, Vec<u16>)> {
    let start: usize = skip_ws(source, arg_start);
    let first: char = source[start..].chars().next()?;
    let (arg_end, units): (usize, Vec<u16>) = if first == '\'' || first == '"' {
        read_js_string_literal_at(source, start)?
    } else {
        let expr_end: usize = find_call_arg_end(source, start)?;
        let expr: &str = source[start..expr_end].trim();
        let key: String = normalize_js_expr(expr);
        (expr_end, assigned_literals.get(&key)?.clone())
    };
    let close: usize = skip_ws(source, arg_end);
    if source.as_bytes().get(close) == Some(&b')') {
        Some((close + 1, units))
    } else {
        None
    }
}

fn skip_ws(source: &str, start: usize) -> usize {
    let mut idx: usize = start;
    for ch in source[start..].chars() {
        if !ch.is_whitespace() {
            break;
        }
        idx += ch.len_utf8();
    }
    idx
}

fn read_js_string_literal_at(source: &str, start: usize) -> Option<(usize, Vec<u16>)> {
    let quote: char = source[start..].chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let body_start: usize = start + quote.len_utf8();
    let mut escaped: bool = false;
    for (rel, ch) in source[body_start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            let end: usize = body_start + rel + ch.len_utf8();
            let literal: &str = &source[start..end];
            return Some((end, decode_js_string_units(literal)?));
        }
    }
    None
}

fn find_call_arg_end(source: &str, start: usize) -> Option<usize> {
    let mut bracket_depth: usize = 0;
    for (rel, ch) in source[start..].char_indices() {
        match ch {
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.checked_sub(1)?,
            ')' if bracket_depth == 0 => return Some(start + rel),
            ',' | ';' | '\n' | '\r' if bracket_depth == 0 => return None,
            _ => {}
        }
    }
    None
}

fn starts_with_js_identifier(expr: &str) -> bool {
    let mut chars: std::str::Chars<'_> = expr.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    first == '_' || first == '$' || first.is_ascii_alphabetic()
}

fn normalize_js_expr(expr: &str) -> String {
    expr.chars()
        .filter(|ch: &char| !ch.is_ascii_whitespace())
        .collect()
}

fn collect_split_string_arrays(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?ms)(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*['"]([^'"]+)['"]\.split\(\s*['"]([^'"]{1,2})['"]\s*\)"#,
    ) else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(payload): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(separator): Option<&str> = caps.get(2).map(|m: regex::Match<'_>| m.as_str())
        else {
            continue;
        };
        if !payload.contains(separator) {
            continue;
        }
        let words: Vec<&str> = payload.split(separator).collect();
        let array_literal: String = format!(
            "[{}]",
            words
                .iter()
                .map(|w: &&str| format!("\"{}\"", w.replace('"', "\\\"")))
                .collect::<Vec<String>>()
                .join(", ")
        );
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(eq_pos): Option<usize> = source[whole.start()..whole.end()].find('=') else {
            continue;
        };
        let prefix_end: usize = whole.start() + eq_pos + 1;
        edits.push((prefix_end..whole.end(), Some(format!(" {array_literal}"))));
    }
}

fn collect_string_fromcharcode_runs(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"String\.fromCharCode\(\s*((?:\s*\d+\s*,){2,}\s*\d+\s*)\)")
    else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let Some(arg_text): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let codepoints: Vec<u32> = arg_text
            .split(',')
            .filter_map(|s: &str| s.trim().parse::<u32>().ok())
            .collect();
        let mut decoded: String = String::with_capacity(codepoints.len());
        for cp in codepoints {
            let Some(ch): Option<char> = char::from_u32(cp) else {
                decoded.clear();
                break;
            };
            decoded.push(ch);
        }
        if decoded.is_empty() {
            continue;
        }
        let escaped: String = decoded
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        edits.push((whole.start()..whole.end(), Some(format!("\"{escaped}\""))));
    }
}

fn lzstring_decompress_method(method: &str, units: &[u16]) -> Option<String> {
    match method {
        "decompressFromBase64" => lzstring_decompress_base64(units),
        "decompressFromEncodedURIComponent" => lzstring_decompress_uri(units),
        "decompressFromUTF16" => lzstring_decompress_utf16(units),
        "decompress" => lzstring_decompress_utf16_raw(units),
        _ => None,
    }
}

fn lzstring_decompress_base64(units: &[u16]) -> Option<String> {
    if units.is_empty() || units.len() > MAX_LZSTRING_INPUT_UNITS {
        return None;
    }
    let values: Vec<u32> = units
        .iter()
        .map(|unit: &u16| base64_value(*unit))
        .collect::<Option<Vec<u32>>>()?;
    lzstring_decompress_values(&values, 32)
}

fn lzstring_decompress_uri(units: &[u16]) -> Option<String> {
    if units.is_empty() || units.len() > MAX_LZSTRING_INPUT_UNITS {
        return None;
    }
    let values: Vec<u32> = units
        .iter()
        .map(|unit: &u16| {
            let normalized: u16 = if *unit == u16::from(b' ') {
                u16::from(b'+')
            } else {
                *unit
            };
            uri_value(normalized)
        })
        .collect::<Option<Vec<u32>>>()?;
    lzstring_decompress_values(&values, 32)
}

fn lzstring_decompress_utf16(units: &[u16]) -> Option<String> {
    if units.is_empty() || units.len() > MAX_LZSTRING_INPUT_UNITS {
        return None;
    }
    let values: Vec<u32> = units
        .iter()
        .map(|unit: &u16| u32::from(*unit).checked_sub(32))
        .collect::<Option<Vec<u32>>>()?;
    lzstring_decompress_values(&values, 16_384)
}

fn lzstring_decompress_utf16_raw(units: &[u16]) -> Option<String> {
    if units.is_empty() || units.len() > MAX_LZSTRING_INPUT_UNITS {
        return None;
    }
    let values: Vec<u32> = units.iter().map(|unit: &u16| u32::from(*unit)).collect();
    lzstring_decompress_values(&values, 32_768)
}

fn base64_value(unit: u16) -> Option<u32> {
    match unit {
        65..=90 => Some(u32::from(unit - 65)),
        97..=122 => Some(u32::from(unit - 97 + 26)),
        48..=57 => Some(u32::from(unit - 48 + 52)),
        43 => Some(62),
        47 => Some(63),
        61 => Some(64),
        _ => None,
    }
}

fn uri_value(unit: u16) -> Option<u32> {
    match unit {
        65..=90 => Some(u32::from(unit - 65)),
        97..=122 => Some(u32::from(unit - 97 + 26)),
        48..=57 => Some(u32::from(unit - 48 + 52)),
        43 => Some(62),
        45 => Some(63),
        36 => Some(64),
        _ => None,
    }
}

#[derive(Debug)]
struct LzData<'a> {
    values: &'a [u32],
    reset_value: u32,
    val: u32,
    position: u32,
    index: usize,
}

fn lzstring_decompress_values(values: &[u32], reset_value: u32) -> Option<String> {
    let first: u32 = *values.first()?;
    let mut data: LzData<'_> = LzData {
        values,
        reset_value,
        val: first,
        position: reset_value,
        index: 1,
    };
    let mut dict: Vec<Option<Vec<u16>>> = vec![None, None, None];
    let mut enlarge_in: usize = 4;
    let mut dict_size: usize = 4;
    let mut num_bits: u32 = 3;

    let next: u32 = read_lz_bits(&mut data, 2)?;
    let initial: Vec<u16> = match next {
        0 => vec![u16::try_from(read_lz_bits(&mut data, 8)?).ok()?],
        1 => vec![u16::try_from(read_lz_bits(&mut data, 16)?).ok()?],
        2 => return Some(String::new()),
        _ => return None,
    };
    dict.push(Some(initial.clone()));
    let mut w: Vec<u16> = initial.clone();
    let mut result: Vec<u16> = initial;

    loop {
        if data.index > values.len() {
            return None;
        }
        let mut c: usize = usize::try_from(read_lz_bits(&mut data, num_bits)?).ok()?;
        match c {
            0 => {
                let unit: u16 = u16::try_from(read_lz_bits(&mut data, 8)?).ok()?;
                dict.push(Some(vec![unit]));
                c = dict_size;
                dict_size += 1;
                enlarge_in = enlarge_in.checked_sub(1)?;
            }
            1 => {
                let unit: u16 = u16::try_from(read_lz_bits(&mut data, 16)?).ok()?;
                dict.push(Some(vec![unit]));
                c = dict_size;
                dict_size += 1;
                enlarge_in = enlarge_in.checked_sub(1)?;
            }
            2 => return String::from_utf16(&result).ok(),
            _ => {}
        }
        if enlarge_in == 0 {
            enlarge_in = 1usize.checked_shl(num_bits)?;
            num_bits += 1;
        }
        if dict.len() > MAX_LZSTRING_DICT_ENTRIES || result.len() > MAX_LZSTRING_OUTPUT_UNITS {
            return None;
        }
        let entry: Vec<u16> = if let Some(Some(found)) = dict.get(c) {
            found.clone()
        } else if c == dict_size {
            let mut next_entry: Vec<u16> = w.clone();
            next_entry.push(*w.first()?);
            next_entry
        } else {
            return None;
        };
        result.extend_from_slice(&entry);
        if result.len() > MAX_LZSTRING_OUTPUT_UNITS {
            return None;
        }
        let mut new_entry: Vec<u16> = w;
        new_entry.push(*entry.first()?);
        dict.push(Some(new_entry));
        dict_size += 1;
        enlarge_in = enlarge_in.checked_sub(1)?;
        w = entry;
        if enlarge_in == 0 {
            enlarge_in = 1usize.checked_shl(num_bits)?;
            num_bits += 1;
        }
    }
}

fn read_lz_bits(data: &mut LzData<'_>, bit_count: u32) -> Option<u32> {
    let mut bits: u32 = 0;
    let max_power: u32 = 1u32.checked_shl(bit_count)?;
    let mut power: u32 = 1;
    while power != max_power {
        let resb: u32 = data.val & data.position;
        data.position >>= 1;
        if data.position == 0 {
            data.position = data.reset_value;
            data.val = *data.values.get(data.index)?;
            data.index += 1;
        }
        if resb > 0 {
            bits |= power;
        }
        power <<= 1;
    }
    Some(bits)
}

fn decode_js_string_units(literal: &str) -> Option<Vec<u16>> {
    let mut chars: std::str::Chars<'_> = literal.chars();
    let quote: char = chars.next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let mut units: Vec<u16> = Vec::new();
    while let Some(ch) = chars.next() {
        if ch == quote {
            return if chars.next().is_none() {
                Some(units)
            } else {
                None
            };
        }
        if ch != '\\' {
            let mut buf: [u16; 2] = [0, 0];
            units.extend_from_slice(ch.encode_utf16(&mut buf));
            continue;
        }
        let escaped: char = chars.next()?;
        match escaped {
            '\'' => units.push(u16::from(b'\'')),
            '"' => units.push(u16::from(b'"')),
            '\\' => units.push(u16::from(b'\\')),
            'b' => units.push(0x08),
            'f' => units.push(0x0c),
            'n' => units.push(0x0a),
            'r' => units.push(0x0d),
            't' => units.push(0x09),
            'v' => units.push(0x0b),
            '0' => units.push(0),
            'x' => units.push(read_hex_unit(&mut chars, 2)?),
            'u' => {
                if chars.as_str().starts_with('{') {
                    chars.next();
                    let scalar: char = read_braced_unicode_scalar(&mut chars)?;
                    let mut buf: [u16; 2] = [0, 0];
                    units.extend_from_slice(scalar.encode_utf16(&mut buf));
                } else {
                    units.push(read_hex_unit(&mut chars, 4)?);
                }
            }
            '\r' => {
                if chars.as_str().starts_with('\n') {
                    chars.next();
                }
            }
            '\n' => {}
            other => {
                let mut buf: [u16; 2] = [0, 0];
                units.extend_from_slice(other.encode_utf16(&mut buf));
            }
        }
    }
    None
}

fn read_hex_unit(chars: &mut std::str::Chars<'_>, digits: usize) -> Option<u16> {
    let mut value: u16 = 0;
    for _ in 0..digits {
        let digit: char = chars.next()?;
        let piece: u16 = u16::try_from(digit.to_digit(16)?).ok()?;
        value = value.checked_mul(16)?.checked_add(piece)?;
    }
    Some(value)
}

fn read_braced_unicode_scalar(chars: &mut std::str::Chars<'_>) -> Option<char> {
    let mut value: u32 = 0;
    let mut saw_digit: bool = false;
    for ch in chars.by_ref() {
        if ch == '}' {
            return if saw_digit {
                char::from_u32(value)
            } else {
                None
            };
        }
        let digit: u32 = ch.to_digit(16)?;
        value = value.checked_mul(16)?.checked_add(digit)?;
        saw_digit = true;
    }
    None
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn escape_js_string(value: &str) -> String {
    let mut escaped: String = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            c if c == ' ' || c.is_ascii_graphic() => escaped.push(c),
            c if u32::from(c) <= 0xffff => {
                push_format(&mut escaped, format_args!("\\u{:04x}", u32::from(c)));
            }
            c => {
                push_format(&mut escaped, format_args!("\\u{{{:x}}}", u32::from(c)));
            }
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_split_string_array() {
        let src: &str = "var dict = 'alpha|beta|gamma'.split('|');\nuse(dict[1]);";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 1);
        assert!(
            r.rewritten_source
                .contains("[\"alpha\", \"beta\", \"gamma\"]")
        );
    }

    #[test]
    fn folds_string_fromcharcode_run() {
        let src: &str = "var s = String.fromCharCode(104, 101, 108, 108, 111);";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 1);
        assert!(r.rewritten_source.contains("\"hello\""));
    }

    #[test]
    fn leaves_simple_split_alone() {
        let src: &str = "x.split(',');";
        let r: StringCompressionResult = reverse_string_compression(src);
        assert_eq!(r.blocks_reversed, 0);
    }
}
