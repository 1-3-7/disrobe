#![allow(clippy::redundant_pub_crate)]

use disrobe_py_marshal::{BigInt, CodeObject, Object};

const CODE_REPR_ADDRESS: &str = "0x0000000000000000";
const MAX_RENDER_DEPTH: usize = 64;

#[must_use]
pub(crate) fn repr_const(object: &Object) -> String {
    repr_object(object, 0)
}

fn repr_object(object: &Object, depth: usize) -> String {
    if depth > MAX_RENDER_DEPTH {
        return "...".to_owned();
    }
    match object {
        Object::None => "None".to_owned(),
        Object::StopIteration => "StopIteration".to_owned(),
        Object::Ellipsis => "Ellipsis".to_owned(),
        Object::False => "False".to_owned(),
        Object::True => "True".to_owned(),
        Object::Int(value) => value.to_string(),
        Object::Int64(value) => value.to_string(),
        Object::Long(big) => repr_bigint(big),
        Object::Float(value) => repr_float(*value),
        Object::Complex { real, imag } => repr_complex(*real, *imag),
        Object::Bytes(bytes) => repr_bytes(bytes),
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => repr_str(value),
        Object::Tuple(items) => repr_tuple(items, depth),
        Object::List(items) => repr_sequence(items, '[', ']', depth),
        Object::Set(items) | Object::FrozenSet(items) => repr_set(object, items, depth),
        Object::Dict(map) | Object::FrozenDict(map) => {
            repr_dict(map.iter().map(|(k, v): (&Object, &Object)| (k, v)), depth)
        }
        Object::Code(code) => repr_code(code),
        Object::Slice { lower, upper, step } => repr_slice(lower, upper, step, depth),
        Object::Ref(index) => format!("<ref {index}>"),
        Object::Null => "NULL".to_owned(),
    }
}

fn repr_bigint(big: &BigInt) -> String {
    if big.sign == 0 || big.digits.is_empty() {
        return "0".to_owned();
    }
    let mut value: Vec<u32> = vec![0];
    for &digit in big.digits.iter().rev() {
        let mut carry: u64 = u64::from(digit);
        for slot in &mut value {
            let product: u64 = (u64::from(*slot) << 15) + carry;
            *slot = (product % 1_000_000_000) as u32;
            carry = product / 1_000_000_000;
        }
        while carry > 0 {
            value.push((carry % 1_000_000_000) as u32);
            carry /= 1_000_000_000;
        }
    }
    let mut out: String = String::new();
    if big.sign < 0 {
        out.push('-');
    }
    let mut chunks: std::iter::Rev<core::slice::Iter<'_, u32>> = value.iter().rev();
    if let Some(first) = chunks.next() {
        crate::push_string_fmt(&mut out, format_args!("{first}"));
    }
    for chunk in chunks {
        crate::push_string_fmt(&mut out, format_args!("{chunk:09}"));
    }
    out
}

#[must_use]
pub(crate) fn repr_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-inf" } else { "inf" }.to_owned();
    }
    format_python_float(value)
}

fn format_python_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_owned()
        } else {
            "0.0".to_owned()
        };
    }
    let scientific: String = format!("{value:e}");
    let (mantissa, exponent): (&str, i32) = split_scientific(&scientific);
    let negative: bool = mantissa.starts_with('-');
    let mantissa_digits: String = mantissa.trim_start_matches('-').replace('.', "");
    let trimmed: &str = mantissa_digits.trim_end_matches('0');
    let digits: &str = if trimmed.is_empty() { "0" } else { trimmed };
    let decimal_exponent: i32 = exponent;
    let body: String = if (-4..16).contains(&decimal_exponent) {
        render_fixed(digits, decimal_exponent)
    } else {
        render_scientific(digits, decimal_exponent)
    };
    if negative { format!("-{body}") } else { body }
}

fn split_scientific(scientific: &str) -> (&str, i32) {
    match scientific.split_once('e') {
        Some((mantissa, exp)) => (mantissa, exp.parse::<i32>().unwrap_or(0)),
        None => (scientific, 0),
    }
}

fn render_fixed(digits: &str, decimal_exponent: i32) -> String {
    let digit_count: i32 = digits.len() as i32;
    if decimal_exponent < 0 {
        let zeros: String = "0".repeat((-decimal_exponent - 1) as usize);
        return format!("0.{zeros}{digits}");
    }
    let integer_len: i32 = decimal_exponent + 1;
    if integer_len >= digit_count {
        let trailing: String = "0".repeat((integer_len - digit_count) as usize);
        format!("{digits}{trailing}.0")
    } else {
        let (head, tail): (&str, &str) = digits.split_at(integer_len as usize);
        format!("{head}.{tail}")
    }
}

fn render_scientific(digits: &str, decimal_exponent: i32) -> String {
    let (first, rest): (&str, &str) = digits.split_at(1);
    let mantissa: String = if rest.is_empty() {
        first.to_owned()
    } else {
        format!("{first}.{rest}")
    };
    let sign: char = if decimal_exponent < 0 { '-' } else { '+' };
    let magnitude: i32 = decimal_exponent.abs();
    format!("{mantissa}e{sign}{magnitude:02}")
}

fn repr_complex(real: f64, imag: f64) -> String {
    let imag_repr: String = repr_complex_component(imag);
    if real == 0.0 && real.is_sign_positive() {
        format!("{imag_repr}j")
    } else {
        let real_repr: String = repr_complex_component(real);
        let connector: &str = if imag_repr.starts_with('-') { "" } else { "+" };
        format!("({real_repr}{connector}{imag_repr}j)")
    }
}

fn repr_complex_component(value: f64) -> String {
    let mut rendered: String = repr_float(value);
    if rendered.ends_with(".0") {
        rendered.truncate(rendered.len() - 2);
    }
    rendered
}

fn repr_bytes(bytes: &[u8]) -> String {
    let has_single: bool = bytes.contains(&b'\'');
    let has_double: bool = bytes.contains(&b'"');
    let quote: u8 = if has_single && !has_double {
        b'"'
    } else {
        b'\''
    };
    let mut out: String = String::with_capacity(bytes.len() + 3);
    out.push('b');
    out.push(quote as char);
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if byte == quote => {
                out.push('\\');
                out.push(quote as char);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => {
                crate::push_string_fmt(&mut out, format_args!("\\x{byte:02x}"));
            }
        }
    }
    out.push(quote as char);
    out
}

fn repr_str(value: &str) -> String {
    let has_single: bool = value.contains('\'');
    let has_double: bool = value.contains('"');
    let quote: char = if has_single && !has_double { '"' } else { '\'' };
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if ch == quote => {
                out.push('\\');
                out.push(quote);
            }
            _ => push_str_char(&mut out, ch),
        }
    }
    out.push(quote);
    out
}

fn push_str_char(out: &mut String, ch: char) {
    let code: u32 = ch as u32;
    if is_python_printable(ch) {
        out.push(ch);
        return;
    }
    if code <= 0xff {
        crate::push_string_fmt(out, format_args!("\\x{code:02x}"));
    } else if code <= 0xffff {
        crate::push_string_fmt(out, format_args!("\\u{code:04x}"));
    } else {
        crate::push_string_fmt(out, format_args!("\\U{code:08x}"));
    }
}

fn is_python_printable(ch: char) -> bool {
    let code: u32 = ch as u32;
    if code < 0x20 || code == 0x7f {
        return false;
    }
    if code < 0x7f {
        return true;
    }
    if (0x80..=0xa0).contains(&code) {
        return false;
    }
    !ch.is_control() && !is_separator_or_other(ch)
}

const fn is_separator_or_other(ch: char) -> bool {
    matches!(
        ch,
        '\u{00a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn repr_tuple(items: &[Object], depth: usize) -> String {
    if items.len() == 1 {
        return format!("({},)", repr_object(&items[0], depth + 1));
    }
    let body: String = join_items(items, depth);
    format!("({body})")
}

fn repr_sequence(items: &[Object], open: char, close: char, depth: usize) -> String {
    let body: String = join_items(items, depth);
    format!("{open}{body}{close}")
}

fn repr_set(object: &Object, items: &[Object], depth: usize) -> String {
    let is_frozen: bool = matches!(object, Object::FrozenSet(_));
    if items.is_empty() {
        return if is_frozen {
            "frozenset()".to_owned()
        } else {
            "set()".to_owned()
        };
    }
    let body: String = join_items(items, depth);
    if is_frozen {
        format!("frozenset({{{body}}})")
    } else {
        format!("{{{body}}}")
    }
}

fn repr_dict<'a>(entries: impl Iterator<Item = (&'a Object, &'a Object)>, depth: usize) -> String {
    let body: String = entries
        .map(|(key, val): (&Object, &Object)| {
            format!(
                "{}: {}",
                repr_object(key, depth + 1),
                repr_object(val, depth + 1)
            )
        })
        .collect::<Vec<String>>()
        .join(", ");
    format!("{{{body}}}")
}

fn join_items(items: &[Object], depth: usize) -> String {
    items
        .iter()
        .map(|item: &Object| repr_object(item, depth + 1))
        .collect::<Vec<String>>()
        .join(", ")
}

fn repr_slice(lower: &Object, upper: &Object, step: &Object, depth: usize) -> String {
    format!(
        "slice({}, {}, {})",
        repr_object(lower, depth + 1),
        repr_object(upper, depth + 1),
        repr_object(step, depth + 1)
    )
}

fn repr_code(code: &CodeObject) -> String {
    let name: String = code_text(&code.name).unwrap_or_else(|| "<unknown>".to_owned());
    let filename: String = code_text(&code.filename).unwrap_or_default();
    format!(
        "<code object {name} at {CODE_REPR_ADDRESS}, file \"{filename}\", line {}>",
        code.firstlineno
    )
}

fn code_text(object: &Object) -> Option<String> {
    match object {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::approx_constant, clippy::unreadable_literal)]
mod tests {
    use super::*;

    #[test]
    fn ints_and_bools() {
        assert_eq!(repr_const(&Object::Int(10)), "10");
        assert_eq!(repr_const(&Object::Int(-3)), "-3");
        assert_eq!(repr_const(&Object::True), "True");
        assert_eq!(repr_const(&Object::None), "None");
        assert_eq!(repr_const(&Object::Ellipsis), "Ellipsis");
    }

    #[test]
    fn strings_choose_quotes_like_python() {
        let plain: Object = Object::ShortAscii {
            value: "hello".to_owned(),
            interned: false,
        };
        assert_eq!(repr_const(&plain), "'hello'");
        let single: Object = Object::ShortAscii {
            value: "with'quote".to_owned(),
            interned: false,
        };
        assert_eq!(repr_const(&single), "\"with'quote\"");
        let escaped: Object = Object::ShortAscii {
            value: "tab\tnl\n".to_owned(),
            interned: false,
        };
        assert_eq!(repr_const(&escaped), "'tab\\tnl\\n'");
    }

    #[test]
    fn bytes_repr_matches_python() {
        assert_eq!(
            repr_const(&Object::Bytes(vec![b'b', b'y', 0x00])),
            "b'by\\x00'"
        );
    }

    #[test]
    fn float_repr_matches_python_forms() {
        assert_eq!(repr_float(3.14), "3.14");
        assert_eq!(repr_float(2.0), "2.0");
        assert_eq!(repr_float(0.5), "0.5");
        assert_eq!(repr_float(-0.0), "-0.0");
        assert_eq!(repr_float(1e100), "1e+100");
        assert_eq!(repr_float(1e-5), "1e-05");
        assert_eq!(repr_float(100.0), "100.0");
        assert_eq!(repr_float(0.0001), "0.0001");
        assert_eq!(repr_float(1234567890123456.0), "1234567890123456.0");
    }

    #[test]
    fn complex_repr_matches_cpython_dropping_whole_number_suffix() {
        let cases: [(f64, f64, &str); 11] = [
            (0.0, 2.0, "2j"),
            (0.0, -0.0, "-0j"),
            (0.0, 0.0, "0j"),
            (1.0, 2.0, "(1+2j)"),
            (3.0, -4.0, "(3-4j)"),
            (2.5, 0.0, "(2.5+0j)"),
            (5.0, -0.0, "(5-0j)"),
            (-0.0, 0.0, "(-0+0j)"),
            (0.0, 1e16, "1e+16j"),
            (0.0001, 0.0, "(0.0001+0j)"),
            (0.5, 0.25, "(0.5+0.25j)"),
        ];
        for (real, imag, expected) in cases {
            assert_eq!(
                repr_const(&Object::Complex { real, imag }),
                expected,
                "complex({real}, {imag}) must render like CPython"
            );
        }
    }

    #[test]
    fn tuple_repr_includes_trailing_comma_for_single() {
        let single: Object = Object::Tuple(vec![Object::Int(1)]);
        assert_eq!(repr_const(&single), "(1,)");
        let triple: Object = Object::Tuple(vec![Object::Int(1), Object::Int(2), Object::Int(3)]);
        assert_eq!(repr_const(&triple), "(1, 2, 3)");
        assert_eq!(repr_const(&Object::Tuple(vec![])), "()");
    }

    #[test]
    fn bigint_decimal_conversion() {
        let big: BigInt = BigInt {
            sign: 1,
            digits: vec![0, 0, 16],
        };
        let expected: u128 = 16u128 << 30;
        assert_eq!(repr_const(&Object::Long(big)), expected.to_string());
    }
}
