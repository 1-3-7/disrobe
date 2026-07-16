#![allow(clippy::redundant_pub_crate)]

use disrobe_py_marshal::{BigInt, CodeObject, Object};
use unicode_general_category::GeneralCategory;

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

pub fn is_python_printable(ch: char) -> bool {
    if ch == ' ' {
        return true;
    }
    !matches!(
        unicode_general_category::get_general_category(ch),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
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
    let body: String = cpython_set_order(items).map_or_else(
        || join_items(items, depth),
        |order: Vec<usize>| {
            order
                .iter()
                .map(|index: &usize| repr_object(&items[*index], depth + 1))
                .collect::<Vec<String>>()
                .join(", ")
        },
    );
    if is_frozen {
        format!("frozenset({{{body}}})")
    } else {
        format!("{{{body}}}")
    }
}

const PY_HASH_MODULUS: u128 = (1u128 << 61) - 1;
const SET_MIN_SIZE: usize = 8;
const SET_LINEAR_PROBES: u64 = 9;
const SET_PERTURB_SHIFT: u32 = 5;
const SET_LARGE_GROWTH_THRESHOLD: u64 = 50_000;
const MAX_SET_SIMULATION: usize = 1 << 20;

fn cpython_set_order(items: &[Object]) -> Option<Vec<usize>> {
    if items.len() > MAX_SET_SIMULATION {
        return None;
    }
    let hashes: Vec<i64> = items
        .iter()
        .map(int_like_hash)
        .collect::<Option<Vec<i64>>>()?;
    Some(simulate_set_table(&hashes))
}

fn int_like_hash(object: &Object) -> Option<i64> {
    match object {
        Object::True => Some(1),
        Object::False => Some(0),
        Object::Int(value) => Some(py_int_hash(i128::from(*value))),
        Object::Int64(value) => Some(py_int_hash(i128::from(*value))),
        Object::Long(big) => Some(py_bigint_hash(big)),
        _ => None,
    }
}

const fn py_int_hash(value: i128) -> i64 {
    let magnitude: i64 = (value.unsigned_abs() % PY_HASH_MODULUS) as i64;
    let signed: i64 = if value < 0 { -magnitude } else { magnitude };
    if signed == -1 { -2 } else { signed }
}

fn py_bigint_hash(big: &BigInt) -> i64 {
    if big.sign == 0 || big.digits.is_empty() {
        return 0;
    }
    let mut acc: u128 = 0;
    for &digit in big.digits.iter().rev() {
        acc = (acc << 15) % PY_HASH_MODULUS;
        acc = (acc + u128::from(digit)) % PY_HASH_MODULUS;
    }
    let signed: i64 = if big.sign < 0 {
        -(acc as i64)
    } else {
        acc as i64
    };
    if signed == -1 { -2 } else { signed }
}

fn simulate_set_table(hashes: &[i64]) -> Vec<usize> {
    let mut table: Vec<Option<usize>> = vec![None; SET_MIN_SIZE];
    let mut mask: u64 = (SET_MIN_SIZE - 1) as u64;
    let mut used: u64 = 0;
    for (index, &hash) in hashes.iter().enumerate() {
        set_insert_clean(&mut table, mask, index, hash);
        used += 1;
        if used * 5 >= mask * 3 {
            let minused: u64 = if used > SET_LARGE_GROWTH_THRESHOLD {
                used * 2
            } else {
                used * 4
            };
            let (grown, grown_mask): (Vec<Option<usize>>, u64) =
                set_resize(&table, hashes, minused);
            table = grown;
            mask = grown_mask;
        }
    }
    table
        .iter()
        .filter_map(|slot: &Option<usize>| *slot)
        .collect()
}

fn set_insert_clean(table: &mut [Option<usize>], mask: u64, index: usize, hash: i64) {
    let mut perturb: u64 = hash as u64;
    let mut i: u64 = (hash as u64) & mask;
    loop {
        if table[i as usize].is_none() {
            table[i as usize] = Some(index);
            return;
        }
        if i + SET_LINEAR_PROBES <= mask {
            for offset in 1..=SET_LINEAR_PROBES {
                let slot: usize = (i + offset) as usize;
                if table[slot].is_none() {
                    table[slot] = Some(index);
                    return;
                }
            }
        }
        perturb >>= SET_PERTURB_SHIFT;
        i = i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb) & mask;
    }
}

fn set_resize(old: &[Option<usize>], hashes: &[i64], minused: u64) -> (Vec<Option<usize>>, u64) {
    let mut newsize: usize = SET_MIN_SIZE;
    while (newsize as u64) <= minused {
        newsize <<= 1;
    }
    let mut table: Vec<Option<usize>> = vec![None; newsize];
    let mask: u64 = (newsize - 1) as u64;
    for index in old.iter().flatten() {
        set_insert_clean(&mut table, mask, *index, hashes[*index]);
    }
    (table, mask)
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
    fn nonprintable_code_points_escape_like_python_repr() {
        let cases: [(&str, &str); 12] = [
            ("\u{ad}", "'\\xad'"),
            ("\u{200b}", "'\\u200b'"),
            ("\u{200d}", "'\\u200d'"),
            ("abc\u{ad}def", "'abc\\xaddef'"),
            ("\u{e000}", "'\\ue000'"),
            ("\u{2065}", "'\\u2065'"),
            ("\u{0602}", "'\\u0602'"),
            ("\u{180e}", "'\\u180e'"),
            ("\u{e0001}", "'\\U000e0001'"),
            ("\u{a0}", "'\\xa0'"),
            ("\u{feff}", "'\\ufeff'"),
            ("tab\tnl\n\u{200b}x\u{ad}", "'tab\\tnl\\n\\u200bx\\xad'"),
        ];
        for (value, expected) in cases {
            let object: Object = Object::Unicode {
                value: value.to_owned(),
                interned: false,
            };
            assert_eq!(repr_const(&object), expected, "repr of {value:?}");
        }
    }

    #[test]
    fn printable_high_code_points_stay_literal() {
        for value in ["\u{e9}", "\u{1f600}", "\u{4e2d}", " "] {
            let object: Object = Object::Unicode {
                value: value.to_owned(),
                interned: false,
            };
            assert_eq!(
                repr_const(&object),
                format!("'{value}'"),
                "repr of {value:?}"
            );
        }
    }

    #[test]
    fn frozenset_of_ints_matches_cpython_iteration_order() {
        let cases: [(&[i64], &str); 6] = [
            (&[7, 8], "frozenset({8, 7})"),
            (&[5, 13, 21, 29], "frozenset({29, 13, 21, 5})"),
            (&[3, 7, 42, 100, 999], "frozenset({3, 100, 999, 7, 42})"),
            (&[0, 8, 16, 24], "frozenset({0, 8, 16, 24})"),
            (&[1, 9], "frozenset({1, 9})"),
            (
                &[-3, -2, -1, 5, 1000000],
                "frozenset({1000000, 5, -1, -3, -2})",
            ),
        ];
        for (values, expected) in cases {
            let items: Vec<Object> = values.iter().map(|v: &i64| Object::Int64(*v)).collect();
            let object: Object = Object::FrozenSet(items);
            assert_eq!(repr_const(&object), expected, "order for {values:?}");
        }
    }

    #[test]
    fn set_of_ints_forces_resize_and_matches_cpython() {
        let values: Vec<i64> = (0..20).collect();
        let items: Vec<Object> = values.iter().map(|v: &i64| Object::Int64(*v)).collect();
        let object: Object = Object::Set(items);
        assert_eq!(
            repr_const(&object),
            "{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}"
        );
    }

    #[test]
    fn frozenset_with_non_integer_element_keeps_storage_order() {
        let items: Vec<Object> = vec![
            Object::Int64(7),
            Object::ShortAscii {
                value: "x".to_owned(),
                interned: false,
            },
            Object::Int64(8),
        ];
        let object: Object = Object::FrozenSet(items);
        assert_eq!(repr_const(&object), "frozenset({7, 'x', 8})");
    }

    #[test]
    fn bool_elements_hash_like_zero_and_one() {
        let items: Vec<Object> = vec![Object::Int64(8), Object::True, Object::Int64(7)];
        let object: Object = Object::FrozenSet(items);
        assert_eq!(repr_const(&object), "frozenset({8, True, 7})");
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
