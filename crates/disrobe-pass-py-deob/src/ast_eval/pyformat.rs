use super::eval::{EvalError, py_repr};
use super::value::{Key, Value};

const MAX_WIDTH: usize = 4096;
const MAX_OUTPUT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Conversion {
    Str,
    Repr,
    Ascii,
    Decimal,
    Octal,
    HexLower,
    HexUpper,
    Char,
    Bytes,
}

#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    alternate: bool,
    zero: bool,
    left: bool,
    space: bool,
    plus: bool,
}

#[derive(Debug, Clone)]
struct Directive {
    key: Option<String>,
    flags: Flags,
    width: Option<usize>,
    precision: Option<usize>,
    conversion: Conversion,
}

const fn conversion_from(symbol: char) -> Option<Conversion> {
    match symbol {
        's' => Some(Conversion::Str),
        'r' => Some(Conversion::Repr),
        'a' => Some(Conversion::Ascii),
        'd' | 'i' | 'u' => Some(Conversion::Decimal),
        'o' => Some(Conversion::Octal),
        'x' => Some(Conversion::HexLower),
        'X' => Some(Conversion::HexUpper),
        'c' => Some(Conversion::Char),
        'b' => Some(Conversion::Bytes),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum Piece {
    Literal(String),
    Field(Directive),
}

fn parse_percent_format(fmt: &str) -> Result<Vec<Piece>, EvalError> {
    let chars: Vec<char> = fmt.chars().collect();
    let mut pieces: Vec<Piece> = Vec::new();
    let mut literal: String = String::new();
    let mut index: usize = 0;
    while index < chars.len() {
        let current: char = *chars.get(index).ok_or(EvalError::Unsupported)?;
        if current != '%' {
            literal.push(current);
            index += 1;
            continue;
        }
        index += 1;
        let next: char = *chars.get(index).ok_or(EvalError::Unsupported)?;
        if next == '%' {
            literal.push('%');
            index += 1;
            continue;
        }
        if !literal.is_empty() {
            pieces.push(Piece::Literal(core::mem::take(&mut literal)));
        }
        let directive: Directive = parse_directive(&chars, &mut index)?;
        pieces.push(Piece::Field(directive));
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    Ok(pieces)
}

fn parse_directive(chars: &[char], index: &mut usize) -> Result<Directive, EvalError> {
    let key: Option<String> = parse_mapping_key(chars, index)?;
    let flags: Flags = parse_flags(chars, index);
    let width: Option<usize> = parse_number(chars, index)?;
    let precision: Option<usize> = if chars.get(*index) == Some(&'.') {
        *index += 1;
        Some(parse_number(chars, index)?.unwrap_or(0))
    } else {
        None
    };
    while matches!(chars.get(*index), Some('h' | 'l' | 'L')) {
        *index += 1;
    }
    let symbol: char = *chars.get(*index).ok_or(EvalError::Unsupported)?;
    *index += 1;
    let conversion: Conversion = conversion_from(symbol).ok_or(EvalError::Unsupported)?;
    if width.is_some_and(|w: usize| w > MAX_WIDTH)
        || precision.is_some_and(|p: usize| p > MAX_WIDTH)
    {
        return Err(EvalError::Overflow);
    }
    Ok(Directive {
        key,
        flags,
        width,
        precision,
        conversion,
    })
}

fn parse_mapping_key(chars: &[char], index: &mut usize) -> Result<Option<String>, EvalError> {
    if chars.get(*index) != Some(&'(') {
        return Ok(None);
    }
    *index += 1;
    let mut key: String = String::new();
    loop {
        let current: char = *chars.get(*index).ok_or(EvalError::Unsupported)?;
        *index += 1;
        if current == ')' {
            return Ok(Some(key));
        }
        if current == '(' {
            return Err(EvalError::Unsupported);
        }
        key.push(current);
    }
}

fn parse_flags(chars: &[char], index: &mut usize) -> Flags {
    let mut flags: Flags = Flags::default();
    while let Some(&current) = chars.get(*index) {
        match current {
            '#' => flags.alternate = true,
            '0' => flags.zero = true,
            '-' => flags.left = true,
            ' ' => flags.space = true,
            '+' => flags.plus = true,
            _ => break,
        }
        *index += 1;
    }
    flags
}

fn parse_number(chars: &[char], index: &mut usize) -> Result<Option<usize>, EvalError> {
    let mut digits: String = String::new();
    while let Some(&current) = chars.get(*index) {
        if !current.is_ascii_digit() {
            break;
        }
        digits.push(current);
        *index += 1;
    }
    if digits.is_empty() {
        return Ok(None);
    }
    digits
        .parse::<usize>()
        .map(Some)
        .map_err(|_| EvalError::Overflow)
}

fn integer_of(value: &Value) -> Result<i128, EvalError> {
    match value {
        Value::Int(n) => Ok(*n),
        Value::Bool(b) => Ok(i128::from(*b)),
        _ => Err(EvalError::TypeMismatch),
    }
}

fn display_str(value: &Value) -> Result<String, EvalError> {
    match value {
        Value::Str(s) => Ok(s.clone()),
        other => py_repr(other, false).ok_or(EvalError::Unsupported),
    }
}

fn repr_of(value: &Value, ascii_only: bool) -> Result<String, EvalError> {
    py_repr(value, ascii_only).ok_or(EvalError::Unsupported)
}

fn digits_of(magnitude: u128, conversion: Conversion) -> Result<String, EvalError> {
    match conversion {
        Conversion::Decimal => Ok(magnitude.to_string()),
        Conversion::Octal => Ok(format!("{magnitude:o}")),
        Conversion::HexLower => Ok(format!("{magnitude:x}")),
        Conversion::HexUpper => Ok(format!("{magnitude:X}")),
        _ => Err(EvalError::Unsupported),
    }
}

const fn alternate_prefix(conversion: Conversion) -> &'static str {
    match conversion {
        Conversion::Octal => "0o",
        Conversion::HexLower => "0x",
        Conversion::HexUpper => "0X",
        _ => "",
    }
}

fn render_integer(directive: &Directive, value: i128) -> Result<String, EvalError> {
    let magnitude: u128 = value.unsigned_abs();
    let mut digits: String = digits_of(magnitude, directive.conversion)?;
    if let Some(precision) = directive.precision {
        while digits.len() < precision {
            digits.insert(0, '0');
        }
    }
    let sign: &str = if value < 0 {
        "-"
    } else if directive.flags.plus {
        "+"
    } else if directive.flags.space {
        " "
    } else {
        ""
    };
    let prefix: &str = if directive.flags.alternate {
        alternate_prefix(directive.conversion)
    } else {
        ""
    };
    let body: String = format!("{sign}{prefix}{digits}");
    let Some(width) = directive.width else {
        return Ok(body);
    };
    if body.chars().count() >= width {
        return Ok(body);
    }
    let pad: usize = width - body.chars().count();
    if directive.flags.left {
        return Ok(format!("{body}{}", " ".repeat(pad)));
    }
    if directive.flags.zero {
        return Ok(format!("{sign}{prefix}{}{digits}", "0".repeat(pad)));
    }
    Ok(format!("{}{body}", " ".repeat(pad)))
}

fn pad_text(directive: &Directive, text: &str) -> String {
    let Some(width) = directive.width else {
        return text.to_owned();
    };
    let current: usize = text.chars().count();
    if current >= width {
        return text.to_owned();
    }
    let pad: String = " ".repeat(width - current);
    if directive.flags.left {
        format!("{text}{pad}")
    } else {
        format!("{pad}{text}")
    }
}

fn truncate_chars(text: &str, precision: Option<usize>) -> String {
    precision.map_or_else(
        || text.to_owned(),
        |limit: usize| text.chars().take(limit).collect(),
    )
}

fn render_str_field(directive: &Directive, value: &Value) -> Result<String, EvalError> {
    match directive.conversion {
        Conversion::Str => Ok(pad_text(
            directive,
            &truncate_chars(&display_str(value)?, directive.precision),
        )),
        Conversion::Repr => Ok(pad_text(
            directive,
            &truncate_chars(&repr_of(value, false)?, directive.precision),
        )),
        Conversion::Ascii => Ok(pad_text(
            directive,
            &truncate_chars(&repr_of(value, true)?, directive.precision),
        )),
        Conversion::Char => {
            let text: String = match value {
                Value::Str(s) if s.chars().count() == 1 => s.clone(),
                Value::Int(n) if (0..0x0011_0000).contains(n) => {
                    let code: u32 = u32::try_from(*n).map_err(|_| EvalError::Overflow)?;
                    char::from_u32(code)
                        .ok_or(EvalError::TypeMismatch)?
                        .to_string()
                }
                _ => return Err(EvalError::TypeMismatch),
            };
            Ok(pad_text(directive, &text))
        }
        Conversion::Bytes => Err(EvalError::Unsupported),
        _ => render_integer(directive, integer_of(value)?),
    }
}

fn render_bytes_field(directive: &Directive, value: &Value) -> Result<Vec<u8>, EvalError> {
    match directive.conversion {
        Conversion::Str | Conversion::Bytes => {
            let Value::Bytes(raw) = value else {
                return Err(EvalError::TypeMismatch);
            };
            let limited: Vec<u8> = directive.precision.map_or_else(
                || raw.clone(),
                |limit: usize| raw.iter().copied().take(limit).collect(),
            );
            Ok(pad_bytes(directive, &limited))
        }
        Conversion::Repr => Ok(pad_bytes(
            directive,
            truncate_chars(&repr_of(value, false)?, directive.precision).as_bytes(),
        )),
        Conversion::Ascii => Ok(pad_bytes(
            directive,
            truncate_chars(&repr_of(value, true)?, directive.precision).as_bytes(),
        )),
        Conversion::Char => {
            let byte: u8 = match value {
                Value::Bytes(raw) if raw.len() == 1 => {
                    *raw.first().ok_or(EvalError::Unsupported)?
                }
                Value::Int(n) if (0..256).contains(n) => {
                    u8::try_from(*n).map_err(|_| EvalError::Overflow)?
                }
                _ => return Err(EvalError::TypeMismatch),
            };
            Ok(pad_bytes(directive, &[byte]))
        }
        _ => Ok(render_integer(directive, integer_of(value)?).map(String::into_bytes)?),
    }
}

fn pad_bytes(directive: &Directive, raw: &[u8]) -> Vec<u8> {
    let Some(width) = directive.width else {
        return raw.to_vec();
    };
    if raw.len() >= width {
        return raw.to_vec();
    }
    let pad: Vec<u8> = vec![b' '; width - raw.len()];
    let mut out: Vec<u8> = Vec::with_capacity(width);
    if directive.flags.left {
        out.extend_from_slice(raw);
        out.extend_from_slice(&pad);
    } else {
        out.extend_from_slice(&pad);
        out.extend_from_slice(raw);
    }
    out
}

fn field_count(pieces: &[Piece]) -> usize {
    pieces
        .iter()
        .filter(|piece: &&Piece| matches!(piece, Piece::Field(_)))
        .count()
}

fn uses_mapping(pieces: &[Piece]) -> bool {
    pieces.iter().any(|piece: &Piece| match piece {
        Piece::Field(directive) => directive.key.is_some(),
        Piece::Literal(_) => false,
    })
}

fn positional_operands(pieces: &[Piece], operand: &Value) -> Result<Vec<Value>, EvalError> {
    let supplied: Vec<Value> = match operand {
        Value::Tuple(items) => items.clone(),
        Value::Dict(_) => return Err(EvalError::Unsupported),
        single => vec![single.clone()],
    };
    if supplied.len() != field_count(pieces) {
        return Err(EvalError::TypeMismatch);
    }
    Ok(supplied)
}

fn mapping_operand<'a>(directive: &Directive, operand: &'a Value) -> Result<&'a Value, EvalError> {
    let Value::Dict(entries) = operand else {
        return Err(EvalError::TypeMismatch);
    };
    let key: &String = directive.key.as_ref().ok_or(EvalError::Unsupported)?;
    entries
        .get(&Key::Str(key.clone()))
        .ok_or(EvalError::TypeMismatch)
}

pub(crate) fn str_mod(fmt: &str, operand: &Value) -> Result<String, EvalError> {
    let pieces: Vec<Piece> = parse_percent_format(fmt)?;
    let mapping: bool = uses_mapping(&pieces);
    let supplied: Vec<Value> = if mapping {
        Vec::new()
    } else {
        positional_operands(&pieces, operand)?
    };
    let mut out: String = String::with_capacity(fmt.len());
    let mut next: usize = 0;
    for piece in &pieces {
        match piece {
            Piece::Literal(text) => out.push_str(text),
            Piece::Field(directive) => {
                let value: &Value = if mapping {
                    mapping_operand(directive, operand)?
                } else {
                    let picked: &Value = supplied.get(next).ok_or(EvalError::TypeMismatch)?;
                    next += 1;
                    picked
                };
                out.push_str(&render_str_field(directive, value)?);
            }
        }
        if out.len() > MAX_OUTPUT {
            return Err(EvalError::Overflow);
        }
    }
    Ok(out)
}

pub(crate) fn bytes_mod(fmt: &[u8], operand: &Value) -> Result<Vec<u8>, EvalError> {
    let text: &str = core::str::from_utf8(fmt).map_err(|_| EvalError::Unsupported)?;
    let pieces: Vec<Piece> = parse_percent_format(text)?;
    let mapping: bool = uses_mapping(&pieces);
    let supplied: Vec<Value> = if mapping {
        Vec::new()
    } else {
        positional_operands(&pieces, operand)?
    };
    let mut out: Vec<u8> = Vec::with_capacity(fmt.len());
    let mut next: usize = 0;
    for piece in &pieces {
        match piece {
            Piece::Literal(literal) => out.extend_from_slice(literal.as_bytes()),
            Piece::Field(directive) => {
                let value: &Value = if mapping {
                    mapping_operand(directive, operand)?
                } else {
                    let picked: &Value = supplied.get(next).ok_or(EvalError::TypeMismatch)?;
                    next += 1;
                    picked
                };
                out.extend_from_slice(&render_bytes_field(directive, value)?);
            }
        }
        if out.len() > MAX_OUTPUT {
            return Err(EvalError::Overflow);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Align {
    Left,
    Right,
    Center,
    SignAware,
}

#[derive(Debug, Clone, Copy)]
struct Spec {
    fill: char,
    align: Option<Align>,
    sign: Option<char>,
    alternate: bool,
    zero: bool,
    width: Option<usize>,
    grouping: Option<char>,
    precision: Option<usize>,
    kind: Option<char>,
}

const fn align_from(symbol: char) -> Option<Align> {
    match symbol {
        '<' => Some(Align::Left),
        '>' => Some(Align::Right),
        '^' => Some(Align::Center),
        '=' => Some(Align::SignAware),
        _ => None,
    }
}

fn parse_spec(spec: &str) -> Result<Spec, EvalError> {
    let chars: Vec<char> = spec.chars().collect();
    let mut index: usize = 0;
    let mut fill: char = ' ';
    let mut align: Option<Align> = None;
    if let (Some(&first), Some(&second)) = (chars.first(), chars.get(1))
        && let Some(found) = align_from(second)
    {
        fill = first;
        align = Some(found);
        index = 2;
    } else if let Some(found) = chars.first().copied().and_then(align_from) {
        align = Some(found);
        index = 1;
    }
    let sign: Option<char> = match chars.get(index) {
        Some(&symbol @ ('+' | '-' | ' ')) => {
            index += 1;
            Some(symbol)
        }
        _ => None,
    };
    if chars.get(index) == Some(&'z') {
        return Err(EvalError::Unsupported);
    }
    let alternate: bool = chars.get(index) == Some(&'#');
    if alternate {
        index += 1;
    }
    let zero: bool = chars.get(index) == Some(&'0');
    if zero {
        index += 1;
    }
    let width: Option<usize> = parse_number(&chars, &mut index)?;
    let grouping: Option<char> = match chars.get(index) {
        Some(&symbol @ (',' | '_')) => {
            index += 1;
            Some(symbol)
        }
        _ => None,
    };
    let precision: Option<usize> = if chars.get(index) == Some(&'.') {
        index += 1;
        Some(parse_number(&chars, &mut index)?.ok_or(EvalError::Unsupported)?)
    } else {
        None
    };
    let kind: Option<char> = chars.get(index).copied();
    if kind.is_some() {
        index += 1;
    }
    if index != chars.len() {
        return Err(EvalError::Unsupported);
    }
    if width.is_some_and(|w: usize| w > MAX_WIDTH)
        || precision.is_some_and(|p: usize| p > MAX_WIDTH)
    {
        return Err(EvalError::Overflow);
    }
    Ok(Spec {
        fill,
        align,
        sign,
        alternate,
        zero,
        width,
        grouping,
        precision,
        kind,
    })
}

fn group_digits(digits: &str, separator: char, size: usize) -> String {
    let mut out: String = String::with_capacity(digits.len() + digits.len() / size);
    let total: usize = digits.len();
    for (position, symbol) in digits.chars().enumerate() {
        if position > 0 && (total - position).is_multiple_of(size) {
            out.push(separator);
        }
        out.push(symbol);
    }
    out
}

fn spec_integer_body(spec: &Spec, value: i128) -> Result<(String, String), EvalError> {
    let magnitude: u128 = value.unsigned_abs();
    let (mut digits, prefix): (String, &str) = match spec.kind {
        None | Some('d') => (magnitude.to_string(), ""),
        Some('b') => (
            format!("{magnitude:b}"),
            if spec.alternate { "0b" } else { "" },
        ),
        Some('o') => (
            format!("{magnitude:o}"),
            if spec.alternate { "0o" } else { "" },
        ),
        Some('x') => (
            format!("{magnitude:x}"),
            if spec.alternate { "0x" } else { "" },
        ),
        Some('X') => (
            format!("{magnitude:X}"),
            if spec.alternate { "0X" } else { "" },
        ),
        _ => return Err(EvalError::Unsupported),
    };
    if let Some(separator) = spec.grouping {
        let size: usize = match (separator, spec.kind) {
            (',' | '_', None | Some('d')) => 3,
            ('_', Some('b' | 'o' | 'x' | 'X')) => 4,
            _ => return Err(EvalError::Unsupported),
        };
        digits = group_digits(&digits, separator, size);
    }
    let sign: String = if value < 0 {
        "-".to_owned()
    } else {
        match spec.sign {
            Some('+') => "+".to_owned(),
            Some(' ') => " ".to_owned(),
            _ => String::new(),
        }
    };
    Ok((format!("{sign}{prefix}"), digits))
}

fn apply_alignment(spec: &Spec, head: &str, body: &str, default: Align) -> String {
    let text: String = format!("{head}{body}");
    let Some(width) = spec.width else {
        return text;
    };
    let current: usize = text.chars().count();
    if current >= width {
        return text;
    }
    let pad: usize = width - current;
    match spec.align.unwrap_or(default) {
        Align::Left => format!("{text}{}", spec.fill.to_string().repeat(pad)),
        Align::Right => format!("{}{text}", spec.fill.to_string().repeat(pad)),
        Align::Center => {
            let left: usize = pad / 2;
            format!(
                "{}{text}{}",
                spec.fill.to_string().repeat(left),
                spec.fill.to_string().repeat(pad - left)
            )
        }
        Align::SignAware => format!("{head}{}{body}", spec.fill.to_string().repeat(pad)),
    }
}

fn format_integer(spec: &Spec, value: i128) -> Result<String, EvalError> {
    if spec.precision.is_some() {
        return Err(EvalError::Unsupported);
    }
    if spec.kind == Some('c') {
        if spec.sign.is_some() || spec.alternate || spec.grouping.is_some() {
            return Err(EvalError::Unsupported);
        }
        let code: u32 = u32::try_from(value).map_err(|_| EvalError::Overflow)?;
        let symbol: char = char::from_u32(code).ok_or(EvalError::TypeMismatch)?;
        return Ok(apply_alignment(spec, "", &symbol.to_string(), Align::Left));
    }
    let (head, body): (String, String) = spec_integer_body(spec, value)?;
    let effective: Spec = if spec.zero && spec.align.is_none() {
        Spec {
            fill: '0',
            align: Some(Align::SignAware),
            ..*spec
        }
    } else {
        *spec
    };
    Ok(apply_alignment(&effective, &head, &body, Align::Right))
}

fn format_text(spec: &Spec, text: &str) -> Result<String, EvalError> {
    if !matches!(spec.kind, None | Some('s')) {
        return Err(EvalError::Unsupported);
    }
    if spec.sign.is_some() || spec.alternate || spec.grouping.is_some() {
        return Err(EvalError::Unsupported);
    }
    if spec.align == Some(Align::SignAware) {
        return Err(EvalError::Unsupported);
    }
    let effective: Spec = if spec.zero && spec.align.is_none() {
        Spec { fill: '0', ..*spec }
    } else {
        *spec
    };
    let limited: String = truncate_chars(text, spec.precision);
    Ok(apply_alignment(&effective, "", &limited, Align::Left))
}

pub(crate) fn format_value(value: &Value, spec_text: &str) -> Result<String, EvalError> {
    let spec: Spec = parse_spec(spec_text)?;
    match value {
        Value::Int(n) => format_integer(&spec, *n),
        Value::Bool(b) => {
            if spec.kind.is_some_and(|kind: char| kind != 's') {
                format_integer(&spec, i128::from(*b))
            } else {
                format_text(&spec, if *b { "True" } else { "False" })
            }
        }
        Value::Str(s) => format_text(&spec, s),
        Value::None => format_text(&spec, "None"),
        Value::Bytes(_) | Value::List(_) | Value::Tuple(_) | Value::Dict(_) => {
            if spec_text.is_empty() {
                repr_of(value, false)
            } else {
                Err(EvalError::Unsupported)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn percent(fmt: &str, operand: &Value) -> String {
        str_mod(fmt, operand).expect("percent format")
    }

    #[test]
    fn percent_pads_and_signs_integers() {
        assert_eq!(percent("%02x", &Value::Int(255)), "ff");
        assert_eq!(percent("%04x", &Value::Int(255)), "00ff");
        assert_eq!(percent("%+d", &Value::Int(5)), "+5");
        assert_eq!(percent("%5d", &Value::Int(-42)), "  -42");
        assert_eq!(percent("%-5d|", &Value::Int(42)), "42   |");
        assert_eq!(percent("%#o", &Value::Int(8)), "0o10");
    }

    #[test]
    fn percent_maps_named_keys() {
        let mut entries: std::collections::BTreeMap<Key, Value> = std::collections::BTreeMap::new();
        entries.insert(
            Key::Str("name".to_owned()),
            Value::Str("disrobe".to_owned()),
        );
        let out: String = percent("%(name)s", &Value::Dict(entries));
        assert_eq!(out, "disrobe");
    }

    #[test]
    fn percent_refuses_float_conversions_and_arity_mismatch() {
        assert!(str_mod("%f", &Value::Int(1)).is_err());
        assert!(str_mod("%s %s", &Value::Str("x".to_owned())).is_err());
        assert!(str_mod("%s", &Value::Tuple(vec![Value::Int(1), Value::Int(2)])).is_err());
    }

    #[test]
    fn percent_bounds_hostile_width() {
        assert!(str_mod("%999999999d", &Value::Int(1)).is_err());
    }

    #[test]
    fn spec_formats_integers_and_text() {
        assert_eq!(format_value(&Value::Int(255), "x").expect("hex spec"), "ff");
        assert_eq!(
            format_value(&Value::Int(5), "03d").expect("zero pad"),
            "005"
        );
        assert_eq!(
            format_value(&Value::Int(255), "#06x").expect("alternate"),
            "0x00ff"
        );
        assert_eq!(
            format_value(&Value::Str("ab".to_owned()), ">5").expect("align"),
            "   ab"
        );
        assert_eq!(
            format_value(&Value::Int(1_234_567), ",").expect("grouping"),
            "1,234,567"
        );
    }

    #[test]
    fn spec_refuses_float_types_and_trailing_garbage() {
        assert!(format_value(&Value::Int(1), "f").is_err());
        assert!(format_value(&Value::Int(1), "dd").is_err());
        assert!(format_value(&Value::Str("a".to_owned()), "d").is_err());
    }
}
