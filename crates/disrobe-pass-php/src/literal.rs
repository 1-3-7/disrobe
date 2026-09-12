pub(crate) fn parse_php_integer_literal(raw: &[u8]) -> Option<i64> {
    if raw == b"0" {
        return Some(0);
    }
    let (radix, digits): (u32, &[u8]) = if raw.starts_with(b"0x") || raw.starts_with(b"0X") {
        (16, raw.get(2..)?)
    } else if raw.starts_with(b"0o") || raw.starts_with(b"0O") {
        (8, raw.get(2..)?)
    } else if raw.starts_with(b"0b") || raw.starts_with(b"0B") {
        (2, raw.get(2..)?)
    } else if raw.starts_with(b"0") {
        (8, raw.get(1..)?)
    } else {
        (10, raw)
    };
    parse_digits(digits, radix)
}

fn parse_digits(digits: &[u8], radix: u32) -> Option<i64> {
    let mut value: i64 = 0;
    let mut saw_digit: bool = false;
    let mut previous_underscore: bool = false;
    for byte in digits.iter().copied() {
        if byte == b'_' {
            if !saw_digit || previous_underscore {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        let digit: u32 = digit_value(byte)?;
        if digit >= radix {
            return None;
        }
        value = value
            .checked_mul(i64::from(radix))?
            .checked_add(i64::from(digit))?;
        saw_digit = true;
        previous_underscore = false;
    }
    (saw_digit && !previous_underscore).then_some(value)
}

const fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u32),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_php_integer_literal;

    #[test]
    fn parses_php_integer_radices_and_separators() {
        let cases: [(&[u8], i64); 8] = [
            (b"0", 0),
            (b"1234", 1234),
            (b"0123", 83),
            (b"0o123", 83),
            (b"0O123", 83),
            (b"0x1A", 26),
            (b"0b11111111", 255),
            (b"1_234_567", 1_234_567),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse_php_integer_literal(raw), Some(expected));
        }
    }

    #[test]
    fn rejects_invalid_or_overflowing_php_integer_literals() {
        let cases: [&[u8]; 11] = [
            b"",
            b"08",
            b"0o",
            b"0x",
            b"0b2",
            b"_1",
            b"1_",
            b"1__2",
            b"0_1",
            b"12z",
            b"9223372036854775808",
        ];
        for raw in cases {
            assert_eq!(parse_php_integer_literal(raw), None);
        }
    }
}
