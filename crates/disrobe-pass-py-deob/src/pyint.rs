pub(crate) fn floor_div(a: i128, b: i128) -> Option<i128> {
    let quotient: i128 = a.checked_div(b)?;
    if a % b != 0 && (a < 0) != (b < 0) {
        quotient.checked_sub(1)
    } else {
        Some(quotient)
    }
}

pub(crate) fn floor_mod(a: i128, b: i128) -> Option<i128> {
    let remainder: i128 = a.checked_rem(b)?;
    if remainder != 0 && (remainder < 0) != (b < 0) {
        Some(remainder + b)
    } else {
        Some(remainder)
    }
}

pub(crate) fn pow_mod(base: i128, exp: i128, modulus: i128) -> Option<i128> {
    if exp < 0 || modulus == 0 {
        return None;
    }
    let m: i128 = modulus.checked_abs()?;
    let mut result: i128 = 1 % m;
    let mut b: i128 = base.rem_euclid(m);
    let mut e: i128 = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.checked_mul(b)? % m;
        }
        e >>= 1;
        if e > 0 {
            b = b.checked_mul(b)? % m;
        }
    }
    floor_mod(result, modulus)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntText {
    Invalid,
    NonAscii,
    TooWide,
}

pub(crate) fn parse_int(text: &str, radix: u32) -> Result<i128, IntText> {
    if !text.is_ascii() {
        return Err(IntText::NonAscii);
    }
    if !(2..=36).contains(&radix) {
        return Err(IntText::Invalid);
    }
    let trimmed: &str = text.trim_matches(|c: char| matches!(c, ' ' | '\t'..='\r'));
    let (negative, unsigned): (bool, &str) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let marker: Option<char> = match radix {
        2 => Some('b'),
        8 => Some('o'),
        16 => Some('x'),
        _ => None,
    };
    let digits: &str = marker
        .and_then(|marker: char| {
            let rest: &str = unsigned.strip_prefix('0')?;
            let rest: &str = rest
                .strip_prefix(marker)
                .or_else(|| rest.strip_prefix(marker.to_ascii_uppercase()))?;
            Some(rest.strip_prefix('_').unwrap_or(rest))
        })
        .unwrap_or(unsigned);
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return Err(IntText::Invalid);
    }
    let mut value: i128 = 0;
    for digit in digits.chars().filter(|c: &char| *c != '_') {
        let digit: u32 = digit.to_digit(radix).ok_or(IntText::Invalid)?;
        value = value
            .checked_mul(i128::from(radix))
            .and_then(|scaled: i128| scaled.checked_add(i128::from(digit)))
            .ok_or(IntText::TooWide)?;
    }
    Ok(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    #[test]
    fn int_text_follows_cpython() {
        for (text, radix, expected) in [
            ("0b_1", 2, Ok(1)),
            ("_1", 2, Err(IntText::Invalid)),
            (" 1 ", 2, Ok(1)),
            ("1_", 2, Err(IntText::Invalid)),
            ("0B1", 2, Ok(1)),
            ("-0b1", 2, Ok(-1)),
            ("0b", 2, Err(IntText::Invalid)),
            ("0_b1", 2, Err(IntText::Invalid)),
            ("0b__1", 2, Err(IntText::Invalid)),
            ("1\u{1c}", 2, Err(IntText::Invalid)),
            ("0o345", 8, Ok(229)),
            ("0O17", 8, Ok(15)),
            ("0x1f", 16, Ok(31)),
            ("0x1f", 10, Err(IntText::Invalid)),
            ("0_0", 10, Ok(0)),
            ("+_1", 10, Err(IntText::Invalid)),
            ("007", 10, Ok(7)),
            ("- 5", 10, Err(IntText::Invalid)),
            ("\u{661}", 10, Err(IntText::NonAscii)),
            (
                "170141183460469231731687303715884105728",
                10,
                Err(IntText::TooWide),
            ),
        ] {
            assert_eq!(parse_int(text, radix), expected, "{text:?} base {radix}");
        }
    }

    use super::*;

    #[test]
    fn division_rounds_toward_negative_infinity_as_python_does() {
        assert_eq!(floor_div(7, -2), Some(-4));
        assert_eq!(floor_mod(7, -2), Some(-1));
        assert_eq!(floor_div(-7, 2), Some(-4));
        assert_eq!(floor_mod(-7, 2), Some(1));
        assert_eq!(floor_div(-7, -2), Some(3));
        assert_eq!(floor_mod(-7, -2), Some(-1));
        assert_eq!(floor_div(6, -3), Some(-2));
        assert_eq!(floor_mod(6, -3), Some(0));
        assert_eq!(floor_div(1, 0), None);
        assert_eq!(floor_div(i128::MIN, -1), None);
    }

    #[test]
    fn a_negative_modulus_gives_a_result_with_its_sign() {
        assert_eq!(pow_mod(2, 3, -5), Some(-2));
        assert_eq!(pow_mod(-2, 3, 5), Some(2));
        assert_eq!(pow_mod(3, 0, -7), Some(-6));
        assert_eq!(pow_mod(5, 3, 1), Some(0));
        assert_eq!(pow_mod(-3, 3, -7), Some(-6));
    }

    #[test]
    fn a_modulus_too_wide_to_square_is_refused_instead_of_overflowing() {
        assert_eq!(pow_mod(i128::MAX - 1, 2, i128::MAX), None);
    }
}
