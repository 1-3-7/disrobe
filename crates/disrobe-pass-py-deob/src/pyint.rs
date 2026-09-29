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

#[cfg(test)]
mod tests {
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
