const MAX_DECIMAL_BYTES: usize = 4096;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[must_use]
pub fn bigint_literal(le_twos_complement: &[u8]) -> String {
    let negative: bool = le_twos_complement
        .last()
        .is_some_and(|b: &u8| *b & 0x80 != 0);
    let magnitude: Vec<u8> = if negative {
        negate_le_twos_complement(le_twos_complement)
    } else {
        le_twos_complement.to_vec()
    };
    let digits: String = if magnitude.len() > MAX_DECIMAL_BYTES {
        le_bytes_to_hex(&magnitude)
    } else {
        le_bytes_to_decimal(&magnitude)
    };
    if negative {
        format!("-{digits}n")
    } else {
        format!("{digits}n")
    }
}

#[must_use]
fn le_bytes_to_hex(le: &[u8]) -> String {
    let significant: &[u8] = match le.iter().rposition(|b: &u8| *b != 0) {
        Some(last) => &le[..=last],
        None => return "0".to_owned(),
    };
    let mut out: String = String::with_capacity(2 + significant.len() * 2);
    out.push_str("0x");
    let mut bytes: std::iter::Rev<std::slice::Iter<'_, u8>> = significant.iter().rev();
    if let Some(first) = bytes.next() {
        if *first >= 0x10 {
            out.push(char::from(HEX_DIGITS[usize::from(first >> 4)]));
        }
        out.push(char::from(HEX_DIGITS[usize::from(first & 0x0f)]));
    }
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[must_use]
fn negate_le_twos_complement(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut carry: u16 = 1;
    for b in bytes {
        let inverted: u16 = (!*b) as u16 + carry;
        out.push((inverted & 0xff) as u8);
        carry = inverted >> 8;
    }
    out
}

#[must_use]
fn le_bytes_to_decimal(le: &[u8]) -> String {
    const CHUNK: u64 = 1_000_000_000;

    let mut digits: Vec<u32> = Vec::with_capacity(le.len().div_ceil(4));
    let mut i: usize = 0;
    while i < le.len() {
        let mut word: u32 = 0;
        for k in 0..4 {
            let Some(b): Option<&u8> = le.get(i + k) else {
                continue;
            };
            word |= (*b as u32) << (8 * k);
        }
        digits.push(word);
        i += 4;
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    if digits.is_empty() {
        return "0".to_owned();
    }

    let mut chunks: Vec<u32> = Vec::new();
    while !digits.is_empty() {
        let mut remainder: u64 = 0;
        for d in digits.iter_mut().rev() {
            let cur: u64 = (remainder << 32) | (*d as u64);
            *d = (cur / CHUNK) as u32;
            remainder = cur % CHUNK;
        }
        chunks.push(remainder as u32);
        while digits.last() == Some(&0) {
            digits.pop();
        }
    }

    let mut out: String = String::with_capacity(chunks.len() * 9);
    let mut iter: core::iter::Rev<core::slice::Iter<'_, u32>> = chunks.iter().rev();
    let Some(first): Option<&u32> = iter.next() else {
        return "0".to_owned();
    };
    out.push_str(&first.to_string());
    for chunk in iter {
        push_padded_chunk(&mut out, *chunk);
    }
    out
}

fn push_padded_chunk(out: &mut String, chunk: u32) {
    let text: String = chunk.to_string();
    for _ in text.len()..9 {
        out.push('0');
    }
    out.push_str(&text);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero_n() {
        assert_eq!(bigint_literal(&[0]), "0n");
        assert_eq!(bigint_literal(&[0, 0, 0, 0]), "0n");
    }

    #[test]
    fn small_positive() {
        assert_eq!(bigint_literal(&42u64.to_le_bytes()), "42n");
        assert_eq!(bigint_literal(&[0x7f]), "127n");
    }

    #[test]
    fn small_negative() {
        assert_eq!(bigint_literal(&[0xff]), "-1n");
        assert_eq!(bigint_literal(&[0x80]), "-128n");
        let neg_two: i64 = -2;
        assert_eq!(bigint_literal(&neg_two.to_le_bytes()), "-2n");
    }

    #[test]
    fn large_positive_beyond_u64() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.push(0x00);
        assert_eq!(bigint_literal(&bytes), "18446744073709551615n");
    }

    #[test]
    fn power_of_ten() {
        let value: u128 = 1_000_000_000_000_000_000_000;
        let mut bytes: Vec<u8> = value.to_le_bytes().to_vec();
        bytes.push(0x00);
        assert_eq!(bigint_literal(&bytes), "1000000000000000000000n");
    }

    #[test]
    fn a_bigint_past_the_decimal_cap_renders_exactly_in_hex() {
        let mut bytes: Vec<u8> = vec![0u8; MAX_DECIMAL_BYTES + 8];
        bytes[0] = 0x2a;
        bytes[MAX_DECIMAL_BYTES + 6] = 0x01;
        let rendered: String = bigint_literal(&bytes);
        let expected: String = format!("0x1{}2an", "00".repeat(MAX_DECIMAL_BYTES + 5));
        assert_eq!(rendered, expected);
        let mut negative: Vec<u8> = vec![0xffu8; MAX_DECIMAL_BYTES + 8];
        negative[0] = 0xfe;
        assert_eq!(bigint_literal(&negative), "-0x2n");
    }
}
