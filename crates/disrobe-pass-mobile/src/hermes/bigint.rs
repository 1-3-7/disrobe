use super::BigIntTableEntry;

/// Upper bound on bigint storage bytes converted to a decimal string for one
/// literal. A forged table `length` could point at a multi-megabyte span whose
/// base-10 conversion is quadratic; real `BigInt` literals are small, so
/// anything past this renders as a hex summary instead.
const MAX_BIGINT_BYTES: usize = 4096;

/// Recovers the JavaScript source form (`<decimal>n`) of every bigint literal in
/// a module from its little-endian two's-complement digit storage.
///
/// The storage is the exact runtime representation, so the recovered decimal is
/// the original literal value (formatting such as separators or radix is lost).
#[must_use]
pub fn recover_bigints(table: &[BigIntTableEntry], storage: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(table.len());
    for entry in table {
        let start: usize = entry.offset as usize;
        let end: usize = start.saturating_add(entry.length as usize);
        if start >= storage.len() || end > storage.len() || entry.length == 0 {
            out.push("0n".to_owned());
            continue;
        }
        out.push(bigint_literal(&storage[start..end]));
    }
    out
}

/// Converts a little-endian two's-complement byte slice to a JS bigint literal.
#[must_use]
pub fn bigint_literal(le_twos_complement: &[u8]) -> String {
    if le_twos_complement.len() > MAX_BIGINT_BYTES {
        return format!("/* bigint {} bytes */ 0n", le_twos_complement.len());
    }
    let negative: bool = le_twos_complement
        .last()
        .is_some_and(|b: &u8| *b & 0x80 != 0);
    let magnitude: Vec<u8> = if negative {
        negate_le_twos_complement(le_twos_complement)
    } else {
        le_twos_complement.to_vec()
    };
    let decimal: String = le_bytes_to_decimal(&magnitude);
    if negative {
        format!("-{decimal}n")
    } else {
        format!("{decimal}n")
    }
}

/// Computes the magnitude of a negative two's-complement value: invert all bytes
/// and add one, little-endian.
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

/// Converts a little-endian unsigned magnitude to its base-10 string via
/// repeated division by `1_000_000_000` (nine decimal digits per step).
#[must_use]
fn le_bytes_to_decimal(le: &[u8]) -> String {
    use std::fmt::Write as _;
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
    let mut iter = chunks.iter().rev();
    let Some(first): Option<&u32> = iter.next() else {
        return "0".to_owned();
    };
    out.push_str(&first.to_string());
    for chunk in iter {
        let _ = write!(out, "{chunk:09}");
    }
    out
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
    fn recover_from_table() {
        let mut storage: Vec<u8> = Vec::new();
        storage.extend_from_slice(&100u32.to_le_bytes());
        storage.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let table: Vec<BigIntTableEntry> = vec![
            BigIntTableEntry {
                offset: 0,
                length: 4,
            },
            BigIntTableEntry {
                offset: 4,
                length: 4,
            },
        ];
        let recovered: Vec<String> = recover_bigints(&table, &storage);
        assert_eq!(recovered, vec!["100n".to_owned(), "-1n".to_owned()]);
    }

    #[test]
    fn out_of_bounds_entry_yields_zero() {
        let storage: Vec<u8> = vec![1, 2, 3, 4];
        let table: Vec<BigIntTableEntry> = vec![BigIntTableEntry {
            offset: 100,
            length: 8,
        }];
        assert_eq!(recover_bigints(&table, &storage), vec!["0n".to_owned()]);
    }
}
