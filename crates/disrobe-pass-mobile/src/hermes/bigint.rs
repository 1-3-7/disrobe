use super::BigIntTableEntry;

const MAX_BIGINT_BYTES: usize = 4096;

#[must_use]
pub fn recover_bigints(table: &[BigIntTableEntry], storage: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(table.len());
    for entry in table {
        let Some(start): Option<usize> = usize::try_from(entry.offset).ok() else {
            out.push("0n".to_owned());
            continue;
        };
        let Some(length): Option<usize> = usize::try_from(entry.length).ok() else {
            out.push("0n".to_owned());
            continue;
        };
        let Some(end): Option<usize> = start.checked_add(length) else {
            out.push("0n".to_owned());
            continue;
        };
        let Some(slice): Option<&[u8]> = storage.get(start..end) else {
            out.push("0n".to_owned());
            continue;
        };
        if slice.is_empty() {
            out.push("0n".to_owned());
            continue;
        }
        out.push(bigint_literal(slice));
    }
    out
}

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
