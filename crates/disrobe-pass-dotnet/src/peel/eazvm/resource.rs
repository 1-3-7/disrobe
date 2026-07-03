const PSEUDO_RANDOM_INTS: [u32; 5] = [52_200_625, 614_125, 7_225, 85, 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionError {
    BadChar(char),
    DanglingGroup,
    Truncated,
}

#[must_use]
pub const fn crypt_byte(key: i32, position: u64, byte: u8) -> u8 {
    let mixed: u64 = (key.cast_unsigned() as u64) | position;
    (mixed as u8) ^ byte
}

#[must_use]
pub fn decrypt_region(resource: &[u8], key: i32, start: u64, len: usize) -> Option<Vec<u8>> {
    let start_usize: usize = usize::try_from(start).ok()?;
    let end: usize = start_usize.checked_add(len)?;
    let slice: &[u8] = resource.get(start_usize..end)?;
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for (i, byte) in slice.iter().enumerate() {
        let pos: u64 = start.checked_add(i as u64)?;
        out.push(crypt_byte(key, pos, *byte));
    }
    Some(out)
}

fn position_string_to_bytes(s: &str) -> Result<Vec<u8>, PositionError> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 4 / 5);
    let mut num: usize = 0;
    let mut acc: u32 = 0;
    for c in s.chars() {
        if c == 'z' && num == 0 {
            write_group(&mut out, 0, 0);
            continue;
        }
        if !('!'..='u').contains(&c) {
            return Err(PositionError::BadChar(c));
        }
        let digit: u32 = u32::from(c) - u32::from('!');
        acc = acc.wrapping_add(PSEUDO_RANDOM_INTS[num].wrapping_mul(digit));
        num += 1;
        if num == 5 {
            write_group(&mut out, acc, 0);
            num = 0;
            acc = 0;
        }
    }
    if num == 1 {
        return Err(PositionError::DanglingGroup);
    }
    if num > 1 {
        let mut padded: u32 = acc;
        for slot in PSEUDO_RANDOM_INTS.iter().take(5).skip(num) {
            padded = padded.wrapping_add(84u32.wrapping_mul(*slot));
        }
        write_group(&mut out, padded, 5 - num);
    }
    Ok(out)
}

fn write_group(out: &mut Vec<u8>, val: u32, skip_tail: usize) {
    out.push((val >> 24) as u8);
    if skip_tail == 3 {
        return;
    }
    out.push((val >> 16) as u8);
    if skip_tail == 2 {
        return;
    }
    out.push((val >> 8) as u8);
    if skip_tail == 1 {
        return;
    }
    out.push(val as u8);
}

pub fn decrypt_position_string(s: &str, crypto_key2: i32) -> Result<i64, PositionError> {
    let raw: Vec<u8> = position_string_to_bytes(s)?;
    let eight: &[u8] = raw.get(0..8).ok_or(PositionError::Truncated)?;
    let mut decrypted: [u8; 8] = [0u8; 8];
    for (i, slot) in decrypted.iter_mut().enumerate() {
        *slot = crypt_byte(crypto_key2, i as u64, eight[i]);
    }
    Ok(i64::from_be_bytes(decrypted))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn crypt_is_symmetric() {
        let key: i32 = 0x1234_5678;
        for pos in 0u64..32 {
            for byte in [0u8, 1, 0x7F, 0x80, 0xFF] {
                let enc: u8 = crypt_byte(key, pos, byte);
                assert_eq!(crypt_byte(key, pos, enc), byte);
            }
        }
    }

    #[test]
    fn position_round_trip_for_small_values() {
        let key2: i32 = 336_077_329;
        for position in [0i64, 50, 136, 244, 314, 1000, 65535] {
            let encoded: String = encode_for_test(position, key2);
            let decoded: i64 =
                decrypt_position_string(&encoded, key2).expect("decode position string");
            assert_eq!(decoded, position, "round trip position {position}");
        }
    }

    fn encode_for_test(position: i64, key2: i32) -> String {
        let raw: [u8; 8] = position.to_be_bytes();
        let mut enc: [u8; 8] = [0u8; 8];
        for (i, slot) in enc.iter_mut().enumerate() {
            *slot = crypt_byte(key2, i as u64, raw[i]);
        }
        base85_encode(&enc)
    }

    fn base85_encode(data: &[u8]) -> String {
        let mut s: String = String::new();
        let full: usize = data.len() / 4;
        for g in 0..full {
            let mut num: u32 = 0;
            for j in 0..4 {
                num = (num << 8) | u32::from(data[g * 4 + j]);
            }
            emit_group(&mut s, num, 5);
        }
        let rem: usize = data.len() % 4;
        if rem > 0 {
            let mut num: u32 = 0;
            for j in 0..4 {
                num <<= 8;
                if j < rem {
                    num |= u32::from(data[full * 4 + j]);
                }
            }
            emit_group(&mut s, num, rem + 1);
        }
        s
    }

    fn emit_group(s: &mut String, mut num: u32, count: usize) {
        let mut chars: [char; 5] = ['!'; 5];
        for slot in chars.iter_mut().rev() {
            *slot = char::from_u32(u32::from(b'!') + (num % 85)).unwrap_or('!');
            num /= 85;
        }
        for ch in chars.iter().take(count) {
            s.push(*ch);
        }
    }
}
