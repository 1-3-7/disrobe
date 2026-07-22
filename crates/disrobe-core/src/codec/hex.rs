use super::DecodeError;

pub const LOWER: &[u8; 16] = b"0123456789abcdef";

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        push_byte(&mut out, byte);
    }
    out
}

pub fn push_byte(out: &mut String, byte: u8) {
    out.push(LOWER[usize::from(byte >> 4)] as char);
    out.push(LOWER[usize::from(byte & 0x0f)] as char);
}

pub fn push_fixed(out: &mut String, value: u32, digits: usize) {
    for nibble_index in (0..digits).rev() {
        let shift: u32 = (nibble_index as u32).saturating_mul(4);
        let index: usize = ((value >> shift) & 0x0f) as usize;
        out.push(LOWER[index] as char);
    }
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes: &[u8] = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(DecodeError::BadLength { len: bytes.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        if let [high, low] = pair {
            out.push((nibble(*high)? << 4) | nibble(*low)?);
        }
    }
    Ok(out)
}

const fn nibble(symbol: u8) -> Result<u8, DecodeError> {
    match symbol {
        b'0'..=b'9' => Ok(symbol - b'0'),
        b'a'..=b'f' => Ok(symbol - b'a' + 10),
        b'A'..=b'F' => Ok(symbol - b'A' + 10),
        other => Err(DecodeError::InvalidSymbol { symbol: other }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{decode, encode, push_fixed};

    #[test]
    fn encode_is_lowercase_and_round_trips() {
        let raw: [u8; 5] = [0x00, 0x0f, 0xa5, 0xff, 0x10];
        let text: String = encode(&raw);
        assert_eq!(text, "000fa5ff10");
        assert_eq!(decode(&text).unwrap(), raw);
    }

    #[test]
    fn decode_rejects_odd_length_and_bad_symbol() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert_eq!(decode("DEADbeef").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn push_fixed_emits_requested_width() {
        let mut out: String = String::new();
        push_fixed(&mut out, 0x1a2b, 4);
        assert_eq!(out, "1a2b");
    }
}
