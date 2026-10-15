use serde::Serialize;

use crate::error::EvmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputEncoding {
    Hex,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputFormat {
    #[default]
    Auto,
    Hex,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInput {
    pub encoding: InputEncoding,
    pub bytes: Vec<u8>,
}

pub const EOF_MAGIC: [u8; 2] = [0xef, 0x00];

pub fn decode(input: &[u8], format: InputFormat, limit: usize) -> Result<DecodedInput, EvmError> {
    let decoded: DecodedInput = match format {
        InputFormat::Raw => DecodedInput {
            encoding: InputEncoding::Raw,
            bytes: input.to_vec(),
        },
        InputFormat::Hex => DecodedInput {
            encoding: InputEncoding::Hex,
            bytes: decode_hex(input, limit)?,
        },
        InputFormat::Auto => {
            if looks_like_hex(input) {
                DecodedInput {
                    encoding: InputEncoding::Hex,
                    bytes: decode_hex(input, limit)?,
                }
            } else {
                DecodedInput {
                    encoding: InputEncoding::Raw,
                    bytes: input.to_vec(),
                }
            }
        }
    };
    if decoded.bytes.is_empty() {
        return Err(EvmError::Empty);
    }
    if decoded.bytes.len() > limit {
        return Err(EvmError::TooLarge {
            size: decoded.bytes.len(),
            limit,
        });
    }
    if decoded.bytes.starts_with(&EOF_MAGIC) {
        return Err(EvmError::EofContainer {
            version: decoded.bytes.get(2).copied().unwrap_or(0),
        });
    }
    Ok(decoded)
}

fn strip_prefix(text: &[u8]) -> &[u8] {
    let trimmed: &[u8] = text.trim_ascii();
    trimmed
        .strip_prefix(b"0x")
        .or_else(|| trimmed.strip_prefix(b"0X"))
        .unwrap_or(trimmed)
}

fn looks_like_hex(input: &[u8]) -> bool {
    let trimmed: &[u8] = input.trim_ascii();
    let body: &[u8] = strip_prefix(input);
    let prefixed: bool = body.len() != trimmed.len();
    let mut digits: usize = 0;
    for byte in body {
        if byte.is_ascii_hexdigit() {
            digits += 1;
        } else if !byte.is_ascii_whitespace() {
            return false;
        }
    }
    prefixed || digits > 0
}

fn decode_hex(input: &[u8], limit: usize) -> Result<Vec<u8>, EvmError> {
    let body: &[u8] = strip_prefix(input);
    let prefix_len: usize =
        input.len() - input.trim_ascii_start().len() + (input.trim_ascii().len() - body.len());
    let digits: usize = body
        .iter()
        .filter(|byte: &&u8| !byte.is_ascii_whitespace())
        .count();
    if digits == 0 {
        return Err(EvmError::NoDigits {
            found: if body.is_empty() {
                "nothing"
            } else {
                "only whitespace"
            },
        });
    }
    if !digits.is_multiple_of(2) {
        return Err(EvmError::OddHex { digits });
    }
    if digits / 2 > limit {
        return Err(EvmError::TooLarge {
            size: digits / 2,
            limit,
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(digits / 2);
    let mut high: Option<u8> = None;
    for (index, byte) in body.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble: u8 = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => {
                return Err(EvmError::BadHex {
                    offset: prefix_len + index,
                    found: char::from(*byte),
                });
            }
        };
        match high.take() {
            Some(upper) => out.push((upper << 4) | nibble),
            None => high = Some(nibble),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{InputEncoding, InputFormat, decode};
    use crate::error::EvmError;

    #[test]
    fn hex_and_raw_are_told_apart() {
        let hex = decode(b"  0x6080604052\n", InputFormat::Auto, 1024);
        assert_eq!(
            hex.map(|d| (d.encoding, d.bytes)),
            Ok((InputEncoding::Hex, vec![0x60, 0x80, 0x60, 0x40, 0x52]))
        );
        let raw = decode(&[0x60, 0x80, 0x60, 0x40, 0x52], InputFormat::Auto, 1024);
        assert_eq!(raw.map(|d| d.encoding), Ok(InputEncoding::Raw));
        assert_eq!(
            decode(b"0x608", InputFormat::Auto, 1024),
            Err(EvmError::OddHex { digits: 3 })
        );
        assert_eq!(
            decode(b"0x60zz", InputFormat::Hex, 1024),
            Err(EvmError::BadHex {
                offset: 4,
                found: 'z'
            })
        );
        assert_eq!(
            decode(b"ef0001", InputFormat::Auto, 1024),
            Err(EvmError::EofContainer { version: 1 })
        );
        assert_eq!(
            decode(b"6060", InputFormat::Auto, 1),
            Err(EvmError::TooLarge { size: 2, limit: 1 })
        );
        assert_eq!(decode(b"", InputFormat::Auto, 1), Err(EvmError::Empty));
    }
}
