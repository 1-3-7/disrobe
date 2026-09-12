use std::error::Error;
use std::fmt;

use crate::reader::{ByteReadError, ByteReader};

const CONTINUATION_BIT: u8 = 0x80;
const LOW_BITS_MASK: u8 = 0x7F;
const SLEB_SIGN_BIT: u8 = 0x40;
const SLEB_ALL_ONES_TERMINATOR: u8 = 0x7F;
const ULEB_MAX_FULL_GROUP_SHIFT: u32 = 63;
const I64_WIDTH_BITS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LebError {
    OutOfBounds(ByteReadError),
    Overflow { offset: usize },
}

impl fmt::Display for LebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds(inner) => write!(f, "leb128 decode ran out of bytes: {inner}"),
            Self::Overflow { offset } => write!(
                f,
                "leb128 value starting at offset {offset} does not fit the target width"
            ),
        }
    }
}

impl Error for LebError {}

impl From<ByteReadError> for LebError {
    fn from(value: ByteReadError) -> Self {
        Self::OutOfBounds(value)
    }
}

impl ByteReader<'_> {
    pub fn read_uleb128(&mut self) -> Result<u64, LebError> {
        let start: usize = self.position();
        match self.read_uleb128_body() {
            Ok(value) => Ok(value),
            Err(err) => {
                let _: Result<(), ByteReadError> = self.seek(start);
                Err(err)
            }
        }
    }

    pub fn read_sleb128(&mut self) -> Result<i64, LebError> {
        let start: usize = self.position();
        match self.read_sleb128_body() {
            Ok(value) => Ok(value),
            Err(err) => {
                let _: Result<(), ByteReadError> = self.seek(start);
                Err(err)
            }
        }
    }

    fn read_uleb128_body(&mut self) -> Result<u64, LebError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte_offset: usize = self.position();
            let byte: u8 = self.read_u8()?;

            if shift == ULEB_MAX_FULL_GROUP_SHIFT && byte != 0x00 && byte != 0x01 {
                return Err(LebError::Overflow {
                    offset: byte_offset,
                });
            }

            let low_bits: u64 = u64::from(byte & LOW_BITS_MASK);
            result |= low_bits << shift;

            if byte & CONTINUATION_BIT == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    fn read_sleb128_body(&mut self) -> Result<i64, LebError> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut last_byte: u8;
        loop {
            let byte_offset: usize = self.position();
            let byte: u8 = self.read_u8()?;
            last_byte = byte;

            if shift == ULEB_MAX_FULL_GROUP_SHIFT
                && byte != 0x00
                && byte != SLEB_ALL_ONES_TERMINATOR
            {
                return Err(LebError::Overflow {
                    offset: byte_offset,
                });
            }

            let low_bits: i64 = i64::from(byte & LOW_BITS_MASK);
            result |= low_bits << shift;
            shift += 7;

            if byte & CONTINUATION_BIT == 0 {
                break;
            }
        }

        if shift < I64_WIDTH_BITS && (last_byte & SLEB_SIGN_BIT) != 0 {
            result |= (-1i64) << shift;
        }

        Ok(result)
    }
}

pub fn read_uleb128_at(bytes: &[u8], offset: usize) -> Result<(u64, usize), LebError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    let value: u64 = reader.read_uleb128()?;
    let consumed: usize = reader.position().saturating_sub(offset);
    Ok((value, consumed))
}

pub fn read_sleb128_at(bytes: &[u8], offset: usize) -> Result<(i64, usize), LebError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    let value: i64 = reader.read_sleb128()?;
    let consumed: usize = reader.position().saturating_sub(offset);
    Ok((value, consumed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{LebError, read_sleb128_at, read_uleb128_at};
    use crate::reader::ByteReader;

    fn encode_uleb128_for_test(value: u64) -> Vec<u8> {
        let mut remaining: u64 = value;
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let mut byte: u8 = (remaining & 0x7F) as u8;
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if remaining == 0 {
                break;
            }
        }
        bytes
    }

    fn encode_sleb128_for_test(value: i64) -> Vec<u8> {
        let mut remaining: i64 = value;
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let byte: u8 = (remaining & 0x7F) as u8;
            remaining >>= 7;
            let sign_bit_set: bool = byte & 0x40 != 0;
            let done: bool = (remaining == 0 && !sign_bit_set) || (remaining == -1 && sign_bit_set);
            if done {
                bytes.push(byte);
                break;
            }
            bytes.push(byte | 0x80);
        }
        bytes
    }

    #[test]
    fn uleb128_decodes_spec_vectors() {
        let cases: [(u64, &[u8]); 4] = [
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (300, &[0xAC, 0x02]),
        ];
        for (expected, bytes) in cases {
            let mut reader: ByteReader<'_> = ByteReader::new(bytes);
            assert_eq!(reader.read_uleb128().unwrap(), expected);
            assert_eq!(reader.position(), bytes.len());

            let (value, consumed): (u64, usize) = read_uleb128_at(bytes, 0).unwrap();
            assert_eq!(value, expected);
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn uleb128_round_trips_u64_max_via_test_encoder() {
        let bytes: Vec<u8> = encode_uleb128_for_test(u64::MAX);
        assert_eq!(
            bytes,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        );

        let (value, consumed): (u64, usize) = read_uleb128_at(&bytes, 0).unwrap();
        assert_eq!(value, u64::MAX);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn uleb128_overlong_trailing_zero_group_is_legal() {
        let bytes: [u8; 2] = [0x80, 0x00];
        let (value, consumed): (u64, usize) = read_uleb128_at(&bytes, 0).unwrap();
        assert_eq!(value, 0);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn uleb128_truncated_continuation_is_out_of_bounds_and_transactional() {
        let bytes: [u8; 1] = [0x80];
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let err: LebError = reader.read_uleb128().unwrap_err();
        assert!(matches!(err, LebError::OutOfBounds(_)));
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn uleb128_overflowing_value_rejected_without_panic_and_transactional() {
        let mut bytes: Vec<u8> = vec![0x80; 9];
        bytes.push(0x02);
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let err: LebError = reader.read_uleb128().unwrap_err();
        assert_eq!(err, LebError::Overflow { offset: 9 });
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn sleb128_decodes_spec_vectors() {
        let cases: [(i64, &[u8]); 7] = [
            (0, &[0x00]),
            (-1, &[0x7F]),
            (2, &[0x02]),
            (-2, &[0x7E]),
            (63, &[0x3F]),
            (-64, &[0x40]),
            (64, &[0xC0, 0x00]),
        ];
        for (expected, bytes) in cases {
            let mut reader: ByteReader<'_> = ByteReader::new(bytes);
            assert_eq!(reader.read_sleb128().unwrap(), expected);
            assert_eq!(reader.position(), bytes.len());

            let (value, consumed): (i64, usize) = read_sleb128_at(bytes, 0).unwrap();
            assert_eq!(value, expected);
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn sleb128_decodes_minus_sixty_five() {
        let bytes: [u8; 2] = [0xBF, 0x7F];
        let (value, consumed): (i64, usize) = read_sleb128_at(&bytes, 0).unwrap();
        assert_eq!(value, -65);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn sleb128_round_trips_i64_extremes_via_test_encoder() {
        for expected in [i64::MIN, i64::MAX] {
            let bytes: Vec<u8> = encode_sleb128_for_test(expected);
            let (value, consumed): (i64, usize) = read_sleb128_at(&bytes, 0).unwrap();
            assert_eq!(value, expected);
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn sleb128_truncated_continuation_is_out_of_bounds_and_transactional() {
        let bytes: [u8; 1] = [0xFF];
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let err: LebError = reader.read_sleb128().unwrap_err();
        assert!(matches!(err, LebError::OutOfBounds(_)));
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn sleb128_overflowing_value_rejected_without_panic_and_transactional() {
        let mut bytes: Vec<u8> = vec![0x80; 9];
        bytes.push(0x02);
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let err: LebError = reader.read_sleb128().unwrap_err();
        assert_eq!(err, LebError::Overflow { offset: 9 });
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn read_at_offsets_into_a_larger_buffer_without_disturbing_prefix() {
        let bytes: [u8; 5] = [0xDE, 0xAD, 0xAC, 0x02, 0xFF];
        let (value, consumed): (u64, usize) = read_uleb128_at(&bytes, 2).unwrap();
        assert_eq!(value, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn at_forms_reject_offset_past_end_without_panic() {
        let bytes: [u8; 2] = [0x00, 0x01];
        assert!(read_uleb128_at(&bytes, 10).is_err());
        assert!(read_sleb128_at(&bytes, 10).is_err());
    }
}
