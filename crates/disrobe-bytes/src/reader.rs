use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteReadError {
    pub offset: usize,
    pub needed: usize,
    pub available: usize,
}

impl fmt::Display for ByteReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "byte read out of bounds at offset {} (needed {} byte(s), {} available)",
            self.offset, self.needed, self.available
        )
    }
}

impl Error for ByteReadError {}

#[derive(Debug, Clone, Copy)]
pub struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

macro_rules! endian_methods {
    ($read_le:ident, $read_be:ident, $peek_le:ident, $peek_be:ident, $ty:ty, $width:literal) => {
        pub fn $read_le(&mut self) -> Result<$ty, ByteReadError> {
            let raw: [u8; $width] = self.read_array::<$width>()?;
            Ok(<$ty>::from_le_bytes(raw))
        }

        pub fn $read_be(&mut self) -> Result<$ty, ByteReadError> {
            let raw: [u8; $width] = self.read_array::<$width>()?;
            Ok(<$ty>::from_be_bytes(raw))
        }

        pub fn $peek_le(&self) -> Result<$ty, ByteReadError> {
            let mut clone: Self = *self;
            clone.$read_le()
        }

        pub fn $peek_be(&self) -> Result<$ty, ByteReadError> {
            let mut clone: Self = *self;
            clone.$read_be()
        }
    };
}

impl<'a> ByteReader<'a> {
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    #[must_use]
    pub const fn total_len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    const fn error_at(&self, needed: usize) -> ByteReadError {
        ByteReadError {
            offset: self.pos,
            needed,
            available: self.remaining(),
        }
    }

    pub const fn seek(&mut self, position: usize) -> Result<(), ByteReadError> {
        if position > self.bytes.len() {
            return Err(ByteReadError {
                offset: position,
                needed: 0,
                available: self.bytes.len(),
            });
        }
        self.pos = position;
        Ok(())
    }

    pub fn skip(&mut self, count: usize) -> Result<(), ByteReadError> {
        let end: usize = self
            .pos
            .checked_add(count)
            .ok_or_else(|| self.error_at(count))?;
        if end > self.bytes.len() {
            return Err(self.error_at(count));
        }
        self.pos = end;
        Ok(())
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ByteReadError> {
        let end: usize = self
            .pos
            .checked_add(count)
            .ok_or_else(|| self.error_at(count))?;
        let slice: &'a [u8] = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| self.error_at(count))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn peek_bytes(&self, count: usize) -> Result<&'a [u8], ByteReadError> {
        let mut clone: Self = *self;
        clone.read_bytes(count)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ByteReadError> {
        let slice: &'a [u8] = self.read_bytes(N)?;
        let mut out: [u8; N] = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, ByteReadError> {
        let raw: [u8; 1] = self.read_array::<1>()?;
        Ok(raw[0])
    }

    pub fn read_i8(&mut self) -> Result<i8, ByteReadError> {
        let raw: [u8; 1] = self.read_array::<1>()?;
        Ok(i8::from_le_bytes(raw))
    }

    pub fn peek_u8(&self) -> Result<u8, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_u8()
    }

    pub fn peek_i8(&self) -> Result<i8, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_i8()
    }

    endian_methods!(read_u16_le, read_u16_be, peek_u16_le, peek_u16_be, u16, 2);
    endian_methods!(read_i16_le, read_i16_be, peek_i16_le, peek_i16_be, i16, 2);
    endian_methods!(read_u32_le, read_u32_be, peek_u32_le, peek_u32_be, u32, 4);
    endian_methods!(read_i32_le, read_i32_be, peek_i32_le, peek_i32_be, i32, 4);
    endian_methods!(read_u64_le, read_u64_be, peek_u64_le, peek_u64_be, u64, 8);
    endian_methods!(read_i64_le, read_i64_be, peek_i64_le, peek_i64_be, i64, 8);
    endian_methods!(
        read_u128_le,
        read_u128_be,
        peek_u128_le,
        peek_u128_be,
        u128,
        16
    );
    endian_methods!(
        read_i128_le,
        read_i128_be,
        peek_i128_le,
        peek_i128_be,
        i128,
        16
    );

    pub fn read_u24_le(&mut self) -> Result<u32, ByteReadError> {
        let raw: [u8; 3] = self.read_array::<3>()?;
        Ok(u32::from(raw[0]) | (u32::from(raw[1]) << 8) | (u32::from(raw[2]) << 16))
    }

    pub fn read_u24_be(&mut self) -> Result<u32, ByteReadError> {
        let raw: [u8; 3] = self.read_array::<3>()?;
        Ok((u32::from(raw[0]) << 16) | (u32::from(raw[1]) << 8) | u32::from(raw[2]))
    }

    pub fn peek_u24_le(&self) -> Result<u32, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_u24_le()
    }

    pub fn peek_u24_be(&self) -> Result<u32, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_u24_be()
    }

    pub fn read_i24_le(&mut self) -> Result<i32, ByteReadError> {
        let raw: u32 = self.read_u24_le()?;
        Ok(sign_extend_24(raw))
    }

    pub fn read_i24_be(&mut self) -> Result<i32, ByteReadError> {
        let raw: u32 = self.read_u24_be()?;
        Ok(sign_extend_24(raw))
    }

    pub fn peek_i24_le(&self) -> Result<i32, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_i24_le()
    }

    pub fn peek_i24_be(&self) -> Result<i32, ByteReadError> {
        let mut clone: Self = *self;
        clone.read_i24_be()
    }
}

const fn sign_extend_24(raw: u32) -> i32 {
    ((raw << 8) as i32) >> 8
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ByteReadError, ByteReader};

    #[test]
    fn reads_little_and_big_endian_widths() {
        let data: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut le_reader: ByteReader<'_> = ByteReader::new(&data);
        assert_eq!(le_reader.read_u16_le().unwrap(), 0x0201);
        let mut be_reader: ByteReader<'_> = ByteReader::new(&data);
        assert_eq!(be_reader.read_u16_be().unwrap(), 0x0102);
        let mut wide_reader: ByteReader<'_> = ByteReader::new(&data);
        assert_eq!(wide_reader.read_u64_le().unwrap(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn read_past_end_returns_error_not_panic() {
        let data: [u8; 2] = [0xAA, 0xBB];
        let mut reader: ByteReader<'_> = ByteReader::new(&data);
        let result: Result<u32, ByteReadError> = reader.read_u32_le();
        assert!(result.is_err());
        assert_eq!(reader.position(), 0, "a failed read must not consume bytes");
    }

    #[test]
    fn read_bytes_overflow_does_not_advance_position() {
        let data: [u8; 2] = [0, 1];
        let mut reader: ByteReader<'_> = ByteReader::new(&data);
        reader.seek(1).unwrap();

        let error: ByteReadError = reader.read_bytes(usize::MAX).unwrap_err();

        assert_eq!(
            error,
            ByteReadError {
                offset: 1,
                needed: usize::MAX,
                available: 1,
            }
        );
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn peek_does_not_advance_position() {
        let data: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
        let mut reader: ByteReader<'_> = ByteReader::new(&data);
        assert_eq!(reader.peek_u32_le().unwrap(), 1);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.read_u32_le().unwrap(), 1);
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn skip_and_seek_are_bounds_checked() {
        let data: [u8; 4] = [0, 1, 2, 3];
        let mut reader: ByteReader<'_> = ByteReader::new(&data);
        assert!(reader.skip(10).is_err());
        assert_eq!(reader.position(), 0);
        assert!(reader.seek(4).is_ok());
        assert!(reader.seek(5).is_err());
    }

    #[test]
    fn u24_round_trips_and_sign_extends() {
        let positive: [u8; 3] = [0x34, 0x12, 0x00];
        let mut reader: ByteReader<'_> = ByteReader::new(&positive);
        assert_eq!(reader.read_u24_le().unwrap(), 0x00_12_34);

        let negative: [u8; 3] = [0xFF, 0xFF, 0xFF];
        let mut reader: ByteReader<'_> = ByteReader::new(&negative);
        assert_eq!(reader.read_i24_le().unwrap(), -1);
    }

    #[test]
    fn zero_length_read_on_empty_slice_succeeds() {
        let data: [u8; 0] = [];
        let mut reader: ByteReader<'_> = ByteReader::new(&data);
        assert!(reader.is_empty());
        assert_eq!(reader.read_bytes(0).unwrap().len(), 0);
        assert!(reader.read_u8().is_err());
    }
}
