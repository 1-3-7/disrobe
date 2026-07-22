use crate::error::{Error, Result};
use disrobe_bytes::{ByteReadError, ByteReader};

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    inner: ByteReader<'a>,
}

impl<'a> Reader<'a> {
    #[inline]
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self {
            inner: ByteReader::new(buf),
        }
    }

    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.inner.position()
    }

    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        self.inner.seek(pos).map_err(map_byte_read_error)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.inner.read_bytes(n).map_err(map_byte_read_error)
    }

    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        self.inner.peek_bytes(n).map_err(map_byte_read_error)
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.inner.read_u8().map_err(map_byte_read_error)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.inner.read_u16_be().map_err(map_byte_read_error)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.inner.read_u32_be().map_err(map_byte_read_error)
    }

    pub fn i32(&mut self) -> Result<i32> {
        self.inner.read_i32_be().map_err(map_byte_read_error)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.inner.read_u64_be().map_err(map_byte_read_error)
    }

    pub fn f64(&mut self) -> Result<f64> {
        let raw: u64 = self.u64()?;
        Ok(f64::from_bits(raw))
    }

    pub fn tag(&mut self) -> Result<[u8; 4]> {
        let bytes: &[u8] = self.take(4)?;
        let mut tag: [u8; 4] = [0u8; 4];
        tag.copy_from_slice(bytes);
        Ok(tag)
    }
}

const fn map_byte_read_error(error: ByteReadError) -> Error {
    Error::Truncated {
        offset: error.offset,
        needed: error.needed,
        had: error.available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_rejects_offset_overflow() {
        let data: [u8; 1] = [0];
        let mut reader: Reader<'_> = Reader::new(&data);
        assert!(reader.seek(1).is_ok());
        assert!(matches!(
            reader.take(usize::MAX),
            Err(Error::Truncated {
                offset,
                needed: usize::MAX,
                ..
            }) if offset == 1
        ));
    }

    #[test]
    fn peek_rejects_offset_overflow() {
        let data: [u8; 1] = [0];
        let mut reader: Reader<'_> = Reader::new(&data);
        assert!(reader.seek(1).is_ok());
        assert!(matches!(
            reader.peek(usize::MAX),
            Err(Error::Truncated {
                offset,
                needed: usize::MAX,
                ..
            }) if offset == 1
        ));
    }
}
