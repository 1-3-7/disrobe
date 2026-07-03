use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    #[inline]
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.buf.len() {
            return Err(Error::Truncated {
                offset: pos,
                needed: 0,
                had: self.buf.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let start: usize = self.pos;
        let end: usize = self.end_for(n)?;
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        let end: usize = self.end_for(n)?;
        Ok(&self.buf[self.pos..end])
    }

    fn end_for(&self, n: usize) -> Result<usize> {
        let Some(end): Option<usize> = self.pos.checked_add(n) else {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                had: self.remaining(),
            });
        };
        if end > self.buf.len() {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                had: self.remaining(),
            });
        }
        Ok(end)
    }

    pub fn u8(&mut self) -> Result<u8> {
        let bytes: &[u8] = self.take(1)?;
        Ok(bytes[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let bytes: &[u8] = self.take(2)?;
        let arr: [u8; 2] = [bytes[0], bytes[1]];
        Ok(u16::from_be_bytes(arr))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes: &[u8] = self.take(4)?;
        let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(u32::from_be_bytes(arr))
    }

    pub fn i32(&mut self) -> Result<i32> {
        let bytes: &[u8] = self.take(4)?;
        let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(i32::from_be_bytes(arr))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let bytes: &[u8] = self.take(8)?;
        let mut arr: [u8; 8] = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(arr))
    }

    pub fn f64(&mut self) -> Result<f64> {
        let raw: u64 = self.u64()?;
        Ok(f64::from_bits(raw))
    }

    pub fn tag(&mut self) -> Result<[u8; 4]> {
        let bytes: &[u8] = self.take(4)?;
        let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_rejects_offset_overflow() {
        let mut reader: Reader<'_> = Reader {
            buf: &[],
            pos: usize::MAX - 1,
        };
        assert!(matches!(
            reader.take(2),
            Err(Error::Truncated {
                offset,
                needed: 2,
                ..
            }) if offset == usize::MAX - 1
        ));
    }

    #[test]
    fn peek_rejects_offset_overflow() {
        let reader: Reader<'_> = Reader {
            buf: &[],
            pos: usize::MAX - 1,
        };
        assert!(matches!(
            reader.peek(2),
            Err(Error::Truncated {
                offset,
                needed: 2,
                ..
            }) if offset == usize::MAX - 1
        ));
    }
}
