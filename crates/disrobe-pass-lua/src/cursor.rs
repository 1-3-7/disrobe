use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    little_endian: bool,
}

impl<'a> ByteCursor<'a> {
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            little_endian: true,
        }
    }

    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn set_little_endian(&mut self, le: bool) {
        self.little_endian = le;
    }

    #[inline]
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    pub fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                had: self.remaining(),
            });
        }
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let b: u8 = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let out: &'a [u8] = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| Error::Truncated {
                offset: self.pos,
                needed: 2,
                had: 0,
            })?;
        Ok(if self.little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .read_bytes(4)?
            .try_into()
            .map_err(|_| Error::Truncated {
                offset: self.pos,
                needed: 4,
                had: 0,
            })?;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self
            .read_bytes(8)?
            .try_into()
            .map_err(|_| Error::Truncated {
                offset: self.pos,
                needed: 8,
                had: 0,
            })?;
        Ok(if self.little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        let raw: u64 = self.read_u64()?;
        Ok(f64::from_bits(raw))
    }

    pub fn read_uleb128(&mut self) -> Result<u64> {
        let start: usize = self.pos;
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte: u8 = self.read_u8()?;
            let value: u64 = u64::from(byte & 0x7F);
            let shifted: u64 = value.checked_shl(shift).ok_or(Error::BadUleb128(start))?;
            result |= shifted;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::BadUleb128(start));
            }
        }
        Ok(result)
    }

    pub fn read_size(&mut self, size_bytes: u8) -> Result<u64> {
        match size_bytes {
            4 => Ok(u64::from(self.read_u32()?)),
            8 => self.read_u64(),
            other => Err(Error::BadIntSize(other)),
        }
    }
}
