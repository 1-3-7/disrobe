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
            if shift >= 64 || value > (u64::MAX >> shift) {
                return Err(Error::BadUleb128(start));
            }
            let shifted: u64 = value << shift;
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

    pub fn checked_len(&self, section: &'static str, len: u64) -> Result<usize> {
        usize::try_from(len).map_err(|_| Error::LimitExceeded {
            section,
            count: len,
            limit: self.remaining(),
        })
    }

    pub fn checked_count<T>(
        &self,
        section: &'static str,
        count: u64,
        elem_bytes: usize,
    ) -> Result<usize> {
        let limit: usize = self.bounded_capacity::<T>(count, elem_bytes);
        let count_usize: usize = self.checked_len(section, count)?;
        if count_usize > limit {
            return Err(Error::LimitExceeded {
                section,
                count,
                limit,
            });
        }
        Ok(count_usize)
    }

    #[inline]
    #[must_use]
    pub fn bounded_capacity<T>(&self, count: u64, elem_bytes: usize) -> usize {
        let max_by_buffer: usize = self.remaining() / elem_bytes.max(1) + 1;
        let in_memory_bytes: usize = std::mem::size_of::<T>().max(1);
        let max_by_memory: usize = MAX_RESERVE_BYTES / in_memory_bytes;
        usize::try_from(count)
            .unwrap_or(usize::MAX)
            .min(max_by_buffer)
            .min(max_by_memory)
    }
}

pub const MAX_PROTO_DEPTH: usize = 256;

const MAX_RESERVE_BYTES: usize = 16 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_capacity_caps_reserved_bytes_by_element_size() {
        let buffer: Vec<u8> = vec![0u8; MAX_RESERVE_BYTES + 64];
        let cursor: ByteCursor<'_> = ByteCursor::new(&buffer);
        let huge_count: u64 = u64::MAX;
        let small_elem: usize = cursor.bounded_capacity::<u8>(huge_count, 1);
        let large_elem: usize = cursor.bounded_capacity::<[u8; 64]>(huge_count, 1);
        assert!(
            large_elem.saturating_mul(std::mem::size_of::<[u8; 64]>()) <= MAX_RESERVE_BYTES,
            "64-byte element reservation exceeded the byte ceiling"
        );
        assert_eq!(
            large_elem,
            MAX_RESERVE_BYTES / std::mem::size_of::<[u8; 64]>(),
            "large element count must be bound by the in-memory byte ceiling"
        );
        assert!(
            large_elem < small_elem,
            "a larger in-memory element must reserve fewer entries"
        );
    }

    #[test]
    fn bounded_capacity_preserves_small_legitimate_count() {
        let buffer: [u8; 64] = [0u8; 64];
        let cursor: ByteCursor<'_> = ByteCursor::new(&buffer);
        assert_eq!(cursor.bounded_capacity::<u32>(3, 4), 3);
        assert_eq!(cursor.bounded_capacity::<u32>(0, 4), 0);
    }

    #[test]
    fn uleb128_rejects_bits_shifted_past_u64() {
        let mut bytes: Vec<u8> = vec![0x80u8; 9];
        bytes.push(0x02u8);
        let mut cursor: ByteCursor<'_> = ByteCursor::new(&bytes);
        let result: Result<u64> = cursor.read_uleb128();
        assert!(matches!(result, Err(Error::BadUleb128(0))));
    }
}
