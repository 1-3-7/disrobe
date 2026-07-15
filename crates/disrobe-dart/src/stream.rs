use crate::error::{Error, Result};

#[derive(Debug)]
pub(super) struct SnapshotStream<'data> {
    bytes: &'data [u8],
    offset: usize,
}

impl<'data> SnapshotStream<'data> {
    pub(super) const fn new(bytes: &'data [u8], offset: usize) -> Result<Self> {
        if offset > bytes.len() {
            return Err(Error::UnexpectedEnd { offset, needed: 0 });
        }
        Ok(Self { bytes, offset })
    }

    pub(super) const fn position(&self) -> usize {
        self.offset
    }

    pub(super) fn read_u8(&mut self) -> Result<u8> {
        self.read_raw_u8()
    }

    pub(super) fn read_u16(&mut self) -> Result<u16> {
        Ok(self.read_compact(16)? as u16)
    }

    pub(super) fn read_i16(&mut self) -> Result<i16> {
        Ok(self.read_compact(16)? as u16 as i16)
    }

    pub(super) fn read_u32(&mut self) -> Result<u32> {
        Ok(self.read_compact(32)? as u32)
    }

    pub(super) fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_compact(32)? as u32 as i32)
    }

    pub(super) fn read_i64(&mut self) -> Result<i64> {
        Ok(self.read_compact(64)? as i64)
    }

    pub(super) fn read_unsigned(&mut self) -> Result<u64> {
        let start: usize = self.offset;
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for index in 0..10_u8 {
            let byte: u8 = self.read_raw_u8()?;
            let payload: u64 = if byte > 127 {
                u64::from(byte - 128)
            } else {
                u64::from(byte)
            };
            if shift >= 64 || payload > (u64::MAX >> shift) {
                return Err(Error::InvalidUnsigned { offset: start });
            }
            value |= payload << shift;
            if byte > 127 {
                return Ok(value);
            }
            if index == 9 {
                return Err(Error::InvalidUnsigned { offset: start });
            }
            shift = shift
                .checked_add(7)
                .ok_or(Error::InvalidUnsigned { offset: start })?;
        }
        Err(Error::InvalidUnsigned { offset: start })
    }

    pub(super) fn read_ref(&mut self, object_count: usize) -> Result<u32> {
        let start: usize = self.offset;
        let mut value: i64 = 0;
        for _ in 0..4_u8 {
            let byte: i8 = self.read_raw_u8()? as i8;
            value = value
                .checked_mul(128)
                .and_then(|current: i64| current.checked_add(i64::from(byte)))
                .ok_or(Error::InvalidReferenceEncoding { offset: start })?;
            if byte < 0 {
                let corrected: i64 = value
                    .checked_add(128)
                    .ok_or(Error::InvalidReferenceEncoding { offset: start })?;
                let reference: u32 = u32::try_from(corrected)
                    .map_err(|_| Error::InvalidReferenceEncoding { offset: start })?;
                let reference_usize: usize = usize::try_from(reference)
                    .map_err(|_| Error::InvalidReferenceEncoding { offset: start })?;
                if reference == 0 || reference_usize > object_count {
                    return Err(Error::ReferenceOutOfBounds {
                        reference,
                        objects: object_count,
                        offset: start,
                    });
                }
                return Ok(reference);
            }
        }
        Err(Error::InvalidReferenceEncoding { offset: start })
    }

    pub(super) fn read_bytes(&mut self, length: usize) -> Result<&'data [u8]> {
        let end: usize = self
            .offset
            .checked_add(length)
            .ok_or(Error::UnexpectedEnd {
                offset: self.offset,
                needed: length,
            })?;
        let bytes: &'data [u8] = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::UnexpectedEnd {
                offset: self.offset,
                needed: length,
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_compact(&mut self, bit_width: u32) -> Result<u64> {
        let start: usize = self.offset;
        let maximum_bytes: u32 = bit_width.div_ceil(7);
        let mask: u64 = if bit_width == 64 {
            u64::MAX
        } else {
            (1_u64 << bit_width) - 1
        };
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for index in 0..maximum_bytes {
            let byte: u8 = self.read_raw_u8()?;
            if byte > 127 {
                let terminal: i16 = i16::from(byte) - 192;
                let terminal_bits: u64 = if terminal < 0 {
                    (i64::from(terminal) as u64) & mask
                } else {
                    u64::try_from(terminal).map_err(|_| Error::InvalidUnsigned { offset: start })?
                };
                value |= terminal_bits.wrapping_shl(shift);
                return Ok(value & mask);
            }
            value |= u64::from(byte).wrapping_shl(shift);
            if index + 1 == maximum_bytes {
                return Err(Error::InvalidUnsigned { offset: start });
            }
            shift = shift
                .checked_add(7)
                .ok_or(Error::InvalidUnsigned { offset: start })?;
        }
        Err(Error::InvalidUnsigned { offset: start })
    }

    fn read_raw_u8(&mut self) -> Result<u8> {
        let value: u8 = *self.bytes.get(self.offset).ok_or(Error::UnexpectedEnd {
            offset: self.offset,
            needed: 1,
        })?;
        self.offset = self.offset.checked_add(1).ok_or(Error::UnexpectedEnd {
            offset: self.offset,
            needed: 1,
        })?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::SnapshotStream;
    use crate::{Error, Result};

    #[test]
    fn reads_dart_unsigned_values() -> Result<()> {
        let bytes: [u8; 5] = [128, 127, 129, 44, 130];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 0)?;
        assert_eq!(stream.read_unsigned()?, 0);
        assert_eq!(stream.read_unsigned()?, 255);
        assert_eq!(stream.read_unsigned()?, 300);
        Ok(())
    }

    #[test]
    fn reads_dart_reference_ids() -> Result<()> {
        let bytes: [u8; 5] = [129, 1, 128, 127, 255];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 0)?;
        assert_eq!(stream.read_ref(20_000)?, 1);
        assert_eq!(stream.read_ref(20_000)?, 128);
        assert_eq!(stream.read_ref(20_000)?, 16_383);
        Ok(())
    }

    #[test]
    fn reads_dart_compact_scalars() -> Result<()> {
        let bytes: [u8; 4] = [2, 33, 215, 191];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 0)?;
        assert_eq!(stream.read_u32()?, 0x0005_d082);
        assert_eq!(stream.read_i32()?, -1);
        Ok(())
    }

    #[test]
    fn rejects_zero_reference_id() -> Result<()> {
        let bytes: [u8; 1] = [128];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 0)?;
        let result: Result<u32> = stream.read_ref(10);
        assert!(matches!(
            result,
            Err(Error::ReferenceOutOfBounds { reference: 0, .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_unterminated_unsigned_value() -> Result<()> {
        let bytes: [u8; 10] = [0; 10];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 0)?;
        let result: Result<u64> = stream.read_unsigned();
        assert!(matches!(result, Err(Error::InvalidUnsigned { .. })));
        Ok(())
    }

    #[test]
    fn rejects_truncated_byte_range() -> Result<()> {
        let bytes: [u8; 2] = [1, 2];
        let mut stream: SnapshotStream<'_> = SnapshotStream::new(&bytes, 1)?;
        let result: Result<&[u8]> = stream.read_bytes(2);
        assert!(matches!(result, Err(Error::UnexpectedEnd { .. })));
        Ok(())
    }
}
