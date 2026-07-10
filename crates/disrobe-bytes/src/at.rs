use crate::reader::{ByteReadError, ByteReader};

macro_rules! at_methods {
    ($($fn_at:ident => $reader_fn:ident : $ty:ty),* $(,)?) => {
        $(
            pub fn $fn_at(bytes: &[u8], offset: usize) -> Result<$ty, ByteReadError> {
                let mut reader: ByteReader<'_> = ByteReader::new(bytes);
                reader.seek(offset)?;
                reader.$reader_fn()
            }
        )*
    };
}

at_methods! {
    read_u8_at => read_u8 : u8,
    read_i8_at => read_i8 : i8,
    read_u16_le_at => read_u16_le : u16,
    read_u16_be_at => read_u16_be : u16,
    read_i16_le_at => read_i16_le : i16,
    read_i16_be_at => read_i16_be : i16,
    read_u24_le_at => read_u24_le : u32,
    read_u24_be_at => read_u24_be : u32,
    read_u32_le_at => read_u32_le : u32,
    read_u32_be_at => read_u32_be : u32,
    read_i32_le_at => read_i32_le : i32,
    read_i32_be_at => read_i32_be : i32,
    read_u64_le_at => read_u64_le : u64,
    read_u64_be_at => read_u64_be : u64,
    read_i64_le_at => read_i64_le : i64,
    read_i64_be_at => read_i64_be : i64,
    read_u128_le_at => read_u128_le : u128,
    read_u128_be_at => read_u128_be : u128,
    read_i128_le_at => read_i128_le : i128,
    read_i128_be_at => read_i128_be : i128,
}

pub fn read_bytes_at(bytes: &[u8], offset: usize, count: usize) -> Result<&[u8], ByteReadError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    reader.read_bytes(count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        read_bytes_at, read_i16_le_at, read_u8_at, read_u16_be_at, read_u16_le_at, read_u24_le_at,
        read_u32_be_at, read_u32_le_at, read_u64_le_at,
    };
    use crate::reader::ByteReadError;

    #[test]
    fn reads_fixed_widths_at_a_nonzero_offset() {
        let data: [u8; 10] = [0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u8_at(&data, 2).unwrap(), 0x01);
        assert_eq!(read_u16_le_at(&data, 2).unwrap(), 0x0201);
        assert_eq!(read_u16_be_at(&data, 2).unwrap(), 0x0102);
        assert_eq!(read_u24_le_at(&data, 2).unwrap(), 0x03_02_01);
        assert_eq!(read_u32_le_at(&data, 2).unwrap(), 0x0403_0201);
        assert_eq!(read_u32_be_at(&data, 2).unwrap(), 0x0102_0304);
        assert_eq!(read_u64_le_at(&data, 2).unwrap(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn signed_reads_sign_extend() {
        let data: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
        assert_eq!(read_i16_le_at(&data, 2).unwrap(), -1);
    }

    #[test]
    fn read_bytes_at_slices_without_panic() {
        let data: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        assert_eq!(read_bytes_at(&data, 2, 3).unwrap(), &[0xBE, 0xEF, 0xCA]);
    }

    #[test]
    fn offset_past_end_rejects_without_panic() {
        let data: [u8; 4] = [0, 1, 2, 3];
        let err: ByteReadError = read_u32_le_at(&data, 2).unwrap_err();
        assert_eq!(err.needed, 4);
        assert!(read_u8_at(&data, 9).is_err());
        assert!(read_bytes_at(&data, 3, 100).is_err());
    }

    #[test]
    fn count_overflow_is_rejected() {
        let data: [u8; 2] = [0, 1];
        assert!(read_bytes_at(&data, 1, usize::MAX).is_err());
    }
}
