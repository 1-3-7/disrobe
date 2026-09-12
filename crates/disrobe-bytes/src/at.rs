use crate::reader::{ByteReadError, ByteReader, sign_extend_24};

macro_rules! at_methods {
    ($($fn_at:ident, $fn_or:ident => $reader_fn:ident : $ty:ty),* $(,)?) => {
        $(
            pub fn $fn_at(bytes: &[u8], offset: usize) -> Result<$ty, ByteReadError> {
                let mut reader: ByteReader<'_> = ByteReader::new(bytes);
                reader.seek(offset)?;
                reader.$reader_fn()
            }

            #[inline]
            #[must_use]
            pub fn $fn_or(bytes: &[u8], offset: usize, default: $ty) -> $ty {
                $fn_at(bytes, offset).unwrap_or(default)
            }
        )*
    };
}

at_methods! {
    read_u8_at, read_u8_at_or => read_u8 : u8,
    read_i8_at, read_i8_at_or => read_i8 : i8,
    read_u16_le_at, read_u16_le_at_or => read_u16_le : u16,
    read_u16_be_at, read_u16_be_at_or => read_u16_be : u16,
    read_i16_le_at, read_i16_le_at_or => read_i16_le : i16,
    read_i16_be_at, read_i16_be_at_or => read_i16_be : i16,
    read_u24_le_at, read_u24_le_at_or => read_u24_le : u32,
    read_u24_be_at, read_u24_be_at_or => read_u24_be : u32,
    read_i24_le_at, read_i24_le_at_or => read_i24_le : i32,
    read_i24_be_at, read_i24_be_at_or => read_i24_be : i32,
    read_u32_le_at, read_u32_le_at_or => read_u32_le : u32,
    read_u32_be_at, read_u32_be_at_or => read_u32_be : u32,
    read_i32_le_at, read_i32_le_at_or => read_i32_le : i32,
    read_i32_be_at, read_i32_be_at_or => read_i32_be : i32,
    read_u64_le_at, read_u64_le_at_or => read_u64_le : u64,
    read_u64_be_at, read_u64_be_at_or => read_u64_be : u64,
    read_i64_le_at, read_i64_le_at_or => read_i64_le : i64,
    read_i64_be_at, read_i64_be_at_or => read_i64_be : i64,
    read_u128_le_at, read_u128_le_at_or => read_u128_le : u128,
    read_u128_be_at, read_u128_be_at_or => read_u128_be : u128,
    read_i128_le_at, read_i128_le_at_or => read_i128_le : i128,
    read_i128_be_at, read_i128_be_at_or => read_i128_be : i128,
    read_f32_le_at, read_f32_le_at_or => read_f32_le : f32,
    read_f32_be_at, read_f32_be_at_or => read_f32_be : f32,
    read_f64_le_at, read_f64_le_at_or => read_f64_le : f64,
    read_f64_be_at, read_f64_be_at_or => read_f64_be : f64,
}

pub fn read_bytes_at(bytes: &[u8], offset: usize, count: usize) -> Result<&[u8], ByteReadError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    reader.read_bytes(count)
}

fn zero_padded_window<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out: [u8; N] = [0u8; N];
    let Some(tail): Option<&[u8]> = bytes.get(offset..) else {
        return out;
    };
    let taken: usize = tail.len().min(N);
    let (Some(source), Some(destination)): (Option<&[u8]>, Option<&mut [u8]>) =
        (tail.get(..taken), out.get_mut(..taken))
    else {
        return out;
    };
    destination.copy_from_slice(source);
    out
}

macro_rules! at_zero_pad_tail_methods {
    ($($fn_le:ident, $fn_be:ident : $ty:ty, $width:literal),* $(,)?) => {
        $(
            #[inline]
            #[must_use]
            pub fn $fn_le(bytes: &[u8], offset: usize) -> $ty {
                <$ty>::from_le_bytes(zero_padded_window::<$width>(bytes, offset))
            }

            #[inline]
            #[must_use]
            pub fn $fn_be(bytes: &[u8], offset: usize) -> $ty {
                <$ty>::from_be_bytes(zero_padded_window::<$width>(bytes, offset))
            }
        )*
    };
}

at_zero_pad_tail_methods! {
    read_u16_le_at_zero_pad_tail, read_u16_be_at_zero_pad_tail : u16, 2,
    read_i16_le_at_zero_pad_tail, read_i16_be_at_zero_pad_tail : i16, 2,
    read_u32_le_at_zero_pad_tail, read_u32_be_at_zero_pad_tail : u32, 4,
    read_i32_le_at_zero_pad_tail, read_i32_be_at_zero_pad_tail : i32, 4,
    read_u64_le_at_zero_pad_tail, read_u64_be_at_zero_pad_tail : u64, 8,
    read_i64_le_at_zero_pad_tail, read_i64_be_at_zero_pad_tail : i64, 8,
    read_u128_le_at_zero_pad_tail, read_u128_be_at_zero_pad_tail : u128, 16,
    read_i128_le_at_zero_pad_tail, read_i128_be_at_zero_pad_tail : i128, 16,
    read_f32_le_at_zero_pad_tail, read_f32_be_at_zero_pad_tail : f32, 4,
    read_f64_le_at_zero_pad_tail, read_f64_be_at_zero_pad_tail : f64, 8,
}

#[inline]
#[must_use]
pub fn read_u8_at_zero_pad_tail(bytes: &[u8], offset: usize) -> u8 {
    zero_padded_window::<1>(bytes, offset)[0]
}

#[inline]
#[must_use]
pub fn read_i8_at_zero_pad_tail(bytes: &[u8], offset: usize) -> i8 {
    i8::from_le_bytes(zero_padded_window::<1>(bytes, offset))
}

#[inline]
#[must_use]
pub fn read_u24_le_at_zero_pad_tail(bytes: &[u8], offset: usize) -> u32 {
    let raw: [u8; 3] = zero_padded_window::<3>(bytes, offset);
    u32::from(raw[0]) | (u32::from(raw[1]) << 8) | (u32::from(raw[2]) << 16)
}

#[inline]
#[must_use]
pub fn read_u24_be_at_zero_pad_tail(bytes: &[u8], offset: usize) -> u32 {
    let raw: [u8; 3] = zero_padded_window::<3>(bytes, offset);
    (u32::from(raw[0]) << 16) | (u32::from(raw[1]) << 8) | u32::from(raw[2])
}

#[inline]
#[must_use]
pub fn read_i24_le_at_zero_pad_tail(bytes: &[u8], offset: usize) -> i32 {
    sign_extend_24(read_u24_le_at_zero_pad_tail(bytes, offset))
}

#[inline]
#[must_use]
pub fn read_i24_be_at_zero_pad_tail(bytes: &[u8], offset: usize) -> i32 {
    sign_extend_24(read_u24_be_at_zero_pad_tail(bytes, offset))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        read_bytes_at, read_f32_le_at, read_f32_le_at_or, read_f64_be_at_zero_pad_tail,
        read_i8_at_zero_pad_tail, read_i16_le_at, read_i24_be_at, read_i24_le_at,
        read_i24_le_at_zero_pad_tail, read_u8_at, read_u8_at_or, read_u8_at_zero_pad_tail,
        read_u16_be_at, read_u16_be_at_zero_pad_tail, read_u16_le_at, read_u24_le_at,
        read_u24_le_at_zero_pad_tail, read_u32_be_at, read_u32_be_at_or,
        read_u32_be_at_zero_pad_tail, read_u32_le_at, read_u32_le_at_or,
        read_u32_le_at_zero_pad_tail, read_u64_le_at, read_u64_le_at_or,
        read_u64_le_at_zero_pad_tail,
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
    fn twenty_four_bit_reads_are_available_in_both_orders_and_signs() {
        let data: [u8; 4] = [0x00, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_i24_le_at(&data, 1).unwrap(), -1);
        assert_eq!(read_i24_be_at(&data, 1).unwrap(), -1);
        let positive: [u8; 3] = [0x34, 0x12, 0x00];
        assert_eq!(read_i24_le_at(&positive, 0).unwrap(), 0x1234);
    }

    #[test]
    fn floating_point_reads_round_trip() {
        let data: [u8; 4] = 1.5f32.to_le_bytes();
        assert_eq!(
            read_f32_le_at(&data, 0).unwrap().to_bits(),
            1.5f32.to_bits()
        );
        assert_eq!(
            read_f32_le_at_or(&data, 4, f32::NAN).to_bits(),
            f32::NAN.to_bits()
        );
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

    #[test]
    fn the_default_form_returns_the_default_for_any_absent_byte() {
        let data: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(read_u32_le_at_or(&data, 0, 0xDEAD_BEEF), 0x0403_0201);
        assert_eq!(read_u32_le_at_or(&data, 2, 0xDEAD_BEEF), 0x0605_0403);
        assert_eq!(read_u32_le_at_or(&data, 3, 0xDEAD_BEEF), 0xDEAD_BEEF);
        assert_eq!(read_u32_le_at_or(&data, 6, 0xDEAD_BEEF), 0xDEAD_BEEF);
        assert_eq!(read_u32_le_at_or(&data, 7, 0xDEAD_BEEF), 0xDEAD_BEEF);
        assert_eq!(read_u32_le_at_or(&data, usize::MAX, 0), 0);
        assert_eq!(read_u32_be_at_or(&data, 0, 0), 0x0102_0304);
        assert_eq!(read_u64_le_at_or(&data, 0, 7), 7);
        assert_eq!(read_u8_at_or(&[], 0, 9), 9);
    }

    #[test]
    fn the_zero_pad_form_fills_the_missing_trailing_bytes() {
        let data: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, 0), 0x0403_0201);
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, 4), 0x0000_0605);
        assert_eq!(read_u32_be_at_zero_pad_tail(&data, 4), 0x0506_0000);
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, 5), 0x0000_0006);
        assert_eq!(read_u32_be_at_zero_pad_tail(&data, 5), 0x0600_0000);
    }

    #[test]
    fn the_zero_pad_form_returns_zero_when_the_field_is_fully_absent() {
        let data: [u8; 2] = [0xFF, 0xFF];
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, 2), 0);
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, 3), 0);
        assert_eq!(read_u32_le_at_zero_pad_tail(&data, usize::MAX), 0);
        assert_eq!(read_u64_le_at_zero_pad_tail(&[], 0), 0);
        assert_eq!(read_u8_at_zero_pad_tail(&[], 0), 0);
        assert_eq!(read_i8_at_zero_pad_tail(&[], 1), 0);
        assert_eq!(read_f64_be_at_zero_pad_tail(&[], 0).to_bits(), 0);
    }

    #[test]
    fn every_partial_tail_length_is_defined_in_both_orders() {
        let data: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let little: [u32; 5] = [
            read_u32_le_at_zero_pad_tail(&data, 0),
            read_u32_le_at_zero_pad_tail(&data, 1),
            read_u32_le_at_zero_pad_tail(&data, 2),
            read_u32_le_at_zero_pad_tail(&data, 3),
            read_u32_le_at_zero_pad_tail(&data, 4),
        ];
        assert_eq!(
            little,
            [0x4433_2211, 0x0044_3322, 0x0000_4433, 0x0000_0044, 0]
        );
        let big: [u32; 5] = [
            read_u32_be_at_zero_pad_tail(&data, 0),
            read_u32_be_at_zero_pad_tail(&data, 1),
            read_u32_be_at_zero_pad_tail(&data, 2),
            read_u32_be_at_zero_pad_tail(&data, 3),
            read_u32_be_at_zero_pad_tail(&data, 4),
        ];
        assert_eq!(big, [0x1122_3344, 0x2233_4400, 0x3344_0000, 0x4400_0000, 0]);
    }

    #[test]
    fn narrow_zero_pad_forms_match_their_result_forms_when_the_field_is_present() {
        let data: [u8; 5] = [0x78, 0x56, 0x34, 0x12, 0x00];
        assert_eq!(
            read_u16_be_at_zero_pad_tail(&data, 0),
            read_u16_be_at(&data, 0).unwrap()
        );
        assert_eq!(
            read_u24_le_at_zero_pad_tail(&data, 0),
            read_u24_le_at(&data, 0).unwrap()
        );
        assert_eq!(
            read_i24_le_at_zero_pad_tail(&data, 0),
            read_i24_le_at(&data, 0).unwrap()
        );
    }

    #[test]
    fn the_twenty_four_bit_zero_pad_form_pads_the_trailing_bytes() {
        let data: [u8; 2] = [0x80, 0xFF];
        assert_eq!(read_u24_le_at_zero_pad_tail(&data, 0), 0x00_FF80);
        assert_eq!(read_i24_le_at_zero_pad_tail(&data, 1), 0x00_00FF);
        assert_eq!(read_u24_le_at_zero_pad_tail(&data, 2), 0);
    }
}
