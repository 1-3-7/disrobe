#![allow(clippy::unwrap_used)]
use disrobe_bytes::{
    ByteReadError, ByteReader, align_down_u32, align_down_u64, align_up_u32, align_up_u64,
    align_up_usize,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn round_trip_u8(value in any::<u8>()) {
        let bytes: [u8; 1] = [value];
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        prop_assert_eq!(reader.read_u8().unwrap(), value);
    }

    #[test]
    fn round_trip_i8(value in any::<i8>()) {
        let bytes: [u8; 1] = value.to_le_bytes();
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        prop_assert_eq!(reader.read_i8().unwrap(), value);
    }

    #[test]
    fn round_trip_u16(value in any::<u16>()) {
        let le_bytes: [u8; 2] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_u16_le().unwrap(), value);

        let be_bytes: [u8; 2] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_u16_be().unwrap(), value);
    }

    #[test]
    fn round_trip_i16(value in any::<i16>()) {
        let le_bytes: [u8; 2] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_i16_le().unwrap(), value);

        let be_bytes: [u8; 2] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_i16_be().unwrap(), value);
    }

    #[test]
    fn round_trip_u32(value in any::<u32>()) {
        let le_bytes: [u8; 4] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_u32_le().unwrap(), value);

        let be_bytes: [u8; 4] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_u32_be().unwrap(), value);
    }

    #[test]
    fn round_trip_i32(value in any::<i32>()) {
        let le_bytes: [u8; 4] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_i32_le().unwrap(), value);

        let be_bytes: [u8; 4] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_i32_be().unwrap(), value);
    }

    #[test]
    fn round_trip_u64(value in any::<u64>()) {
        let le_bytes: [u8; 8] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_u64_le().unwrap(), value);

        let be_bytes: [u8; 8] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_u64_be().unwrap(), value);
    }

    #[test]
    fn round_trip_i64(value in any::<i64>()) {
        let le_bytes: [u8; 8] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_i64_le().unwrap(), value);

        let be_bytes: [u8; 8] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_i64_be().unwrap(), value);
    }

    #[test]
    fn round_trip_u128(value in any::<u128>()) {
        let le_bytes: [u8; 16] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_u128_le().unwrap(), value);

        let be_bytes: [u8; 16] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_u128_be().unwrap(), value);
    }

    #[test]
    fn round_trip_i128(value in any::<i128>()) {
        let le_bytes: [u8; 16] = value.to_le_bytes();
        let mut le_reader: ByteReader<'_> = ByteReader::new(&le_bytes);
        prop_assert_eq!(le_reader.read_i128_le().unwrap(), value);

        let be_bytes: [u8; 16] = value.to_be_bytes();
        let mut be_reader: ByteReader<'_> = ByteReader::new(&be_bytes);
        prop_assert_eq!(be_reader.read_i128_be().unwrap(), value);
    }

    #[test]
    fn round_trip_u24(value in 0u32..=0x00FF_FFFF) {
        let full_le: [u8; 4] = value.to_le_bytes();
        let narrow_le: [u8; 3] = [full_le[0], full_le[1], full_le[2]];
        let mut le_reader: ByteReader<'_> = ByteReader::new(&narrow_le);
        prop_assert_eq!(le_reader.read_u24_le().unwrap(), value);

        let full_be: [u8; 4] = value.to_be_bytes();
        let narrow_be: [u8; 3] = [full_be[1], full_be[2], full_be[3]];
        let mut be_reader: ByteReader<'_> = ByteReader::new(&narrow_be);
        prop_assert_eq!(be_reader.read_u24_be().unwrap(), value);
    }

    #[test]
    fn peek_never_advances_position(
        bytes in proptest::collection::vec(any::<u8>(), 0..64),
        pos in 0usize..96,
    ) {
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        if reader.seek(pos.min(bytes.len())).is_ok() {
            let before: usize = reader.position();
            let _ = reader.peek_u32_le();
            let _ = reader.peek_bytes(3);
            let _ = reader.peek_u8();
            prop_assert_eq!(reader.position(), before);
        }
    }

    #[test]
    fn reads_past_end_error_never_panic_and_never_advance(
        bytes in proptest::collection::vec(any::<u8>(), 0..48),
        skip_amount in 0usize..64,
        read_amount in 0usize..32,
    ) {
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let skip_result: Result<(), ByteReadError> = reader.skip(skip_amount);
        if skip_amount > bytes.len() {
            prop_assert!(skip_result.is_err());
            prop_assert_eq!(reader.position(), 0);
            return Ok(());
        }
        prop_assert!(skip_result.is_ok());
        let pos_before: usize = reader.position();
        let remaining: usize = reader.remaining();
        let read_result: Result<&[u8], ByteReadError> = reader.read_bytes(read_amount);
        if read_amount > remaining {
            prop_assert!(read_result.is_err());
            prop_assert_eq!(reader.position(), pos_before, "a failed read must not consume bytes");
        } else {
            prop_assert!(read_result.is_ok());
            prop_assert_eq!(reader.position(), pos_before + read_amount);
        }
    }

    #[test]
    fn align_up_u32_invariants(value in any::<u32>(), align in any::<u32>()) {
        let result: u32 = align_up_u32(value, align);
        if align == 0 {
            prop_assert_eq!(result, value);
        } else {
            let true_aligned: u64 = u64::from(value).div_ceil(u64::from(align)) * u64::from(align);
            if true_aligned > u64::from(u32::MAX) {
                prop_assert_eq!(result, u32::MAX);
            } else {
                let expected: u32 = true_aligned as u32;
                prop_assert_eq!(result, expected);
                prop_assert!(result >= value);
                prop_assert_eq!(result % align, 0);
            }
        }
    }

    #[test]
    fn align_up_u64_never_panics_near_max(align in any::<u64>()) {
        let near_max_values: [u64; 4] = [u64::MAX, u64::MAX - 1, u64::MAX / 2, 0];
        for value in near_max_values {
            let result: u64 = align_up_u64(value, align);
            if align == 0 {
                prop_assert_eq!(result, value);
                continue;
            }
            let wide_value: u128 = u128::from(value);
            let wide_align: u128 = u128::from(align);
            let true_aligned: u128 = wide_value.div_ceil(wide_align) * wide_align;
            if true_aligned > u128::from(u64::MAX) {
                prop_assert_eq!(result, u64::MAX);
            } else {
                let expected: u64 = true_aligned as u64;
                prop_assert_eq!(result, expected);
                prop_assert!(result >= value);
                prop_assert_eq!(result % align, 0);
            }
        }
    }

    #[test]
    fn align_down_u32_invariants(value in any::<u32>(), align in 1u32..=u32::MAX) {
        let result: u32 = align_down_u32(value, align);
        prop_assert!(result <= value);
        prop_assert_eq!(result % align, 0);
        prop_assert!(value - result < align);
    }

    #[test]
    fn align_down_u64_invariants(value in any::<u64>(), align in 1u64..=u64::MAX) {
        let result: u64 = align_down_u64(value, align);
        prop_assert!(result <= value);
        prop_assert_eq!(result % align, 0);
        prop_assert!(value - result < align);
    }

    #[test]
    fn align_up_usize_matches_align_up_u64_for_small_values(
        value in 0u64..10_000_000,
        align in 1u64..4096,
    ) {
        let usize_result: usize = align_up_usize(value as usize, align as usize);
        let u64_result: u64 = align_up_u64(value, align);
        prop_assert_eq!(usize_result as u64, u64_result);
    }
}
