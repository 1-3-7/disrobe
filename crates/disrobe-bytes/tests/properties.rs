#![allow(clippy::unwrap_used)]
use disrobe_bytes::{
    AddressError, ByteReadError, ByteReader, CStrOptions, CStrRun, CStrSpan, FileOffset, Rva,
    SectionMap, SectionSpan, Size, Va, align_down_u32, align_down_u64, align_up_u32, align_up_u64,
    align_up_usize, cstr_runs, read_cstr_at, read_cstr_span_at, read_u32_be_at,
    read_u32_be_at_zero_pad_tail, read_u32_le_at, read_u32_le_at_or, read_u32_le_at_zero_pad_tail,
    read_u64_le_at, read_u64_le_at_or, read_u64_le_at_zero_pad_tail,
};
use proptest::prelude::*;

fn reference_ascii_split(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == 0 {
            if i > start {
                let chunk: &[u8] = &bytes[start..i];
                if chunk
                    .iter()
                    .all(|c: &u8| c.is_ascii_graphic() || *c == b' ')
                {
                    out.push(String::from_utf8_lossy(chunk).into_owned());
                }
            }
            start = i + 1;
        }
    }
    out
}

fn reference_utf8_split(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == 0 {
            if i > start {
                let chunk: &[u8] = &bytes[start..i];
                if let Ok(s) = std::str::from_utf8(chunk) {
                    out.push(s.to_owned());
                }
            }
            start = i + 1;
        }
    }
    out
}

fn reference_default_on_absent_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let Some(end): Option<usize> = offset.checked_add(4) else {
        return 0;
    };
    let Some(field): Option<&[u8]> = bytes.get(offset..end) else {
        return 0;
    };
    let mut raw: [u8; 4] = [0u8; 4];
    raw.copy_from_slice(field);
    u32::from_le_bytes(raw)
}

fn reference_zero_filled_tail_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut raw: [u8; 8] = [0u8; 8];
    let Some(tail): Option<&[u8]> = bytes.get(offset..) else {
        return 0;
    };
    let taken: usize = tail.len().min(8);
    raw[..taken].copy_from_slice(&tail[..taken]);
    u64::from_le_bytes(raw)
}

fn nul_heavy_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(prop_oneof![Just(0u8), any::<u8>(), 0x20u8..0x7Fu8], 0..max)
}

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

    #[test]
    fn uleb128_round_trips_arbitrary_u64(value in any::<u64>()) {
        let bytes: Vec<u8> = encode_uleb128_for_test(value);
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let decoded: u64 = reader.read_uleb128().unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(reader.position(), bytes.len());
    }

    #[test]
    fn sleb128_round_trips_arbitrary_i64(value in any::<i64>()) {
        let bytes: Vec<u8> = encode_sleb128_for_test(value);
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let decoded: i64 = reader.read_sleb128().unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(reader.position(), bytes.len());
    }

    #[test]
    fn va_addition_never_wraps(base in any::<u64>(), delta in any::<u64>()) {
        let result: Option<Va> = Va::new(base).checked_add(Size::new(delta));
        let wide: u128 = u128::from(base) + u128::from(delta);
        if wide > u128::from(u64::MAX) {
            prop_assert_eq!(result, None);
        } else {
            prop_assert_eq!(result, Some(Va::new(base + delta)));
        }
    }

    #[test]
    fn file_offset_subtraction_never_wraps(base in any::<u64>(), delta in any::<u64>()) {
        let result: Option<FileOffset> = FileOffset::new(base).checked_sub(Size::new(delta));
        if delta > base {
            prop_assert_eq!(result, None);
        } else {
            prop_assert_eq!(result, Some(FileOffset::new(base - delta)));
        }
    }

    #[test]
    fn rva_addition_never_wraps(base in any::<u32>(), delta in any::<u64>()) {
        let result: Option<Rva> = Rva::new(base).checked_add(Size::new(delta));
        let wide: u64 = u64::from(base) + delta;
        if wide > u64::from(u32::MAX) {
            prop_assert_eq!(result, None);
        } else {
            prop_assert_eq!(result, Some(Rva::new(base + (delta as u32))));
        }
    }

    #[test]
    fn va_to_rva_round_trips_within_the_thirty_two_bit_window(
        image_base in any::<u64>(),
        delta in any::<u32>(),
    ) {
        let base: Va = Va::new(image_base);
        let Some(address): Option<Va> = base.checked_add(Rva::new(delta).to_size()) else {
            return Ok(());
        };
        let recovered: Rva = address.to_rva(base).unwrap();
        prop_assert_eq!(recovered, Rva::new(delta));
        prop_assert_eq!(recovered.to_va(base).unwrap(), address);
    }

    #[test]
    fn va_to_rva_below_the_base_always_fails(image_base in 1u64..=u64::MAX, below in any::<u64>()) {
        let base: Va = Va::new(image_base);
        let address: Va = Va::new(below % image_base);
        prop_assert_eq!(
            address.to_rva(base),
            Err(AddressError::BelowImageBase { address, image_base: base })
        );
    }

    #[test]
    fn checked_align_up_is_aligned_or_rejected(value in any::<u64>(), align in any::<u64>()) {
        let Some(aligned): Option<Size> = Size::new(value).checked_align_up(Size::new(align)) else {
            let wide: u128 = if align == 0 {
                u128::from(value)
            } else {
                u128::from(value).div_ceil(u128::from(align)) * u128::from(align)
            };
            prop_assert!(wide > u128::from(u64::MAX));
            return Ok(());
        };
        prop_assert!(aligned.get() >= value);
        if align != 0 {
            prop_assert_eq!(aligned.get() % align, 0);
            prop_assert!(aligned.get() - value < align);
        }
    }

    #[test]
    fn a_checked_range_never_escapes_the_file(
        start in any::<u64>(),
        len in any::<u64>(),
        file_len in 0u64..4096,
    ) {
        let result: Result<std::ops::Range<usize>, AddressError> =
            FileOffset::new(start).checked_range(Size::new(len), Size::new(file_len));
        if let Ok(range) = result {
            prop_assert_eq!(range.start as u64, start);
            prop_assert_eq!((range.end - range.start) as u64, len);
            prop_assert!(range.end as u64 <= file_len);
        } else {
            let wide: u128 = u128::from(start) + u128::from(len);
            prop_assert!(wide > u128::from(file_len));
        }
    }

    #[test]
    fn section_translation_stays_inside_the_raw_bytes(
        section_rva in any::<u32>(),
        virtual_size in any::<u32>(),
        file_offset in any::<u64>(),
        raw_size in any::<u32>(),
        probe in any::<u32>(),
    ) {
        let span: SectionSpan = SectionSpan::new(
            Rva::new(section_rva),
            Size::new(u64::from(virtual_size)),
            FileOffset::new(file_offset),
            Size::new(u64::from(raw_size)),
        );
        let map: SectionMap = std::iter::once(span).collect();
        let rva: Rva = Rva::new(probe);
        if let Ok(offset) = map.file_offset_for(rva) {
            let delta: Size = rva.distance_from(span.rva).unwrap();
            prop_assert!(delta.get() < u64::from(raw_size));
            prop_assert_eq!(offset, FileOffset::new(file_offset + delta.get()));
            prop_assert_eq!(map.rva_for(offset).unwrap(), rva);
        } else {
            let contained: bool = span.contains(rva);
            let has_bytes: bool = rva
                .distance_from(span.rva)
                .is_some_and(|delta: Size| delta.get() < u64::from(raw_size));
            let overflows: bool = file_offset.checked_add(u64::from(probe)).is_none();
            prop_assert!(!contained || !has_bytes || overflows);
        }
    }

    #[test]
    fn read_cstr_at_never_panics_and_never_escapes_its_window(
        bytes in nul_heavy_bytes(96),
        offset in 0usize..128,
        max_len in 0usize..160,
        require_terminator in any::<bool>(),
    ) {
        let options: CStrOptions = CStrOptions::new(max_len, require_terminator);
        let Ok(value): Result<&[u8], ByteReadError> = read_cstr_at(&bytes, offset, options) else {
            prop_assert!(
                offset > bytes.len()
                    || require_terminator
            );
            return Ok(());
        };
        prop_assert!(value.len() <= max_len);
        prop_assert!(offset + value.len() <= bytes.len());
        prop_assert!(!value.contains(&0u8));
        prop_assert_eq!(value, &bytes[offset..offset + value.len()]);

        let span: CStrSpan = read_cstr_span_at(&bytes, offset, options).unwrap();
        prop_assert_eq!(span.offset, offset);
        prop_assert_eq!(span.len, value.len());
        prop_assert!(span.end() <= bytes.len());
        if span.terminated {
            prop_assert_eq!(bytes[offset + span.len], 0u8);
        }
    }

    #[test]
    fn read_cstr_at_never_panics_at_extreme_offsets(
        bytes in nul_heavy_bytes(32),
        max_len in prop_oneof![Just(0usize), Just(1usize), Just(usize::MAX), Just(usize::MAX - 1)],
        require_terminator in any::<bool>(),
    ) {
        let options: CStrOptions = CStrOptions::new(max_len, require_terminator);
        for offset in [0usize, bytes.len(), bytes.len() + 1, usize::MAX / 2, usize::MAX] {
            let result: Result<&[u8], ByteReadError> = read_cstr_at(&bytes, offset, options);
            if offset > bytes.len() {
                prop_assert!(result.is_err());
            }
        }
    }

    #[test]
    fn the_run_iterator_reproduces_both_reference_splitters(bytes in nul_heavy_bytes(128)) {
        let ascii: Vec<String> = cstr_runs(&bytes, CStrOptions::UNBOUNDED)
            .filter(|run: &CStrRun<'_>| run.terminated && !run.bytes.is_empty())
            .filter(|run: &CStrRun<'_>| {
                run.bytes
                    .iter()
                    .all(|c: &u8| c.is_ascii_graphic() || *c == b' ')
            })
            .map(|run: CStrRun<'_>| String::from_utf8_lossy(run.bytes).into_owned())
            .collect();
        prop_assert_eq!(ascii, reference_ascii_split(&bytes));

        let utf8: Vec<String> = cstr_runs(&bytes, CStrOptions::UNBOUNDED)
            .filter(|run: &CStrRun<'_>| run.terminated && !run.bytes.is_empty())
            .filter_map(|run: CStrRun<'_>| std::str::from_utf8(run.bytes).ok().map(str::to_owned))
            .collect();
        prop_assert_eq!(utf8, reference_utf8_split(&bytes));
    }

    #[test]
    fn the_run_iterator_covers_the_input_without_overlapping(bytes in nul_heavy_bytes(96)) {
        let mut expected_offset: usize = 0;
        for run in cstr_runs(&bytes, CStrOptions::LENIENT) {
            prop_assert_eq!(run.offset, expected_offset);
            prop_assert!(!run.bytes.contains(&0u8));
            expected_offset = run.offset + run.bytes.len() + usize::from(run.terminated);
            prop_assert!(expected_offset <= bytes.len());
        }
        prop_assert_eq!(expected_offset, bytes.len());
    }

    #[test]
    fn the_reader_companion_matches_the_slice_form(
        bytes in nul_heavy_bytes(64),
        offset in 0usize..64,
    ) {
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        if reader.seek(offset.min(bytes.len())).is_err() {
            return Ok(());
        }
        let start: usize = reader.position();
        let direct: Result<&[u8], ByteReadError> =
            read_cstr_at(&bytes, start, CStrOptions::LENIENT);
        let through_reader: Result<&[u8], ByteReadError> = reader.read_cstr(CStrOptions::LENIENT);
        prop_assert_eq!(direct.is_ok(), through_reader.is_ok());
        if let (Ok(left), Ok(right)) = (direct, through_reader) {
            prop_assert_eq!(left, right);
            let span: CStrSpan = read_cstr_span_at(&bytes, start, CStrOptions::LENIENT).unwrap();
            prop_assert_eq!(reader.position(), span.end());
        }
    }

    #[test]
    fn the_default_form_never_panics_and_matches_the_result_form(
        bytes in proptest::collection::vec(any::<u8>(), 0..48),
        offset in 0usize..64,
        default in any::<u32>(),
    ) {
        let value: u32 = read_u32_le_at_or(&bytes, offset, default);
        if let Ok(expected) = read_u32_le_at(&bytes, offset) {
            prop_assert_eq!(value, expected);
        } else {
            prop_assert_eq!(value, default);
        }
        prop_assert_eq!(
            read_u32_le_at_or(&bytes, offset, 0),
            reference_default_on_absent_u32_le(&bytes, offset)
        );
    }

    #[test]
    fn the_default_form_never_panics_at_extreme_offsets(
        bytes in proptest::collection::vec(any::<u8>(), 0..16),
        default in any::<u64>(),
    ) {
        for offset in [0usize, bytes.len(), bytes.len() + 1, usize::MAX - 1, usize::MAX] {
            let value: u64 = read_u64_le_at_or(&bytes, offset, default);
            if offset >= bytes.len() {
                prop_assert_eq!(value, default);
            }
        }
    }

    #[test]
    fn the_zero_pad_form_never_panics_and_matches_a_zero_filled_array(
        bytes in proptest::collection::vec(any::<u8>(), 0..48),
        offset in 0usize..64,
    ) {
        prop_assert_eq!(
            read_u64_le_at_zero_pad_tail(&bytes, offset),
            reference_zero_filled_tail_u64_le(&bytes, offset)
        );
        if let Ok(expected) = read_u64_le_at(&bytes, offset) {
            prop_assert_eq!(read_u64_le_at_zero_pad_tail(&bytes, offset), expected);
        }
        if let Ok(expected) = read_u32_be_at(&bytes, offset) {
            prop_assert_eq!(read_u32_be_at_zero_pad_tail(&bytes, offset), expected);
        }
    }

    #[test]
    fn the_zero_pad_form_never_panics_at_extreme_offsets(
        bytes in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        for offset in [0usize, bytes.len(), bytes.len() + 1, usize::MAX - 1, usize::MAX] {
            let little: u64 = read_u64_le_at_zero_pad_tail(&bytes, offset);
            let big: u32 = read_u32_be_at_zero_pad_tail(&bytes, offset);
            if offset > bytes.len() {
                prop_assert_eq!(little, 0);
                prop_assert_eq!(big, 0);
            }
        }
    }

    #[test]
    fn the_two_byte_orders_pad_opposite_ends_of_the_value(
        bytes in proptest::collection::vec(any::<u8>(), 1..4),
    ) {
        let little: u32 = read_u32_le_at_zero_pad_tail(&bytes, 0);
        let big: u32 = read_u32_be_at_zero_pad_tail(&bytes, 0);
        let present: u32 = u32::try_from(bytes.len()).unwrap();
        prop_assert_eq!(little >> (present * 8), 0);
        prop_assert_eq!(big << (present * 8), 0);
    }

    #[test]
    fn uleb128_and_sleb128_never_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..24),
    ) {
        let mut uleb_reader: ByteReader<'_> = ByteReader::new(&bytes);
        let before: usize = uleb_reader.position();
        if uleb_reader.read_uleb128().is_err() {
            prop_assert_eq!(uleb_reader.position(), before);
        }

        let mut sleb_reader: ByteReader<'_> = ByteReader::new(&bytes);
        let before: usize = sleb_reader.position();
        if sleb_reader.read_sleb128().is_err() {
            prop_assert_eq!(sleb_reader.position(), before);
        }
    }
}
