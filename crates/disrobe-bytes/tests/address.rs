#![allow(clippy::unwrap_used)]
use disrobe_bytes::{AddressError, FileOffset, Rva, SectionMap, SectionSpan, Size, Va};

const fn text_section() -> SectionSpan {
    SectionSpan::new(
        Rva::new(0x1000),
        Size::new(0x2000),
        FileOffset::new(0x400),
        Size::new(0x1000),
    )
}

#[test]
fn display_and_debug_are_hex() {
    assert_eq!(Va::new(0xdead_beef).to_string(), "0xdeadbeef");
    assert_eq!(format!("{:?}", Rva::new(0x1000)), "Rva(0x1000)");
    assert_eq!(format!("{:X}", FileOffset::new(0xabc)), "ABC");
}

#[test]
fn rva_in_no_section_is_a_typed_failure() {
    let map: SectionMap = std::iter::once(text_section()).collect();
    let rva: Rva = Rva::new(0x9000);
    assert_eq!(
        map.file_offset_for(rva),
        Err(AddressError::RvaNotMapped { rva })
    );
    assert!(map.containing(rva).is_none());
}

#[test]
fn zero_raw_size_section_reports_no_file_bytes() {
    let bss: SectionSpan = SectionSpan::new(
        Rva::new(0x4000),
        Size::new(0x1000),
        FileOffset::new(0),
        Size::ZERO,
    );
    let map: SectionMap = std::iter::once(bss).collect();
    let rva: Rva = Rva::new(0x4010);
    assert_eq!(
        map.file_offset_for(rva),
        Err(AddressError::RvaHasNoFileBytes { rva })
    );
}

#[test]
fn virtual_size_beyond_raw_size_reports_beyond_raw_data() {
    let map: SectionMap = std::iter::once(text_section()).collect();
    let rva: Rva = Rva::new(0x2800);
    assert_eq!(
        map.file_offset_for(rva),
        Err(AddressError::RvaBeyondRawData { rva })
    );
}

#[test]
fn overlapping_sections_resolve_deterministically() {
    let first: SectionSpan = text_section();
    let second: SectionSpan = SectionSpan::new(
        Rva::new(0x1000),
        Size::new(0x2000),
        FileOffset::new(0x9000),
        Size::new(0x1000),
    );
    let forward: SectionMap = [first, second].into_iter().collect();
    let reverse: SectionMap = [second, first].into_iter().collect();
    assert_eq!(
        forward.file_offset_for(Rva::new(0x1010)),
        Ok(FileOffset::new(0x410))
    );
    assert_eq!(
        reverse.file_offset_for(Rva::new(0x1010)),
        Ok(FileOffset::new(0x9010))
    );
}

#[test]
fn an_overlapping_section_without_file_bytes_defers_to_the_next() {
    let uninitialized: SectionSpan = SectionSpan::new(
        Rva::new(0x1000),
        Size::new(0x2000),
        FileOffset::new(0),
        Size::ZERO,
    );
    let map: SectionMap = [uninitialized, text_section()].into_iter().collect();
    assert_eq!(
        map.file_offset_for(Rva::new(0x1010)),
        Ok(FileOffset::new(0x410))
    );
}

#[test]
fn image_base_plus_rva_overflow_is_a_typed_failure() {
    let base: Va = Va::new(u64::MAX - 4);
    assert_eq!(
        Rva::new(16).to_va(base),
        Err(AddressError::ArithmeticOverflow)
    );
    assert_eq!(Rva::new(4).to_va(base), Ok(Va::MAX));
}

#[test]
fn va_to_rva_rejects_below_base_and_wide_deltas() {
    let base: Va = Va::new(0x1_4000_0000);
    assert_eq!(Va::new(0x1_4000_1000).to_rva(base), Ok(Rva::new(0x1000)));
    let below: Va = Va::new(0x1_3FFF_0000);
    assert_eq!(
        below.to_rva(base),
        Err(AddressError::BelowImageBase {
            address: below,
            image_base: base,
        })
    );
    let wide: Va = Va::new(0x2_4000_0000);
    assert_eq!(
        wide.to_rva(base),
        Err(AddressError::DeltaExceedsRvaWidth {
            delta: 0x1_0000_0000
        })
    );
}

#[test]
fn file_offset_span_past_the_end_is_a_typed_failure() {
    let file_len: Size = Size::new(0x1000);
    assert_eq!(
        FileOffset::new(0xFF0).checked_range(Size::new(0x10), file_len),
        Ok(0xFF0..0x1000)
    );
    assert_eq!(
        FileOffset::new(0xFF0).checked_range(Size::new(0x11), file_len),
        Err(AddressError::PastEnd {
            start: 0xFF0,
            len: 0x11,
            end: 0x1000,
        })
    );
    assert_eq!(
        FileOffset::new(8).checked_range(Size::MAX, file_len),
        Err(AddressError::PastEnd {
            start: 8,
            len: u64::MAX,
            end: 0x1000,
        })
    );
    assert!(FileOffset::new(0x1000).is_within(file_len));
    assert!(!FileOffset::new(0x1001).is_within(file_len));
}

#[test]
fn zero_length_span_at_the_end_is_accepted() {
    let file_len: Size = Size::new(4);
    assert_eq!(
        FileOffset::new(4).checked_range(Size::ZERO, file_len),
        Ok(4..4)
    );
}

#[test]
fn rva_to_host_index_is_exact_for_every_thirty_two_bit_value() {
    let widest: Rva = Rva::MAX;
    if usize::BITS >= 32 {
        assert_eq!(widest.to_usize(), Ok(0xFFFF_FFFF_usize));
    } else {
        assert_eq!(
            widest.to_usize(),
            Err(AddressError::ExceedsHostWidth { value: 0xFFFF_FFFF })
        );
    }
}

#[test]
fn a_wide_size_only_narrows_when_the_host_is_wide_enough() {
    let widest: Size = Size::MAX;
    if usize::BITS >= 64 {
        assert_eq!(widest.to_usize(), Ok(usize::MAX));
    } else {
        assert_eq!(
            widest.to_usize(),
            Err(AddressError::ExceedsHostWidth { value: u64::MAX })
        );
    }
}

#[test]
fn checked_arithmetic_never_wraps() {
    assert_eq!(Va::MAX.checked_add(Size::new(1)), None);
    assert_eq!(Va::ZERO.checked_sub(Size::new(1)), None);
    assert_eq!(Rva::MAX.checked_add(Size::new(1)), None);
    assert_eq!(Rva::new(1).checked_sub(Size::new(2)), None);
    assert_eq!(
        Rva::new(1).checked_add(Size::new(u64::from(u32::MAX) + 1)),
        None
    );
    assert_eq!(FileOffset::MAX.checked_add(Size::new(1)), None);
    assert_eq!(Size::MAX.checked_mul(2), None);
    assert_eq!(Size::new(3).checked_mul(4), Some(Size::new(12)));
}

#[test]
fn distance_rejects_a_negative_delta() {
    assert_eq!(
        Va::new(0x2000).distance_from(Va::new(0x1000)),
        Some(Size::new(0x1000))
    );
    assert_eq!(Va::new(0x1000).distance_from(Va::new(0x2000)), None);
    assert_eq!(Rva::new(0x10).distance_from(Rva::new(0x20)), None);
}

#[test]
fn alignment_rejects_overflow_instead_of_wrapping() {
    assert_eq!(
        Va::new(0x1001).checked_align_up(Size::new(0x1000)),
        Some(Va::new(0x2000))
    );
    assert_eq!(Va::MAX.checked_align_up(Size::new(0x1000)), None);
    assert_eq!(Va::new(42).checked_align_up(Size::ZERO), Some(Va::new(42)));
    assert_eq!(
        Va::new(0x1FFF).align_down(Size::new(0x1000)),
        Va::new(0x1000)
    );
}

#[test]
fn an_untrusted_size_cannot_force_a_preallocation() {
    assert_eq!(Size::MAX.bounded_element_capacity(40, 400), 11);
    let map: SectionMap = SectionMap::with_untrusted_capacity(Size::MAX, 40, 400);
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn file_offset_translates_back_to_a_relative_address() {
    let map: SectionMap = std::iter::once(text_section()).collect();
    assert_eq!(map.rva_for(FileOffset::new(0x410)), Ok(Rva::new(0x1010)));
    let stray: FileOffset = FileOffset::new(0x8000);
    assert_eq!(
        map.rva_for(stray),
        Err(AddressError::FileOffsetNotMapped { offset: stray })
    );
}

#[test]
fn a_virtual_address_resolves_through_the_image_base() {
    let map: SectionMap = std::iter::once(text_section()).collect();
    let image_base: Va = Va::new(0x1_4000_0000);
    assert_eq!(
        map.file_offset_for_va(Va::new(0x1_4000_1010), image_base),
        Ok(FileOffset::new(0x410))
    );
    assert_eq!(
        map.va_for_file_offset(FileOffset::new(0x410), image_base),
        Ok(Va::new(0x1_4000_1010))
    );
    let below: Va = Va::new(0x1_3FFF_0000);
    assert_eq!(
        map.file_offset_for_va(below, image_base),
        Err(AddressError::BelowImageBase {
            address: below,
            image_base,
        })
    );
    assert_eq!(
        map.va_for_file_offset(FileOffset::new(0x410), Va::MAX),
        Err(AddressError::ArithmeticOverflow)
    );
}

#[test]
fn lossless_conversions_round_trip() {
    assert_eq!(u32::from(Rva::from(0x1234_u32)), 0x1234);
    assert_eq!(u64::from(Va::from(0x1234_u64)), 0x1234);
    assert_eq!(
        Rva::try_from(0x1_0000_0000_u64),
        Err(AddressError::DeltaExceedsRvaWidth {
            delta: 0x1_0000_0000
        })
    );
    assert_eq!(Rva::try_from(0xFFFF_FFFF_u64), Ok(Rva::MAX));
    assert_eq!(Size::try_from(64_usize), Ok(Size::new(64)));
}

#[test]
fn errors_render_without_panicking() {
    let rendered: Vec<String> = vec![
        AddressError::RvaNotMapped { rva: Rva::new(1) }.to_string(),
        AddressError::RvaHasNoFileBytes { rva: Rva::new(1) }.to_string(),
        AddressError::RvaBeyondRawData { rva: Rva::new(1) }.to_string(),
        AddressError::FileOffsetNotMapped {
            offset: FileOffset::new(1),
        }
        .to_string(),
        AddressError::BelowImageBase {
            address: Va::ZERO,
            image_base: Va::new(1),
        }
        .to_string(),
        AddressError::DeltaExceedsRvaWidth { delta: 1 }.to_string(),
        AddressError::ArithmeticOverflow.to_string(),
        AddressError::PastEnd {
            start: 0,
            len: 1,
            end: 0,
        }
        .to_string(),
        AddressError::ExceedsHostWidth { value: 1 }.to_string(),
    ];
    assert!(rendered.iter().all(|text| !text.is_empty()));
}
