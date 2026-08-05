use std::error::Error;
use std::fmt;
use std::ops::Range;

use crate::align::{align_down_u64, align_up_u64};
use crate::capacity::bounded_element_capacity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    RvaNotMapped { rva: Rva },
    RvaHasNoFileBytes { rva: Rva },
    RvaBeyondRawData { rva: Rva },
    FileOffsetNotMapped { offset: FileOffset },
    BelowImageBase { address: Va, image_base: Va },
    DeltaExceedsRvaWidth { delta: u64 },
    ArithmeticOverflow,
    PastEnd { start: u64, len: u64, end: u64 },
    ExceedsHostWidth { value: u64 },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::RvaNotMapped { rva } => {
                write!(f, "relative address {rva} lands in no mapped section")
            }
            Self::RvaHasNoFileBytes { rva } => write!(
                f,
                "relative address {rva} lands in a section with no raw file bytes"
            ),
            Self::RvaBeyondRawData { rva } => write!(
                f,
                "relative address {rva} lands past the raw bytes of its section"
            ),
            Self::FileOffsetNotMapped { offset } => {
                write!(f, "file offset {offset} lands in no mapped section")
            }
            Self::BelowImageBase {
                address,
                image_base,
            } => write!(f, "address {address} is below the image base {image_base}"),
            Self::DeltaExceedsRvaWidth { delta } => {
                write!(
                    f,
                    "delta 0x{delta:x} does not fit a 32-bit relative address"
                )
            }
            Self::ArithmeticOverflow => write!(f, "address arithmetic overflowed"),
            Self::PastEnd { start, len, end } => write!(
                f,
                "span at 0x{start:x} of 0x{len:x} byte(s) runs past the end 0x{end:x}"
            ),
            Self::ExceedsHostWidth { value } => {
                write!(f, "value 0x{value:x} does not fit a host-width index")
            }
        }
    }
}

impl Error for AddressError {}

const fn widen_u32(value: u32) -> u64 {
    value as u64
}

const fn widen_u64(value: u64) -> u64 {
    value
}

macro_rules! address_newtype {
    ($name:ident, $inner:ty, $widen:ident) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name($inner);

        impl $name {
            pub const ZERO: Self = Self(0);
            pub const MAX: Self = Self(<$inner>::MAX);

            #[inline]
            #[must_use]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            #[inline]
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }

            #[inline]
            #[must_use]
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }

            #[inline]
            #[must_use]
            pub const fn widened(self) -> u64 {
                $widen(self.0)
            }

            #[inline]
            pub fn to_usize(self) -> Result<usize, AddressError> {
                usize::try_from(self.0).map_err(|_| AddressError::ExceedsHostWidth {
                    value: self.widened(),
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{:x}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "(0x{:x})"), self.0)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl From<$inner> for $name {
            #[inline]
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            #[inline]
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl TryFrom<$name> for usize {
            type Error = AddressError;

            fn try_from(value: $name) -> Result<Self, AddressError> {
                value.to_usize()
            }
        }
    };
}

address_newtype!(Va, u64, widen_u64);
address_newtype!(Rva, u32, widen_u32);
address_newtype!(FileOffset, u64, widen_u64);
address_newtype!(Size, u64, widen_u64);

macro_rules! wide_span_arithmetic {
    ($name:ident) => {
        impl $name {
            #[inline]
            #[must_use]
            pub const fn checked_add(self, delta: Size) -> Option<Self> {
                match self.0.checked_add(delta.0) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            #[inline]
            #[must_use]
            pub const fn checked_sub(self, delta: Size) -> Option<Self> {
                match self.0.checked_sub(delta.0) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            #[inline]
            #[must_use]
            pub const fn distance_from(self, origin: Self) -> Option<Size> {
                match self.0.checked_sub(origin.0) {
                    Some(value) => Some(Size(value)),
                    None => None,
                }
            }

            #[inline]
            #[must_use]
            pub const fn checked_align_up(self, align: Size) -> Option<Self> {
                let aligned: u64 = align_up_u64(self.0, align.0);
                if aligned < self.0 {
                    return None;
                }
                if align.0 != 0 && aligned % align.0 != 0 {
                    return None;
                }
                Some(Self(aligned))
            }

            #[inline]
            #[must_use]
            pub const fn align_down(self, align: Size) -> Self {
                Self(align_down_u64(self.0, align.0))
            }
        }
    };
}

wide_span_arithmetic!(Va);
wide_span_arithmetic!(FileOffset);
wide_span_arithmetic!(Size);

impl Va {
    pub fn to_rva(self, image_base: Self) -> Result<Rva, AddressError> {
        let delta: Size = self
            .distance_from(image_base)
            .ok_or(AddressError::BelowImageBase {
                address: self,
                image_base,
            })?;
        let narrowed: u32 = u32::try_from(delta.get())
            .map_err(|_| AddressError::DeltaExceedsRvaWidth { delta: delta.get() })?;
        Ok(Rva(narrowed))
    }
}

impl Rva {
    #[inline]
    #[must_use]
    pub fn checked_add(self, delta: Size) -> Option<Self> {
        let narrowed: u32 = u32::try_from(delta.get()).ok()?;
        self.0.checked_add(narrowed).map(Self)
    }

    #[inline]
    #[must_use]
    pub fn checked_sub(self, delta: Size) -> Option<Self> {
        let narrowed: u32 = u32::try_from(delta.get()).ok()?;
        self.0.checked_sub(narrowed).map(Self)
    }

    #[inline]
    #[must_use]
    pub const fn distance_from(self, origin: Self) -> Option<Size> {
        match self.0.checked_sub(origin.0) {
            Some(value) => Some(Size(widen_u32(value))),
            None => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn to_size(self) -> Size {
        Size(widen_u32(self.0))
    }

    pub fn to_va(self, image_base: Va) -> Result<Va, AddressError> {
        image_base
            .checked_add(self.to_size())
            .ok_or(AddressError::ArithmeticOverflow)
    }

    pub fn to_file_offset(self, sections: &SectionMap) -> Result<FileOffset, AddressError> {
        sections.file_offset_for(self)
    }
}

impl TryFrom<u64> for Rva {
    type Error = AddressError;

    fn try_from(value: u64) -> Result<Self, AddressError> {
        u32::try_from(value)
            .map(Self)
            .map_err(|_| AddressError::DeltaExceedsRvaWidth { delta: value })
    }
}

impl TryFrom<usize> for Size {
    type Error = AddressError;

    fn try_from(value: usize) -> Result<Self, AddressError> {
        u64::try_from(value)
            .map(Self)
            .map_err(|_| AddressError::ArithmeticOverflow)
    }
}

impl FileOffset {
    #[inline]
    #[must_use]
    pub const fn is_within(self, file_len: Size) -> bool {
        self.0 <= file_len.0
    }

    pub fn checked_range(self, len: Size, file_len: Size) -> Result<Range<usize>, AddressError> {
        let end: Self = self.checked_add(len).ok_or(AddressError::PastEnd {
            start: self.0,
            len: len.0,
            end: file_len.0,
        })?;
        if end.0 > file_len.0 {
            return Err(AddressError::PastEnd {
                start: self.0,
                len: len.0,
                end: file_len.0,
            });
        }
        let start_index: usize = self.to_usize()?;
        let end_index: usize = end.to_usize()?;
        Ok(start_index..end_index)
    }

    pub fn to_rva(self, sections: &SectionMap) -> Result<Rva, AddressError> {
        sections.rva_for(self)
    }
}

impl Size {
    #[inline]
    #[must_use]
    pub const fn checked_mul(self, factor: u64) -> Option<Self> {
        match self.0.checked_mul(factor) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn bounded_element_capacity(self, elem_bytes: usize, remaining: usize) -> usize {
        bounded_element_capacity(self.0, elem_bytes, remaining)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSpan {
    pub rva: Rva,
    pub virtual_size: Size,
    pub file_offset: FileOffset,
    pub raw_size: Size,
}

impl SectionSpan {
    #[inline]
    #[must_use]
    pub const fn new(
        rva: Rva,
        virtual_size: Size,
        file_offset: FileOffset,
        raw_size: Size,
    ) -> Self {
        Self {
            rva,
            virtual_size,
            file_offset,
            raw_size,
        }
    }

    #[must_use]
    pub const fn contains(&self, rva: Rva) -> bool {
        match rva.distance_from(self.rva) {
            Some(delta) => delta.get() < self.virtual_size.get(),
            None => false,
        }
    }

    #[must_use]
    pub const fn contains_file_offset(&self, offset: FileOffset) -> bool {
        match offset.distance_from(self.file_offset) {
            Some(delta) => delta.get() < self.raw_size.get(),
            None => false,
        }
    }

    pub fn translate(&self, rva: Rva) -> Result<FileOffset, AddressError> {
        if !self.contains(rva) {
            return Err(AddressError::RvaNotMapped { rva });
        }
        if self.raw_size.is_zero() {
            return Err(AddressError::RvaHasNoFileBytes { rva });
        }
        let delta: Size = rva
            .distance_from(self.rva)
            .ok_or(AddressError::RvaNotMapped { rva })?;
        if delta.get() >= self.raw_size.get() {
            return Err(AddressError::RvaBeyondRawData { rva });
        }
        self.file_offset
            .checked_add(delta)
            .ok_or(AddressError::ArithmeticOverflow)
    }

    pub fn translate_back(&self, offset: FileOffset) -> Result<Rva, AddressError> {
        if !self.contains_file_offset(offset) {
            return Err(AddressError::FileOffsetNotMapped { offset });
        }
        let delta: Size = offset
            .distance_from(self.file_offset)
            .ok_or(AddressError::FileOffsetNotMapped { offset })?;
        self.rva
            .checked_add(delta)
            .ok_or(AddressError::ArithmeticOverflow)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionMap {
    spans: Vec<SectionSpan>,
}

impl SectionMap {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { spans: Vec::new() }
    }

    #[must_use]
    pub fn with_untrusted_capacity(declared: Size, header_bytes: usize, remaining: usize) -> Self {
        Self {
            spans: Vec::with_capacity(declared.bounded_element_capacity(header_bytes, remaining)),
        }
    }

    pub fn push(&mut self, span: SectionSpan) {
        self.spans.push(span);
    }

    #[must_use]
    pub fn spans(&self) -> &[SectionSpan] {
        &self.spans
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.spans.len()
    }

    #[must_use]
    pub fn containing(&self, rva: Rva) -> Option<&SectionSpan> {
        self.spans.iter().find(|span| span.contains(rva))
    }

    pub fn file_offset_for(&self, rva: Rva) -> Result<FileOffset, AddressError> {
        let mut first_failure: Option<AddressError> = None;
        for span in &self.spans {
            if !span.contains(rva) {
                continue;
            }
            match span.translate(rva) {
                Ok(offset) => return Ok(offset),
                Err(error) => {
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
        Err(first_failure.unwrap_or(AddressError::RvaNotMapped { rva }))
    }

    pub fn rva_for(&self, offset: FileOffset) -> Result<Rva, AddressError> {
        let mut first_failure: Option<AddressError> = None;
        for span in &self.spans {
            if !span.contains_file_offset(offset) {
                continue;
            }
            match span.translate_back(offset) {
                Ok(rva) => return Ok(rva),
                Err(error) => {
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
        Err(first_failure.unwrap_or(AddressError::FileOffsetNotMapped { offset }))
    }
}

impl FromIterator<SectionSpan> for SectionMap {
    fn from_iter<I: IntoIterator<Item = SectionSpan>>(iter: I) -> Self {
        Self {
            spans: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressError, FileOffset, Rva, SectionMap, SectionSpan, Size, Va};

    fn text_section() -> SectionSpan {
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
}
