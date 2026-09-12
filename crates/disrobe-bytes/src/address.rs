use std::error::Error;
use std::fmt;
use std::ops::Range;

use crate::align::{align_down_u64, align_up_u64};
use crate::capacity::bounded_element_capacity;
use crate::section_map::SectionMap;

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
