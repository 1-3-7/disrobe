use crate::address::{AddressError, FileOffset, Rva, Size, Va};

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

    pub fn file_offset_for_va(
        &self,
        address: Va,
        image_base: Va,
    ) -> Result<FileOffset, AddressError> {
        self.file_offset_for(address.to_rva(image_base)?)
    }

    pub fn va_for_file_offset(
        &self,
        offset: FileOffset,
        image_base: Va,
    ) -> Result<Va, AddressError> {
        self.rva_for(offset)?.to_va(image_base)
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
