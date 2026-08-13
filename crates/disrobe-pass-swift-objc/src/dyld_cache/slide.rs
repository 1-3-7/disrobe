use core::ops::Range;

use disrobe_bytes::{ByteReadError, read_u16_le_at, read_u32_le_at, read_u64_le_at};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const V1_PAGE_SIZE: u32 = 4096;
pub const MAX_SLIDE_PAGES: usize = 1 << 22;
pub const MAX_PAGE_EXTRAS: usize = 1 << 20;
pub const MAX_V1_ENTRY_BYTES: usize = 4096;

const PAGE_ATTR_EXTRA: u16 = 0x8000;
const PAGE_ATTR_NO_REBASE_V2: u16 = 0x4000;
const PAGE_ATTR_END: u16 = 0x8000;
const PAGE_INDEX_MASK_V2: u16 = 0x3FFF;
const PAGE_NO_REBASE_V3: u16 = 0xFFFF;
const PAGE_NO_REBASE_V4: u16 = 0xFFFF;
const PAGE_INDEX_MASK_V4: u16 = 0x7FFF;
const PAGE_USE_EXTRA_V4: u16 = 0x8000;
const PAGE_EXTRA_END_V4: u16 = 0x8000;
const PAGE_NO_REBASE_V5: u16 = 0xFFFF;

const V3_PLAIN_LOW_MASK: u64 = 0x0000_07FF_FFFF_FFFF;
const V3_PLAIN_HIGH8_MASK: u64 = 0x0007_F800_0000_0000;
const V3_PLAIN_HIGH8_SHIFT: u32 = 13;
const V3_AUTH_OFFSET_MASK: u64 = 0xFFFF_FFFF;
const V3_AUTH_DIVERSITY_SHIFT: u32 = 32;
const V3_AUTH_ADDR_DIV_SHIFT: u32 = 48;
const V3_AUTH_KEY_SHIFT: u32 = 49;
const V3_NEXT_SHIFT: u32 = 51;
const V3_NEXT_MASK: u64 = 0x7FF;
const V3_AUTHENTICATED_SHIFT: u32 = 63;

const V5_OFFSET_MASK: u64 = 0x3_FFFF_FFFF;
const V5_HIGH8_SHIFT: u32 = 34;
const V5_DIVERSITY_SHIFT: u32 = 34;
const V5_ADDR_DIV_SHIFT: u32 = 50;
const V5_KEY_IS_DATA_SHIFT: u32 = 51;
const V5_NEXT_SHIFT: u32 = 52;
const V5_NEXT_MASK: u64 = 0x7FF;
const V5_AUTH_SHIFT: u32 = 63;
const HIGH8_TARGET_SHIFT: u32 = 56;

const KEY_IA: u8 = 0;
const KEY_DA: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlideInfoVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
}

impl SlideInfoVersion {
    pub const fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            other => Err(Error::UnsupportedDyldSlideInfo(other)),
        }
    }

    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }

    #[must_use]
    pub const fn pointer_width(self) -> u8 {
        match self {
            Self::V1 | Self::V4 => 4,
            Self::V2 | Self::V3 | Self::V5 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerAuth {
    pub key: u8,
    pub diversity: u16,
    pub address_diversity: bool,
}

impl PointerAuth {
    #[must_use]
    pub const fn key_label(self) -> &'static str {
        match self.key {
            0 => "IA",
            1 => "IB",
            2 => "DA",
            _ => "DB",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlidPointer {
    pub vm_address: u64,
    pub unslid_value: u64,
    pub width: u8,
    pub auth: Option<PointerAuth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideSummary {
    pub version: SlideInfoVersion,
    pub page_size: u32,
    pub pages_walked: usize,
    pub pointers: usize,
    pub authenticated_pointers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideLocation {
    pub file_offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SlideTarget {
    pub vm_address: u64,
    pub file_offset: u64,
    pub size: u64,
}

pub fn version_of(cache: &[u8], location: SlideLocation) -> Result<SlideInfoVersion> {
    let blob: &[u8] = blob_of(cache, location)?;
    SlideInfoVersion::from_raw(u32_at(blob, 0, "slide-info version")?)
}

pub fn unapply_range(
    cache: &[u8],
    location: SlideLocation,
    target: SlideTarget,
    va_range: &Range<u64>,
    sink: &mut dyn FnMut(SlidPointer) -> Result<()>,
) -> Result<SlideSummary> {
    let blob: &[u8] = blob_of(cache, location)?;
    let version: SlideInfoVersion =
        SlideInfoVersion::from_raw(u32_at(blob, 0, "slide-info version")?)?;
    let mut walk: Walk<'_> = Walk {
        cache,
        blob,
        target,
        va_range,
        sink,
        summary: SlideSummary {
            version,
            page_size: 0,
            pages_walked: 0,
            pointers: 0,
            authenticated_pointers: 0,
        },
    };
    match version {
        SlideInfoVersion::V1 => walk.run_v1()?,
        SlideInfoVersion::V2 => walk.run_v2_or_v4(SlideInfoVersion::V2)?,
        SlideInfoVersion::V3 => walk.run_v3()?,
        SlideInfoVersion::V4 => walk.run_v2_or_v4(SlideInfoVersion::V4)?,
        SlideInfoVersion::V5 => walk.run_v5()?,
    }
    Ok(walk.summary)
}

struct Walk<'a> {
    cache: &'a [u8],
    blob: &'a [u8],
    target: SlideTarget,
    va_range: &'a Range<u64>,
    sink: &'a mut dyn FnMut(SlidPointer) -> Result<()>,
    summary: SlideSummary,
}

impl Walk<'_> {
    fn page_va(&self, page_index: usize, page_size: u32) -> Result<u64> {
        let delta: u64 = (page_index as u64)
            .checked_mul(u64::from(page_size))
            .ok_or_else(|| Error::BadDyldCache("slide-info page offset overflows".to_owned()))?;
        self.target
            .vm_address
            .checked_add(delta)
            .ok_or_else(|| Error::BadDyldCache("slide-info page address overflows".to_owned()))
    }

    fn page_intersects(&self, page_va: u64, page_size: u32) -> bool {
        let end: u64 = page_va.saturating_add(u64::from(page_size));
        page_va < self.va_range.end && end > self.va_range.start
    }

    fn read_pointer(&self, va: u64, width: u8) -> Result<u64> {
        let delta: u64 = va.checked_sub(self.target.vm_address).ok_or_else(|| {
            Error::BadDyldCache("slide-info pointer precedes its region".to_owned())
        })?;
        if delta.saturating_add(u64::from(width)) > self.target.size {
            return Err(Error::BadDyldCache(format!(
                "slide-info pointer at {va:#x} leaves its {}-byte region",
                self.target.size
            )));
        }
        let at: usize =
            usize::try_from(self.target.file_offset.checked_add(delta).ok_or_else(|| {
                Error::BadDyldCache("slide-info file offset overflows".to_owned())
            })?)
            .map_err(|_| {
                Error::BadDyldCache("slide-info file offset is not addressable".to_owned())
            })?;
        if width == 4 {
            return u32_at(self.cache, at, "slid pointer").map(u64::from);
        }
        u64_at(self.cache, at, "slid pointer")
    }

    fn emit(&mut self, pointer: SlidPointer) -> Result<()> {
        if !self.va_range.contains(&pointer.vm_address) {
            return Ok(());
        }
        self.summary.pointers += 1;
        if pointer.auth.is_some() {
            self.summary.authenticated_pointers += 1;
        }
        (self.sink)(pointer)
    }

    fn run_v1(&mut self) -> Result<()> {
        let toc_offset: u32 = u32_at(self.blob, 4, "v1 toc offset")?;
        let toc_count: u32 = u32_at(self.blob, 8, "v1 toc count")?;
        let entries_offset: u32 = u32_at(self.blob, 12, "v1 entries offset")?;
        let entries_count: u32 = u32_at(self.blob, 16, "v1 entries count")?;
        let entries_size: u32 = u32_at(self.blob, 20, "v1 entries size")?;
        self.summary.page_size = V1_PAGE_SIZE;
        let entry_bytes: usize = entries_size as usize;
        if entry_bytes == 0 || entry_bytes > MAX_V1_ENTRY_BYTES {
            return Err(Error::BadDyldCache(format!(
                "v1 slide-info entry size {entries_size} is outside the 1..={MAX_V1_ENTRY_BYTES} range"
            )));
        }
        let pages: usize = (toc_count as usize).min(MAX_SLIDE_PAGES);
        if (toc_count as usize) > MAX_SLIDE_PAGES {
            return Err(Error::BadDyldCache(format!(
                "v1 slide-info toc count {toc_count} exceeds the {MAX_SLIDE_PAGES} page cap"
            )));
        }
        for page_index in 0..pages {
            let page_va: u64 = self.page_va(page_index, V1_PAGE_SIZE)?;
            if !self.page_intersects(page_va, V1_PAGE_SIZE) {
                continue;
            }
            self.summary.pages_walked += 1;
            let toc_at: usize = (toc_offset as usize)
                .checked_add(page_index.checked_mul(2).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            let entry_index: u16 = u16_at(self.blob, toc_at, "v1 toc entry")?;
            if u32::from(entry_index) >= entries_count {
                return Err(Error::BadDyldCache(format!(
                    "v1 slide-info toc entry {entry_index} is outside the {entries_count}-entry table"
                )));
            }
            let entry_at: usize = (entries_offset as usize)
                .checked_add(
                    (entry_index as usize)
                        .checked_mul(entry_bytes)
                        .ok_or_else(overflow)?,
                )
                .ok_or_else(overflow)?;
            let bits: &[u8] = self
                .blob
                .get(entry_at..entry_at.checked_add(entry_bytes).ok_or_else(overflow)?)
                .ok_or_else(|| {
                    Error::BadDyldCache(format!(
                        "v1 slide-info entry {entry_index} leaves the slide-info blob"
                    ))
                })?;
            for (byte_index, mask) in bits.iter().enumerate() {
                if *mask == 0 {
                    continue;
                }
                for bit in 0u32..8 {
                    if mask >> bit & 1 == 0 {
                        continue;
                    }
                    let in_page: u64 = ((byte_index as u64) * 8 + u64::from(bit)) * 4;
                    if in_page >= u64::from(V1_PAGE_SIZE) {
                        return Err(Error::BadDyldCache(
                            "v1 slide-info bit lies outside its 4096-byte page".to_owned(),
                        ));
                    }
                    let va: u64 = page_va.checked_add(in_page).ok_or_else(overflow)?;
                    let raw: u64 = self.read_pointer(va, 4)?;
                    self.emit(SlidPointer {
                        vm_address: va,
                        unslid_value: raw,
                        width: 4,
                        auth: None,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn run_v2_or_v4(&mut self, version: SlideInfoVersion) -> Result<()> {
        let page_size: u32 = u32_at(self.blob, 4, "page size")?;
        let page_starts_offset: u32 = u32_at(self.blob, 8, "page starts offset")?;
        let page_starts_count: u32 = u32_at(self.blob, 12, "page starts count")?;
        let page_extras_offset: u32 = u32_at(self.blob, 16, "page extras offset")?;
        let page_extras_count: u32 = u32_at(self.blob, 20, "page extras count")?;
        let delta_mask: u64 = u64_at(self.blob, 24, "delta mask")?;
        let value_add: u64 = u64_at(self.blob, 32, "value add")?;
        self.summary.page_size = page_size;
        check_page_size(page_size)?;
        check_page_count(page_starts_count)?;
        if (page_extras_count as usize) > MAX_PAGE_EXTRAS {
            return Err(Error::BadDyldCache(format!(
                "slide-info page-extras count {page_extras_count} exceeds the {MAX_PAGE_EXTRAS} cap"
            )));
        }
        if delta_mask == 0 || delta_mask.trailing_zeros() < 2 {
            return Err(Error::BadDyldCache(format!(
                "slide-info delta mask {delta_mask:#x} does not carry a shiftable delta field"
            )));
        }
        let delta_shift: u32 = delta_mask.trailing_zeros() - 2;
        let width: u8 = version.pointer_width();
        let no_rebase: u16 = if version == SlideInfoVersion::V2 {
            PAGE_ATTR_NO_REBASE_V2
        } else {
            PAGE_NO_REBASE_V4
        };
        let extra_flag: u16 = if version == SlideInfoVersion::V2 {
            PAGE_ATTR_EXTRA
        } else {
            PAGE_USE_EXTRA_V4
        };
        let index_mask: u16 = if version == SlideInfoVersion::V2 {
            PAGE_INDEX_MASK_V2
        } else {
            PAGE_INDEX_MASK_V4
        };
        let end_flag: u16 = if version == SlideInfoVersion::V2 {
            PAGE_ATTR_END
        } else {
            PAGE_EXTRA_END_V4
        };

        for page_index in 0..page_starts_count as usize {
            let page_va: u64 = self.page_va(page_index, page_size)?;
            if !self.page_intersects(page_va, page_size) {
                continue;
            }
            let start_at: usize = (page_starts_offset as usize)
                .checked_add(page_index.checked_mul(2).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            let entry: u16 = u16_at(self.blob, start_at, "page start")?;
            if entry == no_rebase {
                continue;
            }
            self.summary.pages_walked += 1;
            if entry & extra_flag == 0 {
                let page_offset: u64 = u64::from(entry) * 4;
                self.walk_delta_chain(
                    page_va,
                    page_size,
                    page_offset,
                    delta_mask,
                    delta_shift,
                    value_add,
                    width,
                    version,
                )?;
                continue;
            }
            let mut chain_index: usize = usize::from(entry & index_mask);
            let mut steps: usize = 0;
            loop {
                if chain_index >= page_extras_count as usize {
                    return Err(Error::BadDyldCache(format!(
                        "slide-info extras index {chain_index} is outside the {page_extras_count}-entry extras table"
                    )));
                }
                let extra_at: usize = (page_extras_offset as usize)
                    .checked_add(chain_index.checked_mul(2).ok_or_else(overflow)?)
                    .ok_or_else(overflow)?;
                let info: u16 = u16_at(self.blob, extra_at, "page extra")?;
                let page_offset: u64 = u64::from(info & index_mask) * 4;
                self.walk_delta_chain(
                    page_va,
                    page_size,
                    page_offset,
                    delta_mask,
                    delta_shift,
                    value_add,
                    width,
                    version,
                )?;
                if info & end_flag != 0 {
                    break;
                }
                chain_index += 1;
                steps += 1;
                if steps > page_extras_count as usize {
                    return Err(Error::BadDyldCache(
                        "slide-info extras chain does not terminate".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_delta_chain(
        &mut self,
        page_va: u64,
        page_size: u32,
        start_offset: u64,
        delta_mask: u64,
        delta_shift: u32,
        value_add: u64,
        width: u8,
        version: SlideInfoVersion,
    ) -> Result<()> {
        let mut page_offset: u64 = start_offset;
        let steps_cap: u64 = u64::from(page_size) / u64::from(width);
        let mut steps: u64 = 0;
        loop {
            if page_offset.saturating_add(u64::from(width)) > u64::from(page_size) {
                return Err(Error::BadDyldCache(format!(
                    "slide-info chain offset {page_offset} leaves its {page_size}-byte page"
                )));
            }
            let va: u64 = page_va.checked_add(page_offset).ok_or_else(overflow)?;
            let raw: u64 = self.read_pointer(va, width)?;
            let delta: u64 = (raw & delta_mask) >> delta_shift;
            let value: u64 = raw & !delta_mask;
            let unslid: u64 = if version == SlideInfoVersion::V2 {
                if value == 0 {
                    0
                } else {
                    value.wrapping_add(value_add)
                }
            } else {
                unslide_v4_value(value, value_add)
            };
            self.emit(SlidPointer {
                vm_address: va,
                unslid_value: unslid,
                width,
                auth: None,
            })?;
            if delta == 0 {
                return Ok(());
            }
            page_offset = page_offset.checked_add(delta).ok_or_else(overflow)?;
            steps += 1;
            if steps > steps_cap {
                return Err(Error::BadDyldCache(
                    "slide-info delta chain does not terminate inside its page".to_owned(),
                ));
            }
        }
    }

    fn run_v3(&mut self) -> Result<()> {
        let page_size: u32 = u32_at(self.blob, 4, "page size")?;
        let page_starts_count: u32 = u32_at(self.blob, 8, "page starts count")?;
        let auth_value_add: u64 = u64_at(self.blob, 16, "auth value add")?;
        self.summary.page_size = page_size;
        check_page_size(page_size)?;
        check_page_count(page_starts_count)?;
        for page_index in 0..page_starts_count as usize {
            let page_va: u64 = self.page_va(page_index, page_size)?;
            if !self.page_intersects(page_va, page_size) {
                continue;
            }
            let start_at: usize = 24usize
                .checked_add(page_index.checked_mul(2).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            let entry: u16 = u16_at(self.blob, start_at, "page start")?;
            if entry == PAGE_NO_REBASE_V3 {
                continue;
            }
            self.summary.pages_walked += 1;
            self.walk_v3_chain(page_va, page_size, u64::from(entry), auth_value_add)?;
        }
        Ok(())
    }

    fn walk_v3_chain(
        &mut self,
        page_va: u64,
        page_size: u32,
        start_offset: u64,
        auth_value_add: u64,
    ) -> Result<()> {
        let mut page_offset: u64 = start_offset;
        let steps_cap: u64 = u64::from(page_size) / 8;
        let mut steps: u64 = 0;
        loop {
            if !page_offset.is_multiple_of(8) {
                return Err(Error::BadDyldCache(format!(
                    "v3 slide-info chain offset {page_offset} is not 8-byte aligned"
                )));
            }
            if page_offset.saturating_add(8) > u64::from(page_size) {
                return Err(Error::BadDyldCache(format!(
                    "v3 slide-info chain offset {page_offset} leaves its {page_size}-byte page"
                )));
            }
            let va: u64 = page_va.checked_add(page_offset).ok_or_else(overflow)?;
            let raw: u64 = self.read_pointer(va, 8)?;
            let (unslid, auth): (u64, Option<PointerAuth>) = decode_v3(raw, auth_value_add);
            self.emit(SlidPointer {
                vm_address: va,
                unslid_value: unslid,
                width: 8,
                auth,
            })?;
            let next: u64 = raw >> V3_NEXT_SHIFT & V3_NEXT_MASK;
            if next == 0 {
                return Ok(());
            }
            page_offset = page_offset
                .checked_add(next.checked_mul(8).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            steps += 1;
            if steps > steps_cap {
                return Err(Error::BadDyldCache(
                    "v3 slide-info chain does not terminate inside its page".to_owned(),
                ));
            }
        }
    }

    fn run_v5(&mut self) -> Result<()> {
        let page_size: u32 = u32_at(self.blob, 4, "page size")?;
        let page_starts_count: u32 = u32_at(self.blob, 8, "page starts count")?;
        let value_add: u64 = u64_at(self.blob, 16, "value add")?;
        self.summary.page_size = page_size;
        check_page_size(page_size)?;
        check_page_count(page_starts_count)?;
        for page_index in 0..page_starts_count as usize {
            let page_va: u64 = self.page_va(page_index, page_size)?;
            if !self.page_intersects(page_va, page_size) {
                continue;
            }
            let start_at: usize = 24usize
                .checked_add(page_index.checked_mul(2).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            let entry: u16 = u16_at(self.blob, start_at, "page start")?;
            if entry == PAGE_NO_REBASE_V5 {
                continue;
            }
            self.summary.pages_walked += 1;
            self.walk_v5_chain(page_va, page_size, u64::from(entry), value_add)?;
        }
        Ok(())
    }

    fn walk_v5_chain(
        &mut self,
        page_va: u64,
        page_size: u32,
        start_offset: u64,
        value_add: u64,
    ) -> Result<()> {
        let mut page_offset: u64 = start_offset;
        let steps_cap: u64 = u64::from(page_size) / 8;
        let mut steps: u64 = 0;
        loop {
            if !page_offset.is_multiple_of(8) {
                return Err(Error::BadDyldCache(format!(
                    "v5 slide-info chain offset {page_offset} is not 8-byte aligned"
                )));
            }
            if page_offset.saturating_add(8) > u64::from(page_size) {
                return Err(Error::BadDyldCache(format!(
                    "v5 slide-info chain offset {page_offset} leaves its {page_size}-byte page"
                )));
            }
            let va: u64 = page_va.checked_add(page_offset).ok_or_else(overflow)?;
            let raw: u64 = self.read_pointer(va, 8)?;
            let (unslid, auth): (u64, Option<PointerAuth>) = decode_v5(raw, value_add);
            self.emit(SlidPointer {
                vm_address: va,
                unslid_value: unslid,
                width: 8,
                auth,
            })?;
            let next: u64 = raw >> V5_NEXT_SHIFT & V5_NEXT_MASK;
            if next == 0 {
                return Ok(());
            }
            page_offset = page_offset
                .checked_add(next.checked_mul(8).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            steps += 1;
            if steps > steps_cap {
                return Err(Error::BadDyldCache(
                    "v5 slide-info chain does not terminate inside its page".to_owned(),
                ));
            }
        }
    }
}

#[must_use]
pub const fn decode_v3(raw: u64, auth_value_add: u64) -> (u64, Option<PointerAuth>) {
    if raw >> V3_AUTHENTICATED_SHIFT & 1 == 1 {
        let offset: u64 = raw & V3_AUTH_OFFSET_MASK;
        let auth: PointerAuth = PointerAuth {
            key: (raw >> V3_AUTH_KEY_SHIFT & 0b11) as u8,
            diversity: (raw >> V3_AUTH_DIVERSITY_SHIFT & 0xFFFF) as u16,
            address_diversity: raw >> V3_AUTH_ADDR_DIV_SHIFT & 1 == 1,
        };
        return (auth_value_add.wrapping_add(offset), Some(auth));
    }
    let low: u64 = raw & V3_PLAIN_LOW_MASK;
    let high8: u64 = (raw & V3_PLAIN_HIGH8_MASK) << V3_PLAIN_HIGH8_SHIFT;
    (low | high8, None)
}

#[must_use]
pub const fn decode_v5(raw: u64, value_add: u64) -> (u64, Option<PointerAuth>) {
    let runtime_offset: u64 = raw & V5_OFFSET_MASK;
    let target: u64 = value_add.wrapping_add(runtime_offset);
    if raw >> V5_AUTH_SHIFT & 1 == 1 {
        let key: u8 = if raw >> V5_KEY_IS_DATA_SHIFT & 1 == 1 {
            KEY_DA
        } else {
            KEY_IA
        };
        let auth: PointerAuth = PointerAuth {
            key,
            diversity: (raw >> V5_DIVERSITY_SHIFT & 0xFFFF) as u16,
            address_diversity: raw >> V5_ADDR_DIV_SHIFT & 1 == 1,
        };
        return (target, Some(auth));
    }
    let high8: u64 = raw >> V5_HIGH8_SHIFT & 0xFF;
    (target | high8 << HIGH8_TARGET_SHIFT, None)
}

#[must_use]
pub const fn unslide_v4_value(value: u64, value_add: u64) -> u64 {
    if value & 0xFFFF_8000 == 0 {
        return value;
    }
    if value & 0x3FFF_8000 == 0x3FFF_8000 {
        return value | 0xC000_0000;
    }
    value.wrapping_add(value_add)
}

fn blob_of(cache: &[u8], location: SlideLocation) -> Result<&[u8]> {
    let start: usize = usize::try_from(location.file_offset)
        .map_err(|_| Error::BadDyldCache("slide-info offset is not addressable".to_owned()))?;
    let size: usize = usize::try_from(location.size)
        .map_err(|_| Error::BadDyldCache("slide-info size is not addressable".to_owned()))?;
    let end: usize = start
        .checked_add(size)
        .ok_or_else(|| Error::BadDyldCache("slide-info range overflows".to_owned()))?;
    cache.get(start..end).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "slide-info range [{start}, {end}) exceeds cache length {}",
            cache.len()
        ))
    })
}

fn check_page_size(page_size: u32) -> Result<()> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(Error::BadDyldCache(format!(
            "slide-info page size {page_size} is not a power of two"
        )));
    }
    Ok(())
}

fn check_page_count(count: u32) -> Result<()> {
    if count as usize > MAX_SLIDE_PAGES {
        return Err(Error::BadDyldCache(format!(
            "slide-info page count {count} exceeds the {MAX_SLIDE_PAGES} page cap"
        )));
    }
    Ok(())
}

fn overflow() -> Error {
    Error::BadDyldCache("slide-info table offset overflows".to_owned())
}

fn u16_at(bytes: &[u8], off: usize, what: &str) -> Result<u16> {
    read_u16_le_at(bytes, off)
        .map_err(|error: ByteReadError| Error::BadDyldCache(format!("{what}: {error}")))
}

fn u32_at(bytes: &[u8], off: usize, what: &str) -> Result<u32> {
    read_u32_le_at(bytes, off)
        .map_err(|error: ByteReadError| Error::BadDyldCache(format!("{what}: {error}")))
}

fn u64_at(bytes: &[u8], off: usize, what: &str) -> Result<u64> {
    read_u64_le_at(bytes, off)
        .map_err(|error: ByteReadError| Error::BadDyldCache(format!("{what}: {error}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_slide_version_is_refused_by_number() {
        let refusal: Error = SlideInfoVersion::from_raw(6).expect_err("version 6 has no sample");
        assert!(matches!(refusal, Error::UnsupportedDyldSlideInfo(6)));
        assert!(format!("{refusal}").contains("version 6 is not supported"));
    }

    #[test]
    fn every_sampled_version_number_round_trips() {
        for raw in 1u32..=5 {
            let version: SlideInfoVersion =
                SlideInfoVersion::from_raw(raw).expect("documented version");
            assert_eq!(version.number(), raw);
        }
    }

    #[test]
    fn v3_authenticated_pointer_decodes_to_its_documented_fields() {
        let (target, auth): (u64, Option<PointerAuth>) =
            decode_v3(0x8005_ABCD_0000_1234, 0x1_8000_0000);
        assert_eq!(target, 0x1_8000_1234);
        let auth: PointerAuth = auth.expect("bit 63 marks an authenticated pointer");
        assert_eq!(auth.key, 2);
        assert_eq!(auth.key_label(), "DA");
        assert_eq!(auth.diversity, 0xABCD);
        assert!(auth.address_diversity);
    }

    #[test]
    fn v3_plain_pointer_moves_its_high_byte_from_bit_43_to_bit_56() {
        let (target, auth): (u64, Option<PointerAuth>) = decode_v3(0x0004_0001_8000_1234, 0);
        assert_eq!(target, 0x8000_0001_8000_1234);
        assert!(auth.is_none());
    }

    #[test]
    fn v5_regular_pointer_adds_the_cache_base_and_restores_the_high_byte() {
        let (target, auth): (u64, Option<PointerAuth>) =
            decode_v5(0x0000_0200_0000_1234, 0x1_8000_0000);
        assert_eq!(target, 0x8000_0001_8000_1234);
        assert!(auth.is_none());
    }

    #[test]
    fn v5_authenticated_pointer_reports_the_data_key() {
        let (target, auth): (u64, Option<PointerAuth>) =
            decode_v5(0x800E_AF34_0000_1234, 0x1_8000_0000);
        assert_eq!(target, 0x1_8000_1234);
        let auth: PointerAuth = auth.expect("bit 63 marks an authenticated pointer");
        assert_eq!(auth.key, 2);
        assert_eq!(auth.diversity, 0xABCD);
        assert!(auth.address_diversity);
    }

    #[test]
    fn v4_small_values_are_left_alone_and_pointers_take_the_value_add() {
        assert_eq!(unslide_v4_value(0x0000_1234, 0x4000_0000), 0x0000_1234);
        assert_eq!(unslide_v4_value(0x3FFF_8001, 0x4000_0000), 0xFFFF_8001);
        assert_eq!(unslide_v4_value(0x0004_1234, 0x4000_0000), 0x4004_1234);
    }
}
