use core::ops::Range;
use std::path::Path;

use disrobe_bytes::{ByteReadError, align_up_u64, read_u32_le_at, read_u64_le_at};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::macho::{
    self, Bitness, Endian, LC_SEGMENT, LC_SEGMENT_64, LoadCommand, ParsedSlice, Segment,
    read_cstr_bounded, u32_le, u64_le,
};

pub mod linkedit;
pub mod slide;
pub mod subcache;

use linkedit::{FieldPatch, LinkeditPlan, LinkeditSummary, LocalSymbolRun};
use slide::{PointerAuth, SlidPointer, SlideLocation, SlideSummary, SlideTarget};
use subcache::{CacheFamily, LoadedSubCache, MissingSubCache, SubCacheEntry, SubCacheEntryKind};

const MAGIC_PREFIX: &[u8] = b"dyld_v1";
const MAGIC_LEN: usize = 16;

const MAPPING_OFFSET_FIELD: usize = 0x10;
const MAPPING_COUNT_FIELD: usize = 0x14;
const IMAGES_OFFSET_OLD_FIELD: usize = 0x18;
const IMAGES_COUNT_OLD_FIELD: usize = 0x1C;
const LOCAL_SYMBOLS_OFFSET_FIELD: usize = 0x48;
const LOCAL_SYMBOLS_SIZE_FIELD: usize = 0x50;
const UUID_FIELD: usize = 0x58;
const CACHE_TYPE_FIELD: usize = 0x68;
const PLATFORM_FIELD: usize = 0xD8;
const FORMAT_FLAGS_FIELD: usize = 0xDC;
const SHARED_REGION_START_FIELD: usize = 0xE0;
const SHARED_REGION_SIZE_FIELD: usize = 0xE8;
const MAPPING_WITH_SLIDE_OFFSET_FIELD: usize = 0x138;
const MAPPING_WITH_SLIDE_COUNT_FIELD: usize = 0x13C;
const SUBCACHE_ARRAY_OFFSET_FIELD: usize = 0x188;
const SUBCACHE_ARRAY_COUNT_FIELD: usize = 0x18C;
const SYMBOL_FILE_UUID_FIELD: usize = 0x190;
const IMAGES_OFFSET_NEW_FIELD: usize = 0x1C0;
const IMAGES_COUNT_NEW_FIELD: usize = 0x1C4;
const IMAGES_NEW_FIELDS_END: usize = 0x1C8;

const HEADER_END_LEGACY: usize = 0x20;
const HEADER_END_LOCAL_SYMBOLS: usize = 0x58;
const HEADER_END_SLIDE_MAPPINGS: usize = 0x140;
const HEADER_END_SUB_CACHES: usize = 0x190;
const HEADER_END_RELOCATED_IMAGES: usize = IMAGES_NEW_FIELDS_END;
const SUBCACHE_SUFFIX_HEADER_END: usize = 0x1CC;

const MAPPING_INFO_SIZE: usize = 32;
const MAPPING_AND_SLIDE_INFO_SIZE: usize = 56;
const IMAGE_INFO_SIZE: usize = 32;
const UUID_LEN: usize = 16;

const LOCAL_SYMBOLS_ENTRY_32_SIZE: usize = 12;
const LOCAL_SYMBOLS_ENTRY_64_SIZE: usize = 16;
const MAX_LOCAL_SYMBOL_ENTRIES: usize = 1 << 20;

const MAX_MAPPINGS: usize = 4096;
const MAX_IMAGES: usize = 1 << 20;
const MAX_IMAGE_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECORDED_AUTH_POINTERS: usize = 1 << 16;

const SEG64_VMSIZE_FIELD: usize = 32;
const SEG64_FILEOFF_FIELD: usize = 40;
const SEG64_FILESIZE_FIELD: usize = 48;
const SEG64_NSECTS_FIELD: usize = 64;
const SEG64_SECTIONS_START: usize = 72;
const SEG64_SECTION_SIZE: usize = 80;
const SEG64_SECTION_OFFSET_FIELD: usize = 48;

const SEG32_VMSIZE_FIELD: usize = 28;
const SEG32_FILEOFF_FIELD: usize = 32;
const SEG32_FILESIZE_FIELD: usize = 36;
const SEG32_NSECTS_FIELD: usize = 48;
const SEG32_SECTIONS_START: usize = 56;
const SEG32_SECTION_SIZE: usize = 68;
const SEG32_SECTION_OFFSET_FIELD: usize = 40;

pub const DEFAULT_PAGE_SIZE: u64 = 0x4000;
const LINKEDIT_SEGMENT: &str = "__LINKEDIT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CacheHeaderLayout {
    Legacy,
    LocalSymbols,
    SlideMappings,
    SubCaches,
    RelocatedImages,
}

impl CacheHeaderLayout {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::LocalSymbols => "local-symbols",
            Self::SlideMappings => "slide-mappings",
            Self::SubCaches => "sub-caches",
            Self::RelocatedImages => "relocated-images",
        }
    }

    #[must_use]
    pub const fn from_header_size(header_size: usize) -> Option<Self> {
        if header_size >= HEADER_END_RELOCATED_IMAGES {
            return Some(Self::RelocatedImages);
        }
        if header_size >= HEADER_END_SUB_CACHES {
            return Some(Self::SubCaches);
        }
        if header_size >= HEADER_END_SLIDE_MAPPINGS {
            return Some(Self::SlideMappings);
        }
        if header_size >= HEADER_END_LOCAL_SYMBOLS {
            return Some(Self::LocalSymbols);
        }
        if header_size >= HEADER_END_LEGACY {
            return Some(Self::Legacy);
        }
        None
    }

    #[must_use]
    pub const fn has_local_symbols_fields(self) -> bool {
        !matches!(self, Self::Legacy)
    }

    #[must_use]
    pub const fn has_slide_mappings(self) -> bool {
        matches!(
            self,
            Self::SlideMappings | Self::SubCaches | Self::RelocatedImages
        )
    }

    #[must_use]
    pub const fn has_sub_caches(self) -> bool {
        matches!(self, Self::SubCaches | Self::RelocatedImages)
    }

    #[must_use]
    pub const fn has_relocated_images(self) -> bool {
        matches!(self, Self::RelocatedImages)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

impl DyldMapping {
    #[must_use]
    pub const fn end_address(&self) -> Option<u64> {
        self.address.checked_add(self.size)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldSlideMapping {
    pub index: u32,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub flags: u64,
    pub slide: SlideLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldImage {
    pub address: u64,
    pub install_name: String,
    pub path_file_offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSymbolsLocation {
    pub file_offset: u64,
    pub size: u64,
    pub in_symbols_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldSharedCache {
    pub magic: String,
    pub arch: String,
    pub endian: Endian,
    pub layout: CacheHeaderLayout,
    pub header_size: u32,
    pub uuid: Option<String>,
    pub cache_type: u64,
    pub platform: u32,
    pub format_version: u8,
    pub simulator: bool,
    pub built_from_chained_fixups: bool,
    pub shared_region_start: u64,
    pub shared_region_size: u64,
    pub mapping_offset: u32,
    pub mapping_count: u32,
    pub images_offset: u32,
    pub images_count: u32,
    pub mappings: Vec<DyldMapping>,
    pub slide_mappings: Vec<DyldSlideMapping>,
    pub images: Vec<DyldImage>,
    pub sub_caches: Vec<SubCacheEntry>,
    pub sub_cache_entry_kind: Option<SubCacheEntryKind>,
    pub local_symbols: Option<LocalSymbolsLocation>,
    pub truncated_mappings: Vec<u32>,
    pub overlapping_mappings: Vec<(u32, u32)>,
}

impl DyldSharedCache {
    #[must_use]
    pub fn base_address(&self) -> u64 {
        self.mappings
            .first()
            .map_or(self.shared_region_start, |mapping: &DyldMapping| {
                mapping.address
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentLayout {
    Compact,
    PageAligned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructOptions {
    pub layout: SegmentLayout,
    pub page_size: u64,
    pub synthesize_linkedit: bool,
    pub unapply_slide: bool,
}

impl ReconstructOptions {
    pub const COMPACT: Self = Self {
        layout: SegmentLayout::Compact,
        page_size: DEFAULT_PAGE_SIZE,
        synthesize_linkedit: false,
        unapply_slide: false,
    };

    pub const LOAD_READY: Self = Self {
        layout: SegmentLayout::PageAligned,
        page_size: DEFAULT_PAGE_SIZE,
        synthesize_linkedit: true,
        unapply_slide: true,
    };
}

impl Default for ReconstructOptions {
    fn default() -> Self {
        Self::COMPACT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPointerRecord {
    pub vm_address: u64,
    pub target: u64,
    pub auth: PointerAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedDylib {
    pub install_name: String,
    pub image_address: u64,
    pub header_file_offset: usize,
    pub segment_count: usize,
    pub page_size: u64,
    pub page_aligned: bool,
    pub linkedit: Option<LinkeditSummary>,
    pub slide: Vec<SlideSummary>,
    pub authenticated_pointers: Vec<AuthPointerRecord>,
    pub authenticated_pointer_total: usize,
    pub authenticated_records_truncated: bool,
    pub source_files: Vec<String>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedImage {
    pub install_name: String,
    pub image_address: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructBatch {
    pub dylibs: Vec<ReconstructedDylib>,
    pub unresolved: Vec<UnresolvedImage>,
    pub missing_sub_caches: Vec<MissingSubCache>,
    pub partial_reason: Option<String>,
}

#[must_use]
pub fn is_dyld_shared_cache(bytes: &[u8]) -> bool {
    bytes
        .get(0..MAGIC_LEN)
        .is_some_and(|magic: &[u8]| magic.starts_with(MAGIC_PREFIX))
}

pub fn parse(cache: &[u8]) -> Result<DyldSharedCache> {
    let magic_bytes: &[u8] = cache.get(0..MAGIC_LEN).ok_or(Error::NotDyldCache)?;
    if !magic_bytes.starts_with(MAGIC_PREFIX) {
        return Err(Error::NotDyldCache);
    }
    let nul: usize = magic_bytes
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(MAGIC_LEN);
    let magic: String = String::from_utf8_lossy(&magic_bytes[..nul])
        .trim()
        .to_owned();
    let arch: String = magic
        .strip_prefix("dyld_v1")
        .map_or("", str::trim)
        .to_owned();

    let mapping_offset: u32 = u32_le(cache, MAPPING_OFFSET_FIELD)?;
    let mapping_count: u32 = u32_le(cache, MAPPING_COUNT_FIELD)?;
    let header_size: usize = mapping_offset as usize;
    let layout: CacheHeaderLayout = CacheHeaderLayout::from_header_size(header_size)
        .ok_or_else(|| Error::UnsupportedDyldLayout {
            layout: format!("header-size-{header_size:#x}"),
            reason: format!(
                "the mapping table starts at {header_size:#x}, before the {HEADER_END_LEGACY:#x}-byte minimum header that carries the mapping and image tables"
            ),
        })?;

    let images_offset_old: u32 = u32_le(cache, IMAGES_OFFSET_OLD_FIELD)?;
    let images_count_old: u32 = u32_le(cache, IMAGES_COUNT_OLD_FIELD)?;
    let (images_offset, images_count): (u32, u32) = if images_count_old != 0
        && images_offset_old != 0
    {
        (images_offset_old, images_count_old)
    } else if layout.has_relocated_images() {
        (
            u32_le(cache, IMAGES_OFFSET_NEW_FIELD)?,
            u32_le(cache, IMAGES_COUNT_NEW_FIELD)?,
        )
    } else {
        return Err(Error::UnsupportedDyldLayout {
                layout: layout.label().to_owned(),
                reason:
                    "the legacy image fields are zero and the header is too small for the relocated image list"
                        .to_owned(),
            });
    };

    let mapping_count_usize: usize = mapping_count as usize;
    if mapping_count_usize > MAX_MAPPINGS {
        return Err(Error::BadDyldCache(format!(
            "mapping count {mapping_count} exceeds the {MAX_MAPPINGS} mapping cap"
        )));
    }
    let images_count_usize: usize = images_count as usize;
    if images_count_usize > MAX_IMAGES {
        return Err(Error::BadDyldCache(format!(
            "image count {images_count} exceeds the {MAX_IMAGES} image cap"
        )));
    }

    let mappings: Vec<DyldMapping> = parse_mappings(cache, mapping_offset, mapping_count_usize)?;
    let images: Vec<DyldImage> = parse_images(cache, images_offset, images_count_usize)?;
    let slide_mappings: Vec<DyldSlideMapping> = if layout.has_slide_mappings() {
        parse_slide_mappings(cache)?
    } else {
        Vec::new()
    };
    let (sub_caches, sub_cache_entry_kind): (Vec<SubCacheEntry>, Option<SubCacheEntryKind>) =
        if layout.has_sub_caches() {
            let kind: SubCacheEntryKind = if header_size > SUBCACHE_SUFFIX_HEADER_END {
                SubCacheEntryKind::WithFileSuffix
            } else {
                SubCacheEntryKind::UuidAndOffsetOnly
            };
            let array_offset: u32 = u32_le(cache, SUBCACHE_ARRAY_OFFSET_FIELD)?;
            let array_count: u32 = u32_le(cache, SUBCACHE_ARRAY_COUNT_FIELD)?;
            if array_count == 0 {
                (Vec::new(), Some(kind))
            } else {
                (
                    subcache::parse_entries(cache, array_offset, array_count, kind)?,
                    Some(kind),
                )
            }
        } else {
            (Vec::new(), None)
        };

    let local_symbols: Option<LocalSymbolsLocation> = if layout.has_local_symbols_fields() {
        let file_offset: u64 = u64_le(cache, LOCAL_SYMBOLS_OFFSET_FIELD)?;
        let size: u64 = u64_le(cache, LOCAL_SYMBOLS_SIZE_FIELD)?;
        let in_symbols_file: bool = layout.has_sub_caches()
            && header_size >= SYMBOL_FILE_UUID_FIELD + UUID_LEN
            && has_symbol_file_uuid(cache)?;
        if in_symbols_file {
            Some(LocalSymbolsLocation {
                file_offset,
                size,
                in_symbols_file,
            })
        } else {
            (file_offset != 0 && size != 0).then_some(LocalSymbolsLocation {
                file_offset,
                size,
                in_symbols_file,
            })
        }
    } else {
        None
    };

    let (truncated_mappings, overlapping_mappings): (Vec<u32>, Vec<(u32, u32)>) =
        audit_mappings(&mappings, cache.len());

    let (platform, format_flags): (u32, u32) = if header_size >= FORMAT_FLAGS_FIELD + 4 {
        (
            u32_le(cache, PLATFORM_FIELD)?,
            u32_le(cache, FORMAT_FLAGS_FIELD)?,
        )
    } else {
        (0, 0)
    };
    let (shared_region_start, shared_region_size): (u64, u64) =
        if header_size >= SHARED_REGION_SIZE_FIELD + 8 {
            (
                u64_le(cache, SHARED_REGION_START_FIELD)?,
                u64_le(cache, SHARED_REGION_SIZE_FIELD)?,
            )
        } else {
            (0, 0)
        };

    Ok(DyldSharedCache {
        magic,
        arch,
        endian: Endian::Little,
        layout,
        header_size: mapping_offset,
        uuid: read_uuid(cache, UUID_FIELD, header_size >= UUID_FIELD + UUID_LEN),
        cache_type: if header_size >= CACHE_TYPE_FIELD + 8 {
            u64_le(cache, CACHE_TYPE_FIELD)?
        } else {
            0
        },
        platform,
        format_version: (format_flags & 0xFF) as u8,
        simulator: format_flags >> 9 & 1 == 1,
        built_from_chained_fixups: format_flags >> 11 & 1 == 1,
        shared_region_start,
        shared_region_size,
        mapping_offset,
        mapping_count,
        images_offset,
        images_count,
        mappings,
        slide_mappings,
        images,
        sub_caches,
        sub_cache_entry_kind,
        local_symbols,
        truncated_mappings,
        overlapping_mappings,
    })
}

fn has_symbol_file_uuid(cache: &[u8]) -> Result<bool> {
    let field: &[u8] = cache
        .get(SYMBOL_FILE_UUID_FIELD..SYMBOL_FILE_UUID_FIELD + UUID_LEN)
        .ok_or(Error::Truncated(SYMBOL_FILE_UUID_FIELD))?;
    Ok(field.iter().any(|byte: &u8| *byte != 0))
}

fn read_uuid(cache: &[u8], at: usize, present: bool) -> Option<String> {
    if !present {
        return None;
    }
    let field: &[u8] = cache.get(at..at + UUID_LEN)?;
    if field.iter().all(|byte: &u8| *byte == 0) {
        return None;
    }
    Some(subcache::hex_uuid(field))
}

fn audit_mappings(mappings: &[DyldMapping], cache_len: usize) -> (Vec<u32>, Vec<(u32, u32)>) {
    let mut truncated: Vec<u32> = Vec::new();
    let mut overlapping: Vec<(u32, u32)> = Vec::new();
    for (index, mapping) in mappings.iter().enumerate() {
        let ordinal: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let end: Option<u64> = mapping.file_offset.checked_add(mapping.size);
        match end {
            Some(end) if end <= cache_len as u64 => {}
            _ => truncated.push(ordinal),
        }
        for (other_index, other) in mappings.iter().enumerate().skip(index + 1) {
            let (Some(end), Some(other_end)): (Option<u64>, Option<u64>) =
                (mapping.end_address(), other.end_address())
            else {
                continue;
            };
            if mapping.address < other_end && other.address < end {
                overlapping.push((ordinal, u32::try_from(other_index).unwrap_or(u32::MAX)));
            }
        }
    }
    (truncated, overlapping)
}

fn table_bounds(
    base: u32,
    count: usize,
    entry: usize,
    cache_len: usize,
    what: &str,
) -> Result<usize> {
    let start: usize = base as usize;
    let span: usize = count
        .checked_mul(entry)
        .ok_or_else(|| Error::BadDyldCache(format!("{what} table size overflows")))?;
    let end: usize = start
        .checked_add(span)
        .ok_or_else(|| Error::BadDyldCache(format!("{what} table end overflows")))?;
    if end > cache_len {
        return Err(Error::BadDyldCache(format!(
            "{what} table [{start}, {end}) exceeds cache length {cache_len}"
        )));
    }
    Ok(start)
}

fn parse_mappings(cache: &[u8], offset: u32, count: usize) -> Result<Vec<DyldMapping>> {
    let base: usize = table_bounds(offset, count, MAPPING_INFO_SIZE, cache.len(), "mapping")?;
    let mut out: Vec<DyldMapping> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = base + i * MAPPING_INFO_SIZE;
        out.push(DyldMapping {
            address: u64_le(cache, off)?,
            size: u64_le(cache, off + 8)?,
            file_offset: u64_le(cache, off + 16)?,
            max_prot: u32_le(cache, off + 24)?,
            init_prot: u32_le(cache, off + 28)?,
        });
    }
    Ok(out)
}

fn parse_slide_mappings(cache: &[u8]) -> Result<Vec<DyldSlideMapping>> {
    let offset: u32 = u32_le(cache, MAPPING_WITH_SLIDE_OFFSET_FIELD)?;
    let count: u32 = u32_le(cache, MAPPING_WITH_SLIDE_COUNT_FIELD)?;
    if offset == 0 || count == 0 {
        return Ok(Vec::new());
    }
    let count_usize: usize = count as usize;
    if count_usize > MAX_MAPPINGS {
        return Err(Error::BadDyldCache(format!(
            "slide mapping count {count} exceeds the {MAX_MAPPINGS} mapping cap"
        )));
    }
    let base: usize = table_bounds(
        offset,
        count_usize,
        MAPPING_AND_SLIDE_INFO_SIZE,
        cache.len(),
        "slide mapping",
    )?;
    let mut out: Vec<DyldSlideMapping> = Vec::with_capacity(count_usize);
    for i in 0..count_usize {
        let off: usize = base + i * MAPPING_AND_SLIDE_INFO_SIZE;
        let slide_offset: u64 = u64_le(cache, off + 24)?;
        let slide_size: u64 = u64_le(cache, off + 32)?;
        out.push(DyldSlideMapping {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            address: u64_le(cache, off)?,
            size: u64_le(cache, off + 8)?,
            file_offset: u64_le(cache, off + 16)?,
            flags: u64_le(cache, off + 40)?,
            slide: SlideLocation {
                file_offset: slide_offset,
                size: slide_size,
            },
        });
    }
    Ok(out)
}

fn parse_images(cache: &[u8], offset: u32, count: usize) -> Result<Vec<DyldImage>> {
    let base: usize = table_bounds(offset, count, IMAGE_INFO_SIZE, cache.len(), "image")?;
    let mut out: Vec<DyldImage> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = base + i * IMAGE_INFO_SIZE;
        let address: u64 = u64_le(cache, off)?;
        let path_file_offset: u32 = u32_le(cache, off + 24)?;
        let install_name: String = read_cstr_bounded(cache, path_file_offset as usize, cache.len())
            .ok_or_else(|| {
                Error::BadDyldCache(format!(
                    "image {i} install-name at file offset {path_file_offset} is unreadable"
                ))
            })?;
        out.push(DyldImage {
            address,
            install_name,
            path_file_offset,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located {
    pub file_index: usize,
    pub file_offset: usize,
}

#[derive(Debug, Clone)]
pub struct CacheFile<'a> {
    pub label: String,
    pub bytes: &'a [u8],
    pub mappings: Vec<DyldMapping>,
    pub slide_mappings: Vec<DyldSlideMapping>,
}

#[derive(Debug, Clone)]
pub struct CacheSpace<'a> {
    pub files: Vec<CacheFile<'a>>,
    pub local_symbols: Option<(usize, LocalSymbolsLocation)>,
}

impl<'a> CacheSpace<'a> {
    #[must_use]
    pub fn single(cache: &'a [u8], parsed: &DyldSharedCache) -> Self {
        Self {
            files: vec![CacheFile {
                label: "primary".to_owned(),
                bytes: cache,
                mappings: parsed.mappings.clone(),
                slide_mappings: parsed.slide_mappings.clone(),
            }],
            local_symbols: parsed
                .local_symbols
                .as_ref()
                .filter(|location: &&LocalSymbolsLocation| !location.in_symbols_file)
                .map(|location: &LocalSymbolsLocation| (0, location.clone())),
        }
    }

    pub fn from_family(family: &'a CacheFamily, parsed: &DyldSharedCache) -> Result<Self> {
        let mut files: Vec<CacheFile<'a>> = vec![CacheFile {
            label: "primary".to_owned(),
            bytes: &family.primary,
            mappings: parsed.mappings.clone(),
            slide_mappings: parsed.slide_mappings.clone(),
        }];
        for sub in &family.sub_caches {
            let sub_parsed: DyldSharedCache = parse(&sub.bytes)?;
            files.push(CacheFile {
                label: label_of(sub),
                bytes: &sub.bytes,
                mappings: sub_parsed.mappings,
                slide_mappings: sub_parsed.slide_mappings,
            });
        }
        let mut local_symbols: Option<(usize, LocalSymbolsLocation)> = None;
        if let Some(location) = parsed.local_symbols.as_ref() {
            if location.in_symbols_file {
                if let Some(symbols) = family.symbols.as_ref() {
                    let symbols_parsed: DyldSharedCache = parse(&symbols.bytes)?;
                    let symbols_index: usize = files.len();
                    files.push(CacheFile {
                        label: "symbols".to_owned(),
                        bytes: &symbols.bytes,
                        mappings: symbols_parsed.mappings,
                        slide_mappings: symbols_parsed.slide_mappings,
                    });
                    let owned: LocalSymbolsLocation = symbols_parsed
                        .local_symbols
                        .unwrap_or_else(|| location.clone());
                    local_symbols = Some((symbols_index, owned));
                }
            } else {
                local_symbols = Some((0, location.clone()));
            }
        }
        Ok(Self {
            files,
            local_symbols,
        })
    }

    #[must_use]
    pub fn resolve(&self, vmaddr: u64) -> Option<Located> {
        for (file_index, file) in self.files.iter().enumerate() {
            for mapping in &file.mappings {
                let end: u64 = mapping.end_address()?;
                if vmaddr >= mapping.address && vmaddr < end {
                    let delta: u64 = vmaddr - mapping.address;
                    let file_offset: u64 = mapping.file_offset.checked_add(delta)?;
                    return Some(Located {
                        file_index,
                        file_offset: usize::try_from(file_offset).ok()?,
                    });
                }
            }
        }
        None
    }

    #[must_use]
    pub fn read(&self, vmaddr: u64, len: usize) -> Option<&'a [u8]> {
        let located: Located = self.resolve(vmaddr)?;
        let file: &CacheFile<'a> = self.files.get(located.file_index)?;
        let end: usize = located.file_offset.checked_add(len)?;
        file.bytes.get(located.file_offset..end)
    }

    #[must_use]
    pub fn slide_for(&self, file_index: usize, vmaddr: u64) -> Option<&DyldSlideMapping> {
        let file: &CacheFile<'a> = self.files.get(file_index)?;
        file.slide_mappings
            .iter()
            .find(|mapping: &&DyldSlideMapping| {
                let Some(end): Option<u64> = mapping.address.checked_add(mapping.size) else {
                    return false;
                };
                mapping.slide.size != 0 && vmaddr >= mapping.address && vmaddr < end
            })
    }
}

fn label_of(sub: &LoadedSubCache) -> String {
    sub.path
        .file_name()
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        .map_or_else(|| format!("sub-cache-{}", sub.entry.index), str::to_owned)
}

fn map_vmaddr(mappings: &[DyldMapping], vmaddr: u64) -> Option<usize> {
    for m in mappings {
        let end: u64 = m.end_address()?;
        if vmaddr >= m.address && vmaddr < end {
            let delta: u64 = vmaddr - m.address;
            let file_off: u64 = m.file_offset.checked_add(delta)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

pub fn reconstruct_image(
    cache: &[u8],
    parsed: &DyldSharedCache,
    index: usize,
) -> Result<ReconstructedDylib> {
    reconstruct_image_with(cache, parsed, index, ReconstructOptions::COMPACT)
}

pub fn reconstruct_image_with(
    cache: &[u8],
    parsed: &DyldSharedCache,
    index: usize,
    options: ReconstructOptions,
) -> Result<ReconstructedDylib> {
    let image: &DyldImage = parsed.images.get(index).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "image index {index} out of range ({} images)",
            parsed.images.len()
        ))
    })?;
    let space: CacheSpace<'_> = CacheSpace::single(cache, parsed);
    reconstruct(&space, parsed, image, options)
}

pub fn reconstruct_by_name(
    cache: &[u8],
    parsed: &DyldSharedCache,
    install_name: &str,
) -> Result<ReconstructedDylib> {
    reconstruct_by_name_with(cache, parsed, install_name, ReconstructOptions::COMPACT)
}

pub fn reconstruct_by_name_with(
    cache: &[u8],
    parsed: &DyldSharedCache,
    install_name: &str,
    options: ReconstructOptions,
) -> Result<ReconstructedDylib> {
    let image: &DyldImage = parsed
        .images
        .iter()
        .find(|img: &&DyldImage| img.install_name == install_name)
        .ok_or_else(|| Error::BadDyldCache(format!("no bundled image named '{install_name}'")))?;
    let space: CacheSpace<'_> = CacheSpace::single(cache, parsed);
    reconstruct(&space, parsed, image, options)
}

pub fn reconstruct_all(cache: &[u8], parsed: &DyldSharedCache) -> Result<Vec<ReconstructedDylib>> {
    reconstruct_all_with(cache, parsed, ReconstructOptions::COMPACT)
}

pub fn reconstruct_all_with(
    cache: &[u8],
    parsed: &DyldSharedCache,
    options: ReconstructOptions,
) -> Result<Vec<ReconstructedDylib>> {
    let space: CacheSpace<'_> = CacheSpace::single(cache, parsed);
    let mut out: Vec<ReconstructedDylib> = Vec::with_capacity(parsed.images.len());
    let mut total: u64 = 0;
    for image in &parsed.images {
        let dylib: ReconstructedDylib = reconstruct(&space, parsed, image, options)?;
        total = total
            .checked_add(dylib.bytes.len() as u64)
            .ok_or_else(|| Error::BadDyldCache("cumulative output size overflows".to_owned()))?;
        if total > MAX_TOTAL_OUTPUT_BYTES {
            return Err(Error::BadDyldCache(format!(
                "cumulative reconstructed output exceeds the {MAX_TOTAL_OUTPUT_BYTES}-byte cap"
            )));
        }
        out.push(dylib);
    }
    Ok(out)
}

pub fn open_family(path: &Path) -> Result<(CacheFamily, DyldSharedCache)> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    if !is_dyld_shared_cache(&bytes) {
        return Err(Error::NotDyldCache);
    }
    let parsed: DyldSharedCache = parse(&bytes)?;
    let wants_symbols: bool = parsed
        .local_symbols
        .as_ref()
        .is_some_and(|location: &LocalSymbolsLocation| location.in_symbols_file);
    let family: CacheFamily =
        subcache::open_family(path, bytes, &parsed.sub_caches, wants_symbols)?;
    Ok((family, parsed))
}

pub fn reconstruct_family(
    family: &CacheFamily,
    parsed: &DyldSharedCache,
    options: ReconstructOptions,
) -> Result<ReconstructBatch> {
    let space: CacheSpace<'_> = CacheSpace::from_family(family, parsed)?;
    let mut dylibs: Vec<ReconstructedDylib> = Vec::with_capacity(parsed.images.len());
    let mut unresolved: Vec<UnresolvedImage> = Vec::new();
    let mut total: u64 = 0;
    for image in &parsed.images {
        match reconstruct(&space, parsed, image, options) {
            Ok(dylib) => {
                total = total.checked_add(dylib.bytes.len() as u64).ok_or_else(|| {
                    Error::BadDyldCache("cumulative output size overflows".to_owned())
                })?;
                if total > MAX_TOTAL_OUTPUT_BYTES {
                    return Err(Error::BadDyldCache(format!(
                        "cumulative reconstructed output exceeds the {MAX_TOTAL_OUTPUT_BYTES}-byte cap"
                    )));
                }
                dylibs.push(dylib);
            }
            Err(error) => unresolved.push(UnresolvedImage {
                install_name: image.install_name.clone(),
                image_address: image.address,
                reason: format!("{error}"),
            }),
        }
    }
    Ok(ReconstructBatch {
        dylibs,
        unresolved,
        missing_sub_caches: family.missing.clone(),
        partial_reason: family.partial_reason(),
    })
}

struct Placement {
    file_offset: u64,
    bytes: Vec<u8>,
}

fn reconstruct(
    space: &CacheSpace<'_>,
    parsed: &DyldSharedCache,
    image: &DyldImage,
    options: ReconstructOptions,
) -> Result<ReconstructedDylib> {
    let header: Located = space.resolve(image.address).ok_or_else(|| {
        Error::DyldImageUnsupported {
            image: image.install_name.clone(),
            reason: format!(
                "its mach header address {:#x} is not covered by any mapping in the loaded cache files",
                image.address
            ),
        }
    })?;
    let header_file: &CacheFile<'_> = space
        .files
        .get(header.file_index)
        .ok_or_else(|| Error::BadDyldCache("resolved cache file index is absent".to_owned()))?;
    let remainder: &[u8] = header_file
        .bytes
        .get(header.file_offset..)
        .ok_or(Error::Truncated(header.file_offset))?;
    if macho::detect_magic(remainder).is_none() {
        return Err(Error::NotMachO);
    }
    let macho: ParsedSlice = macho::parse_slice(remainder)?;

    let is_64: bool = matches!(macho.header.bitness, Bitness::Bits64);
    let fields: SegmentFields = SegmentFields::for_bitness(is_64);

    let seg_lcs: Vec<&LoadCommand> = macho
        .load_commands
        .iter()
        .filter(|lc: &&LoadCommand| lc.cmd == LC_SEGMENT_64 || lc.cmd == LC_SEGMENT)
        .collect();
    if seg_lcs.len() != macho.segments.len() {
        return Err(Error::BadDyldCache(
            "segment load-command count does not match parsed segment count".to_owned(),
        ));
    }

    let linkedit_built: Option<(LinkeditPlan, String)> = if options.synthesize_linkedit {
        Some(build_linkedit(space, parsed, image, &macho, remainder)?)
    } else {
        None
    };
    let mut source_files: Vec<String> = vec![header_file.label.clone()];
    let linkedit_plan: Option<LinkeditPlan> =
        linkedit_built.map(|(plan, label): (LinkeditPlan, String)| {
            if !source_files.contains(&label) {
                source_files.push(label);
            }
            plan
        });

    let mut placements: Vec<Placement> = Vec::with_capacity(macho.segments.len());
    let mut running: u64 = 0;
    let mut slide_summaries: Vec<SlideSummary> = Vec::new();
    let mut auth_records: Vec<AuthPointerRecord> = Vec::new();
    let mut auth_total: usize = 0;

    for seg in &macho.segments {
        let synthesized: Option<&LinkeditPlan> = linkedit_plan
            .as_ref()
            .filter(|_| seg.name == LINKEDIT_SEGMENT);
        let mut bytes: Vec<u8> = match synthesized {
            Some(plan) => plan.bytes.clone(),
            None => copy_segment_bytes(space, seg, image, &mut source_files)?,
        };
        if options.unapply_slide && synthesized.is_none() && !bytes.is_empty() {
            unapply_segment_slide(
                space,
                seg,
                &mut bytes,
                &mut slide_summaries,
                &mut auth_records,
                &mut auth_total,
            )?;
        }
        let size: u64 = bytes.len() as u64;
        let file_offset: u64 = if size == 0 {
            0
        } else {
            let placed: u64 = match options.layout {
                SegmentLayout::Compact => running,
                SegmentLayout::PageAligned => align_up_u64(running, options.page_size),
            };
            running = placed
                .checked_add(size)
                .ok_or_else(|| Error::BadDyldCache("segment layout size overflows".to_owned()))?;
            if running > MAX_IMAGE_OUTPUT_BYTES {
                return Err(Error::BadDyldCache(format!(
                    "reconstructed image exceeds the {MAX_IMAGE_OUTPUT_BYTES}-byte cap"
                )));
            }
            placed
        };
        placements.push(Placement { file_offset, bytes });
    }

    let total: u64 = match options.layout {
        SegmentLayout::Compact => running,
        SegmentLayout::PageAligned => align_up_u64(running, options.page_size),
    };
    let mut output: Vec<u8> = vec![
        0u8;
        usize::try_from(total).map_err(|_| {
            Error::BadDyldCache("reconstructed image size is not addressable".to_owned())
        })?
    ];
    for placement in &placements {
        if placement.bytes.is_empty() {
            continue;
        }
        let start: usize = usize::try_from(placement.file_offset).map_err(|_| {
            Error::BadDyldCache("segment file offset is not addressable".to_owned())
        })?;
        let end: usize = start
            .checked_add(placement.bytes.len())
            .ok_or_else(|| Error::BadDyldCache("segment file range overflows".to_owned()))?;
        output
            .get_mut(start..end)
            .ok_or_else(|| {
                Error::BadDyldCache("segment placement leaves the reconstructed image".to_owned())
            })?
            .copy_from_slice(&placement.bytes);
    }

    for ((seg, lc), placement) in macho
        .segments
        .iter()
        .zip(seg_lcs.iter())
        .zip(placements.iter())
    {
        patch_segment(
            &mut output,
            lc,
            seg,
            placement,
            fields,
            options.page_size,
            options.synthesize_linkedit && seg.name == LINKEDIT_SEGMENT,
        )?;
    }

    if let Some(plan) = linkedit_plan.as_ref() {
        let base: u64 = linkedit_base(&macho, &placements)?;
        let patches: &[FieldPatch] = &plan.patches;
        for patch in patches {
            write_u32_field(&mut output, patch.at, patch.resolve(base))?;
        }
    }

    let reparsed: ParsedSlice = macho::parse_slice(&output)?;
    if reparsed.segments.len() != macho.segments.len() {
        return Err(Error::BadDyldCache(
            "reconstructed image segment count does not round-trip".to_owned(),
        ));
    }

    let truncated: bool = auth_total > auth_records.len();
    Ok(ReconstructedDylib {
        install_name: image.install_name.clone(),
        image_address: image.address,
        header_file_offset: header.file_offset,
        segment_count: macho.segments.len(),
        page_size: options.page_size,
        page_aligned: options.layout == SegmentLayout::PageAligned,
        linkedit: linkedit_plan.map(|plan: LinkeditPlan| plan.summary),
        slide: slide_summaries,
        authenticated_pointers: auth_records,
        authenticated_pointer_total: auth_total,
        authenticated_records_truncated: truncated,
        source_files,
        bytes: output,
    })
}

fn linkedit_base(macho: &ParsedSlice, placements: &[Placement]) -> Result<u64> {
    macho
        .segments
        .iter()
        .zip(placements.iter())
        .find(|(seg, _): &(&Segment, &Placement)| seg.name == LINKEDIT_SEGMENT)
        .map(|(_, placement): (&Segment, &Placement)| placement.file_offset)
        .ok_or_else(|| {
            Error::BadDyldCache(
                "the image carries no __LINKEDIT segment to hold a synthesized symbol table"
                    .to_owned(),
            )
        })
}

fn copy_segment_bytes(
    space: &CacheSpace<'_>,
    seg: &Segment,
    image: &DyldImage,
    source_files: &mut Vec<String>,
) -> Result<Vec<u8>> {
    if seg.filesize == 0 {
        return Ok(Vec::new());
    }
    let size: usize = usize::try_from(seg.filesize)
        .map_err(|_| Error::BadDyldCache("segment filesize is not addressable".to_owned()))?;
    let located: Located =
        space
            .resolve(seg.vmaddr)
            .ok_or_else(|| Error::DyldImageUnsupported {
                image: image.install_name.clone(),
                reason: format!(
                    "segment '{}' at {:#x} is not covered by any mapping in the loaded cache files",
                    seg.name, seg.vmaddr
                ),
            })?;
    let file: &CacheFile<'_> = space
        .files
        .get(located.file_index)
        .ok_or_else(|| Error::BadDyldCache("resolved cache file index is absent".to_owned()))?;
    let end: usize = located
        .file_offset
        .checked_add(size)
        .ok_or_else(|| Error::BadDyldCache("segment file range overflows".to_owned()))?;
    let bytes: &[u8] =
        file.bytes
            .get(located.file_offset..end)
            .ok_or_else(|| Error::DyldImageUnsupported {
                image: image.install_name.clone(),
                reason: format!(
                    "segment '{}' range [{}, {end}) exceeds the {}-byte cache file '{}'",
                    seg.name,
                    located.file_offset,
                    file.bytes.len(),
                    file.label
                ),
            })?;
    if !source_files.contains(&file.label) {
        source_files.push(file.label.clone());
    }
    Ok(bytes.to_vec())
}

fn unapply_segment_slide(
    space: &CacheSpace<'_>,
    seg: &Segment,
    bytes: &mut [u8],
    summaries: &mut Vec<SlideSummary>,
    auth_records: &mut Vec<AuthPointerRecord>,
    auth_total: &mut usize,
) -> Result<()> {
    let Some(located): Option<Located> = space.resolve(seg.vmaddr) else {
        return Ok(());
    };
    let Some(mapping): Option<&DyldSlideMapping> = space.slide_for(located.file_index, seg.vmaddr)
    else {
        return Ok(());
    };
    let file: &CacheFile<'_> = space
        .files
        .get(located.file_index)
        .ok_or_else(|| Error::BadDyldCache("resolved cache file index is absent".to_owned()))?;
    let seg_end: u64 = seg
        .vmaddr
        .checked_add(seg.filesize)
        .ok_or_else(|| Error::BadDyldCache("segment address range overflows".to_owned()))?;
    let range: Range<u64> = seg.vmaddr..seg_end;
    let base: u64 = seg.vmaddr;
    let mut failure: Option<Error> = None;
    let summary: SlideSummary = slide::unapply_range(
        file.bytes,
        mapping.slide,
        SlideTarget {
            vm_address: mapping.address,
            file_offset: mapping.file_offset,
            size: mapping.size,
        },
        &range,
        &mut |pointer: SlidPointer| -> Result<()> {
            let offset: usize =
                usize::try_from(pointer.vm_address.wrapping_sub(base)).map_err(|_| {
                    Error::BadDyldCache("slid pointer offset is not addressable".to_owned())
                })?;
            let width: usize = usize::from(pointer.width);
            let Some(slot): Option<&mut [u8]> = bytes.get_mut(offset..offset + width) else {
                failure = Some(Error::BadDyldCache(format!(
                    "slid pointer at {:#x} leaves segment '{}'",
                    pointer.vm_address, seg.name
                )));
                return Ok(());
            };
            if width == 4 {
                slot.copy_from_slice(&(pointer.unslid_value as u32).to_le_bytes());
            } else {
                slot.copy_from_slice(&pointer.unslid_value.to_le_bytes());
            }
            if let Some(auth) = pointer.auth {
                *auth_total += 1;
                if auth_records.len() < MAX_RECORDED_AUTH_POINTERS {
                    auth_records.push(AuthPointerRecord {
                        vm_address: pointer.vm_address,
                        target: pointer.unslid_value,
                        auth,
                    });
                }
            }
            Ok(())
        },
    )?;
    if let Some(error) = failure {
        return Err(error);
    }
    summaries.push(summary);
    Ok(())
}

fn build_linkedit(
    space: &CacheSpace<'_>,
    parsed: &DyldSharedCache,
    image: &DyldImage,
    macho: &ParsedSlice,
    image_slice: &[u8],
) -> Result<(LinkeditPlan, String)> {
    let linkedit_seg: &Segment = macho
        .segments
        .iter()
        .find(|seg: &&Segment| seg.name == LINKEDIT_SEGMENT)
        .ok_or_else(|| Error::DyldImageUnsupported {
            image: image.install_name.clone(),
            reason: "the image carries no __LINKEDIT segment".to_owned(),
        })?;
    let located: Located = space.resolve(linkedit_seg.vmaddr).ok_or_else(|| {
        Error::DyldImageUnsupported {
            image: image.install_name.clone(),
            reason: format!(
                "its __LINKEDIT at {:#x} is not covered by any mapping in the loaded cache files",
                linkedit_seg.vmaddr
            ),
        }
    })?;
    let linkedit_file: &CacheFile<'_> = space
        .files
        .get(located.file_index)
        .ok_or_else(|| Error::BadDyldCache("resolved cache file index is absent".to_owned()))?;
    let owned: Vec<u8> = local_symbol_storage(space, parsed, image)?;
    let run: Option<LocalSymbolRun<'_>> = local_symbol_run(&owned, macho);
    let plan: LinkeditPlan = linkedit::build(image_slice, linkedit_file.bytes, macho, run)?;
    Ok((plan, linkedit_file.label.clone()))
}

fn local_symbol_storage(
    space: &CacheSpace<'_>,
    parsed: &DyldSharedCache,
    image: &DyldImage,
) -> Result<Vec<u8>> {
    let Some((file_index, location)): Option<&(usize, LocalSymbolsLocation)> =
        space.local_symbols.as_ref()
    else {
        return Ok(Vec::new());
    };
    let Some(file): Option<&CacheFile<'_>> = space.files.get(*file_index) else {
        return Ok(Vec::new());
    };
    let start: usize = usize::try_from(location.file_offset)
        .map_err(|_| Error::BadDyldCache("local-symbols offset is not addressable".to_owned()))?;
    let size: usize = usize::try_from(location.size)
        .map_err(|_| Error::BadDyldCache("local-symbols size is not addressable".to_owned()))?;
    let end: usize = start
        .checked_add(size)
        .ok_or_else(|| Error::BadDyldCache("local-symbols range overflows".to_owned()))?;
    let blob: &[u8] = file.bytes.get(start..end).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "local-symbols range [{start}, {end}) exceeds the {}-byte cache file '{}'",
            file.bytes.len(),
            file.label
        ))
    })?;
    let nlist_offset: u32 = u32_at(blob, 0, "local-symbols nlist offset")?;
    let nlist_count: u32 = u32_at(blob, 4, "local-symbols nlist count")?;
    let strings_offset: u32 = u32_at(blob, 8, "local-symbols strings offset")?;
    let strings_size: u32 = u32_at(blob, 12, "local-symbols strings size")?;
    let entries_offset: u32 = u32_at(blob, 16, "local-symbols entries offset")?;
    let entries_count: u32 = u32_at(blob, 20, "local-symbols entries count")?;
    if entries_count as usize > MAX_LOCAL_SYMBOL_ENTRIES {
        return Err(Error::BadDyldCache(format!(
            "local-symbols entry count {entries_count} exceeds the {MAX_LOCAL_SYMBOL_ENTRIES} cap"
        )));
    }
    let wide: bool = parsed.layout.has_sub_caches();
    let entry_size: usize = if wide {
        LOCAL_SYMBOLS_ENTRY_64_SIZE
    } else {
        LOCAL_SYMBOLS_ENTRY_32_SIZE
    };
    let wanted: u64 = if wide {
        image.address.wrapping_sub(parsed.base_address())
    } else {
        map_vmaddr(&parsed.mappings, image.address).unwrap_or(usize::MAX) as u64
    };
    for index in 0..entries_count as usize {
        let at: usize = (entries_offset as usize)
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                Error::BadDyldCache("local-symbols entry offset overflows".to_owned())
            })?)
            .ok_or_else(|| {
                Error::BadDyldCache("local-symbols entry offset overflows".to_owned())
            })?;
        let (dylib_offset, start_index, count): (u64, u32, u32) = if wide {
            (
                u64_at(blob, at, "local-symbols dylib offset")?,
                u32_at(blob, at + 8, "local-symbols start index")?,
                u32_at(blob, at + 12, "local-symbols count")?,
            )
        } else {
            (
                u64::from(u32_at(blob, at, "local-symbols dylib offset")?),
                u32_at(blob, at + 4, "local-symbols start index")?,
                u32_at(blob, at + 8, "local-symbols count")?,
            )
        };
        if dylib_offset != wanted {
            continue;
        }
        let mut owned: Vec<u8> = Vec::with_capacity(32);
        owned.extend_from_slice(&nlist_offset.to_le_bytes());
        owned.extend_from_slice(&nlist_count.to_le_bytes());
        owned.extend_from_slice(&strings_offset.to_le_bytes());
        owned.extend_from_slice(&strings_size.to_le_bytes());
        owned.extend_from_slice(&start_index.to_le_bytes());
        owned.extend_from_slice(&count.to_le_bytes());
        owned.extend_from_slice(blob);
        return Ok(owned);
    }
    Ok(Vec::new())
}

fn local_symbol_run<'a>(storage: &'a [u8], macho: &ParsedSlice) -> Option<LocalSymbolRun<'a>> {
    if storage.len() < 24 {
        return None;
    }
    let nlist_offset: u32 = read_u32_le_at(storage, 0).ok()?;
    let nlist_count: u32 = read_u32_le_at(storage, 4).ok()?;
    let strings_offset: u32 = read_u32_le_at(storage, 8).ok()?;
    let strings_size: u32 = read_u32_le_at(storage, 12).ok()?;
    let start_index: u32 = read_u32_le_at(storage, 16).ok()?;
    let count: u32 = read_u32_le_at(storage, 20).ok()?;
    if count == 0 {
        return None;
    }
    let blob: &[u8] = storage.get(24..)?;
    let entry_size: usize = match macho.header.bitness {
        Bitness::Bits64 => linkedit::NLIST_64_SIZE,
        Bitness::Bits32 => linkedit::NLIST_32_SIZE,
    };
    let end_index: u32 = start_index.checked_add(count)?;
    if end_index > nlist_count {
        return None;
    }
    let nlist_start: usize =
        (nlist_offset as usize).checked_add((start_index as usize).checked_mul(entry_size)?)?;
    let nlist_end: usize = nlist_start.checked_add((count as usize).checked_mul(entry_size)?)?;
    let nlist: &[u8] = blob.get(nlist_start..nlist_end)?;
    let strings_start: usize = strings_offset as usize;
    let strings_end: usize = strings_start
        .checked_add(strings_size as usize)?
        .min(blob.len());
    let strings: &[u8] = blob.get(strings_start..strings_end)?;
    Some(LocalSymbolRun {
        nlist,
        strings,
        count: count as usize,
    })
}

#[derive(Debug, Clone, Copy)]
struct SegmentFields {
    vmsize: usize,
    fileoff: usize,
    filesize: usize,
    nsects: usize,
    sections_start: usize,
    section_size: usize,
    section_offset: usize,
    width: usize,
}

impl SegmentFields {
    const fn for_bitness(is_64: bool) -> Self {
        if is_64 {
            Self {
                vmsize: SEG64_VMSIZE_FIELD,
                fileoff: SEG64_FILEOFF_FIELD,
                filesize: SEG64_FILESIZE_FIELD,
                nsects: SEG64_NSECTS_FIELD,
                sections_start: SEG64_SECTIONS_START,
                section_size: SEG64_SECTION_SIZE,
                section_offset: SEG64_SECTION_OFFSET_FIELD,
                width: 8,
            }
        } else {
            Self {
                vmsize: SEG32_VMSIZE_FIELD,
                fileoff: SEG32_FILEOFF_FIELD,
                filesize: SEG32_FILESIZE_FIELD,
                nsects: SEG32_NSECTS_FIELD,
                sections_start: SEG32_SECTIONS_START,
                section_size: SEG32_SECTION_SIZE,
                section_offset: SEG32_SECTION_OFFSET_FIELD,
                width: 4,
            }
        }
    }
}

fn patch_segment(
    output: &mut [u8],
    lc: &LoadCommand,
    seg: &Segment,
    placement: &Placement,
    fields: SegmentFields,
    page_size: u64,
    resized: bool,
) -> Result<()> {
    write_sized_field(
        output,
        lc.data_offset,
        fields.fileoff,
        placement.file_offset,
        fields.width,
    )?;
    if resized {
        let size: u64 = placement.bytes.len() as u64;
        write_sized_field(output, lc.data_offset, fields.filesize, size, fields.width)?;
        write_sized_field(
            output,
            lc.data_offset,
            fields.vmsize,
            align_up_u64(size, page_size),
            fields.width,
        )?;
        return Ok(());
    }
    if placement.bytes.is_empty() {
        return Ok(());
    }
    let nsects: u32 = read_u32_le_at(output, lc.data_offset + fields.nsects).map_err(
        |error: ByteReadError| {
            Error::BadDyldCache(format!("segment '{}' section count: {error}", seg.name))
        },
    )?;
    let declared: usize = nsects as usize;
    if declared != seg.sections.len() {
        return Err(Error::BadDyldCache(format!(
            "segment '{}' declares {declared} sections but {} parsed",
            seg.name,
            seg.sections.len()
        )));
    }
    for (index, section) in seg.sections.iter().enumerate() {
        let at: usize = lc
            .data_offset
            .checked_add(fields.sections_start)
            .and_then(|base: usize| base.checked_add(index.checked_mul(fields.section_size)?))
            .ok_or_else(|| Error::BadDyldCache("section field offset overflows".to_owned()))?;
        let offset_at: usize = at
            .checked_add(fields.section_offset)
            .ok_or_else(|| Error::BadDyldCache("section offset field overflows".to_owned()))?;
        if section.offset == 0 {
            continue;
        }
        let delta: u64 = section.addr.checked_sub(seg.vmaddr).ok_or_else(|| {
            Error::BadDyldCache(format!(
                "section '{}' at {:#x} precedes its segment '{}' at {:#x}",
                section.name, section.addr, seg.name, seg.vmaddr
            ))
        })?;
        let new_offset: u64 = placement
            .file_offset
            .checked_add(delta)
            .ok_or_else(|| Error::BadDyldCache("section file offset overflows".to_owned()))?;
        write_u32_field(output, offset_at, new_offset)?;
    }
    Ok(())
}

fn write_sized_field(
    output: &mut [u8],
    data_offset: usize,
    field: usize,
    value: u64,
    width: usize,
) -> Result<()> {
    let at: usize = data_offset
        .checked_add(field)
        .ok_or_else(|| Error::BadDyldCache("segment field offset overflows".to_owned()))?;
    let end: usize = at
        .checked_add(width)
        .ok_or_else(|| Error::BadDyldCache("segment field end overflows".to_owned()))?;
    let slot: &mut [u8] = output.get_mut(at..end).ok_or_else(|| {
        Error::BadDyldCache(
            "segment field falls outside the reconstructed header segment".to_owned(),
        )
    })?;
    if width == 8 {
        slot.copy_from_slice(&value.to_le_bytes());
        return Ok(());
    }
    let narrowed: u32 = u32::try_from(value)
        .map_err(|_| Error::BadDyldCache("32-bit segment field exceeds u32 range".to_owned()))?;
    slot.copy_from_slice(&narrowed.to_le_bytes());
    Ok(())
}

fn write_u32_field(output: &mut [u8], at: usize, value: u64) -> Result<()> {
    let end: usize = at
        .checked_add(4)
        .ok_or_else(|| Error::BadDyldCache("load-command field end overflows".to_owned()))?;
    let slot: &mut [u8] = output.get_mut(at..end).ok_or_else(|| {
        Error::BadDyldCache(
            "load-command field falls outside the reconstructed header segment".to_owned(),
        )
    })?;
    let narrowed: u32 = u32::try_from(value).map_err(|_| {
        Error::BadDyldCache("reconstructed linkedit offset exceeds u32 range".to_owned())
    })?;
    slot.copy_from_slice(&narrowed.to_le_bytes());
    Ok(())
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

    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const CPU_ARM64: u32 = 0x0100_000C;
    const CPU_SUB_ARM64_ALL: u32 = 0x0000_0000;
    const MH_DYLIB: u32 = 0x6;
    const LC_SEG_64: u32 = 0x19;

    const TEXT_VMADDR: u64 = 0x1_8000_0000;
    const DATA_VMADDR: u64 = 0x1_8000_4000;
    const LINKEDIT_VMADDR: u64 = 0x1_8000_8000;

    const TEXT_FILESIZE: u64 = 0x100;
    const DATA_FILESIZE: u64 = 0x40;
    const LINKEDIT_FILESIZE: u64 = 0x30;

    const MAP1_FILEOFF: u64 = 0x4000;
    const MAP2_FILEOFF: u64 = 0xC000;
    const MAP3_FILEOFF: u64 = 0x1_4000;

    const INSTALL_NAME: &str = "/usr/lib/libExample.dylib";

    fn seg_command(name: &str, vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        let mut cmd: Vec<u8> = Vec::with_capacity(72);
        cmd.extend_from_slice(&LC_SEG_64.to_le_bytes());
        cmd.extend_from_slice(&72u32.to_le_bytes());
        let mut seg_name: [u8; 16] = [0u8; 16];
        let raw: &[u8] = name.as_bytes();
        seg_name[..raw.len()].copy_from_slice(raw);
        cmd.extend_from_slice(&seg_name);
        cmd.extend_from_slice(&vmaddr.to_le_bytes());
        cmd.extend_from_slice(&vmsize.to_le_bytes());
        cmd.extend_from_slice(&fileoff.to_le_bytes());
        cmd.extend_from_slice(&filesize.to_le_bytes());
        cmd.extend_from_slice(&7u32.to_le_bytes());
        cmd.extend_from_slice(&5u32.to_le_bytes());
        cmd.extend_from_slice(&0u32.to_le_bytes());
        cmd.extend_from_slice(&0u32.to_le_bytes());
        cmd
    }

    fn build_standalone_dylib() -> Vec<u8> {
        let text_cmd: Vec<u8> = seg_command("__TEXT", TEXT_VMADDR, TEXT_FILESIZE, 0, TEXT_FILESIZE);
        let data_cmd: Vec<u8> = seg_command(
            "__DATA",
            DATA_VMADDR,
            DATA_FILESIZE,
            TEXT_FILESIZE,
            DATA_FILESIZE,
        );
        let linkedit_cmd: Vec<u8> = seg_command(
            "__LINKEDIT",
            LINKEDIT_VMADDR,
            LINKEDIT_FILESIZE,
            TEXT_FILESIZE + DATA_FILESIZE,
            LINKEDIT_FILESIZE,
        );
        let sizeofcmds: u32 = (text_cmd.len() + data_cmd.len() + linkedit_cmd.len()) as u32;

        let mut header: Vec<u8> = Vec::with_capacity(32);
        header.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        header.extend_from_slice(&CPU_ARM64.to_le_bytes());
        header.extend_from_slice(&CPU_SUB_ARM64_ALL.to_le_bytes());
        header.extend_from_slice(&MH_DYLIB.to_le_bytes());
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&sizeofcmds.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        let mut dylib: Vec<u8> = Vec::new();
        dylib.extend_from_slice(&header);
        dylib.extend_from_slice(&text_cmd);
        dylib.extend_from_slice(&data_cmd);
        dylib.extend_from_slice(&linkedit_cmd);
        assert!(
            dylib.len() as u64 <= TEXT_FILESIZE,
            "load commands must fit __TEXT"
        );
        dylib.resize(TEXT_FILESIZE as usize, 0xCC);
        for i in 0..DATA_FILESIZE as usize {
            dylib.push((0x40 + (i & 0x0F)) as u8);
        }
        for i in 0..LINKEDIT_FILESIZE as usize {
            dylib.push((0x80 + (i & 0x0F)) as u8);
        }
        assert_eq!(
            dylib.len() as u64,
            TEXT_FILESIZE + DATA_FILESIZE + LINKEDIT_FILESIZE
        );
        dylib
    }

    fn write_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_cache(dylib: &[u8]) -> Vec<u8> {
        let mapping_offset: u32 = 0x100;
        let images_offset: u32 = 0x200;
        let name_offset: u32 = 0x240;
        let cache_len: usize = (MAP3_FILEOFF + LINKEDIT_FILESIZE) as usize;
        let mut cache: Vec<u8> = vec![0u8; cache_len];

        let mut magic: [u8; MAGIC_LEN] = [0u8; MAGIC_LEN];
        let magic_str: &[u8] = b"dyld_v1  arm64e";
        magic[..magic_str.len()].copy_from_slice(magic_str);
        cache[..MAGIC_LEN].copy_from_slice(&magic);

        write_u32(&mut cache, MAPPING_OFFSET_FIELD, mapping_offset);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, 3);
        write_u32(&mut cache, IMAGES_OFFSET_OLD_FIELD, images_offset);
        write_u32(&mut cache, IMAGES_COUNT_OLD_FIELD, 1);

        let mapping_specs: [(u64, u64, u64); 3] = [
            (TEXT_VMADDR, 0x4000, MAP1_FILEOFF),
            (DATA_VMADDR, 0x4000, MAP2_FILEOFF),
            (LINKEDIT_VMADDR, 0x4000, MAP3_FILEOFF),
        ];
        for (i, (addr, size, fileoff)) in mapping_specs.iter().enumerate() {
            let off: usize = mapping_offset as usize + i * MAPPING_INFO_SIZE;
            write_u64(&mut cache, off, *addr);
            write_u64(&mut cache, off + 8, *size);
            write_u64(&mut cache, off + 16, *fileoff);
            write_u32(&mut cache, off + 24, 5);
            write_u32(&mut cache, off + 28, 5);
        }

        let img_off: usize = images_offset as usize;
        write_u64(&mut cache, img_off, TEXT_VMADDR);
        write_u64(&mut cache, img_off + 8, 0);
        write_u64(&mut cache, img_off + 16, 0);
        write_u32(&mut cache, img_off + 24, name_offset);
        write_u32(&mut cache, img_off + 28, 0);

        let name_bytes: &[u8] = INSTALL_NAME.as_bytes();
        let name_at: usize = name_offset as usize;
        cache[name_at..name_at + name_bytes.len()].copy_from_slice(name_bytes);

        let text: &[u8] = &dylib[..TEXT_FILESIZE as usize];
        let data: &[u8] = &dylib[TEXT_FILESIZE as usize..(TEXT_FILESIZE + DATA_FILESIZE) as usize];
        let linkedit: &[u8] = &dylib[(TEXT_FILESIZE + DATA_FILESIZE) as usize..];

        let mut cached_text: Vec<u8> = text.to_vec();
        write_u64(&mut cached_text, 32 + SEG64_FILEOFF_FIELD, MAP1_FILEOFF);
        write_u64(&mut cached_text, 104 + SEG64_FILEOFF_FIELD, MAP2_FILEOFF);
        write_u64(&mut cached_text, 176 + SEG64_FILEOFF_FIELD, MAP3_FILEOFF);

        let t: usize = MAP1_FILEOFF as usize;
        cache[t..t + cached_text.len()].copy_from_slice(&cached_text);
        let d: usize = MAP2_FILEOFF as usize;
        cache[d..d + data.len()].copy_from_slice(data);
        let l: usize = MAP3_FILEOFF as usize;
        cache[l..l + linkedit.len()].copy_from_slice(linkedit);

        cache
    }

    #[test]
    fn parses_header_mappings_and_images() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        assert!(is_dyld_shared_cache(&cache));
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        assert_eq!(parsed.arch, "arm64e");
        assert_eq!(parsed.mappings.len(), 3);
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].address, TEXT_VMADDR);
        assert_eq!(parsed.images[0].install_name, INSTALL_NAME);
        assert_eq!(parsed.mappings[1].file_offset, MAP2_FILEOFF);
    }

    #[test]
    fn reconstructs_bundled_dylib_byte_for_byte() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let recovered: ReconstructedDylib =
            reconstruct_image(&cache, &parsed, 0).expect("image reconstructs");
        assert_eq!(recovered.install_name, INSTALL_NAME);
        assert_eq!(recovered.image_address, TEXT_VMADDR);
        assert_eq!(recovered.header_file_offset, MAP1_FILEOFF as usize);
        assert_eq!(recovered.segment_count, 3);
        assert_eq!(recovered.bytes, dylib, "un-bundled dylib matches original");
        let reparsed: ParsedSlice =
            macho::parse_slice(&recovered.bytes).expect("recovered image parses via macho");
        assert_eq!(reparsed.segments.len(), 3);
        assert_eq!(reparsed.segments[0].name, "__TEXT");
        assert_eq!(reparsed.segments[0].fileoff, 0);
        assert_eq!(reparsed.segments[1].fileoff, TEXT_FILESIZE);
        assert_eq!(reparsed.segments[2].fileoff, TEXT_FILESIZE + DATA_FILESIZE);
    }

    #[test]
    fn reconstruct_by_name_matches_index() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let by_name: ReconstructedDylib =
            reconstruct_by_name(&cache, &parsed, INSTALL_NAME).expect("named image reconstructs");
        assert_eq!(by_name.bytes, dylib);
    }

    #[test]
    fn reconstruct_all_respects_image_list() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let all: Vec<ReconstructedDylib> =
            reconstruct_all(&cache, &parsed).expect("all images reconstruct");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].bytes, dylib);
    }

    #[test]
    fn page_aligned_layout_places_every_segment_on_a_page_boundary() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let options: ReconstructOptions = ReconstructOptions {
            layout: SegmentLayout::PageAligned,
            page_size: DEFAULT_PAGE_SIZE,
            synthesize_linkedit: false,
            unapply_slide: false,
        };
        let recovered: ReconstructedDylib =
            reconstruct_image_with(&cache, &parsed, 0, options).expect("image reconstructs");
        assert!(recovered.page_aligned);
        assert_eq!(recovered.bytes.len() as u64 % DEFAULT_PAGE_SIZE, 0);
        let reparsed: ParsedSlice =
            macho::parse_slice(&recovered.bytes).expect("page-aligned image parses");
        for segment in &reparsed.segments {
            assert_eq!(
                segment.fileoff % DEFAULT_PAGE_SIZE,
                0,
                "segment '{}' at file offset {} is not page aligned",
                segment.name,
                segment.fileoff
            );
        }
        assert_eq!(reparsed.segments[1].fileoff, DEFAULT_PAGE_SIZE);
        assert_eq!(reparsed.segments[2].fileoff, DEFAULT_PAGE_SIZE * 2);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut cache: Vec<u8> = vec![0u8; 64];
        cache[..4].copy_from_slice(b"PK\x03\x04");
        assert!(!is_dyld_shared_cache(&cache));
        assert!(matches!(parse(&cache), Err(Error::NotDyldCache)));
    }

    #[test]
    fn rejects_mapping_table_past_cache_length() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, 100_000);
        assert!(matches!(parse(&cache), Err(Error::BadDyldCache(_))));
    }

    #[test]
    fn rejects_image_address_outside_mappings() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        let img_off: usize = 0x200;
        write_u64(&mut cache, img_off, 0x7F00_0000_0000);
        let parsed: DyldSharedCache = parse(&cache).expect("cache still parses");
        assert!(matches!(
            reconstruct_image(&cache, &parsed, 0),
            Err(Error::DyldImageUnsupported { .. })
        ));
    }

    #[test]
    fn rejects_mapping_count_over_cap() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, (MAX_MAPPINGS + 1) as u32);
        assert!(matches!(parse(&cache), Err(Error::BadDyldCache(_))));
    }

    #[test]
    fn refuses_a_header_too_small_to_carry_the_mapping_and_image_tables() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        write_u32(&mut cache, MAPPING_OFFSET_FIELD, 0x18);
        let refusal: Error = parse(&cache).expect_err("a 0x18-byte header names no image table");
        assert!(
            matches!(refusal, Error::UnsupportedDyldLayout { .. }),
            "got {refusal}"
        );
        assert!(format!("{refusal}").contains("header-size-0x18"));
    }

    #[test]
    fn the_layout_ladder_names_each_documented_header_size() {
        assert_eq!(CacheHeaderLayout::from_header_size(0x1F), None);
        assert_eq!(
            CacheHeaderLayout::from_header_size(0x20),
            Some(CacheHeaderLayout::Legacy)
        );
        assert_eq!(
            CacheHeaderLayout::from_header_size(0x58),
            Some(CacheHeaderLayout::LocalSymbols)
        );
        assert_eq!(
            CacheHeaderLayout::from_header_size(0x140),
            Some(CacheHeaderLayout::SlideMappings)
        );
        assert_eq!(
            CacheHeaderLayout::from_header_size(0x190),
            Some(CacheHeaderLayout::SubCaches)
        );
        assert_eq!(
            CacheHeaderLayout::from_header_size(0x1C8),
            Some(CacheHeaderLayout::RelocatedImages)
        );
        assert!(CacheHeaderLayout::RelocatedImages.has_sub_caches());
        assert!(!CacheHeaderLayout::Legacy.has_slide_mappings());
    }

    #[test]
    fn a_mapping_that_runs_past_the_file_is_recorded_rather_than_silently_trusted() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        assert!(
            parsed.truncated_mappings.contains(&2),
            "the linkedit mapping claims 0x4000 bytes in a shorter file, so it must be recorded"
        );
        assert!(parsed.overlapping_mappings.is_empty());
    }

    #[test]
    fn overlapping_mappings_are_recorded_as_a_pair() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        let second: usize = 0x100 + MAPPING_INFO_SIZE;
        write_u64(&mut cache, second, TEXT_VMADDR);
        let parsed: DyldSharedCache = parse(&cache).expect("cache still parses");
        assert_eq!(parsed.overlapping_mappings, vec![(0, 1)]);
    }

    #[test]
    fn short_and_random_inputs_never_panic() {
        for len in 0usize..40 {
            let buf: Vec<u8> = vec![0x11u8; len];
            let _ = parse(&buf);
            let _ = is_dyld_shared_cache(&buf);
        }
        let mut crafted: Vec<u8> = vec![0u8; 0x40];
        crafted[..7].copy_from_slice(MAGIC_PREFIX);
        write_u32(&mut crafted, MAPPING_OFFSET_FIELD, u32::MAX);
        write_u32(&mut crafted, MAPPING_COUNT_FIELD, u32::MAX);
        write_u32(&mut crafted, IMAGES_OFFSET_OLD_FIELD, u32::MAX);
        write_u32(&mut crafted, IMAGES_COUNT_OLD_FIELD, u32::MAX);
        assert!(parse(&crafted).is_err());
    }
}
