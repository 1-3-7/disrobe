use disrobe_pass_swift_objc::macho::{
    self, Bitness, LC_SEGMENT_64, LoadCommand, ParsedSlice, Section, Segment,
};

pub(crate) const CACHE_PAGE: u64 = 0x4000;
pub(crate) const TABLE_AREA: u64 = 0x4000;

const MAGIC_LEN: usize = 16;
const MAPPING_OFFSET_FIELD: usize = 0x10;
const MAPPING_COUNT_FIELD: usize = 0x14;
const IMAGES_OFFSET_OLD_FIELD: usize = 0x18;
const IMAGES_COUNT_OLD_FIELD: usize = 0x1C;
const LOCAL_SYMBOLS_OFFSET_FIELD: usize = 0x48;
const LOCAL_SYMBOLS_SIZE_FIELD: usize = 0x50;
const UUID_FIELD: usize = 0x58;
const SHARED_REGION_START_FIELD: usize = 0xE0;
const MAPPING_WITH_SLIDE_OFFSET_FIELD: usize = 0x138;
const MAPPING_WITH_SLIDE_COUNT_FIELD: usize = 0x13C;
const SUBCACHE_ARRAY_OFFSET_FIELD: usize = 0x188;
const SUBCACHE_ARRAY_COUNT_FIELD: usize = 0x18C;
const SYMBOL_FILE_UUID_FIELD: usize = 0x190;
const IMAGES_OFFSET_NEW_FIELD: usize = 0x1C0;
const IMAGES_COUNT_NEW_FIELD: usize = 0x1C4;

const MAPPING_INFO_SIZE: usize = 32;
const MAPPING_AND_SLIDE_INFO_SIZE: usize = 56;
const IMAGE_INFO_SIZE: usize = 32;
const SUBCACHE_ENTRY_SIZE: usize = 56;
const SUBCACHE_ENTRY_V1_SIZE: usize = 24;
const FORMAT_FLAGS_FIELD: usize = 0xDC;

const SEG64_FILEOFF: usize = 40;
const SEG64_NSECTS: usize = 64;
const SEG64_SECTIONS_START: usize = 72;
const SEG64_SECTION_SIZE: usize = 80;
const SEG64_SECTION_OFFSET: usize = 48;

const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderShape {
    Legacy,
    LocalSymbols,
    SlideMappings,
    SubCachesNoSuffix,
    SubCaches,
}

impl HeaderShape {
    pub(crate) const fn header_size(self) -> u64 {
        match self {
            Self::Legacy => 0x30,
            Self::LocalSymbols => 0x80,
            Self::SlideMappings => 0x140,
            Self::SubCachesNoSuffix => 0x1A0,
            Self::SubCaches => 0x1D0,
        }
    }

    pub(crate) const fn has_slide_mappings(self) -> bool {
        matches!(
            self,
            Self::SlideMappings | Self::SubCachesNoSuffix | Self::SubCaches
        )
    }

    pub(crate) const fn has_sub_caches(self) -> bool {
        matches!(self, Self::SubCachesNoSuffix | Self::SubCaches)
    }

    pub(crate) const fn uses_relocated_images(self) -> bool {
        matches!(self, Self::SubCaches)
    }

    pub(crate) const fn carries_format_flags(self) -> bool {
        matches!(
            self,
            Self::SlideMappings | Self::SubCachesNoSuffix | Self::SubCaches
        )
    }

    pub(crate) const fn sub_cache_entry_size(self) -> usize {
        if matches!(self, Self::SubCaches) {
            SUBCACHE_ENTRY_SIZE
        } else {
            SUBCACHE_ENTRY_V1_SIZE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthSpec {
    pub(crate) key: u8,
    pub(crate) diversity: u16,
    pub(crate) address_diversity: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SlidePlan {
    pub(crate) version: u32,
    pub(crate) value_add: u64,
    pub(crate) delta_mask: u64,
    pub(crate) targets: Vec<(u64, Option<AuthSpec>)>,
}

impl SlidePlan {
    pub(crate) const fn pointer_width(&self) -> u64 {
        match self.version {
            1 | 4 => 4,
            _ => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlideExpectation {
    pub(crate) vm_address: u64,
    pub(crate) unslid: u64,
    pub(crate) raw: u64,
    pub(crate) width: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheSpec {
    pub(crate) arch: String,
    pub(crate) shape: HeaderShape,
    pub(crate) install_name: String,
    pub(crate) split_linkedit: bool,
    pub(crate) emit_sibling: bool,
    pub(crate) declared_suffix: Option<String>,
    pub(crate) slide: Option<SlidePlan>,
    pub(crate) local_symbols: Vec<String>,
    pub(crate) emit_symbols_file: bool,
    pub(crate) format_flags: u32,
    pub(crate) extra_sub_caches: u32,
}

pub(crate) const EXTRA_SUB_CACHE_VM_STEP: u64 = 0x1000_0000;
pub(crate) const SLIDE_TAIL_SENTINEL: u64 = 0xA5A5_A5A5_A5A5_A5A5;

impl CacheSpec {
    pub(crate) fn modern(install_name: &str) -> Self {
        Self {
            arch: "arm64e".to_owned(),
            shape: HeaderShape::SubCaches,
            install_name: install_name.to_owned(),
            split_linkedit: false,
            emit_sibling: false,
            declared_suffix: None,
            slide: None,
            local_symbols: Vec::new(),
            emit_symbols_file: false,
            format_flags: 0,
            extra_sub_caches: 0,
        }
    }

    pub(crate) const fn with_extra_sub_cache_entries(mut self, extra: u32) -> Self {
        self.extra_sub_caches = extra;
        self
    }

    pub(crate) fn with_arch(mut self, arch: &str) -> Self {
        arch.clone_into(&mut self.arch);
        self
    }

    pub(crate) const fn with_format_flags(mut self, flags: u32) -> Self {
        self.format_flags = flags;
        self
    }

    pub(crate) fn with_local_symbols(mut self, names: &[&str]) -> Self {
        self.local_symbols = names.iter().map(|name: &&str| (*name).to_owned()).collect();
        self.emit_symbols_file = true;
        self.shape = HeaderShape::SubCaches;
        self
    }

    pub(crate) const fn without_symbols_file(mut self) -> Self {
        self.emit_symbols_file = false;
        self
    }

    pub(crate) fn with_local_symbols_in_primary(mut self, names: &[&str]) -> Self {
        self.local_symbols = names.iter().map(|name: &&str| (*name).to_owned()).collect();
        self.emit_symbols_file = false;
        self.shape = HeaderShape::SlideMappings;
        self
    }

    pub(crate) const fn with_shape(mut self, shape: HeaderShape) -> Self {
        self.shape = shape;
        self
    }

    pub(crate) const fn split(mut self) -> Self {
        self.split_linkedit = true;
        self.emit_sibling = true;
        self.shape = HeaderShape::SubCaches;
        self
    }

    pub(crate) const fn without_sibling_file(mut self) -> Self {
        self.emit_sibling = false;
        self
    }

    pub(crate) fn with_declared_suffix(mut self, suffix: &str) -> Self {
        self.declared_suffix = Some(suffix.to_owned());
        self.shape = HeaderShape::SubCaches;
        self
    }

    pub(crate) fn with_slide(mut self, plan: SlidePlan) -> Self {
        self.slide = Some(plan);
        self.shape = HeaderShape::SubCaches;
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PlacedSegment {
    pub(crate) name: String,
    pub(crate) vmaddr: u64,
    pub(crate) filesize: u64,
    pub(crate) original_fileoff: u64,
    pub(crate) cache_offset: u64,
    pub(crate) in_sibling: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BuiltCache {
    pub(crate) primary: Vec<u8>,
    pub(crate) sibling: Option<Vec<u8>>,
    pub(crate) symbols: Option<Vec<u8>>,
    pub(crate) image_address: u64,
    pub(crate) segments: Vec<PlacedSegment>,
    pub(crate) slide_expectations: Vec<SlideExpectation>,
    pub(crate) slide_blob_offset: Option<u64>,
}

impl BuiltCache {
    pub(crate) fn segment(&self, name: &str) -> &PlacedSegment {
        self.segments
            .iter()
            .find(|seg: &&PlacedSegment| seg.name == name)
            .unwrap_or_else(|| panic!("the fixture image carries no '{name}' segment"))
    }
}

fn write_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    let mut raw: [u8; 4] = [0u8; 4];
    raw.copy_from_slice(&buf[at..at + 4]);
    u32::from_le_bytes(raw)
}

const fn align_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

fn magic_bytes(arch: &str) -> [u8; MAGIC_LEN] {
    let mut magic: [u8; MAGIC_LEN] = [0u8; MAGIC_LEN];
    let text: String = format!("dyld_v1  {arch}");
    let raw: &[u8] = text.as_bytes();
    assert!(
        raw.len() < MAGIC_LEN,
        "cache magic must stay NUL-terminated"
    );
    magic[..raw.len()].copy_from_slice(raw);
    magic
}

pub(crate) fn build(image: &[u8], spec: &CacheSpec) -> BuiltCache {
    let parsed: ParsedSlice = macho::parse_slice(image).expect("fixture image parses");
    assert!(
        matches!(parsed.header.bitness, Bitness::Bits64),
        "the cache fixture builder writes 64-bit mach headers only"
    );

    let mut placed: Vec<PlacedSegment> = Vec::new();
    let mut primary_cursor: u64 = TABLE_AREA;
    let mut sibling_cursor: u64 = TABLE_AREA;
    for segment in &parsed.segments {
        if segment.filesize == 0 {
            continue;
        }
        let in_sibling: bool = spec.split_linkedit && segment.name == "__LINKEDIT";
        let cursor: &mut u64 = if in_sibling {
            &mut sibling_cursor
        } else {
            &mut primary_cursor
        };
        let cache_offset: u64 = *cursor;
        *cursor = align_up(cache_offset + segment.filesize, CACHE_PAGE);
        placed.push(PlacedSegment {
            name: segment.name.clone(),
            vmaddr: segment.vmaddr,
            filesize: segment.filesize,
            original_fileoff: segment.fileoff,
            cache_offset,
            in_sibling,
        });
    }
    assert!(
        !placed.is_empty(),
        "the fixture image carries no segment with file content"
    );

    let mut primary: Vec<u8> = vec![0u8; primary_cursor as usize];
    let mut sibling: Vec<u8> = vec![0u8; sibling_cursor as usize];
    for entry in &placed {
        let start: usize = entry.original_fileoff as usize;
        let end: usize = start + entry.filesize as usize;
        let source: &[u8] = image
            .get(start..end)
            .unwrap_or_else(|| panic!("segment '{}' leaves the fixture image", entry.name));
        let target: &mut Vec<u8> = if entry.in_sibling {
            &mut sibling
        } else {
            &mut primary
        };
        let at: usize = entry.cache_offset as usize;
        target[at..at + source.len()].copy_from_slice(source);
    }

    let text: &PlacedSegment = placed
        .iter()
        .find(|entry: &&PlacedSegment| entry.name == "__TEXT")
        .expect("the fixture image carries a __TEXT segment");
    let linkedit: Option<&PlacedSegment> = placed
        .iter()
        .find(|entry: &&PlacedSegment| entry.name == "__LINKEDIT");

    patch_header_in_place(&mut primary, text.cache_offset as usize, &parsed, &placed);

    let linkedit_delta: i64 = linkedit.map_or(0, |entry: &PlacedSegment| {
        entry.cache_offset as i64 - entry.original_fileoff as i64
    });
    patch_linkedit_commands(
        &mut primary,
        text.cache_offset as usize,
        &parsed,
        linkedit_delta,
    );

    let slide_expectations: Vec<SlideExpectation> = spec
        .slide
        .as_ref()
        .map_or_else(Vec::new, |plan: &SlidePlan| {
            encode_slide_pointers(&mut primary, &placed, plan)
        });

    let in_primary_locals: Option<(u64, usize)> =
        (!spec.local_symbols.is_empty() && !spec.shape.has_sub_caches()).then(|| {
            let blob: Vec<u8> = local_symbols_blob(spec, text.vmaddr, text.cache_offset);
            let at: u64 = primary.len() as u64;
            primary.extend_from_slice(&blob);
            primary.resize(align_up(primary.len() as u64, CACHE_PAGE) as usize, 0);
            (at, blob.len())
        });

    let slide_blob_offset: Option<u64> =
        write_primary_header(&mut primary, spec, &placed, text.vmaddr);
    if let Some((at, len)) = in_primary_locals {
        write_u64(&mut primary, LOCAL_SYMBOLS_OFFSET_FIELD, at);
        write_u64(&mut primary, LOCAL_SYMBOLS_SIZE_FIELD, len as u64);
    }
    if spec.split_linkedit {
        write_sibling_header(&mut sibling, spec, &placed);
    }

    let symbols: Option<Vec<u8>> = (!spec.local_symbols.is_empty() && spec.emit_symbols_file)
        .then(|| build_symbols_file(spec, text.vmaddr));

    BuiltCache {
        primary,
        sibling: (spec.split_linkedit && spec.emit_sibling).then_some(sibling),
        symbols,
        image_address: text.vmaddr,
        segments: placed,
        slide_expectations,
        slide_blob_offset,
    }
}

fn patch_header_in_place(
    cache: &mut [u8],
    header_at: usize,
    parsed: &ParsedSlice,
    placed: &[PlacedSegment],
) {
    let seg_lcs: Vec<&LoadCommand> = parsed
        .load_commands
        .iter()
        .filter(|lc: &&LoadCommand| lc.cmd == LC_SEGMENT_64)
        .collect();
    for (segment, lc) in parsed.segments.iter().zip(seg_lcs.iter()) {
        let entry: Option<&PlacedSegment> = placed
            .iter()
            .find(|entry: &&PlacedSegment| entry.name == segment.name);
        let Some(entry) = entry else {
            continue;
        };
        let base: usize = header_at + lc.data_offset;
        write_u64(cache, base + SEG64_FILEOFF, entry.cache_offset);
        let declared: u32 = read_u32(cache, base + SEG64_NSECTS);
        assert_eq!(
            declared as usize,
            segment.sections.len(),
            "segment '{}' section count must agree with the parse",
            segment.name
        );
        for (index, section) in segment.sections.iter().enumerate() {
            let section: &Section = section;
            if section.offset == 0 {
                continue;
            }
            let at: usize = base + SEG64_SECTIONS_START + index * SEG64_SECTION_SIZE;
            let delta: u64 = section.addr - segment.vmaddr;
            write_u32(
                cache,
                at + SEG64_SECTION_OFFSET,
                (entry.cache_offset + delta) as u32,
            );
        }
    }
}

fn patch_linkedit_commands(cache: &mut [u8], header_at: usize, parsed: &ParsedSlice, delta: i64) {
    if delta == 0 {
        return;
    }
    for lc in &parsed.load_commands {
        let lc: &LoadCommand = lc;
        let base: usize = header_at + lc.data_offset;
        let fields: &[usize] = match lc.cmd {
            LC_SYMTAB => &[8, 16],
            LC_DYSYMTAB => &[32, 40, 48, 56, 64, 72],
            LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS => &[8],
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => &[8, 16, 24, 32, 40],
            _ => continue,
        };
        for field in fields {
            let at: usize = base + field;
            let current: u32 = read_u32(cache, at);
            if current == 0 {
                continue;
            }
            let moved: i64 = i64::from(current) + delta;
            assert!(moved >= 0, "a linkedit offset moved before the cache start");
            write_u32(cache, at, moved as u32);
        }
    }
}

fn write_primary_header(
    cache: &mut [u8],
    spec: &CacheSpec,
    placed: &[PlacedSegment],
    image_address: u64,
) -> Option<u64> {
    let header_size: u64 = spec.shape.header_size();
    let mapping_offset: u64 = header_size;
    let primary_segments: Vec<&PlacedSegment> = placed
        .iter()
        .filter(|entry: &&PlacedSegment| !entry.in_sibling)
        .collect();
    let mapping_count: u64 = primary_segments.len() as u64;
    let slide_mapping_offset: u64 = mapping_offset + mapping_count * MAPPING_INFO_SIZE as u64;
    let uses_slide_mappings: bool = spec.shape.has_slide_mappings();
    let images_offset: u64 = if uses_slide_mappings {
        slide_mapping_offset + mapping_count * MAPPING_AND_SLIDE_INFO_SIZE as u64
    } else {
        slide_mapping_offset
    };
    let subcache_offset: u64 = images_offset + IMAGE_INFO_SIZE as u64;
    let sub_cache_entries: u64 = u64::from(spec.extra_sub_caches) + 1;
    let name_offset: u64 =
        subcache_offset + sub_cache_entries * spec.shape.sub_cache_entry_size() as u64;
    let slide_blob_offset: u64 = align_up(name_offset + spec.install_name.len() as u64 + 1, 16);
    assert!(
        slide_blob_offset < TABLE_AREA,
        "the fixture header tables must fit the first cache page"
    );

    cache[..MAGIC_LEN].copy_from_slice(&magic_bytes(&spec.arch));
    write_u32(cache, MAPPING_OFFSET_FIELD, mapping_offset as u32);
    write_u32(cache, MAPPING_COUNT_FIELD, mapping_count as u32);
    if spec.shape.uses_relocated_images() {
        write_u32(cache, IMAGES_OFFSET_OLD_FIELD, 0);
        write_u32(cache, IMAGES_COUNT_OLD_FIELD, 0);
        write_u32(cache, IMAGES_OFFSET_NEW_FIELD, images_offset as u32);
        write_u32(cache, IMAGES_COUNT_NEW_FIELD, 1);
    } else {
        write_u32(cache, IMAGES_OFFSET_OLD_FIELD, images_offset as u32);
        write_u32(cache, IMAGES_COUNT_OLD_FIELD, 1);
    }
    if spec.shape.carries_format_flags() {
        write_u32(cache, FORMAT_FLAGS_FIELD, spec.format_flags);
    }
    if header_size as usize > UUID_FIELD {
        cache[UUID_FIELD..UUID_FIELD + 16].copy_from_slice(&[0xAB; 16]);
        write_u64(cache, LOCAL_SYMBOLS_OFFSET_FIELD, 0);
        write_u64(cache, LOCAL_SYMBOLS_SIZE_FIELD, 0);
    }
    if header_size as usize > SHARED_REGION_START_FIELD {
        write_u64(
            cache,
            SHARED_REGION_START_FIELD,
            placed
                .iter()
                .map(|entry: &PlacedSegment| entry.vmaddr)
                .min()
                .unwrap_or(0),
        );
    }

    let mut slide_cursor: u64 = slide_blob_offset;
    let mut written_slide_blob: Option<u64> = None;
    for (index, entry) in primary_segments.iter().enumerate() {
        let at: usize = mapping_offset as usize + index * MAPPING_INFO_SIZE;
        let size: u64 = align_up(entry.filesize, CACHE_PAGE);
        write_u64(cache, at, entry.vmaddr);
        write_u64(cache, at + 8, size);
        write_u64(cache, at + 16, entry.cache_offset);
        write_u32(cache, at + 24, 5);
        write_u32(cache, at + 28, 5);
        if !uses_slide_mappings {
            continue;
        }
        let slide_at: usize = slide_mapping_offset as usize + index * MAPPING_AND_SLIDE_INFO_SIZE;
        write_u64(cache, slide_at, entry.vmaddr);
        write_u64(cache, slide_at + 8, size);
        write_u64(cache, slide_at + 16, entry.cache_offset);
        let carries_slide: bool = spec.slide.is_some()
            && slide_carrier(placed)
                .is_some_and(|carrier: &PlacedSegment| carrier.name == entry.name);
        if carries_slide {
            let plan: &SlidePlan = spec.slide.as_ref().expect("checked above");
            let blob: Vec<u8> = slide_blob(plan, size);
            let at_blob: usize = slide_cursor as usize;
            cache[at_blob..at_blob + blob.len()].copy_from_slice(&blob);
            written_slide_blob = Some(slide_cursor);
            write_u64(cache, slide_at + 24, slide_cursor);
            write_u64(cache, slide_at + 32, blob.len() as u64);
            slide_cursor = align_up(slide_cursor + blob.len() as u64, 16);
            assert!(
                slide_cursor < TABLE_AREA,
                "the fixture slide-info blob must fit the first cache page"
            );
        } else {
            write_u64(cache, slide_at + 24, 0);
            write_u64(cache, slide_at + 32, 0);
        }
        write_u64(cache, slide_at + 40, 0);
        write_u32(cache, slide_at + 48, 5);
        write_u32(cache, slide_at + 52, 5);
    }
    if uses_slide_mappings {
        write_u32(
            cache,
            MAPPING_WITH_SLIDE_OFFSET_FIELD,
            slide_mapping_offset as u32,
        );
        write_u32(cache, MAPPING_WITH_SLIDE_COUNT_FIELD, mapping_count as u32);
    }

    let image_at: usize = images_offset as usize;
    write_u64(cache, image_at, image_address);
    write_u64(cache, image_at + 8, 0);
    write_u64(cache, image_at + 16, 0);
    write_u32(cache, image_at + 24, name_offset as u32);
    write_u32(cache, image_at + 28, 0);
    let name: &[u8] = spec.install_name.as_bytes();
    let name_at: usize = name_offset as usize;
    cache[name_at..name_at + name.len()].copy_from_slice(name);

    if spec.shape.has_sub_caches() && (spec.split_linkedit || spec.declared_suffix.is_some()) {
        let entry_size: usize = spec.shape.sub_cache_entry_size();
        write_u32(cache, SUBCACHE_ARRAY_OFFSET_FIELD, subcache_offset as u32);
        write_u32(cache, SUBCACHE_ARRAY_COUNT_FIELD, sub_cache_entries as u32);
        for index in 0..sub_cache_entries {
            let entry_at: usize = subcache_offset as usize + index as usize * entry_size;
            let tag: u8 = 0xCD_u8.wrapping_add(index as u8);
            cache[entry_at..entry_at + 16].copy_from_slice(&[tag; 16]);
            write_u64(cache, entry_at + 16, index * EXTRA_SUB_CACHE_VM_STEP);
            if index != 0 {
                continue;
            }
            if let Some(suffix) = spec.declared_suffix.as_deref() {
                assert!(
                    entry_size == SUBCACHE_ENTRY_SIZE,
                    "only the widest sub-cache entry carries a file suffix"
                );
                let raw: &[u8] = suffix.as_bytes();
                cache[entry_at + 24..entry_at + 24 + raw.len()].copy_from_slice(raw);
            }
        }
    }
    if spec.shape.has_sub_caches() && !spec.local_symbols.is_empty() {
        cache[SYMBOL_FILE_UUID_FIELD..SYMBOL_FILE_UUID_FIELD + 16].copy_from_slice(&[0xEF; 16]);
    }
    written_slide_blob
}

fn write_sibling_header(cache: &mut [u8], spec: &CacheSpec, placed: &[PlacedSegment]) {
    let header_size: u64 = spec.shape.header_size();
    let mapping_offset: u64 = header_size;
    let sibling_segments: Vec<&PlacedSegment> = placed
        .iter()
        .filter(|entry: &&PlacedSegment| entry.in_sibling)
        .collect();
    let mapping_count: u64 = sibling_segments.len() as u64;
    let images_offset: u32 = (mapping_offset + mapping_count * MAPPING_INFO_SIZE as u64) as u32;
    cache[..MAGIC_LEN].copy_from_slice(&magic_bytes(&spec.arch));
    write_u32(cache, MAPPING_OFFSET_FIELD, mapping_offset as u32);
    write_u32(cache, MAPPING_COUNT_FIELD, mapping_count as u32);
    write_u32(cache, IMAGES_OFFSET_OLD_FIELD, images_offset);
    write_u32(cache, IMAGES_COUNT_OLD_FIELD, 0);
    if spec.shape.uses_relocated_images() {
        write_u32(cache, IMAGES_OFFSET_NEW_FIELD, images_offset);
        write_u32(cache, IMAGES_COUNT_NEW_FIELD, 0);
    }
    for (index, entry) in sibling_segments.iter().enumerate() {
        let at: usize = mapping_offset as usize + index * MAPPING_INFO_SIZE;
        write_u64(cache, at, entry.vmaddr);
        write_u64(cache, at + 8, align_up(entry.filesize, CACHE_PAGE));
        write_u64(cache, at + 16, entry.cache_offset);
        write_u32(cache, at + 24, 1);
        write_u32(cache, at + 28, 1);
    }
}

const LOCAL_SYMBOLS_AT: u64 = 0x4000;
const NLIST_64_SIZE: usize = 16;

fn local_symbols_blob(spec: &CacheSpec, image_address: u64, dylib_offset: u64) -> Vec<u8> {
    let wide: bool = spec.shape.has_sub_caches();
    let mut strings: Vec<u8> = vec![0u8];
    let mut nlist: Vec<u8> = Vec::with_capacity(spec.local_symbols.len() * NLIST_64_SIZE);
    for (index, name) in spec.local_symbols.iter().enumerate() {
        let strx: u32 = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        nlist.extend_from_slice(&strx.to_le_bytes());
        nlist.push(0x0E);
        nlist.push(1);
        nlist.extend_from_slice(&0u16.to_le_bytes());
        nlist.extend_from_slice(&(image_address + 0x100 * index as u64).to_le_bytes());
    }
    let info_size: u32 = 24;
    let nlist_offset: u32 = info_size;
    let strings_offset: u32 = nlist_offset + nlist.len() as u32;
    let entries_offset: u32 = strings_offset + strings.len() as u32;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&nlist_offset.to_le_bytes());
    blob.extend_from_slice(&(spec.local_symbols.len() as u32).to_le_bytes());
    blob.extend_from_slice(&strings_offset.to_le_bytes());
    blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    blob.extend_from_slice(&entries_offset.to_le_bytes());
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&nlist);
    blob.extend_from_slice(&strings);
    if wide {
        blob.extend_from_slice(&dylib_offset.to_le_bytes());
    } else {
        blob.extend_from_slice(&(dylib_offset as u32).to_le_bytes());
    }
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&(spec.local_symbols.len() as u32).to_le_bytes());
    blob
}

fn build_symbols_file(spec: &CacheSpec, image_address: u64) -> Vec<u8> {
    let blob: Vec<u8> = local_symbols_blob(spec, image_address, 0);
    let header_size: u32 = spec.shape.header_size() as u32;
    let total: u64 = align_up(LOCAL_SYMBOLS_AT + blob.len() as u64, CACHE_PAGE);
    let mut file: Vec<u8> = vec![0u8; total as usize];
    file[..MAGIC_LEN].copy_from_slice(&magic_bytes(&spec.arch));
    write_u32(&mut file, MAPPING_OFFSET_FIELD, header_size);
    write_u32(&mut file, MAPPING_COUNT_FIELD, 0);
    write_u32(&mut file, IMAGES_OFFSET_OLD_FIELD, 0);
    write_u32(&mut file, IMAGES_COUNT_OLD_FIELD, 0);
    write_u32(&mut file, IMAGES_OFFSET_NEW_FIELD, header_size);
    write_u32(&mut file, IMAGES_COUNT_NEW_FIELD, 0);
    write_u64(&mut file, LOCAL_SYMBOLS_OFFSET_FIELD, LOCAL_SYMBOLS_AT);
    write_u64(&mut file, LOCAL_SYMBOLS_SIZE_FIELD, blob.len() as u64);
    let at: usize = LOCAL_SYMBOLS_AT as usize;
    file[at..at + blob.len()].copy_from_slice(&blob);
    file
}

pub(crate) fn slide_carrier(placed: &[PlacedSegment]) -> Option<&PlacedSegment> {
    placed
        .iter()
        .find(|entry: &&PlacedSegment| entry.name.starts_with("__DATA") && !entry.in_sibling)
}

fn encode_slide_pointers(
    cache: &mut [u8],
    placed: &[PlacedSegment],
    plan: &SlidePlan,
) -> Vec<SlideExpectation> {
    let data: &PlacedSegment =
        slide_carrier(placed).expect("the fixture image carries a writable data segment");
    let width: u64 = plan.pointer_width();
    assert!(
        data.filesize >= (plan.targets.len() as u64 + 1) * width,
        "the data segment must hold the encoded pointer chain"
    );
    let mut out: Vec<SlideExpectation> = Vec::with_capacity(plan.targets.len());
    for (index, (target, auth)) in plan.targets.iter().enumerate() {
        let slot: usize = data.cache_offset as usize + index * width as usize;
        let last: bool = index + 1 == plan.targets.len();
        let step: u64 = if last { 0 } else { width };
        let raw: u64 = encode_pointer(plan, *target, *auth, step);
        if width == 4 {
            write_u32(
                cache,
                slot,
                u32::try_from(raw).expect("a 32-bit slide word"),
            );
        } else {
            write_u64(cache, slot, raw);
        }
        out.push(SlideExpectation {
            vm_address: data.vmaddr + index as u64 * width,
            unslid: unslid_of(plan, *target),
            raw,
            width: width as u8,
        });
    }
    let tail: usize = data.cache_offset as usize + plan.targets.len() * width as usize;
    if width == 4 {
        write_u32(cache, tail, SLIDE_TAIL_SENTINEL as u32);
    } else {
        write_u64(cache, tail, SLIDE_TAIL_SENTINEL);
    }
    out
}

const fn unslid_of(plan: &SlidePlan, target: u64) -> u64 {
    match plan.version {
        4 => {
            if target & 0xFFFF_8000 == 0 {
                target
            } else if target & 0x3FFF_8000 == 0x3FFF_8000 {
                target | 0xC000_0000
            } else {
                target.wrapping_add(plan.value_add)
            }
        }
        _ => target,
    }
}

fn delta_shift_of(delta_mask: u64) -> u32 {
    assert!(
        delta_mask != 0 && delta_mask.trailing_zeros() >= 2,
        "a version 2 or 4 delta mask must leave room for the two-bit scale"
    );
    delta_mask.trailing_zeros() - 2
}

pub(crate) fn encode_pointer(
    plan: &SlidePlan,
    target: u64,
    auth: Option<AuthSpec>,
    step: u64,
) -> u64 {
    let value_add: u64 = plan.value_add;
    let next: u64 = step / 8;
    match plan.version {
        1 => {
            assert!(auth.is_none(), "version 1 slide info carries no auth bits");
            assert!(
                u32::try_from(target).is_ok(),
                "a version 1 slot holds a 32-bit word"
            );
            target
        }
        2 => {
            assert!(auth.is_none(), "version 2 slide info carries no auth bits");
            let stored: u64 = target
                .checked_sub(value_add)
                .expect("a version 2 target sits at or above the cache base");
            let encoded: u64 = step << delta_shift_of(plan.delta_mask);
            assert!(
                encoded & plan.delta_mask == encoded && stored & plan.delta_mask == 0,
                "a version 2 word must keep its value and delta fields apart"
            );
            stored | encoded
        }
        4 => {
            assert!(auth.is_none(), "version 4 slide info carries no auth bits");
            let encoded: u64 = step << delta_shift_of(plan.delta_mask);
            assert!(
                encoded & plan.delta_mask == encoded && target & plan.delta_mask == 0,
                "a version 4 word must keep its value and delta fields apart"
            );
            target | encoded
        }
        3 => auth.map_or_else(
            || {
                let low: u64 = target & 0x0000_07FF_FFFF_FFFF;
                let high8: u64 = target >> 56 & 0xFF;
                low | (high8 << 43) | (next << 51)
            },
            |spec: AuthSpec| {
                let offset: u64 = target - value_add;
                assert!(
                    offset <= 0xFFFF_FFFF,
                    "a v3 authenticated target must sit within 4 GiB of the cache base"
                );
                offset
                    | (u64::from(spec.diversity) << 32)
                    | (u64::from(spec.address_diversity) << 48)
                    | (u64::from(spec.key & 0b11) << 49)
                    | (next << 51)
                    | (1u64 << 63)
            },
        ),
        5 => auth.map_or_else(
            || {
                let offset: u64 = (target & 0x00FF_FFFF_FFFF_FFFF) - value_add;
                assert!(
                    offset <= 0x3_FFFF_FFFF,
                    "a v5 target must sit within 16 GiB of the cache base"
                );
                let high8: u64 = target >> 56 & 0xFF;
                offset | (high8 << 34) | (next << 52)
            },
            |spec: AuthSpec| {
                let offset: u64 = target - value_add;
                assert!(
                    offset <= 0x3_FFFF_FFFF,
                    "a v5 target must sit within 16 GiB of the cache base"
                );
                offset
                    | (u64::from(spec.diversity) << 34)
                    | (u64::from(spec.address_diversity) << 50)
                    | (u64::from(spec.key == 2) << 51)
                    | (next << 52)
                    | (1u64 << 63)
            },
        ),
        other => panic!("the fixture builder encodes slide-info versions 1 to 5, not {other}"),
    }
}

const V1_PAGE_SIZE: u64 = 4096;
const V1_ENTRY_BYTES: usize = 128;
const V1_EMPTY_ENTRY: u16 = 0;
const V1_MARKED_ENTRY: u16 = 1;
const V2_NO_REBASE: u16 = 0x4000;
const V4_NO_REBASE: u16 = 0xFFFF;
const V3_V5_NO_REBASE: u16 = 0xFFFF;

fn slide_blob(plan: &SlidePlan, region_size: u64) -> Vec<u8> {
    match plan.version {
        1 => v1_slide_blob(plan, region_size),
        2 | 4 => delta_slide_blob(plan, region_size),
        _ => chain_slide_blob(plan, region_size),
    }
}

fn v1_slide_blob(plan: &SlidePlan, region_size: u64) -> Vec<u8> {
    let toc_count: u32 = (region_size / V1_PAGE_SIZE) as u32;
    let toc_offset: u32 = 24;
    let entries_offset: u32 = toc_offset + toc_count * 2;
    let entries_count: u32 = 2;
    let mut blob: Vec<u8> =
        Vec::with_capacity(entries_offset as usize + entries_count as usize * V1_ENTRY_BYTES);
    blob.extend_from_slice(&plan.version.to_le_bytes());
    blob.extend_from_slice(&toc_offset.to_le_bytes());
    blob.extend_from_slice(&toc_count.to_le_bytes());
    blob.extend_from_slice(&entries_offset.to_le_bytes());
    blob.extend_from_slice(&entries_count.to_le_bytes());
    blob.extend_from_slice(&(V1_ENTRY_BYTES as u32).to_le_bytes());
    for page in 0..toc_count {
        let entry: u16 = if page == 0 {
            V1_MARKED_ENTRY
        } else {
            V1_EMPTY_ENTRY
        };
        blob.extend_from_slice(&entry.to_le_bytes());
    }
    blob.resize(blob.len() + V1_ENTRY_BYTES, 0);
    let mut marked: Vec<u8> = vec![0u8; V1_ENTRY_BYTES];
    for slot in 0..plan.targets.len() {
        let byte: usize = slot / 8;
        assert!(
            byte < V1_ENTRY_BYTES,
            "a version 1 bitmap entry covers one 4096-byte page"
        );
        marked[byte] |= 1u8 << (slot % 8);
    }
    marked[V1_ENTRY_BYTES - 1] |= 0x80;
    blob.extend_from_slice(&marked);
    blob
}

pub(crate) const V1_LAST_MARKED_SLOT_OFFSET: u64 = ((V1_ENTRY_BYTES as u64) * 8 - 1) * 4;

fn delta_slide_blob(plan: &SlidePlan, region_size: u64) -> Vec<u8> {
    let page_count: u32 = (region_size / CACHE_PAGE) as u32;
    let page_starts_offset: u32 = 40;
    let page_extras_offset: u32 = page_starts_offset + page_count * 2;
    let no_rebase: u16 = if plan.version == 2 {
        V2_NO_REBASE
    } else {
        V4_NO_REBASE
    };
    let mut blob: Vec<u8> = Vec::with_capacity(page_extras_offset as usize);
    blob.extend_from_slice(&plan.version.to_le_bytes());
    blob.extend_from_slice(&(CACHE_PAGE as u32).to_le_bytes());
    blob.extend_from_slice(&page_starts_offset.to_le_bytes());
    blob.extend_from_slice(&page_count.to_le_bytes());
    blob.extend_from_slice(&page_extras_offset.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&plan.delta_mask.to_le_bytes());
    blob.extend_from_slice(&plan.value_add.to_le_bytes());
    for page in 0..page_count {
        let entry: u16 = if page == 0 { 0 } else { no_rebase };
        blob.extend_from_slice(&entry.to_le_bytes());
    }
    blob
}

fn chain_slide_blob(plan: &SlidePlan, region_size: u64) -> Vec<u8> {
    let page_count: u32 = (region_size / CACHE_PAGE) as u32;
    let mut blob: Vec<u8> = Vec::with_capacity(24 + page_count as usize * 2);
    blob.extend_from_slice(&plan.version.to_le_bytes());
    blob.extend_from_slice(&(CACHE_PAGE as u32).to_le_bytes());
    blob.extend_from_slice(&page_count.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&plan.value_add.to_le_bytes());
    for page in 0..page_count {
        let entry: u16 = if page == 0 { 0 } else { V3_V5_NO_REBASE };
        blob.extend_from_slice(&entry.to_le_bytes());
    }
    blob
}

pub(crate) fn segment_of<'a>(parsed: &'a ParsedSlice, name: &str) -> &'a Segment {
    parsed
        .segments
        .iter()
        .find(|segment: &&Segment| segment.name == name)
        .unwrap_or_else(|| panic!("the fixture image carries no '{name}' segment"))
}
