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
    SlideMappings,
    SubCaches,
}

impl HeaderShape {
    pub(crate) const fn header_size(self) -> u64 {
        match self {
            Self::Legacy => 0x30,
            Self::SlideMappings => 0x140,
            Self::SubCaches => 0x1D0,
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
    pub(crate) targets: Vec<(u64, Option<AuthSpec>)>,
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
}

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
        }
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
    pub(crate) slide_expectations: Vec<(u64, u64)>,
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

    let slide_expectations: Vec<(u64, u64)> = spec.slide.as_ref().map_or_else(Vec::new, |plan| {
        encode_slide_pointers(&mut primary, &placed, plan)
    });

    let slide_blob_offset: Option<u64> =
        write_primary_header(&mut primary, spec, &placed, text.vmaddr);
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
    let uses_slide_mappings: bool = spec.shape != HeaderShape::Legacy;
    let images_offset: u64 = if uses_slide_mappings {
        slide_mapping_offset + mapping_count * MAPPING_AND_SLIDE_INFO_SIZE as u64
    } else {
        slide_mapping_offset
    };
    let subcache_offset: u64 = images_offset + IMAGE_INFO_SIZE as u64;
    let name_offset: u64 = subcache_offset + SUBCACHE_ENTRY_SIZE as u64;
    let slide_blob_offset: u64 = align_up(name_offset + spec.install_name.len() as u64 + 1, 16);
    assert!(
        slide_blob_offset < TABLE_AREA,
        "the fixture header tables must fit the first cache page"
    );

    cache[..MAGIC_LEN].copy_from_slice(&magic_bytes(&spec.arch));
    write_u32(cache, MAPPING_OFFSET_FIELD, mapping_offset as u32);
    write_u32(cache, MAPPING_COUNT_FIELD, mapping_count as u32);
    if spec.shape == HeaderShape::SubCaches {
        write_u32(cache, IMAGES_OFFSET_OLD_FIELD, 0);
        write_u32(cache, IMAGES_COUNT_OLD_FIELD, 0);
        write_u32(cache, IMAGES_OFFSET_NEW_FIELD, images_offset as u32);
        write_u32(cache, IMAGES_COUNT_NEW_FIELD, 1);
    } else {
        write_u32(cache, IMAGES_OFFSET_OLD_FIELD, images_offset as u32);
        write_u32(cache, IMAGES_COUNT_OLD_FIELD, 1);
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

    if spec.shape == HeaderShape::SubCaches
        && (spec.split_linkedit || spec.declared_suffix.is_some())
    {
        write_u32(cache, SUBCACHE_ARRAY_OFFSET_FIELD, subcache_offset as u32);
        write_u32(cache, SUBCACHE_ARRAY_COUNT_FIELD, 1);
        let entry_at: usize = subcache_offset as usize;
        cache[entry_at..entry_at + 16].copy_from_slice(&[0xCD; 16]);
        write_u64(cache, entry_at + 16, 0);
        if let Some(suffix) = spec.declared_suffix.as_deref() {
            let raw: &[u8] = suffix.as_bytes();
            cache[entry_at + 24..entry_at + 24 + raw.len()].copy_from_slice(raw);
        }
    }
    if spec.shape == HeaderShape::SubCaches && !spec.local_symbols.is_empty() {
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
    write_u32(cache, IMAGES_OFFSET_NEW_FIELD, images_offset);
    write_u32(cache, IMAGES_COUNT_NEW_FIELD, 0);
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

fn build_symbols_file(spec: &CacheSpec, image_address: u64) -> Vec<u8> {
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
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&(spec.local_symbols.len() as u32).to_le_bytes());

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
) -> Vec<(u64, u64)> {
    let data: &PlacedSegment =
        slide_carrier(placed).expect("the fixture image carries a writable data segment");
    assert!(
        data.filesize >= (plan.targets.len() as u64 + 1) * 8,
        "the data segment must hold the encoded pointer chain"
    );
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(plan.targets.len());
    for (index, (target, auth)) in plan.targets.iter().enumerate() {
        let slot: usize = data.cache_offset as usize + index * 8;
        let last: bool = index + 1 == plan.targets.len();
        let next: u64 = u64::from(!last);
        let raw: u64 = encode_pointer(plan.version, plan.value_add, *target, *auth, next);
        write_u64(cache, slot, raw);
        out.push((data.vmaddr + index as u64 * 8, *target));
    }
    out
}

pub(crate) fn encode_pointer(
    version: u32,
    value_add: u64,
    target: u64,
    auth: Option<AuthSpec>,
    next: u64,
) -> u64 {
    match version {
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
        other => panic!("the fixture builder encodes slide-info versions 3 and 5, not {other}"),
    }
}

fn slide_blob(plan: &SlidePlan, region_size: u64) -> Vec<u8> {
    let value_add: u64 = plan.value_add;
    let page_count: u32 = (region_size / CACHE_PAGE) as u32;
    let mut blob: Vec<u8> = Vec::with_capacity(24 + page_count as usize * 2);
    blob.extend_from_slice(&plan.version.to_le_bytes());
    blob.extend_from_slice(&(CACHE_PAGE as u32).to_le_bytes());
    blob.extend_from_slice(&page_count.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&value_add.to_le_bytes());
    for page in 0..page_count {
        let entry: u16 = if page == 0 { 0 } else { 0xFFFF };
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
