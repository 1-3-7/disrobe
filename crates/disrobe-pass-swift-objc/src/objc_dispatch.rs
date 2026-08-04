use std::collections::{BTreeMap, BTreeSet};

use disrobe_bytes::{read_u16_le_at, read_u32_le_at, read_u64_le_at, read_uleb128_at};
use serde::{Deserialize, Serialize};

use crate::macho::{self, LinkeditData, ParsedSlice, Section, SliceView};
use crate::native_bodies::DisasmInstruction;

const LC_DYLD_INFO: u32 = 0x22;
const PTR_SIZE_64: u64 = 8;
const MAX_BIND_OPS: usize = 1 << 20;
const MAX_SLOTS: usize = 1 << 20;
const MAX_TOTAL_BINDS: usize = 1 << 20;
const MAX_STUB_ENTRIES: usize = 1 << 16;
const MAX_CALL_SITES: usize = 1 << 14;
const BACKWARD_WINDOW: usize = 24;
const MAX_CSTR: usize = 4096;
const MAX_MOVE_HOPS: usize = 8;
const MAX_CFG_DEPTH: usize = 16;
const MAX_CFG_STEPS: usize = 1 << 13;

const SECT_OBJC_SELREFS: &str = "__objc_selrefs";
const SECT_OBJC_CLASSREFS: &str = "__objc_classrefs";
const SECT_STUBS: &str = "__stubs";
const SEG_TEXT: &str = "__TEXT";
const SEG_DATA: &str = "__DATA";
const SEG_DATA_CONST: &str = "__DATA_CONST";

const CLASS_PREFIX: &str = "_OBJC_CLASS_$_";
const METACLASS_PREFIX: &str = "_OBJC_METACLASS_$_";

const RO_NAME_OFF: usize = 0x18;
const CLASS_DATA_OFF: usize = 0x20;

const CHAINED_HEADER_SIZE: usize = 28;
const CHAINED_START_NONE: u16 = 0xFFFF;
const CHAINED_START_MULTI: u16 = 0x8000;
const CHAINED_START_LAST: u16 = 0x8000;
const CHAINED_IMPORT: u32 = 1;
const CHAINED_IMPORT_ADDEND: u32 = 2;
const CHAINED_IMPORT_ADDEND64: u32 = 3;
const CHAINED_PTR_ARM64E: u16 = 1;
const CHAINED_PTR_64: u16 = 2;
const CHAINED_PTR_64_OFFSET: u16 = 6;
const CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
const CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
const CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
const MAX_CHAINED_IMPORTS: usize = 1 << 20;
const MAX_CHAINED_SEGMENTS: usize = 1 << 12;
const MAX_CHAINED_PAGES: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchArch {
    Arm64,
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcSend {
    pub selector: String,
    pub receiver_class: Option<String>,
    pub rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcMessageSend {
    pub call_site: u64,
    pub send: ObjcSend,
}

#[derive(Debug, Clone, Default)]
pub struct DispatchMaps {
    pub imports_by_addr: BTreeMap<u64, String>,
    pub selref_by_va: BTreeMap<u64, String>,
    pub classref_by_va: BTreeMap<u64, String>,
    pub stub_symbol_by_va: BTreeMap<u64, String>,
}

impl DispatchMaps {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.imports_by_addr.is_empty()
            && self.selref_by_va.is_empty()
            && self.classref_by_va.is_empty()
            && self.stub_symbol_by_va.is_empty()
    }
}

#[must_use]
pub fn build_dispatch_maps(slice: &[u8], parsed: &ParsedSlice, arch: DispatchArch) -> DispatchMaps {
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return DispatchMaps::default();
    };
    let mut imports_by_addr: BTreeMap<u64, String> = parse_binds(slice, parsed, &view);
    imports_by_addr.extend(parse_chained_binds(slice, parsed, &view));
    let selref_by_va: BTreeMap<u64, String> = build_selref_map(parsed, &view);
    let classref_by_va: BTreeMap<u64, String> = build_classref_map(parsed, &view, &imports_by_addr);
    let stub_symbol_by_va: BTreeMap<u64, String> =
        build_stub_map(slice, parsed, &imports_by_addr, arch);
    DispatchMaps {
        imports_by_addr,
        selref_by_va,
        classref_by_va,
        stub_symbol_by_va,
    }
}

#[must_use]
pub fn bound_symbols_by_slot(slice: &[u8], parsed: &ParsedSlice) -> BTreeMap<u64, String> {
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return BTreeMap::new();
    };
    let mut out: BTreeMap<u64, String> = parse_binds(slice, parsed, &view);
    out.extend(parse_chained_binds(slice, parsed, &view));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainedPointerFormat {
    Arm64e,
    Arm64eKernel,
    Arm64eUserland,
    Arm64eUserland24,
    Pointer64,
    Pointer64Offset,
    Unsupported(u16),
}

impl ChainedPointerFormat {
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            CHAINED_PTR_ARM64E => Self::Arm64e,
            CHAINED_PTR_ARM64E_KERNEL => Self::Arm64eKernel,
            CHAINED_PTR_ARM64E_USERLAND => Self::Arm64eUserland,
            CHAINED_PTR_ARM64E_USERLAND24 => Self::Arm64eUserland24,
            CHAINED_PTR_64 => Self::Pointer64,
            CHAINED_PTR_64_OFFSET => Self::Pointer64Offset,
            other => Self::Unsupported(other),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Arm64e => "arm64e",
            Self::Arm64eKernel => "arm64e-kernel",
            Self::Arm64eUserland => "arm64e-userland",
            Self::Arm64eUserland24 => "arm64e-userland24",
            Self::Pointer64 => "ptr64",
            Self::Pointer64Offset => "ptr64-offset",
            Self::Unsupported(_) => "unsupported",
        }
    }

    #[must_use]
    pub const fn is_authenticated(self) -> bool {
        matches!(
            self,
            Self::Arm64e | Self::Arm64eKernel | Self::Arm64eUserland | Self::Arm64eUserland24
        )
    }
}

#[must_use]
pub fn chained_pointer_formats(slice: &[u8], parsed: &ParsedSlice) -> Vec<ChainedPointerFormat> {
    let mut out: Vec<ChainedPointerFormat> = Vec::new();
    let Some(chain_data): Option<&[u8]> = chained_fixup_data(slice, parsed) else {
        return out;
    };
    let Ok(starts_offset): Result<u32, _> = read_u32_le_at(chain_data, 4) else {
        return out;
    };
    for seg_info_at in chained_segment_infos(chain_data, starts_offset as usize) {
        let Ok(raw): Result<u16, _> = read_u16_le_at(chain_data, seg_info_at.saturating_add(6))
        else {
            continue;
        };
        let format: ChainedPointerFormat = ChainedPointerFormat::from_raw(raw);
        if !out.contains(&format) {
            out.push(format);
        }
    }
    out
}

fn chained_fixup_data<'a>(slice: &'a [u8], parsed: &ParsedSlice) -> Option<&'a [u8]> {
    let location: &LinkeditData = parsed.chained_fixups.as_ref()?;
    let start: usize = location.offset as usize;
    let size: usize = usize::try_from(location.size).ok()?;
    let data: &[u8] = slice.get(start..start.checked_add(size)?)?;
    (data.len() >= CHAINED_HEADER_SIZE).then_some(data)
}

fn chained_segment_infos(chain_data: &[u8], starts_offset: usize) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    let Ok(seg_count): Result<u32, _> = read_u32_le_at(chain_data, starts_offset) else {
        return out;
    };
    let segments: usize = usize::try_from(seg_count)
        .unwrap_or(0)
        .min(MAX_CHAINED_SEGMENTS);
    for index in 0..segments {
        let Some(entry_off): Option<usize> = index
            .checked_mul(4)
            .and_then(|delta: usize| starts_offset.checked_add(4)?.checked_add(delta))
        else {
            return out;
        };
        let Ok(seg_info_offset): Result<u32, _> = read_u32_le_at(chain_data, entry_off) else {
            return out;
        };
        if seg_info_offset == 0 {
            continue;
        }
        if let Some(seg_info_at) = starts_offset.checked_add(seg_info_offset as usize) {
            out.push(seg_info_at);
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct ChainedPointerShape {
    stride: u64,
    next_shift: u32,
    next_bits: u32,
    bind_bit: u32,
    ordinal_bits: u32,
}

impl ChainedPointerShape {
    const fn for_format(format: ChainedPointerFormat) -> Option<Self> {
        match format {
            ChainedPointerFormat::Arm64e | ChainedPointerFormat::Arm64eUserland => Some(Self {
                stride: 8,
                next_shift: 51,
                next_bits: 11,
                bind_bit: 62,
                ordinal_bits: 16,
            }),
            ChainedPointerFormat::Arm64eUserland24 => Some(Self {
                stride: 8,
                next_shift: 51,
                next_bits: 11,
                bind_bit: 62,
                ordinal_bits: 24,
            }),
            ChainedPointerFormat::Arm64eKernel => Some(Self {
                stride: 4,
                next_shift: 51,
                next_bits: 11,
                bind_bit: 62,
                ordinal_bits: 16,
            }),
            ChainedPointerFormat::Pointer64 | ChainedPointerFormat::Pointer64Offset => Some(Self {
                stride: 4,
                next_shift: 51,
                next_bits: 12,
                bind_bit: 63,
                ordinal_bits: 24,
            }),
            ChainedPointerFormat::Unsupported(_) => None,
        }
    }

    const fn is_bind(self, raw: u64) -> bool {
        raw >> self.bind_bit & 1 == 1
    }

    const fn ordinal(self, raw: u64) -> u64 {
        raw & ((1u64 << self.ordinal_bits) - 1)
    }

    const fn next_stride_count(self, raw: u64) -> u64 {
        raw >> self.next_shift & ((1u64 << self.next_bits) - 1)
    }
}

fn parse_chained_binds(
    slice: &[u8],
    parsed: &ParsedSlice,
    view: &SliceView<'_>,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(chain_data): Option<&[u8]> = chained_fixup_data(slice, parsed) else {
        return out;
    };
    let Ok(starts_offset): Result<u32, _> = read_u32_le_at(chain_data, 4) else {
        return out;
    };
    let imports: Vec<String> = parse_chained_imports(chain_data);
    if imports.is_empty() {
        return out;
    }
    let Some(image_base): Option<u64> = macho::image_base(parsed) else {
        return out;
    };
    walk_chained_segments(
        chain_data,
        starts_offset as usize,
        view,
        parsed,
        image_base,
        &imports,
        &mut out,
    );
    out
}

fn parse_chained_imports(chain_data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let (Ok(imports_offset), Ok(symbols_offset), Ok(imports_count), Ok(imports_format)): (
        Result<u32, _>,
        Result<u32, _>,
        Result<u32, _>,
        Result<u32, _>,
    ) = (
        read_u32_le_at(chain_data, 8),
        read_u32_le_at(chain_data, 12),
        read_u32_le_at(chain_data, 16),
        read_u32_le_at(chain_data, 20),
    ) else {
        return out;
    };
    let count: usize = usize::try_from(imports_count)
        .unwrap_or(0)
        .min(MAX_CHAINED_IMPORTS);
    let entry_size: usize = match imports_format {
        CHAINED_IMPORT => 4,
        CHAINED_IMPORT_ADDEND => 8,
        CHAINED_IMPORT_ADDEND64 => 16,
        _ => return out,
    };
    out.reserve(count);
    for index in 0..count {
        let Some(entry_off): Option<usize> = index
            .checked_mul(entry_size)
            .and_then(|delta: usize| (imports_offset as usize).checked_add(delta))
        else {
            break;
        };
        let name_offset: u64 = if imports_format == CHAINED_IMPORT_ADDEND64 {
            let Ok(raw): Result<u64, _> = read_u64_le_at(chain_data, entry_off) else {
                break;
            };
            raw >> 32
        } else {
            let Ok(raw): Result<u32, _> = read_u32_le_at(chain_data, entry_off) else {
                break;
            };
            u64::from(raw >> 9)
        };
        let Some(name_at): Option<usize> = usize::try_from(name_offset)
            .ok()
            .and_then(|delta: usize| (symbols_offset as usize).checked_add(delta))
        else {
            out.push(String::new());
            continue;
        };
        out.push(chained_symbol_at(chain_data, name_at).unwrap_or_default());
    }
    out
}

fn chained_symbol_at(chain_data: &[u8], offset: usize) -> Option<String> {
    let end_cap: usize = offset.checked_add(MAX_CSTR)?.min(chain_data.len());
    let window: &[u8] = chain_data.get(offset..end_cap)?;
    let nul: usize = window.iter().position(|byte: &u8| *byte == 0)?;
    std::str::from_utf8(&window[..nul]).ok().map(str::to_owned)
}

fn walk_chained_segments(
    chain_data: &[u8],
    starts_offset: usize,
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    image_base: u64,
    imports: &[String],
    out: &mut BTreeMap<u64, String>,
) {
    for seg_info_at in chained_segment_infos(chain_data, starts_offset) {
        walk_chained_pages(
            chain_data,
            seg_info_at,
            view,
            parsed,
            image_base,
            imports,
            out,
        );
    }
}

fn walk_chained_pages(
    chain_data: &[u8],
    seg_info_at: usize,
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    image_base: u64,
    imports: &[String],
    out: &mut BTreeMap<u64, String>,
) {
    let (Ok(page_size), Ok(pointer_format)): (Result<u16, _>, Result<u16, _>) = (
        read_u16_le_at(chain_data, seg_info_at.saturating_add(4)),
        read_u16_le_at(chain_data, seg_info_at.saturating_add(6)),
    ) else {
        return;
    };
    let (Ok(segment_offset), Ok(page_count)): (Result<u64, _>, Result<u16, _>) = (
        read_u64_le_at(chain_data, seg_info_at.saturating_add(8)),
        read_u16_le_at(chain_data, seg_info_at.saturating_add(20)),
    ) else {
        return;
    };
    let Some(shape): Option<ChainedPointerShape> =
        ChainedPointerShape::for_format(ChainedPointerFormat::from_raw(pointer_format))
    else {
        return;
    };
    if page_size == 0 {
        return;
    }
    let pages: usize = usize::from(page_count).min(MAX_CHAINED_PAGES);
    let page_start_at: usize = seg_info_at.saturating_add(22);
    for page in 0..pages {
        let Some(entry_off): Option<usize> = page
            .checked_mul(2)
            .and_then(|delta: usize| page_start_at.checked_add(delta))
        else {
            return;
        };
        let Ok(page_start): Result<u16, _> = read_u16_le_at(chain_data, entry_off) else {
            return;
        };
        if page_start == CHAINED_START_NONE {
            continue;
        }
        let page_base: u64 = image_base
            .wrapping_add(segment_offset)
            .wrapping_add(u64::from(page_size).wrapping_mul(page as u64));
        if page_start & CHAINED_START_MULTI == 0 {
            walk_chain(
                view,
                parsed,
                page_base.wrapping_add(u64::from(page_start)),
                shape,
                imports,
                out,
            );
            continue;
        }
        let overflow_at: usize = page_start_at
            .saturating_add(usize::from(page_start & !CHAINED_START_MULTI).saturating_mul(2));
        for step in 0..MAX_CHAINED_PAGES {
            let Some(entry_off): Option<usize> = step
                .checked_mul(2)
                .and_then(|delta: usize| overflow_at.checked_add(delta))
            else {
                return;
            };
            let Ok(sub_start): Result<u16, _> = read_u16_le_at(chain_data, entry_off) else {
                return;
            };
            walk_chain(
                view,
                parsed,
                page_base.wrapping_add(u64::from(sub_start & !CHAINED_START_LAST)),
                shape,
                imports,
                out,
            );
            if sub_start & CHAINED_START_LAST != 0 {
                break;
            }
        }
    }
}

fn walk_chain(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    first_slot: u64,
    shape: ChainedPointerShape,
    imports: &[String],
    out: &mut BTreeMap<u64, String>,
) {
    let mut slot_vmaddr: u64 = first_slot;
    for _ in 0..MAX_TOTAL_BINDS {
        let Some(file_off): Option<usize> = macho::vmaddr_to_offset(parsed, slot_vmaddr) else {
            return;
        };
        let Some(raw): Option<u64> = view.read_u64_at(file_off) else {
            return;
        };
        if shape.is_bind(raw)
            && let Ok(ordinal) = usize::try_from(shape.ordinal(raw))
            && let Some(symbol) = imports.get(ordinal)
            && !symbol.is_empty()
        {
            out.insert(slot_vmaddr, symbol.clone());
        }
        let next: u64 = shape.next_stride_count(raw);
        if next == 0 {
            return;
        }
        slot_vmaddr = slot_vmaddr.wrapping_add(next.wrapping_mul(shape.stride));
    }
}

fn find_section_any<'a>(parsed: &'a ParsedSlice, segs: &[&str], name: &str) -> Option<&'a Section> {
    segs.iter()
        .find_map(|seg: &&str| macho::find_section(parsed, seg, name))
}

fn build_selref_map(parsed: &ParsedSlice, view: &SliceView<'_>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> =
        find_section_any(parsed, &[SEG_DATA, SEG_DATA_CONST], SECT_OBJC_SELREFS)
    else {
        return out;
    };
    let count: usize = usize::try_from(section.size / PTR_SIZE_64)
        .unwrap_or(0)
        .min(MAX_SLOTS);
    for i in 0..count {
        let slot_va: u64 = section.addr.saturating_add((i as u64) * PTR_SIZE_64);
        let file_off: usize = (section.offset as usize).saturating_add(i * 8);
        let Some(name_va): Option<u64> = view.read_pointer_at(parsed, file_off) else {
            continue;
        };
        let Some(selector): Option<String> = view.cstr_at_vmaddr(parsed, name_va, MAX_CSTR) else {
            continue;
        };
        if !selector.is_empty() {
            out.insert(slot_va, selector);
        }
    }
    out
}

fn build_classref_map(
    parsed: &ParsedSlice,
    view: &SliceView<'_>,
    imports_by_addr: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> =
        find_section_any(parsed, &[SEG_DATA, SEG_DATA_CONST], SECT_OBJC_CLASSREFS)
    else {
        return out;
    };
    let count: usize = usize::try_from(section.size / PTR_SIZE_64)
        .unwrap_or(0)
        .min(MAX_SLOTS);
    for i in 0..count {
        let slot_va: u64 = section.addr.saturating_add((i as u64) * PTR_SIZE_64);
        if let Some(symbol) = imports_by_addr.get(&slot_va)
            && let Some(name) = strip_class_symbol(symbol)
        {
            out.insert(slot_va, name.to_owned());
            continue;
        }
        let file_off: usize = (section.offset as usize).saturating_add(i * 8);
        if let Some(class_va) = view.read_pointer_at(parsed, file_off)
            && let Some(name) = local_class_name(parsed, view, class_va)
        {
            out.insert(slot_va, name);
        }
    }
    out
}

pub(crate) fn strip_class_symbol(symbol: &str) -> Option<&str> {
    symbol
        .strip_prefix(CLASS_PREFIX)
        .or_else(|| symbol.strip_prefix(METACLASS_PREFIX))
        .filter(|name: &&str| !name.is_empty())
}

pub(crate) fn local_class_name(
    parsed: &ParsedSlice,
    view: &SliceView<'_>,
    class_va: u64,
) -> Option<String> {
    let class_off: usize = macho::vmaddr_to_offset(parsed, class_va)?;
    let bits: u64 = view.read_u64_at(class_off.checked_add(CLASS_DATA_OFF)?)?;
    let data_va: u64 = macho::decode_bound_pointer(bits & macho::FAST_DATA_MASK, view.base());
    let ro_off: usize = macho::vmaddr_to_offset(parsed, data_va)?;
    let name_va: u64 = view.read_pointer_at(parsed, ro_off.checked_add(RO_NAME_OFF)?)?;
    view.cstr_at_vmaddr(parsed, name_va, MAX_CSTR)
        .filter(|name: &String| !name.is_empty())
}

fn build_stub_map(
    slice: &[u8],
    parsed: &ParsedSlice,
    imports_by_addr: &BTreeMap<u64, String>,
    arch: DispatchArch,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> = macho::find_section(parsed, SEG_TEXT, SECT_STUBS) else {
        return out;
    };
    let Some(bytes): Option<&[u8]> = macho::readable_section_bytes(slice, parsed, section) else {
        return out;
    };
    match arch {
        DispatchArch::Arm64 => build_arm64_stub_map(section.addr, bytes, imports_by_addr, &mut out),
        DispatchArch::X86_64 => build_x86_stub_map(section.addr, bytes, imports_by_addr, &mut out),
    }
    out
}

fn build_arm64_stub_map(
    base: u64,
    bytes: &[u8],
    imports_by_addr: &BTreeMap<u64, String>,
    out: &mut BTreeMap<u64, String>,
) {
    let stride: usize = 12;
    let mut offset: usize = 0;
    let mut entries: usize = 0;
    while offset + stride <= bytes.len() && entries < MAX_STUB_ENTRIES {
        entries += 1;
        let entry_va: u64 = base.saturating_add(offset as u64);
        let w0: u32 = read_u32_le(bytes, offset);
        let w1: u32 = read_u32_le(bytes, offset + 4);
        if let Some((_, page)) = decode_adrp(entry_va, w0)
            && let Some((_, _, off)) = decode_ldr64(w1)
        {
            let slot: u64 = page.saturating_add(off);
            if let Some(symbol) = imports_by_addr.get(&slot) {
                out.insert(entry_va, symbol.clone());
            }
        }
        offset += stride;
    }
}

fn build_x86_stub_map(
    base: u64,
    bytes: &[u8],
    imports_by_addr: &BTreeMap<u64, String>,
    out: &mut BTreeMap<u64, String>,
) {
    let stride: usize = 6;
    let mut offset: usize = 0;
    let mut entries: usize = 0;
    while offset + stride <= bytes.len() && entries < MAX_STUB_ENTRIES {
        entries += 1;
        if bytes.get(offset) == Some(&0xFF) && bytes.get(offset + 1) == Some(&0x25) {
            let entry_va: u64 = base.saturating_add(offset as u64);
            let disp: i32 = read_i32_le(bytes, offset + 2);
            let end: u64 = entry_va.saturating_add(stride as u64);
            let slot: u64 = end.wrapping_add(disp as i64 as u64);
            if let Some(symbol) = imports_by_addr.get(&slot) {
                out.insert(entry_va, symbol.clone());
            }
        }
        offset += stride;
    }
}

fn parse_binds(slice: &[u8], parsed: &ParsedSlice, view: &SliceView<'_>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(command): Option<&macho::LoadCommand> = parsed
        .load_commands
        .iter()
        .find(|lc: &&macho::LoadCommand| lc.cmd == LC_DYLD_INFO)
    else {
        return out;
    };
    let base: usize = command.data_offset;
    let streams: [(u32, u32); 3] = [
        (read_lc_u32(view, base, 16), read_lc_u32(view, base, 20)),
        (read_lc_u32(view, base, 24), read_lc_u32(view, base, 28)),
        (read_lc_u32(view, base, 32), read_lc_u32(view, base, 36)),
    ];
    let mut total: usize = 0;
    for (off, size) in streams {
        interpret_bind(
            slice,
            parsed,
            off as usize,
            size as usize,
            &mut out,
            &mut total,
        );
    }
    out
}

fn read_lc_u32(view: &SliceView<'_>, base: usize, delta: usize) -> u32 {
    view.read_u32_at(base.saturating_add(delta)).unwrap_or(0)
}

fn interpret_bind(
    slice: &[u8],
    parsed: &ParsedSlice,
    start: usize,
    size: usize,
    out: &mut BTreeMap<u64, String>,
    total: &mut usize,
) {
    let end: usize = start.saturating_add(size).min(slice.len());
    let Some(stream): Option<&[u8]> = slice.get(start..end) else {
        return;
    };
    let mut cursor: usize = 0;
    let mut seg_index: usize = 0;
    let mut seg_off: u64 = 0;
    let mut symbol: String = String::new();
    let mut ops: usize = 0;
    while cursor < stream.len() && ops < MAX_BIND_OPS && *total < MAX_TOTAL_BINDS {
        ops += 1;
        let byte: u8 = stream[cursor];
        cursor += 1;
        let opcode: u8 = byte & 0xF0;
        let imm: u8 = byte & 0x0F;
        match opcode {
            0x20 | 0x60 => cursor = skip_uleb(stream, cursor),
            0x40 => {
                let (text, next): (String, usize) = read_cstr(stream, cursor);
                symbol = text;
                cursor = next;
            }
            0x70 => {
                seg_index = imm as usize;
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                seg_off = value;
                cursor = next;
            }
            0x80 => {
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                seg_off = seg_off.wrapping_add(value);
                cursor = next;
            }
            0x90 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                seg_off = seg_off.wrapping_add(PTR_SIZE_64);
            }
            0xA0 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                cursor = next;
                seg_off = seg_off.wrapping_add(PTR_SIZE_64).wrapping_add(value);
            }
            0xB0 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                seg_off = seg_off
                    .wrapping_add(PTR_SIZE_64)
                    .wrapping_add((imm as u64).wrapping_mul(PTR_SIZE_64));
            }
            0xC0 => {
                let (count, next): (u64, usize) = read_uleb(stream, cursor);
                let (skip, next2): (u64, usize) = read_uleb(stream, next);
                cursor = next2;
                let bounded: u64 = count.min(MAX_SLOTS as u64);
                for _ in 0..bounded {
                    if *total >= MAX_TOTAL_BINDS {
                        break;
                    }
                    bind_one(parsed, seg_index, seg_off, &symbol, out);
                    *total += 1;
                    seg_off = seg_off.wrapping_add(PTR_SIZE_64).wrapping_add(skip);
                }
            }
            _ => {}
        }
    }
}

fn bind_one(
    parsed: &ParsedSlice,
    seg_index: usize,
    seg_off: u64,
    symbol: &str,
    out: &mut BTreeMap<u64, String>,
) {
    if symbol.is_empty() {
        return;
    }
    let Some(segment): Option<&macho::Segment> = parsed.segments.get(seg_index) else {
        return;
    };
    let addr: u64 = segment.vmaddr.saturating_add(seg_off);
    out.insert(addr, symbol.to_owned());
}

fn read_uleb(stream: &[u8], cursor: usize) -> (u64, usize) {
    match read_uleb128_at(stream, cursor) {
        Ok((value, consumed)) => (value, cursor + consumed),
        Err(_) => (0, stream.len()),
    }
}

fn skip_uleb(stream: &[u8], cursor: usize) -> usize {
    read_uleb(stream, cursor).1
}

fn read_cstr(stream: &[u8], cursor: usize) -> (String, usize) {
    let mut end: usize = cursor;
    while end < stream.len() && stream[end] != 0 {
        end += 1;
    }
    let text: String = std::str::from_utf8(&stream[cursor..end])
        .map(str::to_owned)
        .unwrap_or_default();
    (text, (end + 1).min(stream.len()))
}

#[derive(Debug, Clone, Copy)]
enum CallForm {
    Direct(u64),
    Indirect(u8),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Terminator {
    #[default]
    FallThrough,
    Branch {
        target: Option<u64>,
        conditional: bool,
    },
    Return,
}

#[derive(Debug, Clone, Default)]
struct Step {
    addr: u64,
    boundary: bool,
    terminator: Terminator,
    call: Option<CallForm>,
    adrp: Option<u64>,
    ldr: Option<(u8, u8, u64)>,
    pc_relative_slot: Option<u64>,
    mov_from: Option<u8>,
    writes: WriteSet,
    recognized: bool,
}

#[derive(Debug, Clone, Copy, Default)]
enum WriteSet {
    #[default]
    None,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
}

impl WriteSet {
    const fn contains(self, reg: u8) -> bool {
        match self {
            Self::None => false,
            Self::One(a) => a == reg,
            Self::Two(a, b) => a == reg || b == reg,
            Self::Three(a, b, c) => a == reg || b == reg || c == reg,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackedRegister(u8);

impl TrackedRegister {
    const fn index(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverMode {
    Object,
    Super,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeadingResultMode {
    Direct,
    Hidden(TrackedRegister),
}

impl LeadingResultMode {
    const fn register(self) -> Option<TrackedRegister> {
        match self {
            Self::Direct => None,
            Self::Hidden(register) => Some(register),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageAbiProfile {
    selector: TrackedRegister,
    receiver: TrackedRegister,
    unresolved_receiver: &'static str,
    arguments: &'static [&'static str],
    receiver_mode: ReceiverMode,
    leading_result: LeadingResultMode,
}

const ARM_SEL_REG: TrackedRegister = TrackedRegister(1);
const ARM_RECV_REG: TrackedRegister = TrackedRegister(0);
const X86_SEL_REG: TrackedRegister = TrackedRegister(6);
const X86_RECV_REG: TrackedRegister = TrackedRegister(7);
const X86_STRET_SEL_REG: TrackedRegister = TrackedRegister(2);
const X86_STRET_RECV_REG: TrackedRegister = TrackedRegister(6);
const X86_STRET_RESULT_REG: TrackedRegister = TrackedRegister(7);

const ARM_ARGUMENT_REGISTERS: [&str; 6] = ["x2", "x3", "x4", "x5", "x6", "x7"];
const X86_ARGUMENT_REGISTERS: [&str; 4] = ["rdx", "rcx", "r8", "r9"];
const X86_STRET_ARGUMENT_REGISTERS: [&str; 3] = ["rcx", "r8", "r9"];

const fn arm_message_abi(receiver_mode: ReceiverMode) -> MessageAbiProfile {
    MessageAbiProfile {
        selector: ARM_SEL_REG,
        receiver: ARM_RECV_REG,
        unresolved_receiver: "x0",
        arguments: &ARM_ARGUMENT_REGISTERS,
        receiver_mode,
        leading_result: LeadingResultMode::Direct,
    }
}

const fn x86_message_abi(receiver_mode: ReceiverMode) -> MessageAbiProfile {
    MessageAbiProfile {
        selector: X86_SEL_REG,
        receiver: X86_RECV_REG,
        unresolved_receiver: "rdi",
        arguments: &X86_ARGUMENT_REGISTERS,
        receiver_mode,
        leading_result: LeadingResultMode::Direct,
    }
}

const fn x86_stret_message_abi(receiver_mode: ReceiverMode) -> MessageAbiProfile {
    MessageAbiProfile {
        selector: X86_STRET_SEL_REG,
        receiver: X86_STRET_RECV_REG,
        unresolved_receiver: "rsi",
        arguments: &X86_STRET_ARGUMENT_REGISTERS,
        receiver_mode,
        leading_result: LeadingResultMode::Hidden(X86_STRET_RESULT_REG),
    }
}

fn message_abi_profile(arch: DispatchArch, symbol: &str) -> Option<MessageAbiProfile> {
    match (arch, symbol) {
        (DispatchArch::Arm64, "_objc_msgSend") => Some(arm_message_abi(ReceiverMode::Object)),
        (DispatchArch::Arm64, "_objc_msgSendSuper" | "_objc_msgSendSuper2") => {
            Some(arm_message_abi(ReceiverMode::Super))
        }
        (DispatchArch::X86_64, "_objc_msgSend") => Some(x86_message_abi(ReceiverMode::Object)),
        (DispatchArch::X86_64, "_objc_msgSendSuper" | "_objc_msgSendSuper2") => {
            Some(x86_message_abi(ReceiverMode::Super))
        }
        (DispatchArch::X86_64, "_objc_msgSend_stret") => {
            Some(x86_stret_message_abi(ReceiverMode::Object))
        }
        (DispatchArch::X86_64, "_objc_msgSendSuper_stret" | "_objc_msgSendSuper2_stret") => {
            Some(x86_stret_message_abi(ReceiverMode::Super))
        }
        _ => None,
    }
}

fn dispatch_kind(arch: DispatchArch, symbol: &str) -> Option<Dispatch> {
    if let Some(profile) = message_abi_profile(arch, symbol) {
        return Some(Dispatch::Message(profile));
    }
    match symbol {
        "_objc_alloc" => Some(Dispatch::Alloc),
        "_objc_alloc_init" => Some(Dispatch::AllocInit),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum Dispatch {
    Message(MessageAbiProfile),
    Alloc,
    AllocInit,
}

#[must_use]
pub fn annotate_instructions(
    instructions: &[DisasmInstruction],
    arch: DispatchArch,
    maps: &DispatchMaps,
) -> Vec<ObjcMessageSend> {
    if maps.is_empty() {
        return Vec::new();
    }
    let steps: Vec<Step> = instructions
        .iter()
        .map(|insn: &DisasmInstruction| decode_step(insn, arch))
        .collect();
    let leaves_function: Vec<bool> = steps
        .iter()
        .enumerate()
        .map(|(index, step): (usize, &Step)| {
            step.call.is_some_and(|call: CallForm| {
                call_symbol(&steps, index, call, arch, maps).is_some()
            })
        })
        .collect();
    let cfg: Cfg = Cfg::build(&steps, &leaves_function);
    let mut out: Vec<ObjcMessageSend> = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if out.len() >= MAX_CALL_SITES {
            break;
        }
        let Some(call): Option<CallForm> = step.call else {
            continue;
        };
        let Some(symbol): Option<&String> = call_symbol(&steps, index, call, arch, maps) else {
            continue;
        };
        let Some(kind): Option<Dispatch> = dispatch_kind(arch, symbol) else {
            continue;
        };
        if let Some(send) = resolve_send(&steps, index, arch, maps, &cfg, kind) {
            out.push(ObjcMessageSend {
                call_site: step.addr,
                send,
            });
        }
    }
    out
}

fn call_symbol<'a>(
    steps: &[Step],
    index: usize,
    call: CallForm,
    arch: DispatchArch,
    maps: &'a DispatchMaps,
) -> Option<&'a String> {
    match call {
        CallForm::Direct(target) => maps
            .stub_symbol_by_va
            .get(&target)
            .or_else(|| maps.imports_by_addr.get(&target)),
        CallForm::Indirect(reg) => {
            let slot: u64 = trace_pointer_slot(steps, index, reg, arch)?;
            maps.imports_by_addr.get(&slot)
        }
    }
}

fn resolve_send(
    steps: &[Step],
    index: usize,
    arch: DispatchArch,
    maps: &DispatchMaps,
    cfg: &Cfg,
    kind: Dispatch,
) -> Option<ObjcSend> {
    match kind {
        Dispatch::Message(profile) => {
            if profile.leading_result.register() == Some(profile.receiver) {
                return None;
            }
            let selector: String =
                trace_selector(steps, cfg, index, profile.selector.index(), arch, maps)?;
            let receiver_class: Option<String> = if profile.receiver_mode == ReceiverMode::Super {
                None
            } else {
                trace_receiver_class(steps, cfg, index, profile.receiver.index(), arch, maps)
            };
            let recv_token: String = receiver_token(receiver_class.as_deref(), profile);
            let rendered: String = render_message(&selector, &recv_token, profile.arguments);
            Some(ObjcSend {
                selector,
                receiver_class,
                rendered,
            })
        }
        Dispatch::Alloc => {
            let profile: MessageAbiProfile = match arch {
                DispatchArch::Arm64 => arm_message_abi(ReceiverMode::Object),
                DispatchArch::X86_64 => x86_message_abi(ReceiverMode::Object),
            };
            let receiver_class: Option<String> =
                trace_receiver_class(steps, cfg, index, profile.receiver.index(), arch, maps);
            let recv_token: String = receiver_token(receiver_class.as_deref(), profile);
            Some(ObjcSend {
                selector: "alloc".to_owned(),
                rendered: format!("[{recv_token} alloc]"),
                receiver_class,
            })
        }
        Dispatch::AllocInit => {
            let profile: MessageAbiProfile = match arch {
                DispatchArch::Arm64 => arm_message_abi(ReceiverMode::Object),
                DispatchArch::X86_64 => x86_message_abi(ReceiverMode::Object),
            };
            let receiver_class: Option<String> =
                trace_receiver_class(steps, cfg, index, profile.receiver.index(), arch, maps);
            let recv_token: String = receiver_token(receiver_class.as_deref(), profile);
            Some(ObjcSend {
                selector: "init".to_owned(),
                rendered: format!("[[{recv_token} alloc] init]"),
                receiver_class,
            })
        }
    }
}

fn receiver_token(receiver_class: Option<&str>, profile: MessageAbiProfile) -> String {
    if profile.receiver_mode == ReceiverMode::Super {
        return "super".to_owned();
    }
    if let Some(name) = receiver_class {
        return name.to_owned();
    }
    profile.unresolved_receiver.to_owned()
}

fn render_message(selector: &str, recv: &str, args: &[&str]) -> String {
    if !selector.contains(':') {
        return format!("[{recv} {selector}]");
    }
    let mut rendered: String = String::from("[");
    rendered.push_str(recv);
    let mut arg_index: usize = 0;
    for keyword in selector.split(':') {
        if keyword.is_empty() {
            continue;
        }
        rendered.push(' ');
        rendered.push_str(keyword);
        rendered.push(':');
        rendered.push_str(args.get(arg_index).copied().unwrap_or("?"));
        arg_index += 1;
    }
    rendered.push(']');
    rendered
}

fn trace_selector(
    steps: &[Step],
    cfg: &Cfg,
    call_index: usize,
    reg: u8,
    arch: DispatchArch,
    maps: &DispatchMaps,
) -> Option<String> {
    let slot: u64 = resolve_pointer_slot(steps, cfg, call_index, reg, arch)?;
    maps.selref_by_va.get(&slot).cloned()
}

fn trace_receiver_class(
    steps: &[Step],
    cfg: &Cfg,
    call_index: usize,
    reg: u8,
    arch: DispatchArch,
    maps: &DispatchMaps,
) -> Option<String> {
    let slot: u64 = resolve_pointer_slot(steps, cfg, call_index, reg, arch)?;
    maps.classref_by_va.get(&slot).cloned()
}

fn resolve_pointer_slot(
    steps: &[Step],
    cfg: &Cfg,
    from: usize,
    reg: u8,
    arch: DispatchArch,
) -> Option<u64> {
    trace_pointer_slot(steps, from, reg, arch)
        .or_else(|| cfg.reaching_pointer_slot(steps, from, reg, arch))
}

fn trace_pointer_slot(steps: &[Step], from: usize, reg: u8, arch: DispatchArch) -> Option<u64> {
    let mut register: u8 = reg;
    let mut cursor: usize = from;
    for _ in 0..MAX_MOVE_HOPS {
        let def_index: usize = find_def(steps, cursor, register, arch)?;
        let step: &Step = &steps[def_index];
        if let Some(source) = step.mov_from {
            register = source;
            cursor = def_index;
            continue;
        }
        if let Some(slot) = step.pc_relative_slot {
            return Some(slot);
        }
        let (_, base, off): (u8, u8, u64) = step.ldr?;
        let base_index: usize = find_def(steps, def_index, base, arch)?;
        return Some(steps[base_index].adrp?.wrapping_add(off));
    }
    None
}

const fn is_callee_saved(arch: DispatchArch, reg: u8) -> bool {
    match arch {
        DispatchArch::Arm64 => matches!(reg, 19..=28),
        DispatchArch::X86_64 => matches!(reg, 3..=5 | 12..=15),
    }
}

const fn survives_call(step: &Step, preserved: bool) -> bool {
    preserved && step.call.is_some() && matches!(step.terminator, Terminator::FallThrough)
}

fn find_def(steps: &[Step], from: usize, reg: u8, arch: DispatchArch) -> Option<usize> {
    let preserved: bool = is_callee_saved(arch, reg);
    let lower: usize = from.saturating_sub(BACKWARD_WINDOW);
    for index in (lower..from).rev() {
        let step: &Step = &steps[index];
        if step.boundary && !survives_call(step, preserved) {
            return None;
        }
        if step.writes.contains(reg) {
            return Some(index);
        }
        if !step.recognized {
            return None;
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
struct Cfg {
    block_of: Vec<usize>,
    block_start: Vec<usize>,
    block_end: Vec<usize>,
    preds: Vec<Vec<usize>>,
    analyzable: bool,
}

impl Cfg {
    fn build(steps: &[Step], leaves_function: &[bool]) -> Self {
        if steps.is_empty() || steps.len() > MAX_CFG_STEPS {
            return Self::default();
        }
        let index_of_addr: BTreeMap<u64, usize> = steps
            .iter()
            .enumerate()
            .map(|(index, step): (usize, &Step)| (step.addr, index))
            .collect();

        let mut analyzable: bool = true;
        let mut leaders: BTreeSet<usize> = BTreeSet::from([0usize]);
        for (index, step) in steps.iter().enumerate() {
            match step.terminator {
                Terminator::FallThrough => {}
                Terminator::Return => {
                    leaders.insert(index + 1);
                }
                Terminator::Branch { target, .. } => {
                    leaders.insert(index + 1);
                    match target.and_then(|addr: u64| index_of_addr.get(&addr).copied()) {
                        Some(inside) => {
                            leaders.insert(inside);
                        }
                        None => {
                            analyzable &= leaves_function.get(index).copied().unwrap_or(false);
                        }
                    }
                }
            }
        }
        leaders.retain(|leader: &usize| *leader < steps.len());

        let block_start: Vec<usize> = leaders.into_iter().collect();
        let block_end: Vec<usize> = block_start
            .iter()
            .skip(1)
            .copied()
            .chain(std::iter::once(steps.len()))
            .collect();
        let mut block_of: Vec<usize> = vec![0usize; steps.len()];
        for (block, (start, end)) in block_start.iter().zip(block_end.iter()).enumerate() {
            for slot in block_of.iter_mut().take(*end).skip(*start) {
                *slot = block;
            }
        }

        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); block_start.len()];
        for (block, end) in block_end.iter().enumerate() {
            let last: usize = end.saturating_sub(1);
            let step: &Step = &steps[last];
            let mut link = |to: usize| {
                if to < preds.len() && !preds[to].contains(&block) {
                    preds[to].push(block);
                }
            };
            match step.terminator {
                Terminator::FallThrough => link(block + 1),
                Terminator::Return => {}
                Terminator::Branch {
                    target,
                    conditional,
                } => {
                    if let Some(inside) = target.and_then(|a: u64| index_of_addr.get(&a).copied()) {
                        link(block_of[inside]);
                    }
                    if conditional {
                        link(block + 1);
                    }
                }
            }
        }

        Self {
            block_of,
            block_start,
            block_end,
            preds,
            analyzable,
        }
    }

    fn reaching_pointer_slot(
        &self,
        steps: &[Step],
        from: usize,
        reg: u8,
        arch: DispatchArch,
    ) -> Option<u64> {
        if !self.analyzable {
            return None;
        }
        let block: usize = self.block_of.get(from).copied()?;
        self.reaching_slot(steps, block, from, reg, arch, 0)
    }

    fn reaching_slot(
        &self,
        steps: &[Step],
        block: usize,
        until: usize,
        reg: u8,
        arch: DispatchArch,
        depth: usize,
    ) -> Option<u64> {
        if depth >= MAX_CFG_DEPTH {
            return None;
        }
        let (def_block, def_index): (usize, usize) =
            self.reaching_def(steps, block, until, reg, arch)?;
        let step: &Step = &steps[def_index];
        if let Some(source) = step.mov_from {
            return self.reaching_slot(steps, def_block, def_index, source, arch, depth + 1);
        }
        if let Some(slot) = step.pc_relative_slot {
            return Some(slot);
        }
        let (_, base, off): (u8, u8, u64) = step.ldr?;
        let (_, page_index): (usize, usize) =
            self.reaching_def(steps, def_block, def_index, base, arch)?;
        Some(steps[page_index].adrp?.wrapping_add(off))
    }

    fn reaching_def(
        &self,
        steps: &[Step],
        block: usize,
        until: usize,
        reg: u8,
        arch: DispatchArch,
    ) -> Option<(usize, usize)> {
        let mut visited: Vec<bool> = vec![false; self.block_start.len()];
        self.reaching_def_from(steps, block, until, reg, arch, &mut visited, 0)
    }

    fn reaching_def_from(
        &self,
        steps: &[Step],
        block: usize,
        until: usize,
        reg: u8,
        arch: DispatchArch,
        visited: &mut Vec<bool>,
        depth: usize,
    ) -> Option<(usize, usize)> {
        let preserved: bool = is_callee_saved(arch, reg);
        if depth >= MAX_CFG_DEPTH || *visited.get(block)? {
            return None;
        }
        visited[block] = true;
        let start: usize = self.block_start.get(block).copied()?;
        for index in (start..until.min(self.block_end[block])).rev() {
            let step: &Step = &steps[index];
            if !step.recognized || (step.call.is_some() && !preserved) {
                return None;
            }
            if step.writes.contains(reg) {
                return Some((block, index));
            }
        }
        let preds: &Vec<usize> = self.preds.get(block)?;
        if preds.is_empty() {
            return None;
        }
        let mut answer: Option<(usize, usize)> = None;
        for pred in preds {
            let found: (usize, usize) = self.reaching_def_from(
                steps,
                *pred,
                self.block_end[*pred],
                reg,
                arch,
                visited,
                depth + 1,
            )?;
            match answer {
                None => answer = Some(found),
                Some(existing) if existing == found => {}
                Some(_) => return None,
            }
        }
        answer
    }
}

fn decode_step(insn: &DisasmInstruction, arch: DispatchArch) -> Step {
    let bytes: Vec<u8> = hex_to_bytes(&insn.bytes);
    match arch {
        DispatchArch::Arm64 => decode_arm64(insn.address, &bytes),
        DispatchArch::X86_64 => decode_x86(insn.address, &bytes),
    }
}

fn decode_arm64(addr: u64, bytes: &[u8]) -> Step {
    let mut step: Step = Step {
        addr,
        ..Step::default()
    };
    if bytes.len() < 4 {
        return step;
    }
    let word: u32 = read_u32_le(bytes, 0);
    if word & 0xFFFF_F01F == 0xD503_201F {
        step.recognized = true;
        return step;
    }
    if let Some((rd, page)) = decode_adrp(addr, word) {
        step.adrp = Some(page);
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return step;
    }
    if let Some((rt, rn, off)) = decode_ldr64(word) {
        step.ldr = Some((rt, rn, off));
        step.writes = WriteSet::One(rt);
        step.recognized = true;
        return step;
    }
    if let Some((rt, slot)) = decode_ldr_literal64(addr, word) {
        step.pc_relative_slot = Some(slot);
        step.writes = WriteSet::One(rt);
        step.recognized = true;
        return step;
    }
    if let Some((rd, rm)) = decode_arm64_move(word) {
        step.mov_from = Some(rm);
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return step;
    }
    if word & 0xFC00_0000 == 0x9400_0000 {
        step.call = Some(CallForm::Direct(branch_target(addr, word)));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFC00_0000 == 0x1400_0000 {
        let target: u64 = branch_target(addr, word);
        step.call = Some(CallForm::Direct(target));
        step.terminator = Terminator::Branch {
            target: Some(target),
            conditional: false,
        };
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        step.call = Some(CallForm::Indirect(((word >> 5) & 0x1F) as u8));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        step.call = Some(CallForm::Indirect(((word >> 5) & 0x1F) as u8));
        step.terminator = Terminator::Branch {
            target: None,
            conditional: false,
        };
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        step.terminator = Terminator::Return;
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if let Some(target) = decode_conditional_branch_target(addr, word) {
        step.terminator = Terminator::Branch {
            target: Some(target),
            conditional: true,
        };
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    classify_arm64_writer(word, &mut step);
    step
}

const fn decode_ldr_literal64(addr: u64, word: u32) -> Option<(u8, u64)> {
    if word & 0xFF00_0000 != 0x5800_0000 {
        return None;
    }
    let rt: u8 = (word & 0x1F) as u8;
    let imm19: u64 = ((word >> 5) & 0x7_FFFF) as u64;
    let signed: i64 = ((imm19 << 45) as i64) >> 45;
    Some((rt, addr.wrapping_add((signed << 2) as u64)))
}

const fn decode_arm64_move(word: u32) -> Option<(u8, u8)> {
    if word & 0xFFE0_FFE0 != 0xAA00_03E0 {
        return None;
    }
    let rd: u8 = (word & 0x1F) as u8;
    let rm: u8 = ((word >> 16) & 0x1F) as u8;
    if rm == 31 { None } else { Some((rd, rm)) }
}

const fn decode_conditional_branch_target(addr: u64, word: u32) -> Option<u64> {
    let (imm, width): (u64, u32) =
        if word & 0xFF00_0010 == 0x5400_0000 || word & 0x7E00_0000 == 0x3400_0000 {
            (((word >> 5) & 0x7_FFFF) as u64, 19u32)
        } else if word & 0x7E00_0000 == 0x3600_0000 {
            (((word >> 5) & 0x3FFF) as u64, 14u32)
        } else {
            return None;
        };
    let shift: u32 = 64 - width;
    let signed: i64 = ((imm << shift) as i64) >> shift;
    Some(addr.wrapping_add((signed << 2) as u64))
}

const fn classify_arm64_writer(word: u32, step: &mut Step) {
    if classify_arm64_pair(word, step) || classify_arm64_single(word, step) {
        return;
    }
    let rd: u8 = (word & 0x1F) as u8;
    let hi7: u32 = (word >> 24) & 0x7F;
    if word & 0x1F80_0000 == 0x1280_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if hi7 == 0x11 || hi7 == 0x51 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0x7FE0_0000 == 0x2A00_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0xFFC0_0000 == 0xB940_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0xFFC0_0000 == 0xF900_0000 || word & 0xFFC0_0000 == 0xB900_0000 {
        step.writes = WriteSet::None;
        step.recognized = true;
    }
}

const fn classify_arm64_pair(word: u32, step: &mut Step) -> bool {
    let rt: u8 = (word & 0x1F) as u8;
    let rt2: u8 = ((word >> 10) & 0x1F) as u8;
    let rn: u8 = ((word >> 5) & 0x1F) as u8;
    match word & 0x7FC0_0000 {
        0x2940_0000 => step.writes = WriteSet::Two(rt, rt2),
        0x28C0_0000 | 0x29C0_0000 => step.writes = WriteSet::Three(rt, rt2, rn),
        0x2900_0000 => step.writes = WriteSet::None,
        0x2880_0000 | 0x2980_0000 => step.writes = WriteSet::One(rn),
        _ => return false,
    }
    step.recognized = true;
    true
}

const fn classify_arm64_single(word: u32, step: &mut Step) -> bool {
    let rt: u8 = (word & 0x1F) as u8;
    let rn: u8 = ((word >> 5) & 0x1F) as u8;
    let writes_back: bool = matches!((word >> 10) & 0x3, 1 | 3);
    if word & 0xFFE0_0000 == 0xF840_0000 {
        step.writes = if writes_back {
            WriteSet::Two(rt, rn)
        } else {
            WriteSet::One(rt)
        };
        step.recognized = true;
        return true;
    }
    if word & 0xFFE0_0000 == 0xF800_0000 {
        step.writes = if writes_back {
            WriteSet::One(rn)
        } else {
            WriteSet::None
        };
        step.recognized = true;
        return true;
    }
    false
}

fn decode_adrp(addr: u64, word: u32) -> Option<(u8, u64)> {
    if word & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let rd: u8 = (word & 0x1F) as u8;
    let immlo: u64 = u64::from((word >> 29) & 0x3);
    let immhi: u64 = u64::from((word >> 5) & 0x7_FFFF);
    let imm21: u64 = (immhi << 2) | immlo;
    let signed: i64 = ((imm21 << 43) as i64) >> 43;
    let page_delta: i64 = signed << 12;
    let base: i64 = (addr & !0xFFF) as i64;
    Some((rd, base.wrapping_add(page_delta) as u64))
}

fn decode_ldr64(word: u32) -> Option<(u8, u8, u64)> {
    if word & 0xFFC0_0000 != 0xF940_0000 {
        return None;
    }
    let rt: u8 = (word & 0x1F) as u8;
    let rn: u8 = ((word >> 5) & 0x1F) as u8;
    let imm12: u64 = u64::from((word >> 10) & 0xFFF);
    Some((rt, rn, imm12 * 8))
}

fn branch_target(addr: u64, word: u32) -> u64 {
    let imm26: u64 = u64::from(word & 0x03FF_FFFF);
    let signed: i64 = ((imm26 << 38) as i64) >> 38;
    addr.wrapping_add((signed << 2) as u64)
}

fn decode_x86(addr: u64, bytes: &[u8]) -> Step {
    let mut step: Step = Step {
        addr,
        ..Step::default()
    };
    if bytes.is_empty() {
        return step;
    }
    let len: usize = bytes.len();
    let end: u64 = addr.wrapping_add(len as u64);
    let mut i: usize = 0;
    let (mut rex_r, mut rex_b): (u8, u8) = (0, 0);
    while i < len {
        let byte: u8 = bytes[i];
        if (0x40..=0x4F).contains(&byte) {
            rex_r = (byte >> 2) & 1;
            rex_b = byte & 1;
            i += 1;
            continue;
        }
        if matches!(
            byte,
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65
        ) {
            i += 1;
            continue;
        }
        break;
    }
    let Some(&opcode): Option<&u8> = bytes.get(i) else {
        return step;
    };
    match opcode {
        0xE8 => {
            step.call = Some(CallForm::Direct(end.wrapping_add(read_disp(bytes, i + 1))));
            step.boundary = true;
            step.recognized = true;
        }
        0xE9 | 0xEB => {
            let delta: u64 = if opcode == 0xEB {
                read_disp8(bytes, i + 1)
            } else {
                read_disp(bytes, i + 1)
            };
            let target: u64 = end.wrapping_add(delta);
            step.call = Some(CallForm::Direct(target));
            step.terminator = Terminator::Branch {
                target: Some(target),
                conditional: false,
            };
            step.boundary = true;
            step.recognized = true;
        }
        0xC3 | 0xC2 | 0xF4 => {
            step.terminator = Terminator::Return;
            step.boundary = true;
            step.recognized = true;
        }
        0x70..=0x7F => {
            step.terminator = Terminator::Branch {
                target: Some(end.wrapping_add(read_disp8(bytes, i + 1))),
                conditional: true,
            };
            step.boundary = true;
            step.recognized = true;
        }
        0x0F => {
            if matches!(bytes.get(i + 1), Some(0x80..=0x8F)) {
                step.terminator = Terminator::Branch {
                    target: Some(end.wrapping_add(read_disp(bytes, i + 2))),
                    conditional: true,
                };
                step.boundary = true;
                step.recognized = true;
            } else if matches!(bytes.get(i + 1), Some(0x1F)) {
                step.recognized = true;
            }
        }
        0xFF => decode_x86_ff(bytes, i, end, rex_b, &mut step),
        0x8B => decode_x86_load(bytes, i, end, rex_r, rex_b, true, &mut step),
        0x63 => decode_x86_load(bytes, i, end, rex_r, rex_b, false, &mut step),
        0x89 => decode_x86_store(bytes, i, rex_r, rex_b, true, &mut step),
        0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 => {
            decode_x86_store(bytes, i, rex_r, rex_b, false, &mut step);
        }
        0x8D | 0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 => {
            decode_x86_reg_dest(bytes, i, rex_r, &mut step);
        }
        0xB8..=0xBF => {
            step.writes = WriteSet::One((opcode - 0xB8) | (rex_b << 3));
            step.recognized = true;
        }
        0x58..=0x5F => {
            step.writes = WriteSet::One((opcode - 0x58) | (rex_b << 3));
            step.recognized = true;
        }
        0x83 | 0x81 | 0xC7 => decode_x86_group_imm(bytes, i, rex_b, &mut step),
        0x50..=0x57 | 0x39 | 0x3B | 0x85 | 0x90 => {
            step.recognized = true;
        }
        _ => {}
    }
    step
}

fn decode_x86_ff(bytes: &[u8], i: usize, end: u64, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = (modrm >> 3) & 0x7;
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    match reg {
        2 | 3 => {
            step.call = indirect_call_form(bytes, i, end, mode, rm, rex_b);
            step.boundary = true;
            step.recognized = true;
        }
        4 | 5 => {
            step.call = indirect_call_form(bytes, i, end, mode, rm, rex_b);
            step.terminator = Terminator::Branch {
                target: None,
                conditional: false,
            };
            step.boundary = true;
            step.recognized = true;
        }
        0 | 1 => {
            if mode == 3 {
                step.writes = WriteSet::One(rm | (rex_b << 3));
            }
            step.recognized = true;
        }
        _ => {
            step.recognized = true;
        }
    }
}

fn indirect_call_form(
    bytes: &[u8],
    i: usize,
    end: u64,
    mode: u8,
    rm: u8,
    rex_b: u8,
) -> Option<CallForm> {
    match (mode, rm) {
        (0, 5) => Some(CallForm::Direct(end.wrapping_add(read_disp(bytes, i + 2)))),
        (3, _) => Some(CallForm::Indirect(rm | (rex_b << 3))),
        _ => None,
    }
}

fn decode_x86_load(
    bytes: &[u8],
    i: usize,
    end: u64,
    rex_r: u8,
    rex_b: u8,
    is_move: bool,
    step: &mut Step,
) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = ((modrm >> 3) & 0x7) | (rex_r << 3);
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    step.writes = WriteSet::One(reg);
    step.recognized = true;
    if mode == 0 && rm == 5 {
        step.pc_relative_slot = Some(end.wrapping_add(read_disp(bytes, i + 2)));
    } else if mode == 3 && is_move {
        step.mov_from = Some(rm | (rex_b << 3));
    }
}

fn decode_x86_store(bytes: &[u8], i: usize, rex_r: u8, rex_b: u8, is_move: bool, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    if mode == 3 {
        step.writes = WriteSet::One(rm | (rex_b << 3));
        if is_move {
            step.mov_from = Some(((modrm >> 3) & 0x7) | (rex_r << 3));
        }
    }
    step.recognized = true;
}

fn decode_x86_reg_dest(bytes: &[u8], i: usize, rex_r: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = ((modrm >> 3) & 0x7) | (rex_r << 3);
    step.writes = WriteSet::One(reg);
    step.recognized = true;
}

fn decode_x86_group_imm(bytes: &[u8], i: usize, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    let reg: u8 = (modrm >> 3) & 0x7;
    if mode == 3 && reg != 7 {
        step.writes = WriteSet::One(rm | (rex_b << 3));
    }
    step.recognized = true;
}

fn read_disp(bytes: &[u8], off: usize) -> u64 {
    read_i32_le(bytes, off) as i64 as u64
}

fn read_disp8(bytes: &[u8], off: usize) -> u64 {
    bytes.get(off).map_or(0, |b: &u8| *b as i8 as i64 as u64)
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    let mut arr: [u8; 4] = [0u8; 4];
    if let Some(window) = bytes.get(off..off + 4) {
        arr.copy_from_slice(window);
    }
    u32::from_le_bytes(arr)
}

fn read_i32_le(bytes: &[u8], off: usize) -> i32 {
    read_u32_le(bytes, off) as i32
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let raw: &[u8] = hex.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(raw.len() / 2);
    let mut index: usize = 0;
    while index + 1 < raw.len() {
        let hi: u8 = hex_nibble(raw[index]);
        let lo: u8 = hex_nibble(raw[index + 1]);
        if hi == 0xFF || lo == 0xFF {
            break;
        }
        out.push((hi << 4) | lo);
        index += 2;
    }
    out
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0xFF,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::macho::{Bitness, CpuKind, Endian, SliceHeader};
    use std::time::{Duration, Instant};

    #[test]
    fn message_abi_profiles_pin_every_supported_entry_point() {
        let cases: [(DispatchArch, &str, MessageAbiProfile); 9] = [
            (
                DispatchArch::Arm64,
                "_objc_msgSend",
                MessageAbiProfile {
                    selector: TrackedRegister(1),
                    receiver: TrackedRegister(0),
                    unresolved_receiver: "x0",
                    arguments: &["x2", "x3", "x4", "x5", "x6", "x7"],
                    receiver_mode: ReceiverMode::Object,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::Arm64,
                "_objc_msgSendSuper",
                MessageAbiProfile {
                    selector: TrackedRegister(1),
                    receiver: TrackedRegister(0),
                    unresolved_receiver: "x0",
                    arguments: &["x2", "x3", "x4", "x5", "x6", "x7"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::Arm64,
                "_objc_msgSendSuper2",
                MessageAbiProfile {
                    selector: TrackedRegister(1),
                    receiver: TrackedRegister(0),
                    unresolved_receiver: "x0",
                    arguments: &["x2", "x3", "x4", "x5", "x6", "x7"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSend",
                MessageAbiProfile {
                    selector: TrackedRegister(6),
                    receiver: TrackedRegister(7),
                    unresolved_receiver: "rdi",
                    arguments: &["rdx", "rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Object,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSendSuper",
                MessageAbiProfile {
                    selector: TrackedRegister(6),
                    receiver: TrackedRegister(7),
                    unresolved_receiver: "rdi",
                    arguments: &["rdx", "rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSendSuper2",
                MessageAbiProfile {
                    selector: TrackedRegister(6),
                    receiver: TrackedRegister(7),
                    unresolved_receiver: "rdi",
                    arguments: &["rdx", "rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Direct,
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSend_stret",
                MessageAbiProfile {
                    selector: TrackedRegister(2),
                    receiver: TrackedRegister(6),
                    unresolved_receiver: "rsi",
                    arguments: &["rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Object,
                    leading_result: LeadingResultMode::Hidden(TrackedRegister(7)),
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSendSuper_stret",
                MessageAbiProfile {
                    selector: TrackedRegister(2),
                    receiver: TrackedRegister(6),
                    unresolved_receiver: "rsi",
                    arguments: &["rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Hidden(TrackedRegister(7)),
                },
            ),
            (
                DispatchArch::X86_64,
                "_objc_msgSendSuper2_stret",
                MessageAbiProfile {
                    selector: TrackedRegister(2),
                    receiver: TrackedRegister(6),
                    unresolved_receiver: "rsi",
                    arguments: &["rcx", "r8", "r9"],
                    receiver_mode: ReceiverMode::Super,
                    leading_result: LeadingResultMode::Hidden(TrackedRegister(7)),
                },
            ),
        ];
        for (arch, symbol, expected) in cases {
            assert_eq!(
                message_abi_profile(arch, symbol),
                Some(expected),
                "{symbol}"
            );
        }
        for symbol in [
            "_objc_msgSend_stret",
            "_objc_msgSendSuper_stret",
            "_objc_msgSendSuper2_stret",
        ] {
            assert_eq!(message_abi_profile(DispatchArch::Arm64, symbol), None);
        }
        assert_eq!(
            message_abi_profile(DispatchArch::X86_64, "_objc_msgSend_unknown"),
            None
        );
    }

    fn wide_data_segment() -> ParsedSlice {
        ParsedSlice {
            header: SliceHeader {
                cpu: CpuKind::Arm64,
                bitness: Bitness::Bits64,
                endian: Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            segments: vec![macho::Segment {
                name: SEG_DATA.to_owned(),
                vmaddr: 0x1000,
                vmsize: 0x1_0000_0000,
                fileoff: 0,
                filesize: 0x1_0000_0000,
                sections: Vec::<Section>::new(),
            }],
            ..ParsedSlice::default()
        }
    }

    struct ChainedBlob {
        header: Vec<u8>,
        symbols: Vec<u8>,
    }

    fn chained_blob(imports_format: u32, name_offsets: &[u32], symbols: &[&str]) -> ChainedBlob {
        let entry_size: usize = match imports_format {
            CHAINED_IMPORT_ADDEND => 8,
            CHAINED_IMPORT_ADDEND64 => 16,
            _ => 4,
        };
        let imports_offset: u32 = 64;
        let imports_len: u32 =
            u32::try_from(name_offsets.len() * entry_size).expect("import table fits");
        let symbols_offset: u32 = imports_offset + imports_len;
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&imports_offset.to_le_bytes());
        header.extend_from_slice(&symbols_offset.to_le_bytes());
        header.extend_from_slice(
            &u32::try_from(name_offsets.len())
                .expect("import count fits")
                .to_le_bytes(),
        );
        header.extend_from_slice(&imports_format.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.resize(imports_offset as usize, 0);
        for offset in name_offsets {
            match imports_format {
                CHAINED_IMPORT_ADDEND64 => {
                    header.extend_from_slice(&(u64::from(*offset) << 32).to_le_bytes());
                    header.extend_from_slice(&0u64.to_le_bytes());
                }
                CHAINED_IMPORT_ADDEND => {
                    header.extend_from_slice(&(offset << 9).to_le_bytes());
                    header.extend_from_slice(&0u32.to_le_bytes());
                }
                _ => header.extend_from_slice(&(offset << 9).to_le_bytes()),
            }
        }
        let mut table: Vec<u8> = Vec::new();
        for symbol in symbols {
            table.extend_from_slice(symbol.as_bytes());
            table.push(0);
        }
        ChainedBlob {
            header,
            symbols: table,
        }
    }

    fn chained_symbol_table(imports_format: u32) -> Vec<String> {
        let blob: ChainedBlob = chained_blob(
            imports_format,
            &[0, 20],
            &["_OBJC_CLASS_$_NSURL", "_OBJC_CLASS_$_NSBundle"],
        );
        let mut data: Vec<u8> = blob.header;
        data.extend_from_slice(&blob.symbols);
        parse_chained_imports(&data)
    }

    #[test]
    fn every_chained_import_format_yields_the_symbol_it_names() {
        for imports_format in [
            CHAINED_IMPORT,
            CHAINED_IMPORT_ADDEND,
            CHAINED_IMPORT_ADDEND64,
        ] {
            let symbols: Vec<String> = chained_symbol_table(imports_format);
            assert_eq!(
                symbols,
                vec![
                    "_OBJC_CLASS_$_NSURL".to_owned(),
                    "_OBJC_CLASS_$_NSBundle".to_owned()
                ],
                "import format {imports_format} must decode both entries"
            );
        }
    }

    #[test]
    fn an_unknown_chained_import_format_yields_nothing_rather_than_a_guess() {
        assert!(chained_symbol_table(9).is_empty());
    }

    const CHAIN_DATA_AT: usize = 0x1000;
    const CHAIN_PAGE_START: u16 = 0x10;
    const AUTH_BIT: u64 = 1 << 63;

    fn chained_slice(
        pointer_format: u16,
        words: &[(usize, u64)],
        declared_size: Option<u32>,
    ) -> (Vec<u8>, ParsedSlice) {
        let mut parsed: ParsedSlice = wide_data_segment();
        let blob: ChainedBlob = chained_blob(
            CHAINED_IMPORT,
            &[0, 20],
            &["_OBJC_CLASS_$_NSURL", "_OBJC_CLASS_$_NSBundle"],
        );
        let starts_offset: u32 =
            u32::try_from(blob.header.len() + blob.symbols.len()).expect("starts offset fits");
        let mut data: Vec<u8> = blob.header;
        data.extend_from_slice(&blob.symbols);
        data[4..8].copy_from_slice(&starts_offset.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&0x1000u16.to_le_bytes());
        data.extend_from_slice(&pointer_format.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&CHAIN_PAGE_START.to_le_bytes());
        parsed.chained_fixups = Some(LinkeditData {
            offset: u32::try_from(CHAIN_DATA_AT).expect("offset fits"),
            size: declared_size.unwrap_or_else(|| u32::try_from(data.len()).expect("size fits")),
        });

        let mut slice: Vec<u8> = vec![0u8; CHAIN_DATA_AT + data.len()];
        for (at, word) in words {
            slice[*at..*at + 8].copy_from_slice(&word.to_le_bytes());
        }
        slice[CHAIN_DATA_AT..CHAIN_DATA_AT + data.len()].copy_from_slice(&data);
        (slice, parsed)
    }

    fn chained_binds_of(
        pointer_format: u16,
        words: &[(usize, u64)],
        declared_size: Option<u32>,
    ) -> BTreeMap<u64, String> {
        let (slice, parsed): (Vec<u8>, ParsedSlice) =
            chained_slice(pointer_format, words, declared_size);
        let view: SliceView<'_> = SliceView::new(&slice, &parsed).expect("view");
        parse_chained_binds(&slice, &parsed, &view)
    }

    #[test]
    fn a_chained_bind_chain_resolves_every_slot_it_links() {
        let first: u64 = 1u64 << 63 | 2u64 << 51 | 1;
        let second: u64 = 1u64 << 63;
        let binds: BTreeMap<u64, String> =
            chained_binds_of(CHAINED_PTR_64, &[(0x10, first), (0x18, second)], None);
        assert_eq!(
            binds.get(&0x1010).map(String::as_str),
            Some("_OBJC_CLASS_$_NSBundle"),
            "the first link names the import its ordinal selects"
        );
        assert_eq!(
            binds.get(&0x1018).map(String::as_str),
            Some("_OBJC_CLASS_$_NSURL"),
            "the chain continues to the slot the next field points at, four bytes to the stride"
        );
        assert_eq!(binds.len(), 2);
        assert_eq!(
            strip_class_symbol("_OBJC_CLASS_$_NSBundle"),
            Some("NSBundle")
        );
    }

    #[test]
    fn an_authenticated_bind_names_the_same_import_as_a_plain_one() {
        for pointer_format in [CHAINED_PTR_ARM64E, CHAINED_PTR_ARM64E_USERLAND24] {
            let plain: u64 = 1u64 << 62 | 1;
            let authenticated: u64 = AUTH_BIT | plain;
            let plain_binds: BTreeMap<u64, String> =
                chained_binds_of(pointer_format, &[(0x10, plain)], None);
            let auth_binds: BTreeMap<u64, String> =
                chained_binds_of(pointer_format, &[(0x10, authenticated)], None);
            assert_eq!(
                plain_binds.get(&0x1010).map(String::as_str),
                Some("_OBJC_CLASS_$_NSBundle"),
                "format {pointer_format} must resolve a plain bind"
            );
            assert_eq!(
                auth_binds, plain_binds,
                "format {pointer_format} carries the authentication bits above the bind bit, and \
                 the diversity and key an authenticated pointer adds do not move the ordinal, so \
                 signing a pointer must not change which import it names"
            );
        }
    }

    #[test]
    fn an_authenticated_rebase_is_never_read_as_a_bind() {
        for pointer_format in [CHAINED_PTR_ARM64E, CHAINED_PTR_ARM64E_USERLAND24] {
            let rebase: u64 = AUTH_BIT | 1;
            let binds: BTreeMap<u64, String> =
                chained_binds_of(pointer_format, &[(0x10, rebase)], None);
            assert!(
                binds.is_empty(),
                "format {pointer_format}: this word has the authentication bit set and the bind \
                 bit clear, so it rebases a pointer inside this image and names no import. \
                 Reading the authentication bit as the bind bit would take its low bits for an \
                 ordinal and attach a real symbol name to a slot that never imported anything, \
                 which is the kind of wrong answer that reads as a correct one"
            );
        }
    }

    #[test]
    fn a_chain_that_leaves_the_mapped_image_stops_instead_of_inventing_a_slot() {
        let runaway: u64 = 1u64 << 63 | 0x7FFu64 << 51 | 1;
        let binds: BTreeMap<u64, String> =
            chained_binds_of(CHAINED_PTR_64, &[(0x10, runaway)], None);
        assert_eq!(
            binds.get(&0x1010).map(String::as_str),
            Some("_OBJC_CLASS_$_NSBundle"),
            "the slot that is present is still resolved"
        );
        assert_eq!(
            binds.len(),
            1,
            "the next link lands outside every mapped segment, so the walk stops there rather \
             than reading whatever byte follows and reporting a slot the image does not have"
        );
    }

    #[test]
    fn an_ordinal_past_the_import_table_names_nothing() {
        let out_of_range: u64 = 1u64 << 63 | 0x00FF_FFFF;
        let binds: BTreeMap<u64, String> =
            chained_binds_of(CHAINED_PTR_64, &[(0x10, out_of_range)], None);
        assert!(
            binds.is_empty(),
            "the import table holds two entries, so an ordinal past it must leave the slot \
             unnamed rather than wrap onto a name that happens to be in range"
        );
    }

    #[test]
    fn a_fixup_blob_that_runs_past_the_file_yields_nothing() {
        let word: u64 = 1u64 << 63 | 1;
        let binds: BTreeMap<u64, String> =
            chained_binds_of(CHAINED_PTR_64, &[(0x10, word)], Some(1 << 20));
        assert!(
            binds.is_empty(),
            "the load command declares more fixup bytes than the file holds, so the table is not \
             there to be read and no part of it may be reported as read"
        );
    }

    #[test]
    fn an_unknown_pointer_format_yields_nothing_rather_than_a_guess() {
        let word: u64 = 1u64 << 63 | 1;
        let binds: BTreeMap<u64, String> = chained_binds_of(99, &[(0x10, word)], None);
        assert!(binds.is_empty());
        assert_eq!(
            ChainedPointerFormat::from_raw(99),
            ChainedPointerFormat::Unsupported(99)
        );
        assert!(!ChainedPointerFormat::Unsupported(99).is_authenticated());
    }

    #[test]
    fn the_arm64e_formats_are_the_authenticated_ones() {
        for raw in [
            CHAINED_PTR_ARM64E,
            CHAINED_PTR_ARM64E_KERNEL,
            CHAINED_PTR_ARM64E_USERLAND,
            CHAINED_PTR_ARM64E_USERLAND24,
        ] {
            assert!(ChainedPointerFormat::from_raw(raw).is_authenticated());
        }
        for raw in [CHAINED_PTR_64, CHAINED_PTR_64_OFFSET] {
            assert!(!ChainedPointerFormat::from_raw(raw).is_authenticated());
        }
    }

    fn push_uleb(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte: u8 = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn repeated_uleb_times_skipping_cannot_exceed_shared_cap() {
        let parsed: ParsedSlice = wide_data_segment();
        let mut stream: Vec<u8> = Vec::new();
        stream.push(0x40);
        stream.extend_from_slice(b"_s\0");
        stream.push(0x70);
        push_uleb(&mut stream, 0);
        for _ in 0..8u32 {
            stream.push(0xC0);
            push_uleb(&mut stream, MAX_SLOTS as u64);
            push_uleb(&mut stream, 0);
        }
        let mut out: BTreeMap<u64, String> = BTreeMap::new();
        let mut total: usize = 0;
        let started: Instant = Instant::now();
        interpret_bind(&stream, &parsed, 0, stream.len(), &mut out, &mut total);
        let elapsed: Duration = started.elapsed();
        assert_eq!(total, MAX_TOTAL_BINDS);
        assert_eq!(out.len(), MAX_TOTAL_BINDS);
        assert!(
            elapsed < Duration::from_secs(3),
            "bind parse took {elapsed:?}"
        );
    }
}
