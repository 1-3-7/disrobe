use std::collections::BTreeSet;

use iced_x86::{Instruction, OpKind, Register};
use object::{File, Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind, SymbolSection};

use crate::import_map::ImportMap;
use crate::lattice::Width;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Region {
    Stack,
    Global,
    Heap,
    Tls,
    ConstPool,
    Unknown,
}

impl Region {
    #[must_use]
    pub const fn never_aliases_other_region(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locator {
    FrameDisp(i64),
    Address(u64),
    Based {
        segment: Register,
        base: Register,
        symbol: IndexSymbol,
        disp: i64,
    },
    Wide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellKey {
    pub region: Region,
    pub locator: Locator,
}

impl CellKey {
    #[must_use]
    pub const fn stack(rbp_disp: i64) -> Self {
        Self {
            region: Region::Stack,
            locator: Locator::FrameDisp(rbp_disp),
        }
    }

    #[must_use]
    pub const fn wide(region: Region) -> Self {
        Self {
            region,
            locator: Locator::Wide,
        }
    }

    #[must_use]
    pub fn of(access: &MemoryAccess, symbol: IndexSymbol) -> Self {
        let locator: Locator = match access.base {
            Register::None | Register::RIP | Register::EIP => {
                Locator::Address(u64::from_ne_bytes(access.disp.to_ne_bytes()))
            }
            base => Locator::Based {
                segment: access.segment,
                base: base.full_register(),
                symbol,
                disp: access.disp,
            },
        };
        Self {
            region: access.region,
            locator,
        }
    }

    #[must_use]
    pub const fn frame_disp(self) -> Option<i64> {
        match (self.region, self.locator) {
            (Region::Stack, Locator::FrameDisp(disp)) => Some(disp),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum AliasResult {
    NoAlias {
        reason: Option<DisjointReason>,
    },
    #[default]
    MayAlias,
    PartialAlias,
    MustAlias,
}

impl AliasResult {
    #[must_use]
    pub const fn no_alias(reason: DisjointReason) -> Self {
        Self::NoAlias {
            reason: Some(reason),
        }
    }

    #[must_use]
    pub const fn region_no_alias() -> Self {
        Self::NoAlias { reason: None }
    }

    #[must_use]
    pub const fn may_alias(self) -> bool {
        !matches!(self, Self::NoAlias { .. })
    }

    #[must_use]
    pub const fn is_must(self) -> bool {
        matches!(self, Self::MustAlias)
    }

    #[must_use]
    pub const fn is_partial(self) -> bool {
        matches!(self, Self::PartialAlias)
    }

    #[must_use]
    pub const fn disjoint_reason(self) -> Option<DisjointReason> {
        match self {
            Self::NoAlias { reason } => reason,
            Self::MayAlias | Self::PartialAlias | Self::MustAlias => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisjointReason {
    ConstExtent,
    CorrelatedField,
    BoundedInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IndexSymbol {
    block: usize,
    register_write: Option<usize>,
    call_barrier: Option<usize>,
}

impl IndexSymbol {
    #[must_use]
    pub(crate) const fn new(
        block: usize,
        register_write: Option<usize>,
        call_barrier: Option<usize>,
    ) -> Self {
        Self {
            block,
            register_write,
            call_barrier,
        }
    }
}

pub trait AliasOracle {
    fn alias(&self, a: &MemoryAccess, b: &MemoryAccess) -> AliasResult;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysMayAlias;

impl AliasOracle for AlwaysMayAlias {
    fn alias(&self, _a: &MemoryAccess, _b: &MemoryAccess) -> AliasResult {
        AliasResult::MayAlias
    }
}

impl AliasOracle for RegionModel {
    fn alias(&self, a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
        let result: AliasResult = alias_access(a, b);
        debug_assert!(
            alias_access(b, a) == result,
            "alias oracle must be symmetric",
        );
        debug_assert!(
            !result.is_must() || result.may_alias(),
            "MustAlias must imply MayAlias",
        );
        debug_assert!(
            !(a.escapes || b.escapes) || result.may_alias(),
            "an escaped access must never be proven NoAlias",
        );
        debug_assert!(
            !(a.region == Region::Unknown || b.region == Region::Unknown) || result.may_alias(),
            "an unknown-region access must never be proven NoAlias",
        );
        debug_assert!(
            !unbounded_index_requires_may_alias(a, b) || result.may_alias(),
            "an unbounded indexed access must never be proven NoAlias without correlation",
        );
        result
    }
}

fn alias_access(a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
    if a.escapes || b.escapes {
        return AliasResult::MayAlias;
    }
    if matches!(a.region, Region::Unknown) || matches!(b.region, Region::Unknown) {
        return AliasResult::MayAlias;
    }
    if unbounded_index_requires_may_alias(a, b) {
        return AliasResult::MayAlias;
    }
    if a.region != b.region {
        if a.region.never_aliases_other_region() && b.region.never_aliases_other_region() {
            return AliasResult::region_no_alias();
        }
        return AliasResult::MayAlias;
    }
    match a.region {
        Region::Heap => AliasResult::MayAlias,
        _ => extent_region_alias(a, b),
    }
}

fn extent_region_alias(a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
    if a.base.full_register() != b.base.full_register() || a.segment != b.segment {
        return AliasResult::MayAlias;
    }
    let (Some(wa), Some(wb)): (Option<u8>, Option<u8>) = (a.width.bytes(), b.width.bytes()) else {
        return AliasResult::MayAlias;
    };
    if a.index.is_none() && b.index.is_none() {
        return extent_alias(a.disp, wa, b.disp, wb, DisjointReason::ConstExtent);
    }
    if indexes_are_correlated(a, b) {
        return extent_alias(a.disp, wa, b.disp, wb, DisjointReason::CorrelatedField);
    }
    bounded_interval_alias(a, wa, b, wb)
}

fn unbounded_index_requires_may_alias(a: &MemoryAccess, b: &MemoryAccess) -> bool {
    (unbounded_index(a) || unbounded_index(b)) && !indexes_are_correlated(a, b)
}

const fn unbounded_index(access: &MemoryAccess) -> bool {
    access.index.is_some() && (access.index_bound.is_none() || !has_valid_index_scale(access))
}

fn indexes_are_correlated(a: &MemoryAccess, b: &MemoryAccess) -> bool {
    let (Some(index_a), Some(index_b), Some(symbol_a), Some(symbol_b)): (
        Option<Register>,
        Option<Register>,
        Option<IndexSymbol>,
        Option<IndexSymbol>,
    ) = (a.index, b.index, a.index_symbol, b.index_symbol) else {
        return false;
    };
    index_a != Register::None
        && index_b != Register::None
        && index_a.full_register() == index_b.full_register()
        && a.index_address_size == b.index_address_size
        && symbol_a == symbol_b
        && has_valid_index_scale(a)
        && has_valid_index_scale(b)
        && a.index_scale == b.index_scale
}

const fn has_valid_index_scale(access: &MemoryAccess) -> bool {
    matches!(access.index_scale, 1 | 2 | 4 | 8)
}

fn extent_alias(
    disp_a: i64,
    width_a: u8,
    disp_b: i64,
    width_b: u8,
    reason: DisjointReason,
) -> AliasResult {
    let Some(end_a): Option<i64> = disp_a.checked_add(i64::from(width_a)) else {
        return AliasResult::MayAlias;
    };
    let Some(end_b): Option<i64> = disp_b.checked_add(i64::from(width_b)) else {
        return AliasResult::MayAlias;
    };
    if disp_a >= end_b || disp_b >= end_a {
        return AliasResult::no_alias(reason);
    }
    if disp_a == disp_b && width_a == width_b {
        return AliasResult::MustAlias;
    }
    AliasResult::PartialAlias
}

fn bounded_interval_alias(
    a: &MemoryAccess,
    width_a: u8,
    b: &MemoryAccess,
    width_b: u8,
) -> AliasResult {
    let (Some(upper_a), Some(upper_b)): (Option<u64>, Option<u64>) =
        (index_upper_bound(a), index_upper_bound(b))
    else {
        return AliasResult::MayAlias;
    };
    if !bounded_offsets_are_linear(a, upper_a, b, upper_b) {
        return AliasResult::MayAlias;
    }
    let scale_a: u8 = address_scale(a);
    let scale_b: u8 = address_scale(b);
    let Some(scale_gcd): Option<u8> = nonzero_gcd(scale_a, scale_b) else {
        return AliasResult::MayAlias;
    };
    let base: i128 = i128::from(a.disp) - i128::from(b.disp);
    let minimum: i128 = base - i128::from(scale_b) * i128::from(upper_b);
    let maximum: i128 = base + i128::from(scale_a) * i128::from(upper_a);
    let overlap_minimum: i128 = 1 - i128::from(width_a);
    let overlap_maximum: i128 = i128::from(width_b) - 1;
    let candidate_minimum: i128 = minimum.max(overlap_minimum);
    let candidate_maximum: i128 = maximum.min(overlap_maximum);
    if candidate_minimum > candidate_maximum {
        return AliasResult::no_alias(DisjointReason::BoundedInterval);
    }
    let modulus: i128 = i128::from(scale_gcd);
    let residue: i128 = base.rem_euclid(modulus);
    let first: i128 = candidate_minimum + (residue - candidate_minimum).rem_euclid(modulus);
    if first > candidate_maximum {
        return AliasResult::no_alias(DisjointReason::BoundedInterval);
    }
    AliasResult::MayAlias
}

fn index_upper_bound(access: &MemoryAccess) -> Option<u64> {
    if access.index.is_none() {
        return Some(0);
    }
    if !has_valid_index_scale(access) {
        return None;
    }
    let (lower, upper): (u64, u64) = access.index_bound?;
    (lower <= upper).then_some(upper)
}

fn bounded_offsets_are_linear(
    a: &MemoryAccess,
    upper_a: u64,
    b: &MemoryAccess,
    upper_b: u64,
) -> bool {
    if (a.index.is_some() && a.index_address_size != 8)
        || (b.index.is_some() && b.index_address_size != 8)
    {
        return false;
    }
    let maximum_a: i128 = i128::from(a.disp) + i128::from(address_scale(a)) * i128::from(upper_a);
    let maximum_b: i128 = i128::from(b.disp) + i128::from(address_scale(b)) * i128::from(upper_b);
    let minimum: i128 = i128::from(a.disp).min(i128::from(b.disp));
    let maximum: i128 = maximum_a.max(maximum_b);
    maximum - minimum <= i128::from(i64::MAX)
}

const fn address_scale(access: &MemoryAccess) -> u8 {
    if access.index.is_some() {
        access.index_scale
    } else {
        0
    }
}

fn nonzero_gcd(left: u8, right: u8) -> Option<u8> {
    let mut a: u8 = left;
    let mut b: u8 = right;
    while b != 0 {
        let remainder: u8 = a % b;
        a = b;
        b = remainder;
    }
    (a != 0).then_some(a)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Rodata,
    Data,
    Bss,
    Tls,
    Code,
    Other,
}

const MAX_SECTIONS: usize = 1 << 12;
const MAX_RELOC_TARGETS: usize = 1 << 16;
const MAX_ALLOCATOR_SITES: usize = 1 << 12;
const MAX_ALLOCATOR_SYMBOLS: usize = 1 << 20;
const MAX_THUNK_SCAN: usize = 1 << 24;
const THUNK_LENGTH: usize = 6;
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
const BND_PREFIX: u8 = 0xf2;
const ELF_SHF_WRITE: u64 = 0x1;
const ELF_SHF_ALLOC: u64 = 0x2;
const ELF_SHF_EXECINSTR: u64 = 0x4;
const ELF_SHF_TLS: u64 = 0x400;
const COFF_MEM_EXECUTE: u32 = 0x2000_0000;
const COFF_MEM_WRITE: u32 = 0x8000_0000;
const COFF_CNT_CODE: u32 = 0x20;
const MACHO_SECTION_TYPE: u32 = 0xff;
const MACHO_ZEROFILL: u32 = 0x1;
const MACHO_THREAD_LOCAL_FIRST: u32 = 0x11;
const MACHO_THREAD_LOCAL_LAST: u32 = 0x15;
const MACHO_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const MACHO_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

const ALLOCATOR_NAMES: &[&str] = &[
    "??2@YAPAXI@Z",
    "??2@YAPEAX_K@Z",
    "??2@YAPEAX_KAEBUnothrow_t@std@@@Z",
    "??_U@YAPAXI@Z",
    "??_U@YAPEAX_K@Z",
    "??_U@YAPEAX_KAEBUnothrow_t@std@@@Z",
    "CoTaskMemAlloc",
    "CoTaskMemRealloc",
    "GlobalAlloc",
    "GlobalReAlloc",
    "HeapAlloc",
    "HeapReAlloc",
    "LocalAlloc",
    "LocalReAlloc",
    "MIDL_user_allocate",
    "RtlAllocateHeap",
    "RtlReAllocateHeap",
    "SysAllocString",
    "SysAllocStringByteLen",
    "SysAllocStringLen",
    "VirtualAlloc",
    "_ZnajRKSt9nothrow_t",
    "_ZnamRKSt9nothrow_t",
    "_ZnamSt11align_val_t",
    "_ZnamSt11align_val_tRKSt9nothrow_t",
    "_ZnwjRKSt9nothrow_t",
    "_ZnwmRKSt9nothrow_t",
    "_ZnwmSt11align_val_t",
    "_ZnwmSt11align_val_tRKSt9nothrow_t",
    "_Znaj",
    "_Znam",
    "_Znwj",
    "_Znwm",
    "__libc_calloc",
    "__libc_malloc",
    "__libc_memalign",
    "__libc_realloc",
    "__strdup",
    "_aligned_malloc",
    "_aligned_offset_malloc",
    "_aligned_realloc",
    "_calloc_base",
    "_expand",
    "_malloc_base",
    "_mbsdup",
    "_realloc_base",
    "_recalloc",
    "_strdup",
    "_wcsdup",
    "aligned_alloc",
    "calloc",
    "malloc",
    "memalign",
    "pvalloc",
    "realloc",
    "reallocarray",
    "strdup",
    "strndup",
    "valloc",
];

fn allocator_key(name: &str) -> &str {
    if name.starts_with('?') {
        return name;
    }
    name.split_once('@')
        .map_or(name, |(head, _): (&str, &str)| head)
}

fn is_allocator_name(name: &str) -> bool {
    ALLOCATOR_NAMES.contains(&allocator_key(name))
}

#[derive(Debug, Default, Clone)]
pub struct RegionModel {
    frame_regs: Vec<Register>,
    rodata: Vec<(u64, u64)>,
    data: Vec<(u64, u64)>,
    bss: Vec<(u64, u64)>,
    tls: Vec<(u64, u64)>,
    code: Vec<(u64, u64)>,
    reloc_targets: BTreeSet<u64>,
    allocator_sites: BTreeSet<u64>,
}

fn contains(ranges: &[(u64, u64)], addr: u64) -> bool {
    ranges
        .iter()
        .any(|(start, end): &(u64, u64)| addr >= *start && addr < *end)
}

fn section_kind_of(section: &object::Section<'_, '_>) -> SectionKind {
    match section.flags() {
        SectionFlags::Elf { sh_flags } => elf_section_kind(sh_flags),
        SectionFlags::Coff { characteristics } => {
            coff_section_kind(characteristics, section.name().unwrap_or_default())
        }
        SectionFlags::MachO { flags } => mach_o_section_kind(flags, section),
        _ => SectionKind::Other,
    }
}

const fn elf_section_kind(sh_flags: u64) -> SectionKind {
    if sh_flags & ELF_SHF_ALLOC == 0 {
        return SectionKind::Other;
    }
    if sh_flags & ELF_SHF_EXECINSTR != 0 {
        return SectionKind::Code;
    }
    if sh_flags & ELF_SHF_TLS != 0 {
        return SectionKind::Tls;
    }
    if sh_flags & ELF_SHF_WRITE != 0 {
        return SectionKind::Data;
    }
    SectionKind::Rodata
}

fn coff_section_kind(characteristics: u32, name: &str) -> SectionKind {
    if characteristics & (COFF_MEM_EXECUTE | COFF_CNT_CODE) != 0 {
        return SectionKind::Code;
    }
    if name.starts_with(".tls") {
        return SectionKind::Tls;
    }
    if characteristics & COFF_MEM_WRITE != 0 {
        return SectionKind::Data;
    }
    SectionKind::Rodata
}

fn mach_o_section_kind(flags: u32, section: &object::Section<'_, '_>) -> SectionKind {
    let kind: u32 = flags & MACHO_SECTION_TYPE;
    if (MACHO_THREAD_LOCAL_FIRST..=MACHO_THREAD_LOCAL_LAST).contains(&kind) {
        return SectionKind::Tls;
    }
    if flags & (MACHO_ATTR_PURE_INSTRUCTIONS | MACHO_ATTR_SOME_INSTRUCTIONS) != 0 {
        return SectionKind::Code;
    }
    let segment: &str = section.segment_name().ok().flatten().unwrap_or_default();
    if segment.starts_with("__DATA") || segment.starts_with("__AUTH") {
        if kind == MACHO_ZEROFILL {
            return SectionKind::Bss;
        }
        return SectionKind::Data;
    }
    if segment.starts_with("__TEXT") {
        return SectionKind::Rodata;
    }
    SectionKind::Other
}

impl RegionModel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_image(data: &[u8]) -> Self {
        let mut model: Self = Self::default();
        let Ok(file): core::result::Result<File<'_>, object::Error> = File::parse(data) else {
            return model;
        };
        let imports: ImportMap = ImportMap::from_image(data);
        model.absorb_sections(&file);
        model.absorb_relocations(&file);
        model.absorb_import_slots(&imports);
        model.absorb_allocators(&file, &imports);
        model
    }

    fn absorb_sections(&mut self, file: &File<'_>) {
        for section in file.sections().take(MAX_SECTIONS) {
            let start: u64 = section.address();
            let Some(end): Option<u64> = start.checked_add(section.size()) else {
                continue;
            };
            if start == 0 || end == start {
                continue;
            }
            match section_kind_of(&section) {
                SectionKind::Rodata => self.rodata.push((start, end)),
                SectionKind::Data => self.data.push((start, end)),
                SectionKind::Bss => self.bss.push((start, end)),
                SectionKind::Tls => self.tls.push((start, end)),
                SectionKind::Code => self.code.push((start, end)),
                SectionKind::Other => {}
            }
        }
    }

    fn absorb_relocations(&mut self, file: &File<'_>) {
        for section in file.sections().take(MAX_SECTIONS) {
            for (address, _relocation) in section.relocations() {
                if !self.record_reloc_target(address) {
                    return;
                }
            }
        }
        let Some(dynamic): Option<object::read::DynamicRelocationIterator<'_, '_>> =
            file.dynamic_relocations()
        else {
            return;
        };
        for (address, _relocation) in dynamic {
            if !self.record_reloc_target(address) {
                return;
            }
        }
    }

    fn absorb_import_slots(&mut self, imports: &ImportMap) {
        for slot in imports.by_slot_va.keys() {
            if !self.record_reloc_target(*slot) {
                return;
            }
        }
    }

    fn absorb_allocators(&mut self, file: &File<'_>, imports: &ImportMap) {
        let mut slots: BTreeSet<u64> = BTreeSet::new();
        for (slot_va, import) in &imports.by_slot_va {
            let Some(name): Option<&str> = import.name() else {
                continue;
            };
            if !is_allocator_name(name) {
                continue;
            }
            slots.insert(*slot_va);
            if !self.record_allocator_site(*slot_va) {
                return;
            }
        }
        if !self.absorb_allocator_definitions(file) {
            return;
        }
        if !slots.is_empty() {
            self.absorb_allocator_thunks(file, &slots);
        }
    }

    fn absorb_allocator_definitions(&mut self, file: &File<'_>) -> bool {
        for symbol in file
            .symbols()
            .chain(file.dynamic_symbols())
            .take(MAX_ALLOCATOR_SYMBOLS)
        {
            if symbol.kind() != SymbolKind::Text
                || !matches!(symbol.section(), SymbolSection::Section(_))
            {
                continue;
            }
            let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
                continue;
            };
            if !is_allocator_name(name) {
                continue;
            }
            let address: u64 = symbol.address();
            if address == 0 {
                continue;
            }
            if !self.record_allocator_site(address) {
                return false;
            }
        }
        true
    }

    fn absorb_allocator_thunks(&mut self, file: &File<'_>, slots: &BTreeSet<u64>) {
        let mut budget: usize = MAX_THUNK_SCAN;
        for section in file.sections().take(MAX_SECTIONS) {
            if budget == 0 {
                return;
            }
            if section_kind_of(&section) != SectionKind::Code {
                continue;
            }
            let base: u64 = section.address();
            let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
                continue;
            };
            let window: &[u8] = &data[..data.len().min(budget)];
            budget -= window.len();
            if !self.scan_thunks(window, base, slots) {
                return;
            }
        }
    }

    fn scan_thunks(&mut self, data: &[u8], base: u64, slots: &BTreeSet<u64>) -> bool {
        for (offset, window) in data.windows(THUNK_LENGTH).enumerate() {
            let [0xff, 0x25, low, second, third, high]: &[u8] = window else {
                continue;
            };
            let relative: i32 = i32::from_le_bytes([*low, *second, *third, *high]);
            let site: u64 = base.wrapping_add(offset as u64);
            let slot: u64 = site
                .wrapping_add(THUNK_LENGTH as u64)
                .wrapping_add(relative as i64 as u64);
            if !slots.contains(&slot) {
                continue;
            }
            if !self.record_allocator_site(site) {
                return false;
            }
            if !self.record_guarded_entry(data, offset, site) {
                return false;
            }
        }
        true
    }

    fn record_guarded_entry(&mut self, data: &[u8], offset: usize, site: u64) -> bool {
        for lead in [ENDBR64.len(), ENDBR64.len() + 1] {
            let Some(start): Option<usize> = offset.checked_sub(lead) else {
                continue;
            };
            let Some(prefix): Option<&[u8]> = data.get(start..start + ENDBR64.len()) else {
                continue;
            };
            if prefix != ENDBR64 {
                continue;
            }
            if lead > ENDBR64.len() && data.get(offset - 1) != Some(&BND_PREFIX) {
                continue;
            }
            if !self.record_allocator_site(site.wrapping_sub(lead as u64)) {
                return false;
            }
        }
        true
    }

    fn record_reloc_target(&mut self, address: u64) -> bool {
        if self.reloc_targets.len() >= MAX_RELOC_TARGETS {
            return false;
        }
        if !contains(&self.code, address) {
            self.reloc_targets.insert(address);
        }
        true
    }

    fn record_allocator_site(&mut self, address: u64) -> bool {
        if self.allocator_sites.len() >= MAX_ALLOCATOR_SITES {
            return false;
        }
        self.allocator_sites.insert(address);
        true
    }

    #[cfg(test)]
    pub(crate) fn mark_allocator_site(&mut self, address: u64) {
        self.allocator_sites.insert(address);
    }

    #[must_use]
    pub(crate) fn is_allocator_site(&self, address: u64) -> bool {
        self.allocator_sites.contains(&address)
    }

    #[must_use]
    pub(crate) fn has_allocator_sites(&self) -> bool {
        !self.allocator_sites.is_empty()
    }

    pub fn mark_frame(&mut self, reg: Register) {
        let full: Register = reg.full_register();
        if !self.frame_regs.contains(&full) {
            self.frame_regs.push(full);
        }
    }

    pub fn add_rodata(&mut self, start: u64, end: u64) {
        self.rodata.push((start, end));
    }

    pub fn add_data(&mut self, start: u64, end: u64) {
        self.data.push((start, end));
    }

    pub fn add_bss(&mut self, start: u64, end: u64) {
        self.bss.push((start, end));
    }

    pub fn add_tls(&mut self, start: u64, end: u64) {
        self.tls.push((start, end));
    }

    pub fn add_code(&mut self, start: u64, end: u64) {
        self.code.push((start, end));
    }

    pub fn add_reloc_target(&mut self, target: u64) {
        self.reloc_targets.insert(target);
    }

    #[must_use]
    pub(crate) fn is_frame(&self, reg: Register) -> bool {
        matches!(reg, Register::RSP | Register::RBP)
            || self.frame_regs.contains(&reg.full_register())
    }

    #[must_use]
    fn section_of(&self, addr: u64) -> SectionKind {
        if contains(&self.code, addr) {
            return SectionKind::Code;
        }
        let candidates: [(&[(u64, u64)], SectionKind); 4] = [
            (&self.tls, SectionKind::Tls),
            (&self.rodata, SectionKind::Rodata),
            (&self.data, SectionKind::Data),
            (&self.bss, SectionKind::Bss),
        ];
        let mut found: Option<SectionKind> = None;
        for (ranges, kind) in candidates {
            if !contains(ranges, addr) {
                continue;
            }
            match found {
                None => found = Some(kind),
                Some(previous) if region_of_section(previous) == region_of_section(kind) => {}
                Some(_) => return SectionKind::Other,
            }
        }
        found.unwrap_or(SectionKind::Other)
    }

    #[must_use]
    pub fn region_of(&self, addr: u64) -> Region {
        match self.section_of(addr) {
            SectionKind::Code => Region::Unknown,
            SectionKind::Other if self.is_reloc_target(addr) => Region::Global,
            kind => region_of_section(kind),
        }
    }

    #[must_use]
    fn is_reloc_target(&self, addr: u64) -> bool {
        self.reloc_targets.contains(&addr)
    }
}

const fn region_of_section(kind: SectionKind) -> Region {
    match kind {
        SectionKind::Rodata => Region::ConstPool,
        SectionKind::Data | SectionKind::Bss => Region::Global,
        SectionKind::Tls => Region::Tls,
        SectionKind::Code | SectionKind::Other => Region::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    pub region: Region,
    pub segment: Register,
    pub base: Register,
    pub disp: i64,
    pub index: Option<Register>,
    pub index_address_size: u8,
    pub index_symbol: Option<IndexSymbol>,
    pub index_scale: u8,
    pub index_bound: Option<(u64, u64)>,
    pub width: Width,
    pub escapes: bool,
}

#[must_use]
pub fn classify(insn: &Instruction, memop: u32, model: &RegionModel) -> Option<MemoryAccess> {
    if insn.op_kind(memop) != OpKind::Memory {
        return None;
    }
    let segment: Register = insn.segment_prefix();
    let base: Register = insn.memory_base();
    let width: Width = memory_width(insn);
    let disp: i64 = if insn.is_ip_rel_memory_operand() {
        i64::from_ne_bytes(insn.ip_rel_memory_address().to_ne_bytes())
    } else {
        i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes())
    };
    let region: Region = classify_region(insn, segment, base, disp, model);
    let raw_index: Register = insn.memory_index();
    let index: Option<Register> =
        (raw_index != Register::None).then_some(raw_index.full_register());
    let index_address_size: u8 = index_address_size(raw_index);
    let index_scale: u8 = decoded_index_scale(insn.memory_index_scale());
    Some(MemoryAccess {
        region,
        segment,
        base,
        disp,
        index,
        index_address_size,
        index_symbol: None,
        index_scale,
        index_bound: None,
        width,
        escapes: false,
    })
}

fn classify_region(
    insn: &Instruction,
    segment: Register,
    base: Register,
    disp: i64,
    model: &RegionModel,
) -> Region {
    if matches!(segment, Register::FS | Register::GS) {
        return Region::Tls;
    }
    if insn.is_ip_rel_memory_operand() {
        return model.region_of(u64::from_ne_bytes(disp.to_ne_bytes()));
    }
    if model.is_frame(base) {
        return Region::Stack;
    }
    if base == Register::None {
        return model.region_of(u64::from_ne_bytes(disp.to_ne_bytes()));
    }
    Region::Unknown
}

fn index_address_size(index: Register) -> u8 {
    match index.size() {
        4 => 4,
        8 => 8,
        _ => 0,
    }
}

const fn decoded_index_scale(scale: u32) -> u8 {
    match scale {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => 0,
    }
}

fn memory_width(insn: &Instruction) -> Width {
    let size: usize = insn.memory_size().size();
    u8::try_from(size).map_or(Width::Unknown, Width::from_bytes)
}

#[must_use]
pub fn may_alias(a: MemoryAccess, b: MemoryAccess) -> bool {
    RegionModel::default().alias(&a, &b).may_alias()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_single(bytes: &[u8]) -> Instruction {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let instruction: Instruction = decoder.decode();
        assert!(!instruction.is_invalid());
        instruction
    }

    fn stack_access(rbp_disp: i64, width: Width) -> MemoryAccess {
        MemoryAccess {
            region: Region::Stack,
            segment: Register::None,
            base: Register::RBP,
            disp: rbp_disp,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width,
            escapes: false,
        }
    }

    fn indexed_stack_access(
        rbp_disp: i64,
        width: Width,
        index: Register,
        index_scale: u8,
        index_bound: Option<(u64, u64)>,
    ) -> MemoryAccess {
        MemoryAccess {
            region: Region::Stack,
            segment: Register::None,
            base: Register::RBP,
            disp: rbp_disp,
            index: Some(index.full_register()),
            index_address_size: 8,
            index_symbol: Some(IndexSymbol::new(0, None, None)),
            index_scale,
            index_bound,
            width,
            escapes: false,
        }
    }

    #[test]
    fn distinct_stack_slots_never_alias() {
        let a: MemoryAccess = stack_access(-8, Width::Qword);
        let b: MemoryAccess = stack_access(-16, Width::Qword);
        assert!(!may_alias(a, b));
    }

    #[test]
    fn overlapping_stack_slots_may_alias() {
        let a: MemoryAccess = stack_access(-8, Width::Qword);
        let b: MemoryAccess = stack_access(-4, Width::Dword);
        assert!(may_alias(a, b));
    }

    #[test]
    fn distinct_regions_never_alias() {
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let heap: MemoryAccess = MemoryAccess {
            region: Region::Heap,
            segment: Register::None,
            base: Register::RAX,
            disp: 0,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width: Width::Qword,
            escapes: false,
        };
        assert!(!may_alias(stack, heap));
    }

    #[test]
    fn unknown_region_may_alias_everything() {
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let unknown: MemoryAccess = MemoryAccess {
            region: Region::Unknown,
            segment: Register::None,
            base: Register::RAX,
            disp: 0,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width: Width::Qword,
            escapes: false,
        };
        assert!(may_alias(stack, unknown));
        assert!(may_alias(unknown, stack));
    }

    #[test]
    fn escaped_stack_slot_may_alias_same_region() {
        let escaped: MemoryAccess = MemoryAccess {
            escapes: true,
            ..stack_access(-8, Width::Qword)
        };
        let other: MemoryAccess = stack_access(-64, Width::Qword);
        assert!(may_alias(escaped, other));
    }

    #[test]
    fn model_marks_frame_registers() {
        let mut model: RegionModel = RegionModel::new();
        model.mark_frame(Register::R12);
        assert!(model.is_frame(Register::R12));
        assert!(model.is_frame(Register::RBP));
    }

    #[test]
    fn allocator_names_normalize_decoration_but_keep_microsoft_mangling() {
        assert!(is_allocator_name("malloc"));
        assert!(is_allocator_name("malloc@GLIBC_2.2.5"));
        assert!(is_allocator_name("_Znwm"));
        assert!(is_allocator_name("??2@YAPEAX_K@Z"));
        assert!(!is_allocator_name("free"));
        assert!(!is_allocator_name("mmap"));
        assert!(!is_allocator_name("posix_memalign"));
        assert!(!is_allocator_name("VirtualAllocEx"));
        assert!(!is_allocator_name("malloc_usable_size"));
    }

    #[test]
    fn an_allocator_site_is_only_the_recorded_address() {
        let mut model: RegionModel = RegionModel::new();
        model.mark_allocator_site(0x1400);
        assert!(model.is_allocator_site(0x1400));
        assert!(!model.is_allocator_site(0x1401));
        assert!(!model.is_allocator_site(0));
    }

    #[test]
    fn section_membership_resolves_kind() {
        let mut model: RegionModel = RegionModel::new();
        model.add_rodata(0x2000, 0x3000);
        model.add_data(0x4000, 0x5000);
        model.add_bss(0x6000, 0x7000);
        assert_eq!(model.section_of(0x2500), SectionKind::Rodata);
        assert_eq!(model.section_of(0x4001), SectionKind::Data);
        assert_eq!(model.section_of(0x6800), SectionKind::Bss);
        assert_eq!(model.section_of(0x9000), SectionKind::Other);
    }

    fn heap_access(width: Width) -> MemoryAccess {
        MemoryAccess {
            region: Region::Heap,
            segment: Register::None,
            base: Register::RAX,
            disp: 0,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width,
            escapes: false,
        }
    }

    #[test]
    fn default_alias_result_is_may_alias() {
        assert_eq!(AliasResult::default(), AliasResult::MayAlias);
        assert!(AliasResult::MayAlias.may_alias());
        assert!(AliasResult::PartialAlias.may_alias());
        assert!(AliasResult::MustAlias.may_alias());
        assert!(!AliasResult::no_alias(DisjointReason::ConstExtent).may_alias());
    }

    #[test]
    fn oracle_reports_four_valued_stack_results() {
        let model: RegionModel = RegionModel::new();
        let identical_a: MemoryAccess = stack_access(-8, Width::Qword);
        let identical_b: MemoryAccess = stack_access(-8, Width::Qword);
        assert_eq!(
            model.alias(&identical_a, &identical_b),
            AliasResult::MustAlias
        );

        let wide: MemoryAccess = stack_access(-8, Width::Qword);
        let inner: MemoryAccess = stack_access(-4, Width::Dword);
        assert_eq!(model.alias(&wide, &inner), AliasResult::PartialAlias);

        let low: MemoryAccess = stack_access(-16, Width::Qword);
        let high: MemoryAccess = stack_access(-8, Width::Qword);
        let disjoint: AliasResult = model.alias(&low, &high);
        assert_eq!(disjoint, AliasResult::no_alias(DisjointReason::ConstExtent));
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::ConstExtent)
        );
    }

    #[test]
    fn classify_preserves_indexed_rbp_displacements_for_field_aliasing() {
        let first: Instruction = decode_single(&[0x48, 0x8b, 0x44, 0xcd, 0xc0]);
        let second: Instruction = decode_single(&[0x48, 0x8b, 0x54, 0xcd, 0xc8]);
        let model: RegionModel = RegionModel::new();
        let first_access: MemoryAccess = classify(&first, 1, &model).expect("first memory access");
        let second_access: MemoryAccess =
            classify(&second, 1, &model).expect("second memory access");

        assert_eq!(first_access.region, Region::Stack);
        assert_eq!(second_access.region, Region::Stack);
        assert_eq!(first_access.disp, -0x40);
        assert_eq!(second_access.disp, -0x38);
        assert_eq!(first_access.index, Some(Register::RCX));
        assert_eq!(second_access.index, Some(Register::RCX));
        assert_eq!(first_access.index_scale, 8);
        assert_eq!(second_access.index_scale, 8);
        assert_eq!(
            model.alias(&first_access, &second_access),
            AliasResult::MayAlias
        );
    }

    #[test]
    fn correlated_indexes_cancel_to_the_constant_extent_relation() {
        let model: RegionModel = RegionModel::new();
        let low: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let high: MemoryAccess = indexed_stack_access(-0x38, Width::Qword, Register::RCX, 8, None);
        let same: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let overlap: MemoryAccess =
            indexed_stack_access(-0x3c, Width::Dword, Register::RCX, 8, None);

        let disjoint: AliasResult = model.alias(&low, &high);
        assert_eq!(
            disjoint,
            AliasResult::no_alias(DisjointReason::CorrelatedField)
        );
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::CorrelatedField)
        );
        assert_eq!(model.alias(&low, &same), AliasResult::MustAlias);
        assert_eq!(model.alias(&low, &overlap), AliasResult::PartialAlias);
    }

    #[test]
    fn bounded_index_ranges_can_prove_disjoint_extents() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess =
            indexed_stack_access(-0x100, Width::Qword, Register::RCX, 8, Some((0, 3)));
        let second: MemoryAccess =
            indexed_stack_access(-0x80, Width::Qword, Register::RDX, 8, Some((0, 3)));

        let disjoint: AliasResult = model.alias(&first, &second);
        assert_eq!(
            disjoint,
            AliasResult::no_alias(DisjointReason::BoundedInterval)
        );
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::BoundedInterval)
        );
    }

    #[test]
    fn different_unbounded_indexes_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let second: MemoryAccess =
            indexed_stack_access(-0x38, Width::Qword, Register::RDX, 8, None);
        let constant: MemoryAccess = stack_access(-0x40, Width::Qword);

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
        assert_eq!(model.alias(&first, &constant), AliasResult::MayAlias);
    }

    #[test]
    fn different_index_address_sizes_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RAX, 8, None);
        let second: MemoryAccess = MemoryAccess {
            disp: -0x38,
            index_address_size: 4,
            ..first
        };

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
    }

    #[test]
    fn bounded_no_alias_never_overlaps_an_enumerated_index_pair() {
        let model: RegionModel = RegionModel::new();
        let scales: [u8; 4] = [1, 2, 4, 8];
        let width: i64 = 8;
        for disp_a in -16_i64..=16 {
            for disp_b in -16_i64..=16 {
                for scale_a in scales {
                    for scale_b in scales {
                        for bound_a in 0_u64..=3 {
                            for bound_b in 0_u64..=3 {
                                let first: MemoryAccess = indexed_stack_access(
                                    disp_a,
                                    Width::Qword,
                                    Register::RCX,
                                    scale_a,
                                    Some((0, bound_a)),
                                );
                                let second: MemoryAccess = indexed_stack_access(
                                    disp_b,
                                    Width::Qword,
                                    Register::RDX,
                                    scale_b,
                                    Some((0, bound_b)),
                                );
                                let result: AliasResult = model.alias(&first, &second);
                                if result.may_alias() {
                                    continue;
                                }
                                assert_eq!(
                                    result.disjoint_reason(),
                                    Some(DisjointReason::BoundedInterval)
                                );
                                for index_a in 0..=bound_a {
                                    for index_b in 0..=bound_b {
                                        let start_a: i64 = disp_a
                                            + i64::try_from(index_a).expect("small index")
                                                * i64::from(scale_a);
                                        let start_b: i64 = disp_b
                                            + i64::try_from(index_b).expect("small index")
                                                * i64::from(scale_b);
                                        let end_a: i64 = start_a + width;
                                        let end_b: i64 = start_b + width;
                                        assert!(start_a >= end_b || start_b >= end_a);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bounded_ranges_that_can_wrap_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(
            16,
            Width::Qword,
            Register::RCX,
            8,
            Some((0, (1_u64 << 61) - 2)),
        );
        let second: MemoryAccess =
            indexed_stack_access(0, Width::Qword, Register::RDX, 8, Some((0, 0)));

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
    }

    #[test]
    fn oracle_never_proves_disjoint_across_top_or_escape() {
        let model: RegionModel = RegionModel::new();
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let heap: MemoryAccess = heap_access(Width::Qword);
        assert_eq!(model.alias(&stack, &heap), AliasResult::region_no_alias());

        let escaped: MemoryAccess = MemoryAccess {
            escapes: true,
            ..heap
        };
        assert!(model.alias(&stack, &escaped).may_alias());

        let unknown: MemoryAccess = MemoryAccess {
            region: Region::Unknown,
            ..heap
        };
        assert!(model.alias(&stack, &unknown).may_alias());
    }

    fn absolute_access(region: Region, segment: Register, disp: i64, width: Width) -> MemoryAccess {
        MemoryAccess {
            region,
            segment,
            base: Register::None,
            disp,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width,
            escapes: false,
        }
    }

    #[test]
    fn global_extents_report_the_same_four_valued_relation_as_frame_slots() {
        let model: RegionModel = RegionModel::new();
        let counter: MemoryAccess =
            absolute_access(Region::Global, Register::None, 0x0020_3300, Width::Dword);
        let neighbour: MemoryAccess =
            absolute_access(Region::Global, Register::None, 0x0020_3304, Width::Dword);
        let overlap: MemoryAccess =
            absolute_access(Region::Global, Register::None, 0x0020_3302, Width::Word);
        let same: MemoryAccess =
            absolute_access(Region::Global, Register::None, 0x0020_3300, Width::Dword);

        assert_eq!(
            model.alias(&counter, &neighbour),
            AliasResult::no_alias(DisjointReason::ConstExtent),
        );
        assert_eq!(model.alias(&counter, &overlap), AliasResult::PartialAlias);
        assert_eq!(model.alias(&counter, &same), AliasResult::MustAlias);
    }

    #[test]
    fn constant_pool_and_thread_local_extents_split_the_same_way() {
        let model: RegionModel = RegionModel::new();
        let first_constant: MemoryAccess =
            absolute_access(Region::ConstPool, Register::None, 0x0020_0200, Width::Dword);
        let second_constant: MemoryAccess =
            absolute_access(Region::ConstPool, Register::None, 0x0020_0204, Width::Dword);
        assert_eq!(
            model.alias(&first_constant, &second_constant),
            AliasResult::no_alias(DisjointReason::ConstExtent),
        );

        let first_slot: MemoryAccess =
            absolute_access(Region::Tls, Register::FS, 0x28, Width::Qword);
        let second_slot: MemoryAccess =
            absolute_access(Region::Tls, Register::FS, 0x30, Width::Qword);
        assert_eq!(
            model.alias(&first_slot, &second_slot),
            AliasResult::no_alias(DisjointReason::ConstExtent),
        );
    }

    #[test]
    fn a_different_segment_never_proves_disjoint() {
        let model: RegionModel = RegionModel::new();
        let from_fs: MemoryAccess = absolute_access(Region::Tls, Register::FS, 0x28, Width::Qword);
        let from_gs: MemoryAccess = absolute_access(Region::Tls, Register::GS, 0x30, Width::Qword);
        assert_eq!(model.alias(&from_fs, &from_gs), AliasResult::MayAlias);
    }

    #[test]
    fn heap_accesses_stay_conservative_within_the_heap() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = heap_access(Width::Qword);
        let second: MemoryAccess = MemoryAccess {
            disp: 0x40,
            ..heap_access(Width::Qword)
        };
        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
    }

    #[test]
    fn a_relocation_target_outside_every_section_is_a_global() {
        let mut model: RegionModel = RegionModel::new();
        model.add_data(0x4000, 0x5000);
        model.add_code(0x1000, 0x2000);
        model.add_reloc_target(0x9000);
        model.add_reloc_target(0x1400);

        assert_eq!(model.region_of(0x9000), Region::Global);
        assert_eq!(model.region_of(0x9008), Region::Unknown);
        assert_eq!(
            model.region_of(0x1400),
            Region::Unknown,
            "a relocation inside code never turns code into data",
        );
    }

    #[test]
    fn an_address_two_sections_claim_is_unknown_rather_than_a_guess() {
        let mut model: RegionModel = RegionModel::new();
        model.add_tls(0x2300, 0x2304);
        model.add_data(0x2300, 0x3000);
        assert_eq!(model.region_of(0x2300), Region::Unknown);
        assert_eq!(model.region_of(0x2304), Region::Global);
    }

    #[test]
    fn always_may_alias_stub_never_proves_disjoint() {
        let stub: AlwaysMayAlias = AlwaysMayAlias;
        let low: MemoryAccess = stack_access(-16, Width::Qword);
        let high: MemoryAccess = stack_access(-8, Width::Qword);
        assert_eq!(stub.alias(&low, &high), AliasResult::MayAlias);
    }
}
