use std::collections::BTreeMap;

use object::pe;
use object::read::elf::{ElfFile, FileHeader, Rel, Rela, SectionHeader, SectionTable, SymbolTable};
use object::read::pe::{
    DelayLoadDescriptorIterator, DelayLoadImportTable, ImageNtHeaders, ImageOptionalHeader, Import,
    ImportDescriptorIterator, ImportTable, ImportThunkList, PeFile,
};
use object::{Endianness, FileKind, LittleEndian, SectionIndex, SymbolIndex};

const MAX_DESCRIPTORS: usize = 1 << 14;
const MAX_THUNKS: u64 = 1 << 20;
const MAX_ENTRIES: usize = 1 << 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportFormat {
    Pe,
    Elf,
    #[default]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSource {
    PeImport,
    PeDelayLoad,
    ElfJumpSlot,
    ElfGlobData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRef {
    pub library: String,
    pub symbol: ImportSymbol,
    pub source: ImportSource,
}

impl ImportRef {
    #[must_use]
    pub const fn name(&self) -> Option<&str> {
        match &self.symbol {
            ImportSymbol::Name(name) => Some(name.as_str()),
            ImportSymbol::Ordinal(_) => None,
        }
    }

    #[must_use]
    pub const fn ordinal(&self) -> Option<u16> {
        match &self.symbol {
            ImportSymbol::Ordinal(ordinal) => Some(*ordinal),
            ImportSymbol::Name(_) => None,
        }
    }

    #[must_use]
    pub fn lookup_key(&self) -> Option<&str> {
        self.name().map(|name: &str| {
            name.split_once('@')
                .map_or(name, |(base, _): (&str, &str)| base)
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportMap {
    pub by_slot_va: BTreeMap<u64, ImportRef>,
    pub image_base: u64,
    pub format: ImportFormat,
}

impl ImportMap {
    #[must_use]
    pub fn from_image(data: &[u8]) -> Self {
        let mut map: Self = Self::default();
        match FileKind::parse(data) {
            Ok(FileKind::Pe32) => {
                map.format = ImportFormat::Pe;
                parse_pe::<pe::ImageNtHeaders32>(data, &mut map);
            }
            Ok(FileKind::Pe64) => {
                map.format = ImportFormat::Pe;
                parse_pe::<pe::ImageNtHeaders64>(data, &mut map);
            }
            Ok(FileKind::Elf32) => {
                map.format = ImportFormat::Elf;
                parse_elf::<object::elf::FileHeader32<Endianness>>(data, &mut map);
            }
            Ok(FileKind::Elf64) => {
                map.format = ImportFormat::Elf;
                parse_elf::<object::elf::FileHeader64<Endianness>>(data, &mut map);
            }
            _ => {}
        }
        map
    }

    #[must_use]
    pub fn resolve(&self, target_va: u64) -> Option<&ImportRef> {
        self.by_slot_va.get(&target_va)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_slot_va.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_slot_va.is_empty()
    }
}

fn decode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    image_base: u64,
    thunk_size: u64,
}

fn parse_pe<Pe: ImageNtHeaders>(data: &[u8], out: &mut ImportMap) {
    let Ok(pe): core::result::Result<PeFile<'_, Pe>, _> = PeFile::<Pe>::parse(data) else {
        return;
    };
    let layout: PeLayout = PeLayout {
        image_base: pe.nt_headers().optional_header().image_base(),
        thunk_size: core::mem::size_of::<Pe::ImageThunkData>() as u64,
    };
    out.image_base = layout.image_base;
    if let Ok(Some(table)) = pe.import_table() {
        collect_pe_imports::<Pe>(&table, layout, out);
    }
    let sections: object::read::pe::SectionTable<'_> = pe.section_table();
    if let Ok(Some(delay)) = pe
        .data_directories()
        .delay_load_import_table(data, &sections)
    {
        collect_pe_delay::<Pe>(&delay, layout, out);
    }
}

fn collect_pe_imports<Pe: ImageNtHeaders>(
    table: &ImportTable<'_>,
    layout: PeLayout,
    out: &mut ImportMap,
) {
    let Ok(mut descriptors): core::result::Result<ImportDescriptorIterator<'_>, _> =
        table.descriptors()
    else {
        return;
    };
    let mut descriptor_count: usize = 0;
    loop {
        if descriptor_count >= MAX_DESCRIPTORS || out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        let Ok(Some(descriptor)): core::result::Result<Option<&pe::ImageImportDescriptor>, _> =
            descriptors.next()
        else {
            break;
        };
        descriptor_count += 1;
        let Ok(library_bytes): core::result::Result<&[u8], _> =
            table.name(descriptor.name.get(LittleEndian))
        else {
            continue;
        };
        let library: String = decode(library_bytes);
        let int_rva: u32 = descriptor.original_first_thunk.get(LittleEndian);
        let iat_rva: u32 = descriptor.first_thunk.get(LittleEndian);
        let name_rva: u32 = if int_rva != 0 { int_rva } else { iat_rva };
        if name_rva == 0 {
            continue;
        }
        collect_pe_thunks::<Pe>(
            table,
            &library,
            layout,
            iat_rva,
            name_rva,
            ImportSource::PeImport,
            out,
        );
    }
}

fn collect_pe_thunks<Pe: ImageNtHeaders>(
    table: &ImportTable<'_>,
    library: &str,
    layout: PeLayout,
    iat_rva: u32,
    name_rva: u32,
    source: ImportSource,
    out: &mut ImportMap,
) {
    let Ok(mut thunks): core::result::Result<ImportThunkList<'_>, _> = table.thunks(name_rva)
    else {
        return;
    };
    let mut index: u64 = 0;
    loop {
        if index >= MAX_THUNKS || out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        let Ok(Some(thunk)): core::result::Result<Option<Pe::ImageThunkData>, _> =
            thunks.next::<Pe>()
        else {
            break;
        };
        let slot_va: u64 = layout
            .image_base
            .wrapping_add(u64::from(iat_rva))
            .wrapping_add(index.wrapping_mul(layout.thunk_size));
        if let Ok(import) = table.import::<Pe>(thunk) {
            out.by_slot_va
                .insert(slot_va, make_ref(library, import, source));
        }
        index += 1;
    }
}

fn collect_pe_delay<Pe: ImageNtHeaders>(
    table: &DelayLoadImportTable<'_>,
    layout: PeLayout,
    out: &mut ImportMap,
) {
    let Ok(mut descriptors): core::result::Result<DelayLoadDescriptorIterator<'_>, _> =
        table.descriptors()
    else {
        return;
    };
    let mut descriptor_count: usize = 0;
    loop {
        if descriptor_count >= MAX_DESCRIPTORS || out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        let Ok(Some(descriptor)): core::result::Result<Option<&pe::ImageDelayloadDescriptor>, _> =
            descriptors.next()
        else {
            break;
        };
        descriptor_count += 1;
        let Ok(library_bytes): core::result::Result<&[u8], _> =
            table.name(descriptor.dll_name_rva.get(LittleEndian))
        else {
            continue;
        };
        let library: String = decode(library_bytes);
        let iat_rva: u32 = descriptor.import_address_table_rva.get(LittleEndian);
        let name_rva: u32 = descriptor.import_name_table_rva.get(LittleEndian);
        if name_rva == 0 {
            continue;
        }
        let Ok(mut thunks): core::result::Result<ImportThunkList<'_>, _> = table.thunks(name_rva)
        else {
            continue;
        };
        let mut index: u64 = 0;
        loop {
            if index >= MAX_THUNKS || out.by_slot_va.len() >= MAX_ENTRIES {
                break;
            }
            let Ok(Some(thunk)): core::result::Result<Option<Pe::ImageThunkData>, _> =
                thunks.next::<Pe>()
            else {
                break;
            };
            let slot_va: u64 = layout
                .image_base
                .wrapping_add(u64::from(iat_rva))
                .wrapping_add(index.wrapping_mul(layout.thunk_size));
            if let Ok(import) = table.import::<Pe>(thunk) {
                out.by_slot_va.insert(
                    slot_va,
                    make_ref(&library, import, ImportSource::PeDelayLoad),
                );
            }
            index += 1;
        }
    }
}

fn make_ref(library: &str, import: Import<'_>, source: ImportSource) -> ImportRef {
    let symbol: ImportSymbol = match import {
        Import::Ordinal(ordinal) => ImportSymbol::Ordinal(ordinal),
        Import::Name(_hint, name) => ImportSymbol::Name(decode(name)),
    };
    ImportRef {
        library: library.to_owned(),
        symbol,
        source,
    }
}

const fn reloc_kinds(machine: u16) -> Option<(u32, u32)> {
    match machine {
        object::elf::EM_X86_64 => Some((
            object::elf::R_X86_64_JUMP_SLOT,
            object::elf::R_X86_64_GLOB_DAT,
        )),
        object::elf::EM_AARCH64 => Some((
            object::elf::R_AARCH64_JUMP_SLOT,
            object::elf::R_AARCH64_GLOB_DAT,
        )),
        object::elf::EM_386 => Some((object::elf::R_386_JMP_SLOT, object::elf::R_386_GLOB_DAT)),
        object::elf::EM_ARM => Some((object::elf::R_ARM_JUMP_SLOT, object::elf::R_ARM_GLOB_DAT)),
        _ => None,
    }
}

const fn reloc_source(r_type: u32, kinds: (u32, u32)) -> Option<ImportSource> {
    let (jump_slot, glob_dat): (u32, u32) = kinds;
    if r_type == jump_slot {
        Some(ImportSource::ElfJumpSlot)
    } else if r_type == glob_dat {
        Some(ImportSource::ElfGlobData)
    } else {
        None
    }
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(data: &[u8], out: &mut ImportMap) {
    let Ok(elf): core::result::Result<ElfFile<'_, Elf>, _> = ElfFile::<Elf>::parse(data) else {
        return;
    };
    let endian: Endianness = elf.endian();
    let Some(kinds): Option<(u32, u32)> = reloc_kinds(elf.elf_header().e_machine(endian)) else {
        return;
    };
    let sections: &SectionTable<'_, Elf> = elf.elf_section_table();
    for section in sections.iter() {
        if out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        if let Ok(Some((relas, link))) = section.rela(endian, data) {
            collect_relas::<Elf>(relas, link, sections, endian, data, kinds, out);
        }
        if let Ok(Some((rels, link))) = section.rel(endian, data) {
            collect_rels::<Elf>(rels, link, sections, endian, data, kinds, out);
        }
    }
}

fn collect_relas<Elf: FileHeader>(
    relas: &[Elf::Rela],
    link: SectionIndex,
    sections: &SectionTable<'_, Elf>,
    endian: Elf::Endian,
    data: &[u8],
    kinds: (u32, u32),
    out: &mut ImportMap,
) {
    let Ok(symtab): core::result::Result<SymbolTable<'_, Elf>, _> =
        sections.symbol_table_by_index(endian, data, link)
    else {
        return;
    };
    for rela in relas {
        if out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        let Some(source): Option<ImportSource> = reloc_source(rela.r_type(endian, false), kinds)
        else {
            continue;
        };
        let Some(sym_index): Option<SymbolIndex> = rela.symbol(endian, false) else {
            continue;
        };
        let slot_va: u64 = rela.r_offset(endian).into();
        insert_elf_symbol::<Elf>(out, &symtab, endian, sym_index, slot_va, source);
    }
}

fn collect_rels<Elf: FileHeader>(
    rels: &[Elf::Rel],
    link: SectionIndex,
    sections: &SectionTable<'_, Elf>,
    endian: Elf::Endian,
    data: &[u8],
    kinds: (u32, u32),
    out: &mut ImportMap,
) {
    let Ok(symtab): core::result::Result<SymbolTable<'_, Elf>, _> =
        sections.symbol_table_by_index(endian, data, link)
    else {
        return;
    };
    for rel in rels {
        if out.by_slot_va.len() >= MAX_ENTRIES {
            break;
        }
        let Some(source): Option<ImportSource> = reloc_source(rel.r_type(endian), kinds) else {
            continue;
        };
        let Some(sym_index): Option<SymbolIndex> = rel.symbol(endian) else {
            continue;
        };
        let slot_va: u64 = rel.r_offset(endian).into();
        insert_elf_symbol::<Elf>(out, &symtab, endian, sym_index, slot_va, source);
    }
}

fn insert_elf_symbol<Elf: FileHeader>(
    out: &mut ImportMap,
    symtab: &SymbolTable<'_, Elf>,
    endian: Elf::Endian,
    sym_index: SymbolIndex,
    slot_va: u64,
    source: ImportSource,
) {
    let Ok(sym): core::result::Result<&Elf::Sym, _> = symtab.symbol(sym_index) else {
        return;
    };
    let Ok(name): core::result::Result<&[u8], _> = symtab.symbol_name(endian, sym) else {
        return;
    };
    if name.is_empty() {
        return;
    }
    out.by_slot_va.insert(
        slot_va,
        ImportRef {
            library: String::new(),
            symbol: ImportSymbol::Name(decode(name)),
            source,
        },
    );
}
