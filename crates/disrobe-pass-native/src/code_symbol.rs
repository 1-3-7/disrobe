use std::cell::OnceCell;
use std::collections::BTreeSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use object::read::{Object as _, ObjectSection as _, ObjectSymbol as _};
use object::{
    Architecture, RelocationKind, RelocationTarget, SectionFlags, SectionKind, SymbolKind,
};

const MAX_X86_INSTRUCTION_BYTES: usize = 15;

const DISPLACEMENT_BYTES: u64 = 4;

const IMPORT_SYMBOL_PREFIX: &str = "__imp_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThunkWidth {
    Bits32,
    Bits64,
}

impl ThunkWidth {
    const fn of(architecture: Architecture) -> Option<Self> {
        match architecture {
            Architecture::I386 => Some(Self::Bits32),
            Architecture::X86_64 => Some(Self::Bits64),
            _ => None,
        }
    }

    const fn bitness(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    const fn slot_bytes(self) -> u64 {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }

    const fn relocation_kind(self) -> RelocationKind {
        match self {
            Self::Bits32 => RelocationKind::Absolute,
            Self::Bits64 => RelocationKind::Relative,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    Image {
        import_address_table: Option<(u64, u64)>,
    },
    Relocatable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThunkLayout {
    width: ThunkWidth,
    container: Container,
}

#[derive(Debug)]
pub(crate) struct CodeSymbols<'data, 'file> {
    file: &'file object::File<'data>,
    layout: Option<ThunkLayout>,
    data_ranges: OnceCell<Vec<(u64, u64)>>,
    import_symbol_addresses: OnceCell<BTreeSet<u64>>,
    import_relocation_sites: OnceCell<BTreeSet<(usize, u64)>>,
}

impl<'data, 'file> CodeSymbols<'data, 'file> {
    pub(crate) fn new(file: &'file object::File<'data>) -> Self {
        Self {
            file,
            layout: thunk_layout(file),
            data_ranges: OnceCell::new(),
            import_symbol_addresses: OnceCell::new(),
            import_relocation_sites: OnceCell::new(),
        }
    }

    pub(crate) fn names_code(&self, symbol: &object::Symbol<'data, '_>) -> bool {
        match symbol.kind() {
            SymbolKind::Text => true,
            SymbolKind::Data => {
                symbol.is_global()
                    && self
                        .layout
                        .is_some_and(|layout: ThunkLayout| self.is_import_thunk(layout, symbol))
            }
            _ => false,
        }
    }

    fn is_import_thunk(&self, layout: ThunkLayout, symbol: &object::Symbol<'data, '_>) -> bool {
        let Some(index): Option<object::SectionIndex> = symbol.section_index() else {
            return false;
        };
        let Ok(section): object::Result<object::Section<'data, 'file>> =
            self.file.section_by_index(index)
        else {
            return false;
        };
        if section.kind() != SectionKind::Text {
            return false;
        }
        let address: u64 = symbol.address();
        let Some(start): Option<usize> = address
            .checked_sub(section.address())
            .and_then(|offset: u64| usize::try_from(offset).ok())
        else {
            return false;
        };
        let Ok(body): object::Result<&'data [u8]> = section.data() else {
            return false;
        };
        let Some(tail): Option<&[u8]> = body.get(start..) else {
            return false;
        };
        let window: &[u8] = tail.get(..MAX_X86_INSTRUCTION_BYTES).unwrap_or(tail);
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            layout.width.bitness(),
            window,
            address,
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() {
            return false;
        }
        let instruction: Instruction = decoder.decode();
        let Some(target): Option<u64> = indirect_jump_target(layout.width, &instruction) else {
            return false;
        };
        match layout.container {
            Container::Image {
                import_address_table,
            } => {
                self.is_data_slot(target, layout.width.slot_bytes())
                    && (import_address_table.is_some_and(|table: (u64, u64)| {
                        is_table_slot(table, target, layout.width.slot_bytes())
                    }) || self.import_symbol_addresses().contains(&target))
            }
            Container::Relocatable => {
                let Some(site): Option<u64> = u64::try_from(instruction.len())
                    .ok()
                    .and_then(|length: u64| address.checked_add(length))
                    .and_then(|end: u64| end.checked_sub(DISPLACEMENT_BYTES))
                    .and_then(|field: u64| field.checked_sub(self.file.relative_address_base()))
                else {
                    return false;
                };
                self.import_relocation_sites(layout.width)
                    .contains(&(index.0, site))
            }
        }
    }

    fn is_data_slot(&self, target: u64, slot_bytes: u64) -> bool {
        target.checked_add(slot_bytes).is_some_and(|slot_end: u64| {
            self.data_ranges()
                .iter()
                .any(|&(start, end): &(u64, u64)| start <= target && slot_end <= end)
        })
    }

    fn data_ranges(&self) -> &[(u64, u64)] {
        self.data_ranges.get_or_init(|| {
            self.file
                .sections()
                .filter(|section: &object::Section<'data, 'file>| is_non_executable(section))
                .filter_map(|section: object::Section<'data, 'file>| {
                    let start: u64 = section.address();
                    start
                        .checked_add(section.size())
                        .map(|end: u64| (start, end))
                })
                .collect()
        })
    }

    fn import_symbol_addresses(&self) -> &BTreeSet<u64> {
        self.import_symbol_addresses.get_or_init(|| {
            self.file
                .symbols()
                .filter(|symbol: &object::Symbol<'data, 'file>| {
                    symbol.section_index().is_some()
                        && symbol
                            .name()
                            .is_ok_and(|name: &str| name.starts_with(IMPORT_SYMBOL_PREFIX))
                })
                .map(|symbol: object::Symbol<'data, 'file>| symbol.address())
                .collect()
        })
    }

    fn import_relocation_sites(&self, width: ThunkWidth) -> &BTreeSet<(usize, u64)> {
        self.import_relocation_sites.get_or_init(|| {
            let mut sites: BTreeSet<(usize, u64)> = BTreeSet::new();
            for section in self.file.sections() {
                if section.kind() != SectionKind::Text {
                    continue;
                }
                for (offset, relocation) in section.relocations() {
                    if relocation.kind() != width.relocation_kind()
                        || u64::from(relocation.size()) != DISPLACEMENT_BYTES * 8
                    {
                        continue;
                    }
                    let RelocationTarget::Symbol(target) = relocation.target() else {
                        continue;
                    };
                    if self
                        .file
                        .symbol_by_index(target)
                        .and_then(|symbol: object::Symbol<'data, 'file>| symbol.name())
                        .is_ok_and(|name: &str| name.starts_with(IMPORT_SYMBOL_PREFIX))
                    {
                        sites.insert((section.index().0, offset));
                    }
                }
            }
            sites
        })
    }
}

fn thunk_layout(file: &object::File<'_>) -> Option<ThunkLayout> {
    let width: ThunkWidth = ThunkWidth::of(file.architecture())?;
    let container: Container = match file {
        object::File::Pe32(image) => Container::Image {
            import_address_table: import_address_table(
                image.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IAT),
                file.relative_address_base(),
            ),
        },
        object::File::Pe64(image) => Container::Image {
            import_address_table: import_address_table(
                image.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IAT),
                file.relative_address_base(),
            ),
        },
        object::File::Coff(_) | object::File::CoffBig(_) => Container::Relocatable,
        _ => return None,
    };
    Some(ThunkLayout { width, container })
}

fn import_address_table(
    directory: Option<&object::pe::ImageDataDirectory>,
    image_base: u64,
) -> Option<(u64, u64)> {
    let (relative, size): (u32, u32) = directory?.address_range();
    if relative == 0 || size == 0 {
        return None;
    }
    let start: u64 = image_base.checked_add(u64::from(relative))?;
    let end: u64 = start.checked_add(u64::from(size))?;
    Some((start, end))
}

fn is_non_executable(section: &object::Section<'_, '_>) -> bool {
    match section.flags() {
        SectionFlags::Coff { characteristics } => {
            characteristics & (object::pe::IMAGE_SCN_CNT_CODE | object::pe::IMAGE_SCN_MEM_EXECUTE)
                == 0
        }
        _ => false,
    }
}

fn is_table_slot((start, end): (u64, u64), target: u64, slot_bytes: u64) -> bool {
    target >= start
        && target
            .checked_add(slot_bytes)
            .is_some_and(|slot_end: u64| slot_end <= end)
        && (target - start) % slot_bytes == 0
}

fn indirect_jump_target(width: ThunkWidth, instruction: &Instruction) -> Option<u64> {
    if instruction.is_invalid()
        || instruction.op_count() != 1
        || instruction.op0_kind() != OpKind::Memory
        || instruction.segment_prefix() != Register::None
        || instruction.memory_index() != Register::None
    {
        return None;
    }
    match width {
        ThunkWidth::Bits64 => (instruction.code() == Code::Jmp_rm64
            && instruction.is_ip_rel_memory_operand())
        .then(|| instruction.ip_rel_memory_address()),
        ThunkWidth::Bits32 => (instruction.code() == Code::Jmp_rm32
            && instruction.memory_base() == Register::None)
            .then(|| instruction.memory_displacement64()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use disrobe_ir::payload::{DisasmPayload, DisasmSymbol, DisasmSymbolKind};
    use object::write::{
        Mangling, Object as WriteObject, Relocation as WriteRelocation, SectionId, StandardSection,
        Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags, SymbolId,
        SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
    };
    use object::{BinaryFormat, Endianness, RelocationEncoding, RelocationFlags};

    use super::*;
    use crate::backend_export::{
        RecoveredSymbol, SymbolClass, SymbolMap, collect_recovered_symbols,
    };
    use crate::build_disasm_payload;

    const GNU_LD_TWIN: &[u8] =
        include_bytes!("../../../corpus/native/linkers/base32-clang19-gnuld.exe");

    const LLD_TWIN: &[u8] = include_bytes!("../../../corpus/native/linkers/base32-clang19-lld.exe");

    const I386_THUNKS: &[u8] =
        include_bytes!("../../../corpus/native/linkers/i386-thunks-clang19-lld.exe");

    const LLD_UNTYPED_IMPORT_THUNKS: [&str; 28] = [
        "_XcptFilter",
        "__acrt_iob_func",
        "__p___argc",
        "__p___argv",
        "__p__commode",
        "__p__environ",
        "__p__fmode",
        "__set_app_type",
        "__setusermatherr",
        "__stdio_common_vfprintf",
        "_cexit",
        "_configthreadlocale",
        "_configure_narrow_argv",
        "_crt_atexit",
        "_exit",
        "_initialize_narrow_environment",
        "_initterm",
        "_initterm_e",
        "_set_invalid_parameter_handler",
        "_set_new_mode",
        "abort",
        "exit",
        "fflush",
        "malloc",
        "memcpy",
        "setvbuf",
        "strlen",
        "strncmp",
    ];

    const THUNK: [u8; 8] = [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];

    const LIST_SENTINEL: [u8; 8] = [0xff; 8];

    const RETURN_ZERO: [u8; 8] = [0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90];

    const REGISTER_JUMP: [u8; 8] = [0xff, 0xe0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];

    #[derive(Debug, Clone, Copy)]
    enum Target {
        Import,
        Local,
        Unrelocated,
    }

    #[derive(Debug, Clone, Copy)]
    struct Entry {
        name: &'static str,
        bytes: [u8; 8],
        kind: WriteSymbolKind,
        target: Target,
    }

    const ENTRIES: [Entry; 7] = [
        Entry {
            name: "import_thunk",
            bytes: THUNK,
            kind: WriteSymbolKind::Data,
            target: Target::Import,
        },
        Entry {
            name: "local_slot_thunk",
            bytes: THUNK,
            kind: WriteSymbolKind::Data,
            target: Target::Local,
        },
        Entry {
            name: "unrelocated_thunk",
            bytes: THUNK,
            kind: WriteSymbolKind::Data,
            target: Target::Unrelocated,
        },
        Entry {
            name: "__CTOR_LIST__",
            bytes: LIST_SENTINEL,
            kind: WriteSymbolKind::Data,
            target: Target::Unrelocated,
        },
        Entry {
            name: "linker_sentinel",
            bytes: RETURN_ZERO,
            kind: WriteSymbolKind::Data,
            target: Target::Unrelocated,
        },
        Entry {
            name: "register_jump",
            bytes: REGISTER_JUMP,
            kind: WriteSymbolKind::Data,
            target: Target::Unrelocated,
        },
        Entry {
            name: "typed_function",
            bytes: RETURN_ZERO,
            kind: WriteSymbolKind::Text,
            target: Target::Unrelocated,
        },
    ];

    fn defined(
        object: &mut WriteObject<'_>,
        name: &str,
        section: SectionId,
        value: u64,
        kind: WriteSymbolKind,
    ) -> SymbolId {
        object.add_symbol(WriteSymbol {
            name: name.as_bytes().to_vec(),
            value,
            size: 0,
            kind,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: WriteSymbolFlags::None,
        })
    }

    fn synthesized_object(format: BinaryFormat, architecture: Architecture) -> Vec<u8> {
        let width: ThunkWidth = ThunkWidth::of(architecture).expect("x86 architecture");
        let mut object: WriteObject<'_> =
            WriteObject::new(format, architecture, Endianness::Little);
        object.set_mangling(Mangling::None);
        let text: SectionId = object.section_id(StandardSection::Text);
        let data: SectionId = object.section_id(StandardSection::Data);
        let _: u64 = object.append_section_data(data, &[0_u8; 8], 8);
        let local_slot: SymbolId =
            defined(&mut object, "local_slot", data, 0, WriteSymbolKind::Data);
        let import_name: &str = match width {
            ThunkWidth::Bits32 => "__imp__puts",
            ThunkWidth::Bits64 => "__imp_puts",
        };
        let import_slot: SymbolId = object.add_symbol(WriteSymbol {
            name: import_name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: WriteSymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: WriteSymbolFlags::None,
        });
        let addend: i64 = match width {
            ThunkWidth::Bits32 => 0,
            ThunkWidth::Bits64 => -4,
        };
        let code: Vec<u8> = ENTRIES
            .iter()
            .flat_map(|entry: &Entry| entry.bytes)
            .collect();
        let base: u64 = object.append_section_data(text, &code, 16);
        for (offset, entry) in (0_u64..).step_by(8).zip(ENTRIES) {
            let value: u64 = base + offset;
            let _: SymbolId = defined(&mut object, entry.name, text, value, entry.kind);
            let symbol: SymbolId = match entry.target {
                Target::Import => import_slot,
                Target::Local => local_slot,
                Target::Unrelocated => continue,
            };
            object
                .add_relocation(
                    text,
                    WriteRelocation {
                        offset: value + 2,
                        symbol,
                        addend,
                        flags: RelocationFlags::Generic {
                            kind: width.relocation_kind(),
                            encoding: RelocationEncoding::Generic,
                            size: 32,
                        },
                    },
                )
                .expect("add thunk relocation");
        }
        let second: SectionId =
            object.add_section(Vec::new(), b".text$second".to_vec(), SectionKind::Text);
        let _: u64 = object.append_section_data(second, &THUNK, 16);
        let _: SymbolId = defined(
            &mut object,
            "other_section_thunk",
            second,
            0,
            WriteSymbolKind::Data,
        );
        object.write().expect("write synthesized object")
    }

    fn verdicts(bytes: &[u8]) -> BTreeMap<String, bool> {
        let file: object::File<'_> = object::File::parse(bytes).expect("parse object");
        let code_symbols: CodeSymbols<'_, '_> = CodeSymbols::new(&file);
        file.symbols()
            .filter_map(|symbol: object::Symbol<'_, '_>| {
                let name: &str = symbol.name().ok()?;
                Some((name.to_owned(), code_symbols.names_code(&symbol)))
            })
            .collect()
    }

    fn assert_verdict(verdicts: &BTreeMap<String, bool>, name: &str, expected: bool) {
        assert_eq!(
            verdicts.get(name).copied(),
            Some(expected),
            "{name} must name code: {expected}"
        );
    }

    #[test]
    fn coff_objects_accept_only_thunks_relocated_against_an_import_slot() {
        for architecture in [Architecture::X86_64, Architecture::I386] {
            let bytes: Vec<u8> = synthesized_object(BinaryFormat::Coff, architecture);
            let verdicts: BTreeMap<String, bool> = verdicts(&bytes);
            assert_verdict(&verdicts, "import_thunk", true);
            assert_verdict(&verdicts, "typed_function", true);
            assert_verdict(&verdicts, "local_slot_thunk", false);
            assert_verdict(&verdicts, "unrelocated_thunk", false);
            assert_verdict(&verdicts, "other_section_thunk", false);
            assert_verdict(&verdicts, "local_slot", false);
        }
    }

    #[test]
    fn coff_linker_data_inside_executable_sections_is_not_code() {
        for architecture in [Architecture::X86_64, Architecture::I386] {
            let bytes: Vec<u8> = synthesized_object(BinaryFormat::Coff, architecture);
            let file: object::File<'_> = object::File::parse(&*bytes).expect("parse object");
            let verdicts: BTreeMap<String, bool> = verdicts(&bytes);
            for name in ["__CTOR_LIST__", "linker_sentinel", "register_jump"] {
                let symbol: object::Symbol<'_, '_> =
                    file.symbol_by_name(name).expect("synthesized symbol");
                assert_eq!(symbol.kind(), SymbolKind::Data, "{name} is untyped");
                let section: object::Section<'_, '_> = file
                    .section_by_index(symbol.section_index().expect("defined symbol"))
                    .expect("symbol section");
                assert_eq!(
                    section.kind(),
                    SectionKind::Text,
                    "{name} lies inside an executable section"
                );
                assert_verdict(&verdicts, name, false);
            }
        }
    }

    #[test]
    fn elf_objects_keep_the_symbol_type_as_the_only_code_evidence() {
        let bytes: Vec<u8> = synthesized_object(BinaryFormat::Elf, Architecture::X86_64);
        let verdicts: BTreeMap<String, bool> = verdicts(&bytes);
        assert_verdict(&verdicts, "typed_function", true);
        for name in ENTRIES
            .iter()
            .filter(|entry: &&Entry| matches!(entry.kind, WriteSymbolKind::Data))
            .map(|entry: &Entry| entry.name)
        {
            assert_verdict(&verdicts, name, false);
        }
    }

    #[test]
    fn lld_import_thunks_name_code_and_untyped_non_thunks_do_not() {
        let lld: BTreeMap<String, bool> = verdicts(LLD_TWIN);
        let gnu_ld: BTreeMap<String, bool> = verdicts(GNU_LD_TWIN);
        let file: object::File<'_> = object::File::parse(LLD_TWIN).expect("parse lld twin");
        for name in LLD_UNTYPED_IMPORT_THUNKS {
            let symbol: object::Symbol<'_, '_> = file
                .symbol_by_name(name)
                .unwrap_or_else(|| panic!("lld twin carries {name}"));
            assert_eq!(symbol.kind(), SymbolKind::Data, "lld leaves {name} untyped");
            assert_verdict(&lld, name, true);
            assert_verdict(&gnu_ld, name, true);
        }
        let thunk_addresses: BTreeSet<u64> = LLD_UNTYPED_IMPORT_THUNKS
            .iter()
            .filter_map(|name: &&str| file.symbol_by_name(name))
            .map(|symbol: object::Symbol<'_, '_>| symbol.address())
            .collect();
        let code_symbols: CodeSymbols<'_, '_> = CodeSymbols::new(&file);
        let labels_on_thunks: usize = file
            .symbols()
            .filter(|symbol: &object::Symbol<'_, '_>| {
                !symbol.is_global()
                    && symbol.kind() == SymbolKind::Data
                    && symbol.name().is_ok_and(|name: &str| name == ".text")
                    && thunk_addresses.contains(&symbol.address())
            })
            .inspect(|label: &object::Symbol<'_, '_>| {
                assert!(
                    !code_symbols.names_code(label),
                    "a local .text label at {:#x} is not a function",
                    label.address()
                );
            })
            .count();
        assert!(
            labels_on_thunks > 0,
            "the lld twin carries local .text labels on its thunks"
        );
    }

    #[test]
    fn pe_linker_data_outside_executable_sections_is_rejected_by_section_kind() {
        for image in [LLD_TWIN, GNU_LD_TWIN] {
            let file: object::File<'_> = object::File::parse(image).expect("parse twin");
            let verdicts: BTreeMap<String, bool> = verdicts(image);
            for name in ["__CTOR_LIST__", "__DTOR_LIST__", "__imp_strlen"] {
                let symbol: object::Symbol<'_, '_> =
                    file.symbol_by_name(name).expect("twin symbol");
                let section: object::Section<'_, '_> = file
                    .section_by_index(symbol.section_index().expect("defined symbol"))
                    .expect("symbol section");
                assert_ne!(
                    section.kind(),
                    SectionKind::Text,
                    "{name} lies outside executable sections"
                );
                assert_verdict(&verdicts, name, false);
            }
        }
    }

    #[test]
    fn untyped_non_thunk_code_is_not_proven_code() {
        for image in [LLD_TWIN, GNU_LD_TWIN] {
            let file: object::File<'_> = object::File::parse(image).expect("parse twin");
            let symbol: object::Symbol<'_, '_> =
                file.symbol_by_name("___chkstk_ms").expect("chkstk symbol");
            assert_eq!(symbol.kind(), SymbolKind::Data, "___chkstk_ms is untyped");
            assert_verdict(&verdicts(image), "___chkstk_ms", false);
        }
        let map: SymbolMap = collect_recovered_symbols(LLD_TWIN).expect("lld symbol map");
        let chkstk: Vec<SymbolClass> = map
            .symbols
            .iter()
            .filter(|symbol: &&RecoveredSymbol| symbol.name == "___chkstk_ms")
            .map(|symbol: &RecoveredSymbol| symbol.class)
            .collect();
        assert_eq!(
            chkstk,
            [SymbolClass::Data],
            "named limitation: untyped non-thunk code is not proven code, so ___chkstk_ms is not classed as a function"
        );
    }

    const COFF_SYMBOL_RECORD_BYTES: usize = 18;

    fn displacement(from: u64, to: u64) -> i32 {
        i32::try_from(i128::from(to) - i128::from(from)).expect("near displacement")
    }

    fn le_offset(image: &[u8], at: usize) -> usize {
        let field: [u8; 4] = image[at..at + 4].try_into().expect("four bytes");
        usize::try_from(u32::from_le_bytes(field)).expect("offset fits usize")
    }

    fn pe_header(image: &[u8]) -> usize {
        let header: usize = le_offset(image, 0x3c);
        assert_eq!(image[header..header + 4], *b"PE\0\0", "PE signature");
        header
    }

    fn import_address_table_directory(image: &[u8]) -> usize {
        let optional: usize = pe_header(image) + 24;
        let directories: usize = match u16::from_le_bytes([image[optional], image[optional + 1]]) {
            object::pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC => optional + 96,
            object::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC => optional + 112,
            magic => panic!("optional header magic {magic:#x}"),
        };
        directories + object::pe::IMAGE_DIRECTORY_ENTRY_IAT * 8
    }

    fn with_import_address_table(image: &[u8], relative: u32, size: u32) -> Vec<u8> {
        let directory: usize = import_address_table_directory(image);
        let mut bytes: Vec<u8> = image.to_vec();
        bytes[directory..directory + 4].copy_from_slice(&relative.to_le_bytes());
        bytes[directory + 4..directory + 8].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    fn coff_symbol_table(image: &[u8]) -> (usize, usize) {
        let header: usize = pe_header(image);
        (le_offset(image, header + 12), le_offset(image, header + 16))
    }

    fn with_renamed_import_symbol(image: &[u8], name: &str) -> Vec<u8> {
        assert!(
            name.starts_with(IMPORT_SYMBOL_PREFIX),
            "{name} is an import slot"
        );
        let (table, count): (usize, usize) = coff_symbol_table(image);
        let strings: usize = table + count * COFF_SYMBOL_RECORD_BYTES;
        let end: usize = strings + le_offset(image, strings);
        let needle: Vec<u8> = [name.as_bytes(), b"\0"].concat();
        let starts: Vec<usize> = (strings + 4..=end - needle.len())
            .filter(|at: &usize| {
                image[*at..*at + needle.len()] == needle[..]
                    && (*at == strings + 4 || image[*at - 1] == 0)
            })
            .collect();
        let [start]: [usize; 1] = starts.try_into().expect("one string table entry");
        let mut bytes: Vec<u8> = image.to_vec();
        bytes[start + IMPORT_SYMBOL_PREFIX.len() - 2] = b'q';
        let renamed: object::File<'_> = object::File::parse(&*bytes).expect("parse renamed");
        assert!(renamed.symbol_by_name(name).is_none(), "{name} is renamed");
        bytes
    }

    fn with_import_symbol_moved_onto(image: &[u8], import: &str, thunk: &str) -> Vec<u8> {
        let file: object::File<'_> = object::File::parse(image).expect("parse image");
        let import_symbol: object::Symbol<'_, '_> =
            file.symbol_by_name(import).expect("import symbol");
        let thunk_symbol: object::Symbol<'_, '_> = file.symbol_by_name(thunk).expect("thunk");
        let (table, _): (usize, usize) = coff_symbol_table(image);
        let from: usize = table + thunk_symbol.index().0 * COFF_SYMBOL_RECORD_BYTES + 8;
        let to: usize = table + import_symbol.index().0 * COFF_SYMBOL_RECORD_BYTES + 8;
        let mut bytes: Vec<u8> = image.to_vec();
        bytes.copy_within(from..from + 6, to);
        let moved: object::File<'_> = object::File::parse(&*bytes).expect("parse moved");
        assert_eq!(
            moved
                .symbol_by_name(import)
                .map(|symbol: object::Symbol<'_, '_>| symbol.address()),
            Some(thunk_symbol.address()),
            "{import} now names the {thunk} address"
        );
        bytes
    }

    fn retargeted_strlen_thunk(image: &[u8], retarget: impl Fn(u64, u64) -> i32) -> Vec<u8> {
        let file: object::File<'_> = object::File::parse(image).expect("parse lld twin");
        let thunk: object::Symbol<'_, '_> = file.symbol_by_name("strlen").expect("strlen thunk");
        let slot: u64 = file
            .symbol_by_name("__imp_strlen")
            .expect("strlen import slot")
            .address();
        let section: object::Section<'_, '_> = file
            .section_by_index(thunk.section_index().expect("thunk section"))
            .expect("thunk section header");
        let (file_offset, _): (u64, u64) = section.file_range().expect("thunk bytes on disk");
        let field: usize = usize::try_from(file_offset + (thunk.address() - section.address()) + 2)
            .expect("field offset");
        let next_instruction: u64 = thunk.address() + 6;
        let mut bytes: Vec<u8> = image.to_vec();
        assert_eq!(
            bytes[field - 2..field],
            [0xff, 0x25],
            "strlen is a rip jump"
        );
        bytes[field..field + 4].copy_from_slice(&retarget(next_instruction, slot).to_le_bytes());
        bytes
    }

    #[test]
    fn a_pe_thunk_counts_only_while_it_jumps_through_an_import_slot() {
        let intact: Vec<u8> = retargeted_strlen_thunk(LLD_TWIN, displacement);
        assert_verdict(&verdicts(&intact), "strlen", true);
        let into_code: Vec<u8> =
            retargeted_strlen_thunk(LLD_TWIN, |next: u64, _: u64| displacement(next, next - 6));
        assert_verdict(&verdicts(&into_code), "strlen", false);
        let misaligned: Vec<u8> = retargeted_strlen_thunk(LLD_TWIN, |next: u64, slot: u64| {
            displacement(next, slot + 1)
        });
        assert_verdict(&verdicts(&misaligned), "strlen", false);
    }

    #[test]
    fn an_import_address_table_directory_over_code_does_not_prove_a_thunk() {
        let file: object::File<'_> = object::File::parse(LLD_TWIN).expect("parse lld twin");
        let text: object::Section<'_, '_> = file.section_by_name(".text").expect("text section");
        let text_start: u64 = text.address();
        let relative: u32 = u32::try_from(text_start - file.relative_address_base())
            .expect("text relative address");
        let size: u32 = u32::try_from(text.size()).expect("text size");
        let covered: Vec<u8> = with_import_address_table(LLD_TWIN, relative, size);
        let into_real_slot: Vec<u8> = retargeted_strlen_thunk(&covered, displacement);
        assert_verdict(&verdicts(&into_real_slot), "strlen", true);
        let into_code: Vec<u8> =
            retargeted_strlen_thunk(&covered, |next: u64, _: u64| displacement(next, text_start));
        assert_verdict(&verdicts(&into_code), "strlen", false);
    }

    #[test]
    fn an_import_symbol_placed_in_code_does_not_prove_a_thunk() {
        let crafted: Vec<u8> = with_import_symbol_moved_onto(LLD_TWIN, "__imp_strlen", "strlen");
        let into_crafted_slot: Vec<u8> = retargeted_strlen_thunk(&crafted, displacement);
        assert_verdict(&verdicts(&into_crafted_slot), "strlen", false);
    }

    #[test]
    fn each_pe_image_branch_alone_proves_an_import_thunk() {
        for (image, thunk, import, control) in [
            (LLD_TWIN, "strlen", "__imp_strlen", "malloc"),
            (
                I386_THUNKS,
                "_GetTickCount@0",
                "__imp__GetTickCount@0",
                "_ExitProcess@4",
            ),
        ] {
            let without_table: Vec<u8> = with_import_address_table(image, 0, 0);
            assert_verdict(&verdicts(&without_table), thunk, true);
            let without_symbol: Vec<u8> = with_renamed_import_symbol(image, import);
            assert_verdict(&verdicts(&without_symbol), thunk, true);
            let without_either: Vec<u8> = with_renamed_import_symbol(&without_table, import);
            let verdicts: BTreeMap<String, bool> = verdicts(&without_either);
            assert_verdict(&verdicts, thunk, false);
            assert_verdict(&verdicts, control, true);
        }
    }

    #[test]
    fn i386_image_thunks_jump_through_absolute_import_slots() {
        let file: object::File<'_> = object::File::parse(I386_THUNKS).expect("parse i386 image");
        assert_eq!(file.architecture(), Architecture::I386);
        for name in ["_GetTickCount@0", "_ExitProcess@4", "_local_jump"] {
            let symbol: object::Symbol<'_, '_> = file.symbol_by_name(name).expect("i386 symbol");
            assert_eq!(symbol.kind(), SymbolKind::Data, "{name} is untyped");
        }
        let verdicts: BTreeMap<String, bool> = verdicts(I386_THUNKS);
        assert_verdict(&verdicts, "_entry@0", true);
        assert_verdict(&verdicts, "_GetTickCount@0", true);
        assert_verdict(&verdicts, "_ExitProcess@4", true);
        assert_verdict(&verdicts, "_local_jump", false);
        assert_verdict(&verdicts, "_local_slot", false);
        assert_verdict(&verdicts, "__imp__GetTickCount@0", false);
    }

    fn global_symbol_names(image: &[u8]) -> BTreeSet<String> {
        let file: object::File<'_> = object::File::parse(image).expect("parse twin");
        file.symbols()
            .filter(|symbol: &object::Symbol<'_, '_>| symbol.is_global())
            .filter_map(|symbol: object::Symbol<'_, '_>| symbol.name().ok().map(str::to_owned))
            .collect()
    }

    fn seeded_code_symbols(image: &[u8]) -> BTreeMap<String, DisasmSymbolKind> {
        let file: object::File<'_> = object::File::parse(image).expect("parse twin");
        let executable: Vec<(u64, u64)> = file
            .sections()
            .filter(|section: &object::Section<'_, '_>| section.kind() == SectionKind::Text)
            .map(|section: object::Section<'_, '_>| {
                (section.address(), section.address() + section.size())
            })
            .collect();
        let payload: DisasmPayload = build_disasm_payload(image).expect("build twin payload");
        let mut seeded: BTreeMap<String, DisasmSymbolKind> = BTreeMap::new();
        for symbol in payload
            .symbol_table
            .iter()
            .filter(|symbol: &&DisasmSymbol| {
                executable
                    .iter()
                    .any(|(start, end): &(u64, u64)| (*start..*end).contains(&symbol.address))
            })
        {
            let previous: Option<DisasmSymbolKind> =
                seeded.insert(symbol.name.clone(), symbol.kind);
            assert!(
                previous.is_none_or(|kind: DisasmSymbolKind| kind == symbol.kind),
                "{} is seeded with one kind",
                symbol.name
            );
        }
        seeded
    }

    #[test]
    fn gnu_ld_and_lld_twins_seed_the_same_code_symbols() {
        let mut gnu_ld: BTreeMap<String, DisasmSymbolKind> = seeded_code_symbols(GNU_LD_TWIN);
        let mut lld: BTreeMap<String, DisasmSymbolKind> = seeded_code_symbols(LLD_TWIN);
        for name in LLD_UNTYPED_IMPORT_THUNKS {
            assert!(lld.contains_key(name), "lld twin seeds {name}");
        }
        let gnu_ld_globals: BTreeSet<String> = global_symbol_names(GNU_LD_TWIN);
        let lld_globals: BTreeSet<String> = global_symbol_names(LLD_TWIN);
        let gnu_ld_locals: Vec<String> = gnu_ld
            .keys()
            .filter(|name: &&String| !gnu_ld_globals.contains(*name))
            .cloned()
            .collect();
        for name in &gnu_ld_locals {
            assert!(
                !lld_globals.contains(name),
                "{name} is local in GNU ld and must not be a global lld symbol"
            );
            gnu_ld.remove(name);
        }
        lld.retain(|name: &String, _: &mut DisasmSymbolKind| lld_globals.contains(name));
        let gnu_only: Vec<&String> = gnu_ld
            .keys()
            .filter(|name: &&String| !lld.contains_key(*name))
            .collect();
        let lld_only: Vec<&String> = lld
            .keys()
            .filter(|name: &&String| !gnu_ld.contains_key(*name))
            .collect();
        assert!(
            gnu_only.is_empty() && lld_only.is_empty(),
            "GNU ld only: {gnu_only:?}; lld only: {lld_only:?}"
        );
        assert_eq!(gnu_ld, lld);
        assert!(
            gnu_ld.len() > LLD_UNTYPED_IMPORT_THUNKS.len(),
            "the twins seed more than the thunks: {}",
            gnu_ld.len()
        );
    }

    #[test]
    fn recovered_symbol_maps_class_lld_thunks_as_functions() {
        let map: SymbolMap = collect_recovered_symbols(LLD_TWIN).expect("lld symbol map");
        for name in LLD_UNTYPED_IMPORT_THUNKS {
            let classes: Vec<SymbolClass> = map
                .symbols
                .iter()
                .filter(|symbol: &&RecoveredSymbol| symbol.name == name)
                .map(|symbol: &RecoveredSymbol| symbol.class)
                .collect();
            assert_eq!(classes, [SymbolClass::Function], "{name} class");
        }
    }
}
