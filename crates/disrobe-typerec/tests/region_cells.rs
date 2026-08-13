#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_typerec::CellStore;
use disrobe_typerec::cfg::{self, Cfg};
use disrobe_typerec::decode::decode_all;
use disrobe_typerec::import_map::ImportMap;
use disrobe_typerec::lattice::TypeVar;
use disrobe_typerec::memssa::{self, CellAccess, MemSsa};
use disrobe_typerec::region::{Region, RegionModel};
use iced_x86::Instruction;
use object::{File, Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind, SymbolSection};

const ELF_SHF_EXECINSTR: u64 = 0x4;
const COFF_MEM_EXECUTE: u32 = 0x2000_0000;
const MACHO_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn corpus(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("corpus");
    for part in relative.split('/') {
        path.push(part);
    }
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn executable_section(section: &object::Section<'_, '_>) -> bool {
    match section.flags() {
        SectionFlags::Elf { sh_flags } => sh_flags & ELF_SHF_EXECINSTR != 0,
        SectionFlags::Coff { characteristics } => characteristics & COFF_MEM_EXECUTE != 0,
        SectionFlags::MachO { flags, .. } => flags & MACHO_PURE_INSTRUCTIONS != 0,
        _ => false,
    }
}

fn symbol_addresses(bytes: &[u8]) -> BTreeMap<String, u64> {
    let file: File<'_> = File::parse(bytes).expect("parse ground truth image");
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for symbol in file.symbols() {
        let Ok(name): Result<&str, _> = symbol.name() else {
            continue;
        };
        out.insert(name.to_owned(), symbol.address());
    }
    out
}

fn ground_truth_address(names: &BTreeMap<String, u64>, name: &str) -> u64 {
    *names
        .get(name)
        .unwrap_or_else(|| panic!("{name} must exist in the fixture symbol table"))
}

#[test]
fn elf_named_objects_classify_into_the_region_the_compiler_placed_them_in() {
    let unstripped: Vec<u8> = fixture("region_corpus.unstripped.elf");
    let stripped: Vec<u8> = fixture("region_corpus.stripped.elf");
    let names: BTreeMap<String, u64> = symbol_addresses(&unstripped);
    let model: RegionModel = RegionModel::from_image(&stripped);

    assert_eq!(
        model.region_of(ground_truth_address(&names, "g_counter")),
        Region::Global,
        "an initialized mutable global is a global cell",
    );
    assert_eq!(
        model.region_of(ground_truth_address(&names, "g_zero")),
        Region::Global,
        "a zero initialized global is a global cell",
    );
    assert_eq!(
        model.region_of(ground_truth_address(&names, "g_const_table")),
        Region::ConstPool,
        "a const array is a constant pool cell",
    );
    for text in ["bump", "reload", "_start"] {
        assert_eq!(
            model.region_of(ground_truth_address(&names, text)),
            Region::Unknown,
            "{text} is code and never a data region",
        );
    }
}

#[test]
fn elf_thread_local_storage_sections_classify_as_tls() {
    let unstripped: Vec<u8> = fixture("region_corpus.unstripped.elf");
    let stripped: Vec<u8> = fixture("region_corpus.stripped.elf");
    let file: File<'_> = File::parse(&*unstripped).expect("parse elf");
    let thread_locals: BTreeSet<String> = file
        .symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| symbol.kind() == SymbolKind::Tls)
        .filter_map(|symbol: object::Symbol<'_, '_>| {
            symbol.name().ok().map(|name: &str| name.to_owned())
        })
        .collect();
    assert!(
        thread_locals.contains("t_slot") && thread_locals.contains("t_zero"),
        "the fixture must carry thread local objects: {thread_locals:?}",
    );

    let template: object::Section<'_, '_> = file
        .section_by_name(".tdata")
        .expect("the fixture must carry an initialized tls section");
    let model: RegionModel = RegionModel::from_image(&stripped);
    assert_eq!(
        model.region_of(template.address()),
        Region::Tls,
        "an address inside the tls template is a thread local cell",
    );
}

#[test]
fn every_allocated_data_symbol_leaves_the_unknown_region() {
    for name in [
        "region_corpus.unstripped.elf",
        "region_corpus.pic.unstripped.so",
        "abi_corpus.unstripped.exe",
    ] {
        let bytes: Vec<u8> = fixture(name);
        let file: File<'_> = File::parse(&*bytes).expect("parse image");
        let model: RegionModel = RegionModel::from_image(&bytes);
        let mut checked: usize = 0;
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Data {
                continue;
            }
            let SymbolSection::Section(index) = symbol.section() else {
                continue;
            };
            let Ok(section): Result<object::Section<'_, '_>, _> = file.section_by_index(index)
            else {
                continue;
            };
            let end: u64 = section.address() + section.size();
            if executable_section(&section) || section.address() == 0 {
                continue;
            }
            if symbol.address() >= end {
                continue;
            }
            let region: Region = model.region_of(symbol.address());
            assert!(
                matches!(region, Region::Global | Region::ConstPool | Region::Tls),
                "{name}: {} at {:#x} classified {region:?}",
                symbol.name().unwrap_or("?"),
                symbol.address(),
            );
            checked += 1;
        }
        assert!(checked > 0, "{name} must contribute graded data symbols");
        eprintln!("{name}: {checked} data symbols classified out of Unknown");
    }
}

#[test]
fn mach_o_data_symbols_classify_by_segment() {
    let bytes: Vec<u8> = corpus("mobile/macho-mac/SwiftHello.original");
    let file: File<'_> = File::parse(&*bytes).expect("parse mach-o");
    let model: RegionModel = RegionModel::from_image(&bytes);
    let mut data: usize = 0;
    for symbol in file.symbols() {
        let SymbolSection::Section(index) = symbol.section() else {
            continue;
        };
        let Ok(section): Result<object::Section<'_, '_>, _> = file.section_by_index(index) else {
            continue;
        };
        match symbol.kind() {
            SymbolKind::Data if !executable_section(&section) => {
                assert!(
                    matches!(
                        model.region_of(symbol.address()),
                        Region::Global | Region::ConstPool | Region::Tls
                    ),
                    "{} at {:#x} must classify as data",
                    symbol.name().unwrap_or("?"),
                    symbol.address(),
                );
                data += 1;
            }
            SymbolKind::Text if executable_section(&section) => {
                assert_eq!(
                    model.region_of(symbol.address()),
                    Region::Unknown,
                    "{} is code",
                    symbol.name().unwrap_or("?"),
                );
            }
            _ => {}
        }
    }
    assert!(data > 0, "the mach-o fixture must carry data symbols");
    eprintln!("mach-o: {data} data symbols classified by segment");
}

#[test]
fn import_table_slots_are_global_cells() {
    let bytes: Vec<u8> = fixture("imports_pe.exe");
    let imports: ImportMap = ImportMap::from_image(&bytes);
    let model: RegionModel = RegionModel::from_image(&bytes);
    assert!(!imports.is_empty(), "the fixture must carry imports");
    for slot in imports.by_slot_va.keys() {
        assert_eq!(
            model.region_of(*slot),
            Region::Global,
            "import slot {slot:#x} is a global cell",
        );
    }
}

fn regions_at(bytes: &[u8], base: u64, model: &RegionModel) -> BTreeMap<u64, (Region, TypeVar)> {
    let instrs: Vec<Instruction> = decode_all(bytes, base);
    let control_flow: Cfg = cfg::build(&instrs);
    let mut store: CellStore = CellStore::new();
    let ssa: MemSsa = memssa::build_with_model(&instrs, &control_flow, &mut store, model);
    let mut out: BTreeMap<u64, (Region, TypeVar)> = BTreeMap::new();
    for insn in &instrs {
        let found: Option<CellAccess> = ssa.access_at(insn.ip());
        if let Some(access) = found {
            out.insert(insn.ip(), (access.key.region, access.cell));
        }
    }
    out
}

fn function_slice(image: &[u8], name: &str) -> (u64, Vec<u8>) {
    let file: File<'_> = File::parse(image).expect("parse image");
    let symbol: object::Symbol<'_, '_> = file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| symbol.name() == Ok(name))
        .unwrap_or_else(|| panic!("{name} must exist"));
    let text: object::Section<'_, '_> = file.section_by_name(".text").expect("text section");
    let data: &[u8] = text.data().expect("text bytes");
    let start: usize = usize::try_from(symbol.address() - text.address()).expect("offset");
    let size: usize = usize::try_from(symbol.size()).expect("size");
    assert!(size > 0, "{name} must have a sized symbol");
    (symbol.address(), data[start..start + size].to_vec())
}

#[test]
fn distinct_globals_and_frame_slots_never_share_a_cell() {
    let unstripped: Vec<u8> = fixture("region_corpus.unstripped.elf");
    let (base, code): (u64, Vec<u8>) = function_slice(&unstripped, "reload");
    let names: BTreeMap<String, u64> = symbol_addresses(&unstripped);
    let model: RegionModel = RegionModel::from_image(&fixture("region_corpus.stripped.elf"));
    let cells: BTreeMap<u64, (Region, TypeVar)> = regions_at(&code, base, &model);

    let counter: u64 = ground_truth_address(&names, "g_counter");
    let zero: u64 = ground_truth_address(&names, "g_zero");
    let instrs: Vec<Instruction> = decode_all(&code, base);
    let mut counter_cells: BTreeSet<TypeVar> = BTreeSet::new();
    let mut zero_cells: BTreeSet<TypeVar> = BTreeSet::new();
    let mut frame_cells: BTreeSet<TypeVar> = BTreeSet::new();
    for insn in &instrs {
        let Some((region, cell)): Option<(Region, TypeVar)> = cells.get(&insn.ip()).copied() else {
            continue;
        };
        let target: u64 = insn.memory_displacement64();
        if region == Region::Global && target == counter {
            counter_cells.insert(cell);
        }
        if region == Region::Global && target == zero {
            zero_cells.insert(cell);
        }
        if region == Region::Stack {
            frame_cells.insert(cell);
        }
    }

    assert!(
        !counter_cells.is_empty(),
        "the load of g_counter must produce a global cell",
    );
    assert!(
        !zero_cells.is_empty(),
        "the store to g_zero must produce a global cell",
    );
    assert!(
        !frame_cells.is_empty(),
        "the frame slots must still produce stack cells",
    );
    assert!(
        counter_cells.is_disjoint(&zero_cells),
        "two disjoint globals must never share a cell",
    );
    assert!(
        counter_cells.is_disjoint(&frame_cells) && zero_cells.is_disjoint(&frame_cells),
        "a global and a frame slot must never share a cell",
    );
}

#[test]
fn every_region_the_function_touches_reaches_memory_ssa() {
    let unstripped: Vec<u8> = fixture("region_corpus.unstripped.elf");
    let (base, code): (u64, Vec<u8>) = function_slice(&unstripped, "bump");
    let model: RegionModel = RegionModel::from_image(&fixture("region_corpus.stripped.elf"));
    let cells: BTreeMap<u64, (Region, TypeVar)> = regions_at(&code, base, &model);
    let regions: BTreeSet<Region> = cells
        .values()
        .map(|(region, _): &(Region, TypeVar)| *region)
        .collect();
    for expected in [
        Region::Tls,
        Region::ConstPool,
        Region::Global,
        Region::Stack,
        Region::Unknown,
    ] {
        assert!(
            regions.contains(&expected),
            "{expected:?} must reach memory ssa: {regions:?}",
        );
    }

    let stack_cells: BTreeSet<TypeVar> = cells
        .values()
        .filter(|(region, _): &&(Region, TypeVar)| *region == Region::Stack)
        .map(|(_, cell): &(Region, TypeVar)| *cell)
        .collect();
    let foreign_cells: BTreeSet<TypeVar> = cells
        .values()
        .filter(|(region, _): &&(Region, TypeVar)| *region != Region::Stack)
        .map(|(_, cell): &(Region, TypeVar)| *cell)
        .collect();
    assert!(
        stack_cells.is_disjoint(&foreign_cells),
        "a frame slot never shares a cell with any other region",
    );

    let conflated: BTreeSet<TypeVar> = cells
        .values()
        .filter(|(region, _): &&(Region, TypeVar)| {
            matches!(region, Region::Tls | Region::ConstPool | Region::Unknown)
        })
        .map(|(_, cell): &(Region, TypeVar)| *cell)
        .collect();
    let global_cells: BTreeSet<TypeVar> = cells
        .values()
        .filter(|(region, _): &&(Region, TypeVar)| *region == Region::Global)
        .map(|(_, cell): &(Region, TypeVar)| *cell)
        .collect();
    assert!(
        !conflated.is_disjoint(&global_cells),
        "a store through an unclassified pointer must conservatively reach every foreign region",
    );
}

#[test]
fn position_independent_build_reaches_the_same_regions() {
    let unstripped: Vec<u8> = fixture("region_corpus.pic.unstripped.so");
    let (base, code): (u64, Vec<u8>) = function_slice(&unstripped, "bump");
    let model: RegionModel = RegionModel::from_image(&fixture("region_corpus.pic.stripped.so"));
    let cells: BTreeMap<u64, (Region, TypeVar)> = regions_at(&code, base, &model);
    let regions: BTreeSet<Region> = cells
        .values()
        .map(|(region, _): &(Region, TypeVar)| *region)
        .collect();
    assert!(
        regions.contains(&Region::Global),
        "rip relative global offset table loads must be global cells: {regions:?}",
    );
    assert!(
        regions.contains(&Region::Tls),
        "segment prefixed thread local accesses must be tls cells: {regions:?}",
    );
}
