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
use disrobe_typerec::dwarf_gt::{self, DebugImage, GroundTruthAggregate, GroundTruthFunction};
use disrobe_typerec::lattice::TypeVar;
use disrobe_typerec::memssa::{self, CellAccess, MemSsa};
use disrobe_typerec::region::{Region, RegionModel};
use iced_x86::{
    Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, UsedRegister,
};
use object::{File, Object, ObjectSection, ObjectSymbol};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn stripped_slice(stripped: &[u8], unstripped: &[u8], name: &str) -> (u64, Vec<u8>) {
    let symbols: File<'_> = File::parse(unstripped).expect("parse ground truth image");
    let symbol: object::Symbol<'_, '_> = symbols
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| symbol.name() == Ok(name))
        .unwrap_or_else(|| panic!("{name} must exist in the ground truth symbol table"));
    let input: File<'_> = File::parse(stripped).expect("parse stripped image");
    let text: object::Section<'_, '_> = input.section_by_name(".text").expect("text section");
    let data: &[u8] = text.data().expect("text bytes");
    let start: usize = usize::try_from(symbol.address() - text.address()).expect("text offset");
    let size: usize = usize::try_from(symbol.size()).expect("symbol size");
    assert!(size > 0, "{name} must have a sized symbol");
    let end: usize = start.checked_add(size).expect("slice end");
    (symbol.address(), data[start..end].to_vec())
}

fn ground_truth_function<'a>(image: &'a DebugImage, name: &str) -> &'a GroundTruthFunction {
    image
        .functions
        .iter()
        .find(|function: &&GroundTruthFunction| function.name == name)
        .unwrap_or_else(|| panic!("{name} must carry debug information"))
}

fn pointer_slot(image: &DebugImage, name: &str, pointee: &str) -> i64 {
    let function: &GroundTruthFunction = ground_truth_function(image, name);
    let slots: BTreeSet<i64> = function
        .aggregates
        .iter()
        .filter(|aggregate: &&GroundTruthAggregate| aggregate.type_name == pointee)
        .map(|aggregate: &GroundTruthAggregate| aggregate.rbp_disp)
        .collect();
    let mut found: std::collections::btree_set::IntoIter<i64> = slots.into_iter();
    let slot: i64 = found
        .next()
        .unwrap_or_else(|| panic!("{name} must declare one pointer to {pointee}"));
    assert!(
        found.next().is_none(),
        "{name} must declare exactly one pointer to {pointee}",
    );
    slot
}

const fn writes_register(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn reads_frame_slot(insn: &Instruction, rbp_disp: i64) -> bool {
    insn.mnemonic() == Mnemonic::Mov
        && insn.op0_kind() == OpKind::Register
        && insn.op1_kind() == OpKind::Memory
        && !insn.is_ip_rel_memory_operand()
        && insn.memory_base() == Register::RBP
        && insn.memory_index() == Register::None
        && i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes()) == rbp_disp
}

fn touches_memory(insn: &Instruction) -> bool {
    insn.mnemonic() != Mnemonic::Lea
        && (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory)
}

fn accesses_through_slot(instrs: &[Instruction], rbp_disp: i64) -> BTreeSet<u64> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut carriers: BTreeSet<Register> = BTreeSet::new();
    let mut found: BTreeSet<u64> = BTreeSet::new();
    for insn in instrs {
        if touches_memory(insn) && carriers.contains(&insn.memory_base().full_register()) {
            found.insert(insn.ip());
        }
        let loads: bool = reads_frame_slot(insn, rbp_disp);
        for used in factory.info(insn).used_registers() {
            let used: UsedRegister = *used;
            if writes_register(used.access()) {
                carriers.remove(&used.register().full_register());
            }
        }
        if loads {
            carriers.insert(insn.op0_register().full_register());
        }
    }
    found
}

fn accesses_after_pointer_load(instrs: &[Instruction]) -> BTreeSet<u64> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut loaded: BTreeSet<Register> = BTreeSet::new();
    let mut found: BTreeSet<u64> = BTreeSet::new();
    for insn in instrs {
        if touches_memory(insn) && loaded.contains(&insn.memory_base().full_register()) {
            found.insert(insn.ip());
        }
        let loads: bool = insn.mnemonic() == Mnemonic::Mov
            && insn.op0_kind() == OpKind::Register
            && insn.op1_kind() == OpKind::Memory
            && insn.is_ip_rel_memory_operand();
        for used in factory.info(insn).used_registers() {
            let used: UsedRegister = *used;
            if writes_register(used.access()) {
                loaded.remove(&used.register().full_register());
            }
        }
        if loads {
            loaded.insert(insn.op0_register().full_register());
        }
    }
    found
}

fn cells_at(code: &[u8], base: u64, model: &RegionModel) -> BTreeMap<u64, (Region, TypeVar)> {
    let instrs: Vec<Instruction> = decode_all(code, base);
    let control_flow: Cfg = cfg::build(&instrs);
    let mut store: CellStore = CellStore::new();
    let ssa: MemSsa = memssa::build_with_model(&instrs, &control_flow, &mut store, model);
    let mut out: BTreeMap<u64, (Region, TypeVar)> = BTreeMap::new();
    for insn in &instrs {
        if let Some(access) = ssa.access_at(insn.ip()) {
            let access: CellAccess = access;
            out.insert(insn.ip(), (access.key.region, access.cell));
        }
    }
    out
}

fn region_cells(cells: &BTreeMap<u64, (Region, TypeVar)>, region: Region) -> BTreeSet<TypeVar> {
    cells
        .values()
        .filter(|(found, _): &&(Region, TypeVar)| *found == region)
        .map(|(_, cell): &(Region, TypeVar)| *cell)
        .collect()
}

fn heap_ips(cells: &BTreeMap<u64, (Region, TypeVar)>) -> BTreeSet<u64> {
    cells
        .iter()
        .filter(|(_, (region, _)): &(&u64, &(Region, TypeVar))| *region == Region::Heap)
        .map(|(ip, _): (&u64, &(Region, TypeVar))| *ip)
        .collect()
}

struct SlotGrade {
    expected: BTreeSet<u64>,
    heap: BTreeSet<u64>,
    cells: BTreeMap<u64, (Region, TypeVar)>,
}

fn grade_pointer_slot(stem: &str, function: &str, pointee: &str) -> SlotGrade {
    let unstripped: Vec<u8> = fixture(&format!("{stem}.unstripped.so"));
    let stripped: Vec<u8> = fixture(&format!("{stem}.stripped.so"));
    let image: DebugImage = dwarf_gt::load(&unstripped).expect("load heap corpus debug image");
    let rbp_disp: i64 = pointer_slot(&image, function, pointee);
    let (base, code): (u64, Vec<u8>) = stripped_slice(&stripped, &unstripped, function);
    let instrs: Vec<Instruction> = decode_all(&code, base);
    let expected: BTreeSet<u64> = accesses_through_slot(&instrs, rbp_disp);
    let model: RegionModel = RegionModel::from_image(&stripped);
    let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &model);
    let heap: BTreeSet<u64> = heap_ips(&cells);
    SlotGrade {
        expected,
        heap,
        cells,
    }
}

#[test]
fn allocation_derefs_recover_as_heap_cells_at_the_dwarf_declared_slot() {
    for stem in ["heap_corpus", "heap_corpus.noplt", "heap_corpus.cet"] {
        let fill: SlotGrade = grade_pointer_slot(stem, "fill", "int");
        assert_eq!(
            fill.expected.len(),
            4,
            "{stem}: the debug slot of the allocation pointer must front four dereferences",
        );
        let recovered: BTreeSet<u64> = fill.expected.intersection(&fill.heap).copied().collect();
        eprintln!(
            "{stem} fill: heap correct={}/{} false_positives={}",
            recovered.len(),
            fill.expected.len(),
            fill.heap.difference(&fill.expected).count(),
        );
        assert_eq!(
            recovered.len(),
            fill.expected.len(),
            "{stem}: every dereference of the allocation pointer is a heap cell, missing {:?}",
            fill.expected.difference(&fill.heap).collect::<Vec<&u64>>(),
        );
        assert!(
            fill.heap.is_subset(&fill.expected),
            "{stem}: no access outside the allocation pointer may claim the heap: {:?}",
            fill.heap.difference(&fill.expected).collect::<Vec<&u64>>(),
        );

        let reserve: SlotGrade = grade_pointer_slot(stem, "reserve", "long");
        assert_eq!(
            reserve.expected.len(),
            3,
            "{stem}: the calloc pointer slot must front three dereferences",
        );
        eprintln!(
            "{stem} reserve: heap correct={}/{}",
            reserve.expected.intersection(&reserve.heap).count(),
            reserve.expected.len(),
        );
        assert_eq!(
            reserve.expected.intersection(&reserve.heap).count(),
            reserve.expected.len(),
            "{stem}: calloc is an allocation site too",
        );
    }
}

#[test]
fn a_pointer_parameter_never_claims_the_heap() {
    for stem in ["heap_corpus", "heap_corpus.noplt", "heap_corpus.cet"] {
        let through: SlotGrade = grade_pointer_slot(stem, "through_pointer", "int");
        assert_eq!(
            through.expected.len(),
            4,
            "{stem}: the parameter slot must front four dereferences",
        );
        eprintln!(
            "{stem} through_pointer: heap={}/{} unknown={}",
            through.expected.intersection(&through.heap).count(),
            through.expected.len(),
            through
                .expected
                .iter()
                .filter(|ip: &&u64| {
                    through
                        .cells
                        .get(ip)
                        .is_some_and(|(region, _): &(Region, TypeVar)| *region == Region::Unknown)
                })
                .count(),
        );
        assert!(
            through.heap.is_empty(),
            "{stem}: a caller supplied pointer is not a proven allocation: {:?}",
            through.heap,
        );
        for ip in &through.expected {
            let region: Region = through
                .cells
                .get(ip)
                .map_or(Region::Unknown, |(region, _): &(Region, TypeVar)| *region);
            assert_eq!(
                region,
                Region::Unknown,
                "{stem}: {ip:#x} through an unproven pointer stays unknown",
            );
        }
    }
}

#[test]
fn a_pointer_loaded_from_the_global_offset_table_is_not_an_allocation() {
    for stem in [
        "heap_corpus",
        "heap_corpus.noplt",
        "heap_corpus.cet",
        "heap_corpus.o2",
    ] {
        let unstripped: Vec<u8> = fixture(&format!("{stem}.unstripped.so"));
        let stripped: Vec<u8> = fixture(&format!("{stem}.stripped.so"));
        let (base, code): (u64, Vec<u8>) = stripped_slice(&stripped, &unstripped, "fill");
        let instrs: Vec<Instruction> = decode_all(&code, base);
        let indirect: BTreeSet<u64> = accesses_after_pointer_load(&instrs);
        assert!(
            !indirect.is_empty(),
            "{stem}: fill must dereference a pointer loaded from the global offset table",
        );
        let model: RegionModel = RegionModel::from_image(&stripped);
        let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &model);
        let heap: BTreeSet<u64> = heap_ips(&cells);
        eprintln!(
            "{stem} fill: table indirections={} claimed as heap={}",
            indirect.len(),
            indirect.intersection(&heap).count(),
        );
        assert_eq!(
            indirect.intersection(&heap).count(),
            0,
            "{stem}: a register overwritten by a table load carries no allocation",
        );
    }
}

#[test]
fn heap_cells_never_share_a_cell_with_a_global_or_a_frame_slot() {
    for stem in [
        "heap_corpus",
        "heap_corpus.noplt",
        "heap_corpus.cet",
        "heap_corpus.o2",
    ] {
        let unstripped: Vec<u8> = fixture(&format!("{stem}.unstripped.so"));
        let stripped: Vec<u8> = fixture(&format!("{stem}.stripped.so"));
        let (base, code): (u64, Vec<u8>) = stripped_slice(&stripped, &unstripped, "reserve");
        let model: RegionModel = RegionModel::from_image(&stripped);
        let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &model);
        let heap: BTreeSet<TypeVar> = region_cells(&cells, Region::Heap);
        let global: BTreeSet<TypeVar> = region_cells(&cells, Region::Global);
        let stack: BTreeSet<TypeVar> = region_cells(&cells, Region::Stack);
        let unknown: BTreeSet<TypeVar> = region_cells(&cells, Region::Unknown);
        eprintln!(
            "{stem} reserve: heap cells={} global cells={} frame cells={} unknown cells={}",
            heap.len(),
            global.len(),
            stack.len(),
            unknown.len(),
        );
        assert!(!heap.is_empty(), "{stem}: reserve must produce heap cells");
        assert!(
            !global.is_empty(),
            "{stem}: reserve must store into a directly addressed global",
        );
        assert!(
            unknown.is_empty(),
            "{stem}: reserve must classify every access, so no access may bridge two regions",
        );
        assert!(
            heap.is_disjoint(&global),
            "{stem}: an allocation never shares a cell with a global",
        );
        assert!(
            heap.is_disjoint(&stack),
            "{stem}: an allocation never shares a cell with a frame slot",
        );
        assert_eq!(
            heap.len(),
            1,
            "{stem}: the store into the global must not open a new version of the allocation",
        );
    }
}

#[test]
fn the_register_resident_build_recovers_the_allocation_without_a_frame_slot() {
    let unstripped: Vec<u8> = fixture("heap_corpus.o2.unstripped.so");
    let stripped: Vec<u8> = fixture("heap_corpus.o2.stripped.so");
    let model: RegionModel = RegionModel::from_image(&stripped);
    let expected: [(&str, usize); 3] = [("fill", 2), ("reserve", 2), ("through_pointer", 0)];
    for (name, count) in expected {
        let (base, code): (u64, Vec<u8>) = stripped_slice(&stripped, &unstripped, name);
        let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &model);
        let heap: BTreeSet<u64> = heap_ips(&cells);
        eprintln!("o2 {name}: heap accesses={} expected={count}", heap.len());
        assert_eq!(
            heap.len(),
            count,
            "o2 {name}: the surviving dereferences of the allocation pointer",
        );
    }
}

#[test]
fn an_image_without_an_allocator_import_never_claims_the_heap() {
    let unstripped: Vec<u8> = fixture("region_corpus.unstripped.elf");
    let stripped: Vec<u8> = fixture("region_corpus.stripped.elf");
    let model: RegionModel = RegionModel::from_image(&stripped);
    for name in ["bump", "reload"] {
        let symbols: File<'_> = File::parse(&*unstripped).expect("parse ground truth image");
        let symbol: object::Symbol<'_, '_> = symbols
            .symbols()
            .find(|symbol: &object::Symbol<'_, '_>| symbol.name() == Ok(name))
            .unwrap_or_else(|| panic!("{name} must exist"));
        let text: object::Section<'_, '_> = symbols.section_by_name(".text").expect("text section");
        let data: &[u8] = text.data().expect("text bytes");
        let start: usize = usize::try_from(symbol.address() - text.address()).expect("offset");
        let size: usize = usize::try_from(symbol.size()).expect("size");
        let cells: BTreeMap<u64, (Region, TypeVar)> =
            cells_at(&data[start..start + size], symbol.address(), &model);
        assert!(
            heap_ips(&cells).is_empty(),
            "{name}: an image with no allocator import proves no allocation",
        );
    }
}

#[test]
fn truncated_and_malformed_images_refuse_without_panicking() {
    let stripped: Vec<u8> = fixture("heap_corpus.stripped.so");
    for length in [0_usize, 1, 4, 64, 512, 2048] {
        let prefix: &[u8] = &stripped[..length.min(stripped.len())];
        let model: RegionModel = RegionModel::from_image(prefix);
        let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(prefix, 0x1000, &model);
        assert!(
            heap_ips(&cells).is_empty(),
            "a truncated image proves no allocation at {length} bytes",
        );
    }
    let noise: Vec<u8> = (0..4096_u32)
        .map(|index: u32| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let model: RegionModel = RegionModel::from_image(&noise);
    let cells: BTreeMap<u64, (Region, TypeVar)> = cells_at(&noise, 0x400_000, &model);
    assert!(
        heap_ips(&cells).is_empty(),
        "an image that parses as nothing proves no allocation",
    );
}

#[test]
fn heap_recovery_is_deterministic() {
    let unstripped: Vec<u8> = fixture("heap_corpus.unstripped.so");
    let stripped: Vec<u8> = fixture("heap_corpus.stripped.so");
    let (base, code): (u64, Vec<u8>) = stripped_slice(&stripped, &unstripped, "fill");
    let first: RegionModel = RegionModel::from_image(&stripped);
    let second: RegionModel = RegionModel::from_image(&stripped);
    let left: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &first);
    let right: BTreeMap<u64, (Region, TypeVar)> = cells_at(&code, base, &second);
    assert_eq!(left, right, "repeated recovery must produce equal cells");
}
