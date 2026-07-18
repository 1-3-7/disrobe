use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    CodeSize, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register,
    UsedMemory,
};

use crate::cells::CellStore;
use crate::cfg::Cfg;
use crate::lattice::{TypeClass, TypeVar, Width};
use crate::region::{AliasOracle, IndexSymbol, MemoryAccess, Region, RegionModel};

pub type VersionId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Load,
    Store,
    Rmw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackEvent {
    pub rbp_disp: i64,
    pub index: Option<Register>,
    pub index_address_size: u8,
    pub index_symbol: Option<IndexSymbol>,
    pub index_scale: u8,
    pub width: Width,
    pub kind: AccessKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StackOffset {
    rbp_disp: i64,
    index: Option<Register>,
    index_address_size: u8,
    index_symbol: Option<IndexSymbol>,
    index_scale: u8,
}

impl StackEvent {
    const fn offset(self) -> StackOffset {
        StackOffset {
            rbp_disp: self.rbp_disp,
            index: self.index,
            index_address_size: self.index_address_size,
            index_symbol: self.index_symbol,
            index_scale: self.index_scale,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    pub rbp_disp: i64,
    pub cell: TypeVar,
    pub live_lo: u64,
    pub live_hi: u64,
    pub is_phi: bool,
    pub escaped: bool,
}

#[derive(Debug, Default)]
pub struct MemSsa {
    versions: Vec<VersionInfo>,
    access: BTreeMap<(u64, i64), VersionId>,
    escaped: BTreeSet<i64>,
}

impl MemSsa {
    #[must_use]
    pub fn version_cell(&self, ip: u64, rbp_disp: i64) -> Option<TypeVar> {
        let id: VersionId = *self.access.get(&(ip, rbp_disp))?;
        self.versions
            .get(id as usize)
            .map(|info: &VersionInfo| info.cell)
    }

    #[must_use]
    pub fn versions(&self) -> &[VersionInfo] {
        &self.versions
    }

    #[must_use]
    pub fn is_escaped(&self, rbp_disp: i64) -> bool {
        self.escaped.contains(&rbp_disp)
    }

    fn fresh(
        &mut self,
        store: &mut CellStore,
        rbp_disp: i64,
        is_phi: bool,
        escaped: bool,
    ) -> VersionId {
        let id: VersionId = u32::try_from(self.versions.len()).unwrap_or(u32::MAX);
        let cell: TypeVar = store.fresh(TypeClass::Top);
        self.versions.push(VersionInfo {
            rbp_disp,
            cell,
            live_lo: u64::MAX,
            live_hi: 0,
            is_phi,
            escaped,
        });
        id
    }

    fn touch(&mut self, id: VersionId, ip: u64) {
        if let Some(info) = self.versions.get_mut(id as usize) {
            info.live_lo = info.live_lo.min(ip);
            info.live_hi = info.live_hi.max(ip);
        }
    }
}

fn stack_event(insn: &Instruction, factory: &mut InstructionInfoFactory) -> Option<StackEvent> {
    if insn.mnemonic() == Mnemonic::Lea {
        return None;
    }
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    for mem in info.used_memory() {
        let mem: UsedMemory = *mem;
        if mem.base() != Register::RBP {
            continue;
        }
        let raw_index: Register = mem.index();
        let index: Option<Register> =
            (raw_index != Register::None).then_some(raw_index.full_register());
        let index_address_size: u8 = match mem.address_size() {
            CodeSize::Code32 => 4,
            CodeSize::Code64 => 8,
            _ => continue,
        };
        let index_scale: u8 = match decoded_index_scale(mem.scale()) {
            Some(scale) => scale,
            None => continue,
        };
        let kind: AccessKind = match mem.access() {
            OpAccess::Read | OpAccess::CondRead => AccessKind::Load,
            OpAccess::Write | OpAccess::CondWrite => AccessKind::Store,
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => AccessKind::Rmw,
            OpAccess::None | OpAccess::NoMemAccess => continue,
        };
        let rbp_disp: i64 = i64::from_ne_bytes(mem.displacement().to_ne_bytes());
        let bytes: Option<u8> = u8::try_from(mem.memory_size().size()).ok();
        let width: Width = bytes.map_or(Width::Unknown, Width::from_bytes);
        return Some(StackEvent {
            rbp_disp,
            index,
            index_address_size,
            index_symbol: None,
            index_scale,
            width,
            kind,
        });
    }
    None
}

fn annotate_index_symbols(instrs: &[Instruction], cfg: &Cfg, events: &mut [Option<StackEvent>]) {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut register_writes: BTreeMap<Register, usize> = BTreeMap::new();
        let mut call_barrier: Option<usize> = None;
        for instruction_index in block.start..block.end {
            if let Some(Some(event)) = events.get_mut(instruction_index)
                && let Some(index) = event.index
            {
                let register_write: Option<usize> = register_writes.get(&index).copied();
                event.index_symbol =
                    Some(IndexSymbol::new(block_index, register_write, call_barrier));
            }
            let Some(insn): Option<&Instruction> = instrs.get(instruction_index) else {
                break;
            };
            let info: &iced_x86::InstructionInfo = factory.info(insn);
            for used in info.used_registers() {
                if writes_register(used.access()) {
                    register_writes.insert(used.register().full_register(), instruction_index);
                }
            }
            if matches!(
                insn.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) {
                call_barrier = Some(instruction_index);
            }
        }
    }
}

const fn writes_register(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn escaped_slot(insn: &Instruction) -> Option<i64> {
    if insn.mnemonic() != Mnemonic::Lea {
        return None;
    }
    if insn.memory_base() != Register::RBP || insn.memory_index() != Register::None {
        return None;
    }
    Some(i64::from_ne_bytes(
        insn.memory_displacement64().to_ne_bytes(),
    ))
}

fn has_indexed_frame_escape(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Lea
        && matches!(insn.memory_base(), Register::RBP | Register::RSP)
        && insn.memory_index() != Register::None
        && decoded_index_scale(insn.memory_index_scale()).is_some()
}

#[must_use]
pub fn build(instrs: &[Instruction], cfg: &Cfg, store: &mut CellStore) -> MemSsa {
    build_with_oracle(instrs, cfg, store, &RegionModel::default())
}

fn build_with_oracle(
    instrs: &[Instruction],
    cfg: &Cfg,
    store: &mut CellStore,
    oracle: &dyn AliasOracle,
) -> MemSsa {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut events: Vec<Option<StackEvent>> = instrs
        .iter()
        .map(|insn: &Instruction| stack_event(insn, &mut factory))
        .collect();
    annotate_index_symbols(instrs, cfg, &mut events);

    let mut ssa: MemSsa = MemSsa::default();
    if instrs
        .iter()
        .any(|insn: &Instruction| has_indexed_frame_escape(insn))
    {
        build_all_escaped(&mut ssa, store, instrs, &events);
        return ssa;
    }
    for insn in instrs {
        if let Some(rbp_disp) = escaped_slot(insn) {
            ssa.escaped.insert(rbp_disp);
        }
    }

    let mut widths: BTreeMap<i64, Width> = BTreeMap::new();
    let mut offsets: BTreeMap<i64, Option<StackOffset>> = BTreeMap::new();
    for event in events.iter().flatten() {
        let entry: &mut Width = widths.entry(event.rbp_disp).or_insert(Width::Unknown);
        *entry = entry.join(event.width);
        let offset: StackOffset = event.offset();
        let known: &mut Option<StackOffset> = offsets.entry(event.rbp_disp).or_insert(Some(offset));
        if known.is_some_and(|current: StackOffset| current != offset) {
            *known = None;
        }
    }

    for &rbp_disp in widths.keys() {
        if ssa.escaped.contains(&rbp_disp) {
            build_escaped_slot(&mut ssa, store, instrs, &events, rbp_disp);
        }
    }

    let concrete: Vec<i64> = widths
        .keys()
        .copied()
        .filter(|rbp_disp: &i64| !ssa.escaped.contains(rbp_disp))
        .collect();
    for group in group_offsets(&concrete, &widths, &offsets, oracle) {
        build_slot(&mut ssa, store, cfg, instrs, &events, &group);
    }
    ssa
}

const fn stack_alloc(offset: StackOffset, width: Width) -> MemoryAccess {
    MemoryAccess {
        region: Region::Stack,
        base: Register::RBP,
        rbp_disp: offset.rbp_disp,
        index: offset.index,
        index_address_size: offset.index_address_size,
        index_symbol: offset.index_symbol,
        index_scale: offset.index_scale,
        index_bound: None,
        width,
        escapes: false,
    }
}

fn group_offsets(
    concrete: &[i64],
    widths: &BTreeMap<i64, Width>,
    offsets: &BTreeMap<i64, Option<StackOffset>>,
    oracle: &dyn AliasOracle,
) -> Vec<BTreeSet<i64>> {
    let count: usize = concrete.len();
    let mut parent: Vec<usize> = (0..count).collect();
    for left in 0..count {
        for right in (left + 1)..count {
            let Some(offset_a): Option<StackOffset> =
                offsets.get(&concrete[left]).copied().flatten()
            else {
                union_find_join(&mut parent, left, right);
                continue;
            };
            let Some(offset_b): Option<StackOffset> =
                offsets.get(&concrete[right]).copied().flatten()
            else {
                union_find_join(&mut parent, left, right);
                continue;
            };
            let a: MemoryAccess = stack_alloc(
                offset_a,
                widths
                    .get(&concrete[left])
                    .copied()
                    .unwrap_or(Width::Unknown),
            );
            let b: MemoryAccess = stack_alloc(
                offset_b,
                widths
                    .get(&concrete[right])
                    .copied()
                    .unwrap_or(Width::Unknown),
            );
            if oracle.alias(&a, &b).may_alias() {
                union_find_join(&mut parent, left, right);
            }
        }
    }
    let mut groups: BTreeMap<usize, BTreeSet<i64>> = BTreeMap::new();
    for (index, &rbp_disp) in concrete.iter().enumerate() {
        let root: usize = union_find_root(&mut parent, index);
        groups.entry(root).or_default().insert(rbp_disp);
    }
    let mut ordered: Vec<BTreeSet<i64>> = groups.into_values().collect();
    ordered.sort_by_key(|group: &BTreeSet<i64>| group.iter().next().copied().unwrap_or(0));
    ordered
}

const fn decoded_index_scale(scale: u32) -> Option<u8> {
    match scale {
        1 => Some(1),
        2 => Some(2),
        4 => Some(4),
        8 => Some(8),
        _ => None,
    }
}

fn union_find_root(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

fn union_find_join(parent: &mut [usize], left: usize, right: usize) {
    let root_left: usize = union_find_root(parent, left);
    let root_right: usize = union_find_root(parent, right);
    if root_left != root_right {
        parent[root_left.max(root_right)] = root_left.min(root_right);
    }
}

fn build_escaped_slot(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    instrs: &[Instruction],
    events: &[Option<StackEvent>],
    rbp_disp: i64,
) {
    let version: VersionId = ssa.fresh(store, rbp_disp, false, true);
    for (index, event) in events.iter().enumerate() {
        let Some(event): Option<&StackEvent> = event.as_ref() else {
            continue;
        };
        if event.rbp_disp != rbp_disp {
            continue;
        }
        let Some(insn): Option<&Instruction> = instrs.get(index) else {
            continue;
        };
        ssa.access.insert((insn.ip(), rbp_disp), version);
        ssa.touch(version, insn.ip());
    }
}

fn build_all_escaped(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    instrs: &[Instruction],
    events: &[Option<StackEvent>],
) {
    let Some(representative): Option<i64> = events
        .iter()
        .flatten()
        .map(|event: &StackEvent| event.rbp_disp)
        .min()
    else {
        return;
    };
    let version: VersionId = ssa.fresh(store, representative, false, true);
    for (index, event) in events.iter().enumerate() {
        let Some(event): Option<&StackEvent> = event.as_ref() else {
            continue;
        };
        let Some(insn): Option<&Instruction> = instrs.get(index) else {
            continue;
        };
        ssa.escaped.insert(event.rbp_disp);
        ssa.access.insert((insn.ip(), event.rbp_disp), version);
        ssa.touch(version, insn.ip());
    }
}

fn build_slot(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    cfg: &Cfg,
    instrs: &[Instruction],
    events: &[Option<StackEvent>],
    group: &BTreeSet<i64>,
) {
    let block_count: usize = cfg.blocks.len();
    if block_count == 0 {
        return;
    }
    let rep: i64 = group.iter().next().copied().unwrap_or(0);
    let mut store_version: BTreeMap<usize, VersionId> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let Some(event): Option<StackEvent> = *event else {
            continue;
        };
        if group.contains(&event.rbp_disp) && event.kind == AccessKind::Store {
            let version: VersionId = ssa.fresh(store, event.rbp_disp, false, false);
            store_version.insert(index, version);
        }
    }
    let initial: VersionId = ssa.fresh(store, rep, false, false);
    let mut phi: BTreeMap<usize, VersionId> = BTreeMap::new();
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        if block.preds.len() >= 2 {
            phi.insert(block_index, ssa.fresh(store, rep, true, false));
        }
    }

    let mut entry: Vec<Option<VersionId>> = vec![None; block_count];
    let mut exit: Vec<Option<VersionId>> = vec![None; block_count];
    let last_store: Vec<Option<VersionId>> = cfg
        .blocks
        .iter()
        .map(|block: &crate::cfg::BasicBlock| {
            (block.start..block.end)
                .rev()
                .find_map(|index: usize| store_version.get(&index).copied())
        })
        .collect();

    let budget: usize = block_count.saturating_mul(4).saturating_add(8);
    for _ in 0..budget {
        let mut changed: bool = false;
        for block_index in 0..block_count {
            let new_entry: VersionId = compute_entry(
                block_index,
                &cfg.blocks[block_index].preds,
                &exit,
                &phi,
                initial,
            );
            if entry[block_index] != Some(new_entry) {
                entry[block_index] = Some(new_entry);
                changed = true;
            }
            let new_exit: VersionId = last_store[block_index].unwrap_or(new_entry);
            if exit[block_index] != Some(new_exit) {
                exit[block_index] = Some(new_exit);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    assign_versions(
        ssa,
        cfg,
        instrs,
        events,
        group,
        &entry,
        &store_version,
        initial,
    );
}

fn compute_entry(
    block_index: usize,
    preds: &[usize],
    exit: &[Option<VersionId>],
    phi: &BTreeMap<usize, VersionId>,
    initial: VersionId,
) -> VersionId {
    if preds.is_empty() {
        return initial;
    }
    let mut seen: BTreeSet<VersionId> = BTreeSet::new();
    for pred in preds {
        if let Some(version) = exit.get(*pred).copied().flatten() {
            seen.insert(version);
        }
    }
    match seen.len() {
        0 => initial,
        1 => seen.into_iter().next().unwrap_or(initial),
        _ => phi.get(&block_index).copied().unwrap_or(initial),
    }
}

fn assign_versions(
    ssa: &mut MemSsa,
    cfg: &Cfg,
    instrs: &[Instruction],
    events: &[Option<StackEvent>],
    group: &BTreeSet<i64>,
    entry: &[Option<VersionId>],
    store_version: &BTreeMap<usize, VersionId>,
    initial: VersionId,
) {
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut current: VersionId = entry[block_index].unwrap_or(initial);
        for index in block.start..block.end {
            let Some(event): Option<StackEvent> = events.get(index).copied().flatten() else {
                continue;
            };
            if !group.contains(&event.rbp_disp) {
                continue;
            }
            let Some(insn): Option<&Instruction> = instrs.get(index) else {
                continue;
            };
            let version: VersionId = match event.kind {
                AccessKind::Store => store_version.get(&index).copied().unwrap_or(current),
                AccessKind::Load | AccessKind::Rmw => current,
            };
            ssa.access.insert((insn.ip(), event.rbp_disp), version);
            ssa.touch(version, insn.ip());
            if event.kind == AccessKind::Store {
                current = version;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cfg;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8], base: u64) -> Vec<Instruction> {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        let mut out: Vec<Instruction> = Vec::new();
        while decoder.can_decode() {
            let insn: Instruction = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            out.push(insn);
        }
        out
    }

    #[test]
    fn diamond_reuse_splits_into_distinct_versions() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x85, 0xc9, 0x7e, 0x0a, 0x48, 0x89, 0x4d, 0x00, 0x48, 0xc1,
            0x7d, 0x00, 0x02, 0xeb, 0x08, 0x48, 0x89, 0x45, 0x00, 0x48, 0xd1, 0x6d, 0x00, 0x48,
            0x8b, 0x45, 0x00, 0x5d, 0xc3,
        ];
        let instrs: Vec<Instruction> = decode(bytes, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store: CellStore = CellStore::new();
        let ssa: MemSsa = build(&instrs, &cfg, &mut store);
        let phi_count: usize = ssa
            .versions()
            .iter()
            .filter(|v: &&VersionInfo| v.is_phi)
            .count();
        assert!(phi_count >= 1, "the join must carry a phi version");
        let store_versions: BTreeSet<TypeVar> = ssa
            .versions()
            .iter()
            .filter(|v: &&VersionInfo| !v.is_phi && v.rbp_disp == 0 && v.live_hi > 0)
            .map(|v: &VersionInfo| v.cell)
            .collect();
        assert!(
            store_versions.len() >= 2,
            "the reused slot must produce at least two live definitions",
        );
    }

    #[test]
    fn straight_line_single_store_is_one_version() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x5d, 0xc3,
        ];
        let instrs: Vec<Instruction> = decode(bytes, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store: CellStore = CellStore::new();
        let ssa: MemSsa = build(&instrs, &cfg, &mut store);
        let live: Vec<&VersionInfo> = ssa
            .versions()
            .iter()
            .filter(|v: &&VersionInfo| v.rbp_disp == 0x10 && v.live_hi > 0)
            .collect();
        let cells: BTreeSet<TypeVar> = live.iter().map(|v: &&VersionInfo| v.cell).collect();
        assert_eq!(cells.len(), 1, "one store plus one load share one version");
    }

    #[test]
    fn escaped_slot_is_single_version() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0x10, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b,
            0x45, 0x10, 0x5d, 0xc3,
        ];
        let instrs: Vec<Instruction> = decode(bytes, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store: CellStore = CellStore::new();
        let ssa: MemSsa = build(&instrs, &cfg, &mut store);
        assert!(ssa.is_escaped(0x10));
        let live: Vec<&VersionInfo> = ssa
            .versions()
            .iter()
            .filter(|v: &&VersionInfo| v.rbp_disp == 0x10 && v.live_hi > 0)
            .collect();
        assert_eq!(live.len(), 1);
        assert!(live[0].escaped);
    }

    const TWO_DISJOINT_SLOTS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x45, 0xf8, 0x48, 0x89, 0x45, 0xf0, 0x48, 0x8b, 0x4d,
        0xf8, 0x48, 0x8b, 0x4d, 0xf0, 0x5d, 0xc3,
    ];

    fn ssa_with(bytes: &[u8], base: u64, oracle: &dyn AliasOracle) -> MemSsa {
        let instrs: Vec<Instruction> = decode(bytes, base);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store: CellStore = CellStore::new();
        build_with_oracle(&instrs, &cfg, &mut store, oracle)
    }

    fn assert_exact_mem_ssa_match(refined: &MemSsa, conflated: &MemSsa) {
        assert_eq!(refined.versions, conflated.versions);
        assert_eq!(refined.access, conflated.access);
        assert_eq!(refined.escaped, conflated.escaped);
    }

    #[test]
    fn always_may_alias_conflates_every_concrete_offset_into_one_group() {
        let concrete: [i64; 2] = [-16, -8];
        let mut widths: BTreeMap<i64, Width> = BTreeMap::new();
        widths.insert(-16, Width::Qword);
        widths.insert(-8, Width::Qword);
        let offsets: BTreeMap<i64, Option<StackOffset>> = BTreeMap::from([
            (
                -16,
                Some(StackOffset {
                    rbp_disp: -16,
                    index: None,
                    index_address_size: 0,
                    index_symbol: None,
                    index_scale: 1,
                }),
            ),
            (
                -8,
                Some(StackOffset {
                    rbp_disp: -8,
                    index: None,
                    index_address_size: 0,
                    index_symbol: None,
                    index_scale: 1,
                }),
            ),
        ]);

        let conflated: Vec<BTreeSet<i64>> =
            group_offsets(&concrete, &widths, &offsets, &crate::region::AlwaysMayAlias);
        assert_eq!(conflated.len(), 1, "the ignorant oracle merges every slot");
        assert_eq!(conflated[0].len(), 2);

        let split: Vec<BTreeSet<i64>> =
            group_offsets(&concrete, &widths, &offsets, &RegionModel::default());
        assert_eq!(split.len(), 2, "disjoint extents are proven and kept apart");
    }

    #[test]
    fn conservativity_differential_conflates_disjoint_loads_under_ignorance() {
        let conflated: MemSsa =
            ssa_with(TWO_DISJOINT_SLOTS, 0x1000, &crate::region::AlwaysMayAlias);
        assert_eq!(
            conflated.version_cell(0x100c, -8),
            conflated.version_cell(0x1010, -16),
            "the ignorant oracle must fold both loads onto the last store",
        );

        let refined: MemSsa = ssa_with(TWO_DISJOINT_SLOTS, 0x1000, &RegionModel::default());
        assert_ne!(
            refined.version_cell(0x100c, -8),
            refined.version_cell(0x1010, -16),
            "the region oracle may split only what it proves disjoint",
        );
    }

    const CORRELATED_INDEXED_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0x48, 0x89, 0x54, 0xcd, 0xc8, 0x48,
        0x8b, 0x44, 0xcd, 0xc0, 0x48, 0x8b, 0x54, 0xcd, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn correlated_indexed_fields_split_only_with_the_region_model() {
        let conflated: MemSsa = ssa_with(
            CORRELATED_INDEXED_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(CORRELATED_INDEXED_FIELDS, 0x1000, &RegionModel::default());

        assert_eq!(
            conflated.version_cell(0x100e, -0x40),
            conflated.version_cell(0x1013, -0x38),
            "the ignorant model merges both indexed fields",
        );
        assert_ne!(
            refined.version_cell(0x100e, -0x40),
            refined.version_cell(0x1013, -0x38),
            "matching indexed fields with disjoint extents split",
        );
    }

    const UNBOUNDED_DIFFERENT_INDEXES: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0x48, 0x89, 0x54, 0xd5, 0xc8, 0x48,
        0x8b, 0x44, 0xcd, 0xc0, 0x48, 0x8b, 0x54, 0xd5, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn unbounded_index_pair_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            UNBOUNDED_DIFFERENT_INDEXES,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa =
            ssa_with(UNBOUNDED_DIFFERENT_INDEXES, 0x1000, &RegionModel::default());

        assert!(
            !refined.versions().is_empty(),
            "indexed accesses enter memory SSA"
        );
        assert_exact_mem_ssa_match(&refined, &conflated);
        assert_eq!(
            refined.version_cell(0x1004, -0x40),
            conflated.version_cell(0x1004, -0x40),
        );
        assert_eq!(
            refined.version_cell(0x1009, -0x38),
            conflated.version_cell(0x1009, -0x38),
        );
        assert_eq!(
            refined.version_cell(0x100e, -0x40),
            conflated.version_cell(0x100e, -0x40),
        );
        assert_eq!(
            refined.version_cell(0x1013, -0x38),
            conflated.version_cell(0x1013, -0x38),
        );
    }

    const REASSIGNED_INDEX_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0x89, 0xd1, 0x48, 0x89, 0x54, 0xcd,
        0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn reassigned_index_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            REASSIGNED_INDEX_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(REASSIGNED_INDEX_FIELDS, 0x1000, &RegionModel::default());

        assert_exact_mem_ssa_match(&refined, &conflated);
        assert_eq!(
            refined.version_cell(0x1004, -0x40),
            conflated.version_cell(0x1004, -0x40),
        );
        assert_eq!(
            refined.version_cell(0x100b, -0x38),
            conflated.version_cell(0x100b, -0x38),
        );
    }

    const INDEXED_ESCAPE_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x44, 0xcd, 0xc0, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0x48,
        0x89, 0x54, 0xcd, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn indexed_frame_escape_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            INDEXED_ESCAPE_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(INDEXED_ESCAPE_FIELDS, 0x1000, &RegionModel::default());

        assert!(refined.is_escaped(-0x40));
        assert!(refined.is_escaped(-0x38));
        assert_exact_mem_ssa_match(&refined, &conflated);
        assert_eq!(
            refined.version_cell(0x1009, -0x40),
            conflated.version_cell(0x1009, -0x40),
        );
        assert_eq!(
            refined.version_cell(0x100e, -0x38),
            conflated.version_cell(0x100e, -0x38),
        );
    }

    const RSP_INDEXED_ESCAPE_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x44, 0xcc, 0xc0, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0x48,
        0x89, 0x54, 0xcd, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn rsp_indexed_frame_escape_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            RSP_INDEXED_ESCAPE_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(RSP_INDEXED_ESCAPE_FIELDS, 0x1000, &RegionModel::default());

        assert!(refined.is_escaped(-0x40));
        assert!(refined.is_escaped(-0x38));
        assert_exact_mem_ssa_match(&refined, &conflated);
    }

    const CALL_BARRIER_INDEX_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48,
        0x89, 0x54, 0xcd, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn call_barrier_index_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            CALL_BARRIER_INDEX_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(CALL_BARRIER_INDEX_FIELDS, 0x1000, &RegionModel::default());

        assert_exact_mem_ssa_match(&refined, &conflated);
    }

    const CROSS_BLOCK_INDEX_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x44, 0xcd, 0xc0, 0xeb, 0x00, 0x48, 0x89, 0x54, 0xcd,
        0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn cross_block_index_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            CROSS_BLOCK_INDEX_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(CROSS_BLOCK_INDEX_FIELDS, 0x1000, &RegionModel::default());

        assert_exact_mem_ssa_match(&refined, &conflated);
    }

    #[test]
    fn version_chain_observes_every_store_the_execution_observes() {
        let refined: MemSsa = ssa_with(TWO_DISJOINT_SLOTS, 0x1000, &RegionModel::default());
        assert_eq!(
            refined.version_cell(0x100c, -8),
            refined.version_cell(0x1004, -8),
            "the load of slot -8 observes its own store",
        );
        assert_eq!(
            refined.version_cell(0x1010, -16),
            refined.version_cell(0x1008, -16),
            "the load of slot -16 observes its own store",
        );

        let restore: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x45, 0xf8, 0x48, 0x8b, 0x4d, 0xf8, 0x48, 0x89,
            0x45, 0xf8, 0x48, 0x8b, 0x4d, 0xf8, 0x5d, 0xc3,
        ];
        let chain: MemSsa = ssa_with(restore, 0x1000, &RegionModel::default());
        let first_store: Option<TypeVar> = chain.version_cell(0x1004, -8);
        let second_store: Option<TypeVar> = chain.version_cell(0x100c, -8);
        assert_ne!(first_store, second_store, "each store advances the chain");
        assert_eq!(
            chain.version_cell(0x1008, -8),
            first_store,
            "the first load observes the first store",
        );
        assert_eq!(
            chain.version_cell(0x1010, -8),
            second_store,
            "the second load observes the second store",
        );
    }

    #[test]
    fn build_matches_the_default_region_oracle() {
        let instrs: Vec<Instruction> = decode(TWO_DISJOINT_SLOTS, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store_a: CellStore = CellStore::new();
        let plain: MemSsa = build(&instrs, &cfg, &mut store_a);
        let mut store_b: CellStore = CellStore::new();
        let via_oracle: MemSsa =
            build_with_oracle(&instrs, &cfg, &mut store_b, &RegionModel::default());
        assert_eq!(plain.versions().len(), via_oracle.versions().len());
    }
}
