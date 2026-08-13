use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    CodeSize, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, UsedMemory,
};

use crate::cells::CellStore;
use crate::cfg::{BasicBlock, Cfg};
use crate::lattice::{TypeClass, TypeVar, Width};
use crate::region::{self, AliasOracle, CellKey, IndexSymbol, MemoryAccess, Region, RegionModel};

pub type VersionId = u32;

const MAX_STACK_SLOTS: usize = 1 << 12;
const MAX_REGION_CELLS: usize = 1 << 8;

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
struct MemEvent {
    key: CellKey,
    kind: AccessKind,
}

#[derive(Debug, Clone, Copy)]
struct RegionEvent {
    key: CellKey,
    access: MemoryAccess,
    kind: AccessKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    pub key: CellKey,
    pub cell: TypeVar,
    pub live_lo: u64,
    pub live_hi: u64,
    pub is_phi: bool,
    pub escaped: bool,
}

impl VersionInfo {
    #[must_use]
    pub const fn rbp_disp(&self) -> Option<i64> {
        self.key.frame_disp()
    }

    #[must_use]
    pub const fn region(&self) -> Region {
        self.key.region
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellAccess {
    pub key: CellKey,
    pub cell: TypeVar,
    pub escaped: bool,
}

#[derive(Debug, Default)]
pub struct MemSsa {
    versions: Vec<VersionInfo>,
    access: BTreeMap<u64, (CellKey, VersionId)>,
    escaped: BTreeSet<i64>,
}

impl MemSsa {
    #[must_use]
    pub fn version_cell(&self, ip: u64, rbp_disp: i64) -> Option<TypeVar> {
        self.version_at(ip, CellKey::stack(rbp_disp))
    }

    #[must_use]
    pub fn version_at(&self, ip: u64, key: CellKey) -> Option<TypeVar> {
        let (found, id): (CellKey, VersionId) = *self.access.get(&ip)?;
        if found != key {
            return None;
        }
        self.versions
            .get(id as usize)
            .map(|info: &VersionInfo| info.cell)
    }

    #[must_use]
    pub fn access_at(&self, ip: u64) -> Option<CellAccess> {
        let (key, id): (CellKey, VersionId) = *self.access.get(&ip)?;
        let version: &VersionInfo = self.versions.get(id as usize)?;
        Some(CellAccess {
            key,
            cell: version.cell,
            escaped: version.escaped,
        })
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
        key: CellKey,
        is_phi: bool,
        escaped: bool,
    ) -> VersionId {
        let id: VersionId = u32::try_from(self.versions.len()).unwrap_or(u32::MAX);
        let cell: TypeVar = store.fresh(TypeClass::Top);
        self.versions.push(VersionInfo {
            key,
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

fn forces_whole_frame_escape(insn: &Instruction) -> bool {
    if insn.mnemonic() != Mnemonic::Lea {
        return false;
    }
    if matches!(
        insn.op0_register().full_register(),
        Register::RSP | Register::RBP
    ) {
        return false;
    }
    match insn.memory_base() {
        Register::RSP => true,
        Register::RBP => {
            insn.memory_index() != Register::None
                && decoded_index_scale(insn.memory_index_scale()).is_some()
        }
        _ => false,
    }
}

#[must_use]
pub fn build(instrs: &[Instruction], cfg: &Cfg, store: &mut CellStore) -> MemSsa {
    build_with_model(instrs, cfg, store, &RegionModel::default())
}

#[must_use]
pub fn build_with_model(
    instrs: &[Instruction],
    cfg: &Cfg,
    store: &mut CellStore,
    model: &RegionModel,
) -> MemSsa {
    build_with_oracle(instrs, cfg, store, model, model)
}

fn build_with_oracle(
    instrs: &[Instruction],
    cfg: &Cfg,
    store: &mut CellStore,
    oracle: &dyn AliasOracle,
    model: &RegionModel,
) -> MemSsa {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut stack: Vec<Option<StackEvent>> = instrs
        .iter()
        .map(|insn: &Instruction| stack_event(insn, &mut factory))
        .collect();
    annotate_index_symbols(instrs, cfg, &mut stack);

    let mut events: Vec<Option<MemEvent>> = stack
        .iter()
        .map(|event: &Option<StackEvent>| {
            event.map(|event: StackEvent| MemEvent {
                key: CellKey::stack(event.rbp_disp),
                kind: event.kind,
            })
        })
        .collect();

    let mut ssa: MemSsa = MemSsa::default();
    build_stack_cells(&mut ssa, store, cfg, instrs, &stack, &events, oracle);

    let (region_events, barriers): (Vec<Option<RegionEvent>>, BTreeSet<usize>) =
        collect_region_events(instrs, cfg, model, &stack);
    build_region_cells(
        &mut ssa,
        store,
        cfg,
        instrs,
        &mut events,
        &region_events,
        &barriers,
        oracle,
    );
    ssa
}

fn build_stack_cells(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    cfg: &Cfg,
    instrs: &[Instruction],
    stack: &[Option<StackEvent>],
    events: &[Option<MemEvent>],
    oracle: &dyn AliasOracle,
) {
    if instrs
        .iter()
        .any(|insn: &Instruction| forces_whole_frame_escape(insn))
    {
        build_all_escaped(ssa, store, instrs, stack);
        return;
    }
    for insn in instrs {
        if let Some(rbp_disp) = escaped_slot(insn) {
            ssa.escaped.insert(rbp_disp);
        }
    }

    let mut widths: BTreeMap<i64, Width> = BTreeMap::new();
    let mut offsets: BTreeMap<i64, Option<StackOffset>> = BTreeMap::new();
    for event in stack.iter().flatten() {
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
            build_escaped_slot(ssa, store, instrs, stack, rbp_disp);
        }
    }

    let concrete: Vec<i64> = widths
        .keys()
        .copied()
        .filter(|rbp_disp: &i64| !ssa.escaped.contains(rbp_disp))
        .collect();
    let empty: BTreeSet<usize> = BTreeSet::new();
    for group in group_offsets(&concrete, &widths, &offsets, oracle) {
        let keys: BTreeSet<CellKey> = group.iter().copied().map(CellKey::stack).collect();
        build_group(ssa, store, cfg, instrs, events, &keys, &empty);
    }
}

const fn stack_alloc(offset: StackOffset, width: Width) -> MemoryAccess {
    MemoryAccess {
        region: Region::Stack,
        segment: Register::None,
        base: Register::RBP,
        disp: offset.rbp_disp,
        index: offset.index,
        index_address_size: offset.index_address_size,
        index_symbol: offset.index_symbol,
        index_scale: offset.index_scale,
        index_bound: None,
        width,
        escapes: false,
    }
}

const fn region_alloc(region: Region) -> MemoryAccess {
    MemoryAccess {
        region,
        segment: Register::None,
        base: Register::None,
        disp: 0,
        index: None,
        index_address_size: 0,
        index_symbol: None,
        index_scale: 0,
        index_bound: None,
        width: Width::Unknown,
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
    if count > MAX_STACK_SLOTS {
        return vec![concrete.iter().copied().collect()];
    }
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

fn single_memory_operand(insn: &Instruction) -> Option<u32> {
    let mut found: Option<u32> = None;
    for op in 0..insn.op_count() {
        if insn.op_kind(op) != OpKind::Memory {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(op);
    }
    found
}

const fn memory_access_kind(access: OpAccess) -> Option<AccessKind> {
    match access {
        OpAccess::Read | OpAccess::CondRead => Some(AccessKind::Load),
        OpAccess::Write | OpAccess::CondWrite => Some(AccessKind::Store),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(AccessKind::Rmw),
        OpAccess::None | OpAccess::NoMemAccess => None,
    }
}

fn symbol_of(
    register: Register,
    block: usize,
    writes: &BTreeMap<Register, usize>,
    call_barrier: Option<usize>,
) -> IndexSymbol {
    IndexSymbol::new(
        block,
        writes.get(&register.full_register()).copied(),
        call_barrier,
    )
}

fn region_event(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    model: &RegionModel,
    block: usize,
    writes: &BTreeMap<Register, usize>,
    call_barrier: Option<usize>,
) -> Option<RegionEvent> {
    if insn.mnemonic() == Mnemonic::Lea {
        return None;
    }
    let memop: u32 = single_memory_operand(insn)?;
    let [used]: &[UsedMemory] = factory.info(insn).used_memory() else {
        return None;
    };
    let kind: AccessKind = memory_access_kind(used.access())?;
    let mut access: MemoryAccess = region::classify(insn, memop, model)?;
    if access.region == Region::Stack {
        return None;
    }
    access.index_symbol = access
        .index
        .map(|index: Register| symbol_of(index, block, writes, call_barrier));
    let base: IndexSymbol = symbol_of(access.base, block, writes, call_barrier);
    Some(RegionEvent {
        key: CellKey::of(&access, base),
        access,
        kind,
    })
}

fn unmodelled_memory(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    model: &RegionModel,
) -> bool {
    factory
        .info(insn)
        .used_memory()
        .iter()
        .filter(|used: &&UsedMemory| memory_access_kind(used.access()).is_some())
        .any(|used: &UsedMemory| !model.is_frame(used.base()) || used.index() != Register::None)
}

fn collect_region_events(
    instrs: &[Instruction],
    cfg: &Cfg,
    model: &RegionModel,
    stack: &[Option<StackEvent>],
) -> (Vec<Option<RegionEvent>>, BTreeSet<usize>) {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut events: Vec<Option<RegionEvent>> = vec![None; instrs.len()];
    let mut barriers: BTreeSet<usize> = BTreeSet::new();
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut writes: BTreeMap<Register, usize> = BTreeMap::new();
        let mut call_barrier: Option<usize> = None;
        for index in block.start..block.end {
            let Some(insn): Option<&Instruction> = instrs.get(index) else {
                break;
            };
            let occupied: bool = stack.get(index).copied().flatten().is_some();
            let event: Option<RegionEvent> = if occupied {
                None
            } else {
                region_event(
                    insn,
                    &mut factory,
                    model,
                    block_index,
                    &writes,
                    call_barrier,
                )
            };
            let calls: bool = matches!(
                insn.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            );
            if calls
                || (event.is_none() && !occupied && unmodelled_memory(insn, &mut factory, model))
            {
                barriers.insert(index);
            }
            if let Some(slot) = events.get_mut(index) {
                *slot = event;
            }
            let info: &iced_x86::InstructionInfo = factory.info(insn);
            for used in info.used_registers() {
                if writes_register(used.access()) {
                    writes.insert(used.register().full_register(), index);
                }
            }
            if calls {
                call_barrier = Some(index);
            }
        }
    }
    (events, barriers)
}

fn region_shapes(events: &[Option<RegionEvent>]) -> BTreeMap<CellKey, MemoryAccess> {
    let mut shapes: BTreeMap<CellKey, MemoryAccess> = BTreeMap::new();
    for event in events.iter().flatten() {
        let entry: &mut MemoryAccess = shapes.entry(event.key).or_insert(event.access);
        let same: bool = MemoryAccess {
            width: Width::Unknown,
            ..*entry
        } == MemoryAccess {
            width: Width::Unknown,
            ..event.access
        };
        if same {
            entry.width = entry.width.join(event.access.width);
        } else {
            *entry = region_alloc(event.key.region);
        }
    }
    shapes
}

fn group_region_keys(
    shapes: &BTreeMap<CellKey, MemoryAccess>,
    oracle: &dyn AliasOracle,
) -> Vec<BTreeSet<CellKey>> {
    let keys: Vec<CellKey> = shapes.keys().copied().collect();
    let count: usize = keys.len();
    let mut parent: Vec<usize> = (0..count).collect();
    for left in 0..count {
        for right in (left + 1)..count {
            let (Some(a), Some(b)): (Option<&MemoryAccess>, Option<&MemoryAccess>) =
                (shapes.get(&keys[left]), shapes.get(&keys[right]))
            else {
                continue;
            };
            if oracle.alias(a, b).may_alias() {
                union_find_join(&mut parent, left, right);
            }
        }
    }
    let mut groups: BTreeMap<usize, BTreeSet<CellKey>> = BTreeMap::new();
    for (index, key) in keys.iter().enumerate() {
        let root: usize = union_find_root(&mut parent, index);
        groups.entry(root).or_default().insert(*key);
    }
    groups.into_values().collect()
}

fn build_region_cells(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    cfg: &Cfg,
    instrs: &[Instruction],
    events: &mut [Option<MemEvent>],
    region_events: &[Option<RegionEvent>],
    barriers: &BTreeSet<usize>,
    oracle: &dyn AliasOracle,
) {
    let mut shapes: BTreeMap<CellKey, MemoryAccess> = region_shapes(region_events);
    let capped: bool = shapes.len() > MAX_REGION_CELLS;
    if capped {
        shapes = region_events
            .iter()
            .flatten()
            .map(|event: &RegionEvent| {
                (
                    CellKey::wide(event.key.region),
                    region_alloc(event.key.region),
                )
            })
            .collect();
    }
    let mut present: bool = false;
    for (index, event) in region_events.iter().enumerate() {
        let Some(event): Option<&RegionEvent> = event.as_ref() else {
            continue;
        };
        let key: CellKey = if capped {
            CellKey::wide(event.key.region)
        } else {
            event.key
        };
        if let Some(slot) = events.get_mut(index)
            && slot.is_none()
        {
            *slot = Some(MemEvent {
                key,
                kind: event.kind,
            });
            present = true;
        }
    }
    if !present {
        return;
    }
    for group in group_region_keys(&shapes, oracle) {
        build_group(ssa, store, cfg, instrs, events, &group, barriers);
    }
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
    let key: CellKey = CellKey::stack(rbp_disp);
    let version: VersionId = ssa.fresh(store, key, false, true);
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
        ssa.access.insert(insn.ip(), (key, version));
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
    let version: VersionId = ssa.fresh(store, CellKey::stack(representative), false, true);
    for (index, event) in events.iter().enumerate() {
        let Some(event): Option<&StackEvent> = event.as_ref() else {
            continue;
        };
        let Some(insn): Option<&Instruction> = instrs.get(index) else {
            continue;
        };
        ssa.escaped.insert(event.rbp_disp);
        ssa.access
            .insert(insn.ip(), (CellKey::stack(event.rbp_disp), version));
        ssa.touch(version, insn.ip());
    }
}

fn build_group(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    cfg: &Cfg,
    instrs: &[Instruction],
    events: &[Option<MemEvent>],
    group: &BTreeSet<CellKey>,
    barriers: &BTreeSet<usize>,
) {
    let block_count: usize = cfg.blocks.len();
    if block_count == 0 {
        return;
    }
    let Some(rep): Option<CellKey> = group.iter().next().copied() else {
        return;
    };
    let mut store_version: BTreeMap<usize, VersionId> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let Some(event): Option<MemEvent> = *event else {
            continue;
        };
        if group.contains(&event.key) && event.kind == AccessKind::Store {
            let version: VersionId = ssa.fresh(store, event.key, false, false);
            store_version.insert(index, version);
        }
    }
    for index in barriers {
        if store_version.contains_key(index) {
            continue;
        }
        let version: VersionId = ssa.fresh(store, rep, false, false);
        store_version.insert(*index, version);
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
        .map(|block: &BasicBlock| {
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
    events: &[Option<MemEvent>],
    group: &BTreeSet<CellKey>,
    entry: &[Option<VersionId>],
    store_version: &BTreeMap<usize, VersionId>,
    initial: VersionId,
) {
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut current: VersionId = entry[block_index].unwrap_or(initial);
        for index in block.start..block.end {
            let event: Option<MemEvent> = events
                .get(index)
                .copied()
                .flatten()
                .filter(|event: &MemEvent| group.contains(&event.key));
            if let Some(event) = event
                && let Some(insn) = instrs.get(index)
            {
                let version: VersionId = match event.kind {
                    AccessKind::Store => store_version.get(&index).copied().unwrap_or(current),
                    AccessKind::Load | AccessKind::Rmw => current,
                };
                ssa.access.insert(insn.ip(), (event.key, version));
                ssa.touch(version, insn.ip());
            }
            if let Some(version) = store_version.get(&index).copied() {
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
            .filter(|v: &&VersionInfo| !v.is_phi && v.rbp_disp() == Some(0) && v.live_hi > 0)
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
            .filter(|v: &&VersionInfo| v.rbp_disp() == Some(0x10) && v.live_hi > 0)
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
            .filter(|v: &&VersionInfo| v.rbp_disp() == Some(0x10) && v.live_hi > 0)
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
        build_with_oracle(&instrs, &cfg, &mut store, oracle, &RegionModel::default())
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

    const RSP_PLAIN_ESCAPE_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x44, 0x24, 0xc0, 0x48, 0x89, 0x45, 0xc0, 0x48, 0x89,
        0x55, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn rsp_plain_lea_escape_matches_the_ignorant_version_chain() {
        let conflated: MemSsa = ssa_with(
            RSP_PLAIN_ESCAPE_FIELDS,
            0x1000,
            &crate::region::AlwaysMayAlias,
        );
        let refined: MemSsa = ssa_with(RSP_PLAIN_ESCAPE_FIELDS, 0x1000, &RegionModel::default());

        assert!(refined.is_escaped(-0x40));
        assert!(refined.is_escaped(-0x38));
        assert_exact_mem_ssa_match(&refined, &conflated);
    }

    const FRAME_SETUP_LEA_FIELDS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x45, 0xc0, 0x48, 0x89,
        0x55, 0xc8, 0x5d, 0xc3,
    ];

    #[test]
    fn frame_pointer_setup_lea_does_not_escape_the_frame() {
        let refined: MemSsa = ssa_with(FRAME_SETUP_LEA_FIELDS, 0x1000, &RegionModel::default());
        assert!(!refined.is_escaped(-0x40));
        assert!(!refined.is_escaped(-0x38));
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

    const EVERY_REGION: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x45, 0xf8, 0x8b, 0x0c, 0x25, 0x00, 0x33, 0x20, 0x00,
        0x8b, 0x14, 0x25, 0x00, 0x02, 0x20, 0x00, 0x64, 0x8b, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00,
        0x8b, 0x78, 0x10, 0x44, 0x8b, 0x43, 0x10, 0x5d, 0xc3,
    ];

    const FIVE_KNOWN_REGIONS: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x45, 0xf8, 0x8b, 0x0c, 0x25, 0x00, 0x33, 0x20, 0x00,
        0x8b, 0x14, 0x25, 0x00, 0x02, 0x20, 0x00, 0x64, 0x8b, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00,
        0x8b, 0x78, 0x10, 0x5d, 0xc3,
    ];

    fn seeded_model() -> RegionModel {
        let mut model: RegionModel = RegionModel::new();
        model.add_data(0x0020_3300, 0x0020_3310);
        model.add_rodata(0x0020_0200, 0x0020_0210);
        model.mark_heap(Register::RAX);
        model
    }

    fn accesses(bytes: &[u8], model: &RegionModel) -> Vec<(Region, TypeVar)> {
        let instrs: Vec<Instruction> = decode(bytes, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store: CellStore = CellStore::new();
        let ssa: MemSsa = build_with_model(&instrs, &cfg, &mut store, model);
        instrs
            .iter()
            .filter_map(|insn: &Instruction| ssa.access_at(insn.ip()))
            .map(|access: CellAccess| (access.key.region, access.cell))
            .collect()
    }

    #[test]
    fn every_region_receives_its_own_cell() {
        let model: RegionModel = seeded_model();
        let found: BTreeSet<Region> = accesses(EVERY_REGION, &model)
            .into_iter()
            .map(|(region, _): (Region, TypeVar)| region)
            .collect();
        assert_eq!(
            found,
            BTreeSet::from([
                Region::Stack,
                Region::Global,
                Region::Heap,
                Region::Tls,
                Region::ConstPool,
                Region::Unknown,
            ]),
            "every region the code touches enters memory ssa",
        );
    }

    #[test]
    fn known_regions_never_share_a_cell() {
        let model: RegionModel = seeded_model();
        let observed: Vec<(Region, TypeVar)> = accesses(FIVE_KNOWN_REGIONS, &model);
        let regions: BTreeSet<Region> = observed
            .iter()
            .map(|(region, _): &(Region, TypeVar)| *region)
            .collect();
        let cells: BTreeSet<TypeVar> = observed
            .iter()
            .map(|(_, cell): &(Region, TypeVar)| *cell)
            .collect();
        assert_eq!(regions.len(), 5, "five distinct regions: {regions:?}");
        assert_eq!(
            cells.len(),
            5,
            "each proven region keeps its own cell: {observed:?}",
        );
    }

    const GLOBAL_ACROSS_CALL: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x8b, 0x0c, 0x25, 0x00, 0x33, 0x20, 0x00, 0xe8, 0x00, 0x00, 0x00,
        0x00, 0x8b, 0x14, 0x25, 0x00, 0x33, 0x20, 0x00, 0x5d, 0xc3,
    ];

    const GLOBAL_WITHOUT_CALL: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x8b, 0x0c, 0x25, 0x00, 0x33, 0x20, 0x00, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x8b, 0x14, 0x25, 0x00, 0x33, 0x20, 0x00, 0x5d, 0xc3,
    ];

    #[test]
    fn a_call_clobbers_the_global_version_chain() {
        let model: RegionModel = seeded_model();
        let across: Vec<(Region, TypeVar)> = accesses(GLOBAL_ACROSS_CALL, &model);
        let stable: Vec<(Region, TypeVar)> = accesses(GLOBAL_WITHOUT_CALL, &model);

        let across_cells: BTreeSet<TypeVar> = across
            .iter()
            .map(|(_, cell): &(Region, TypeVar)| *cell)
            .collect();
        let stable_cells: BTreeSet<TypeVar> = stable
            .iter()
            .map(|(_, cell): &(Region, TypeVar)| *cell)
            .collect();
        assert_eq!(across.len(), 2, "both global loads enter memory ssa");
        assert_eq!(stable.len(), 2, "both global loads enter memory ssa");
        assert_eq!(
            stable_cells.len(),
            1,
            "without a call the two loads observe one definition",
        );
        assert_eq!(
            across_cells.len(),
            2,
            "a call may write the global, so the second load is a new definition",
        );
    }

    fn many_global_loads(count: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0x55, 0x48, 0x89, 0xe5];
        for index in 0..count {
            let address: u32 = 0x0020_3300 + u32::try_from(index).unwrap() * 8;
            bytes.extend_from_slice(&[0x8b, 0x04, 0x25]);
            bytes.extend_from_slice(&address.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x5d, 0xc3]);
        bytes
    }

    #[test]
    fn the_cell_cap_falls_back_to_one_conservative_cell_per_region() {
        let mut model: RegionModel = RegionModel::new();
        model.add_data(0x0020_3300, 0x0021_0000);

        let under: Vec<u8> = many_global_loads(MAX_REGION_CELLS);
        let over: Vec<u8> = many_global_loads(MAX_REGION_CELLS + 1);

        let under_cells: BTreeSet<TypeVar> = accesses(&under, &model)
            .into_iter()
            .map(|(_, cell): (Region, TypeVar)| cell)
            .collect();
        assert_eq!(
            under_cells.len(),
            MAX_REGION_CELLS,
            "below the cap every proven global keeps its own cell",
        );

        let over_accesses: Vec<(Region, TypeVar)> = accesses(&over, &model);
        let over_cells: BTreeSet<TypeVar> = over_accesses
            .iter()
            .map(|(_, cell): &(Region, TypeVar)| *cell)
            .collect();
        assert_eq!(
            over_accesses.len(),
            MAX_REGION_CELLS + 1,
            "the cap never drops an access",
        );
        assert_eq!(
            over_cells.len(),
            1,
            "above the cap the region collapses to one conservative cell",
        );
    }

    #[test]
    fn region_cells_are_deterministic() {
        let model: RegionModel = seeded_model();
        let instrs: Vec<Instruction> = decode(EVERY_REGION, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut first_store: CellStore = CellStore::new();
        let first: MemSsa = build_with_model(&instrs, &cfg, &mut first_store, &model);
        let mut second_store: CellStore = CellStore::new();
        let second: MemSsa = build_with_model(&instrs, &cfg, &mut second_store, &model);
        assert_exact_mem_ssa_match(&first, &second);
    }

    #[test]
    fn a_seeded_model_never_disturbs_the_frame_slots() {
        let model: RegionModel = seeded_model();
        let instrs: Vec<Instruction> = decode(TWO_DISJOINT_SLOTS, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut plain_store: CellStore = CellStore::new();
        let plain: MemSsa = build(&instrs, &cfg, &mut plain_store);
        let mut seeded_store: CellStore = CellStore::new();
        let seeded: MemSsa = build_with_model(&instrs, &cfg, &mut seeded_store, &model);
        assert_exact_mem_ssa_match(&plain, &seeded);
    }

    #[test]
    fn build_matches_the_default_region_oracle() {
        let instrs: Vec<Instruction> = decode(TWO_DISJOINT_SLOTS, 0x1000);
        let cfg: cfg::Cfg = cfg::build(&instrs);
        let mut store_a: CellStore = CellStore::new();
        let plain: MemSsa = build(&instrs, &cfg, &mut store_a);
        let mut store_b: CellStore = CellStore::new();
        let via_oracle: MemSsa = build_with_oracle(
            &instrs,
            &cfg,
            &mut store_b,
            &RegionModel::default(),
            &RegionModel::default(),
        );
        assert_eq!(plain.versions().len(), via_oracle.versions().len());
    }
}
