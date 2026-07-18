use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register, UsedMemory};

use crate::cells::CellStore;
use crate::cfg::Cfg;
use crate::lattice::{TypeClass, TypeVar, Width};

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
    pub width: Width,
    pub kind: AccessKind,
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
        if mem.base() != Register::RBP || mem.index() != Register::None {
            continue;
        }
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
            width,
            kind,
        });
    }
    None
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

#[must_use]
pub fn build(instrs: &[Instruction], cfg: &Cfg, store: &mut CellStore) -> MemSsa {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let events: Vec<Option<StackEvent>> = instrs
        .iter()
        .map(|insn: &Instruction| stack_event(insn, &mut factory))
        .collect();

    let mut ssa: MemSsa = MemSsa::default();
    for insn in instrs {
        if let Some(rbp_disp) = escaped_slot(insn) {
            ssa.escaped.insert(rbp_disp);
        }
    }

    let mut rbp_disps: BTreeSet<i64> = BTreeSet::new();
    for event in events.iter().flatten() {
        rbp_disps.insert(event.rbp_disp);
    }

    for rbp_disp in rbp_disps {
        if ssa.escaped.contains(&rbp_disp) {
            build_escaped_slot(&mut ssa, store, instrs, &events, rbp_disp);
        } else {
            build_slot(&mut ssa, store, cfg, instrs, &events, rbp_disp);
        }
    }
    ssa
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

fn build_slot(
    ssa: &mut MemSsa,
    store: &mut CellStore,
    cfg: &Cfg,
    instrs: &[Instruction],
    events: &[Option<StackEvent>],
    rbp_disp: i64,
) {
    let block_count: usize = cfg.blocks.len();
    if block_count == 0 {
        return;
    }
    let mut store_version: BTreeMap<usize, VersionId> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if event.is_some_and(|event: StackEvent| {
            event.rbp_disp == rbp_disp && event.kind == AccessKind::Store
        }) {
            let version: VersionId = ssa.fresh(store, rbp_disp, false, false);
            store_version.insert(index, version);
        }
    }
    let initial: VersionId = ssa.fresh(store, rbp_disp, false, false);
    let mut phi: BTreeMap<usize, VersionId> = BTreeMap::new();
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        if block.preds.len() >= 2 {
            phi.insert(block_index, ssa.fresh(store, rbp_disp, true, false));
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
        rbp_disp,
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
    rbp_disp: i64,
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
            if event.rbp_disp != rbp_disp {
                continue;
            }
            let Some(insn): Option<&Instruction> = instrs.get(index) else {
                continue;
            };
            let version: VersionId = match event.kind {
                AccessKind::Store => store_version.get(&index).copied().unwrap_or(current),
                AccessKind::Load | AccessKind::Rmw => current,
            };
            ssa.access.insert((insn.ip(), rbp_disp), version);
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
}
