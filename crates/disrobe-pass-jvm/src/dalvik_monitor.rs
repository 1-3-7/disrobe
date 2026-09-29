use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::dalvik_cfg::DalvikMethodCfg;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Edge, EdgeKind, MonitorRegion, NaturalLoop, compute_dominators,
    find_natural_loops,
};

const MONITOR_ENTER: u8 = 0x1D;
const MONITOR_EXIT: u8 = 0x1E;
const MOVE_EXCEPTION: u8 = 0x0D;
const THROW: u8 = 0x27;
const MAX_HANDLER_BLOCKS: usize = 4;
const MAX_TRAMPOLINE_HOPS: usize = 4;
const MAX_MONITOR_BODY_BLOCKS: usize = 4_096;

#[derive(Debug, Default)]
pub(crate) struct MonitorPlan {
    pub(crate) regions: BTreeMap<BlockId, MonitorRegion>,
    pub(crate) released: BTreeSet<usize>,
    pub(crate) unrecovered: bool,
}

#[derive(Debug, Clone)]
struct MonitorHandler {
    lock_register: u16,
    exit_insn: usize,
}

#[derive(Debug)]
struct RecoveredMonitor {
    enter: BlockId,
    region: MonitorRegion,
    exits: Vec<usize>,
    handlers: BTreeSet<BlockId>,
}

pub(crate) fn recover_monitors(built: &mut DalvikMethodCfg) -> MonitorPlan {
    let enters: Vec<(BlockId, u16)> = built
        .cfg
        .blocks
        .iter()
        .filter_map(|block: &BasicBlock| {
            let last: &DalvikInsn = built.insns.get(block.insn_range.1.checked_sub(1)?)?;
            if last.op != MONITOR_ENTER {
                return None;
            }
            last.regs.first().map(|&lock: &u16| (block.id, lock))
        })
        .collect();
    let monitor_insns: usize = built
        .insns
        .iter()
        .filter(|insn: &&DalvikInsn| matches!(insn.op, MONITOR_ENTER | MONITOR_EXIT))
        .count();
    if monitor_insns == 0 {
        return MonitorPlan::default();
    }
    let unrecovered: MonitorPlan = MonitorPlan {
        unrecovered: true,
        ..MonitorPlan::default()
    };
    let handlers: BTreeMap<BlockId, MonitorHandler> = monitor_handlers(&built.cfg, &built.insns);
    let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &compute_dominators(&built.cfg));
    let mut recovered: Vec<RecoveredMonitor> = Vec::with_capacity(enters.len());
    for &(enter, lock_register) in &enters {
        let Some(monitor): Option<RecoveredMonitor> =
            monitor_region(built, &handlers, &loops, enter, lock_register)
        else {
            return unrecovered;
        };
        recovered.push(monitor);
    }
    let mut released: BTreeSet<usize> = BTreeSet::new();
    let mut detached: BTreeSet<BlockId> = BTreeSet::new();
    for monitor in &recovered {
        released.extend(monitor.exits.iter().copied());
        detached.extend(monitor.handlers.iter().copied());
    }
    for handler in &detached {
        if let Some(found) = handlers.get(handler) {
            released.insert(found.exit_insn);
        }
    }
    let exits_in_method: usize = built
        .insns
        .iter()
        .filter(|insn: &&DalvikInsn| insn.op == MONITOR_EXIT)
        .count();
    if released.len() != exits_in_method || enters.len() + exits_in_method != monitor_insns {
        return unrecovered;
    }
    detach_handlers(&mut built.cfg, &detached);
    MonitorPlan {
        regions: recovered
            .into_iter()
            .map(|monitor: RecoveredMonitor| (monitor.enter, monitor.region))
            .collect(),
        released,
        unrecovered: false,
    }
}

fn monitor_handlers(cfg: &Cfg, insns: &[DalvikInsn]) -> BTreeMap<BlockId, MonitorHandler> {
    let heads: BTreeSet<BlockId> = cfg
        .exception_regions
        .iter()
        .filter(|region| region.catch_type.is_none())
        .filter_map(|region| cfg.pc_to_block.get(&region.handler_pc).copied())
        .collect();
    heads
        .into_iter()
        .filter_map(|head: BlockId| {
            monitor_handler(cfg, insns, head).map(|found: MonitorHandler| (head, found))
        })
        .collect()
}

fn monitor_handler(cfg: &Cfg, insns: &[DalvikInsn], head: BlockId) -> Option<MonitorHandler> {
    let mut blocks: Vec<BlockId> = vec![head];
    let mut body: Vec<usize> = Vec::new();
    let mut current: BlockId = head;
    loop {
        let block: &BasicBlock = cfg.blocks.get(current.0 as usize)?;
        body.extend(
            (block.insn_range.0..block.insn_range.1).filter(|&index: &usize| {
                insns
                    .get(index)
                    .is_some_and(|insn: &DalvikInsn| !insn.is_unconditional_goto())
            }),
        );
        if body.len() > 3 {
            return None;
        }
        let normal: Vec<BlockId> = normal_successors(block).collect();
        match normal.as_slice() {
            [] => break,
            [next] if blocks.len() < MAX_HANDLER_BLOCKS && !blocks.contains(next) => {
                blocks.push(*next);
                current = *next;
            }
            _ => return None,
        }
    }
    let [catch, release, rethrow]: [usize; 3] = body.try_into().ok()?;
    let caught: &DalvikInsn = insns.get(catch)?;
    let releasing: &DalvikInsn = insns.get(release)?;
    let throwing: &DalvikInsn = insns.get(rethrow)?;
    let exception: u16 = *caught.regs.first()?;
    let lock_register: u16 = *releasing.regs.first()?;
    (caught.op == MOVE_EXCEPTION
        && releasing.op == MONITOR_EXIT
        && throwing.op == THROW
        && throwing.regs.first() == Some(&exception)
        && lock_register != exception)
        .then_some(MonitorHandler {
            lock_register,
            exit_insn: release,
        })
}

fn monitor_region(
    built: &DalvikMethodCfg,
    handlers: &BTreeMap<BlockId, MonitorHandler>,
    loops: &[NaturalLoop],
    enter: BlockId,
    lock_register: u16,
) -> Option<RecoveredMonitor> {
    let cfg: &Cfg = &built.cfg;
    let enter_block: &BasicBlock = cfg.blocks.get(enter.0 as usize)?;
    let body_entry: BlockId = match normal_successors(enter_block).collect::<Vec<BlockId>>()[..] {
        [only] => only,
        _ => return None,
    };
    let mut body: BTreeSet<BlockId> = BTreeSet::new();
    let mut exit_blocks: BTreeSet<BlockId> = BTreeSet::new();
    let mut used_handlers: BTreeSet<BlockId> = BTreeSet::new();
    let mut pending: Vec<BlockId> = vec![body_entry];
    while let Some(current) = pending.pop() {
        if current == enter {
            return None;
        }
        if !body.insert(current) {
            continue;
        }
        if body.len() > MAX_MONITOR_BODY_BLOCKS {
            return None;
        }
        let block: &BasicBlock = cfg.blocks.get(current.0 as usize)?;
        let insns: &[DalvikInsn] = built.insns.get(block.insn_range.0..block.insn_range.1)?;
        if insns.iter().any(|insn: &DalvikInsn| {
            crate::dalvik_decompile::instruction_writes_register(insn, lock_register)
        }) {
            return None;
        }
        for edge in &block.successors {
            if !matches!(edge.kind, EdgeKind::Exception) {
                continue;
            }
            match handlers.get(&edge.target) {
                Some(handler) if handler.lock_register == lock_register => {
                    used_handlers.insert(edge.target);
                }
                Some(_) => {}
                None => {
                    if releases_before_leaving(built, edge.target, lock_register) {
                        pending.push(edge.target);
                    }
                }
            }
        }
        let last: &DalvikInsn = insns.last()?;
        if last.op == MONITOR_EXIT && last.regs.first() == Some(&lock_register) {
            exit_blocks.insert(current);
            continue;
        }
        if last.is_return() {
            return None;
        }
        pending.extend(normal_successors(block));
    }
    if used_handlers.is_empty() && body.iter().any(|block: &BlockId| throws_in(built, *block)) {
        return None;
    }
    let mut continuation: Option<BlockId> = None;
    for &exit in &exit_blocks {
        let block: &BasicBlock = cfg.blocks.get(exit.0 as usize)?;
        for successor in normal_successors(block) {
            if terminal_tail(built, successor, &exit_blocks) {
                continue;
            }
            let landing: BlockId = past_trampolines(built, successor);
            let leaves_loop: bool = loops
                .iter()
                .filter(|found: &&NaturalLoop| found.body.contains(&enter))
                .any(|found: &NaturalLoop| {
                    landing == found.header || !found.body.contains(&landing)
                });
            if leaves_loop {
                continue;
            }
            if body.contains(&landing) || landing == enter {
                return None;
            }
            match continuation {
                Some(previous) if previous != landing => return None,
                _ => continuation = Some(landing),
            }
        }
    }
    let exits: Vec<usize> = exit_blocks
        .iter()
        .filter_map(|exit: &BlockId| {
            cfg.blocks
                .get(exit.0 as usize)
                .and_then(|block: &BasicBlock| block.insn_range.1.checked_sub(1))
        })
        .collect();
    Some(RecoveredMonitor {
        enter,
        region: MonitorRegion {
            body: body_entry,
            lock_register,
            continuation,
            blocks: body,
        },
        exits,
        handlers: used_handlers,
    })
}

fn releases_before_leaving(built: &DalvikMethodCfg, start: BlockId, lock_register: u16) -> bool {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    let mut pending: Vec<BlockId> = vec![start];
    while let Some(current) = pending.pop() {
        if !seen.insert(current) || seen.len() > MAX_MONITOR_BODY_BLOCKS {
            continue;
        }
        let Some(block): Option<&BasicBlock> = built.cfg.blocks.get(current.0 as usize) else {
            return false;
        };
        let Some(last): Option<&DalvikInsn> = block
            .insn_range
            .1
            .checked_sub(1)
            .and_then(|index: usize| built.insns.get(index))
        else {
            return false;
        };
        if last.op == MONITOR_EXIT && last.regs.first() == Some(&lock_register) {
            return true;
        }
        pending.extend(normal_successors(block));
    }
    false
}

fn throws_in(built: &DalvikMethodCfg, block: BlockId) -> bool {
    built
        .cfg
        .blocks
        .get(block.0 as usize)
        .and_then(|found: &BasicBlock| built.insns.get(found.insn_range.0..found.insn_range.1))
        .is_some_and(|insns: &[DalvikInsn]| {
            insns
                .iter()
                .any(|insn: &DalvikInsn| crate::dalvik_decompile::may_throw(insn.op))
        })
}

fn terminal_tail(built: &DalvikMethodCfg, block: BlockId, exits: &BTreeSet<BlockId>) -> bool {
    let Some(found): Option<&BasicBlock> = built.cfg.blocks.get(block.0 as usize) else {
        return false;
    };
    let Some(insns): Option<&[DalvikInsn]> =
        built.insns.get(found.insn_range.0..found.insn_range.1)
    else {
        return false;
    };
    normal_successors(found).next().is_none()
        && insns.last().is_some_and(DalvikInsn::is_return)
        && !insns
            .iter()
            .any(|insn: &DalvikInsn| crate::dalvik_decompile::may_throw(insn.op))
        && found
            .predecessors
            .iter()
            .all(|predecessor: &BlockId| exits.contains(predecessor))
}

fn past_trampolines(built: &DalvikMethodCfg, start: BlockId) -> BlockId {
    let mut current: BlockId = start;
    for _ in 0..MAX_TRAMPOLINE_HOPS {
        let Some(block): Option<&BasicBlock> = built.cfg.blocks.get(current.0 as usize) else {
            return current;
        };
        let only_goto: bool = block.insn_range.1 == block.insn_range.0 + 1
            && built
                .insns
                .get(block.insn_range.0)
                .is_some_and(DalvikInsn::is_unconditional_goto);
        let targets: Vec<BlockId> = normal_successors(block).collect();
        match (only_goto, targets.as_slice()) {
            (true, [next]) => current = *next,
            _ => return current,
        }
    }
    current
}

fn normal_successors(block: &BasicBlock) -> impl Iterator<Item = BlockId> + '_ {
    block
        .successors
        .iter()
        .filter(|edge: &&Edge| !matches!(edge.kind, EdgeKind::Exception))
        .map(|edge: &Edge| edge.target)
}

fn detach_handlers(cfg: &mut Cfg, detached: &BTreeSet<BlockId>) {
    let handler_pcs: BTreeSet<u32> = detached
        .iter()
        .filter_map(|block: &BlockId| cfg.blocks.get(block.0 as usize))
        .map(|block: &BasicBlock| block.start_pc)
        .collect();
    cfg.exception_regions
        .retain(|region| !handler_pcs.contains(&region.handler_pc));
    for block in &mut cfg.blocks {
        block.successors.retain(|edge: &Edge| {
            !(matches!(edge.kind, EdgeKind::Exception) && detached.contains(&edge.target))
        });
    }
    let mut predecessors: Vec<Vec<BlockId>> = vec![Vec::new(); cfg.blocks.len()];
    for block in &cfg.blocks {
        for edge in &block.successors {
            if let Some(slot) = predecessors.get_mut(edge.target.0 as usize)
                && !slot.contains(&block.id)
            {
                slot.push(block.id);
            }
        }
    }
    for (block, incoming) in cfg.blocks.iter_mut().zip(predecessors) {
        block.predecessors = incoming;
    }
}
