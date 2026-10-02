use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph};

use super::region_check::{Defect, HandlerClause, handler_clauses};
use crate::dalvik::DalvikInsn;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, EdgeKind, NaturalLoop, PrecomputedSwitch, Region, SwitchKey,
};

const MAX_NEST_DEPTH: usize = 384;
const MAX_TRAMPOLINE_STEPS: usize = 16;
const MAX_LAYERS: usize = 512;
const MOVE_EXCEPTION: u8 = 0x0D;

const NO_FLOW: Defect = "the method's control flow graph could not be built for nested blocks";
const TOO_DEEP: Defect = "the method nests control flow too deeply for nested blocks";
const CROSSING_TRIES: Defect =
    "the method's try ranges overlap in an order that no nesting of try statements reproduces";
const MIXED_BODY: Defect =
    "a try statement would protect an instruction the bytecode sends to other handlers";
const HANDLER_PLACE: Defect = "a catch handler lies outside the statement that holds its try";
const TRY_ENTRY: Defect = "a try range is entered somewhere other than its first block";
const NO_PLACE: Defect = "a block has no enclosing statement where its code can be placed";
const LOOP_ACROSS_TRY: Defect = "a loop crosses the boundary of a try range";
const NOT_A_SWITCH: Defect = "a switch block has no recovered dispatch table";

pub(super) struct NestedBlocks {
    pub(super) root: Region,
    pub(super) rethrows: BTreeSet<BlockId>,
    pub(super) duplicated: BTreeSet<BlockId>,
    pub(super) caught: BTreeMap<BlockId, u16>,
    pub(super) split_heads: BTreeSet<BlockId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Context {
    Root,
    Body(usize),
    Handler(usize, usize),
}

type LayerClause = (Option<String>, Option<BlockId>);
type LayerHandler = (Vec<String>, Option<BlockId>, BTreeSet<BlockId>);

#[derive(Debug)]
struct Layer {
    clauses: Vec<LayerClause>,
    covered: BTreeSet<BlockId>,
    fix: bool,
    head: BlockId,
    parent: Context,
    body: BTreeSet<BlockId>,
    handlers: Vec<LayerHandler>,
}

pub(super) fn nested_blocks(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    switches: &BTreeMap<BlockId, PrecomputedSwitch>,
    loops: &[NaturalLoop],
    split_shared_handlers: bool,
) -> Result<NestedBlocks, Defect> {
    let flow: FlowGraph<BlockId> = throwing_flow(cfg, insns).ok_or(NO_FLOW)?;
    let order: Vec<BlockId> = flow.reverse_postorder().collect();
    let rank: BTreeMap<BlockId, usize> = order
        .iter()
        .enumerate()
        .map(|(index, block): (usize, &BlockId)| (*block, index))
        .collect();
    let mut builder: Builder<'_> = Builder {
        cfg,
        insns,
        switches,
        flow: &flow,
        rank,
        original: BTreeMap::new(),
        canonical: BTreeMap::new(),
        fixups: BTreeMap::new(),
        chains: BTreeMap::new(),
        caught: BTreeMap::new(),
        split_heads: BTreeSet::new(),
        layers: Vec::new(),
        context: BTreeMap::new(),
        heads: BTreeMap::new(),
        handler_entries: BTreeSet::new(),
        duplicated: BTreeSet::new(),
        loops: BTreeMap::new(),
        children: BTreeMap::new(),
        labelled: BTreeSet::new(),
        depth: 0,
    };
    builder.handler_lists(&order)?;
    builder.canonicalize();
    builder.canonical_layers(split_shared_handlers)?;
    builder.assign_contexts(&order, 0)?;
    builder.share_split_handlers()?;
    let canonical_count: usize = builder.layers.len();
    builder.fix_layers()?;
    builder.assign_contexts(&order, canonical_count)?;
    builder.place_loops(loops)?;
    builder.place_blocks(&order)?;
    let root: Region = builder.emit(cfg.entry, 0)?;
    Ok(NestedBlocks {
        root,
        rethrows: builder.chains.keys().copied().collect(),
        duplicated: builder.duplicated,
        caught: builder.caught,
        split_heads: builder.split_heads,
    })
}

fn throwing_flow(cfg: &Cfg, insns: &[DalvikInsn]) -> Option<FlowGraph<BlockId>> {
    FlowGraph::build(
        (0..cfg.blocks.len()).filter_map(|index: usize| u32::try_from(index).ok().map(BlockId)),
        cfg.entry,
        |node: BlockId, emit: &mut dyn FnMut(Flow<BlockId>)| {
            let Some(block): Option<&BasicBlock> = cfg.blocks.get(node.0 as usize) else {
                return;
            };
            let throws: bool = insns
                .get(block.insn_range.0..block.insn_range.1)
                .unwrap_or_default()
                .iter()
                .any(|insn: &DalvikInsn| super::may_throw(insn));
            let mut exits: bool = true;
            for edge in &block.successors {
                if matches!(edge.kind, EdgeKind::Exception) && !throws {
                    continue;
                }
                exits = false;
                emit(Flow::To(edge.target));
            }
            if exits {
                emit(Flow::Exit);
            }
        },
    )
    .ok()
}

struct Builder<'a> {
    cfg: &'a Cfg,
    insns: &'a [DalvikInsn],
    switches: &'a BTreeMap<BlockId, PrecomputedSwitch>,
    flow: &'a FlowGraph<BlockId>,
    rank: BTreeMap<BlockId, usize>,
    original: BTreeMap<BlockId, Vec<HandlerClause>>,
    canonical: BTreeMap<HandlerClause, BlockId>,
    fixups: BTreeMap<BlockId, BlockId>,
    chains: BTreeMap<BlockId, Vec<BlockId>>,
    caught: BTreeMap<BlockId, u16>,
    split_heads: BTreeSet<BlockId>,
    layers: Vec<Layer>,
    context: BTreeMap<BlockId, Context>,
    heads: BTreeMap<BlockId, Vec<usize>>,
    handler_entries: BTreeSet<BlockId>,
    duplicated: BTreeSet<BlockId>,
    loops: BTreeMap<BlockId, (usize, BTreeSet<BlockId>)>,
    children: BTreeMap<(BlockId, Context), Vec<BlockId>>,
    labelled: BTreeSet<BlockId>,
    depth: usize,
}

impl Builder<'_> {
    fn block(&self, id: BlockId) -> Result<&BasicBlock, Defect> {
        self.cfg.blocks.get(id.0 as usize).ok_or(NO_FLOW)
    }

    fn body(&self, block: &BasicBlock) -> &[DalvikInsn] {
        self.insns
            .get(block.insn_range.0..block.insn_range.1)
            .unwrap_or_default()
    }

    fn throws(&self, block: &BasicBlock) -> bool {
        self.body(block)
            .iter()
            .any(|insn: &DalvikInsn| super::may_throw(insn))
    }

    fn normal_successors(block: &BasicBlock) -> Vec<BlockId> {
        let mut targets: Vec<BlockId> = Vec::new();
        for edge in &block.successors {
            if !matches!(edge.kind, EdgeKind::Exception) && !targets.contains(&edge.target) {
                targets.push(edge.target);
            }
        }
        targets
    }

    fn trampoline_end(&self, start: BlockId) -> BlockId {
        let mut current: BlockId = start;
        for _ in 0..MAX_TRAMPOLINE_STEPS {
            let Ok(block) = self.block(current) else {
                return current;
            };
            let only_goto: bool = self
                .body(block)
                .iter()
                .all(|insn: &DalvikInsn| insn.is_unconditional_goto());
            match Self::normal_successors(block).as_slice() {
                [next] if only_goto && *next != current => current = *next,
                _ => return current,
            }
        }
        current
    }

    fn moves_only(&self, block: &BasicBlock, handler: bool) -> bool {
        let body: &[DalvikInsn] = self.body(block);
        let prologue: &[DalvikInsn] = match body.split_first() {
            Some((first, rest)) if handler && first.op == MOVE_EXCEPTION => rest,
            _ => body,
        };
        prologue.iter().all(|insn: &DalvikInsn| {
            matches!(insn.op, 0x01..=0x09 | 0x12..=0x1B) || insn.is_unconditional_goto()
        })
    }

    fn normal_predecessors(&self, target: BlockId) -> Vec<BlockId> {
        let Ok(block) = self.block(target) else {
            return Vec::new();
        };
        block
            .predecessors
            .iter()
            .copied()
            .filter(|pred: &BlockId| {
                self.block(*pred).is_ok_and(|source: &BasicBlock| {
                    source.successors.iter().any(|edge| {
                        edge.target == target && !matches!(edge.kind, EdgeKind::Exception)
                    })
                })
            })
            .collect()
    }

    fn reached_only_from_moves(&self, target: BlockId) -> bool {
        self.normal_predecessors(target)
            .iter()
            .all(|pred: &BlockId| {
                self.block(*pred)
                    .is_ok_and(|source: &BasicBlock| self.moves_only(source, true))
            })
    }

    fn fixup_path(&self, handler: BlockId) -> Option<(Vec<BlockId>, BlockId)> {
        let head: &BasicBlock = self.block(handler).ok()?;
        if !self.moves_only(head, true) || !self.reached_only_from_moves(handler) {
            return None;
        }
        let mut chain: Vec<BlockId> = vec![handler];
        let mut current: &BasicBlock = head;
        for _ in 0..MAX_TRAMPOLINE_STEPS {
            let [next]: [BlockId; 1] = Self::normal_successors(current).try_into().ok()?;
            let next: BlockId = self.trampoline_end(next);
            if chain.contains(&next) || !self.reached_only_from_moves(next) {
                return None;
            }
            let following: &BasicBlock = self.block(next).ok()?;
            let continues: bool = self.moves_only(following, false)
                && Self::normal_successors(following).len() == 1
                && !self.throws(following);
            if !continues {
                return Some((chain, next));
            }
            chain.push(next);
            current = following;
        }
        None
    }

    fn handler_lists(&mut self, order: &[BlockId]) -> Result<(), Defect> {
        for &id in order {
            let block: &BasicBlock = self.block(id)?;
            if !self.throws(block) {
                continue;
            }
            let clauses: Vec<HandlerClause> = handler_clauses(self.cfg, block.start_pc);
            if !clauses.is_empty() {
                self.original.insert(id, clauses);
            }
        }
        Ok(())
    }

    fn canonicalize(&mut self) {
        let mut handler_types: BTreeMap<BlockId, BTreeSet<Option<String>>> = BTreeMap::new();
        for clauses in self.original.values() {
            for (catch_type, handler) in clauses {
                handler_types
                    .entry(*handler)
                    .or_default()
                    .insert(catch_type.clone());
            }
        }
        let mut groups: BTreeMap<HandlerClause, Vec<(BlockId, Vec<BlockId>)>> = BTreeMap::new();
        for (&handler, types) in &handler_types {
            for catch_type in types {
                let path: Option<(Vec<BlockId>, BlockId)> = if types.len() == 1 {
                    self.fixup_path(handler)
                } else {
                    None
                };
                let (chain, terminal): (Vec<BlockId>, BlockId) =
                    path.unwrap_or_else(|| (Vec::new(), handler));
                groups
                    .entry((catch_type.clone(), terminal))
                    .or_default()
                    .push((handler, chain));
            }
        }
        for ((catch_type, terminal), members) in groups {
            let terminal_is_entry: bool = handler_types
                .get(&terminal)
                .is_some_and(|types: &BTreeSet<Option<String>>| types.contains(&catch_type));
            let merges: bool = members.len() > 1
                || (terminal_is_entry
                    && members
                        .iter()
                        .any(|(member, _): &(BlockId, Vec<BlockId>)| *member != terminal));
            if merges && !terminal_is_entry {
                let mut shared: Option<BTreeSet<u16>> = None;
                for (_, chain) in &members {
                    let holding: BTreeSet<u16> = self.exception_registers(chain);
                    shared = Some(match shared {
                        None => holding,
                        Some(known) => known.intersection(&holding).copied().collect(),
                    });
                }
                if let Some(register) =
                    shared.and_then(|known: BTreeSet<u16>| self.read_first(terminal, &known))
                {
                    self.caught.insert(terminal, register);
                }
            }
            for (member, chain) in members {
                let target: BlockId = if merges { terminal } else { member };
                if target != member {
                    for &block in &chain {
                        self.fixups.insert(block, target);
                    }
                    self.chains.insert(member, chain);
                }
                self.canonical.insert((catch_type.clone(), member), target);
            }
        }
    }

    fn exception_registers(&self, chain: &[BlockId]) -> BTreeSet<u16> {
        let mut holding: BTreeSet<u16> = BTreeSet::new();
        for &id in chain {
            let Ok(block) = self.block(id) else {
                return BTreeSet::new();
            };
            for insn in self.body(block) {
                let (Some(&dest), source): (Option<&u16>, Option<&u16>) =
                    (insn.regs.first(), insn.regs.get(1))
                else {
                    continue;
                };
                match insn.op {
                    MOVE_EXCEPTION => {
                        holding = BTreeSet::from([dest]);
                    }
                    0x07..=0x09 if source.is_some_and(|from: &u16| holding.contains(from)) => {
                        holding.insert(dest);
                    }
                    0x01..=0x09 | 0x12..=0x1B => {
                        holding.remove(&dest);
                    }
                    _ => {}
                }
            }
        }
        holding
    }

    fn read_first(&self, block: BlockId, candidates: &BTreeSet<u16>) -> Option<u16> {
        let found: &BasicBlock = self.block(block).ok()?;
        self.body(found)
            .iter()
            .flat_map(|insn: &DalvikInsn| insn.regs.iter().copied())
            .find(|register: &u16| candidates.contains(register))
            .or_else(|| candidates.first().copied())
    }

    fn canonical_of(&self, clause: &HandlerClause) -> BlockId {
        self.canonical.get(clause).copied().unwrap_or(clause.1)
    }

    fn canonical_layers(&mut self, split_shared_handlers: bool) -> Result<(), Defect> {
        let mut covered: BTreeMap<HandlerClause, BTreeSet<BlockId>> = BTreeMap::new();
        for (&id, clauses) in &self.original {
            for clause in clauses {
                covered
                    .entry((clause.0.clone(), self.canonical_of(clause)))
                    .or_default()
                    .insert(id);
            }
        }
        let mut grouped: BTreeMap<BTreeSet<BlockId>, Vec<HandlerClause>> = BTreeMap::new();
        for (clause, blocks) in &covered {
            grouped
                .entry(blocks.clone())
                .or_default()
                .push(clause.clone());
        }
        if grouped.len() > MAX_LAYERS {
            return Err(CROSSING_TRIES);
        }
        let sets: Vec<&BTreeSet<BlockId>> = grouped.keys().collect();
        for (index, first) in sets.iter().enumerate() {
            for second in sets.iter().skip(index + 1) {
                let nested: bool =
                    first.is_subset(second) || second.is_subset(first) || first.is_disjoint(second);
                if !nested {
                    return Err(CROSSING_TRIES);
                }
            }
        }
        let mut layers: Vec<Layer> = Vec::with_capacity(grouped.len());
        for (blocks, mut clauses) in grouped {
            let sample: Vec<HandlerClause> = blocks
                .first()
                .and_then(|id: &BlockId| self.original.get(id))
                .map(|list: &Vec<HandlerClause>| {
                    list.iter()
                        .map(|clause: &HandlerClause| (clause.0.clone(), self.canonical_of(clause)))
                        .collect()
                })
                .ok_or(CROSSING_TRIES)?;
            clauses.sort_by_key(|clause: &HandlerClause| {
                sample
                    .iter()
                    .position(|known: &HandlerClause| known == clause)
            });
            let head: BlockId = self.common_dominator(&blocks)?;
            let pieces: Vec<(BTreeSet<BlockId>, BlockId)> = if split_shared_handlers
                && self.encloses_foreign_handlers(&blocks, head, &clauses, &covered)
                && clauses
                    .iter()
                    .all(|(_, handler): &HandlerClause| self.handler_is_one_block(*handler))
            {
                let mut pieces: Vec<(BTreeSet<BlockId>, BlockId)> = Vec::new();
                for component in self.components(&blocks)? {
                    let piece_head: BlockId = self.common_dominator(&component)?;
                    pieces.push((component, piece_head));
                }
                pieces
            } else {
                vec![(blocks, head)]
            };
            for (piece, piece_head) in pieces {
                layers.push(Layer {
                    clauses: clauses
                        .iter()
                        .map(|(catch_type, handler): &HandlerClause| {
                            (catch_type.clone(), Some(*handler))
                        })
                        .collect(),
                    covered: piece,
                    fix: false,
                    head: piece_head,
                    parent: Context::Root,
                    body: BTreeSet::new(),
                    handlers: Vec::new(),
                });
            }
        }
        self.sort_layers(&mut layers);
        self.layers = layers;
        Ok(())
    }

    fn encloses_foreign_handlers(
        &self,
        blocks: &BTreeSet<BlockId>,
        head: BlockId,
        clauses: &[HandlerClause],
        covered: &BTreeMap<HandlerClause, BTreeSet<BlockId>>,
    ) -> bool {
        let reach: BTreeSet<BlockId> = self.reach_back(blocks, head);
        reach
            .iter()
            .filter(|block: &&BlockId| !blocks.contains(*block))
            .filter_map(|block: &BlockId| self.original.get(block))
            .any(|list: &Vec<HandlerClause>| {
                clauses.iter().any(|(catch_type, _): &HandlerClause| {
                    list.iter()
                        .filter(|(known, _): &&HandlerClause| {
                            known.is_none() || (catch_type.is_some() && known == catch_type)
                        })
                        .any(|clause: &HandlerClause| {
                            let canonical: HandlerClause =
                                (clause.0.clone(), self.canonical_of(clause));
                            covered
                                .get(&canonical)
                                .and_then(|inner: &BTreeSet<BlockId>| {
                                    self.common_dominator(inner).ok()
                                })
                                .is_some_and(|inner_head: BlockId| {
                                    !self.flow.dominates(head, inner_head)
                                })
                        })
                })
            })
    }

    fn handler_is_one_block(&self, handler: BlockId) -> bool {
        self.rank
            .keys()
            .filter(|block: &&BlockId| self.flow.dominates(handler, **block))
            .count()
            == 1
    }

    fn share_split_handlers(&mut self) -> Result<(), Defect> {
        let mut uses: BTreeMap<BlockId, Vec<&BTreeSet<BlockId>>> = BTreeMap::new();
        for layer in &self.layers {
            for (_, entry, region) in &layer.handlers {
                if let Some(entry) = entry {
                    uses.entry(*entry).or_default().push(region);
                }
            }
        }
        let mut shared: BTreeSet<BlockId> = BTreeSet::new();
        for (entry, regions) in uses {
            if regions.len() < 2 {
                continue;
            }
            if regions
                .iter()
                .any(|region: &&BTreeSet<BlockId>| region.len() != 1 || !region.contains(&entry))
            {
                return Err(HANDLER_PLACE);
            }
            shared.insert(entry);
        }
        self.duplicated.extend(shared);
        Ok(())
    }

    fn sort_layers(&self, layers: &mut [Layer]) {
        layers.sort_by_cached_key(|layer: &Layer| {
            (
                self.rank.get(&layer.head).copied().unwrap_or(usize::MAX),
                usize::MAX - self.extent(layer),
                usize::MAX - layer.covered.len(),
            )
        });
    }

    fn extent(&self, layer: &Layer) -> usize {
        self.reach_back(&layer.covered, layer.head).len()
    }

    fn reach_back(&self, covered: &BTreeSet<BlockId>, head: BlockId) -> BTreeSet<BlockId> {
        let mut reached: BTreeSet<BlockId> = BTreeSet::new();
        let mut pending: Vec<BlockId> = covered.iter().copied().collect();
        while let Some(block) = pending.pop() {
            if !reached.insert(block) || block == head {
                continue;
            }
            pending.extend(self.flow.predecessors(block).filter(|pred: &BlockId| {
                self.rank.contains_key(pred) && self.flow.dominates(head, *pred)
            }));
        }
        reached
    }

    fn fix_layers(&mut self) -> Result<(), Defect> {
        let mut groups: BTreeMap<(Vec<HandlerClause>, Context), BTreeSet<BlockId>> =
            BTreeMap::new();
        for (&id, clauses) in &self.original {
            if clauses
                .iter()
                .all(|clause: &HandlerClause| self.canonical_of(clause) == clause.1)
            {
                continue;
            }
            groups
                .entry((clauses.clone(), self.context_of(id)))
                .or_default()
                .insert(id);
        }
        let mut layers: Vec<Layer> = Vec::new();
        let mut uses: BTreeMap<BlockId, usize> = BTreeMap::new();
        for ((clauses, _), blocks) in groups {
            let mut pieces: Vec<(BTreeSet<BlockId>, BlockId)> = Vec::new();
            for component in self.components(&blocks)? {
                let head: BlockId = self.common_dominator(&component)?;
                let clean: bool = self
                    .reach_back(&component, head)
                    .iter()
                    .filter(|block: &&BlockId| !component.contains(*block))
                    .all(|block: &BlockId| {
                        self.block(*block)
                            .is_ok_and(|found: &BasicBlock| !self.throws(found))
                    });
                if clean && component.contains(&head) {
                    pieces.push((component, head));
                } else {
                    pieces.extend(
                        component
                            .into_iter()
                            .map(|block: BlockId| (BTreeSet::from([block]), block)),
                    );
                }
            }
            for (component, head) in pieces {
                let mut fix_clauses: Vec<LayerClause> = clauses
                    .iter()
                    .map(|clause: &HandlerClause| {
                        let rethrown: Option<BlockId> =
                            (self.canonical_of(clause) != clause.1).then_some(clause.1);
                        for block in rethrown
                            .and_then(|fixup: BlockId| self.chains.get(&fixup))
                            .into_iter()
                            .flatten()
                        {
                            *uses.entry(*block).or_default() += 1;
                        }
                        (clause.0.clone(), rethrown)
                    })
                    .collect();
                while fix_clauses
                    .last()
                    .is_some_and(|(_, rethrown): &LayerClause| rethrown.is_none())
                {
                    fix_clauses.pop();
                }
                layers.push(Layer {
                    clauses: fix_clauses,
                    covered: component,
                    fix: true,
                    head,
                    parent: Context::Root,
                    body: BTreeSet::new(),
                    handlers: Vec::new(),
                });
            }
        }
        if self.layers.len() + layers.len() > MAX_LAYERS {
            return Err(CROSSING_TRIES);
        }
        self.duplicated.extend(
            uses.into_iter()
                .filter(|(_, count): &(BlockId, usize)| *count > 1)
                .map(|(block, _): (BlockId, usize)| block),
        );
        self.sort_layers(&mut layers);
        self.layers.extend(layers);
        Ok(())
    }

    fn components(&self, blocks: &BTreeSet<BlockId>) -> Result<Vec<BTreeSet<BlockId>>, Defect> {
        let mut remaining: BTreeSet<BlockId> = blocks.clone();
        let mut components: Vec<BTreeSet<BlockId>> = Vec::new();
        while let Some(start) = remaining.pop_first() {
            let mut component: BTreeSet<BlockId> = BTreeSet::from([start]);
            let mut pending: Vec<BlockId> = vec![start];
            while let Some(block) = pending.pop() {
                let found: &BasicBlock = self.block(block)?;
                let neighbours: Vec<BlockId> = Self::normal_successors(found)
                    .into_iter()
                    .chain(found.predecessors.iter().copied())
                    .collect();
                for neighbour in neighbours {
                    if remaining.remove(&neighbour) {
                        component.insert(neighbour);
                        pending.push(neighbour);
                    }
                }
            }
            components.push(component);
        }
        Ok(components)
    }

    fn common_dominator(&self, blocks: &BTreeSet<BlockId>) -> Result<BlockId, Defect> {
        let mut common: Option<BlockId> = None;
        for &block in blocks {
            common = Some(match common {
                None => block,
                Some(current) => {
                    let mut candidate: BlockId = current;
                    let mut steps: usize = 0;
                    while !self.flow.dominates(candidate, block) {
                        candidate = self.flow.immediate_dominator(candidate).ok_or(NO_FLOW)?;
                        steps += 1;
                        if steps > self.cfg.blocks.len() {
                            return Err(NO_FLOW);
                        }
                    }
                    candidate
                }
            });
        }
        common.ok_or(NO_FLOW)
    }

    fn region_of(&self, context: Context) -> Option<&BTreeSet<BlockId>> {
        match context {
            Context::Root => None,
            Context::Body(layer) => self.layers.get(layer).map(|found: &Layer| &found.body),
            Context::Handler(layer, clause) => self
                .layers
                .get(layer)
                .and_then(|found: &Layer| found.handlers.get(clause))
                .map(|(_, _, blocks): &LayerHandler| blocks),
        }
    }

    fn within(&self, block: BlockId, context: Context) -> bool {
        self.region_of(context)
            .is_none_or(|blocks: &BTreeSet<BlockId>| blocks.contains(&block))
    }

    fn context_of(&self, block: BlockId) -> Context {
        self.context.get(&block).copied().unwrap_or(Context::Root)
    }

    fn assign_contexts(&mut self, order: &[BlockId], from: usize) -> Result<(), Defect> {
        for index in from..self.layers.len() {
            let head: BlockId = self.layers[index].head;
            let parent: Context = self.context_of(head);
            if self.layers[index]
                .covered
                .iter()
                .any(|block: &BlockId| !self.within(*block, parent))
            {
                return Err(CROSSING_TRIES);
            }
            let body: BTreeSet<BlockId> = self.try_body(index, parent)?;
            let head_block: &BasicBlock = self.block(head)?;
            if self.throws(head_block)
                && !self.layers[index].covered.contains(&head)
                && !self.shadows(head, &self.layers[index])
            {
                self.split_heads.insert(head);
            }
            let fix: bool = self.layers[index].fix;
            let mut handlers: Vec<LayerHandler> = Vec::new();
            for (catch_type, handler) in &self.layers[index].clauses {
                let types: Vec<String> = catch_type.iter().cloned().collect();
                let Some(entry) = handler else {
                    handlers.push((types, None, BTreeSet::new()));
                    continue;
                };
                if (!fix && !self.within(*entry, parent)) || body.contains(entry) {
                    return Err(HANDLER_PLACE);
                }
                if let Some(existing) = handlers
                    .iter_mut()
                    .find(|(_, known, _): &&mut LayerHandler| *known == Some(*entry))
                {
                    existing.0.extend(types);
                    continue;
                }
                let region: BTreeSet<BlockId> = if fix {
                    self.chains
                        .get(entry)
                        .map(|chain: &Vec<BlockId>| chain.iter().copied().collect())
                        .unwrap_or_default()
                } else {
                    order
                        .iter()
                        .copied()
                        .filter(|block: &BlockId| {
                            self.flow.dominates(*entry, *block) && self.within(*block, parent)
                        })
                        .collect()
                };
                handlers.push((types, Some(*entry), region));
            }
            for (_, entry, region) in &handlers {
                if region.iter().any(|block: &BlockId| body.contains(block)) {
                    return Err(HANDLER_PLACE);
                }
                if let Some(entry) = entry {
                    self.handler_entries.insert(*entry);
                }
            }
            for &block in &body {
                self.context.insert(block, Context::Body(index));
            }
            if !fix {
                for (clause, (_, _, region)) in handlers.iter().enumerate() {
                    for &block in region {
                        self.context.insert(block, Context::Handler(index, clause));
                    }
                }
            }
            self.heads.entry(head).or_default().push(index);
            let layer: &mut Layer = &mut self.layers[index];
            layer.parent = parent;
            layer.body = body;
            layer.handlers = handlers;
        }
        Ok(())
    }

    fn try_body(&self, index: usize, parent: Context) -> Result<BTreeSet<BlockId>, Defect> {
        let layer: &Layer = &self.layers[index];
        let mut body: BTreeSet<BlockId> = BTreeSet::new();
        let mut pending: Vec<BlockId> = layer.covered.iter().copied().collect();
        pending.push(layer.head);
        while let Some(block) = pending.pop() {
            if !body.insert(block) || block == layer.head {
                continue;
            }
            let preds: Vec<BlockId> = self.flow.predecessors(block).collect();
            for pred in preds {
                if body.contains(&pred) || !self.rank.contains_key(&pred) {
                    continue;
                }
                if !self.flow.dominates(layer.head, pred) || !self.within(pred, parent) {
                    return Err(TRY_ENTRY);
                }
                pending.push(pred);
            }
        }
        for &block in &body {
            let found: &BasicBlock = self.block(block)?;
            let split_head: bool = block == layer.head && self.splits_cleanly(found);
            if self.throws(found)
                && !layer.covered.contains(&block)
                && (layer.fix || !self.shadows(block, layer))
                && !split_head
            {
                return Err(MIXED_BODY);
            }
        }
        Ok(body)
    }

    fn splits_cleanly(&self, block: &BasicBlock) -> bool {
        let body: &[DalvikInsn] = self.body(block);
        let Some((branch, before)) = body.split_last() else {
            return false;
        };
        if !branch.is_conditional_branch() && !branch.is_switch() {
            return false;
        }
        branch.regs.iter().all(|operand: &u16| {
            before
                .iter()
                .rev()
                .find(|insn: &&DalvikInsn| super::instruction_writes_register(insn, *operand))
                .is_none_or(|definer: &DalvikInsn| {
                    !super::may_throw(definer) && !matches!(definer.op, 0x0A..=0x0C)
                })
        })
    }

    fn shadows(&self, block: BlockId, layer: &Layer) -> bool {
        let Some(list) = self.original.get(&block) else {
            return false;
        };
        layer.clauses.iter().all(|(catch_type, _): &LayerClause| {
            list.iter().any(|(known, _): &HandlerClause| {
                known.is_none() || (catch_type.is_some() && known == catch_type)
            })
        })
    }

    fn slots(&self, block: BlockId) -> Vec<Context> {
        let mut slots: Vec<Context> = Vec::new();
        if let Some(layers) = self.heads.get(&block) {
            for &layer in layers {
                slots.push(self.layers[layer].parent);
            }
        }
        slots.push(self.context_of(block));
        slots
    }

    fn outer_slot(&self, block: BlockId) -> Context {
        self.slots(block).first().copied().unwrap_or(Context::Root)
    }

    fn place_loops(&mut self, loops: &[NaturalLoop]) -> Result<(), Defect> {
        for found in loops {
            if !self.rank.contains_key(&found.header) {
                continue;
            }
            let slots: Vec<Context> = self.slots(found.header);
            let level: Option<usize> = (0..slots.len()).rev().find(|&level: &usize| {
                found
                    .latches
                    .iter()
                    .all(|latch: &BlockId| self.within(*latch, slots[level]))
            });
            let Some(level) = level else {
                return Err(LOOP_ACROSS_TRY);
            };
            for &member in &found.body {
                let placed_by_try: bool = self.handler_entries.contains(&member)
                    || matches!(self.context_of(member), Context::Handler(..))
                    || !self.rank.contains_key(&member);
                if !placed_by_try && !self.within(member, slots[level]) {
                    return Err(LOOP_ACROSS_TRY);
                }
            }
            self.loops.insert(found.header, (level, found.body.clone()));
        }
        Ok(())
    }

    fn forward_edges(&self, target: BlockId) -> Result<Vec<BlockId>, Defect> {
        let mut sources: Vec<BlockId> = Vec::new();
        for &pred in &self.block(target)?.predecessors {
            if !self.rank.contains_key(&pred)
                || self.flow.dominates(target, pred)
                || self.fixups.contains_key(&pred)
            {
                continue;
            }
            let kinds: Vec<EdgeKind> = self
                .block(pred)?
                .successors
                .iter()
                .filter(|edge| edge.target == target && !matches!(edge.kind, EdgeKind::Exception))
                .map(|edge| edge.kind)
                .collect();
            let switched: bool = kinds
                .iter()
                .any(|kind: &EdgeKind| matches!(kind, EdgeKind::Switch | EdgeKind::SwitchDefault));
            let count: usize = if switched { 1 } else { kinds.len() };
            sources.extend(std::iter::repeat_n(pred, count));
        }
        Ok(sources)
    }

    fn place_blocks(&mut self, order: &[BlockId]) -> Result<(), Defect> {
        for &block in order {
            if block == self.cfg.entry || self.handler_entries.contains(&block) {
                continue;
            }
            let sources: Vec<BlockId> = self.forward_edges(block)?;
            if sources.is_empty() {
                continue;
            }
            let slot: Context = self.outer_slot(block);
            let mut parent: Option<BlockId> = self.flow.immediate_dominator(block);
            let mut steps: usize = 0;
            let placed: (BlockId, Context) = loop {
                let Some(candidate) = parent else {
                    return Err(NO_PLACE);
                };
                if self.slots(candidate).contains(&slot) {
                    break (candidate, slot);
                }
                parent = self.flow.immediate_dominator(candidate);
                steps += 1;
                if steps > self.cfg.blocks.len() {
                    return Err(NO_PLACE);
                }
            };
            let exits_loop: bool =
                self.loops
                    .values()
                    .any(|(_, members): &(usize, BTreeSet<BlockId>)| {
                        !members.contains(&block)
                            && sources
                                .iter()
                                .any(|source: &BlockId| members.contains(source))
                    });
            let inline: bool = match sources.as_slice() {
                [only] => !exits_loop && placed == (*only, self.context_of(*only)),
                _ => false,
            };
            if !inline {
                self.labelled.insert(block);
                self.children.entry(placed).or_default().push(block);
            }
        }
        let rank: &BTreeMap<BlockId, usize> = &self.rank;
        for children in self.children.values_mut() {
            children.sort_by_key(|child: &BlockId| rank.get(child).copied().unwrap_or(usize::MAX));
        }
        Ok(())
    }

    const fn block_label(block: BlockId) -> u32 {
        block.0.saturating_mul(2)
    }

    const fn loop_label(block: BlockId) -> u32 {
        block.0.saturating_mul(2).saturating_add(1)
    }

    fn emit(&mut self, block: BlockId, level: usize) -> Result<Region, Defect> {
        self.depth += 1;
        if self.depth > MAX_NEST_DEPTH {
            return Err(TOO_DEEP);
        }
        let result: Result<Region, Defect> = self.emit_level(block, level);
        self.depth -= 1;
        result
    }

    fn emit_level(&mut self, block: BlockId, level: usize) -> Result<Region, Defect> {
        let slots: Vec<Context> = self.slots(block);
        let innermost: usize = slots.len().saturating_sub(1);
        let core: Region = if level >= innermost {
            self.code(block)?
        } else {
            let layer: usize = self
                .heads
                .get(&block)
                .and_then(|layers: &Vec<usize>| layers.get(level))
                .copied()
                .ok_or(NO_PLACE)?;
            self.try_statement(layer, block, level)?
        };
        let slot: Context = slots.get(level).copied().unwrap_or(Context::Root);
        let children: Vec<BlockId> = self
            .children
            .get(&(block, slot))
            .cloned()
            .unwrap_or_default();
        match self.loops.get(&block).cloned() {
            Some((loop_level, members)) if loop_level == level => {
                let (inside, outside): (Vec<BlockId>, Vec<BlockId>) = children
                    .into_iter()
                    .partition(|child: &BlockId| members.contains(child));
                let body: Region = self.wrap(core, &inside)?;
                let looped: Region = Region::LabeledLoop {
                    label: Self::loop_label(block),
                    body: Box::new(Region::DoWhile {
                        header: block,
                        body: Box::new(body),
                        exit: None,
                    }),
                };
                self.wrap(looped, &outside)
            }
            _ => self.wrap(core, &children),
        }
    }

    fn wrap(&mut self, core: Region, children: &[BlockId]) -> Result<Region, Defect> {
        let mut region: Region = core;
        for &child in children {
            let placed: Region = self.emit(child, 0)?;
            region = Region::Sequence(vec![
                Region::LabeledLoop {
                    label: Self::block_label(child),
                    body: Box::new(region),
                },
                placed,
            ]);
        }
        Ok(region)
    }

    fn try_statement(
        &mut self,
        layer: usize,
        head: BlockId,
        level: usize,
    ) -> Result<Region, Defect> {
        let try_body: Region = self.emit(head, level + 1)?;
        let fix: bool = self.layers[layer].fix;
        let handlers: Vec<(Vec<String>, Option<BlockId>)> = self.layers[layer]
            .handlers
            .iter()
            .map(|(types, entry, _): &LayerHandler| (types.clone(), *entry))
            .collect();
        let mut clauses: Vec<(Vec<String>, Region)> = Vec::with_capacity(handlers.len());
        for (types, entry) in handlers {
            let region: Region = match entry {
                None => Region::Sequence(Vec::new()),
                Some(entry) if fix => match self.chains.get(&entry).map(Vec::as_slice) {
                    Some([only]) => Region::Block(*only),
                    Some(chain) => {
                        Region::Sequence(chain.iter().copied().map(Region::Block).collect())
                    }
                    None => return Err(HANDLER_PLACE),
                },
                Some(entry) => self.emit(entry, 0)?,
            };
            clauses.push((types, region));
        }
        Ok(Region::Try {
            try_body: Box::new(try_body),
            handlers: clauses,
        })
    }

    fn code(&mut self, block: BlockId) -> Result<Region, Defect> {
        let found: &BasicBlock = self.block(block)?;
        let last: Option<&DalvikInsn> = self.body(found).last();
        if last.is_some_and(|insn: &DalvikInsn| insn.is_return() || insn.is_throw()) {
            return Ok(Region::Block(block));
        }
        if last.is_some_and(DalvikInsn::is_conditional_branch) {
            let mut taken: Option<BlockId> = None;
            let mut fallthrough: Option<BlockId> = None;
            for edge in &found.successors {
                match edge.kind {
                    EdgeKind::CondTrue => taken = Some(edge.target),
                    EdgeKind::CondFalse => fallthrough = Some(edge.target),
                    _ => {}
                }
            }
            let (Some(taken), Some(fallthrough)) = (taken, fallthrough) else {
                return Err(NO_FLOW);
            };
            let then_body: Region = self.branch(block, fallthrough)?;
            let else_body: Region = self.branch(block, taken)?;
            return Ok(Region::IfThenElse {
                head: block,
                cond_negated: false,
                then_body: Box::new(then_body),
                else_body: Box::new(else_body),
                join: None,
            });
        }
        if last.is_some_and(DalvikInsn::is_switch) {
            let table: PrecomputedSwitch =
                self.switches.get(&block).cloned().ok_or(NOT_A_SWITCH)?;
            let default_target: BlockId = table.default.ok_or(NOT_A_SWITCH)?;
            let mut cases: Vec<(SwitchKey, Region)> = Vec::with_capacity(table.cases.len());
            for (key, target) in table.cases {
                if target == default_target {
                    continue;
                }
                cases.push((key, self.branch(block, target)?));
            }
            let default: Region = self.branch(block, default_target)?;
            let default_position: usize = cases.len();
            return Ok(Region::Switch {
                head: block,
                cases,
                default: Some(Box::new(default)),
                join: None,
                fallthrough: BTreeSet::new(),
                default_position,
            });
        }
        match Self::normal_successors(found).as_slice() {
            [] => Ok(Region::Block(block)),
            [next] => {
                let next: BlockId = *next;
                let jump: Region = self.branch(block, next)?;
                Ok(Region::Sequence(vec![Region::Block(block), jump]))
            }
            _ => Err(NO_FLOW),
        }
    }

    fn branch(&mut self, source: BlockId, target: BlockId) -> Result<Region, Defect> {
        if self.flow.dominates(target, source) {
            return Ok(Region::Continue {
                label: Some(Self::loop_label(target)),
                latch: None,
            });
        }
        if self.labelled.contains(&target) {
            return Ok(Region::Break {
                label: Some(Self::block_label(target)),
            });
        }
        self.emit(target, 0)
    }
}
