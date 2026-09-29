use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Edge, EdgeKind, PrecomputedSwitch, SwitchKey,
};
use crate::dex::{DexFile, MethodId};

const STRING_DESCRIPTOR: &str = "Ljava/lang/String;";
const MAX_BUCKET_TESTS: usize = 256;
const MAX_TRAMPOLINE_HOPS: usize = 4;

#[derive(Debug, Clone)]
pub(crate) struct DalvikStringSwitch {
    pub(crate) index_head: BlockId,
    pub(crate) subject_register: u16,
    pub(crate) subject_block: BlockId,
    pub(crate) literals: BTreeMap<i32, String>,
    pub(crate) absorbed: BTreeSet<BlockId>,
}

struct BucketTest {
    literal: String,
    matched: BlockId,
    missed: BlockId,
}

struct Idiom<'a> {
    cfg: &'a Cfg,
    insns: &'a [DalvikInsn],
    dex: &'a DexFile,
    subject: u16,
    index_register: Option<u16>,
    index_head: Option<BlockId>,
    absorbed: BTreeSet<BlockId>,
    literals: BTreeMap<i32, String>,
}

pub(crate) fn detect_string_switches(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    switch_map: &BTreeMap<BlockId, PrecomputedSwitch>,
    dex: &DexFile,
) -> BTreeMap<BlockId, DalvikStringSwitch> {
    switch_map
        .iter()
        .filter_map(|(&head, switch): (&BlockId, &PrecomputedSwitch)| {
            string_switch_at(cfg, insns, dex, switch_map, head, switch).map(|found| (head, found))
        })
        .collect()
}

fn string_switch_at(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    dex: &DexFile,
    switch_map: &BTreeMap<BlockId, PrecomputedSwitch>,
    head: BlockId,
    switch: &PrecomputedSwitch,
) -> Option<DalvikStringSwitch> {
    let block: &BasicBlock = cfg.blocks.get(head.0 as usize)?;
    let body: &[DalvikInsn] = insns.get(block.insn_range.0..block.insn_range.1)?;
    let (terminator, before): (&DalvikInsn, &[DalvikInsn]) = body.split_last()?;
    let hashed: u16 = *terminator.regs.first()?;
    let hash_def: usize = before.iter().rposition(|insn: &DalvikInsn| {
        crate::dalvik_decompile::instruction_writes_register(insn, hashed)
    })?;
    let result: &DalvikInsn = before.get(hash_def)?;
    let call: &DalvikInsn = before.get(hash_def.checked_sub(1)?)?;
    if result.op != 0x0A || !is_string_method(dex, call, "hashCode", &[], "I") {
        return None;
    }
    let subject: u16 = *call.regs.first()?;
    let mut idiom: Idiom<'_> = Idiom {
        cfg,
        insns,
        dex,
        subject,
        index_register: None,
        index_head: None,
        absorbed: BTreeSet::new(),
        literals: BTreeMap::new(),
    };
    let mut subject_block: Option<BlockId> = None;
    for (_, target) in &switch.cases {
        subject_block.get_or_insert(*target);
        idiom.bucket_chain(*target)?;
    }
    let default: BlockId = switch.default?;
    idiom.miss_landing(default)?;
    let index_head: BlockId = idiom.index_head?;
    let index_register: u16 = idiom.index_register?;
    let index_block: &BasicBlock = cfg.blocks.get(index_head.0 as usize)?;
    let index_switch: &DalvikInsn =
        match insns.get(index_block.insn_range.0..index_block.insn_range.1)? {
            [only] if only.is_switch() => only,
            _ => return None,
        };
    if index_switch.regs.first() != Some(&index_register) || idiom.literals.is_empty() {
        return None;
    }
    let index_cases: &PrecomputedSwitch = switch_map.get(&index_head)?;
    let labelled: bool = index_cases
        .cases
        .iter()
        .all(|(key, _): &(SwitchKey, BlockId)| string_case_labels(key, &idiom.literals).is_some());
    if !labelled {
        return None;
    }
    let admitted: BTreeSet<BlockId> = idiom.absorbed.iter().copied().chain([head]).collect();
    let closed: bool = idiom
        .absorbed
        .iter()
        .chain([&index_head])
        .all(|block: &BlockId| {
            normal_predecessors(cfg, *block).all(|pred: BlockId| admitted.contains(&pred))
        });
    if !closed {
        return None;
    }
    Some(DalvikStringSwitch {
        index_head,
        subject_register: subject,
        subject_block: subject_block?,
        literals: idiom.literals,
        absorbed: idiom.absorbed,
    })
}

impl Idiom<'_> {
    fn bucket_chain(&mut self, start: BlockId) -> Option<()> {
        let mut current: BlockId = start;
        for _ in 0..MAX_BUCKET_TESTS {
            if !self.absorbed.insert(current) {
                return None;
            }
            let test: BucketTest = self.bucket_test(current)?;
            let index: i32 = self.match_landing(test.matched)?;
            if self.literals.insert(index, test.literal).is_some() {
                return None;
            }
            let missed: BlockId = self.skip_trampolines(test.missed);
            if self.bucket_test(missed).is_some() {
                let _: BlockId = self.absorb_trampolines(test.missed);
                current = missed;
                continue;
            }
            return self.miss_landing(test.missed);
        }
        None
    }

    fn bucket_test(&self, block: BlockId) -> Option<BucketTest> {
        let found: &BasicBlock = self.cfg.blocks.get(block.0 as usize)?;
        let [constant, call, result, branch]: &[DalvikInsn; 4] = self
            .insns
            .get(found.insn_range.0..found.insn_range.1)?
            .try_into()
            .ok()?;
        if !matches!(constant.op, 0x1A | 0x1B)
            || !is_string_method(self.dex, call, "equals", &["Ljava/lang/Object;"], "Z")
            || call.regs.as_slice() != [self.subject, *constant.regs.first()?]
            || result.op != 0x0A
            || branch.regs.first() != result.regs.first()
        {
            return None;
        }
        let literal: String = self.dex.strings.get(constant.index? as usize)?.clone();
        let (taken, fallthrough): (BlockId, BlockId) = branch_targets(found)?;
        match branch.op {
            0x38 => Some(BucketTest {
                literal,
                matched: fallthrough,
                missed: taken,
            }),
            0x39 => Some(BucketTest {
                literal,
                matched: taken,
                missed: fallthrough,
            }),
            _ => None,
        }
    }

    fn match_landing(&mut self, block: BlockId) -> Option<i32> {
        let found: &BasicBlock = self.cfg.blocks.get(block.0 as usize)?;
        let body: &[DalvikInsn] = self.insns.get(found.insn_range.0..found.insn_range.1)?;
        let (constant, rest): (&DalvikInsn, &[DalvikInsn]) = body.split_first()?;
        if !matches!(constant.op, 0x12..=0x14)
            || !rest.iter().all(DalvikInsn::is_unconditional_goto)
        {
            return None;
        }
        let register: u16 = *constant.regs.first()?;
        let index: i32 = i32::try_from(constant.literal?).ok()?;
        self.claim_index_register(register)?;
        self.absorbed.insert(block);
        let next: BlockId = single_normal_successor(found)?;
        let landing: BlockId = self.absorb_trampolines(next);
        self.claim_index_head(landing)?;
        Some(index)
    }

    fn miss_landing(&mut self, block: BlockId) -> Option<()> {
        let landing: BlockId = self.absorb_trampolines(block);
        if self.index_head == Some(landing) {
            return Some(());
        }
        let found: &BasicBlock = self.cfg.blocks.get(landing.0 as usize)?;
        let body: &[DalvikInsn] = self.insns.get(found.insn_range.0..found.insn_range.1)?;
        match body {
            [only] if only.is_switch() => self.claim_index_head(landing),
            [constant, rest @ ..]
                if matches!(constant.op, 0x12..=0x14)
                    && constant.literal == Some(-1)
                    && rest.iter().all(DalvikInsn::is_unconditional_goto) =>
            {
                self.claim_index_register(*constant.regs.first()?)?;
                self.absorbed.insert(landing);
                let next: BlockId = single_normal_successor(found)?;
                let index_head: BlockId = self.absorb_trampolines(next);
                self.claim_index_head(index_head)
            }
            _ => None,
        }
    }

    const fn claim_index_register(&mut self, register: u16) -> Option<()> {
        match self.index_register {
            Some(previous) if previous != register => None,
            _ => {
                self.index_register = Some(register);
                Some(())
            }
        }
    }

    fn claim_index_head(&mut self, block: BlockId) -> Option<()> {
        match self.index_head {
            Some(previous) if previous != block => None,
            _ => {
                self.index_head = Some(block);
                Some(())
            }
        }
    }

    fn skip_trampolines(&self, start: BlockId) -> BlockId {
        let mut current: BlockId = start;
        for _ in 0..MAX_TRAMPOLINE_HOPS {
            match self.trampoline_target(current) {
                Some(next) => current = next,
                None => return current,
            }
        }
        current
    }

    fn absorb_trampolines(&mut self, start: BlockId) -> BlockId {
        let mut current: BlockId = start;
        for _ in 0..MAX_TRAMPOLINE_HOPS {
            match self.trampoline_target(current) {
                Some(next) => {
                    self.absorbed.insert(current);
                    current = next;
                }
                None => return current,
            }
        }
        current
    }

    fn trampoline_target(&self, block: BlockId) -> Option<BlockId> {
        let found: &BasicBlock = self.cfg.blocks.get(block.0 as usize)?;
        match self.insns.get(found.insn_range.0..found.insn_range.1)? {
            [only] if only.is_unconditional_goto() => single_normal_successor(found),
            _ => None,
        }
    }
}

fn is_string_method(
    dex: &DexFile,
    call: &DalvikInsn,
    name: &str,
    parameters: &[&str],
    returns: &str,
) -> bool {
    matches!(call.op, 0x6E | 0x74)
        && call
            .index
            .and_then(|index: u32| dex.method_ids.get(index as usize))
            .is_some_and(|method: &MethodId| {
                method.class == STRING_DESCRIPTOR
                    && method.name == name
                    && method.proto.return_type == returns
                    && method.proto.parameters == parameters
            })
}

fn branch_targets(block: &BasicBlock) -> Option<(BlockId, BlockId)> {
    let taken: BlockId = block
        .successors
        .iter()
        .find(|edge: &&Edge| matches!(edge.kind, EdgeKind::CondTrue))?
        .target;
    let fallthrough: BlockId = block
        .successors
        .iter()
        .find(|edge: &&Edge| matches!(edge.kind, EdgeKind::CondFalse))?
        .target;
    Some((taken, fallthrough))
}

fn single_normal_successor(block: &BasicBlock) -> Option<BlockId> {
    let normal: Vec<BlockId> = block
        .successors
        .iter()
        .filter(|edge: &&Edge| !matches!(edge.kind, EdgeKind::Exception))
        .map(|edge: &Edge| edge.target)
        .collect();
    match normal.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn normal_predecessors(cfg: &Cfg, block: BlockId) -> impl Iterator<Item = BlockId> + '_ {
    cfg.blocks
        .get(block.0 as usize)
        .into_iter()
        .flat_map(|found: &BasicBlock| found.predecessors.iter().copied())
        .filter(move |pred: &BlockId| {
            cfg.blocks
                .get(pred.0 as usize)
                .is_some_and(|source: &BasicBlock| {
                    source.successors.iter().any(|edge: &Edge| {
                        edge.target == block && !matches!(edge.kind, EdgeKind::Exception)
                    })
                })
        })
}

pub(crate) fn string_case_labels(
    key: &SwitchKey,
    literals: &BTreeMap<i32, String>,
) -> Option<Vec<String>> {
    let values: Vec<i32> = match key {
        SwitchKey::Range { low, high } => (*low..=*high).collect(),
        SwitchKey::Values(values) => values.clone(),
    };
    values
        .iter()
        .map(|value: &i32| {
            literals
                .get(value)
                .map(|literal: &String| crate::bytecode::escape_java_string(literal))
        })
        .collect()
}
