use crate::fingerprint::ControlFlowFingerprint;

pub const INSTRUCTION_CATEGORY_COUNT: usize = 15;

pub const MINIMUM_DISTINGUISHING_BLOCKS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstructionCategory {
    Arithmetic,
    Logic,
    Shift,
    Move,
    Compare,
    Load,
    Store,
    Branch,
    Call,
    Return,
    Stack,
    FloatingPoint,
    Vector,
    System,
    Other,
}

impl InstructionCategory {
    pub const ALL: [Self; INSTRUCTION_CATEGORY_COUNT] = [
        Self::Arithmetic,
        Self::Logic,
        Self::Shift,
        Self::Move,
        Self::Compare,
        Self::Load,
        Self::Store,
        Self::Branch,
        Self::Call,
        Self::Return,
        Self::Stack,
        Self::FloatingPoint,
        Self::Vector,
        Self::System,
        Self::Other,
    ];

    #[must_use]
    pub const fn position(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct InstructionMix([u32; INSTRUCTION_CATEGORY_COUNT]);

impl InstructionMix {
    #[must_use]
    pub fn tally(categories: impl IntoIterator<Item = InstructionCategory>) -> Self {
        let mut counts: [u32; INSTRUCTION_CATEGORY_COUNT] = [0; INSTRUCTION_CATEGORY_COUNT];
        for category in categories {
            if let Some(slot) = counts.get_mut(category.position()) {
                *slot = slot.saturating_add(1);
            }
        }
        Self(counts)
    }

    #[must_use]
    pub fn count(&self, category: InstructionCategory) -> u32 {
        self.0.get(category.position()).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.0.iter().copied().map(u64::from).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|count: &u32| *count == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    successors: Vec<usize>,
    categories: Vec<InstructionCategory>,
}

impl BasicBlock {
    pub fn new(
        successors: impl IntoIterator<Item = usize>,
        categories: impl IntoIterator<Item = InstructionCategory>,
    ) -> Self {
        Self {
            successors: successors.into_iter().collect(),
            categories: categories.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn successors(&self) -> &[usize] {
        &self.successors
    }

    #[must_use]
    pub fn categories(&self) -> &[InstructionCategory] {
        &self.categories
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowGraph {
    entry: usize,
    blocks: Vec<BasicBlock>,
}

impl ControlFlowGraph {
    #[must_use]
    pub fn new(entry: usize, blocks: impl IntoIterator<Item = BasicBlock>) -> Option<Self> {
        let blocks: Vec<BasicBlock> = blocks.into_iter().collect();
        let order: usize = blocks.len();
        if entry >= order {
            return None;
        }
        let reachable_targets: bool = blocks.iter().all(|block: &BasicBlock| {
            block
                .successors
                .iter()
                .all(|target: &usize| *target < order)
        });
        reachable_targets.then_some(Self { entry, blocks })
    }

    #[must_use]
    pub const fn entry(&self) -> usize {
        self.entry
    }

    #[must_use]
    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|block: &BasicBlock| block.successors.len())
            .sum()
    }

    #[must_use]
    pub fn fingerprint(&self) -> ControlFlowFingerprint {
        ControlFlowFingerprint::of(self)
    }

    #[must_use]
    pub fn instruction_mix(&self) -> InstructionMix {
        InstructionMix::tally(
            self.blocks
                .iter()
                .flat_map(|block: &BasicBlock| block.categories.iter().copied()),
        )
    }

    #[must_use]
    pub fn structural_key(&self) -> Option<StructuralKey> {
        if self.block_count() < MINIMUM_DISTINGUISHING_BLOCKS {
            return None;
        }
        let instruction_mix: InstructionMix = self.instruction_mix();
        if instruction_mix.is_empty() {
            return None;
        }
        Some(StructuralKey {
            fingerprint: self.fingerprint(),
            instruction_mix,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructuralKey {
    pub fingerprint: ControlFlowFingerprint,
    pub instruction_mix: InstructionMix,
}
