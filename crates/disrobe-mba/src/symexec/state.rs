use std::collections::BTreeMap;

use oxiz::TermId;

use super::memory::Memory;
use super::value::Sym;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) block: u64,
    pub(crate) env: BTreeMap<String, Sym>,
    pub(crate) memory: Memory,
    pub(crate) path: Vec<TermId>,
    pub(crate) loop_counts: BTreeMap<u64, u32>,
}

impl State {
    pub(crate) const fn entry(block: u64, memory_ceiling: usize) -> Self {
        Self {
            block,
            env: BTreeMap::new(),
            memory: Memory::with_ceiling(memory_ceiling),
            path: Vec::new(),
            loop_counts: BTreeMap::new(),
        }
    }

    pub(crate) fn fork(&self, block: u64) -> Self {
        Self {
            block,
            env: self.env.clone(),
            memory: self.memory.clone(),
            path: self.path.clone(),
            loop_counts: self.loop_counts.clone(),
        }
    }

    pub(crate) fn clobber_registers(&mut self) {
        self.env.clear();
    }
}
