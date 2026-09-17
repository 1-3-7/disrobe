use std::collections::BTreeMap;

use super::solver::SymSolver;
use super::value::{BitWidth, Sym};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    value: Sym,
    bytes: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Memory {
    cells: BTreeMap<u64, Cell>,
    ceiling: usize,
}

impl Memory {
    pub(crate) const fn with_ceiling(ceiling: usize) -> Self {
        Self {
            cells: BTreeMap::new(),
            ceiling,
        }
    }

    pub(crate) fn load(&self, address: Sym, width: BitWidth) -> Option<Sym> {
        let base: u64 = address.const_value()?;
        let cell: &Cell = self.cells.get(&base)?;
        let bytes: u32 = u32::from(width.bits() / 8);
        if cell.bytes == bytes && cell.value.width() == width {
            Some(cell.value)
        } else {
            None
        }
    }

    pub(crate) fn store(&mut self, address: Sym, value: Sym, width: BitWidth) {
        let bytes: u32 = u32::from(width.bits() / 8);
        let Some(base) = address.const_value() else {
            self.invalidate_all();
            return;
        };
        self.invalidate_overlap(base, bytes);
        if self.cells.len() >= self.ceiling {
            self.invalidate_all();
            return;
        }
        self.cells.insert(base, Cell { value, bytes });
    }

    pub(crate) fn invalidate_all(&mut self) {
        self.cells.clear();
    }

    fn invalidate_overlap(&mut self, base: u64, bytes: u32) {
        let write_end: u64 = base.saturating_add(u64::from(bytes.max(1)));
        let overlapping: Vec<u64> = self
            .cells
            .iter()
            .filter_map(|(start, cell): (&u64, &Cell)| {
                let cell_end: u64 = start.saturating_add(u64::from(cell.bytes.max(1)));
                let overlaps: bool = *start < write_end && base < cell_end;
                overlaps.then_some(*start)
            })
            .collect();
        for start in overlapping {
            self.cells.remove(&start);
        }
    }
}

pub(crate) fn load_or_havoc(
    memory: &Memory,
    solver: &mut SymSolver,
    address: Sym,
    width: BitWidth,
) -> Sym {
    memory
        .load(address, width)
        .unwrap_or_else(|| solver.fresh_havoc(width))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::solver::SolverBudget;
    use super::*;

    fn width(bits: u16) -> BitWidth {
        BitWidth::new(bits).expect("width is valid")
    }

    #[test]
    fn concrete_store_then_load_returns_the_written_value() {
        let width8: BitWidth = width(8);
        let mut memory: Memory = Memory::with_ceiling(64);
        let address: Sym = Sym::constant(width(64), 0x100);
        let value: Sym = Sym::constant(width8, 0x2a);
        memory.store(address, value, width8);
        assert_eq!(memory.load(address, width8), Some(value));
    }

    #[test]
    fn symbolic_pointer_write_invalidates_concrete_cells() {
        let width8: BitWidth = width(8);
        let mut solver: SymSolver = SymSolver::new(SolverBudget::default());
        let mut memory: Memory = Memory::with_ceiling(64);
        let address: Sym = Sym::constant(width(64), 0x100);
        memory.store(address, Sym::constant(width8, 0x2a), width8);
        let unknown_pointer: Sym = solver.fresh_havoc(width(64));
        let unknown_value: Sym = solver.fresh_havoc(width8);
        memory.store(unknown_pointer, unknown_value, width8);
        assert_eq!(memory.load(address, width8), None);
        let refreshed: Sym = load_or_havoc(&memory, &mut solver, address, width8);
        assert!(matches!(refreshed, Sym::Bv { .. }));
    }

    #[test]
    fn overlapping_write_evicts_the_prior_cell() {
        let width8: BitWidth = width(8);
        let width16: BitWidth = width(16);
        let mut memory: Memory = Memory::with_ceiling(64);
        let low: Sym = Sym::constant(width(64), 0x200);
        memory.store(low, Sym::constant(width16, 0xbeef), width16);
        let high: Sym = Sym::constant(width(64), 0x201);
        memory.store(high, Sym::constant(width8, 0x11), width8);
        assert_eq!(memory.load(low, width16), None);
        assert_eq!(memory.load(high, width8), Some(Sym::constant(width8, 0x11)));
    }
}
