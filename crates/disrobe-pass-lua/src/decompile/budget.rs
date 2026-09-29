use crate::error::{Error, Result};

pub const MAX_LIFT_WORK: u64 = 1 << 24;
pub const INLINED_BYTES_PER_UNIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftBudget {
    limit: u64,
    spent: u64,
}

impl LiftBudget {
    #[must_use]
    pub const fn new(limit: u64) -> Self {
        Self { limit, spent: 0 }
    }

    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    #[must_use]
    pub const fn spent(&self) -> u64 {
        self.spent
    }

    #[must_use]
    pub(crate) const fn exhausted(&self) -> bool {
        self.spent > self.limit
    }

    pub(crate) fn charge_proto(&mut self, instructions: usize) -> bool {
        let units: u64 = u64::try_from(instructions).unwrap_or(u64::MAX);
        self.charge(units.saturating_add(1))
    }

    pub(crate) fn charge_inlined(&mut self, bytes: usize) {
        let units: u64 = u64::try_from(bytes / INLINED_BYTES_PER_UNIT).unwrap_or(u64::MAX);
        self.charge(units.saturating_add(1));
    }

    fn charge(&mut self, units: u64) -> bool {
        self.spent = self.spent.saturating_add(units);
        !self.exhausted()
    }

    pub(crate) fn settle<T>(&self, value: T) -> Result<T> {
        if self.exhausted() {
            Err(Error::LiftBudgetExceeded { limit: self.limit })
        } else {
            Ok(value)
        }
    }
}

impl Default for LiftBudget {
    fn default() -> Self {
        Self::new(MAX_LIFT_WORK)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_proto_costs_its_instructions_plus_one() {
        let mut budget: LiftBudget = LiftBudget::new(10);
        assert!(budget.charge_proto(9));
        assert_eq!(budget.spent(), 10);
        assert!(!budget.charge_proto(0));
        assert!(matches!(
            budget.settle(()),
            Err(Error::LiftBudgetExceeded { limit: 10 })
        ));
    }

    #[test]
    fn inlined_text_costs_one_unit_per_block_of_bytes() {
        let mut budget: LiftBudget = LiftBudget::new(u64::MAX);
        budget.charge_inlined(INLINED_BYTES_PER_UNIT * 3 + 1);
        assert_eq!(budget.spent(), 4);
        assert!(budget.settle(()).is_ok());
    }
}
