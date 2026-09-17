use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    StepCapExceeded { cap: u64, attempted: u64 },
    DeadlineExceeded,
    TimeLimitOverflow,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StepCapExceeded { cap, attempted } => {
                write!(
                    formatter,
                    "step cap {cap} rejects attempted spend {attempted}"
                )
            }
            Self::DeadlineExceeded => formatter.write_str("wall-clock deadline elapsed"),
            Self::TimeLimitOverflow => formatter.write_str("wall-clock deadline overflowed"),
        }
    }
}

impl std::error::Error for BudgetError {}

#[derive(Clone, Debug)]
pub struct Budget {
    cap: u64,
    spent: u64,
    deadline: Option<Instant>,
}

impl Budget {
    #[must_use]
    pub const fn new(cap: u64) -> Self {
        Self {
            cap,
            spent: 0,
            deadline: None,
        }
    }

    pub fn with_time_limit(cap: u64, limit: Duration) -> Result<Self, BudgetError> {
        let started: Instant = Instant::now();
        let deadline: Instant = match started.checked_add(limit) {
            Some(value) => value,
            None => return Err(BudgetError::TimeLimitOverflow),
        };
        Ok(Self {
            cap,
            spent: 0,
            deadline: Some(deadline),
        })
    }

    pub fn spend(&mut self, amount: u64) -> Result<(), BudgetError> {
        match self.deadline {
            Some(deadline) if Instant::now() >= deadline => {
                return Err(BudgetError::DeadlineExceeded);
            }
            Some(_) | None => {}
        }
        let attempted: u64 = match self.spent.checked_add(amount) {
            Some(value) => value,
            None => {
                return Err(BudgetError::StepCapExceeded {
                    cap: self.cap,
                    attempted: u64::MAX,
                });
            }
        };
        if attempted > self.cap {
            return Err(BudgetError::StepCapExceeded {
                cap: self.cap,
                attempted,
            });
        }
        self.spent = attempted;
        Ok(())
    }

    #[must_use]
    pub const fn cap(&self) -> u64 {
        self.cap
    }

    #[must_use]
    pub const fn spent(&self) -> u64 {
        self.spent
    }
}
