use super::RuleOutcome;

#[derive(Debug, Clone, Default)]
pub(super) struct ArgumentSpreadStats {
    pub(super) apply_calls_spread: usize,
}

pub(super) fn recover(_source: &str) -> (RuleOutcome, ArgumentSpreadStats) {
    (RuleOutcome::empty(), ArgumentSpreadStats::default())
}
