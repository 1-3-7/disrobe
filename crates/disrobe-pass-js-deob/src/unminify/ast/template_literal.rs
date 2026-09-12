use super::RuleOutcome;

#[derive(Debug, Clone, Default)]
pub(super) struct TemplateLiteralStats {
    pub(super) chains_rebuilt: usize,
}

pub(super) fn recover(_source: &str) -> (RuleOutcome, TemplateLiteralStats) {
    (RuleOutcome::empty(), TemplateLiteralStats::default())
}
