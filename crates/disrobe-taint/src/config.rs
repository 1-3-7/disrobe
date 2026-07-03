use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

const DEFAULT_MAX_STATES_PER_FUNCTION: usize = 65_536;
const HARD_MAX_STATES_PER_FUNCTION: usize = 1_048_576;

const fn default_max_states_per_function() -> usize {
    DEFAULT_MAX_STATES_PER_FUNCTION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintConfig {
    sources: BTreeSet<String>,
    sinks: BTreeSet<String>,
    #[serde(default = "default_max_states_per_function")]
    max_states_per_function: usize,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            sources: BTreeSet::new(),
            sinks: BTreeSet::new(),
            max_states_per_function: DEFAULT_MAX_STATES_PER_FUNCTION,
        }
    }
}

impl TaintConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_source(mut self, symbol: impl AsRef<str>) -> Self {
        if let Some(symbol) = normalize_symbol(symbol.as_ref()) {
            self.sources.insert(symbol);
        }
        self
    }

    #[must_use]
    pub fn with_sink(mut self, symbol: impl AsRef<str>) -> Self {
        if let Some(symbol) = normalize_symbol(symbol.as_ref()) {
            self.sinks.insert(symbol);
        }
        self
    }

    #[must_use]
    pub const fn with_max_states_per_function(mut self, max_states: usize) -> Self {
        self.max_states_per_function = normalize_max_states(max_states);
        self
    }

    #[must_use]
    pub fn from_lists<S: AsRef<str>>(
        sources: impl IntoIterator<Item = S>,
        sinks: impl IntoIterator<Item = S>,
    ) -> Self {
        Self {
            sources: sources
                .into_iter()
                .filter_map(|symbol: S| normalize_symbol(symbol.as_ref()))
                .collect(),
            sinks: sinks
                .into_iter()
                .filter_map(|symbol: S| normalize_symbol(symbol.as_ref()))
                .collect(),
            max_states_per_function: DEFAULT_MAX_STATES_PER_FUNCTION,
        }
    }

    #[must_use]
    pub fn is_source(&self, symbol: &str) -> bool {
        normalize_symbol(symbol).is_some_and(|symbol: String| self.sources.contains(&symbol))
    }

    #[must_use]
    pub fn is_sink(&self, symbol: &str) -> bool {
        normalize_symbol(symbol).is_some_and(|symbol: String| self.sinks.contains(&symbol))
    }

    pub fn sources(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(String::as_str)
    }

    pub fn sinks(&self) -> impl Iterator<Item = &str> {
        self.sinks.iter().map(String::as_str)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty() || self.sinks.is_empty()
    }

    #[must_use]
    pub const fn max_states_per_function(&self) -> usize {
        normalize_max_states(self.max_states_per_function)
    }
}

const fn normalize_max_states(max_states: usize) -> usize {
    if max_states == 0 {
        1
    } else if max_states > HARD_MAX_STATES_PER_FUNCTION {
        HARD_MAX_STATES_PER_FUNCTION
    } else {
        max_states
    }
}

fn normalize_symbol(symbol: &str) -> Option<String> {
    let normalized: &str = symbol.trim().trim_start_matches('_');
    (!normalized.is_empty()).then(|| normalized.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_and_sink_matching_is_case_and_decoration_tolerant() {
        let config: TaintConfig = TaintConfig::new()
            .with_source(" _Recv ")
            .with_sink("__CreateFileW");
        assert!(config.is_source("recv"));
        assert!(config.is_source("_RECV"));
        assert!(config.is_sink("createfilew"));
        assert!(config.is_sink("_CreateFileW"));
    }

    #[test]
    fn empty_symbols_are_ignored() {
        let config: TaintConfig = TaintConfig::from_lists([" ", "__"], ["sink"]);
        assert!(config.sources().next().is_none());
        assert!(config.is_empty());
    }

    #[test]
    fn state_budget_is_bounded() {
        let zero: TaintConfig = TaintConfig::new().with_max_states_per_function(0);
        assert_eq!(zero.max_states_per_function(), 1);
        let huge: TaintConfig = TaintConfig::new().with_max_states_per_function(usize::MAX);
        assert_eq!(huge.max_states_per_function(), HARD_MAX_STATES_PER_FUNCTION);
    }
}
