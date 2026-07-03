use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::summary::{FeatureSet, KindSet};

const DEFAULT_MAX_STATES_PER_FUNCTION: usize = 65_536;
const HARD_MAX_STATES_PER_FUNCTION: usize = 1_048_576;
const MAX_INTERNED: u16 = 63;

const fn default_max_states_per_function() -> usize {
    DEFAULT_MAX_STATES_PER_FUNCTION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SinkPolicy {
    sensitive_kinds: u64,
    suppress: u64,
}

impl Default for SinkPolicy {
    fn default() -> Self {
        Self {
            sensitive_kinds: u64::MAX,
            suppress: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintConfig {
    sources: BTreeMap<String, u16>,
    sinks: BTreeMap<String, SinkPolicy>,
    sanitizers: BTreeMap<String, u16>,
    global_suppress: u64,
    next_kind: u16,
    next_feature: u16,
    #[serde(default = "default_max_states_per_function")]
    max_states_per_function: usize,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            sources: BTreeMap::new(),
            sinks: BTreeMap::new(),
            sanitizers: BTreeMap::new(),
            global_suppress: 0,
            next_kind: 0,
            next_feature: 0,
            max_states_per_function: DEFAULT_MAX_STATES_PER_FUNCTION,
        }
    }
}

pub(crate) struct ResolvedSinkPolicy {
    pub(crate) sensitive: KindSet,
    pub(crate) suppress: FeatureSet,
}

impl TaintConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_source(mut self, symbol: impl AsRef<str>) -> Self {
        if let Some(symbol) = normalize_symbol(symbol.as_ref()) {
            let next: u16 = self.next_kind.min(MAX_INTERNED);
            self.sources.entry(symbol).or_insert(next);
            self.next_kind = self.next_kind.saturating_add(1);
        }
        self
    }

    #[must_use]
    pub fn with_sink(mut self, symbol: impl AsRef<str>) -> Self {
        if let Some(symbol) = normalize_symbol(symbol.as_ref()) {
            self.sinks.entry(symbol).or_default();
        }
        self
    }

    #[must_use]
    pub fn with_sanitizer(mut self, symbol: impl AsRef<str>) -> Self {
        if let Some(symbol) = normalize_symbol(symbol.as_ref()) {
            let feature: u16 = self.register_feature(symbol);
            self.global_suppress |= 1u64 << u64::from(feature);
        }
        self
    }

    #[must_use]
    pub fn with_sanitizer_for(mut self, sanitizer: impl AsRef<str>, sink: impl AsRef<str>) -> Self {
        let Some(sanitizer) = normalize_symbol(sanitizer.as_ref()) else {
            return self;
        };
        let Some(sink) = normalize_symbol(sink.as_ref()) else {
            return self;
        };
        let feature: u16 = self.register_feature(sanitizer);
        let policy: &mut SinkPolicy = self.sinks.entry(sink).or_default();
        policy.suppress |= 1u64 << u64::from(feature);
        self
    }

    fn register_feature(&mut self, symbol: String) -> u16 {
        if let Some(existing) = self.sanitizers.get(&symbol) {
            return *existing;
        }
        let feature: u16 = self.next_feature.min(MAX_INTERNED);
        self.sanitizers.insert(symbol, feature);
        self.next_feature = self.next_feature.saturating_add(1);
        feature
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
        let mut config: Self = Self::new();
        for source in sources {
            config = config.with_source(source);
        }
        for sink in sinks {
            config = config.with_sink(sink);
        }
        config
    }

    #[must_use]
    pub fn is_source(&self, symbol: &str) -> bool {
        normalize_symbol(symbol).is_some_and(|symbol: String| self.sources.contains_key(&symbol))
    }

    #[must_use]
    pub fn is_sink(&self, symbol: &str) -> bool {
        normalize_symbol(symbol).is_some_and(|symbol: String| self.sinks.contains_key(&symbol))
    }

    pub(crate) fn source_kind(&self, symbol: &str) -> Option<KindSet> {
        let symbol: String = normalize_symbol(symbol)?;
        self.sources
            .get(&symbol)
            .map(|index: &u16| KindSet::from_index(*index))
    }

    pub(crate) fn sink_policy(&self, symbol: &str) -> Option<ResolvedSinkPolicy> {
        let symbol: String = normalize_symbol(symbol)?;
        self.sinks
            .get(&symbol)
            .map(|policy: &SinkPolicy| ResolvedSinkPolicy {
                sensitive: KindSet::from_bits(policy.sensitive_kinds),
                suppress: FeatureSet::from_bits(policy.suppress | self.global_suppress),
            })
    }

    pub(crate) fn sanitizer_feature(&self, symbol: &str) -> Option<FeatureSet> {
        let symbol: String = normalize_symbol(symbol)?;
        self.sanitizers
            .get(&symbol)
            .map(|index: &u16| FeatureSet::from_index(*index))
    }

    pub fn sources(&self) -> impl Iterator<Item = &str> {
        self.sources.keys().map(String::as_str)
    }

    pub fn sinks(&self) -> impl Iterator<Item = &str> {
        self.sinks.keys().map(String::as_str)
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
#[allow(clippy::expect_used)]
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
    fn distinct_sources_get_distinct_kinds() {
        let config: TaintConfig = TaintConfig::from_lists(["recv", "getenv"], ["system"]);
        let recv: KindSet = config.source_kind("recv").expect("recv kind");
        let getenv: KindSet = config.source_kind("getenv").expect("getenv kind");
        assert!(!recv.intersects(getenv));
    }

    #[test]
    fn targeted_sanitizer_only_suppresses_its_sink() {
        let config: TaintConfig = TaintConfig::from_lists(["recv"], ["system", "printf"])
            .with_sanitizer_for("escape_shell", "system");
        let feature: FeatureSet = config.sanitizer_feature("escape_shell").expect("feature");
        let system: ResolvedSinkPolicy = config.sink_policy("system").expect("system policy");
        let printf: ResolvedSinkPolicy = config.sink_policy("printf").expect("printf policy");
        assert!(system.suppress.intersects(feature));
        assert!(!printf.suppress.intersects(feature));
    }

    #[test]
    fn state_budget_is_bounded() {
        let zero: TaintConfig = TaintConfig::new().with_max_states_per_function(0);
        assert_eq!(zero.max_states_per_function(), 1);
        let huge: TaintConfig = TaintConfig::new().with_max_states_per_function(usize::MAX);
        assert_eq!(huge.max_states_per_function(), HARD_MAX_STATES_PER_FUNCTION);
    }
}
