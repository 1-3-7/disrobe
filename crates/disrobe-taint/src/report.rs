use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaintStep {
    pub address: u64,
    pub symbol: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaintFinding {
    pub function: String,
    pub function_address: u64,
    pub source_site: u64,
    pub source_symbol: String,
    pub sink_site: u64,
    pub sink_symbol: String,
    pub path: Vec<TaintStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct TaintReport {
    findings: Vec<TaintFinding>,
    truncated: bool,
}

impl TaintReport {
    #[must_use]
    pub const fn new(findings: Vec<TaintFinding>) -> Self {
        Self {
            findings,
            truncated: false,
        }
    }

    #[must_use]
    pub(crate) const fn new_with_truncated(findings: Vec<TaintFinding>, truncated: bool) -> Self {
        Self {
            findings,
            truncated,
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn findings(&self) -> &[TaintFinding] {
        &self.findings
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.findings.len()
    }

    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn reaches(&self, source_symbol: &str, sink_symbol: &str) -> bool {
        self.findings.iter().any(|f: &TaintFinding| {
            f.source_symbol == source_symbol && f.sink_symbol == sink_symbol
        })
    }

    #[must_use]
    pub fn flow_in(&self, function: &str, source_symbol: &str, sink_symbol: &str) -> bool {
        self.findings.iter().any(|f: &TaintFinding| {
            f.function == function
                && f.source_symbol == source_symbol
                && f.sink_symbol == sink_symbol
        })
    }
}
