use serde::Serialize;

use crate::callgraph::CallEdge;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedCallKind {
    UnnamedTarget,
    IndirectTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnresolvedCall {
    pub function: String,
    pub function_address: u64,
    pub site: u64,
    pub kind: UnresolvedCallKind,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct TaintReport {
    findings: Vec<TaintFinding>,
    truncated: bool,
    unresolved_calls: Vec<UnresolvedCall>,
    unresolved_call_count: usize,
    call_edges: Vec<CallEdge>,
}

impl TaintReport {
    #[must_use]
    pub const fn new(findings: Vec<TaintFinding>) -> Self {
        Self {
            findings,
            truncated: false,
            unresolved_calls: Vec::new(),
            unresolved_call_count: 0,
            call_edges: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) const fn new_with_truncated(findings: Vec<TaintFinding>, truncated: bool) -> Self {
        Self {
            findings,
            truncated,
            unresolved_calls: Vec::new(),
            unresolved_call_count: 0,
            call_edges: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_unresolved_calls(
        mut self,
        unresolved_calls: Vec<UnresolvedCall>,
        unresolved_call_count: usize,
    ) -> Self {
        self.unresolved_calls = unresolved_calls;
        self.unresolved_call_count = unresolved_call_count;
        self
    }

    #[must_use]
    pub(crate) fn with_call_edges(mut self, call_edges: Vec<CallEdge>) -> Self {
        self.call_edges = call_edges;
        self
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
    pub fn unresolved_calls(&self) -> &[UnresolvedCall] {
        &self.unresolved_calls
    }

    #[must_use]
    pub const fn unresolved_call_count(&self) -> usize {
        self.unresolved_call_count
    }

    #[must_use]
    pub const fn has_unresolved_calls(&self) -> bool {
        self.unresolved_call_count > 0
    }

    #[must_use]
    pub fn call_edges(&self) -> &[CallEdge] {
        &self.call_edges
    }

    #[must_use]
    pub fn unresolved_call_sites(&self, function: &str) -> Vec<u64> {
        self.unresolved_calls
            .iter()
            .filter(|call: &&UnresolvedCall| call.function == function)
            .map(|call: &UnresolvedCall| call.site)
            .collect()
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
