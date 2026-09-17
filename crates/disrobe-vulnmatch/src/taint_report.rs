use std::collections::BTreeSet;

use disrobe_nir::NirModule;
use disrobe_taint::{TaintConfig, TaintFinding, TaintReport, TaintStep};

use crate::adapters::{
    CallSiteId, DirectCall, FunctionId, TaintOracle, TaintStatus, TaintWitness, TaintWitnessStep,
};
use crate::query_call_graph::QueryCallGraphView;
use crate::reach::Budget;
use crate::report::Report;
use crate::rules::{RuleStore, SinkSignature, SourceClass};

const USER_CONTROLLED_SOURCES: &[&str] = &[
    "fgets", "fread", "gets", "read", "readfile", "recv", "recvfrom", "scanf",
];
const ENVIRONMENT_SOURCES: &[&str] = &[
    "getenv",
    "getenv_s",
    "getenvironmentvariablea",
    "getenvironmentvariablew",
    "secure_getenv",
];
const NETWORK_SOURCES: &[&str] = &["recv", "recvfrom", "wsarecv"];
const FILE_SOURCES: &[&str] = &["fread", "read", "readfile"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintReportOracle {
    report: TaintReport,
    configured_sources: BTreeSet<String>,
    configured_sinks: BTreeSet<String>,
}

impl TaintReportOracle {
    #[must_use]
    pub fn new(report: TaintReport, config: &TaintConfig) -> Self {
        let configured_sources: BTreeSet<String> = config.sources().map(normalize_symbol).collect();
        let configured_sinks: BTreeSet<String> = config.sinks().map(normalize_symbol).collect();
        Self {
            report,
            configured_sources,
            configured_sinks,
        }
    }

    #[must_use]
    pub const fn report(&self) -> &TaintReport {
        &self.report
    }
}

impl TaintOracle for TaintReportOracle {
    fn taint_status(&self, source: &SourceClass, site: &DirectCall) -> TaintStatus {
        let Some((caller_address, sink_site)): Option<(u64, u64)> = query_site(site) else {
            return TaintStatus::Unknown;
        };
        let Some(callee) = &site.resolved_callee else {
            return TaintStatus::Unknown;
        };
        let source_symbols: &[&str] = source_symbols(source);
        if !source_symbols
            .iter()
            .all(|symbol: &&str| self.configured_sources.contains(&normalize_symbol(symbol)))
        {
            return TaintStatus::Unknown;
        }
        if !self
            .configured_sinks
            .contains(&normalize_symbol(&callee.canonical_name))
        {
            return TaintStatus::Unknown;
        }
        for finding in self.report.findings() {
            if !matches_sink(finding, caller_address, sink_site, &callee.canonical_name)
                || !matches_source(finding, source_symbols)
            {
                continue;
            }
            if contains_sanitizer_step(&finding.path) {
                continue;
            }
            let steps: Vec<TaintWitnessStep> =
                finding.path.iter().map(TaintWitnessStep::from).collect();
            let witness: Result<TaintWitness, crate::adapters::TaintWitnessError> =
                TaintWitness::from_steps(steps);
            if let Ok(witness) = witness {
                return TaintStatus::Present(witness);
            }
            return TaintStatus::Unknown;
        }
        if self.report.is_truncated() {
            return TaintStatus::Unknown;
        }
        TaintStatus::Absent
    }
}

impl From<&TaintStep> for TaintWitnessStep {
    fn from(step: &TaintStep) -> Self {
        Self::new(step.address, step.symbol.clone(), step.kind.clone())
    }
}

#[must_use]
pub const fn source_symbols(source: &SourceClass) -> &'static [&'static str] {
    match source {
        SourceClass::UserControlled => USER_CONTROLLED_SOURCES,
        SourceClass::Environment => ENVIRONMENT_SOURCES,
        SourceClass::Network => NETWORK_SOURCES,
        SourceClass::File => FILE_SOURCES,
    }
}

#[must_use]
pub fn taint_config_for_rules<S>(rules: &RuleStore, sanitizers: S) -> TaintConfig
where
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    let mut sources: BTreeSet<&str> = BTreeSet::new();
    let mut sinks: BTreeSet<String> = BTreeSet::new();
    for rule in rules.rules() {
        if let Some(source) = &rule.requires_source {
            sources.extend(source_symbols(source).iter().copied());
        }
        match &rule.sink {
            SinkSignature::ResolvedSymbol {
                canonical_name,
                aliases,
            } => {
                sinks.insert(canonical_name.clone());
                sinks.extend(aliases.iter().cloned());
            }
        }
    }
    let mut config: TaintConfig = TaintConfig::new();
    for source in sources {
        config = config.with_source(source);
    }
    for sink in sinks {
        config = config.with_sink(sink);
    }
    for sanitizer in sanitizers {
        config = config.with_sanitizer(sanitizer);
    }
    config
}

#[must_use]
pub fn analyze_with_taint<S>(
    call_graph: &QueryCallGraphView<'_>,
    module: &NirModule,
    rules: &RuleStore,
    sanitizers: S,
    budget: &mut Budget,
) -> Report
where
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    let config: TaintConfig = taint_config_for_rules(rules, sanitizers);
    let report: TaintReport = disrobe_taint::analyze(module, &config);
    let taint: TaintReportOracle = TaintReportOracle::new(report, &config);
    crate::analyze(call_graph, &taint, rules, budget)
}

fn query_site(site: &DirectCall) -> Option<(u64, u64)> {
    let caller: u64 = query_function_address(&site.caller)?;
    let (call_caller, sink): (u64, u64) = query_call_site(&site.id)?;
    (caller == call_caller).then_some((caller, sink))
}

fn query_function_address(function: &FunctionId) -> Option<u64> {
    let mut parts: std::str::SplitN<'_, char> = function.as_str().splitn(3, ':');
    let namespace: &str = parts.next()?;
    let address: &str = parts.next()?;
    let name: &str = parts.next()?;
    if namespace != "query" || name.is_empty() {
        return None;
    }
    u64::from_str_radix(address, 16).ok()
}

fn query_call_site(site: &CallSiteId) -> Option<(u64, u64)> {
    let mut parts: std::str::Split<'_, char> = site.as_str().split(':');
    let namespace: &str = parts.next()?;
    let caller: &str = parts.next()?;
    let sink: &str = parts.next()?;
    if namespace != "query" || parts.next().is_some() {
        return None;
    }
    let caller: u64 = u64::from_str_radix(caller, 16).ok()?;
    let sink: u64 = u64::from_str_radix(sink, 16).ok()?;
    Some((caller, sink))
}

fn matches_sink(finding: &TaintFinding, caller_address: u64, sink_site: u64, callee: &str) -> bool {
    finding.function_address == caller_address
        && finding.sink_site == sink_site
        && normalize_symbol(&finding.sink_symbol) == normalize_symbol(callee)
}

fn matches_source(finding: &TaintFinding, sources: &[&str]) -> bool {
    let source: String = normalize_symbol(&finding.source_symbol);
    sources
        .iter()
        .any(|symbol: &&str| source == normalize_symbol(symbol))
}

fn contains_sanitizer_step(path: &[TaintStep]) -> bool {
    path.iter()
        .any(|step: &TaintStep| step.kind.eq_ignore_ascii_case("sanitize"))
}

fn normalize_symbol(symbol: &str) -> String {
    symbol.trim().trim_start_matches('_').to_ascii_lowercase()
}
