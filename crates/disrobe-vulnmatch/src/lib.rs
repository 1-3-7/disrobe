#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PredicateEvaluation {
    Match,
    NoMatch,
    Indeterminate,
}

mod adapters;
mod constraint;
mod matcher;
mod offline;
mod package_url;
mod query_call_graph;
pub mod rank;
mod reach;
mod report;
mod rules;
mod taint_report;
mod version;

pub use adapters::{
    AbstractArgument, CallGraphEdge, CallGraphView, CallSiteId, DirectCall, EdgeKind, FunctionId,
    MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE, ResolvedCallee, TaintOracle, TaintStatus, TaintWitness,
    TaintWitnessError, TaintWitnessStep,
};
pub use matcher::{CandidateSink, MatchOutput, SinkMatcher, match_package_versions};
pub use offline::{
    InstalledDebianPackage, OfflineMatchError, OfflineMatchIssue, OfflineMatchIssueKind,
    OfflineMatchReport, OfflineVulnerabilityFinding, match_debian_rootfs,
};
pub use package_url::{PackageType, PackageUrlError, build_package_url};
pub use query_call_graph::QueryCallGraphView;
pub use rank::{FindingEvidence, FindingTier, ReachabilityEvidence};
pub use reach::{
    Budget, EdgeSoundness, PathWitness, ReachabilityEngine, ReachabilityResult, ReachabilityState,
};
pub use report::{
    Finding, FindingId, PackageMatchIssue, PackageMatchReport, PackageMatchStatus,
    PackageRuleMatch, PackageVersion, Report, Reporter,
};
pub use rules::{
    ArgPredicate, PackageRule, Rule, RuleStore, RuleStoreError, Severity, SinkSignature,
    SourceClass,
};
pub use taint_report::{
    TaintReportOracle, analyze_with_taint, source_symbols, taint_config_for_rules,
};
pub use version::{VersionError, VersionScheme, compare_versions};

pub fn analyze<C: CallGraphView, T: TaintOracle>(
    call_graph: &C,
    taint: &T,
    rules: &RuleStore,
    budget: &mut Budget,
) -> Report {
    let matches: MatchOutput = SinkMatcher::match_call_graph(call_graph, rules, budget);
    let reachability: ReachabilityResult = ReachabilityEngine::analyze(call_graph, budget);
    let ranked: Vec<rank::RankedFinding> =
        rank::rank_candidates(&matches.candidates, &reachability, taint);
    Reporter::report(ranked, matches.complete && reachability.complete)
}
