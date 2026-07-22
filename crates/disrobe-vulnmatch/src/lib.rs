#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PredicateEvaluation {
    Match,
    NoMatch,
    Indeterminate,
}

mod adapters;
mod matcher;
pub mod rank;
mod reach;
mod report;
mod rules;

pub use adapters::{
    AbstractArgument, CallGraphEdge, CallGraphView, CallSiteId, DirectCall, EdgeKind, FunctionId,
    MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE, ResolvedCallee, TaintOracle, TaintStatus, TaintWitness,
    TaintWitnessError,
};
pub use matcher::{CandidateSink, MatchOutput, SinkMatcher};
pub use rank::{FindingEvidence, FindingTier, ReachabilityEvidence};
pub use reach::{
    Budget, EdgeSoundness, PathWitness, ReachabilityEngine, ReachabilityResult, ReachabilityState,
};
pub use report::{Finding, FindingId, Report, Reporter};
pub use rules::{
    ArgPredicate, Rule, RuleStore, RuleStoreError, Severity, SinkSignature, SourceClass,
};

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
