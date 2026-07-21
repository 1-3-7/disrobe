use serde::{Deserialize, Serialize};

use crate::adapters::{CallGraphView, DirectCall};
use crate::reach::Budget;
use crate::rules::{ArgPredicate, RuleStore, Severity, SourceClass};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSink {
    pub rule_id: String,
    pub cwe: String,
    pub severity: Severity,
    pub requires_source: Option<SourceClass>,
    pub matched_constraints: Vec<ArgPredicate>,
    pub sink_site: DirectCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOutput {
    pub candidates: Vec<CandidateSink>,
    pub complete: bool,
}

#[derive(Debug, Default)]
pub struct SinkMatcher;

impl SinkMatcher {
    pub fn match_call_graph<C: CallGraphView>(
        call_graph: &C,
        rules: &RuleStore,
        budget: &mut Budget,
    ) -> MatchOutput {
        let mut calls: Vec<DirectCall> = call_graph.direct_calls();
        calls.sort();
        let mut candidates: Vec<CandidateSink> = Vec::new();
        let mut complete: bool = true;
        'calls: for call in calls {
            if !budget.consume_step() {
                complete = false;
                break;
            }
            let Some(callee) = &call.resolved_callee else {
                continue;
            };
            for rule in rules.rules() {
                if !budget.consume_step() {
                    complete = false;
                    break 'calls;
                }
                if rule.sink.matches(callee)
                    && rule
                        .arg_constraints
                        .iter()
                        .all(|predicate: &ArgPredicate| predicate.matches(&call))
                {
                    candidates.push(CandidateSink {
                        rule_id: rule.id.clone(),
                        cwe: rule.cwe.clone(),
                        severity: rule.severity,
                        requires_source: rule.requires_source.clone(),
                        matched_constraints: rule.arg_constraints.clone(),
                        sink_site: call.clone(),
                    });
                }
            }
        }
        candidates.sort_by(|left: &CandidateSink, right: &CandidateSink| {
            left.rule_id
                .cmp(&right.rule_id)
                .then_with(|| left.sink_site.cmp(&right.sink_site))
        });
        MatchOutput {
            candidates,
            complete,
        }
    }
}
