use serde::{Deserialize, Serialize};

use crate::PredicateEvaluation;
use crate::adapters::{CallGraphView, DirectCall};
use crate::constraint::evaluate_constraint;
use crate::reach::Budget;
use crate::report::{
    PackageMatchIssue, PackageMatchReport, PackageMatchStatus, PackageRuleMatch, PackageVersion,
};
use crate::rules::PackageRule;
use crate::rules::{ArgPredicate, RuleStore, Severity, SourceClass};
use crate::version::compare_versions;

const MAX_PACKAGE_MATCH_INPUTS: usize = 16_384;
const MAX_PACKAGE_MATCH_WORK: usize = 1_048_576;
const MAX_PACKAGE_MATCH_RESULTS: usize = 16_384;
const MAX_PACKAGE_MATCH_TEXT_BYTES: usize = 8 * 1024;
const MAX_PACKAGE_MATCH_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSink {
    pub rule_id: String,
    pub cwe: String,
    pub severity: Severity,
    pub requires_source: Option<SourceClass>,
    pub matched_constraints: Vec<ArgPredicate>,
    pub indeterminate_constraints: Vec<ArgPredicate>,
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
        calls.dedup();
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
                if !rule.sink.matches(callee) {
                    continue;
                }
                let mut rejected: bool = false;
                let mut matched_constraints: Vec<ArgPredicate> = Vec::new();
                let mut indeterminate_constraints: Vec<ArgPredicate> = Vec::new();
                for predicate in &rule.arg_constraints {
                    match predicate.evaluate(&call) {
                        PredicateEvaluation::Match => {
                            matched_constraints.push(predicate.clone());
                        }
                        PredicateEvaluation::NoMatch => {
                            rejected = true;
                            break;
                        }
                        PredicateEvaluation::Indeterminate => {
                            indeterminate_constraints.push(predicate.clone());
                        }
                    }
                }
                if rejected {
                    continue;
                }
                if !indeterminate_constraints.is_empty() {
                    complete = false;
                }
                candidates.push(CandidateSink {
                    rule_id: rule.id.clone(),
                    cwe: rule.cwe.clone(),
                    severity: rule.severity,
                    requires_source: rule.requires_source.clone(),
                    matched_constraints,
                    indeterminate_constraints,
                    sink_site: call.clone(),
                });
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

pub fn match_package_versions(
    packages: &[PackageVersion],
    rules: &[PackageRule],
) -> PackageMatchReport {
    if packages.len() > MAX_PACKAGE_MATCH_INPUTS || rules.len() > MAX_PACKAGE_MATCH_INPUTS {
        return PackageMatchReport {
            matches: Vec::new(),
            complete: false,
            issue: Some(PackageMatchIssue::LimitExceeded),
        };
    }
    if packages.iter().any(|package: &PackageVersion| {
        package.name.len() > MAX_PACKAGE_MATCH_TEXT_BYTES
            || package.version.len() > MAX_PACKAGE_MATCH_TEXT_BYTES
    }) || rules.iter().any(|rule: &PackageRule| {
        rule.id.len() > MAX_PACKAGE_MATCH_TEXT_BYTES
            || rule.package.len() > MAX_PACKAGE_MATCH_TEXT_BYTES
            || rule.constraint.len() > MAX_PACKAGE_MATCH_TEXT_BYTES
    }) {
        return PackageMatchReport {
            matches: Vec::new(),
            complete: false,
            issue: Some(PackageMatchIssue::LimitExceeded),
        };
    }
    let result_capacity: usize = packages
        .len()
        .checked_mul(rules.len())
        .map_or(MAX_PACKAGE_MATCH_RESULTS, |count: usize| count)
        .min(MAX_PACKAGE_MATCH_RESULTS);
    let mut matches: Vec<PackageRuleMatch> = Vec::new();
    if matches.try_reserve_exact(result_capacity).is_err() {
        return PackageMatchReport {
            matches,
            complete: false,
            issue: Some(PackageMatchIssue::LimitExceeded),
        };
    }
    let mut complete: bool = true;
    let mut issue: Option<PackageMatchIssue> = None;
    let mut work: usize = 0;
    let mut output_bytes: usize = 0;
    'packages: for package in packages {
        for rule in rules {
            work = work.saturating_add(1);
            if work > MAX_PACKAGE_MATCH_WORK {
                complete = false;
                issue = Some(PackageMatchIssue::LimitExceeded);
                break 'packages;
            }
            if package.scheme != rule.scheme {
                continue;
            }
            if package.name != rule.package {
                continue;
            }
            if matches.len() == MAX_PACKAGE_MATCH_RESULTS {
                complete = false;
                issue = Some(PackageMatchIssue::LimitExceeded);
                break 'packages;
            }
            let required_output_bytes: usize = rule
                .id
                .len()
                .saturating_add(package.name.len())
                .saturating_add(package.version.len());
            output_bytes = output_bytes.saturating_add(required_output_bytes);
            if output_bytes > MAX_PACKAGE_MATCH_OUTPUT_BYTES {
                complete = false;
                issue = Some(PackageMatchIssue::LimitExceeded);
                break 'packages;
            }
            let status: PackageMatchStatus =
                match compare_versions(package.scheme, &package.version, &package.version) {
                    Err(error) => {
                        complete = false;
                        PackageMatchStatus::Indeterminate(PackageMatchIssue::from_version(
                            error,
                            &package.version,
                        ))
                    }
                    Ok(_) => match evaluate_constraint(
                        package.scheme,
                        &package.version,
                        &rule.constraint,
                    ) {
                        Ok(true) => PackageMatchStatus::Affected,
                        Ok(false) => PackageMatchStatus::Unaffected,
                        Err(error) => {
                            complete = false;
                            PackageMatchStatus::Indeterminate(PackageMatchIssue::from_constraint(
                                error,
                                &rule.constraint,
                            ))
                        }
                    },
                };
            matches.push(PackageRuleMatch {
                rule_id: rule.id.clone(),
                package: package.clone(),
                status,
            });
        }
    }
    matches.sort_by(|left: &PackageRuleMatch, right: &PackageRuleMatch| {
        left.package
            .scheme
            .cmp(&right.package.scheme)
            .then(left.package.name.cmp(&right.package.name))
            .then(left.package.version.cmp(&right.package.version))
            .then(left.rule_id.cmp(&right.rule_id))
    });
    PackageMatchReport {
        matches,
        complete,
        issue,
    }
}
