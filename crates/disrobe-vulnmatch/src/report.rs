use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::adapters::{AbstractArgument, DirectCall, FunctionId};
use crate::constraint::ConstraintError;
use crate::rank::{FindingEvidence, FindingTier, RankedFinding};
use crate::reach::PathWitness;
use crate::version::{VersionError, VersionScheme};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(String);

impl FindingId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub rule_id: String,
    pub sink_site: DirectCall,
    pub tier: FindingTier,
    pub score: u32,
    pub witness_path: Option<PathWitness>,
    pub evidence: FindingEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageVersion {
    pub scheme: VersionScheme,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PackageMatchIssue {
    UnsupportedScheme { scheme: VersionScheme },
    NonconformingConstraint { constraint: String },
    InvalidVersion { value: String },
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "issue")]
pub enum PackageMatchStatus {
    Affected,
    Unaffected,
    Indeterminate(PackageMatchIssue),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRuleMatch {
    pub rule_id: String,
    pub package: PackageVersion,
    pub status: PackageMatchStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMatchReport {
    pub matches: Vec<PackageRuleMatch>,
    pub complete: bool,
    pub issue: Option<PackageMatchIssue>,
}

impl PackageMatchIssue {
    pub(crate) fn from_constraint(error: ConstraintError, constraint: &str) -> Self {
        match error {
            ConstraintError::Version(VersionError::UnsupportedScheme { scheme }) => {
                Self::UnsupportedScheme { scheme }
            }
            ConstraintError::Version(VersionError::Invalid { .. } | VersionError::Empty { .. })
            | ConstraintError::Empty
            | ConstraintError::Nonconforming { .. } => Self::NonconformingConstraint {
                constraint: constraint.to_owned(),
            },
            ConstraintError::Version(VersionError::TooLong { .. })
            | ConstraintError::TooLong { .. }
            | ConstraintError::TooManyPredicates { .. } => Self::LimitExceeded,
        }
    }

    pub(crate) fn from_version(error: VersionError, version: &str) -> Self {
        match error {
            VersionError::UnsupportedScheme { scheme } => Self::UnsupportedScheme { scheme },
            VersionError::TooLong { .. } => Self::LimitExceeded,
            VersionError::Empty { .. } | VersionError::Invalid { .. } => Self::InvalidVersion {
                value: version.to_owned(),
            },
        }
    }
}

impl Report {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn human(&self) -> String {
        Reporter::human(self)
    }
}

#[derive(Debug, Default)]
pub struct Reporter;

impl Reporter {
    pub fn report(ranked: Vec<RankedFinding>, complete: bool) -> Report {
        let mut findings: Vec<Finding> = ranked.into_iter().map(Finding::from_ranked).collect();
        findings.sort_by(|left: &Finding, right: &Finding| {
            right
                .tier
                .output_rank()
                .cmp(&left.tier.output_rank())
                .then_with(|| right.score.cmp(&left.score))
                .then_with(|| left.id.cmp(&right.id))
        });
        Report { findings, complete }
    }

    pub fn human(report: &Report) -> String {
        let mut output: String = String::new();
        for finding in &report.findings {
            let witness: String = witness_string(finding.witness_path.as_ref());
            if writeln!(
                output,
                "{} tier={:?} score={} rule={} site={} path={}",
                finding.id.as_str(),
                finding.tier,
                finding.score,
                finding.rule_id,
                finding.sink_site.id.as_str(),
                witness,
            )
            .is_err()
            {
                return output;
            }
        }
        output
    }
}

impl Finding {
    fn from_ranked(ranked: RankedFinding) -> Self {
        let id: FindingId = stable_finding_id(&ranked.rule_id, &ranked.sink_site);
        Self {
            id,
            rule_id: ranked.rule_id,
            sink_site: ranked.sink_site,
            tier: ranked.tier,
            score: ranked.score,
            witness_path: ranked.witness_path,
            evidence: ranked.evidence,
        }
    }
}

fn witness_string(witness: Option<&PathWitness>) -> String {
    let Some(path) = witness else {
        return String::from("unavailable");
    };
    let names: Vec<&str> = path
        .functions
        .iter()
        .map(|function: &FunctionId| function.as_str())
        .collect();
    names.join("->")
}

fn stable_finding_id(rule_id: &str, site: &DirectCall) -> FindingId {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    hash_string(&mut hash, rule_id);
    hash_string(&mut hash, site.id.as_str());
    hash_string(&mut hash, site.caller.as_str());
    match &site.callee_function {
        Some(function) => hash_string(&mut hash, function.as_str()),
        None => hash_string(&mut hash, ""),
    }
    match &site.resolved_callee {
        Some(callee) => hash_string(&mut hash, &callee.canonical_name),
        None => hash_string(&mut hash, ""),
    }
    for argument in &site.arguments {
        hash_argument(&mut hash, *argument);
    }
    FindingId(format!("vm-{hash:032x}"))
}

fn hash_string(hash: &mut u128, value: &str) {
    hash_bytes(hash, &(value.len() as u128).to_le_bytes());
    hash_bytes(hash, value.as_bytes());
}

fn hash_argument(hash: &mut u128, argument: AbstractArgument) {
    let value: u8 = match argument {
        AbstractArgument::Constant => 1,
        AbstractArgument::NonConstant => 2,
        AbstractArgument::Unknown => 3,
    };
    hash_bytes(hash, &[value]);
}

fn hash_bytes(hash: &mut u128, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u128::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b);
    }
}
