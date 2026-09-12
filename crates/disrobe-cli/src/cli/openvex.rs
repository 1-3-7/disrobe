use std::collections::BTreeMap;

use serde::Serialize;

use disrobe_vulnmatch::{Finding, FindingTier, ReachabilityEvidence, Report};

use crate::cli::structured_document::{
    StructuredDocumentError, require_author, to_bounded_pretty_json, validate_utc_timestamp,
};

const CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";
const DOCUMENT_ID_PREFIX: &str = "urn:disrobe:openvex:";
const PRODUCT_ID_PREFIX: &str = "urn:sha256:";
const IDENTITY_DOMAIN: &[u8] = b"disrobe:openvex-0.2.0:document:v1\0";

#[derive(Debug)]
pub(crate) enum OpenVexError {
    Document(StructuredDocumentError),
    NoFindings,
}

impl std::fmt::Display for OpenVexError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document(error) => error.fmt(formatter),
            Self::NoFindings => formatter.write_str(
                "OpenVEX 0.2.0 requires at least one vulnerability statement; vulnmatch produced none",
            ),
        }
    }
}

impl std::error::Error for OpenVexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Document(error) => Some(error),
            Self::NoFindings => None,
        }
    }
}

impl From<StructuredDocumentError> for OpenVexError {
    fn from(error: StructuredDocumentError) -> Self {
        Self::Document(error)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenVexDocument {
    #[serde(rename = "@context")]
    context: &'static str,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    role: &'static str,
    timestamp: String,
    version: u32,
    tooling: String,
    statements: Vec<Statement>,
}

#[derive(Debug, Serialize)]
struct Statement {
    vulnerability: Vulnerability,
    products: Vec<Product>,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<Justification>,
    #[serde(rename = "action_statement", skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

#[derive(Debug, Serialize)]
struct Vulnerability {
    name: String,
    aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Product {
    #[serde(rename = "@id")]
    id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    NotAffected,
    Affected,
    UnderInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Justification {
    VulnerableCodeNotInExecutePath,
}

impl OpenVexDocument {
    pub(crate) fn from_report(
        author: &str,
        timestamp: &str,
        product_sha256: &str,
        report: &Report,
    ) -> Result<Self, OpenVexError> {
        require_author(author)?;
        validate_utc_timestamp(timestamp)?;
        if report.findings.is_empty() {
            return Err(OpenVexError::NoFindings);
        }
        let product: Product = Product {
            id: format!("{PRODUCT_ID_PREFIX}{product_sha256}"),
        };
        let mut grouped: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for finding in &report.findings {
            grouped.entry(&finding.rule_id).or_default().push(finding);
        }
        let statements: Vec<Statement> = grouped
            .into_values()
            .filter_map(|findings: Vec<&Finding>| statement_from_findings(&findings, &product))
            .collect();
        let id: String = document_id(author, timestamp, &product.id, &statements);
        Ok(Self {
            context: CONTEXT,
            id,
            author: author.to_owned(),
            role: "Document Creator",
            timestamp: timestamp.to_owned(),
            version: 1,
            tooling: format!("disrobe {}", env!("CARGO_PKG_VERSION")),
            statements,
        })
    }
}

pub(crate) fn to_pretty_json(
    document: &OpenVexDocument,
) -> Result<Vec<u8>, StructuredDocumentError> {
    to_bounded_pretty_json(document)
}

fn statement_from_findings(findings: &[&Finding], product: &Product) -> Option<Statement> {
    let first: &Finding = *findings.first()?;
    let mut selected: (Status, Option<Justification>) = (
        Status::NotAffected,
        Some(Justification::VulnerableCodeNotInExecutePath),
    );
    for finding in findings {
        let candidate: (Status, Option<Justification>) =
            status_for_verdict(finding.tier, &finding.evidence.reachability);
        if status_rank(candidate.0) > status_rank(selected.0) {
            selected = candidate;
        }
    }
    let (status, justification): (Status, Option<Justification>) = selected;
    let remediation: Option<String> = matches!(status, Status::Affected).then(|| {
        let related_count: usize = findings.len().saturating_sub(1);
        format!(
            "Review disrobe finding {} and {related_count} related site(s); no remediation was inferred.",
            first.id.as_str()
        )
    });
    Some(Statement {
        vulnerability: Vulnerability {
            name: first.rule_id.clone(),
            aliases: vec![first.evidence.cwe.clone()],
        },
        products: vec![product.clone()],
        status,
        justification,
        remediation,
    })
}

const fn status_for_verdict(
    tier: FindingTier,
    reachability: &ReachabilityEvidence,
) -> (Status, Option<Justification>) {
    match (tier, reachability) {
        (FindingTier::Confirmed | FindingTier::Reachable, _) => (Status::Affected, None),
        (FindingTier::Present, ReachabilityEvidence::Unreachable) => (
            Status::NotAffected,
            Some(Justification::VulnerableCodeNotInExecutePath),
        ),
        (FindingTier::Present | FindingTier::ReachabilityUnknown | FindingTier::Unknown, _) => {
            (Status::UnderInvestigation, None)
        }
    }
}

const fn status_rank(status: Status) -> u8 {
    match status {
        Status::NotAffected => 1,
        Status::UnderInvestigation => 2,
        Status::Affected => 3,
    }
}

fn document_id(
    author: &str,
    timestamp: &str,
    product_id: &str,
    statements: &[Statement],
) -> String {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_DOMAIN);
    update_hash(&mut hasher, author.as_bytes());
    update_hash(&mut hasher, timestamp.as_bytes());
    update_hash(&mut hasher, product_id.as_bytes());
    update_hash(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    for statement in statements {
        update_hash(&mut hasher, statement.vulnerability.name.as_bytes());
        for alias in &statement.vulnerability.aliases {
            update_hash(&mut hasher, alias.as_bytes());
        }
        let status: &[u8] = match statement.status {
            Status::NotAffected => b"not_affected",
            Status::Affected => b"affected",
            Status::UnderInvestigation => b"under_investigation",
        };
        update_hash(&mut hasher, status);
        let justification: &[u8] = match statement.justification {
            Some(Justification::VulnerableCodeNotInExecutePath) => {
                b"vulnerable_code_not_in_execute_path"
            }
            None => b"",
        };
        update_hash(&mut hasher, justification);
        update_hash(
            &mut hasher,
            statement
                .remediation
                .as_deref()
                .map_or(b"".as_slice(), str::as_bytes),
        );
    }
    format!("{DOCUMENT_ID_PREFIX}{}", hasher.finalize().to_hex())
}

fn update_hash(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_follow_only_reachability_verdicts() {
        assert_eq!(
            status_for_verdict(FindingTier::Confirmed, &ReachabilityEvidence::Unknown),
            (Status::Affected, None)
        );
        assert_eq!(
            status_for_verdict(FindingTier::Reachable, &ReachabilityEvidence::Unknown),
            (Status::Affected, None)
        );
        assert_eq!(
            status_for_verdict(FindingTier::Present, &ReachabilityEvidence::Unreachable),
            (
                Status::NotAffected,
                Some(Justification::VulnerableCodeNotInExecutePath)
            )
        );
        assert_eq!(
            status_for_verdict(FindingTier::Present, &ReachabilityEvidence::Unknown),
            (Status::UnderInvestigation, None)
        );
        assert_eq!(
            status_for_verdict(
                FindingTier::ReachabilityUnknown,
                &ReachabilityEvidence::Unknown
            ),
            (Status::UnderInvestigation, None)
        );
        assert_eq!(
            status_for_verdict(FindingTier::Unknown, &ReachabilityEvidence::Unknown),
            (Status::UnderInvestigation, None)
        );
    }
}
