use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Map, Value};

use super::secret_scan::{self, SecretScanReport, SecretScrubber, redaction_token};
use super::{ReconCategory, ReconFinding, ReconReport};

#[cfg(not(target_arch = "wasm32"))]
use super::git_history::{GitFinding, GitHistoryReport};

const MAX_SERIALIZED_DEPTH: usize = 64;
const MAX_SERIALIZED_NODES: usize = 1_048_576;
const MAX_SERIALIZED_STRING_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionError {
    DepthLimit { limit: usize },
    NodeLimit { limit: usize },
    StringBytesLimit { limit: usize },
    DuplicateObjectKey,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DepthLimit { limit } => {
                write!(
                    formatter,
                    "redaction input exceeds the {limit}-level depth limit"
                )
            }
            Self::NodeLimit { limit } => {
                write!(formatter, "redaction input exceeds the {limit}-node limit")
            }
            Self::StringBytesLimit { limit } => {
                write!(
                    formatter,
                    "redaction input exceeds the {limit}-byte string limit"
                )
            }
            Self::DuplicateObjectKey => {
                formatter.write_str("redaction would create duplicate object keys")
            }
        }
    }
}

impl std::error::Error for RedactionError {}

#[derive(Debug, Clone, Copy, Default)]
pub struct Redactor;

#[allow(clippy::unused_self)]
impl Redactor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn token(self, secret: &str) -> String {
        redaction_token(secret)
    }

    pub fn redact_report(self, report: &mut ReconReport) {
        let scrubber: SecretScrubber = self.scrubber(secret_values(&report.findings));
        for finding in &mut report.findings {
            redact_finding(finding, &scrubber);
        }
        if let Some(root) = &mut report.root {
            *root = scrubber.scrub(root.as_str());
        }
    }

    pub fn redact_secret_report(self, report: &mut SecretScanReport) {
        secret_scan::redact_report(report);
    }

    pub fn redact_text(self, input: &str) -> Result<String, RedactionError> {
        if input.len() > MAX_SERIALIZED_STRING_BYTES {
            return Err(RedactionError::StringBytesLimit {
                limit: MAX_SERIALIZED_STRING_BYTES,
            });
        }
        let secrets: BTreeSet<String> = secret_scan::scan_bytes(input.as_bytes(), None)
            .into_iter()
            .map(|finding: secret_scan::Finding| finding.value)
            .filter(|value: &String| !value.is_empty())
            .collect();
        Ok(self.scrubber(secrets).scrub(input))
    }

    pub fn redact_json_value(self, value: &mut Value) -> Result<(), RedactionError> {
        let secrets: BTreeSet<String> = serialized_secrets(value)?;
        let scrubber: SecretScrubber = self.scrubber(secrets);
        validate_json_keys(value, &scrubber)?;
        scrub_json_value(value, &scrubber, 0)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn redact_git_report(self, report: &mut GitHistoryReport) {
        let secrets: BTreeSet<String> = report
            .findings
            .iter()
            .filter(|gf: &&GitFinding| {
                matches!(
                    gf.finding.category,
                    ReconCategory::Secret | ReconCategory::Custom
                )
            })
            .map(|gf: &GitFinding| gf.finding.value.clone())
            .filter(|v: &String| !v.is_empty())
            .collect();
        let scrubber: SecretScrubber = self.scrubber(secrets);
        for gf in &mut report.findings {
            redact_git_finding(gf, &scrubber);
        }
    }

    fn scrubber(self, secrets: BTreeSet<String>) -> SecretScrubber {
        SecretScrubber::new(secrets)
    }
}

fn secret_values(findings: &[ReconFinding]) -> BTreeSet<String> {
    findings
        .iter()
        .filter(|finding: &&ReconFinding| {
            matches!(
                finding.category,
                ReconCategory::Secret | ReconCategory::Custom
            )
        })
        .map(|f: &ReconFinding| f.value.clone())
        .filter(|v: &String| !v.is_empty())
        .collect()
}

fn serialized_secrets(value: &Value) -> Result<BTreeSet<String>, RedactionError> {
    serialized_secrets_with_limits(
        value,
        MAX_SERIALIZED_DEPTH,
        MAX_SERIALIZED_NODES,
        MAX_SERIALIZED_STRING_BYTES,
    )
}

fn serialized_secrets_with_limits(
    value: &Value,
    max_depth: usize,
    max_nodes: usize,
    max_string_bytes: usize,
) -> Result<BTreeSet<String>, RedactionError> {
    let mut secrets: BTreeSet<String> = BTreeSet::new();
    let mut nodes: usize = 0;
    let mut string_bytes: usize = 0;
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((current, depth)) = stack.pop() {
        if depth > max_depth {
            return Err(RedactionError::DepthLimit { limit: max_depth });
        }
        nodes = nodes.saturating_add(1);
        if nodes > max_nodes {
            return Err(RedactionError::NodeLimit { limit: max_nodes });
        }
        match current {
            Value::String(text) => {
                collect_text_secrets(text, &mut secrets, &mut string_bytes, max_string_bytes)?;
            }
            Value::Array(values) => {
                admit_pending_nodes(stack.len(), values.len(), nodes, max_nodes)?;
                for nested in values.iter().rev() {
                    stack.push((nested, depth.saturating_add(1)));
                }
            }
            Value::Object(fields) => {
                admit_pending_nodes(stack.len(), fields.len(), nodes, max_nodes)?;
                for (key, nested) in fields.iter().rev() {
                    collect_text_secrets(key, &mut secrets, &mut string_bytes, max_string_bytes)?;
                    stack.push((nested, depth.saturating_add(1)));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(secrets)
}

const fn admit_pending_nodes(
    pending: usize,
    incoming: usize,
    visited: usize,
    limit: usize,
) -> Result<(), RedactionError> {
    let remaining: usize = limit.saturating_sub(visited);
    if pending > remaining || incoming > remaining.saturating_sub(pending) {
        return Err(RedactionError::NodeLimit { limit });
    }
    Ok(())
}

fn collect_text_secrets(
    text: &str,
    secrets: &mut BTreeSet<String>,
    string_bytes: &mut usize,
    limit: usize,
) -> Result<(), RedactionError> {
    *string_bytes = string_bytes.saturating_add(text.len());
    if *string_bytes > limit {
        return Err(RedactionError::StringBytesLimit { limit });
    }
    secrets.extend(
        secret_scan::scan_bytes(text.as_bytes(), None)
            .into_iter()
            .map(|finding: secret_scan::Finding| finding.value)
            .filter(|value: &String| !value.is_empty()),
    );
    Ok(())
}

fn scrub_json_value(
    value: &mut Value,
    scrubber: &SecretScrubber,
    depth: usize,
) -> Result<(), RedactionError> {
    if depth > MAX_SERIALIZED_DEPTH {
        return Err(RedactionError::DepthLimit {
            limit: MAX_SERIALIZED_DEPTH,
        });
    }
    match value {
        Value::String(text) => *text = scrubber.scrub(text),
        Value::Array(values) => {
            for nested in values {
                scrub_json_value(nested, scrubber, depth.saturating_add(1))?;
            }
        }
        Value::Object(fields) => scrub_json_object(fields, scrubber, depth)?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn validate_json_keys(value: &Value, scrubber: &SecretScrubber) -> Result<(), RedactionError> {
    let mut stack: Vec<&Value> = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Array(values) => stack.extend(values.iter().rev()),
            Value::Object(fields) => {
                let renamed: BTreeSet<String> = fields
                    .keys()
                    .map(|key: &String| scrubber.scrub(key))
                    .collect();
                if renamed.len() != fields.len() {
                    return Err(RedactionError::DuplicateObjectKey);
                }
                stack.extend(fields.values().rev());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn scrub_json_object(
    fields: &mut Map<String, Value>,
    scrubber: &SecretScrubber,
    depth: usize,
) -> Result<(), RedactionError> {
    let renamed: Vec<String> = fields
        .keys()
        .map(|key: &String| scrubber.scrub(key))
        .collect();
    let unique: BTreeSet<&str> = renamed.iter().map(String::as_str).collect();
    if unique.len() != renamed.len() {
        return Err(RedactionError::DuplicateObjectKey);
    }
    let original: Map<String, Value> = std::mem::take(fields);
    for ((_, mut nested), key) in original.into_iter().zip(renamed) {
        scrub_json_value(&mut nested, scrubber, depth.saturating_add(1))?;
        fields.insert(key, nested);
    }
    Ok(())
}

fn redact_finding(finding: &mut ReconFinding, scrubber: &SecretScrubber) {
    let ReconFinding {
        category: _,
        rule_id,
        value,
        path,
        line: _,
        column: _,
        offset: _,
        severity,
    } = finding;
    *rule_id = scrubber.scrub(rule_id.as_str());
    *value = scrubber.scrub(value.as_str());
    if let Some(path_value) = path {
        *path_value = scrubber.scrub(path_value.as_str());
    }
    *severity = scrubber.scrub(severity.as_str());
}

#[cfg(not(target_arch = "wasm32"))]
fn redact_git_finding(gf: &mut GitFinding, scrubber: &SecretScrubber) {
    let GitFinding {
        commit,
        author_name,
        author_email,
        commit_time_unix: _,
        blob_path,
        finding,
    } = gf;
    *commit = scrubber.scrub(commit.as_str());
    *author_name = scrubber.scrub(author_name.as_str());
    *author_email = scrubber.scrub(author_email.as_str());
    *blob_path = scrubber.scrub(blob_path.as_str());
    redact_finding(finding, scrubber);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::recon::{ReconConfig, report_bytes};
    use crate::secret_scan::{Finding, SecretKind, SecretScanReport};

    fn aws_akid() -> String {
        format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
    }

    #[test]
    fn secret_value_is_replaced_locations_and_iocs_preserved() {
        let secret: String = aws_akid();
        let input: String = format!("line one\nkey {secret} see https://api.example.com/v1\n");
        let mut report: ReconReport =
            report_bytes(input.as_bytes(), Some("a.txt"), &ReconConfig::default());

        let before: Vec<(String, usize, usize)> = report
            .findings
            .iter()
            .map(|f: &ReconFinding| (f.rule_id.clone(), f.line, f.column))
            .collect();

        Redactor::new().redact_report(&mut report);

        let after: Vec<(String, usize, usize)> = report
            .findings
            .iter()
            .map(|f: &ReconFinding| (f.rule_id.clone(), f.line, f.column))
            .collect();
        assert_eq!(before, after, "location multiset must be preserved");

        let aws: &ReconFinding = report
            .findings
            .iter()
            .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
            .expect("aws finding");
        assert!(
            aws.value.starts_with("[REDACTED:") && !aws.value.contains(secret.as_str()),
            "secret value must be replaced by a sentinel: {aws:?}"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|f: &ReconFinding| !f.value.contains(secret.as_str())),
            "no field may still carry the secret: {:?}",
            report.findings
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.value.contains("api.example.com")),
            "non-secret IOCs stay visible for triage: {:?}",
            report.findings
        );
    }

    #[test]
    fn tokens_are_stable_across_instances() {
        let secret: String = aws_akid();
        let same_a: String = Redactor::new().token(&secret);
        let same_b: String = Redactor::new().token(&secret);
        assert_eq!(same_a, same_b, "same key + secret must be stable");
        assert!(same_a.starts_with("[REDACTED:") && same_a.ends_with(']'));
    }

    #[test]
    fn short_token_is_unsalted_truncated_sha256_without_reveal() {
        let token: String = Redactor::new().token("abc");
        assert_eq!(token, "[REDACTED:ba7816bf8f01cfea414140de]");
    }

    #[test]
    fn long_token_reveals_only_two_edge_characters() {
        let secret: String = aws_akid();
        let token: String = Redactor::new().token(&secret);
        assert!(token.starts_with("[REDACTED:"));
        assert!(token.ends_with(":AK…AB]"));
        assert!(!token.contains(secret.as_str()));
    }

    #[test]
    fn secret_scan_redacts_value_preview_message_uri_and_report_uri() {
        let secret: String = aws_akid();
        let uri: String = format!("https://user:{secret}@example.test/{secret}");
        let mut report: SecretScanReport = SecretScanReport {
            schema: crate::secret_scan::SCAN_SCHEMA,
            uri: Some(uri.clone()),
            byte_len: secret.len(),
            findings: vec![Finding {
                code: "DR-SEC-AWS-AKID".to_owned(),
                message: format!("found {secret}"),
                uri: Some(uri),
                level: "error".to_owned(),
                kind: SecretKind::AwsAccessKeyId,
                offset: 7,
                value: secret.clone(),
                preview: format!("prefix {secret} suffix"),
                validation: None,
            }],
        };

        Redactor::new().redact_secret_report(&mut report);

        let serialized: String = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.contains(secret.as_str()));
        assert!(serialized.matches("[REDACTED:").count() >= 5);
        assert_eq!(report.findings[0].offset, 7);
    }

    #[test]
    fn substring_values_use_the_longest_match_without_leaking_either_value() {
        let long: String = aws_akid();
        let short: String = long[..12].to_owned();
        let scrubber: SecretScrubber =
            Redactor::new().scrubber(BTreeSet::from([short.clone(), long.clone()]));
        let scrubbed: String = scrubber.scrub(&format!("{long}|{short}"));
        assert!(!scrubbed.contains(long.as_str()));
        assert!(!scrubbed.contains(short.as_str()));
        assert_eq!(scrubbed.matches("[REDACTED:").count(), 2);
    }

    #[test]
    fn replacement_treats_regular_expression_metacharacters_as_literal_text() {
        let secret: String = "token[1].*?(value)".to_owned();
        let scrubber: SecretScrubber = Redactor::new().scrubber(BTreeSet::from([secret.clone()]));
        let scrubbed: String = scrubber.scrub(&format!("before {secret} after tokenZvalue"));
        assert!(!scrubbed.contains(secret.as_str()));
        assert!(scrubbed.contains("tokenZvalue"));
        assert_eq!(scrubbed.matches("[REDACTED:").count(), 1);
    }

    #[test]
    fn nested_serialized_value_scrubs_every_sarif_secret_surface() {
        let secret: String = aws_akid();
        let mut value: serde_json::Value = serde_json::json!({
            "message": { "text": format!("found {secret}") },
            "locations": [{ "physicalLocation": { "artifactLocation": {
                "uri": format!("https://user:{secret}@example.test/{secret}")
            }, "region": { "byteOffset": 17, "snippet": { "text": secret } } } }],
            "codeFlows": [{ "threadFlows": [{ "locations": [{
                "location": { "message": { "text": format!("flow {secret}") } }
            }] }] }],
            "fixes": [{ "artifactChanges": [{ "replacements": [{
                "insertedContent": { "text": format!("replace {secret}") }
            }] }] }],
            "fingerprints": { "secretHash": format!("fingerprint-{secret}") }
        });

        Redactor::new()
            .redact_json_value(&mut value)
            .expect("redact nested value");

        let serialized: String = serde_json::to_string(&value).expect("serialize value");
        assert!(!serialized.contains(secret.as_str()));
        assert!(serialized.matches("[REDACTED:").count() >= 7);
        assert_eq!(
            value["locations"][0]["physicalLocation"]["region"]["byteOffset"],
            17
        );
    }

    #[test]
    fn serialized_redaction_refuses_values_past_the_depth_bound() {
        let mut value: serde_json::Value = serde_json::Value::String(aws_akid());
        for _ in 0..=MAX_SERIALIZED_DEPTH {
            value = serde_json::json!({ "nested": value });
        }

        let error: RedactionError = Redactor::new()
            .redact_json_value(&mut value)
            .expect_err("over-depth value must be refused");
        assert!(matches!(error, RedactionError::DepthLimit { .. }));
    }

    #[test]
    fn serialized_redaction_refuses_a_wide_container_before_enqueuing_its_children() {
        let value: serde_json::Value =
            serde_json::Value::Array(vec![serde_json::Value::Null; MAX_SERIALIZED_NODES]);

        let error: RedactionError = serialized_secrets_with_limits(
            &value,
            MAX_SERIALIZED_DEPTH,
            MAX_SERIALIZED_NODES - 1,
            MAX_SERIALIZED_STRING_BYTES,
        )
        .expect_err("the root plus every array member exceeds the node limit");

        assert_eq!(
            error,
            RedactionError::NodeLimit {
                limit: MAX_SERIALIZED_NODES - 1
            }
        );
        assert!(
            value
                .as_array()
                .is_some_and(|items: &Vec<serde_json::Value>| {
                    items.len() == MAX_SERIALIZED_NODES
                })
        );
    }

    #[test]
    fn rendered_redaction_rescans_without_secret_findings() {
        let secret: String = aws_akid();
        let rendered: String = format!("secret={secret} repeated={secret}");
        let redacted: String = Redactor::new()
            .redact_text(&rendered)
            .expect("redact rendered text");
        let findings: Vec<crate::secret_scan::Finding> =
            crate::secret_scan::scan_bytes(redacted.as_bytes(), None);
        assert!(!redacted.contains(secret.as_str()));
        assert_eq!(redacted.matches("[REDACTED:").count(), 2);
        assert!(
            findings.is_empty(),
            "redacted output rescanned as secret: {findings:?}"
        );

        let mutated: String = redacted.replace(Redactor::new().token(&secret).as_str(), &secret);
        let mutation_findings: Vec<crate::secret_scan::Finding> =
            crate::secret_scan::scan_bytes(mutated.as_bytes(), None);
        assert!(
            mutation_findings
                .iter()
                .any(|finding: &crate::secret_scan::Finding| finding.value == secret),
            "the rescan check must fail when the planted secret is restored"
        );
    }

    #[test]
    fn duplicate_redacted_object_keys_are_refused_without_mutation() {
        let secret: String = aws_akid();
        let token: String = Redactor::new().token(secret.as_str());
        let mut value: serde_json::Value = serde_json::json!({
            "wrapper": {
                secret: 1,
                token: 2
            }
        });
        let original: serde_json::Value = value.clone();

        let error: RedactionError = Redactor::new()
            .redact_json_value(&mut value)
            .expect_err("duplicate redacted keys must be refused");

        assert_eq!(error, RedactionError::DuplicateObjectKey);
        assert_eq!(value, original);
    }
}
