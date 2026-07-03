use std::collections::BTreeSet;

use aho_corasick::{AhoCorasick, MatchKind};

use super::{ReconCategory, ReconFinding, ReconReport};

#[cfg(not(target_arch = "wasm32"))]
use super::git_history::{GitFinding, GitHistoryReport};

const REDACT_KDF_CONTEXT: &str = "disrobe.frisk.redact v1 sentinel key";

/// Rewrites detected secrets to non-reversible blake3 sentinels before serialization.
#[derive(Debug, Clone)]
pub struct Redactor {
    key: [u8; 32],
}

impl Redactor {
    /// Per-run redactor keyed by random OS entropy (tokens differ every run).
    #[must_use]
    pub fn with_random_key() -> Self {
        use rand::RngExt as _;
        let key: [u8; 32] = crate::rng::os().random();
        Self { key }
    }

    /// Cross-run-stable redactor keyed from `user_key` via the blake3 KDF.
    #[must_use]
    pub fn with_key(user_key: &str) -> Self {
        Self {
            key: blake3::derive_key(REDACT_KDF_CONTEXT, user_key.as_bytes()),
        }
    }

    fn token(&self, secret: &str) -> String {
        let digest: blake3::Hash = blake3::keyed_hash(&self.key, secret.as_bytes());
        let b: &[u8; 32] = digest.as_bytes();
        format!(
            "[REDACTED:{:02x}{:02x}{:02x}{:02x}]",
            b[0], b[1], b[2], b[3]
        )
    }

    /// Redacts a working-tree recon report in place.
    pub fn redact_report(&self, report: &mut ReconReport) {
        let scrubber: Scrubber = self.scrubber(secret_values(&report.findings));
        for finding in &mut report.findings {
            redact_finding(finding, &scrubber);
        }
    }

    /// Redacts a git-history recon report in place.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn redact_git_report(&self, report: &mut GitHistoryReport) {
        let secrets: BTreeSet<String> = report
            .findings
            .iter()
            .filter(|gf: &&GitFinding| gf.finding.category == ReconCategory::Secret)
            .map(|gf: &GitFinding| gf.finding.value.clone())
            .filter(|v: &String| !v.is_empty())
            .collect();
        let scrubber: Scrubber = self.scrubber(secrets);
        for gf in &mut report.findings {
            redact_git_finding(gf, &scrubber);
        }
    }

    fn scrubber(&self, secrets: BTreeSet<String>) -> Scrubber {
        let mut patterns: Vec<String> = secrets
            .into_iter()
            .filter(|s: &String| !s.is_empty())
            .collect();
        patterns.sort_by(|a: &String, b: &String| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let tokens: Vec<String> = patterns.iter().map(|s: &String| self.token(s)).collect();
        let automaton: Option<AhoCorasick> = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .ok()
        };
        Scrubber {
            automaton,
            patterns,
            tokens,
        }
    }
}

fn secret_values(findings: &[ReconFinding]) -> BTreeSet<String> {
    findings
        .iter()
        .filter(|f: &&ReconFinding| f.category == ReconCategory::Secret)
        .map(|f: &ReconFinding| f.value.clone())
        .filter(|v: &String| !v.is_empty())
        .collect()
}

/// Leftmost-longest Aho-Corasick replacer mapping each secret to its sentinel in one pass.
struct Scrubber {
    automaton: Option<AhoCorasick>,
    patterns: Vec<String>,
    tokens: Vec<String>,
}

impl Scrubber {
    fn scrub(&self, input: &str) -> String {
        self.automaton.as_ref().map_or_else(
            || {
                let mut out: String = input.to_owned();
                for (pattern, token) in self.patterns.iter().zip(self.tokens.iter()) {
                    out = out.replace(pattern.as_str(), token.as_str());
                }
                out
            },
            |automaton: &AhoCorasick| automaton.replace_all(input, &self.tokens),
        )
    }
}

fn redact_finding(finding: &mut ReconFinding, scrubber: &Scrubber) {
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
fn redact_git_finding(gf: &mut GitFinding, scrubber: &Scrubber) {
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

        Redactor::with_key("k").redact_report(&mut report);

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
    fn keyed_tokens_are_stable_and_key_scoped() {
        let secret: String = aws_akid();
        let same_a: String = Redactor::with_key("shared").token(&secret);
        let same_b: String = Redactor::with_key("shared").token(&secret);
        let other: String = Redactor::with_key("different").token(&secret);
        assert_eq!(same_a, same_b, "same key + secret must be stable");
        assert_ne!(
            same_a, other,
            "a different key must yield a different token"
        );
        assert!(same_a.starts_with("[REDACTED:") && same_a.ends_with(']'));
    }
}
