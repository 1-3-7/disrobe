use std::path::Path;

use disrobe_core::codec::web_escape::{PercentEncodeSet, percent_encode_str};
use serde::Serialize;

#[cfg(feature = "pickle")]
use disrobe_pass_pickle::{Finding, SafetyReport, Severity};

const SARIF_SCHEMA_URI: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const DRIVER_NAME: &str = "disrobe";
const DRIVER_INFO_URI: &str = "https://github.com/1-3-7/disrobe";

pub(crate) fn artifact_uri(input: &Path) -> String {
    let path: String = input.display().to_string().replace('\\', "/");
    let encoded: String = percent_encode_str(&path, PercentEncodeSet::SARIF_ARTIFACT_URI);
    if path.starts_with('/') {
        return format!("file://{encoded}");
    }
    if path
        .as_bytes()
        .get(1)
        .is_some_and(|byte: &u8| *byte == b':')
    {
        return format!("file:///{encoded}");
    }
    encoded
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifLog {
    #[serde(rename = "$schema")]
    pub(crate) schema: &'static str,
    pub(crate) version: &'static str,
    pub(crate) runs: Vec<Run>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Run {
    pub(crate) tool: Tool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) automation_details: Option<RunAutomationDetails>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) invocations: Vec<Invocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) artifacts: Vec<SarifArtifact>,
    pub(crate) results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunAutomationDetails {
    pub(crate) id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Invocation {
    pub(crate) execution_successful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) arguments: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) end_time_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifArtifact {
    pub(crate) location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) length: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) roles: Vec<ArtifactRole>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) hashes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ArtifactRole {
    AnalysisTarget,
    ResultFile,
    Unmodified,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Tool {
    pub(crate) driver: Driver,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Driver {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) information_uri: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) rules: Vec<ReportingDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportingDescriptor {
    pub(crate) id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) short_description: Option<MultiformatMessageString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) full_description: Option<MultiformatMessageString>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MultiformatMessageString {
    pub(crate) text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ResultKind {
    Fail,
    Review,
    Informational,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifResult {
    pub(crate) rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kind: Option<ResultKind>,
    pub(crate) level: SarifLevel,
    pub(crate) message: Message,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Message {
    pub(crate) text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Location {
    pub(crate) physical_location: PhysicalLocation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhysicalLocation {
    pub(crate) artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) region: Option<Region>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactLocation {
    pub(crate) uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) index: Option<usize>,
}

impl ArtifactLocation {
    pub(crate) const fn at(uri: String) -> Self {
        Self { uri, index: None }
    }

    pub(crate) const fn indexed(uri: String, index: usize) -> Self {
        Self {
            uri,
            index: Some(index),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Region {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) end_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) byte_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) byte_length: Option<u64>,
}

impl Region {
    pub(crate) const fn line_col(line: u32, column: u32) -> Self {
        Self {
            start_line: Some(line),
            start_column: Some(column),
            end_line: None,
            end_column: None,
            byte_offset: None,
            byte_length: None,
        }
    }

    pub(crate) const fn at_byte_offset(offset: u64) -> Self {
        Self {
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            byte_offset: Some(offset),
            byte_length: None,
        }
    }

    pub(crate) const fn byte_span(offset: u64, length: u64) -> Self {
        Self {
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            byte_offset: Some(offset),
            byte_length: Some(length),
        }
    }

    #[must_use]
    pub(crate) const fn with_byte_offset(mut self, offset: u64) -> Self {
        self.byte_offset = Some(offset);
        self
    }
}

impl SarifLog {
    #[inline]
    pub(crate) fn new(driver: Driver, results: Vec<SarifResult>) -> Self {
        Self {
            schema: SARIF_SCHEMA_URI,
            version: SARIF_VERSION,
            runs: vec![Run {
                tool: Tool { driver },
                automation_details: None,
                invocations: Vec::new(),
                artifacts: Vec::new(),
                results,
                properties: None,
            }],
        }
    }

    #[inline]
    pub(crate) fn from_run(run: Run) -> Self {
        Self {
            schema: SARIF_SCHEMA_URI,
            version: SARIF_VERSION,
            runs: vec![run],
        }
    }
}

impl Driver {
    #[inline]
    pub(crate) const fn disrobe(rules: Vec<ReportingDescriptor>) -> Self {
        Self {
            name: DRIVER_NAME,
            version: env!("CARGO_PKG_VERSION"),
            information_uri: DRIVER_INFO_URI,
            rules,
        }
    }
}

#[cfg(feature = "pickle")]
#[inline]
const fn severity_to_level(sev: Severity) -> SarifLevel {
    match sev {
        Severity::Benign => SarifLevel::Note,
        Severity::Suspicious => SarifLevel::Warning,
        Severity::OvertlyMalicious => SarifLevel::Error,
    }
}

#[cfg(feature = "pickle")]
pub(crate) trait IntoSarif {
    fn to_sarif(&self, artifact_uri: &str) -> SarifLog;
}

#[cfg(feature = "pickle")]
pub(crate) fn from_findings(findings: &[Finding], artifact_uri: &str) -> SarifLog {
    let rule_ids: std::collections::BTreeSet<&str> = findings
        .iter()
        .map(|f: &Finding| f.category.as_str())
        .collect();
    let rules: Vec<ReportingDescriptor> = rule_ids
        .iter()
        .map(|id: &&str| ReportingDescriptor {
            id: (*id).to_owned(),
            name: Some((*id).to_owned()),
            short_description: None,
            full_description: None,
        })
        .collect();
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f: &Finding| SarifResult {
            rule_id: f.category.clone(),
            kind: None,
            level: severity_to_level(f.severity),
            message: Message {
                text: f.offset.map_or_else(
                    || f.detail.clone(),
                    |off: usize| format!("{} (offset {off})", f.detail),
                ),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation::at(artifact_uri.to_owned()),
                    region: f
                        .offset
                        .and_then(|off: usize| u64::try_from(off).ok().map(Region::at_byte_offset)),
                },
            }],
            properties: None,
        })
        .collect();
    SarifLog::new(Driver::disrobe(rules), results)
}

#[cfg(feature = "pickle")]
impl IntoSarif for SafetyReport {
    fn to_sarif(&self, artifact_uri: &str) -> SarifLog {
        from_findings(&self.findings, artifact_uri)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod uri_tests {
    use super::artifact_uri;
    use std::path::Path;

    #[test]
    fn artifact_uri_preserves_structure_and_encodes_reserved_path_bytes() {
        assert_eq!(
            artifact_uri(Path::new(r"C:\Program Files\a#b?.dll")),
            "file:///C:/Program%20Files/a%23b%3F.dll"
        );
        assert_eq!(
            artifact_uri(Path::new(r"\\server\share\a b")),
            "file:////server/share/a%20b"
        );
        assert_eq!(
            artifact_uri(Path::new("relative/a b/%")),
            "relative/a%20b/%25"
        );
        assert_eq!(
            artifact_uri(Path::new("relative/\u{00e9}")),
            "relative/%C3%A9"
        );
    }
}

#[cfg(all(test, feature = "pickle"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn finding(sev: Severity, cat: &str, detail: &str, offset: Option<usize>) -> Finding {
        Finding {
            severity: sev,
            category: cat.to_owned(),
            detail: detail.to_owned(),
            offset,
            confidence: disrobe_pass_pickle::ConfidenceTier::SignatureCertain,
        }
    }

    fn to_value(log: &SarifLog) -> Value {
        serde_json::to_value(log).expect("serialize sarif log")
    }

    #[test]
    fn full_shape_is_faithful() {
        let findings: Vec<Finding> = vec![
            finding(
                Severity::OvertlyMalicious,
                "reduce.payload",
                "os.system call",
                Some(12),
            ),
            finding(
                Severity::Suspicious,
                "global.suspicious_module",
                "imports pickle",
                None,
            ),
            finding(Severity::Benign, "memo.unused", "memo never read", None),
        ];
        let v: Value = to_value(&from_findings(&findings, "evil.pkl"));

        assert_eq!(v["version"], "2.1.0");
        assert_eq!(
            v["$schema"],
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        );
        let driver: &Value = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "disrobe");
        assert_eq!(driver["informationUri"], "https://github.com/1-3-7/disrobe");
        assert!(driver["version"].is_string());

        let rules: &Vec<Value> = driver["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 3);
        let rule_ids: std::collections::BTreeSet<&str> = rules
            .iter()
            .map(|r: &Value| r["id"].as_str().expect("rule id"))
            .collect();
        assert!(rule_ids.contains("reduce.payload"));
        assert!(rule_ids.contains("global.suspicious_module"));
        assert!(rule_ids.contains("memo.unused"));

        let results: &Vec<Value> = v["runs"][0]["results"].as_array().expect("results array");
        assert_eq!(results.len(), 3);
        let r0: &Value = &results[0];
        assert!(r0["ruleId"].is_string());
        assert!(r0["level"].is_string());
        assert!(r0["message"]["text"].is_string());
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "evil.pkl"
        );
    }

    #[test]
    fn severity_maps_to_sarif_levels() {
        let findings: Vec<Finding> = vec![
            finding(Severity::Benign, "a", "x", None),
            finding(Severity::Suspicious, "b", "y", None),
            finding(Severity::OvertlyMalicious, "c", "z", None),
        ];
        let v: Value = to_value(&from_findings(&findings, "f.pkl"));
        let results: &Vec<Value> = v["runs"][0]["results"].as_array().expect("results");
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "error");
    }

    #[test]
    fn empty_findings_is_valid_log_without_rules() {
        let v: Value = to_value(&from_findings(&[], "clean.pkl"));
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(
            v["runs"][0]["results"].as_array().expect("results").len(),
            0
        );
        assert!(v["runs"][0]["tool"]["driver"].get("rules").is_none());
    }

    #[test]
    fn offset_appears_in_message_and_region_byte_offset() {
        let v: Value = to_value(&from_findings(
            &[finding(
                Severity::OvertlyMalicious,
                "reduce.payload",
                "danger",
                Some(7),
            )],
            "f.pkl",
        ));
        let r0: &Value = &v["runs"][0]["results"][0];
        assert!(
            r0["message"]["text"]
                .as_str()
                .expect("text")
                .contains("offset 7")
        );
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["region"]["byteOffset"], 7,
            "a finding that knows its byte offset must place it in the sarif region"
        );
    }

    #[test]
    fn absent_offset_leaves_the_region_out() {
        let v: Value = to_value(&from_findings(
            &[finding(Severity::Benign, "memo.unused", "nothing", None)],
            "f.pkl",
        ));
        assert!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                .get("region")
                .is_none()
        );
    }

    #[test]
    fn duplicate_categories_dedup_into_one_rule() {
        let findings: Vec<Finding> = vec![
            finding(Severity::OvertlyMalicious, "reduce.payload", "a", None),
            finding(Severity::OvertlyMalicious, "reduce.payload", "b", None),
        ];
        let v: Value = to_value(&from_findings(&findings, "f.pkl"));
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules")
                .len(),
            1
        );
        assert_eq!(
            v["runs"][0]["results"].as_array().expect("results").len(),
            2
        );
    }
}
