use serde::Serialize;

#[cfg(feature = "pickle")]
use disrobe_pass_pickle::{Finding, SafetyReport, Severity};

const SARIF_SCHEMA_URI: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const DRIVER_NAME: &str = "disrobe";
const DRIVER_INFO_URI: &str = "https://github.com/1-3-7/disrobe";

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
    pub(crate) results: Vec<SarifResult>,
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MultiformatMessageString {
    pub(crate) text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SarifLevel {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SarifResult {
    pub(crate) rule_id: String,
    pub(crate) level: SarifLevel,
    pub(crate) message: Message,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) locations: Vec<Location>,
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
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Region {
    pub(crate) start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) end_column: Option<u32>,
}

impl SarifLog {
    #[inline]
    pub(crate) fn new(driver: Driver, results: Vec<SarifResult>) -> Self {
        Self {
            schema: SARIF_SCHEMA_URI,
            version: SARIF_VERSION,
            runs: vec![Run {
                tool: Tool { driver },
                results,
            }],
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
        })
        .collect();
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f: &Finding| SarifResult {
            rule_id: f.category.clone(),
            level: severity_to_level(f.severity),
            message: Message {
                text: f.offset.map_or_else(
                    || f.detail.clone(),
                    |off: usize| format!("{} (offset {off})", f.detail),
                ),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: artifact_uri.to_owned(),
                    },
                    region: None,
                },
            }],
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
    fn offset_appears_in_message_and_region_omitted() {
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
        assert!(
            r0["locations"][0]["physicalLocation"]
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
