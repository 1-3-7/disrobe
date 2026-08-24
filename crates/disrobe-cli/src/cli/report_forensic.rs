#![cfg(feature = "chain")]
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use disrobe_core::behavior::{BehaviorReport, CategoryFinding};
use disrobe_core::interop::{
    ArtifactSchema, IndicatorAggregator, IndicatorBundle, IndicatorClass, UnifiedIndicator,
};
use disrobe_core::ioc::{Indicator as IocIndicator, IocReport};
use serde_json::{Map, Value, json};

use super::llm::iso8601_millis_from_epoch;
use super::report::{
    BatchReport, EvidenceItem, EvidenceRole, FailureView, HashSource, ReportDocument, SingleReport,
    WallView,
};
use super::report_html::{Enrichment, enrich_single};
use super::sarif::{
    ArtifactLocation, ArtifactRole, Driver, Invocation, Location, Message,
    MultiformatMessageString, PhysicalLocation, Region, ReportingDescriptor, ResultKind, Run,
    RunAutomationDetails, SarifArtifact, SarifLevel, SarifLog, SarifResult, Tool,
};

const STIX_SPEC_VERSION: &str = "2.1";
const MAEC_SCHEMA_VERSION: &str = "5.0";
const SARIF_SPEC_VERSION: &str = "2.1.0";
const CYCLONEDX_SPEC_VERSION: &str = "1.5";
const STIX_PATTERN_TYPE: &str = "stix";
const ATTACK_SOURCE_NAME: &str = "mitre-attack";
const PRODUCER_NAME: &str = "disrobe";
const RULE_STAGE: &str = "disrobe.stage";
const RULE_WALL: &str = "disrobe.wall";
const RULE_FAILURE: &str = "disrobe.failure";
const RULE_EVIDENCE: &str = "disrobe.evidence";
const RULE_INDICATOR: &str = "disrobe.indicator";
const RULE_BEHAVIOR: &str = "disrobe.behavior";
const RULE_BATCH_FILE: &str = "disrobe.batch-file";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimestampSource {
    SystemClock,
    SourceDateEpoch,
}

impl TimestampSource {
    const fn label(self) -> &'static str {
        match self {
            Self::SystemClock => "system-clock",
            Self::SourceDateEpoch => "source-date-epoch",
        }
    }
}

#[derive(Debug, Clone)]
struct Generated {
    at: String,
    source: TimestampSource,
}

fn generated() -> Generated {
    let source: TimestampSource = if std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .is_some_and(|raw: String| raw.parse::<u64>().is_ok())
    {
        TimestampSource::SourceDateEpoch
    } else {
        TimestampSource::SystemClock
    };
    Generated {
        at: iso8601_millis_from_epoch(disrobe_core::time::now_secs()),
        source,
    }
}

fn deterministic_uuid(seed: &str) -> String {
    let digest: blake3::Hash = blake3::hash(seed.as_bytes());
    let source: &[u8; 32] = digest.as_bytes();
    let mut raw: [u8; 16] = [0u8; 16];
    raw.copy_from_slice(&source[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let hex: String = super::util::hex_bytes(raw);
    let mut out: String = String::with_capacity(36);
    for (index, ch) in hex.chars().enumerate() {
        if matches!(index, 8 | 12 | 16 | 20) {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

fn stix_id(object_type: &str, seed: &str) -> String {
    format!("{object_type}--{}", deterministic_uuid(seed))
}

fn checked_span(offset: u64, length: u64, artifact_length: Option<u64>) -> Option<Region> {
    let end: u64 = offset.checked_add(length)?;
    match artifact_length {
        Some(limit) if end > limit => None,
        _ => Some(Region::byte_span(offset, length)),
    }
}

fn quote_stix_literal(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('\'', "\\'")
}

const fn stix_object_path(class: IndicatorClass) -> Option<&'static str> {
    match class {
        IndicatorClass::Url => Some("url:value"),
        IndicatorClass::Domain => Some("domain-name:value"),
        IndicatorClass::Ipv4 => Some("ipv4-addr:value"),
        IndicatorClass::Ipv6 => Some("ipv6-addr:value"),
        IndicatorClass::Email => Some("email-addr:value"),
        IndicatorClass::Registry => Some("windows-registry-key:key"),
        IndicatorClass::Hash
        | IndicatorClass::Asn
        | IndicatorClass::Wallet
        | IndicatorClass::Path
        | IndicatorClass::Secret
        | IndicatorClass::Other => None,
    }
}

fn attack_reference(technique: &str) -> Value {
    json!({
        "source_name": ATTACK_SOURCE_NAME,
        "external_id": technique,
        "url": format!("https://attack.mitre.org/techniques/{technique}/"),
    })
}

#[derive(Debug, Default)]
struct ArtifactTable {
    order: BTreeMap<String, usize>,
    entries: Vec<SarifArtifact>,
}

#[derive(Debug)]
struct MergedArtifact {
    length: Option<u64>,
    blake3: Option<String>,
    roles: BTreeSet<ArtifactRole>,
    display: String,
}

impl ArtifactTable {
    fn from_evidence(evidence: &[EvidenceItem]) -> Self {
        let mut merged: BTreeMap<String, MergedArtifact> = BTreeMap::new();
        for item in evidence {
            let role: ArtifactRole = match item.role {
                EvidenceRole::AnalysisTarget => ArtifactRole::AnalysisTarget,
                EvidenceRole::RecoveredArtifact => ArtifactRole::ResultFile,
                EvidenceRole::StageInput | EvidenceRole::StageOutput => ArtifactRole::Unmodified,
            };
            let slot: &mut MergedArtifact =
                merged
                    .entry(item.uri.clone())
                    .or_insert_with(|| MergedArtifact {
                        length: None,
                        blake3: None,
                        roles: BTreeSet::new(),
                        display: item.display.clone(),
                    });
            if slot.length.is_none() {
                slot.length = item.byte_length;
            }
            if slot.blake3.is_none() {
                slot.blake3.clone_from(&item.blake3);
            }
            slot.roles.insert(role);
        }
        let mut order: BTreeMap<String, usize> = BTreeMap::new();
        let mut entries: Vec<SarifArtifact> = Vec::with_capacity(merged.len());
        for (uri, artifact) in merged {
            let mut hashes: BTreeMap<String, String> = BTreeMap::new();
            if let Some(digest) = artifact.blake3 {
                hashes.insert("blake3".to_string(), digest);
            }
            order.insert(uri.clone(), entries.len());
            entries.push(SarifArtifact {
                location: ArtifactLocation::at(uri),
                description: Some(Message {
                    text: artifact.display,
                }),
                length: artifact.length,
                roles: artifact.roles.into_iter().collect(),
                hashes,
            });
        }
        Self { order, entries }
    }

    fn locate(&self, uri: &str) -> Location {
        let index: Option<usize> = self.order.get(uri).copied();
        Location {
            physical_location: PhysicalLocation {
                artifact_location: index.map_or_else(
                    || ArtifactLocation::at(uri.to_string()),
                    |i: usize| ArtifactLocation::indexed(uri.to_string(), i),
                ),
                region: None,
            },
        }
    }

    fn locate_span(&self, uri: &str, region: Option<Region>) -> Location {
        let mut location: Location = self.locate(uri);
        location.physical_location.region = region;
        location
    }

    fn length_of(&self, uri: &str) -> Option<u64> {
        self.order
            .get(uri)
            .and_then(|index: &usize| self.entries.get(*index))
            .and_then(|artifact: &SarifArtifact| artifact.length)
    }
}

fn rule(id: &str, name: &str, description: &str) -> ReportingDescriptor {
    ReportingDescriptor {
        id: id.to_string(),
        name: Some(name.to_string()),
        short_description: Some(MultiformatMessageString {
            text: description.to_string(),
        }),
        full_description: None,
    }
}

fn rules_for(used: &BTreeSet<&'static str>) -> Vec<ReportingDescriptor> {
    used.iter()
        .map(|id: &&'static str| match *id {
            RULE_STAGE => rule(RULE_STAGE, "recovery stage", "one executed chain layer"),
            RULE_WALL => rule(
                RULE_WALL,
                "recovery wall",
                "a layer that stopped because a named input is missing",
            ),
            RULE_FAILURE => rule(
                RULE_FAILURE,
                "layer failure",
                "a layer that returned an error",
            ),
            RULE_EVIDENCE => rule(
                RULE_EVIDENCE,
                "cited artifact",
                "an artifact range a third party can re-check",
            ),
            RULE_INDICATOR => rule(
                RULE_INDICATOR,
                "extracted indicator",
                "a value read out of the analysis target",
            ),
            RULE_BEHAVIOR => rule(
                RULE_BEHAVIOR,
                "observed behavior",
                "a behavior category matched in the analysis target",
            ),
            other => rule(other, "batch entry", "one file of a batch run"),
        })
        .collect()
}

fn stage_results(report: &SingleReport, artifacts: &ArtifactTable) -> Vec<SarifResult> {
    report
        .stages
        .iter()
        .map(|stage: &super::report::StageView| SarifResult {
            rule_id: RULE_STAGE.to_string(),
            kind: Some(ResultKind::Informational),
            level: SarifLevel::None,
            message: Message {
                text: format!(
                    "stage {} `{}` returned {} at confidence {}",
                    stage.index, stage.pass, stage.verdict, stage.confidence
                ),
            },
            locations: stage_location(report, stage, artifacts),
            properties: Some(json!({
                "stage_index": stage.index,
                "node_id": stage.node_id,
                "pass": stage.pass,
                "confidence": stage.confidence,
                "recovery_score": stage.recovery_score,
                "format_in": stage.format_in,
                "format_out": stage.format_out,
                "artifacts": stage.artifacts,
            })),
        })
        .collect()
}

fn stage_location(
    report: &SingleReport,
    stage: &super::report::StageView,
    artifacts: &ArtifactTable,
) -> Vec<Location> {
    report
        .evidence
        .iter()
        .find(|item: &&EvidenceItem| {
            item.role == EvidenceRole::StageInput && item.stage_index == Some(stage.index)
        })
        .map(|item: &EvidenceItem| {
            let region: Option<Region> = item
                .byte_length
                .and_then(|length: u64| checked_span(item.byte_offset, length, item.byte_length));
            vec![artifacts.locate_span(&item.uri, region)]
        })
        .unwrap_or_default()
}

fn wall_results(report: &SingleReport, artifacts: &ArtifactTable) -> Vec<SarifResult> {
    report
        .walls
        .iter()
        .map(|wall: &WallView| {
            let uri: String = content_uri_of(&wall.artifact_blake3);
            let region: Option<Region> = checked_span(
                0,
                wall.artifact_size,
                artifacts.length_of(&uri).or(Some(wall.artifact_size)),
            );
            SarifResult {
                rule_id: RULE_WALL.to_string(),
                kind: Some(ResultKind::Review),
                level: SarifLevel::None,
                message: Message {
                    text: format!("{}: {}", wall.kind.label(), wall.missing),
                },
                locations: vec![artifacts.locate_span(&uri, region)],
                properties: Some(json!({
                    "wall_kind": wall.kind.label(),
                    "node_id": wall.node_id,
                    "stage_index": wall.stage_index,
                    "pass": wall.pass,
                    "format_in": wall.format_in,
                    "missing_input": wall.missing,
                    "artifact_blake3": wall.artifact_blake3,
                    "artifact_size": wall.artifact_size,
                })),
            }
        })
        .collect()
}

fn failure_results(report: &SingleReport, artifacts: &ArtifactTable) -> Vec<SarifResult> {
    report
        .failures
        .iter()
        .map(|failure: &FailureView| {
            let uri: String = content_uri_of(&failure.artifact_blake3);
            SarifResult {
                rule_id: RULE_FAILURE.to_string(),
                kind: Some(ResultKind::Fail),
                level: SarifLevel::Error,
                message: Message {
                    text: format!(
                        "node {} `{}` failed: {}",
                        failure.node_id,
                        failure.pass.as_deref().unwrap_or("terminal"),
                        failure.message
                    ),
                },
                locations: vec![artifacts.locate(&uri)],
                properties: Some(json!({
                    "node_id": failure.node_id,
                    "stage_index": failure.stage_index,
                    "pass": failure.pass,
                    "artifact_blake3": failure.artifact_blake3,
                    "artifact_size": failure.artifact_size,
                })),
            }
        })
        .collect()
}

fn evidence_results(report: &SingleReport, artifacts: &ArtifactTable) -> Vec<SarifResult> {
    report
        .evidence
        .iter()
        .map(|item: &EvidenceItem| {
            let region: Option<Region> = item
                .byte_length
                .and_then(|length: u64| checked_span(item.byte_offset, length, Some(length)));
            let text: String = match (&item.blake3, &item.unavailable_reason) {
                (Some(digest), _) => format!(
                    "{} `{}` is {} bytes from offset {} with blake3 {digest} ({})",
                    item.role.label(),
                    item.uri,
                    item.byte_length.map_or_else(
                        || "an unknown number of".to_string(),
                        |l: u64| l.to_string()
                    ),
                    item.byte_offset,
                    item.hash_source.label()
                ),
                (None, Some(reason)) => format!(
                    "{} `{}` carries no digest: {reason}",
                    item.role.label(),
                    item.uri
                ),
                (None, None) => format!(
                    "{} `{}` carries no digest and no reason was recorded",
                    item.role.label(),
                    item.uri
                ),
            };
            SarifResult {
                rule_id: RULE_EVIDENCE.to_string(),
                kind: Some(if item.hash_source == HashSource::Unavailable {
                    ResultKind::Review
                } else {
                    ResultKind::Informational
                }),
                level: SarifLevel::None,
                message: Message { text },
                locations: vec![artifacts.locate_span(&item.uri, region)],
                properties: Some(json!({
                    "role": item.role.label(),
                    "digest_source": item.hash_source.label(),
                    "blake3": item.blake3,
                    "byte_offset": item.byte_offset,
                    "byte_length": item.byte_length,
                    "stage_index": item.stage_index,
                    "node_id": item.node_id,
                    "unavailable_reason": item.unavailable_reason,
                })),
            }
        })
        .collect()
}

fn indicator_results(
    ioc: &IocReport,
    target_uri: &str,
    artifacts: &ArtifactTable,
) -> Vec<SarifResult> {
    let target_length: Option<u64> = artifacts.length_of(target_uri);
    ioc.indicators
        .iter()
        .map(|indicator: &IocIndicator| {
            let offset: u64 = indicator.offset as u64;
            let length: u64 = indicator.value.len() as u64;
            let region: Option<Region> = checked_span(offset, length, target_length);
            let outside: bool = region.is_none();
            let text: String = if outside {
                format!(
                    "{} ({}) `{}` reports offset {offset} length {length}, which lies outside the analysis target",
                    indicator.kind.label(),
                    indicator.encoding.label(),
                    indicator.value
                )
            } else {
                format!(
                    "{} ({}) `{}` at byte {offset} for {length} bytes",
                    indicator.kind.label(),
                    indicator.encoding.label(),
                    indicator.value
                )
            };
            SarifResult {
                rule_id: RULE_INDICATOR.to_string(),
                kind: Some(ResultKind::Informational),
                level: SarifLevel::None,
                message: Message { text },
                locations: vec![artifacts.locate_span(target_uri, region)],
                properties: Some(json!({
                    "indicator_kind": indicator.kind.label(),
                    "encoding": indicator.encoding.label(),
                    "value": indicator.value,
                    "byte_offset": offset,
                    "byte_length": length,
                    "range_within_target": !outside,
                })),
            }
        })
        .collect()
}

fn behavior_results(
    behavior: &BehaviorReport,
    target_uri: &str,
    artifacts: &ArtifactTable,
) -> Vec<SarifResult> {
    behavior
        .categories
        .iter()
        .map(|finding: &CategoryFinding| SarifResult {
            rule_id: RULE_BEHAVIOR.to_string(),
            kind: Some(ResultKind::Review),
            level: SarifLevel::None,
            message: Message {
                text: format!("{}: {}", finding.category.label(), finding.description),
            },
            locations: vec![artifacts.locate(target_uri)],
            properties: Some(json!({
                "category": finding.category.label(),
                "attack_ids": finding.attack_ids,
                "evidence": finding
                    .evidence
                    .iter()
                    .map(|e: &disrobe_core::behavior::Evidence| json!({
                        "signal": e.signal,
                        "source": e.source,
                        "attack_id": e.attack_id,
                    }))
                    .collect::<Vec<Value>>(),
            })),
        })
        .collect()
}

fn content_uri_of(blake3: &str) -> String {
    format!("ni:///blake3;{blake3}")
}

fn target_uri_of(report: &SingleReport) -> String {
    report
        .evidence
        .iter()
        .find(|item: &&EvidenceItem| item.role == EvidenceRole::AnalysisTarget)
        .map_or_else(
            || content_uri_of(&report.input.blake3),
            |item: &EvidenceItem| item.uri.clone(),
        )
}

fn unified_indicators(ioc: Option<&IocReport>) -> Option<IndicatorBundle> {
    let report: &IocReport = ioc?;
    let encoded: String = serde_json::to_string(report).ok()?;
    let mut aggregator: IndicatorAggregator = IndicatorAggregator::new();
    let schema: Option<ArtifactSchema> = aggregator.ingest_json(&encoded);
    schema?;
    Some(aggregator.finish())
}

fn stix_bundle(
    report: &SingleReport,
    generated: &Generated,
    indicators: Option<&IndicatorBundle>,
    behavior: Option<&BehaviorReport>,
) -> (Value, Vec<String>) {
    let identity_id: String = stix_id("identity", "disrobe/identity/v1");
    let mut objects: Vec<Value> = vec![json!({
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": identity_id,
        "created": generated.at,
        "modified": generated.at,
        "name": PRODUCER_NAME,
        "identity_class": "system",
        "description": "static recovery of readable source, structure and unpacked bytes",
    })];

    let mut analysis: Map<String, Value> = Map::new();
    analysis.insert("type".to_string(), json!("malware-analysis"));
    analysis.insert("spec_version".to_string(), json!(STIX_SPEC_VERSION));
    analysis.insert(
        "id".to_string(),
        json!(stix_id(
            "malware-analysis",
            &format!("disrobe/analysis/{}", report.input.blake3)
        )),
    );
    analysis.insert("created".to_string(), json!(generated.at));
    analysis.insert("modified".to_string(), json!(generated.at));
    analysis.insert("created_by_ref".to_string(), json!(identity_id));
    analysis.insert("product".to_string(), json!(PRODUCER_NAME));
    analysis.insert("version".to_string(), json!(report.tool_version));
    analysis.insert("analysis_started".to_string(), json!(generated.at));
    analysis.insert("analysis_ended".to_string(), json!(generated.at));
    analysis.insert("result".to_string(), json!("unknown"));
    analysis.insert(
        "x_disrobe_result_basis".to_string(),
        json!("disrobe performs deterministic static recovery and never classifies a sample, so the malware-av-result-ov value stays `unknown`"),
    );
    analysis.insert("x_disrobe_verdict".to_string(), json!(report.verdict));
    analysis.insert(
        "x_disrobe_recovery_score".to_string(),
        json!(report.recovery_score),
    );
    analysis.insert(
        "x_disrobe_input_blake3".to_string(),
        json!(report.input.blake3),
    );
    analysis.insert("x_disrobe_input_size".to_string(), json!(report.input.size));
    analysis.insert(
        "x_disrobe_wall_count".to_string(),
        json!(report.walls.len()),
    );
    if !report.stages.is_empty() {
        analysis.insert(
            "modules".to_string(),
            json!(
                report
                    .stages
                    .iter()
                    .map(|s: &super::report::StageView| s.pass.clone())
                    .collect::<Vec<String>>()
            ),
        );
    }
    let attack_ids: BTreeSet<&str> = behavior.map_or_else(BTreeSet::new, |b: &BehaviorReport| {
        b.attack_ids.iter().copied().collect()
    });
    if !attack_ids.is_empty() {
        analysis.insert(
            "external_references".to_string(),
            json!(
                attack_ids
                    .iter()
                    .map(|id: &&str| attack_reference(id))
                    .collect::<Vec<Value>>()
            ),
        );
    }
    objects.push(Value::Object(analysis));

    let mut unmapped: BTreeMap<&'static str, usize> = BTreeMap::new();
    if let Some(bundle) = indicators {
        for indicator in &bundle.indicators {
            let Some(path): Option<&'static str> = stix_object_path(indicator.class) else {
                *unmapped.entry(indicator.class.label()).or_insert(0) += 1;
                continue;
            };
            objects.push(indicator_object(
                indicator,
                path,
                &identity_id,
                generated,
                &report.input.blake3,
            ));
        }
    }

    let bundle: Value = json!({
        "type": "bundle",
        "id": stix_id("bundle", &format!("disrobe/bundle/{}", report.input.blake3)),
        "objects": objects,
    });
    let unmapped_notes: Vec<String> = unmapped
        .into_iter()
        .map(|(class, count): (&'static str, usize)| {
            format!("{count} `{class}` indicators have no STIX 2.1 pattern object path and stay in the sarif results only")
        })
        .collect();
    (bundle, unmapped_notes)
}

fn indicator_object(
    indicator: &UnifiedIndicator,
    object_path: &str,
    identity_id: &str,
    generated: &Generated,
    input_blake3: &str,
) -> Value {
    let pattern: String = format!(
        "[{object_path} = '{}']",
        quote_stix_literal(&indicator.value)
    );
    json!({
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id("indicator", &format!("disrobe/indicator/{input_blake3}/{pattern}")),
        "created": generated.at,
        "modified": generated.at,
        "created_by_ref": identity_id,
        "name": format!("{} observed by static recovery", indicator.class.label()),
        "description": format!(
            "read from the analysis target by {}",
            indicator.sources.join(", ")
        ),
        "indicator_types": ["unknown"],
        "pattern": pattern,
        "pattern_type": STIX_PATTERN_TYPE,
        "valid_from": generated.at,
    })
}

fn maec_package(
    report: &SingleReport,
    behavior: Option<&BehaviorReport>,
    generated: &Generated,
) -> Value {
    let Some(behavior): Option<&BehaviorReport> = behavior else {
        return json!({
            "available": false,
            "reason": "the analysis target was not readable, so no behavior categories were derived",
        });
    };
    if behavior.categories.is_empty() {
        return json!({
            "available": false,
            "reason": "the analysis target matched no behavior category",
        });
    }
    let objects: Vec<Value> = behavior
        .categories
        .iter()
        .map(|finding: &CategoryFinding| {
            let mut object: Map<String, Value> = Map::new();
            object.insert("type".to_string(), json!("behavior"));
            object.insert(
                "id".to_string(),
                json!(format!(
                    "behavior--{}",
                    deterministic_uuid(&format!(
                        "disrobe/behavior/{}/{}",
                        report.input.blake3,
                        finding.category.label()
                    ))
                )),
            );
            object.insert("name".to_string(), json!(finding.category.label()));
            object.insert("description".to_string(), json!(finding.description));
            object.insert("timestamp".to_string(), json!(generated.at));
            if !finding.attack_ids.is_empty() {
                object.insert(
                    "technique_refs".to_string(),
                    json!(
                        finding
                            .attack_ids
                            .iter()
                            .map(|id: &&str| attack_reference(id))
                            .collect::<Vec<Value>>()
                    ),
                );
            }
            Value::Object(object)
        })
        .collect();
    json!({
        "available": true,
        "package": {
            "type": "package",
            "id": format!(
                "package--{}",
                deterministic_uuid(&format!("disrobe/package/{}", report.input.blake3))
            ),
            "schema_version": MAEC_SCHEMA_VERSION,
            "maec_objects": objects,
        },
    })
}

fn standards_block(generated: &Generated, unmapped: &[String]) -> Value {
    json!({
        "sarif": { "version": SARIF_SPEC_VERSION },
        "stix": {
            "version": STIX_SPEC_VERSION,
            "identifier_derivation": "every identifier is the first 16 bytes of blake3 over a stable seed, stamped with the RFC 9562 version 4 and variant bits, so repeated runs over one input produce one identifier; no UUIDv5 name-based identifier is produced because this build has no SHA-1",
            "unmapped_indicator_classes": unmapped,
        },
        "maec": { "version": MAEC_SCHEMA_VERSION },
        "cyclonedx": {
            "version": CYCLONEDX_SPEC_VERSION,
            "emitted_by": "disrobe sbom --format cyclonedx",
        },
        "excluded": [
            { "standard": "OpenIOC 1.1", "reason": "superseded by STIX 2.1 patterning" },
            { "standard": "CybOX 2.x", "reason": "folded into STIX 2.1 cyber-observable objects" }
        ],
        "timestamp": {
            "field": "generated_at",
            "source": generated.source.label(),
            "note": "every timestamp in this document holds the value of generated_at; set SOURCE_DATE_EPOCH to fix it",
        },
    })
}

fn capabilities_block(report: &SingleReport) -> Value {
    match (
        report.capabilities.available,
        report.capabilities.report.as_ref(),
        report.capabilities.reason.as_deref(),
    ) {
        (true, Some(capabilities), _) => json!({
            "available": true,
            "report": capabilities,
        }),
        (_, _, Some(reason)) => json!({
            "available": false,
            "reason": reason,
        }),
        _ => json!({
            "available": false,
            "reason": "no capability report was produced",
        }),
    }
}

fn single_run(document: &ReportDocument, report: &SingleReport, generated: &Generated) -> Run {
    let enrichment: Enrichment = enrich_single(report);
    let artifacts: ArtifactTable = ArtifactTable::from_evidence(&report.evidence);
    let target_uri: String = target_uri_of(report);
    let mut used: BTreeSet<&'static str> = BTreeSet::new();
    let mut results: Vec<SarifResult> = Vec::new();

    if !report.stages.is_empty() {
        used.insert(RULE_STAGE);
        results.extend(stage_results(report, &artifacts));
    }
    if !report.walls.is_empty() {
        used.insert(RULE_WALL);
        results.extend(wall_results(report, &artifacts));
    }
    if !report.failures.is_empty() {
        used.insert(RULE_FAILURE);
        results.extend(failure_results(report, &artifacts));
    }
    if !report.evidence.is_empty() {
        used.insert(RULE_EVIDENCE);
        results.extend(evidence_results(report, &artifacts));
    }
    if let Some(ioc) = enrichment.ioc.as_ref()
        && !ioc.indicators.is_empty()
    {
        used.insert(RULE_INDICATOR);
        results.extend(indicator_results(ioc, &target_uri, &artifacts));
    }
    if let Some(behavior) = enrichment.behavior.as_ref()
        && !behavior.categories.is_empty()
    {
        used.insert(RULE_BEHAVIOR);
        results.extend(behavior_results(behavior, &target_uri, &artifacts));
    }

    let indicators: Option<IndicatorBundle> = unified_indicators(enrichment.ioc.as_ref());
    let (bundle, unmapped): (Value, Vec<String>) = stix_bundle(
        report,
        generated,
        indicators.as_ref(),
        enrichment.behavior.as_ref(),
    );
    let properties: Value = json!({
        "generated_at": generated.at,
        "disrobe": document,
        "stix": { "available": true, "bundle": bundle },
        "maec": maec_package(report, enrichment.behavior.as_ref(), generated),
        "capabilities": capabilities_block(report),
        "indicators": indicators.as_ref().map_or_else(
            || json!({
                "available": false,
                "reason": "the analysis target was not readable, so no indicators were aggregated",
            }),
            |bundle: &IndicatorBundle| json!({ "available": true, "bundle": bundle }),
        ),
        "reproduction": report.reproduction,
        "standards": standards_block(generated, &unmapped),
    });

    Run {
        tool: Tool {
            driver: Driver::disrobe(rules_for(&used)),
        },
        automation_details: Some(RunAutomationDetails {
            id: format!("disrobe/report/{}", report.input.blake3),
        }),
        invocations: vec![Invocation {
            execution_successful: report.failures.is_empty(),
            arguments: Vec::new(),
            command_line: Some(report.reproduction.command.clone()),
            end_time_utc: Some(generated.at.clone()),
        }],
        artifacts: artifacts.entries,
        results,
        properties: Some(properties),
    }
}

fn batch_run(document: &ReportDocument, report: &BatchReport, generated: &Generated) -> Run {
    let mut order: BTreeMap<String, usize> = BTreeMap::new();
    let mut entries: Vec<SarifArtifact> = Vec::with_capacity(report.files.len());
    for file in &report.files {
        let uri: String = super::sarif::artifact_uri(Path::new(&file.relative));
        if order.contains_key(&uri) {
            continue;
        }
        order.insert(uri.clone(), entries.len());
        entries.push(SarifArtifact {
            location: ArtifactLocation::at(uri),
            description: Some(Message {
                text: file.relative.clone(),
            }),
            length: None,
            roles: vec![ArtifactRole::AnalysisTarget],
            hashes: BTreeMap::new(),
        });
    }
    let results: Vec<SarifResult> = report
        .files
        .iter()
        .map(|file: &super::report::BatchFileView| {
            let uri: String = super::sarif::artifact_uri(Path::new(&file.relative));
            let index: Option<usize> = order.get(&uri).copied();
            let failed: bool = file.error.is_some();
            SarifResult {
                rule_id: RULE_BATCH_FILE.to_string(),
                kind: Some(if failed {
                    ResultKind::Fail
                } else {
                    ResultKind::Informational
                }),
                level: if failed {
                    SarifLevel::Error
                } else {
                    SarifLevel::None
                },
                message: Message {
                    text: file.error.as_ref().map_or_else(
                        || {
                            format!(
                                "{} ran chain [{}] with verdict {}",
                                file.relative,
                                file.chain.join(" -> "),
                                file.verdict.as_deref().unwrap_or("none")
                            )
                        },
                        |error: &String| format!("{} failed: {error}", file.relative),
                    ),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: index.map_or_else(
                            || ArtifactLocation::at(uri.clone()),
                            |i: usize| ArtifactLocation::indexed(uri.clone(), i),
                        ),
                        region: None,
                    },
                }],
                properties: Some(json!({
                    "detected_format": file.detected_format,
                    "chain": file.chain,
                    "verdict": file.verdict,
                    "recovery_score": file.recovery_score,
                    "duration_ms": file.duration_ms,
                    "error": file.error,
                })),
            }
        })
        .collect();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();
    if !results.is_empty() {
        used.insert(RULE_BATCH_FILE);
    }
    let properties: Value = json!({
        "generated_at": generated.at,
        "disrobe": document,
        "stix": {
            "available": false,
            "reason": "a batch report aggregates per-file manifests and holds no analysis-target bytes to observe",
        },
        "maec": {
            "available": false,
            "reason": "a batch report aggregates per-file manifests and holds no analysis-target bytes to observe",
        },
        "capabilities": {
            "available": false,
            "reason": "a batch report aggregates per-file manifests and holds no analysis-target bytes to observe",
        },
        "indicators": {
            "available": false,
            "reason": "a batch report aggregates per-file manifests and holds no analysis-target bytes to observe",
        },
        "standards": standards_block(generated, &[]),
    });
    Run {
        tool: Tool {
            driver: Driver::disrobe(rules_for(&used)),
        },
        automation_details: Some(RunAutomationDetails {
            id: format!("disrobe/report/batch/{}", report.root),
        }),
        invocations: vec![Invocation {
            execution_successful: report.errors == 0,
            arguments: Vec::new(),
            command_line: Some(format!("disrobe report {}", report.source_dir)),
            end_time_utc: Some(generated.at.clone()),
        }],
        artifacts: entries,
        results,
        properties: Some(properties),
    }
}

pub(crate) fn render_sarif(document: &ReportDocument) -> miette::Result<String> {
    let generated: Generated = generated();
    let run: Run = match document {
        ReportDocument::Single(report) => single_run(document, report, &generated),
        ReportDocument::Batch(report) => batch_run(document, report, &generated),
    };
    let log: SarifLog = SarifLog::from_run(run);
    serde_json::to_string_pretty(&log)
        .map_err(|e| miette::miette!("DR-CLI-0359: forensic report serialize: {e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_stable_and_carry_the_version_four_form() {
        let first: String = deterministic_uuid("disrobe/identity/v1");
        let second: String = deterministic_uuid("disrobe/identity/v1");
        assert_eq!(first, second);
        assert_ne!(first, deterministic_uuid("disrobe/identity/v2"));
        assert_eq!(first.len(), 36);
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(
            parts.iter().map(|p: &&str| p.len()).collect::<Vec<usize>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'), "version nibble: {first}");
        assert!(
            ['8', '9', 'a', 'b'].contains(&parts[3].chars().next().expect("variant nibble")),
            "variant nibble: {first}"
        );
    }

    #[test]
    fn a_span_that_leaves_the_artifact_is_refused_rather_than_cited() {
        assert!(checked_span(0, 16, Some(16)).is_some());
        assert!(checked_span(8, 8, Some(16)).is_some());
        assert!(checked_span(9, 8, Some(16)).is_none());
        assert!(checked_span(u64::MAX, 1, None).is_none());
        assert!(checked_span(0, 0, Some(0)).is_some());
    }

    #[test]
    fn stix_string_literals_escape_the_pattern_delimiters() {
        assert_eq!(quote_stix_literal(r"a'b"), r"a\'b");
        assert_eq!(quote_stix_literal(r"a\b"), r"a\\b");
        assert_eq!(quote_stix_literal(r"a\'b"), r"a\\\'b");
    }

    #[test]
    fn every_indicator_class_is_mapped_or_named_as_unmapped() {
        for class in [
            IndicatorClass::Url,
            IndicatorClass::Domain,
            IndicatorClass::Ipv4,
            IndicatorClass::Ipv6,
            IndicatorClass::Email,
            IndicatorClass::Registry,
        ] {
            assert!(stix_object_path(class).is_some(), "{class:?}");
        }
        for class in [
            IndicatorClass::Hash,
            IndicatorClass::Asn,
            IndicatorClass::Wallet,
            IndicatorClass::Path,
            IndicatorClass::Secret,
            IndicatorClass::Other,
        ] {
            assert!(stix_object_path(class).is_none(), "{class:?}");
        }
    }
}
