#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::{Run, run_disrobe, temp_dir};
use jsonschema::{Resource, Validator};
use serde_json::Value;

const SARIF_SCHEMA: &str = include_str!("schemas/sarif-2.1.0.schema.json");

const STIX_BASE: &str =
    "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/";

const STIX_SCHEMAS: &[(&str, &str)] = &[
    (
        "common/binary.json",
        include_str!("schemas/stix-2.1/common/binary.json"),
    ),
    (
        "common/core.json",
        include_str!("schemas/stix-2.1/common/core.json"),
    ),
    (
        "common/dictionary.json",
        include_str!("schemas/stix-2.1/common/dictionary.json"),
    ),
    (
        "common/extension.json",
        include_str!("schemas/stix-2.1/common/extension.json"),
    ),
    (
        "common/external-reference.json",
        include_str!("schemas/stix-2.1/common/external-reference.json"),
    ),
    (
        "common/granular-marking.json",
        include_str!("schemas/stix-2.1/common/granular-marking.json"),
    ),
    (
        "common/hashes-type.json",
        include_str!("schemas/stix-2.1/common/hashes-type.json"),
    ),
    (
        "common/hex.json",
        include_str!("schemas/stix-2.1/common/hex.json"),
    ),
    (
        "common/identifier.json",
        include_str!("schemas/stix-2.1/common/identifier.json"),
    ),
    (
        "common/kill-chain-phase.json",
        include_str!("schemas/stix-2.1/common/kill-chain-phase.json"),
    ),
    (
        "common/properties.json",
        include_str!("schemas/stix-2.1/common/properties.json"),
    ),
    (
        "common/timestamp.json",
        include_str!("schemas/stix-2.1/common/timestamp.json"),
    ),
    (
        "common/url-regex.json",
        include_str!("schemas/stix-2.1/common/url-regex.json"),
    ),
    (
        "sdos/identity.json",
        include_str!("schemas/stix-2.1/sdos/identity.json"),
    ),
    (
        "sdos/indicator.json",
        include_str!("schemas/stix-2.1/sdos/indicator.json"),
    ),
    (
        "sdos/malware-analysis.json",
        include_str!("schemas/stix-2.1/sdos/malware-analysis.json"),
    ),
];

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(path, bytes).expect("write fixture");
}

fn run_auto_into(input: &Path, out: &Path) {
    let r: Run = run_disrobe(&[
        "auto",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "auto setup must succeed; stderr={}", r.stderr);
}

fn sarif_validator() -> Validator {
    let schema: Value = serde_json::from_str(SARIF_SCHEMA).expect("pinned sarif schema parses");
    jsonschema::validator_for(&schema).expect("pinned sarif schema compiles")
}

fn stix_validator(object_type: &str) -> Validator {
    let mut options: jsonschema::ValidationOptions = jsonschema::options();
    for (relative, body) in STIX_SCHEMAS {
        let value: Value =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("{relative} parses: {e}"));
        let resource: Resource =
            Resource::from_contents(value).unwrap_or_else(|e| panic!("{relative} resource: {e}"));
        options.with_resource(format!("{STIX_BASE}{relative}"), resource);
    }
    let target: &str = match object_type {
        "identity" => "sdos/identity.json",
        "indicator" => "sdos/indicator.json",
        "malware-analysis" => "sdos/malware-analysis.json",
        "identifier" => "common/identifier.json",
        other => panic!("no vendored stix schema for `{other}`"),
    };
    let schema: Value = serde_json::json!({ "$ref": format!("{STIX_BASE}{target}") });
    options
        .build(&schema)
        .unwrap_or_else(|e| panic!("stix {object_type} schema compiles: {e}"))
}

fn assert_valid(validator: &Validator, instance: &Value, label: &str) {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e: jsonschema::ValidationError<'_>| format!("{} at {}", e, e.instance_path))
        .collect();
    assert!(errors.is_empty(), "{label} is not valid: {errors:#?}");
}

fn report_sarif(target: &Path) -> Value {
    let r: Run = run_disrobe(&["report", target.to_str().unwrap(), "--format", "sarif"]);
    assert_eq!(
        r.code, 0,
        "report --format sarif must succeed; stderr={}",
        r.stderr
    );
    serde_json::from_str(&r.stdout).expect("sarif output must be valid json")
}

fn completed_run(stem: &str, bytes: &[u8]) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(stem);
    let work: PathBuf = scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    write(&input, bytes);
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);
    (scratch, out)
}

fn collect_timestamps(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::String(s) => {
            let bytes: &[u8] = s.as_bytes();
            if bytes.len() >= 20
                && s.ends_with('Z')
                && bytes.get(4) == Some(&b'-')
                && bytes.get(7) == Some(&b'-')
                && bytes.get(10) == Some(&b'T')
                && bytes.get(13) == Some(&b':')
                && s.chars().take(4).all(|c: char| c.is_ascii_digit())
            {
                found.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_timestamps(item, found);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_timestamps(item, found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[test]
fn the_forensic_report_validates_against_the_pinned_sarif_schema() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-sarif", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    assert_valid(&sarif_validator(), &log, "the forensic report");
    assert_eq!(log["version"], "2.1.0");
    assert_eq!(log["runs"][0]["tool"]["driver"]["name"], "disrobe");
    assert!(
        log["runs"][0]["invocations"][0]["executionSuccessful"].is_boolean(),
        "sarif requires executionSuccessful on every invocation"
    );
    assert!(
        log["runs"][0]["properties"]["disrobe"]["report_kind"] == serde_json::json!("single"),
        "the disrobe document must ride inside run.properties"
    );
}

#[test]
fn every_cited_range_names_the_artifact_it_indexes() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-ranges", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    let artifacts: &Vec<Value> = log["runs"][0]["artifacts"]
        .as_array()
        .expect("run.artifacts");
    assert!(
        !artifacts.is_empty(),
        "the run must carry an artifact table"
    );
    let results: &Vec<Value> = log["runs"][0]["results"].as_array().expect("run.results");
    let mut ranges: usize = 0;
    for result in results {
        let Some(locations) = result["locations"].as_array() else {
            continue;
        };
        for location in locations {
            let physical: &Value = &location["physicalLocation"];
            let artifact: &Value = &physical["artifactLocation"];
            assert!(
                artifact["uri"].is_string(),
                "every location names its artifact: {result}"
            );
            let index: usize = usize::try_from(
                artifact["index"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("every location indexes run.artifacts: {result}")),
            )
            .expect("index fits");
            let named: &Value = artifacts
                .get(index)
                .unwrap_or_else(|| panic!("index {index} is inside run.artifacts"));
            assert_eq!(
                named["location"]["uri"], artifact["uri"],
                "the index and the uri must name one artifact"
            );
            if let Some(region) = physical.get("region") {
                ranges += 1;
                let offset: u64 = region["byteOffset"].as_u64().expect("byteOffset");
                let length: u64 = region["byteLength"].as_u64().expect("byteLength");
                let end: u64 = offset.checked_add(length).expect("range does not overflow");
                if let Some(artifact_length) = named["length"].as_u64() {
                    assert!(
                        end <= artifact_length,
                        "cited range {offset}+{length} leaves `{}` of {artifact_length} bytes",
                        named["location"]["uri"]
                    );
                }
            }
        }
    }
    assert!(ranges > 0, "the report must cite at least one byte range");
}

const RECOVERED_CHAIN_JSON: &str = r#"{
  "schema": "disrobe.chain/v1",
  "tool_version": "0.9.0",
  "input": { "path": "app.pyc", "blake3": "abcd", "size": 128, "detected": ["pyc-3.11"] },
  "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
  "topology": "linear",
  "root_node_id": 0,
  "nodes": [
    { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
      "pass": null, "format_tag_in": null, "input_blake3": "abcd", "input_size": 128,
      "output_kind": null, "output_blake3": null, "output_size": null,
      "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
      "verdict": "ok", "error": null },
    { "id": 1, "parent_id": 0, "depth": 1, "branch_id": "root",
      "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "abcd", "input_size": 128,
      "output_kind": { "kind": "source", "language": "Python", "formatted": true },
      "output_blake3": "ef01", "output_size": 15,
      "duration_ms": 7, "detector_picks": [], "artifacts": ["app.py"], "metadata": {},
      "verdict": "complete", "error": null }
  ],
  "verdict": "complete",
  "final_format": "Python",
  "stats": { "layers": 1, "branches": 1, "total_ms": 7,
    "max_branch_depth": 1, "detector_calls": 1, "rejected_passes": 0 }
}"#;

const RECOVERED_RECOVERY_JSON: &str = r#"{
  "schema": "disrobe.recovery/v1",
  "tool_version": "0.9.0",
  "input": { "path": "app.pyc", "blake3": "abcd", "size": 128 },
  "passes": [
    { "name": "py.decompile", "status": "recovered", "confidence": "semantic",
      "duration_ms": 7, "format_in": "pyc-3.11", "format_out": "Python" }
  ],
  "histogram": { "exact": 0, "semantic": 1, "partial": 0, "skeleton": 0 },
  "total_ms": 7,
  "verdict": "complete"
}"#;

fn recovered_run(stem: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(stem);
    let out: PathBuf = scratch.path().to_path_buf();
    write(&out.join("chain.json"), RECOVERED_CHAIN_JSON.as_bytes());
    write(
        &out.join("recovery.json"),
        RECOVERED_RECOVERY_JSON.as_bytes(),
    );
    write(&out.join("app.py"), b"print('hello')\n");
    (scratch, out)
}

#[test]
fn every_recomputed_digest_matches_the_file_it_names() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        recovered_run("forensic-digest");
    let log: Value = report_sarif(&out);
    let evidence: &Vec<Value> = log["runs"][0]["properties"]["disrobe"]["evidence"]
        .as_array()
        .expect("evidence list");
    let mut checked: usize = 0;
    for item in evidence {
        if item["hash_source"] != serde_json::json!("recomputed-from-file") {
            continue;
        }
        let display: &str = item["display"].as_str().expect("display");
        let path: PathBuf = out.join(display);
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cited artifact {} must exist: {e}", path.display()));
        assert_eq!(
            item["blake3"].as_str().expect("blake3"),
            blake3::hash(&bytes).to_hex().as_str(),
            "the cited digest of {display} must be blake3 over its bytes"
        );
        assert_eq!(item["byte_length"].as_u64(), Some(bytes.len() as u64));
        checked += 1;
    }
    assert_eq!(
        checked, 1,
        "the one recovered artifact must be cited with a re-checkable digest"
    );
    let artifacts: &Vec<Value> = log["runs"][0]["artifacts"]
        .as_array()
        .expect("run.artifacts");
    let recovered: &Value = artifacts
        .iter()
        .find(|a: &&Value| {
            a["roles"]
                .as_array()
                .is_some_and(|r: &Vec<Value>| r.contains(&serde_json::json!("resultFile")))
        })
        .expect("the recovered artifact must carry the sarif resultFile role");
    assert_eq!(
        recovered["hashes"]["blake3"],
        serde_json::json!(blake3::hash(b"print('hello')\n").to_hex().as_str())
    );
    assert_eq!(recovered["length"], serde_json::json!(15));
}

#[test]
fn the_embedded_bundle_validates_object_by_object_against_the_pinned_stix_schemas() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-stix", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    let stix: &Value = &log["runs"][0]["properties"]["stix"];
    assert_eq!(stix["available"], serde_json::json!(true));
    let bundle: &Value = &stix["bundle"];
    assert_eq!(bundle["type"], "bundle");
    let identifier: Validator = stix_validator("identifier");
    assert_valid(&identifier, &bundle["id"], "the bundle identifier");
    let objects: &Vec<Value> = bundle["objects"].as_array().expect("bundle objects");
    assert!(!objects.is_empty(), "the bundle must carry objects");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for object in objects {
        let object_type: &str = object["type"].as_str().expect("object type");
        let id: &str = object["id"].as_str().expect("object id");
        assert_valid(&identifier, &object["id"], object_type);
        assert!(
            id.starts_with(&format!("{object_type}--")),
            "{id} must be prefixed with its own type"
        );
        assert_eq!(object["spec_version"], "2.1", "{object_type}");
        assert_valid(&stix_validator(object_type), object, object_type);
        seen.insert(object_type.to_string());
    }
    assert!(seen.contains("identity"), "{seen:?}");
    assert!(seen.contains("malware-analysis"), "{seen:?}");
    let created_by: BTreeSet<&str> = objects
        .iter()
        .filter_map(|o: &Value| o["created_by_ref"].as_str())
        .collect();
    let ids: BTreeSet<&str> = objects
        .iter()
        .filter_map(|o: &Value| o["id"].as_str())
        .collect();
    for reference in &created_by {
        assert!(
            ids.contains(reference),
            "created_by_ref {reference} does not resolve inside the bundle"
        );
    }
}

#[test]
fn a_cited_indicator_range_reads_back_as_the_indicator_value() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("forensic-indicator");
    let work: PathBuf = scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    let mut bytes: Vec<u8> = vec![0x41u8; 64];
    bytes.extend_from_slice(b"http://malware-example.com/payload.bin");
    bytes.extend_from_slice(&[0x42u8; 64]);
    write(&input, &bytes);
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let log: Value = report_sarif(&out);
    let artifacts: &Vec<Value> = log["runs"][0]["artifacts"]
        .as_array()
        .expect("run.artifacts");
    let results: &Vec<Value> = log["runs"][0]["results"].as_array().expect("run.results");
    let indicators: Vec<&Value> = results
        .iter()
        .filter(|r: &&Value| r["ruleId"] == serde_json::json!("disrobe.indicator"))
        .collect();
    assert!(
        !indicators.is_empty(),
        "an input carrying a url must produce at least one cited indicator: {results:#?}"
    );
    let target: Vec<u8> = std::fs::read(&input).expect("read the analysis target");
    let mut read_back: usize = 0;
    for result in indicators {
        let properties: &Value = &result["properties"];
        let value: &str = properties["value"].as_str().expect("indicator value");
        if properties["encoding"] != serde_json::json!("plain") {
            continue;
        }
        assert_eq!(
            properties["range_within_target"],
            serde_json::json!(true),
            "a plain indicator must cite a range inside the analysis target: {result}"
        );
        let physical: &Value = &result["locations"][0]["physicalLocation"];
        let index: usize = usize::try_from(
            physical["artifactLocation"]["index"]
                .as_u64()
                .expect("index"),
        )
        .expect("index fits");
        let named: &Value = artifacts.get(index).expect("artifact index resolves");
        assert!(
            named["roles"]
                .as_array()
                .is_some_and(|r: &Vec<Value>| r.contains(&serde_json::json!("analysisTarget"))),
            "an indicator range must index the analysis target, not a decompressed child: {named}"
        );
        let offset: usize = usize::try_from(
            physical["region"]["byteOffset"]
                .as_u64()
                .expect("byteOffset"),
        )
        .expect("offset fits");
        let length: usize = usize::try_from(
            physical["region"]["byteLength"]
                .as_u64()
                .expect("byteLength"),
        )
        .expect("length fits");
        let end: usize = offset.checked_add(length).expect("range does not overflow");
        let slice: &[u8] = target
            .get(offset..end)
            .unwrap_or_else(|| panic!("cited range {offset}+{length} is inside the target"));
        assert_eq!(
            std::str::from_utf8(slice).expect("cited bytes are text"),
            value,
            "reading the analysis target at the cited range must yield the cited value"
        );
        read_back += 1;
    }
    assert!(
        read_back > 0,
        "at least one plain indicator must be re-readable from the analysis target"
    );
}

#[test]
fn the_maec_package_carries_behavior_objects_or_names_why_it_cannot() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-maec", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    let maec: &Value = &log["runs"][0]["properties"]["maec"];
    if maec["available"] == serde_json::json!(false) {
        assert!(
            maec["reason"]
                .as_str()
                .is_some_and(|r: &str| !r.trim().is_empty()),
            "an unavailable maec package must name why: {maec}"
        );
        return;
    }
    let package: &Value = &maec["package"];
    assert_eq!(package["type"], "package");
    assert_eq!(package["schema_version"], "5.0");
    assert!(
        package["id"]
            .as_str()
            .is_some_and(|i: &str| i.starts_with("package--"))
    );
    let objects: &Vec<Value> = package["maec_objects"].as_array().expect("maec_objects");
    assert!(!objects.is_empty());
    for object in objects {
        assert_eq!(object["type"], "behavior");
        assert!(
            object["id"]
                .as_str()
                .is_some_and(|i: &str| i.starts_with("behavior--"))
        );
        assert!(
            object["name"].as_str().is_some_and(|n: &str| !n.is_empty()),
            "maec requires id, type and name on every behavior: {object}"
        );
    }
}

#[test]
fn walls_are_first_class_and_never_reported_as_an_error() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-wall", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    let walls: &Vec<Value> = log["runs"][0]["properties"]["disrobe"]["walls"]
        .as_array()
        .expect("walls list");
    assert!(
        !walls.is_empty(),
        "a run that recovered nothing must record a wall"
    );
    for wall in walls {
        assert!(
            wall["missing"]
                .as_str()
                .is_some_and(|m: &str| !m.trim().is_empty()),
            "every wall names the input it lacks: {wall}"
        );
    }
    let results: &Vec<Value> = log["runs"][0]["results"].as_array().expect("results");
    let wall_results: Vec<&Value> = results
        .iter()
        .filter(|r: &&Value| r["ruleId"] == serde_json::json!("disrobe.wall"))
        .collect();
    assert_eq!(wall_results.len(), walls.len());
    for result in wall_results {
        assert_eq!(
            result["level"],
            serde_json::json!("none"),
            "a wall must not be rendered as an error: {result}"
        );
        assert_eq!(result["kind"], serde_json::json!("review"));
    }
}

#[test]
fn two_runs_over_one_target_agree_byte_for_byte_in_every_render() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-determinism", &(0u8..96).collect::<Vec<u8>>());
    for format in ["text", "json", "markdown", "html"] {
        let first: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", format]);
        let second: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", format]);
        assert_eq!(first.code, 0, "{format}: stderr={}", first.stderr);
        assert_eq!(second.code, 0, "{format}: stderr={}", second.stderr);
        assert!(!first.stdout.is_empty(), "{format} rendered nothing");
        assert_eq!(
            first.stdout, second.stdout,
            "`report --format {format}` is not byte-identical across runs"
        );
    }

    let first: Value = report_sarif(&out);
    let second: Value = report_sarif(&out);
    let generated: &str = first["runs"][0]["properties"]["generated_at"]
        .as_str()
        .expect("generated_at");
    let mut first_stamps: BTreeSet<String> = BTreeSet::new();
    collect_timestamps(&first, &mut first_stamps);
    assert_eq!(
        first_stamps.len(),
        1,
        "the sarif document must hold exactly one distinct timestamp value: {first_stamps:?}"
    );
    assert!(first_stamps.contains(generated));

    let mut second_stamps: BTreeSet<String> = BTreeSet::new();
    collect_timestamps(&second, &mut second_stamps);
    let second_generated: &str = second["runs"][0]["properties"]["generated_at"]
        .as_str()
        .expect("generated_at");
    let masked_first: String = serde_json::to_string_pretty(&first)
        .unwrap()
        .replace(generated, "<generated_at>");
    let masked_second: String = serde_json::to_string_pretty(&second)
        .unwrap()
        .replace(second_generated, "<generated_at>");
    assert_eq!(
        masked_first, masked_second,
        "`report --format sarif` differs by more than its timestamp"
    );
}

#[test]
fn a_pinned_source_date_epoch_fixes_the_only_wall_clock_field() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-epoch", &(0u8..96).collect::<Vec<u8>>());
    let first: Run = common::run_disrobe_env(
        &["report", out.to_str().unwrap(), "--format", "sarif"],
        &[("SOURCE_DATE_EPOCH", "1700000000")],
    );
    let second: Run = common::run_disrobe_env(
        &["report", out.to_str().unwrap(), "--format", "sarif"],
        &[("SOURCE_DATE_EPOCH", "1700000000")],
    );
    assert_eq!(first.code, 0, "stderr={}", first.stderr);
    assert_eq!(
        first.stdout, second.stdout,
        "a pinned SOURCE_DATE_EPOCH must make the sarif render byte-identical"
    );
    let log: Value = serde_json::from_str(&first.stdout).expect("valid json");
    assert_eq!(
        log["runs"][0]["properties"]["generated_at"],
        serde_json::json!("2023-11-14T22:13:20.000Z")
    );
    assert_eq!(
        log["runs"][0]["properties"]["standards"]["timestamp"]["source"],
        serde_json::json!("source-date-epoch")
    );
}

#[test]
fn a_batch_of_only_errors_still_produces_a_valid_document() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("forensic-batch");
    let work: PathBuf = scratch.path().to_path_buf();
    let manifest: &str = r#"{
      "schema": "disrobe.batch.manifest/v1",
      "tool_version": "0.9.0",
      "root": "samples",
      "out_root": "out/samples-batch",
      "chain": "auto:8",
      "jobs": 1,
      "summary": { "processed": 2, "recovered": 0, "detect_only": 0, "errors": 2 },
      "entries": [
        { "input": "samples/a", "relative": "a", "size": 0, "detected_format": null,
          "chain": [], "verdict": null, "recovery_score": null, "output_dir": null,
          "duration_ms": 1, "error": "read failed" },
        { "input": "samples/b", "relative": "b", "size": 0, "detected_format": null,
          "chain": [], "verdict": null, "recovery_score": null, "output_dir": null,
          "duration_ms": 1, "error": "read failed" }
      ]
    }"#;
    write(&work.join("manifest.json"), manifest.as_bytes());
    let log: Value = report_sarif(&work);
    assert_valid(&sarif_validator(), &log, "the batch forensic report");
    assert_eq!(
        log["runs"][0]["properties"]["disrobe"]["mean_recovery_score"],
        Value::Null,
        "a batch of only errors must not divide by zero"
    );
    assert_eq!(
        log["runs"][0]["invocations"][0]["executionSuccessful"],
        serde_json::json!(false)
    );
    for standard in ["stix", "maec", "capabilities", "indicators"] {
        let block: &Value = &log["runs"][0]["properties"][standard];
        assert_eq!(block["available"], serde_json::json!(false), "{standard}");
        assert!(
            block["reason"]
                .as_str()
                .is_some_and(|r: &str| !r.trim().is_empty()),
            "{standard} must name why it is unavailable"
        );
    }
}

fn zip_bundle() -> Vec<u8> {
    let entries: [(&str, &[u8]); 2] = [
        ("a/hello.txt", b"hello world\n".as_slice()),
        ("b/second.txt", b"second payload\n".as_slice()),
    ];
    let mut local: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, body) in entries {
        let offset: u32 = u32::try_from(local.len()).expect("offset fits");
        let crc: u32 = crc32(body);
        let size: u32 = u32::try_from(body.len()).expect("size fits");
        let name_len: u16 = u16::try_from(name.len()).expect("name fits");
        local.extend_from_slice(b"PK\x03\x04");
        local.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&name_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        local.extend_from_slice(body);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset: u32 = u32::try_from(local.len()).expect("central offset fits");
    let central_len: u32 = u32::try_from(central.len()).expect("central length fits");
    let count: u16 = u16::try_from(entries.len()).expect("entry count fits");
    let mut out: Vec<u8> = local;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[test]
fn a_real_extracting_run_cites_each_recovered_file_against_the_chain_document() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("forensic-extract");
    let work: PathBuf = scratch.path().to_path_buf();
    let input: PathBuf = work.join("bundle.zip");
    write(&input, &zip_bundle());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let chain: Value =
        serde_json::from_slice(&std::fs::read(out.join("chain.json")).expect("chain.json"))
            .expect("chain json");
    let node_digests: BTreeSet<String> = chain["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|n: &Value| n["input_blake3"].as_str().map(str::to_string))
        .collect();

    let log: Value = report_sarif(&out);
    let evidence: &Vec<Value> = log["runs"][0]["properties"]["disrobe"]["evidence"]
        .as_array()
        .expect("evidence");
    let recovered: Vec<&Value> = evidence
        .iter()
        .filter(|e: &&Value| e["role"] == serde_json::json!("recovered-artifact"))
        .collect();
    assert_eq!(
        recovered.len(),
        2,
        "both extracted files must be cited: {evidence:#?}"
    );
    for item in recovered {
        let display: &str = item["display"].as_str().expect("display");
        let bytes: Vec<u8> = std::fs::read(out.join(display))
            .unwrap_or_else(|e| panic!("cited file {display} must exist: {e}"));
        let digest: String = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(
            item["blake3"].as_str(),
            Some(digest.as_str()),
            "the cited digest of {display} must be blake3 over its bytes"
        );
        assert_eq!(item["byte_length"].as_u64(), Some(bytes.len() as u64));
        assert!(
            node_digests.contains(&digest),
            "the digest of {display} must match a chain node input recorded independently in chain.json"
        );
    }
}

#[test]
fn a_chain_run_leaves_the_citable_report_without_a_second_command() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-auto", &(0u8..96).collect::<Vec<u8>>());
    let written: PathBuf = out.join("report.json");
    assert!(
        written.is_file(),
        "`disrobe auto` must leave {} beside chain.json",
        written.display()
    );
    let left: Value =
        serde_json::from_slice(&std::fs::read(&written).expect("read report.json")).expect("json");
    assert!(left["walls"].is_array(), "{left}");
    assert!(left["evidence"].is_array(), "{left}");
    assert!(left["reproduction"]["command"].is_string(), "{left}");

    let r: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", "json"]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let mut right: Value = serde_json::from_str(&r.stdout).expect("json");
    let object: &mut serde_json::Map<String, Value> =
        right.as_object_mut().expect("report document object");
    assert_eq!(
        object.remove("report_kind"),
        Some(serde_json::json!("single"))
    );
    assert_eq!(
        left, right,
        "the report `auto` writes and the report the command renders must agree"
    );
}

#[test]
fn every_file_of_a_batch_run_leaves_its_own_citable_report() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("forensic-batch-report");
    let work: PathBuf = scratch.path().to_path_buf();
    write(&work.join("samples/a.bin"), &[1u8; 32]);
    write(&work.join("samples/b.bin"), &[2u8; 32]);
    let out: PathBuf = work.join("batch-out");
    let r: Run = run_disrobe(&[
        "auto",
        work.join("samples").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "batch setup; stderr={}", r.stderr);
    for relative in ["a.bin", "b.bin"] {
        let written: PathBuf = out.join(relative).join("report.json");
        assert!(
            written.is_file(),
            "a batch entry must leave {}",
            written.display()
        );
        let document: Value =
            serde_json::from_slice(&std::fs::read(&written).expect("read")).expect("json");
        assert_eq!(document["kind"], serde_json::json!("single"));
        assert!(document["evidence"].is_array(), "{document}");
        assert!(
            document["reproduction"]["command"].is_string(),
            "{document}"
        );
    }
}

#[test]
fn the_excluded_standards_are_named_rather_than_silently_dropped() {
    let (_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        completed_run("forensic-standards", &(0u8..96).collect::<Vec<u8>>());
    let log: Value = report_sarif(&out);
    let standards: &Value = &log["runs"][0]["properties"]["standards"];
    assert_eq!(standards["sarif"]["version"], "2.1.0");
    assert_eq!(standards["stix"]["version"], "2.1");
    assert_eq!(standards["maec"]["version"], "5.0");
    assert_eq!(standards["cyclonedx"]["version"], "1.5");
    let excluded: Vec<&str> = standards["excluded"]
        .as_array()
        .expect("excluded list")
        .iter()
        .map(|e: &Value| e["standard"].as_str().expect("standard name"))
        .collect();
    assert!(excluded.iter().any(|s: &&str| s.contains("OpenIOC")));
    assert!(excluded.iter().any(|s: &&str| s.contains("CybOX")));
    for entry in standards["excluded"].as_array().expect("excluded list") {
        assert!(
            entry["reason"]
                .as_str()
                .is_some_and(|r: &str| !r.trim().is_empty()),
            "every excluded standard names its reason: {entry}"
        );
    }
}
