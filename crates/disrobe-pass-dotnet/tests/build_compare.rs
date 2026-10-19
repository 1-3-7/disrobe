#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fmt::Write as _;

use disrobe_pass_dotnet::build_compare::{
    Aspect, BuildComparison, Change, ChangeCounts, CompareError, Entity, Finding, Side, compare,
};
use disrobe_pass_dotnet::metadata::{
    MetadataRoot, StreamHeader, decompress_uint, metadata_slice, parse_metadata_root,
    parse_table_stream,
};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::tables::{TableId, TableSpan, Tables, parse_tables, table_spans};
use sha2::{Digest as _, Sha256};

const CORPUS: &str = "corpus/dotnet/build-compare";
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
const PAIRS: [(&str, &str); 10] = [
    ("members", "Shop"),
    ("body", "Scoring"),
    ("signature", "Units"),
    ("reorder", "Layout"),
    ("attributes", "Tagged"),
    ("version", "Release"),
    ("pinvoke", "Platform"),
    ("resource", "Assets"),
    ("shapes", "Shapes"),
    ("identical", "Stable"),
];

fn fixture(relative: &str) -> Vec<u8> {
    let path: String = format!("{CORPUS}/{relative}");
    disrobe_testkit::load_fixture(&path, MAX_FIXTURE_BYTES)
        .unwrap_or_else(|error| panic!("required fixture {path} is missing: {error}"))
}

fn text(relative: &str) -> String {
    String::from_utf8(fixture(relative))
        .unwrap_or_else(|error| panic!("{relative} is not UTF-8: {error}"))
}

fn manifest_digests() -> BTreeMap<String, String> {
    let manifest: toml::Table = text("MANIFEST.toml")
        .parse::<toml::Table>()
        .expect("MANIFEST.toml parses");
    let fixtures: &Vec<toml::Value> = manifest["fixture"].as_array().expect("fixture entries");
    fixtures
        .iter()
        .map(|entry: &toml::Value| {
            (
                entry["path"].as_str().expect("path").to_owned(),
                entry["sha256"].as_str().expect("sha256").to_owned(),
            )
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut text: String, byte: &u8| {
            let _: std::fmt::Result = write!(text, "{byte:02x}");
            text
        })
}

fn verified(relative: &str, digests: &BTreeMap<String, String>) -> Vec<u8> {
    let bytes: Vec<u8> = fixture(relative);
    let recorded: &String = digests
        .get(relative)
        .unwrap_or_else(|| panic!("{relative} has no build record in MANIFEST.toml"));
    assert_eq!(
        &sha256_hex(&bytes),
        recorded,
        "{relative} differs from its build record"
    );
    bytes
}

fn pair(name: &str, assembly: &str, digests: &BTreeMap<String, String>) -> (Vec<u8>, Vec<u8>) {
    (
        verified(&format!("{name}/old/{assembly}.dll"), digests),
        verified(&format!("{name}/new/{assembly}.dll"), digests),
    )
}

fn reference(name: &str, digests: &BTreeMap<String, String>) -> Vec<String> {
    let relative: String = format!("{name}/reference.txt");
    let bytes: Vec<u8> = verified(&relative, digests);
    String::from_utf8(bytes)
        .expect("reference output is UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn report(name: &str, assembly: &str, digests: &BTreeMap<String, String>) -> BuildComparison {
    let (old, new): (Vec<u8>, Vec<u8>) = pair(name, assembly, digests);
    compare(&old, &new).unwrap_or_else(|error: CompareError| panic!("{name}: {error}"))
}

fn grade(actual: &[String], expected: &[String]) -> Vec<String> {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for line in actual {
        *counts.entry(line.as_str()).or_insert(0) += 1;
    }
    for line in expected {
        *counts.entry(line.as_str()).or_insert(0) -= 1;
    }
    counts
        .into_iter()
        .filter(|(_, count): &(&str, i64)| *count != 0)
        .map(|(line, count): (&str, i64)| {
            if count > 0 {
                format!("unexpected: {line}")
            } else {
                format!("missing: {line}")
            }
        })
        .collect()
}

fn has(report: &BuildComparison, entity: Entity, change: Change, aspect: Option<Aspect>) -> bool {
    report.findings.iter().any(|finding: &Finding| {
        finding.entity == entity
            && finding.change == change
            && (aspect.is_none() || finding.aspect == aspect)
    })
}

#[test]
fn every_pair_matches_the_reflection_metadata_reference() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let mut failures: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for (name, assembly) in PAIRS {
        let expected: Vec<String> = reference(name, &digests);
        assert!(
            !expected.is_empty(),
            "{name}: the reference lists no finding"
        );
        let actual: Vec<String> = report(name, assembly, &digests).lines();
        graded += expected.len();
        failures.extend(
            grade(&actual, &expected)
                .into_iter()
                .map(|line: String| format!("{name}: {line}")),
        );
    }
    assert!(
        failures.is_empty(),
        "{} of {graded} reference findings disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn one_changed_expected_fact_turns_the_grade_red() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let mut mutations: usize = 0;
    for (name, assembly) in PAIRS {
        let expected: Vec<String> = reference(name, &digests);
        let actual: Vec<String> = report(name, assembly, &digests).lines();
        assert!(
            grade(&actual, &expected).is_empty(),
            "{name}: baseline must be green"
        );
        for index in 0..expected.len() {
            let mut changed: Vec<String> = expected.clone();
            let line: &mut String = &mut changed[index];
            let colon: usize = line.find(':').unwrap_or(line.len() / 2);
            line.insert(colon, '~');
            assert!(
                !grade(&actual, &changed).is_empty(),
                "{name}: changing expected line {index} left the grade green"
            );
            let mut dropped: Vec<String> = expected.clone();
            dropped.remove(index);
            assert!(
                !grade(&actual, &dropped).is_empty(),
                "{name}: dropping expected line {index} left the grade green"
            );
            mutations += 2;
        }
        let mut extra: Vec<String> = expected.clone();
        extra.push(expected[0].clone());
        assert!(
            !grade(&actual, &extra).is_empty(),
            "{name}: a duplicated expected line left the grade green"
        );
        mutations += 1;
    }
    assert!(mutations > 200, "only {mutations} mutation controls ran");
}

#[test]
fn identical_sources_differ_only_in_mvid_and_pe_timestamp() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let (old, new): (Vec<u8>, Vec<u8>) = pair("identical", "Stable", &digests);
    assert_ne!(
        old, new,
        "the identical-source builds must not be byte-identical"
    );
    let comparison: BuildComparison = compare(&old, &new).expect("identical pair compares");
    let keys: Vec<(Entity, Change, &str)> = comparison
        .findings
        .iter()
        .map(|finding: &Finding| (finding.entity, finding.change, finding.key.as_str()))
        .collect();
    assert_eq!(
        keys,
        vec![
            (Entity::Identity, Change::Changed, "mvid"),
            (Entity::Identity, Change::Changed, "pe-timestamp"),
        ],
        "a non-deterministic rebuild of one source may change only the MVID and the PE timestamp"
    );
    for finding in &comparison.findings {
        assert_ne!(finding.old, finding.new);
    }
    let expected: Vec<String> = reference("identical", &digests);
    let prefixes: Vec<&str> = expected
        .iter()
        .map(|line: &String| line.split(':').next().unwrap_or_default())
        .collect();
    assert_eq!(
        prefixes,
        vec!["changed identity mvid", "changed identity pe-timestamp"],
        "the reference must state the same two differences"
    );
}

#[test]
fn comparing_a_build_with_itself_reports_nothing() {
    let digests: BTreeMap<String, String> = manifest_digests();
    for (name, assembly) in PAIRS {
        for side in ["old", "new"] {
            let bytes: Vec<u8> = verified(&format!("{name}/{side}/{assembly}.dll"), &digests);
            let comparison: BuildComparison = compare(&bytes, &bytes).expect("self comparison");
            assert!(
                comparison.findings.is_empty(),
                "{name}/{side} differs from itself: {:?}",
                comparison.lines()
            );
        }
    }
}

#[test]
fn each_pair_exercises_its_change_kind() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let members: BuildComparison = report("members", "Shop", &digests);
    for entity in [Entity::Type, Entity::Field, Entity::Method, Entity::Event] {
        assert!(
            has(&members, entity, Change::Added, None),
            "members: no added {entity:?}"
        );
        assert!(
            has(&members, entity, Change::Removed, None),
            "members: no removed {entity:?}"
        );
    }
    assert!(has(&members, Entity::Property, Change::Added, None));

    let body: BuildComparison = report("body", "Scoring", &digests);
    assert!(has(
        &body,
        Entity::Method,
        Change::Changed,
        Some(Aspect::BodyIlChanged)
    ));
    assert!(
        !body
            .lines()
            .iter()
            .any(|line: &String| line.contains("::Unchanged("))
    );
    assert!(
        body.findings
            .iter()
            .all(|finding: &Finding| finding.change == Change::Changed),
        "the body pair adds and removes nothing"
    );

    let signature: BuildComparison = report("signature", "Units", &digests);
    assert!(has(
        &signature,
        Entity::Method,
        Change::Changed,
        Some(Aspect::Signature)
    ));
    assert!(has(
        &signature,
        Entity::Property,
        Change::Changed,
        Some(Aspect::Signature)
    ));
    assert!(has(
        &signature,
        Entity::Field,
        Change::Changed,
        Some(Aspect::Type)
    ));
    assert!(signature.lines().iter().any(|line: &String| {
        line.contains("modreq([System.Runtime]System.Runtime.InteropServices.InAttribute)")
    }));

    let reorder: BuildComparison = report("reorder", "Layout", &digests);
    assert!(has(
        &reorder,
        Entity::Method,
        Change::Changed,
        Some(Aspect::BodyTokenRenumbered)
    ));
    assert!(
        reorder.findings.iter().all(|finding: &Finding| {
            finding.entity == Entity::Identity
                || finding.aspect == Some(Aspect::BodyTokenRenumbered)
        }),
        "a declaration reorder must change only tokens: {:?}",
        reorder.lines()
    );

    let attributes: BuildComparison = report("attributes", "Tagged", &digests);
    for change in [Change::Added, Change::Removed, Change::Changed] {
        assert!(
            has(&attributes, Entity::Attribute, change, None),
            "attributes: no {change:?}"
        );
    }
    assert!(has(
        &attributes,
        Entity::Type,
        Change::Changed,
        Some(Aspect::Flags)
    ));

    let version: BuildComparison = report("version", "Release", &digests);
    let identity: Vec<&str> = version
        .findings
        .iter()
        .filter(|finding: &&Finding| finding.entity == Entity::Identity)
        .map(|finding: &Finding| finding.key.as_str())
        .collect();
    for field in ["version", "public-key-token", "target-framework", "mvid"] {
        assert!(
            identity.contains(&field),
            "version: no identity {field} change"
        );
    }
    assert!(has(
        &version,
        Entity::AssemblyRef,
        Change::Changed,
        Some(Aspect::Version)
    ));

    let pinvoke: BuildComparison = report("pinvoke", "Platform", &digests);
    for aspect in [Aspect::EntryPoint, Aspect::Module, Aspect::Flags] {
        assert!(
            has(&pinvoke, Entity::Pinvoke, Change::Changed, Some(aspect)),
            "pinvoke: no {aspect:?}"
        );
    }
    assert!(has(&pinvoke, Entity::Pinvoke, Change::Added, None));
    assert!(has(&pinvoke, Entity::Pinvoke, Change::Removed, None));

    let resource: BuildComparison = report("resource", "Assets", &digests);
    for aspect in [Aspect::Sha256, Aspect::Size, Aspect::Flags] {
        assert!(
            has(&resource, Entity::Resource, Change::Changed, Some(aspect)),
            "resource: no {aspect:?}"
        );
    }
    assert!(has(&resource, Entity::Resource, Change::Added, None));
    assert!(has(&resource, Entity::Resource, Change::Removed, None));

    let shapes: BuildComparison = report("shapes", "Shapes", &digests);
    for (entity, aspect) in [
        (Entity::Type, Aspect::Layout),
        (Entity::Type, Aspect::MethodImpls),
        (Entity::Type, Aspect::GenericParameters),
        (Entity::Field, Aspect::Offset),
        (Entity::Field, Aspect::Constant),
        (Entity::Method, Aspect::Parameters),
        (Entity::Method, Aspect::GenericParameters),
        (Entity::Property, Aspect::Accessors),
        (Entity::Event, Aspect::Type),
    ] {
        assert!(
            has(&shapes, entity, Change::Changed, Some(aspect)),
            "shapes: no {entity:?} {aspect:?} change"
        );
    }
    let lines: Vec<String> = shapes.lines();
    for spelling in [
        "method unmanaged cdecl int32(int32)",
        "int32[0:,0:,0:]",
        "Dictionary`2/Enumerator<string, int32>",
        "modreq([System.Runtime]System.Runtime.InteropServices.UnmanagedType)",
    ] {
        assert!(
            lines.iter().any(|line: &String| line.contains(spelling)),
            "shapes: no line spells {spelling}"
        );
    }
}

#[test]
fn swapping_the_builds_mirrors_every_count() {
    let digests: BTreeMap<String, String> = manifest_digests();
    for (name, assembly) in PAIRS {
        let (old, new): (Vec<u8>, Vec<u8>) = pair(name, assembly, &digests);
        let forward: BuildComparison = compare(&old, &new).expect("forward");
        let backward: BuildComparison = compare(&new, &old).expect("backward");
        assert_eq!(forward.findings.len(), backward.findings.len(), "{name}");
        for (entity, counts) in &forward.counts {
            let mirrored: ChangeCounts = backward.counts.get(entity).copied().unwrap_or_default();
            assert_eq!(
                (counts.added, counts.removed, counts.changed),
                (mirrored.removed, mirrored.added, mirrored.changed),
                "{name}: {entity:?}"
            );
        }
    }
}

#[test]
fn json_report_is_deterministic_and_counts_every_finding() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let first: BuildComparison = report("members", "Shop", &digests);
    let second: BuildComparison = report("members", "Shop", &digests);
    let first_json: String = serde_json::to_string(&first).expect("json");
    assert_eq!(first_json, serde_json::to_string(&second).expect("json"));
    let value: serde_json::Value = serde_json::from_str(&first_json).expect("parse");
    assert_eq!(value["schema"], "disrobe.dotnet.build-compare/v1");
    let findings: &Vec<serde_json::Value> = value["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), first.findings.len());
    let counted: usize = first
        .counts
        .values()
        .map(|counts: &ChangeCounts| counts.added + counts.removed + counts.changed)
        .sum();
    assert_eq!(counted, findings.len());
    assert!(findings.iter().all(|finding: &serde_json::Value| {
        finding["old_location"].is_string() || finding["new_location"].is_string()
    }));
}

#[test]
fn malformed_inputs_are_typed_refusals() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let good: Vec<u8> = verified("members/new/Shop.dll", &digests);
    let refused: CompareError = compare(b"not a portable executable", &good).expect_err("refused");
    assert!(
        matches!(
            refused,
            CompareError::Image {
                side: Side::Old,
                ..
            }
        ),
        "{refused}"
    );
    assert!(refused.to_string().starts_with("DR-DOTNET-0960"));
    let truncated: CompareError = compare(&good, &good[..good.len() / 3]).expect_err("refused");
    assert!(
        matches!(
            truncated,
            CompareError::Image {
                side: Side::New,
                ..
            } | CompareError::Malformed {
                side: Side::New,
                ..
            }
        ),
        "{truncated}"
    );
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    for cut in (0..good.len()).step_by(61) {
        let label: &str = match compare(&good[..cut], &good) {
            Ok(_) => "ok",
            Err(CompareError::Image { .. }) => "image",
            Err(CompareError::Malformed { .. }) => "malformed",
            Err(CompareError::Bound { .. }) => "bound",
        };
        *outcomes.entry(label).or_insert(0) += 1;
    }
    for position in (0..good.len()).step_by(7) {
        let mut flipped: Vec<u8> = good.clone();
        flipped[position] ^= 0xA5;
        let label: &str = match compare(&good, &flipped) {
            Ok(_) => "ok",
            Err(CompareError::Image { .. }) => "image",
            Err(CompareError::Malformed { .. }) => "malformed",
            Err(CompareError::Bound { .. }) => "bound",
        };
        *outcomes.entry(label).or_insert(0) += 1;
    }
    assert!(
        outcomes.get("image").copied().unwrap_or(0) > 0,
        "{outcomes:?}"
    );
    assert!(
        outcomes.get("malformed").copied().unwrap_or(0) > 0,
        "{outcomes:?}"
    );
}

#[test]
fn a_signature_nested_past_the_bound_is_a_typed_refusal() {
    let digests: BTreeMap<String, String> = manifest_digests();
    let original: Vec<u8> = verified("version/new/Release.dll", &digests);
    let pe: PeImage = parse(&original).expect("PE headers");
    let clr: ClrHeader = parse_clr_header(&original, &pe).expect("CLI header");
    let root: MetadataRoot = parse_metadata_root(&original, &pe, &clr).expect("metadata root");
    let metadata: &[u8] = metadata_slice(&original, &pe, &clr, &root).expect("metadata");
    let base: usize = pe.rva_to_offset(clr.metadata.rva).expect("metadata offset");
    let table_header: StreamHeader = root.streams["#~"];
    let tables: Tables = parse_tables(metadata, table_header).expect("tables");
    let key_index: u32 = tables.assembly.expect("assembly row").public_key;
    let blob_start: usize = base + root.streams["#Blob"].offset as usize + key_index as usize;
    let (length, consumed): (u32, usize) =
        decompress_uint(&original[blob_start..]).expect("blob length");
    let content: usize = blob_start + consumed;
    let length: usize = length as usize;
    assert!(
        length > 64,
        "the public key blob is long enough to nest 64 levels"
    );
    let mut hostile: Vec<u8> = original.clone();
    hostile[content] = 0x00;
    hostile[content + 1] = 0x01;
    hostile[content + 2..content + length - 1].fill(0x1D);
    hostile[content + length - 1] = 0x08;
    let heap_sizes: u8 = parse_table_stream(metadata, table_header)
        .expect("table stream")
        .heap_sizes;
    let strings: usize = if heap_sizes & 0x01 == 0 { 2 } else { 4 };
    let blobs: usize = if heap_sizes & 0x04 == 0 { 2 } else { 4 };
    let span: TableSpan =
        table_spans(metadata, table_header).expect("spans")[&TableId::MethodDef.index()];
    let column: usize = base + table_header.offset as usize + span.offset + 8 + strings;
    hostile[column..column + blobs].copy_from_slice(&key_index.to_le_bytes()[..blobs]);
    let refused: CompareError = compare(&original, &hostile).expect_err("deep signature refused");
    assert!(
        matches!(
            refused,
            CompareError::Bound {
                side: Side::New,
                what: "signature depth",
                ..
            }
        ),
        "{refused}"
    );
}
