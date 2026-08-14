#![cfg(feature = "ml")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_pickle::{EmbeddedPickle, MlReport, ModelFormat, extract_ml};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MemberRef {
    offset: usize,
    length: usize,
    protocol: u8,
    first_dot_length: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FixtureRef {
    format: String,
    size_bytes: usize,
    trailing_bytes: usize,
    members: Vec<MemberRef>,
}

#[derive(Debug, Deserialize)]
struct StreamReference {
    schema: String,
    measured_by: String,
    fixtures: BTreeMap<String, FixtureRef>,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("pickle")
        .join("ml")
}

fn reference() -> StreamReference {
    let path: PathBuf = corpus_root().join("stream_ref.json");
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "{}: the CPython-measured member boundaries must be readable; a grader that cannot \
             reach its reference fails, it does not skip ({e})",
            path.display()
        )
    });
    let parsed: StreamReference = serde_json::from_str(&text)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    assert_eq!(parsed.schema, "disrobe-pickle-ml-ref/v1");
    assert!(
        parsed.measured_by.contains("Unpickler"),
        "the reference must name the CPython machinery that measured it, got {:?}",
        parsed.measured_by
    );
    assert!(
        parsed.fixtures.len() >= 4,
        "the container reference carries only {} fixtures",
        parsed.fixtures.len()
    );
    parsed
}

fn fixture_bytes(name: &str, expected_len: usize) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(name);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "{}: the committed container fixture must be readable, or the boundary figure grades \
             nothing ({e})",
            path.display()
        )
    });
    assert_eq!(
        bytes.len(),
        expected_len,
        "{name} is {} bytes but the reference measured {expected_len}; the fixture and its \
         CPython measurement have drifted apart",
        bytes.len()
    );
    bytes
}

fn format_tag(format: ModelFormat) -> String {
    serde_json::to_value(format)
        .expect("model format serializes")
        .as_str()
        .expect("model format is a string")
        .to_owned()
}

#[test]
fn every_container_member_lands_on_the_cpython_measured_boundary() {
    let reference: StreamReference = reference();
    let mut graded: usize = 0;
    let mut population: usize = 0;
    let mut discriminating: usize = 0;
    let mut defects: Vec<String> = Vec::new();

    for (name, expected) in &reference.fixtures {
        let bytes: Vec<u8> = fixture_bytes(name, expected.size_bytes);
        let report: MlReport = extract_ml(&bytes)
            .unwrap_or_else(|e: disrobe_pass_pickle::Error| panic!("extract {name}: {e}"));
        let actual_format: String = format_tag(report.format);
        if actual_format != expected.format {
            defects.push(format!(
                "{name}: recovered as {actual_format}, but the container was built as {}",
                expected.format
            ));
        }
        if report.embedded.len() != expected.members.len() {
            defects.push(format!(
                "{name}: {} embedded pickles recovered, CPython measures {} members",
                report.embedded.len(),
                expected.members.len()
            ));
        }
        for (index, want) in expected.members.iter().enumerate() {
            population += 1;
            if want
                .first_dot_length
                .is_some_and(|len: usize| len != want.length)
            {
                discriminating += 1;
            }
            let Some(got): Option<&EmbeddedPickle> = report.embedded.get(index) else {
                defects.push(format!(
                    "{name}: member {index} at offset {} was not recovered at all",
                    want.offset
                ));
                continue;
            };
            let mut member_defects: Vec<String> = Vec::new();
            if got.offset != want.offset {
                member_defects.push(format!("offset {} != {}", got.offset, want.offset));
            }
            if got.length != want.length {
                member_defects.push(format!(
                    "length {} != {}{}",
                    got.length,
                    want.length,
                    match want.first_dot_length {
                        Some(dot) if dot == got.length => format!(
                            " (that is the first 0x2e byte at index {}, not the STOP opcode)",
                            dot - 1
                        ),
                        _ => String::new(),
                    }
                ));
            }
            if got.protocol != Some(want.protocol) {
                member_defects.push(format!(
                    "protocol {:?} != Some({})",
                    got.protocol, want.protocol
                ));
            }
            if member_defects.is_empty() {
                graded += 1;
            } else {
                defects.push(format!(
                    "{name}: member {index} ({}): {}",
                    got.path,
                    member_defects.join(", ")
                ));
            }
        }
    }

    eprintln!(
        "pickle model containers: {graded} of {population} members land on the boundary CPython's \
         unpickler measures; {discriminating} of them sit past a 0x2e byte that a first-dot scan \
         would have stopped at"
    );
    assert!(
        discriminating >= 3,
        "only {discriminating} members carry a 0x2e byte before their STOP, so this gate could \
         not tell a real end-of-stream walk apart from a first-dot scan"
    );
    assert!(
        defects.is_empty(),
        "{graded} of {population} container members match the CPython reference:\n{}",
        defects.join("\n")
    );
    assert_eq!(
        graded, population,
        "every committed container member must be recovered on its measured boundary"
    );
}

#[test]
fn the_legacy_torch_container_names_its_five_documented_members() {
    let reference: StreamReference = reference();
    for name in ["legacy_torch_p2.pt", "legacy_torch_p0.pt"] {
        let expected: &FixtureRef = reference
            .fixtures
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be in the reference"));
        let bytes: Vec<u8> = fixture_bytes(name, expected.size_bytes);
        let report: MlReport = extract_ml(&bytes).expect("extract");
        assert_eq!(report.format, ModelFormat::PyTorchStackedPickle);
        let paths: Vec<&str> = report
            .embedded
            .iter()
            .map(|member: &EmbeddedPickle| member.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "<magic>",
                "<protocol_version>",
                "<sys_info>",
                "<module>",
                "<storage_keys>",
            ],
            "{name}: the five members of torch's legacy save order must be named for what they are"
        );
        let framing: &str = report.framing.as_deref().unwrap_or_default();
        assert!(
            framing.contains("0x1950a86a20f9469cfc6c"),
            "{name}: the framing must report the magic number that identified the container, got \
             {framing:?}"
        );
        assert!(
            framing.contains(&format!("{} trailing bytes", expected.trailing_bytes)),
            "{name}: the framing must account for the {} bytes of storage payload after the last \
             member, got {framing:?}",
            expected.trailing_bytes
        );
    }
}

#[test]
fn a_single_stream_with_a_trailer_is_not_a_stacked_container() {
    let reference: StreamReference = reference();
    let name: &str = "bare_pickle_trailer.bin";
    let expected: &FixtureRef = reference.fixtures.get(name).expect("fixture in reference");
    let bytes: Vec<u8> = fixture_bytes(name, expected.size_bytes);
    let report: MlReport = extract_ml(&bytes).expect("extract");
    assert_eq!(
        report.format,
        ModelFormat::BarePickle,
        "one stream plus trailing bytes is a bare pickle, not a stacked container"
    );
    assert_eq!(report.embedded.len(), 1);
    assert_eq!(
        report.embedded[0].length, expected.members[0].length,
        "the reported length must be the pickle stream, not the whole file"
    );
    assert!(
        report
            .framing
            .as_deref()
            .unwrap_or_default()
            .contains(&format!("{} trailing bytes", expected.trailing_bytes)),
        "the trailing bytes after the stream must be reported, got {:?}",
        report.framing
    );
}
