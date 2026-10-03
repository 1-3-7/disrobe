#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use object::Object as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BUILD_RECORD: &[u8] =
    include_bytes!("../../../../corpus/native/ollvm/real/build-record.json");
const TOOL_ENV: &[u8] = include_bytes!("../../../../corpus/native/ollvm/real/tool.env");
const BUILD_RECORD_SHA256: &str =
    "f7bedd6c9ac872d86a12f0f20f58f1c1ecfa5e53b90d3453c9f75acd654c8c84";
const TOOL_ENV_SHA256: &str = "b8028812ac2f587cc573db9ddac19de66ee783c4cd952ea989c3040ae022b186";
const OLLVM_COMMIT: &str = "b58debfd7f62c55f0a83ce975527f378b145ad6a";
const OLLVM_TREE: &str = "d78891c4b251fcd2d6618dae275be61c4f00c95e";
const RUNNER_COMMIT: &str = "594620ab93181d85ea32df2a48a580fe228c609e";
const RUNNER_URL: &str = "https://github.com/1-3-7/disrobe/actions/runs/37109535286";
const LLVM_ARCHIVE_SHA256: &str =
    "58a8818c60e6627064f312dbf46c02d9949956558340938b71cf731ad8bc0813";
const PATCHED_UTILS_SHA256: &str =
    "edc394317a4ec07682c3552fd6f6d36bf588299fcb5447195ee1106ef979a5d9";
const PATCHED_IP_CONTEXT_SHA256: &str =
    "ad63a53dc974564568307c6d4b30591677d37ec08a6c569a649642a465a9ee1d";

const PROBE_SOURCE: &[u8] = include_bytes!("../../../../corpus/native/ollvm/probe_src.c");
const OBFUSH_SOURCE: &[u8] =
    include_bytes!("../../../../corpus/native/obfuscators/obfush/sample.c");
const PROBE_SOURCE_SHA256: &str =
    "f90fe3aa7874c44e0a04803b47034738d113f5b393e66a7c437377fde4245813";
const OBFUSH_SOURCE_SHA256: &str =
    "16c8ebce39cd317dbf1eddf4b0d188784da6fb4c43922761cefb2dc6e88a1d71";

struct Fixture {
    bytes: &'static [u8],
    bytes_sha256: &'static str,
    command_fragment: &'static str,
    record_output: &'static str,
    source: &'static [u8],
    source_path: &'static str,
    source_sha256: &'static str,
}

const FIXTURES: [Fixture; 6] = [
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/ollvm-probe_src.bcf.elf"),
        bytes_sha256: "8e50dd8ff14f7e4bbc4611a70f358bdb025cbbd2e786accd2eb22ebceec9968c",
        command_fragment: "-bcf -mllvm -bcf_prob=100",
        record_output: "files/ollvm-probe_src.bcf.elf",
        source: PROBE_SOURCE,
        source_path: "corpus/native/ollvm/probe_src.c",
        source_sha256: PROBE_SOURCE_SHA256,
    },
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/ollvm-probe_src.sub.elf"),
        bytes_sha256: "07d27021fa18644e7f9f374a4d0394c2536ee44942f504681114efceed03e01a",
        command_fragment: "-sub -mllvm -sub_loop=2",
        record_output: "files/ollvm-probe_src.sub.elf",
        source: PROBE_SOURCE,
        source_path: "corpus/native/ollvm/probe_src.c",
        source_sha256: PROBE_SOURCE_SHA256,
    },
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/ollvm-probe_src.split.elf"),
        bytes_sha256: "3e0f47ae45718bb33bd4d76d7fffbd28bd65453db6db98def942fe14f2d1ef73",
        command_fragment: "-split -mllvm -split_num=3",
        record_output: "files/ollvm-probe_src.split.elf",
        source: PROBE_SOURCE,
        source_path: "corpus/native/ollvm/probe_src.c",
        source_sha256: PROBE_SOURCE_SHA256,
    },
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/obfush-sample.bcf.elf"),
        bytes_sha256: "5dc4b38846e5dbb36865162ce0daaed3813ca8c0ec7b8c827a2272975e11d44e",
        command_fragment: "-bcf -mllvm -bcf_prob=100",
        record_output: "files/obfush-sample.bcf.elf",
        source: OBFUSH_SOURCE,
        source_path: "corpus/native/obfuscators/obfush/sample.c",
        source_sha256: OBFUSH_SOURCE_SHA256,
    },
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/obfush-sample.sub.elf"),
        bytes_sha256: "4633fe8bc3da46df95faecda24dff7e1448d986f44f87b59b92045211b432f71",
        command_fragment: "-sub -mllvm -sub_loop=2",
        record_output: "files/obfush-sample.sub.elf",
        source: OBFUSH_SOURCE,
        source_path: "corpus/native/obfuscators/obfush/sample.c",
        source_sha256: OBFUSH_SOURCE_SHA256,
    },
    Fixture {
        bytes: include_bytes!("../../../../corpus/native/ollvm/real/obfush-sample.split.elf"),
        bytes_sha256: "f2d8ecdf14733067bf42161f8ba55caf2fceaa1bbccfacb84520f222d1f2507e",
        command_fragment: "-split -mllvm -split_num=3",
        record_output: "files/obfush-sample.split.elf",
        source: OBFUSH_SOURCE,
        source_path: "corpus/native/obfuscators/obfush/sample.c",
        source_sha256: OBFUSH_SOURCE_SHA256,
    },
];

#[derive(Deserialize)]
struct BuildRecord {
    files: BTreeMap<String, String>,
    outputs: Vec<RunnerOutput>,
    recipe: String,
    repository_commit: String,
    tool: ToolRecord,
    workflow_run: String,
}

#[derive(Deserialize)]
struct RunnerOutput {
    behaviour: String,
    command: String,
    input: String,
    input_sha256: String,
    output: Option<String>,
    output_bytes: Option<u64>,
    output_sha256: Option<String>,
}

#[derive(Deserialize)]
struct ToolRecord {
    commit: String,
    tree: String,
    url: String,
    version: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixture_identity_matches(bytes: &[u8], expected_sha256: &str) -> bool {
    sha256(bytes) == expected_sha256
}

fn assert_remote_producer_equivalence_receipts(record: &BuildRecord) {
    let same: Vec<&RunnerOutput> = record
        .outputs
        .iter()
        .filter(|output: &&RunnerOutput| output.behaviour == "same")
        .collect();
    assert_eq!(
        same.len(),
        FIXTURES.len(),
        "remote producer receipt must retain exactly the eligible equivalence outcomes"
    );

    for fixture in &FIXTURES {
        assert!(
            fixture_identity_matches(fixture.source, fixture.source_sha256),
            "authored source identity changed for {}",
            fixture.source_path
        );
        assert!(
            fixture_identity_matches(fixture.bytes, fixture.bytes_sha256),
            "remote producer fixture identity changed for {}",
            fixture.record_output
        );

        let object: object::File<'_> = object::File::parse(fixture.bytes)
            .expect("remote producer fixture is a static ELF object");
        assert_eq!(object.format(), object::BinaryFormat::Elf);
        assert_eq!(object.architecture(), object::Architecture::X86_64);
        let fixture_bytes: u64 =
            u64::try_from(fixture.bytes.len()).expect("fixture byte length fits u64");

        let output: &&RunnerOutput = same
            .iter()
            .find(|output: &&&RunnerOutput| output.output.as_deref() == Some(fixture.record_output))
            .expect("fixture has a remote producer equivalence receipt");
        assert_eq!(output.input, fixture.source_path);
        assert_eq!(output.input_sha256, fixture.source_sha256);
        assert!(output.command.contains(fixture.command_fragment));
        assert_eq!(output.output_bytes, Some(fixture_bytes));
        assert_eq!(output.output_sha256.as_deref(), Some(fixture.bytes_sha256));
        assert_eq!(
            record.files.get(fixture.record_output).map(String::as_str),
            Some(fixture.bytes_sha256)
        );
    }
}

#[test]
fn remote_ollvm_producer_receipt_is_pinned_and_static() {
    assert!(fixture_identity_matches(BUILD_RECORD, BUILD_RECORD_SHA256));
    assert!(fixture_identity_matches(TOOL_ENV, TOOL_ENV_SHA256));
    let tool_env: &str = std::str::from_utf8(TOOL_ENV).expect("OLLVM tool environment is utf-8");
    assert!(tool_env.contains("name=OLLVM (ollvm17 passes over LLVM 17.0.6)"));
    assert!(tool_env.contains("url=https://github.com/DreamSoule/ollvm17"));
    assert!(tool_env.contains(OLLVM_COMMIT));
    assert!(tool_env.contains(OLLVM_TREE));
    assert!(tool_env.contains(LLVM_ARCHIVE_SHA256));
    assert!(tool_env.contains(PATCHED_UTILS_SHA256));
    assert!(tool_env.contains(PATCHED_IP_CONTEXT_SHA256));

    let record: BuildRecord =
        serde_json::from_slice(BUILD_RECORD).expect("OLLVM build record is json");
    assert_eq!(record.recipe, "ollvm");
    assert_eq!(record.repository_commit, RUNNER_COMMIT);
    assert_eq!(record.workflow_run, RUNNER_URL);
    assert_eq!(record.tool.url, "https://github.com/DreamSoule/ollvm17");
    assert_eq!(record.tool.commit, OLLVM_COMMIT);
    assert_eq!(record.tool.tree, OLLVM_TREE);
    assert!(record.tool.version.contains(LLVM_ARCHIVE_SHA256));
    assert_remote_producer_equivalence_receipts(&record);
}

#[test]
fn remote_ollvm_producer_receipt_rejects_fixture_mutation() {
    let fixture: &Fixture = &FIXTURES[0];
    let mut mutated: Vec<u8> = fixture.bytes.to_vec();
    mutated[0] ^= 1;

    assert!(fixture_identity_matches(
        fixture.bytes,
        fixture.bytes_sha256
    ));
    assert!(!fixture_identity_matches(&mutated, fixture.bytes_sha256));
}

#[test]
fn remote_ollvm_producer_receipt_rejects_behaviour_mutation() {
    let mut record: BuildRecord =
        serde_json::from_slice(BUILD_RECORD).expect("OLLVM build record is json");
    let output: &mut RunnerOutput = record
        .outputs
        .iter_mut()
        .find(|output: &&mut RunnerOutput| {
            output.output.as_deref() == Some(FIXTURES[0].record_output)
        })
        .expect("fixture has a remote runner record");
    assert_eq!(output.behaviour, "same");
    output.behaviour = "differs".to_owned();

    let validation = std::panic::catch_unwind(|| {
        assert_remote_producer_equivalence_receipts(&record);
    });
    assert!(
        validation.is_err(),
        "a changed remote producer behaviour must fail the exact equivalence receipt validator"
    );
}
