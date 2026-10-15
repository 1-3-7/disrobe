#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_pass_evm::{
    EvmReport, FunctionReport, InputFormat, Limits, Options, TypeBasis, analyze, decode_input,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const BUILDS: [&str; 13] = [
    "solc/0.8.37-o0",
    "solc/0.8.37-o1",
    "solc/0.8.37-ir-o0",
    "solc/0.8.37-ir-o1",
    "solc/0.8.19-o0",
    "solc/0.8.19-o1",
    "solc/0.8.19-ir-o1",
    "solc/0.6.12-o0",
    "solc/0.6.12-o1",
    "solc/0.4.26-o0",
    "solc/0.4.26-o1",
    "vyper/gas",
    "vyper/codesize",
];

const UNCONSTRAINED_WORD: [&str; 3] = ["uint256", "int256", "bytes32"];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/evm")
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn selector(signature: &str) -> String {
    let digest = Keccak256::digest(signature.as_bytes());
    format!("0x{}", hex_digest(&digest[..4]))
}

fn topic(signature: &str) -> String {
    format!("0x{}", hex_digest(&Keccak256::digest(signature.as_bytes())))
}

fn canonical(entry: &Value) -> String {
    let inputs: Vec<String> = entry["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["type"].as_str().unwrap().to_owned())
        .collect();
    format!("{}({})", entry["name"].as_str().unwrap(), inputs.join(","))
}

#[derive(Debug, Default, Clone)]
struct Figures {
    contracts: usize,
    splits_exact: usize,
    functions: usize,
    selectors_found: usize,
    mutability_exact: usize,
    arguments: usize,
    arguments_exact: usize,
    arguments_class: usize,
    signatures_resolved: usize,
    fallback_receive_exact: usize,
    events_named: usize,
    errors_found: usize,
}

impl Figures {
    const fn add(&mut self, other: &Self) {
        self.contracts += other.contracts;
        self.splits_exact += other.splits_exact;
        self.functions += other.functions;
        self.selectors_found += other.selectors_found;
        self.mutability_exact += other.mutability_exact;
        self.arguments += other.arguments;
        self.arguments_exact += other.arguments_exact;
        self.arguments_class += other.arguments_class;
        self.signatures_resolved += other.signatures_resolved;
        self.fallback_receive_exact += other.fallback_receive_exact;
        self.events_named += other.events_named;
        self.errors_found += other.errors_found;
    }
}

struct Grade {
    figures: Figures,
    mismatches: Vec<String>,
}

fn class_match(reference: &str, function: &FunctionReport, index: usize) -> bool {
    let argument = &function.arguments[index];
    match argument.basis {
        TypeBasis::Unconstrained => UNCONSTRAINED_WORD.contains(&reference),
        TypeBasis::DynamicBytes | TypeBasis::DynamicUnscaled => {
            reference == "string" || reference == "bytes"
        }
        _ => false,
    }
}

fn grade(label: &str, report: &EvmReport, reference: &Value) -> Grade {
    let mut figures: Figures = Figures {
        contracts: 1,
        ..Figures::default()
    };
    let mut mismatches: Vec<String> = Vec::new();
    let runtime_sha = reference["runtime"]["sha256"].as_str().unwrap();
    let runtime_len = reference["runtime"]["length"].as_u64().unwrap() as usize;
    if report.layout.kind == "creation"
        && report.layout.runtime_bytes == runtime_len
        && report.runtime.sha256 == format!("0x{runtime_sha}")
    {
        figures.splits_exact += 1;
    } else {
        mismatches.push(format!(
            "{label}: runtime split {} {} bytes {} vs solc {runtime_len} bytes {runtime_sha}",
            report.layout.kind, report.layout.runtime_bytes, report.runtime.sha256
        ));
    }
    let abi: &Vec<Value> = reference["abi"].as_array().unwrap();
    let getters: BTreeSet<&str> = reference["constantGetters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    let identifiers: BTreeMap<String, String> = reference["methodIdentifiers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(signature, id)| (format!("0x{}", id.as_str().unwrap()), signature.clone()))
        .collect();
    let found: BTreeMap<&str, &FunctionReport> = report
        .functions
        .iter()
        .map(|function| (function.selector.as_str(), function))
        .collect();
    for extra in found
        .keys()
        .filter(|selector| !identifiers.contains_key(**selector))
    {
        mismatches.push(format!(
            "{label}: selector {extra} is not in solc's method identifiers"
        ));
    }
    for entry in abi.iter().filter(|entry| entry["type"] == "function") {
        let signature: String = canonical(entry);
        let id: String = selector(&signature);
        assert_eq!(
            identifiers.get(&id),
            Some(&signature),
            "{label}: ABI and methodIdentifiers disagree on {signature}"
        );
        figures.functions += 1;
        let Some(function) = found.get(id.as_str()) else {
            mismatches.push(format!("{label}: {signature} ({id}) not recovered"));
            continue;
        };
        figures.selectors_found += 1;
        let declared: &str = entry["stateMutability"].as_str().unwrap();
        let expected: &str = if getters.contains(entry["name"].as_str().unwrap()) {
            "pure"
        } else {
            declared
        };
        if function.mutability.name() == expected {
            figures.mutability_exact += 1;
        } else {
            mismatches.push(format!(
                "{label}: {signature} mutability {} vs {expected} ({:?})",
                function.mutability.name(),
                function.mutability_basis
            ));
        }
        let inputs: Vec<&str> = entry["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| input["type"].as_str().unwrap())
            .collect();
        figures.arguments += inputs.len();
        if function.arguments.len() == inputs.len() {
            for (index, reference_type) in inputs.iter().enumerate() {
                if function.arguments[index].ty == *reference_type {
                    figures.arguments_exact += 1;
                } else if class_match(reference_type, function, index) {
                    figures.arguments_class += 1;
                } else {
                    mismatches.push(format!(
                        "{label}: {signature} argument {index} {} ({:?}) vs {reference_type}",
                        function.arguments[index].ty, function.arguments[index].basis
                    ));
                }
            }
        } else {
            let types: Vec<&str> = function
                .arguments
                .iter()
                .map(|arg| arg.ty.as_str())
                .collect();
            mismatches.push(format!(
                "{label}: {signature} recovered {} arguments ({}) vs {}",
                types.len(),
                types.join(","),
                inputs.len()
            ));
        }
        if let Some(known) = function.signature {
            figures.signatures_resolved += 1;
            if known != signature {
                mismatches.push(format!(
                    "{label}: {id} named {known} but solc says {signature}"
                ));
            }
        }
    }
    let has = |kind: &str| abi.iter().any(|entry| entry["type"] == kind);
    if report.dispatcher.fallback == has("fallback") && report.dispatcher.receive == has("receive")
    {
        figures.fallback_receive_exact += 1;
    } else {
        mismatches.push(format!(
            "{label}: fallback {} receive {} vs ABI fallback {} receive {}",
            report.dispatcher.fallback,
            report.dispatcher.receive,
            has("fallback"),
            has("receive")
        ));
    }
    let events: BTreeSet<String> = abi
        .iter()
        .filter(|entry| entry["type"] == "event")
        .map(|entry| topic(&canonical(entry)))
        .collect();
    for found_topic in report.event_topics.keys() {
        if events.contains(found_topic) {
            figures.events_named += 1;
        } else {
            mismatches.push(format!(
                "{label}: event topic {found_topic} is not an ABI event"
            ));
        }
    }
    for missing in events
        .iter()
        .filter(|event| !report.event_topics.contains_key(*event))
    {
        mismatches.push(format!(
            "{label}: ABI event {missing} is never seen emitted"
        ));
    }
    let errors: BTreeSet<String> = abi
        .iter()
        .filter(|entry| entry["type"] == "error")
        .map(|entry| selector(&canonical(entry)))
        .collect();
    for found_error in report.error_selectors.keys() {
        if errors.contains(found_error) {
            figures.errors_found += 1;
        } else {
            mismatches.push(format!(
                "{label}: error selector {found_error} is not an ABI error"
            ));
        }
    }
    for missing in errors
        .iter()
        .filter(|error| !report.error_selectors.contains_key(*error))
    {
        mismatches.push(format!(
            "{label}: ABI error {missing} is never seen reverted with"
        ));
    }
    if !report.cfg.unresolved_jumps.is_empty() || !report.cfg.invalid_jump_targets.is_empty() {
        mismatches.push(format!(
            "{label}: CFG left jumps unresolved {:?} or invalid {:?}",
            report.cfg.unresolved_jumps, report.cfg.invalid_jump_targets
        ));
    }
    let reverts: BTreeSet<&str> = report
        .functions
        .iter()
        .flat_map(|function| function.reverts.iter().map(String::as_str))
        .collect();
    for message in reference["requireMessages"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let wanted: String = format!("Error({:?})", message.as_str().unwrap());
        if !reverts.contains(wanted.as_str()) {
            mismatches.push(format!("{label}: revert reason {wanted} not decoded"));
        }
    }
    Grade {
        figures,
        mismatches,
    }
}

fn load(build: &str) -> Value {
    let path: PathBuf = corpus().join(build).join("reference.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("solc reference {} is missing: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn creation(build: &str, file: &str) -> Vec<u8> {
    let path: PathBuf = corpus().join(build).join(file);
    let text: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("solc output {} is missing: {e}", path.display()));
    let creation_sha: String = hex_digest(&Sha256::digest(
        decode_input(&text, InputFormat::Hex, &Limits::default())
            .unwrap()
            .bytes,
    ));
    let reference: Value = load(build);
    let recorded = reference["contracts"]
        .as_object()
        .unwrap()
        .values()
        .find(|contract| contract["creation"]["file"] == file)
        .unwrap();
    assert_eq!(
        recorded["creation"]["sha256"].as_str().unwrap(),
        creation_sha,
        "{build}/{file} differs from the build record"
    );
    decode_input(&text, InputFormat::Auto, &Limits::default())
        .unwrap()
        .bytes
}

fn grade_bytes(label: &str, code: &[u8], reference: &Value) -> Grade {
    let report: EvmReport = analyze(code, &Options::default())
        .unwrap_or_else(|e| panic!("{label}: analysis failed: {e}"));
    grade(label, &report, reference)
}

fn metadata_mismatches(label: &str, report: &EvmReport, reference: &Value) -> Vec<String> {
    let compiler: &str = reference["compiler"].as_str().unwrap();
    let release: &str = compiler.split('+').next().unwrap();
    let (name, version): (&str, &str) = release
        .strip_prefix("vyper ")
        .map_or(("solc", release), |version| ("vyper", version));
    let settings: &Value = &reference["settings"];
    let expect_trailer: bool = settings["appendCBOR"].as_bool().unwrap_or(true);
    let Some(metadata) = &report.metadata else {
        return if expect_trailer {
            vec![format!(
                "{label}: no metadata trailer although {compiler} appends one"
            )]
        } else {
            Vec::new()
        };
    };
    if !expect_trailer {
        return vec![format!(
            "{label}: metadata trailer found although appendCBOR is off"
        )];
    }
    let mut out: Vec<String> = Vec::new();
    let decoded: Option<(&str, &str)> = metadata
        .compiler
        .as_ref()
        .map(|c| (c.name, c.version.as_str()));
    let legacy_trailer: bool = version.starts_with("0.4.");
    if !legacy_trailer && decoded != Some((name, version)) {
        out.push(format!(
            "{label}: metadata compiler {decoded:?} vs {name} {version}"
        ));
    }
    let hash_kind: &str = match (&metadata.ipfs, &metadata.bzzr0, &metadata.bzzr1) {
        (Some(_), _, _) => "ipfs",
        (_, Some(_), _) => "bzzr0",
        (_, _, Some(_)) => "bzzr1",
        _ => "none",
    };
    let expected_kind: &str = match settings["bytecodeHash"].as_str() {
        Some(kind) => kind,
        None if name == "vyper" => "none",
        None if legacy_trailer => "bzzr0",
        None => "ipfs",
    };
    if hash_kind != expected_kind {
        out.push(format!(
            "{label}: metadata hash {hash_kind} vs {expected_kind}"
        ));
    }
    out
}

#[test]
fn recovered_interfaces_match_solc_exactly() {
    let mut total: Figures = Figures::default();
    let mut mismatches: Vec<String> = Vec::new();
    for build in BUILDS {
        let reference: Value = load(build);
        for (name, contract) in reference["contracts"].as_object().unwrap() {
            let label: String = format!("{build}/{name}");
            let code: Vec<u8> = creation(build, contract["creation"]["file"].as_str().unwrap());
            let report: EvmReport = analyze(&code, &Options::default())
                .unwrap_or_else(|e| panic!("{label}: analysis failed: {e}"));
            let grade: Grade = grade(&label, &report, contract);
            total.add(&grade.figures);
            mismatches.extend(grade.mismatches);
            mismatches.extend(metadata_mismatches(&label, &report, &reference));
        }
    }
    println!("{total:#?}");
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(total.selectors_found, total.functions);
    assert_eq!(total.mutability_exact, total.functions);
    assert_eq!(total.splits_exact, total.contracts);
}

fn runtime_of(build: &str, name: &str) -> (Vec<u8>, Value) {
    let reference: Value = load(build);
    let contract: Value = reference["contracts"][name].clone();
    let code: Vec<u8> = creation(build, contract["creation"]["file"].as_str().unwrap());
    let report: EvmReport = analyze(&code, &Options::default()).unwrap();
    let offset: usize = report.layout.runtime_offset.unwrap();
    let runtime: Vec<u8> = code[offset..offset + report.layout.runtime_bytes].to_vec();
    (runtime, contract)
}

#[test]
fn raw_runtime_grades_like_the_creation_split() {
    let (runtime, contract) = runtime_of("solc/0.8.37-o1", "Erc20");
    let grade: Grade = grade_bytes("raw runtime", &runtime, &contract);
    let runtime_only: Vec<String> = grade
        .mismatches
        .iter()
        .filter(|line| !line.contains("runtime split"))
        .cloned()
        .collect();
    assert!(runtime_only.is_empty(), "{runtime_only:#?}");
    assert_eq!(grade.figures.selectors_found, grade.figures.functions);
}

#[test]
fn a_dropped_jumpdest_turns_the_grader_red() {
    let (mut runtime, contract) = runtime_of("solc/0.8.37-o0", "Erc20");
    let report: EvmReport = analyze(&runtime, &Options::default()).unwrap();
    let entry: usize = report.functions[0].entry;
    assert_eq!(runtime[entry], 0x5b, "function entries are JUMPDESTs");
    runtime[entry] = 0x58;
    let grade: Grade = grade_bytes("dropped jumpdest", &runtime, &contract);
    assert!(
        grade
            .mismatches
            .iter()
            .any(|line| line.contains("not recovered") || line.contains("mutability")),
        "the grader stayed green after a function entry lost its JUMPDEST: {:#?}",
        grade.mismatches
    );
}

#[test]
fn an_altered_selector_turns_the_grader_red() {
    let (mut runtime, contract) = runtime_of("solc/0.8.19-o1", "Erc20");
    let transfer: [u8; 5] = [0x63, 0xa9, 0x05, 0x9c, 0xbb];
    let at: usize = runtime
        .windows(5)
        .position(|window| window == transfer)
        .expect("PUSH4 transfer(address,uint256) is in the dispatcher");
    runtime[at + 4] ^= 0x01;
    let grade: Grade = grade_bytes("altered selector", &runtime, &contract);
    assert!(
        grade
            .mismatches
            .iter()
            .any(|line| line.contains("0xa9059cbb") && line.contains("not recovered")),
        "the grader stayed green after a PUSH4 selector changed: {:#?}",
        grade.mismatches
    );
    assert!(
        grade
            .mismatches
            .iter()
            .any(|line| line.contains("0xa9059cba")),
        "the altered selector was not reported as foreign: {:#?}",
        grade.mismatches
    );
}

#[test]
fn an_altered_vyper_table_selector_turns_the_grader_red() {
    let (mut runtime, contract) = runtime_of("vyper/codesize", "Ledger");
    let transfer: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    let at: usize = runtime
        .windows(4)
        .position(|window| window == transfer)
        .expect("transfer(address,uint256) is in the dense selector table");
    runtime[at + 3] ^= 0x01;
    let grade: Grade = grade_bytes("altered vyper table", &runtime, &contract);
    assert!(
        grade
            .mismatches
            .iter()
            .any(|line| line.contains("0xa9059cbb") && line.contains("not recovered")),
        "the grader stayed green after a dense-table selector changed: {:#?}",
        grade.mismatches
    );
}
