#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "common/published.rs"]
mod published;
#[path = "common/wat_corpus.rs"]
mod wat_corpus;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body,
};
use published::published_bar;
use serde::{Deserialize, Serialize};
use wat_corpus::{callees, corpus_key, defined_bodies, wat_files};

const EXTERNAL_TOOL: &str = "wasm-tools";
const EXTERNAL_TOOL_VERSION: &str = "wasm-tools 1.250.0";
const EXTERNAL_COMMAND: &str = "wasm-tools dump <corpus>.wat";
const INSTRUCTION_UNIT: &str = "body_instructions = decoded_instructions minus the single 0x0B that terminates each function \
     body, which the binary format carries as the body delimiter rather than as an instruction of \
     the body";

const INVENTORY_PATH: &str = "tests/golden/external_wasm_op_inventory.json";
const TOOL_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_TOOL_OUTPUT: usize = 32 * 1024 * 1024;

const PUBLISHED_HEADING: &str = "WebAssembly (committed 133-fn corpus";
const PUBLISHED_BAR: &str = "op-coverage";
const COVERAGE_FLOOR_PCT: f64 = 100.0;
const PINNED_FUNCTIONS: usize = 133;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExternalInventory {
    tool: String,
    tool_version: String,
    command: String,
    instruction_unit: String,
    modules: Vec<ExternalModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExternalModule {
    path: String,
    source_blake3: String,
    assembles: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reject_reason: Option<String>,
    functions: Vec<ExternalFunction>,
    decoded_instructions: usize,
    body_instructions: usize,
    mnemonics: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExternalFunction {
    index: usize,
    decoded_instructions: usize,
    body_instructions: usize,
}

#[derive(Debug, Clone)]
struct DumpFunction {
    index: usize,
    mnemonics: Vec<String>,
}

fn inventory_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(INVENTORY_PATH)
}

fn source_blake3(path: &Path) -> String {
    let bytes: Vec<u8> = fs::read(path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    blake3::hash(&bytes).to_hex().to_string()
}

fn run_tool(args: &[OsString]) -> CapturedOutput {
    let program: PathBuf = PathBuf::from(EXTERNAL_TOOL);
    let spawned: Option<CapturedOutput> =
        run_captured(&program, args, TOOL_TIMEOUT, MAX_TOOL_OUTPUT).unwrap_or_else(
            |error: std::io::Error| {
                panic!(
                    "regenerating {INVENTORY_PATH} needs {EXTERNAL_TOOL} ({EXTERNAL_TOOL_VERSION}) \
                     on PATH; install it with `cargo install --locked wasm-tools --version \
                     1.250.0`: {error}"
                )
            },
        );
    spawned.unwrap_or_else(|| {
        panic!("{EXTERNAL_TOOL} did not finish within {TOOL_TIMEOUT:?}, so nothing was measured")
    })
}

fn pinned_tool_or_panic() {
    let captured: CapturedOutput = run_tool(&[OsString::from("--version")]);
    let reported: String = String::from_utf8_lossy(&captured.stdout).trim().to_owned();
    assert_eq!(
        reported, EXTERNAL_TOOL_VERSION,
        "the pinned inventory records {EXTERNAL_TOOL_VERSION}; regenerating it under a different \
         build silently reinterprets every count"
    );
}

fn function_header_index(line: &str) -> Option<usize> {
    let rest: &str = line.strip_prefix("==============")?;
    let name: &str = rest.trim_matches('=').trim();
    name.strip_prefix("func ")?.trim().parse::<usize>().ok()
}

fn description_field(line: &str) -> Option<&str> {
    let mut parts: std::str::SplitN<'_, char> = line.splitn(3, '|');
    let _offset: &str = parts.next()?;
    let _bytes: &str = parts.next()?;
    let description: &str = parts.next()?.trim();
    (!description.is_empty()).then_some(description)
}

fn is_body_prelude(description: &str) -> bool {
    if description == "size of function" {
        return true;
    }
    let mut words: std::str::SplitWhitespace<'_> = description.split_whitespace();
    let Some(first): Option<&str> = words.next() else {
        return false;
    };
    if first.parse::<u64>().is_err() {
        return false;
    }
    let rest: String = words.collect::<Vec<&str>>().join(" ");
    matches!(rest.as_str(), "local block" | "local blocks") || rest.starts_with("local")
}

fn parse_dump_functions(dump: &str) -> Result<Vec<DumpFunction>, String> {
    let mut out: Vec<DumpFunction> = Vec::new();
    let mut current: Option<DumpFunction> = None;
    for raw in dump.lines() {
        let line: &str = raw.trim_end();
        if let Some(index) = function_header_index(line.trim()) {
            out.extend(current.take());
            current = Some(DumpFunction {
                index,
                mnemonics: Vec::new(),
            });
            continue;
        }
        let Some(description): Option<&str> = description_field(line) else {
            continue;
        };
        if description.ends_with(" section") {
            out.extend(current.take());
            continue;
        }
        let Some(function): Option<&mut DumpFunction> = current.as_mut() else {
            continue;
        };
        if is_body_prelude(description) {
            continue;
        }
        let mnemonic: &str = description.split_whitespace().next().unwrap_or(description);
        function.mnemonics.push(mnemonic.to_owned());
    }
    out.extend(current.take());
    for function in &out {
        let last: Option<&str> = function.mnemonics.last().map(String::as_str);
        if last != Some("end") {
            return Err(format!(
                "function {} did not decode down to a terminating end (last was {last:?}), so the \
                 dump was read wrong and no count derived from it can be trusted",
                function.index
            ));
        }
    }
    Ok(out)
}

fn measure_external(path: &Path) -> ExternalModule {
    let key: String = corpus_key(path);
    let hash: String = source_blake3(path);
    let captured: CapturedOutput = run_tool(&[OsString::from("dump"), OsString::from(path)]);
    if captured.exit_code != Some(0) {
        let stderr: String = String::from_utf8_lossy(&captured.stderr).into_owned();
        let reason: String = stderr
            .lines()
            .find(|line: &&str| !line.trim().is_empty())
            .unwrap_or("rejected without a message")
            .trim()
            .to_owned();
        return ExternalModule {
            path: key,
            source_blake3: hash,
            assembles: false,
            reject_reason: Some(reason),
            functions: Vec::new(),
            decoded_instructions: 0,
            body_instructions: 0,
            mnemonics: BTreeMap::new(),
        };
    }
    let dump: String = String::from_utf8_lossy(&captured.stdout).into_owned();
    let functions: Vec<DumpFunction> = parse_dump_functions(&dump)
        .unwrap_or_else(|error: String| panic!("{}: {error}", path.display()));
    let mut mnemonics: BTreeMap<String, usize> = BTreeMap::new();
    let mut decoded: usize = 0;
    let mut body: usize = 0;
    let mut rows: Vec<ExternalFunction> = Vec::with_capacity(functions.len());
    for function in &functions {
        for mnemonic in &function.mnemonics {
            *mnemonics.entry(mnemonic.clone()).or_default() += 1;
        }
        let function_decoded: usize = function.mnemonics.len();
        let function_body: usize = function_decoded.saturating_sub(1);
        decoded += function_decoded;
        body += function_body;
        rows.push(ExternalFunction {
            index: function.index,
            decoded_instructions: function_decoded,
            body_instructions: function_body,
        });
    }
    ExternalModule {
        path: key,
        source_blake3: hash,
        assembles: true,
        reject_reason: None,
        functions: rows,
        decoded_instructions: decoded,
        body_instructions: body,
        mnemonics,
    }
}

#[derive(Debug, Default, Clone)]
struct OurTally {
    accounted_ops: usize,
    lowered_ops: usize,
    functions: usize,
    functions_rejected_by_reparse: usize,
    untranslated: BTreeMap<String, usize>,
}

fn measure_ours(path: &Path) -> Option<OurTally> {
    let text: String = fs::read_to_string(path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let bytes: Vec<u8> = wat::parse_str(&text).ok()?;
    let sigs: ModuleSignatures = extract_signatures(&bytes).ok()?;
    let defined: &[FunctionSig] = sigs.defined();
    let names: CalleeNames = callees(&sigs);
    let mut tally: OurTally = OurTally::default();
    for (i, body) in defined_bodies(&bytes).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(i) else {
            continue;
        };
        tally.functions += 1;
        let lifted: LiftResult = lift_function_body(body, sig, &names, LiftTarget::Wat);
        tally.accounted_ops += lifted.coverage.total_ops;
        for mnemonic in &lifted.coverage.untranslated {
            *tally.untranslated.entry(mnemonic.clone()).or_default() += 1;
        }
        if wat::parse_str(&lifted.pseudo_source).is_ok() {
            tally.lowered_ops += lifted.coverage.translated_ops;
        } else {
            tally.functions_rejected_by_reparse += 1;
        }
    }
    Some(tally)
}

fn load_inventory() -> ExternalInventory {
    let path: PathBuf = inventory_path();
    let raw: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} pins the third-party instruction inventory the published figure is divided by; \
             without it nothing external has been measured and the run must fail rather than \
             score itself: {error}",
            path.display()
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()))
}

#[test]
#[ignore = "regenerates the pinned third-party inventory and needs wasm-tools on PATH"]
fn regenerate_external_inventory() {
    pinned_tool_or_panic();
    let files: Vec<PathBuf> = wat_files();
    assert!(
        !files.is_empty(),
        "the wat corpus resolved to nothing, so regeneration would freeze an empty inventory"
    );
    let modules: Vec<ExternalModule> = files
        .iter()
        .map(|path: &PathBuf| measure_external(path))
        .collect();
    let inventory: ExternalInventory = ExternalInventory {
        tool: EXTERNAL_TOOL.to_owned(),
        tool_version: EXTERNAL_TOOL_VERSION.to_owned(),
        command: EXTERNAL_COMMAND.to_owned(),
        instruction_unit: INSTRUCTION_UNIT.to_owned(),
        modules,
    };
    let path: PathBuf = inventory_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error: std::io::Error| panic!("create {}: {error}", parent.display()));
    }
    let mut encoded: String = serde_json::to_string_pretty(&inventory).expect("encode inventory");
    encoded.push('\n');
    fs::write(&path, encoded)
        .unwrap_or_else(|error: std::io::Error| panic!("write {}: {error}", path.display()));

    let assembles: usize = inventory
        .modules
        .iter()
        .filter(|module: &&ExternalModule| module.assembles)
        .count();
    let instructions: usize = inventory
        .modules
        .iter()
        .map(|module: &ExternalModule| module.body_instructions)
        .sum();
    eprintln!(
        "wrote {} modules ({assembles} assembled by {EXTERNAL_TOOL_VERSION}) totalling \
         {instructions} body instructions to {}",
        inventory.modules.len(),
        path.display()
    );
}

#[test]
fn op_coverage_is_divided_by_the_external_instruction_inventory() {
    let inventory: ExternalInventory = load_inventory();
    assert_eq!(
        inventory.tool_version, EXTERNAL_TOOL_VERSION,
        "the inventory was produced by a build this check does not pin"
    );
    assert_eq!(inventory.tool, EXTERNAL_TOOL, "unexpected inventory tool");

    let files: Vec<PathBuf> = wat_files();
    let corpus_keys: Vec<String> = files
        .iter()
        .map(|path: &PathBuf| corpus_key(path))
        .collect();
    let inventory_keys: Vec<String> = inventory
        .modules
        .iter()
        .map(|module: &ExternalModule| module.path.clone())
        .collect();
    assert_eq!(
        corpus_keys, inventory_keys,
        "the corpus and the pinned inventory describe different module sets, so the denominator \
         no longer covers what runs; regenerate with `cargo test -p disrobe-pass-wasm-deob --test \
         external_op_denominator -- --ignored regenerate_external_inventory`"
    );

    let mut external_total: usize = 0;
    let mut ours_accounted: usize = 0;
    let mut ours_lowered: usize = 0;
    let mut functions: usize = 0;
    let mut modules_measured: usize = 0;
    let mut modules_rejected: usize = 0;
    let mut untranslated: BTreeMap<String, usize> = BTreeMap::new();
    let mut reparse_rejects: usize = 0;

    for (path, module) in files.iter().zip(inventory.modules.iter()) {
        assert_eq!(
            source_blake3(path),
            module.source_blake3,
            "{} changed since the inventory was pinned, so its instruction count is stale",
            module.path
        );
        let ours: Option<OurTally> = measure_ours(path);
        if !module.assembles {
            assert!(
                ours.is_none(),
                "{} is pinned as rejected by {EXTERNAL_TOOL_VERSION} ({}), yet this crate \
                 assembled it; a module only one side can read cannot be scored against the other",
                module.path,
                module
                    .reject_reason
                    .as_deref()
                    .unwrap_or("no reason pinned")
            );
            modules_rejected += 1;
            continue;
        }
        let ours: OurTally = ours.unwrap_or_else(|| {
            panic!(
                "{EXTERNAL_TOOL_VERSION} decoded {} instructions in {}, and this crate could not \
                 read the module at all",
                module.body_instructions, module.path
            )
        });
        assert_eq!(
            module.functions.len(),
            ours.functions,
            "{EXTERNAL_TOOL_VERSION} decoded {} function bodies in {}, this crate found {}; a \
             denominator computed over a different set of bodies is not the same measurement",
            module.functions.len(),
            module.path,
            ours.functions
        );
        assert!(
            ours.accounted_ops <= module.body_instructions,
            "{} carries {} body instructions per {EXTERNAL_TOOL_VERSION}, but this crate accounted \
             for {}; a count above the external one means the inventory is stale or the decode \
             double-counts",
            module.path,
            module.body_instructions,
            ours.accounted_ops
        );
        modules_measured += 1;
        external_total += module.body_instructions;
        ours_accounted += ours.accounted_ops;
        ours_lowered += ours.lowered_ops;
        functions += ours.functions;
        reparse_rejects += ours.functions_rejected_by_reparse;
        for (mnemonic, count) in &ours.untranslated {
            *untranslated.entry(mnemonic.clone()).or_default() += count;
        }
    }

    assert!(
        external_total > 0,
        "the pinned inventory carries no instructions, so this check would divide by nothing"
    );
    let coverage: f64 = 100.0 * ours_lowered as f64 / external_total as f64;
    let unseen: usize = external_total.saturating_sub(ours_accounted);

    eprintln!(
        "wasm op-coverage against {EXTERNAL_TOOL_VERSION}: {modules_measured} modules measured, \
         {modules_rejected} rejected by both sides, {functions} functions"
    );
    eprintln!("  external body instructions: {external_total}");
    eprintln!("  instructions this crate accounted for: {ours_accounted} (unseen: {unseen})");
    eprintln!("  instructions lowered in re-parsing output: {ours_lowered} = {coverage:.2}%");
    eprintln!("  functions whose output failed re-parse: {reparse_rejects}");
    for (mnemonic, count) in &untranslated {
        eprintln!("  untranslated {mnemonic}: {count}");
    }

    assert!(
        coverage >= COVERAGE_FLOOR_PCT,
        "op-coverage against the external inventory is {coverage:.2}% ({ours_lowered} of \
         {external_total}), below the published floor of {COVERAGE_FLOOR_PCT}%"
    );

    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the wasm op-coverage bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the wasm op-coverage bar must carry a denominator");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the wasm op-coverage bar must carry a numeric value");
    assert_eq!(
        u64::try_from(external_total).expect("external total fits u64"),
        den,
        "every document renders the denominator from recovery.json, and it publishes {den} where \
         {EXTERNAL_TOOL_VERSION} counts {external_total}"
    );
    assert!(
        u64::try_from(ours_lowered).expect("lowered fits u64") >= num,
        "recovery.json publishes {num} of {den} instructions lowered; this run lowered \
         {ours_lowered}"
    );
    let derived: f64 = 100.0 * num as f64 / den as f64;
    assert!(
        (derived - value).abs() < 0.005,
        "the published value {value} disagrees with its own {num}/{den} = {derived:.4}"
    );
}

#[test]
fn every_module_the_external_tool_rejects_is_pinned_with_its_reason() {
    let inventory: ExternalInventory = load_inventory();
    let mut pinned_functions: usize = 0;
    for module in &inventory.modules {
        if module.assembles {
            assert!(
                module.reject_reason.is_none(),
                "{} assembles, so it must not carry a rejection reason",
                module.path
            );
            let counted: usize = module
                .functions
                .iter()
                .map(|function: &ExternalFunction| function.body_instructions)
                .sum();
            assert_eq!(
                counted, module.body_instructions,
                "{} pins a module total that its own per-function rows do not add up to",
                module.path
            );
            pinned_functions += module.functions.len();
            continue;
        }
        let reason: &str = module
            .reject_reason
            .as_deref()
            .unwrap_or_else(|| panic!("{} is pinned as rejected with no reason", module.path));
        assert!(
            reason.starts_with("error:"),
            "{} must pin the reason {EXTERNAL_TOOL} gave, got {reason:?}",
            module.path
        );
        assert_eq!(
            module.body_instructions, 0,
            "{} is rejected, so it can contribute no instructions",
            module.path
        );
    }
    assert_eq!(
        pinned_functions, PINNED_FUNCTIONS,
        "the inventory pins {pinned_functions} function bodies where the published corpus carries \
         {PINNED_FUNCTIONS}; a shrunken inventory shrinks the denominator with it"
    );
}
