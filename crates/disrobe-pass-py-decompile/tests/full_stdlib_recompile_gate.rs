#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::stdlib_measure::{
    EvidenceRequest, FULL_POPULATION, HarnessRun, MEASURE_HARNESS, Measurement, PINNED_POPULATION,
    PublishedBar, bar_disagreements, find_disrobe, find_python_314, interpreter_release,
    interpreter_stdlib, interpreter_version, manifest_dir, parse_measurement, population_line,
    publish_pct, published_bar, published_detail, read_module_list, recovery_document, run_measure,
    run_measure_with_evidence, workspace_target,
};

const FULL_MODULE_LIST: &str = "tests/harness/full_modules_314.txt";
const PINNED_MODULE_LIST: &str = "tests/harness/pinned_modules_314.txt";

const FULL_BAR_LABEL: &str = "fixed 574-module core population";
const PINNED_BAR_LABEL: &str = "200-module pinned corpus (normalized opcode-structure agreement)";

const FULL_MODULES: u64 = 574;
const FULL_MODULE_LIST_SHA256: &str =
    "cab2ea10ce57441d29f1117aa40e324fca805abf8ae80c2342cbd1ddcede028d";
const FULL_CODE_OBJECTS: u64 = 18_276;
const FULL_OBJECTS_OK_FLOOR: u64 = 17_396;
const FULL_MODULES_EXACT_FLOOR: u64 = 337;
const FULL_OBJECT_PCT_FLOOR: f64 = 95.18;

const PINNED_MODULES: u64 = 200;
const PINNED_CODE_OBJECTS: u64 = 6_286;
const PINNED_OBJECTS_OK: u64 = 6_077;

const PINNED_CPYTHON: &str = "3.14.5";
const PINNED_MAGIC: &str = "2b0e0d0a";

const SAMPLE_POPULATION: &str = "stdlib-sample-115";
const SAMPLE_SCRATCH_DIR: &str = "py-stdlib-sample";
const SAMPLE_LIST_NAME: &str = "sample_modules_314.txt";

const SAMPLE_MODULES: u64 = 115;
const SAMPLE_CODE_OBJECTS: u64 = 3_567;
const SAMPLE_OBJECTS_OK_FLOOR: u64 = 3_396;
const SAMPLE_OBJECT_PCT_FLOOR: f64 = 95.21;
const SAMPLE_MODULES_EXACT_FLOOR: u64 = 66;
const SAMPLE_LIST_DIGEST: u64 = 0xffa6_a85a_98bf_8108;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn known_ledger_verdict(verdict: &str) -> bool {
    matches!(
        verdict,
        "OK" | "code" | "sig" | "MISSING" | "COLLISION" | "DECOMPILE_ERR" | "SYNTAX_ERR"
    )
}

fn validate_evidence_rows(
    sources: &[serde_json::Value],
    expected_sources: &BTreeSet<String>,
    ledger: &str,
    objects: u64,
    objects_ok: u64,
) -> Result<String, String> {
    let mut observed_sources: BTreeSet<String> = BTreeSet::new();
    let mut manifest: String = String::new();
    for row in sources {
        let path: &str = row["path"].as_str().ok_or("source path is missing")?;
        let digest: &str = row["sha256"].as_str().ok_or("source hash is missing")?;
        if digest.len() != 64 || !digest.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid source hash for {path}"));
        }
        if !observed_sources.insert(path.to_owned()) {
            return Err(format!("duplicate source: {path}"));
        }
        manifest.push_str(path);
        manifest.push('\t');
        manifest.push_str(digest);
        manifest.push('\n');
    }
    if &observed_sources != expected_sources {
        return Err("source manifest differs from the fixed population".to_owned());
    }
    let mut keys: BTreeSet<(&str, &str, u64)> = BTreeSet::new();
    let mut successes: u64 = 0;
    for line in ledger.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let Ok([module, qualname, position, verdict]): Result<[&str; 4], Vec<&str>> =
            fields.try_into()
        else {
            return Err(format!("malformed ledger row: {line}"));
        };
        let position: u64 = position
            .parse()
            .map_err(|error: core::num::ParseIntError| format!("invalid position: {error}"))?;
        if !expected_sources.contains(module) || qualname.is_empty() {
            return Err(format!(
                "unknown module or empty qualified name: {module}::{qualname}"
            ));
        }
        if !known_ledger_verdict(verdict) {
            return Err(format!("unknown ledger verdict: {verdict}"));
        }
        if !keys.insert((module, qualname, position)) {
            return Err(format!(
                "duplicate ledger key: {module}::{qualname}:{position}"
            ));
        }
        successes += u64::from(verdict == "OK");
    }
    if u64::try_from(keys.len()).map_err(|error| format!("ledger count: {error}"))? != objects
        || successes != objects_ok
    {
        return Err("ledger totals differ from the measurement".to_owned());
    }
    Ok(manifest)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn deterministic_sample(population: &[String], take: usize) -> Vec<String> {
    let mut ranked: Vec<(u64, &str)> = population
        .iter()
        .map(|module: &String| (fnv1a64(module.as_bytes()), module.as_str()))
        .collect();
    ranked.sort_unstable();
    let mut chosen: Vec<String> = ranked
        .into_iter()
        .take(take)
        .map(|(_, module): (u64, &str)| module.to_owned())
        .collect();
    chosen.sort_unstable();
    chosen
}

fn sample_digest(sample: &[String]) -> u64 {
    fnv1a64(sample.join("\n").as_bytes())
}

fn selected_sample() -> Vec<String> {
    let (full, _pinned): (Vec<String>, Vec<String>) = module_lists();
    let take: usize = usize::try_from(SAMPLE_MODULES).expect("sample size fits usize");
    assert!(
        full.len() >= take,
        "the {FULL_POPULATION} list carries {} module paths, fewer than the {SAMPLE_MODULES} the \
         {SAMPLE_POPULATION} slice draws from it",
        full.len()
    );
    deterministic_sample(&full, take)
}

fn module_lists() -> (Vec<String>, Vec<String>) {
    let full_path: PathBuf = manifest_dir().join(FULL_MODULE_LIST);
    let pinned_path: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
    assert!(
        full_path.is_file(),
        "the {FULL_POPULATION} module list is missing at {}; without it the published full-stdlib \
         figure has no committed population",
        full_path.display()
    );
    assert!(
        pinned_path.is_file(),
        "the {PINNED_POPULATION} module list is missing at {}",
        pinned_path.display()
    );
    let full: Vec<String> = read_module_list(&full_path).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: Vec<String> =
        read_module_list(&pinned_path).unwrap_or_else(|e: String| panic!("{e}"));
    (full, pinned)
}

fn supplied_measurement_executable() -> PathBuf {
    let raw: String = std::env::var("DISROBE_MEASUREMENT_EXECUTABLE").unwrap_or_else(|_| {
        panic!(
            "set DISROBE_MEASUREMENT_EXECUTABLE to the exact disrobe executable being measured; \
             this gate does not infer candidate provenance from an arbitrary debug or release artifact"
        )
    });
    let path: PathBuf = PathBuf::from(raw);
    assert!(
        path.is_file(),
        "DISROBE_MEASUREMENT_EXECUTABLE points to {}, which is not a file",
        path.display()
    );
    path
}

fn supplied_candidate_source_identity() -> String {
    let identity: String =
        std::env::var("DISROBE_CANDIDATE_SOURCE_IDENTITY").unwrap_or_else(|_| {
            panic!(
                "set DISROBE_CANDIDATE_SOURCE_IDENTITY to the source identity for the supplied \
             measurement executable; this gate records caller-provided provenance and does not \
             invent a build-to-source mapping"
            )
        });
    assert!(
        !identity.trim().is_empty(),
        "DISROBE_CANDIDATE_SOURCE_IDENTITY must not be empty"
    );
    identity
}

fn evidence_directory() -> PathBuf {
    let raw: String = std::env::var("DISROBE_FULL_EVIDENCE_DIR").unwrap_or_else(|_| {
        panic!(
            "set DISROBE_FULL_EVIDENCE_DIR to an unused absolute durable directory outside the \
             Cargo target; a full measurement never reuses or overwrites prior evidence"
        )
    });
    let path: PathBuf = PathBuf::from(raw);
    assert!(
        path.is_absolute() && !path.starts_with(workspace_target()),
        "DISROBE_FULL_EVIDENCE_DIR must be an absolute path outside {}: {}",
        workspace_target().display(),
        path.display()
    );
    fs::create_dir(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "create new evidence directory {}: {e}; choose an unused destination rather than \
             reusing a prior run",
            path.display()
        )
    });
    path
}

fn reusable_evidence_directory() -> Option<PathBuf> {
    std::env::var_os("DISROBE_FULL_MEASUREMENT_DIR").map(|raw: std::ffi::OsString| {
        let path: PathBuf = PathBuf::from(raw);
        assert!(
            path.is_absolute() && path.is_dir() && !path.starts_with(workspace_target()),
            "DISROBE_FULL_MEASUREMENT_DIR must name an existing durable directory outside {}: {}",
            workspace_target().display(),
            path.display()
        );
        assert!(
            path.join("measurement.json").is_file(),
            "{} contains no measurement.json receipt; only a completed measurement may be reused",
            path.display()
        );
        path
    })
}

fn sha256_path(python: &Path, path: &Path) -> String {
    let output: std::process::Output = Command::new(python)
        .args([
            "-c",
            "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("hash {}: {e}", path.display()));
    assert!(
        output.status.success(),
        "hash {} with {}: {}",
        path.display(),
        python.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn current_runtime_identity(python: &Path) -> serde_json::Value {
    let script: &str = r"import ctypes, hashlib, json, os, platform, sys
runtime = None
if os.name == 'nt' and hasattr(sys, 'dllhandle'):
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetModuleFileNameW(ctypes.c_void_p(sys.dllhandle), buffer, len(buffer))
    if length and length < len(buffer) and os.path.isfile(buffer.value): runtime = buffer.value
print(json.dumps({'implementation': platform.python_implementation(), 'sys_version': sys.version, 'runtime_library': runtime, 'runtime_library_sha256': hashlib.sha256(open(runtime, 'rb').read()).hexdigest() if runtime else None}))";
    let output: std::process::Output = Command::new(python)
        .args(["-c", script])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("read runtime identity: {error}"));
    assert!(
        output.status.success(),
        "read runtime identity with {}: {}",
        python.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse runtime identity")
}

fn current_source_manifest(python: &Path, lib: &Path, modules: &Path) -> Vec<serde_json::Value> {
    let script: &str = r"import hashlib, json, pathlib, sys
lib, modules = map(pathlib.Path, sys.argv[1:])
rows = []
for line in modules.read_text(encoding='utf-8').splitlines():
    rel = line.strip()
    if rel and not rel.startswith('#'):
        rows.append({'path': rel, 'sha256': hashlib.sha256((lib / rel).read_bytes()).hexdigest()})
print(json.dumps(sorted(rows, key=lambda row: row['path'])))";
    let output: std::process::Output = Command::new(python)
        .args(["-c", script])
        .arg(lib)
        .arg(modules)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("hash fixed source population: {error}"));
    assert!(
        output.status.success(),
        "hash fixed source population with {}: {}",
        python.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse current source manifest")
}

fn receipt_string<'a>(receipt: &'a serde_json::Value, field: &str) -> &'a str {
    receipt
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("measurement receipt has no {field}"))
}

fn assert_reusable_measurement(
    receipt: &serde_json::Value,
    evidence: &Path,
    python: &Path,
    disrobe: &Path,
    harness: &Path,
    modules: &Path,
    candidate_source_identity: &str,
) {
    assert_eq!(
        receipt_string(receipt, "candidate_source_identity"),
        candidate_source_identity,
        "the caller source identity differs from the reusable measurement"
    );
    let snapshot: PathBuf = evidence.join(receipt_string(receipt, "snapshot_file"));
    assert!(
        snapshot.is_file(),
        "reusable measurement is missing {}",
        snapshot.display()
    );
    assert_eq!(
        sha256_path(python, &snapshot),
        receipt_string(receipt, "measured_executable_sha256"),
        "reusable measurement executable snapshot differs from its receipt"
    );
    assert_eq!(
        sha256_path(python, disrobe),
        receipt_string(receipt, "measured_executable_sha256"),
        "current executable differs from the reusable measurement snapshot"
    );
    let report: &serde_json::Value = receipt.get("report").expect("measurement receipt report");
    assert_eq!(
        sha256_path(python, modules),
        report["module_list_sha256"]
            .as_str()
            .expect("measurement report module-list digest"),
        "current module list differs from the reusable measurement"
    );
    for (field, path) in [
        ("original_executable_sha256", disrobe),
        ("harness_sha256", harness),
        ("stdout_sha256", &evidence.join("harness.stdout")),
        ("stderr_sha256", &evidence.join("harness.stderr")),
        ("ledger_sha256", &evidence.join("object-ledger.tsv")),
        (
            "source_manifest_sha256",
            &evidence.join("source-manifest.tsv"),
        ),
    ] {
        assert!(
            path.is_file(),
            "reusable measurement is missing {}",
            path.display()
        );
        assert_eq!(
            sha256_path(python, path),
            receipt_string(receipt, field),
            "reusable measurement {field} differs from its receipt"
        );
    }
    let runtime: serde_json::Value = current_runtime_identity(python);
    assert_eq!(
        receipt_string(receipt, "interpreter_sha256"),
        sha256_path(python, python),
        "reusable measurement interpreter_sha256 differs from the current runtime"
    );
    for field in [
        "runtime_library",
        "runtime_library_sha256",
        "sys_version",
        "implementation",
    ] {
        assert_eq!(
            receipt.get(field),
            runtime.get(field),
            "reusable measurement {field} differs from the current runtime"
        );
    }
}

#[test]
fn the_full_stdlib_population_contains_every_pinned_module() {
    let (full, pinned): (Vec<String>, Vec<String>) = module_lists();
    let full_count: u64 = u64::try_from(full.len()).expect("module count fits u64");
    let pinned_count: u64 = u64::try_from(pinned.len()).expect("module count fits u64");

    assert_eq!(
        full_count, FULL_MODULES,
        "the {FULL_POPULATION} list carries {full_count} module paths, not the {FULL_MODULES} the \
         published figure names; a shorter list measures a smaller population under the same \
         headline, so re-measure and re-publish both the numerator and the denominator rather than \
         trimming the list"
    );
    assert_eq!(
        pinned_count, PINNED_MODULES,
        "the {PINNED_POPULATION} list carries {pinned_count} module paths, not {PINNED_MODULES}"
    );

    let full_set: BTreeSet<&str> = full.iter().map(String::as_str).collect();
    assert_eq!(
        full_set.len(),
        full.len(),
        "the {FULL_POPULATION} list repeats a module path, which would count one module's code \
         objects twice in the published denominator"
    );

    let absent: Vec<&str> = pinned
        .iter()
        .map(String::as_str)
        .filter(|module: &&str| !full_set.contains(module))
        .collect();
    assert!(
        absent.is_empty(),
        "{} of the {PINNED_POPULATION} modules are not members of the {FULL_POPULATION} list, so \
         the two published figures do not describe nested populations and neither one bounds the \
         other: {absent:?}",
        absent.len()
    );
    assert!(
        full_count > pinned_count,
        "the {FULL_POPULATION} list ({full_count} modules) must be strictly larger than the \
         {PINNED_POPULATION} list ({pinned_count} modules); equal sizes mean one figure was \
         published over the other's population"
    );
}

#[test]
fn published_full_stdlib_bar_agrees_with_the_gated_population() {
    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    println!("=== PUBLISHED PYTHON RECOVERY POPULATIONS ===");
    println!(
        "this test compares the published bars against the constants this file pins. It decompiles \
         nothing and recompiles nothing, so it proves the documents and this crate name the same \
         numbers, not that either number is the one a real interpreter measures. The measurements \
         live in `sampled_stdlib_recompile_equivalence_gate` ({SAMPLE_POPULATION}, unignored) and \
         `full_stdlib_recompile_equivalence_gate` ({FULL_POPULATION}, ignored by default)."
    );
    println!(
        "{}",
        population_line(FULL_POPULATION, full.num, full.den, full.modules)
    );
    println!(
        "{}",
        population_line(PINNED_POPULATION, pinned.num, pinned.den, pinned.modules)
    );

    let published_full_pct: f64 = publish_pct(FULL_OBJECTS_OK_FLOOR, FULL_CODE_OBJECTS);
    let disagreements: Vec<String> = bar_disagreements(&full, published_full_pct);
    assert!(
        disagreements.is_empty(),
        "the published `{FULL_BAR_LABEL}` bar and the truncation of its exact counts describe different \
         numbers, and every document renders the JSON: {disagreements:?}"
    );

    assert_eq!(
        (full.num, full.den, full.modules),
        (FULL_OBJECTS_OK_FLOOR, FULL_CODE_OBJECTS, FULL_MODULES),
        "the published `{FULL_BAR_LABEL}` bar reads {}/{} over {} modules, but this gate enforces \
         {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} over {FULL_MODULES}",
        full.num,
        full.den,
        full.modules
    );
    assert!(
        (full.value - published_full_pct).abs() < f64::EPSILON,
        "the published `{FULL_BAR_LABEL}` percentage must be the exact-count fraction truncated to \
         two decimals ({published_full_pct:.2}), while the separate rounded measurement floor remains \
         {FULL_OBJECT_PCT_FLOOR:.2}"
    );
    assert_eq!(
        (pinned.num, pinned.den, pinned.modules),
        (PINNED_OBJECTS_OK, PINNED_CODE_OBJECTS, PINNED_MODULES),
        "the published `{PINNED_BAR_LABEL}` bar reads {}/{} over {} modules, but the pinned corpus \
         gate measures {PINNED_OBJECTS_OK}/{PINNED_CODE_OBJECTS} over {PINNED_MODULES}",
        pinned.num,
        pinned.den,
        pinned.modules
    );
    assert!(
        full.den > pinned.den && full.modules > pinned.modules,
        "the two Python figures must stay separate populations: {FULL_POPULATION} publishes \
         {}/{} over {} modules and {PINNED_POPULATION} publishes {}/{} over {} modules, and the \
         full population must be the strictly larger one",
        full.num,
        full.den,
        full.modules,
        pinned.num,
        pinned.den,
        pinned.modules
    );

    let full_detail: String =
        published_detail(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned_detail: String =
        published_detail(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let full_den: String = FULL_CODE_OBJECTS.to_string();
    let pinned_den: String = PINNED_CODE_OBJECTS.to_string();
    assert!(
        full_detail.contains(&full_den) && !full_detail.contains(&pinned_den),
        "the `{FULL_BAR_LABEL}` detail must state its own denominator {full_den} and never the \
         {PINNED_POPULATION} denominator {pinned_den}, otherwise the two figures read as one \
         population: {full_detail}"
    );
    assert!(
        pinned_detail.contains(&pinned_den) && !pinned_detail.contains(&full_den),
        "the `{PINNED_BAR_LABEL}` detail must state its own denominator {pinned_den} and never the \
         {FULL_POPULATION} denominator {full_den}: {pinned_detail}"
    );
}

#[test]
fn a_bar_that_blends_the_two_populations_is_rejected() {
    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    let full_over_pinned_denominator: PublishedBar = PublishedBar {
        den: pinned.den,
        ..full
    };
    assert_eq!(
        bar_disagreements(
            &full_over_pinned_denominator,
            publish_pct(full.num, full.den)
        )
        .len(),
        1,
        "publishing the {FULL_POPULATION} numerator over the {PINNED_POPULATION} denominator must \
         break the ratio leg, otherwise the denominator is not really pinned"
    );

    let pinned_percentage_on_full_population: PublishedBar = PublishedBar {
        value: pinned.value,
        ..full
    };
    assert_eq!(
        bar_disagreements(
            &pinned_percentage_on_full_population,
            publish_pct(full.num, full.den)
        )
        .len(),
        2,
        "reprinting the {PINNED_POPULATION} percentage against the {FULL_POPULATION} counts must \
         break both the ratio check and the expected published value check"
    );

    let short_numerator: PublishedBar = PublishedBar {
        num: full.num - 1,
        ..full
    };
    assert_eq!(
        bar_disagreements(&short_numerator, publish_pct(full.num, full.den)).len(),
        0,
        "a one-object numerator drift stays inside the 0.05 percentage-point ratio tolerance, so \
         the numerator floor in the measurement gate is what catches it, not this ratio check"
    );

    assert!(
        bar_disagreements(&full, publish_pct(full.num, full.den)).is_empty(),
        "the committed {FULL_POPULATION} bar itself must stay clean"
    );
    assert!(
        bar_disagreements(&pinned, pinned.value).is_empty(),
        "the committed {PINNED_POPULATION} bar itself must stay clean against its own value"
    );
}

#[test]
fn the_stdlib_sample_is_drawn_by_module_name_hash_and_pinned_by_digest() {
    let (full, _pinned): (Vec<String>, Vec<String>) = module_lists();
    let take: usize = usize::try_from(SAMPLE_MODULES).expect("sample size fits usize");
    let sample: Vec<String> = deterministic_sample(&full, take);

    let sample_count: u64 = u64::try_from(sample.len()).expect("sample count fits u64");
    assert_eq!(
        sample_count, SAMPLE_MODULES,
        "the {SAMPLE_POPULATION} slice drew {sample_count} module paths, not {SAMPLE_MODULES}"
    );

    let reversed: Vec<String> = full.iter().rev().cloned().collect();
    assert_eq!(
        deterministic_sample(&reversed, take),
        sample,
        "reversing the {FULL_POPULATION} list changed which modules the {SAMPLE_POPULATION} slice \
         selects, so the selection reads iteration order somewhere instead of hashing the module \
         name, and two machines could measure two different populations under one floor"
    );
    assert_eq!(
        deterministic_sample(&full, take),
        sample,
        "two draws from the same list disagree, so the {SAMPLE_POPULATION} selection is not a pure \
         function of the committed module names"
    );

    let digest: u64 = sample_digest(&sample);
    assert_eq!(
        digest, SAMPLE_LIST_DIGEST,
        "the {SAMPLE_POPULATION} slice now digests to {digest:#018x}, not the pinned \
         {SAMPLE_LIST_DIGEST:#018x}. The slice is a function of the committed {FULL_POPULATION} \
         list, so this fires when that list changed; the floors below were measured against the old \
         slice and mean nothing against a new one. Re-measure the slice and re-pin its denominator \
         and its digest together, never the digest alone"
    );

    let full_set: BTreeSet<&str> = full.iter().map(String::as_str).collect();
    let stray: Vec<&str> = sample
        .iter()
        .map(String::as_str)
        .filter(|module: &&str| !full_set.contains(module))
        .collect();
    assert!(
        stray.is_empty(),
        "{} {SAMPLE_POPULATION} modules are not members of the {FULL_POPULATION} list, so the slice \
         does not sample the published population: {stray:?}",
        stray.len()
    );

    assert!(
        sample.len() < full.len(),
        "the {SAMPLE_POPULATION} slice draws {} of the {FULL_POPULATION} list's {} module paths; a \
         slice the size of the whole population would let the sampled floor be read as the \
         published figure",
        sample.len(),
        full.len()
    );

    let object_share: f64 = (SAMPLE_CODE_OBJECTS as f64) * 100.0 / (FULL_CODE_OBJECTS as f64);
    let module_share: f64 = (SAMPLE_MODULES as f64) * 100.0 / (FULL_MODULES as f64);
    println!(
        "{SAMPLE_POPULATION} covers {SAMPLE_MODULES} / {FULL_MODULES} modules ({module_share:.2}%) \
         and {SAMPLE_CODE_OBJECTS} / {FULL_CODE_OBJECTS} code objects ({object_share:.2}%) of the \
         published {FULL_POPULATION} population, digest {SAMPLE_LIST_DIGEST:#018x}"
    );
}

#[test]
fn sampled_stdlib_recompile_equivalence_gate() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the {SAMPLE_POPULATION} gate \
             measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14.5 interpreter found (uv python find 3.14.5 / known install paths). This \
             gate is the running measurement behind the published {FULL_POPULATION} figure of \
             {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} code objects, so its absence fails the run \
             rather than passing it. Install one with `uv python install 3.14.5`."
        );
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        (maj, min),
        (3, 14),
        "resolved interpreter at {} is {maj}.{min}, not 3.14; the {FULL_POPULATION} list the \
         {SAMPLE_POPULATION} slice is drawn from is 3.14-specific",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );

    let sample: Vec<String> = selected_sample();
    let sample_count: u64 = u64::try_from(sample.len()).expect("sample count fits u64");
    assert_eq!(
        sample_count, SAMPLE_MODULES,
        "the {SAMPLE_POPULATION} slice drew {sample_count} module paths, not {SAMPLE_MODULES}"
    );
    let digest: u64 = sample_digest(&sample);
    assert_eq!(
        digest, SAMPLE_LIST_DIGEST,
        "the {SAMPLE_POPULATION} slice digests to {digest:#018x}, not the pinned \
         {SAMPLE_LIST_DIGEST:#018x}, so this run would measure a different population than the one \
         the floors below were measured against"
    );

    let scratch: PathBuf = workspace_target().join(SAMPLE_SCRATCH_DIR);
    fs::create_dir_all(&scratch)
        .unwrap_or_else(|e: std::io::Error| panic!("create {}: {e}", scratch.display()));
    let modules: PathBuf = scratch.join(SAMPLE_LIST_NAME);
    let mut rendered: String = sample.join("\n");
    rendered.push('\n');
    fs::write(&modules, rendered.as_bytes())
        .unwrap_or_else(|e: std::io::Error| panic!("write {}: {e}", modules.display()));

    let run: HarnessRun = run_measure(&python, &disrobe, &lib, &modules);
    println!("=== SAMPLED STDLIB RECOMPILE-EQUIVALENCE GATE ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!("sample list : {}", modules.display());
    println!(
        "this measures a {SAMPLE_MODULES} of {FULL_MODULES} module slice of the published \
         {FULL_POPULATION} population, selected by a hash of each committed module name so the same \
         slice is drawn on every run and every platform. Its floors are its own. It is not the \
         published {FULL_POPULATION} figure and must never be quoted as one; \
         `full_stdlib_recompile_equivalence_gate` measures that."
    );
    println!("--- harness taxonomy (stderr) ---\n{}", run.stderr);
    assert!(
        run.success,
        "harness exited {:?}\nstdout:\n{}\nstderr:\n{}",
        run.code, run.stdout, run.stderr
    );

    let m: Measurement = parse_measurement(&run.stdout).expect("parse harness measurement");
    println!(
        "{}",
        population_line(SAMPLE_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "population {SAMPLE_POPULATION}: whole-module normalized opcode-structure matches {} / {} ({:.2}%), sibling-count \
         collisions {}, measured on CPython {}",
        m.modules_exact, m.modules, m.module_pct, m.sibling_collisions, m.cpython_version
    );

    assert_eq!(
        m.listed_modules, SAMPLE_MODULES,
        "the harness read {} module paths from the {SAMPLE_POPULATION} slice, not {SAMPLE_MODULES}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, 0,
        "{} of the {SAMPLE_MODULES} sampled modules are absent from this interpreter's Lib, so this \
         run cannot measure the slice the floors were pinned against; the denominator was pinned on \
         CPython {PINNED_CPYTHON}, and an interpreter that ships a different Lib needs a fresh \
         measurement plus a re-pinned denominator, never a lowered floor",
        m.missing_from_lib
    );
    assert_eq!(
        m.modules, SAMPLE_MODULES,
        "only {} of the {SAMPLE_MODULES} sampled modules were measured; a run that inspects fewer \
         modules must score worse, not measure itself against a smaller population",
        m.modules
    );
    assert_eq!(
        m.code_objects, SAMPLE_CODE_OBJECTS,
        "the {SAMPLE_POPULATION} denominator is pinned by equality: this run walked {} code \
         objects, the slice measures {SAMPLE_CODE_OBJECTS} (CPython {PINNED_CPYTHON}, measured \
         {}). A different denominator is a different population, so re-measure and re-pin both \
         halves of the fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.objects_ok >= SAMPLE_OBJECTS_OK_FLOOR,
        "{SAMPLE_POPULATION} per-code-object recompile-equivalence regressed: {} / {} recovered, \
         floor {SAMPLE_OBJECTS_OK_FLOOR} / {SAMPLE_CODE_OBJECTS} ({SAMPLE_OBJECT_PCT_FLOOR}%) on \
         CPython {}. This slice is a fifth of the published {FULL_POPULATION} population, so a drop \
         here is a drop there",
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
    assert!(
        m.object_pct >= SAMPLE_OBJECT_PCT_FLOOR,
        "{SAMPLE_POPULATION} measured {:.2}%, below the pinned {SAMPLE_OBJECT_PCT_FLOOR}% ({} / {} \
         on {} modules, CPython {})",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= SAMPLE_MODULES_EXACT_FLOOR,
        "{SAMPLE_POPULATION} whole-module normalized opcode-structure matches regressed: {} / {} modules had \
         every code object's normalized opcode structure match, floor {SAMPLE_MODULES_EXACT_FLOOR} / {SAMPLE_MODULES}",
        m.modules_exact,
        m.modules
    );
    assert!(
        m.code_objects < FULL_CODE_OBJECTS && m.modules < FULL_MODULES,
        "this run measured {} code objects over {} modules, which is not smaller than the \
         {FULL_POPULATION} population it samples; a slice that grew into the whole would let the \
         sampled floor stand in for the published figure",
        m.code_objects,
        m.modules
    );
    assert!(
        m.code_objects != PINNED_CODE_OBJECTS && m.modules != PINNED_MODULES,
        "this run measured the {PINNED_POPULATION} population, not the {SAMPLE_POPULATION} slice; \
         the three must never be measured as one"
    );
}

#[test]
#[ignore = "measures the whole 574-module CPython 3.14 stdlib through the real CLI; about four \
            minutes against a debug CLI and less against a release one. No workflow runs it today, \
            so the published full-stdlib figure is re-derived in CI only through the \
            115-module slice in `sampled_stdlib_recompile_equivalence_gate`. Drive the whole \
            population with `cargo test -p disrobe-pass-py-decompile --test \
            full_stdlib_recompile_gate -- --ignored --nocapture`"]
fn full_stdlib_recompile_equivalence_gate() {
    let disrobe: PathBuf = supplied_measurement_executable();
    let candidate_source_identity: String = supplied_candidate_source_identity();

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14.5 interpreter found (uv python find 3.14.5 / known install paths). This \
             gate is the reference behind the published {FULL_POPULATION} figure of \
             {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} code objects, so its absence fails the \
             run rather than passing it. Install one with `uv python install 3.14.5`."
        );
    };

    let Some(release): Option<String> = interpreter_release(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        release,
        PINNED_CPYTHON,
        "resolved interpreter at {} is {release}, not CPython {PINNED_CPYTHON}; the \
         {FULL_POPULATION} list and its floor are pinned to that exact release",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let modules: PathBuf = manifest_dir().join(FULL_MODULE_LIST);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "the {FULL_POPULATION} module list is missing at {}",
        modules.display()
    );

    let reusable_evidence: Option<PathBuf> = reusable_evidence_directory();
    let reuse: bool = reusable_evidence.is_some();
    assert!(
        !(reuse && std::env::var_os("DISROBE_FULL_EVIDENCE_DIR").is_some()),
        "set either DISROBE_FULL_EVIDENCE_DIR for a fresh measurement or DISROBE_FULL_MEASUREMENT_DIR for reuse, not both"
    );
    let (evidence, snapshot, ledger, stdout_path, stderr_path, stdout, stderr, fresh_run): (
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        String,
        String,
        Option<HarnessRun>,
    ) = if reuse {
        let evidence: PathBuf = reusable_evidence.expect("reuse path was checked");
        let receipt_path: PathBuf = evidence.join("measurement.json");
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap_or_else(
                |error: std::io::Error| panic!("read {}: {error}", receipt_path.display()),
            ))
            .expect("parse reusable measurement receipt");
        assert_reusable_measurement(
            &receipt,
            &evidence,
            &python,
            &disrobe,
            &harness,
            &modules,
            &candidate_source_identity,
        );
        let stdout_path: PathBuf = evidence.join("harness.stdout");
        let stderr_path: PathBuf = evidence.join("harness.stderr");
        let stdout: String =
            fs::read_to_string(&stdout_path).unwrap_or_else(|error: std::io::Error| {
                panic!("read {}: {error}", stdout_path.display())
            });
        let stderr: String =
            fs::read_to_string(&stderr_path).unwrap_or_else(|error: std::io::Error| {
                panic!("read {}: {error}", stderr_path.display())
            });
        let ledger: PathBuf = evidence.join("object-ledger.tsv");
        (
            evidence,
            disrobe,
            ledger,
            stdout_path,
            stderr_path,
            stdout,
            stderr,
            None,
        )
    } else {
        let evidence: PathBuf = evidence_directory();
        let snapshot: PathBuf = evidence.join(disrobe.file_name().unwrap_or_else(|| {
            panic!(
                "measurement executable has no file name: {}",
                disrobe.display()
            )
        }));
        fs::copy(&disrobe, &snapshot).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "snapshot measurement executable from {} to {}: {error}",
                disrobe.display(),
                snapshot.display()
            )
        });
        let ledger: PathBuf = evidence.join("object-ledger.tsv");
        let request: EvidenceRequest<'_> = EvidenceRequest {
            original_executable: &disrobe,
            object_ledger: &ledger,
            candidate_source_identity: &candidate_source_identity,
            require_version: PINNED_CPYTHON,
            require_magic: PINNED_MAGIC,
            require_optimize: 0,
        };
        let run: HarnessRun =
            run_measure_with_evidence(&python, &snapshot, &lib, &modules, &request);
        let stdout_path: PathBuf = evidence.join("harness.stdout");
        let stderr_path: PathBuf = evidence.join("harness.stderr");
        fs::write(&stdout_path, &run.stdout).unwrap_or_else(|error: std::io::Error| {
            panic!("write {}: {error}", stdout_path.display())
        });
        fs::write(&stderr_path, &run.stderr).unwrap_or_else(|error: std::io::Error| {
            panic!("write {}: {error}", stderr_path.display())
        });
        let stdout: String = run.stdout.clone();
        let stderr: String = run.stderr.clone();
        (
            evidence,
            snapshot,
            ledger,
            stdout_path,
            stderr_path,
            stdout,
            stderr,
            Some(run),
        )
    };
    println!("=== FULL STDLIB RECOMPILE-EQUIVALENCE GATE ===");
    println!("interpreter : {} ({release})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", snapshot.display());
    println!("--- harness taxonomy (stderr) ---\n{stderr}");
    if let Some(run) = fresh_run {
        assert!(
            run.success,
            "harness exited {:?}\nstdout:\n{}\nstderr:\n{}",
            run.code, run.stdout, run.stderr
        );
    }

    let m: Measurement = parse_measurement(&stdout).expect("parse harness measurement");
    let report: serde_json::Value = serde_json::from_str(
        stdout
            .lines()
            .find(|line: &&str| line.trim_start().starts_with('{'))
            .expect("harness report JSON"),
    )
    .expect("parse harness report JSON");
    assert_eq!(
        report
            .get("module_list_sha256")
            .and_then(serde_json::Value::as_str),
        Some(FULL_MODULE_LIST_SHA256),
        "the harness measured a module list other than the fixed {FULL_POPULATION} population"
    );
    assert_eq!(
        report
            .get("candidate_source_identity")
            .and_then(serde_json::Value::as_str),
        Some(candidate_source_identity.as_str()),
        "the harness report lost the caller-supplied candidate source identity"
    );
    assert_eq!(
        report
            .get("candidate_source_identity_attestation")
            .and_then(serde_json::Value::as_str),
        Some("caller-supplied"),
        "the harness did not label the candidate source identity as caller-supplied"
    );
    assert_eq!(
        report
            .get("implementation")
            .and_then(serde_json::Value::as_str),
        Some("CPython"),
        "the fixed CPython population was measured by a different implementation"
    );
    assert!(
        report
            .get("sys_version")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|version: &str| version.starts_with(PINNED_CPYTHON)),
        "the harness report contains no full CPython {PINNED_CPYTHON} runtime version"
    );
    if cfg!(windows) {
        for field in ["runtime_library", "runtime_library_sha256"] {
            assert!(
                report
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value: &str| !value.is_empty()),
                "the Windows interpreter report contains no {field}"
            );
        }
    }
    assert_eq!(
        report
            .get("optimize_level")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "the harness did not measure the required optimize 0 compilation mode"
    );
    assert_eq!(
        report
            .get("magic_number")
            .and_then(serde_json::Value::as_str),
        Some(PINNED_MAGIC),
        "the harness did not measure the required CPython {PINNED_MAGIC} pyc format"
    );
    for field in [
        "original_executable_sha256",
        "measured_executable_sha256",
        "interpreter_sha256",
        "source_manifest_sha256",
    ] {
        assert!(
            report
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|digest: &str| digest.len() == 64),
            "the harness report contains no SHA256 for {field}"
        );
    }
    assert_eq!(
        report
            .get("original_executable_sha256")
            .and_then(serde_json::Value::as_str),
        report
            .get("measured_executable_sha256")
            .and_then(serde_json::Value::as_str),
        "the measured snapshot no longer matches the caller-supplied executable"
    );
    let source_rows: &Vec<serde_json::Value> = report
        .get("source_manifest")
        .and_then(serde_json::Value::as_array)
        .expect("harness report source manifest");
    assert_eq!(
        source_rows.len(),
        usize::try_from(FULL_MODULES).expect("module count fits usize"),
        "the source manifest omitted members of the fixed {FULL_POPULATION} population"
    );
    let expected_sources: BTreeSet<String> = read_module_list(&modules)
        .unwrap_or_else(|e: String| panic!("{e}"))
        .into_iter()
        .collect();
    let ledger_raw: String = fs::read_to_string(&ledger)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", ledger.display()));
    let manifest_text: String = validate_evidence_rows(
        source_rows,
        &expected_sources,
        &ledger_raw,
        m.code_objects,
        m.objects_ok,
    )
    .unwrap_or_else(|error: String| panic!("invalid measurement evidence: {error}"));
    let source_manifest: PathBuf = evidence.join("source-manifest.tsv");
    assert_eq!(
        current_source_manifest(&python, &lib, &modules),
        *source_rows,
        "the current CPython library differs from the source corpus captured by this measurement"
    );
    if reuse {
        assert_eq!(
            fs::read_to_string(&source_manifest).unwrap_or_else(|error: std::io::Error| panic!(
                "read {}: {error}",
                source_manifest.display()
            )),
            manifest_text,
            "reusable measurement source-manifest.tsv differs from its harness report"
        );
    } else {
        fs::write(&source_manifest, &manifest_text).unwrap_or_else(|error: std::io::Error| {
            panic!("write {}: {error}", source_manifest.display())
        });
    }
    assert_eq!(
        sha256_path(&python, &source_manifest),
        report
            .get("source_manifest_sha256")
            .and_then(serde_json::Value::as_str)
            .expect("source manifest digest"),
        "the source manifest differs from the digests in the harness report"
    );
    println!(
        "{}",
        population_line(FULL_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "{}",
        population_line(
            PINNED_POPULATION,
            PINNED_OBJECTS_OK,
            PINNED_CODE_OBJECTS,
            PINNED_MODULES
        )
    );
    println!(
        "population {FULL_POPULATION}: whole-module normalized opcode-structure matches {} / {} ({:.2}%), sibling-count \
         collisions {}, measured on CPython {}",
        m.modules_exact, m.modules, m.module_pct, m.sibling_collisions, m.cpython_version
    );

    assert_eq!(
        m.listed_modules, FULL_MODULES,
        "the harness read {} module paths from the {FULL_POPULATION} list, not {FULL_MODULES}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, 0,
        "{} of the {FULL_MODULES} listed modules are absent from this interpreter's Lib, so this \
         run cannot measure the published population; the denominator was pinned against CPython \
         {PINNED_CPYTHON}, and a patch release that adds or drops stdlib modules needs a fresh \
         measurement plus a re-published numerator and denominator, never a lowered floor",
        m.missing_from_lib
    );
    assert_eq!(
        m.modules, FULL_MODULES,
        "only {} of the {FULL_MODULES} listed modules were measured; a run that inspects fewer \
         modules must score worse, not measure itself against a smaller population",
        m.modules
    );
    assert_eq!(
        m.code_objects, FULL_CODE_OBJECTS,
        "the {FULL_POPULATION} denominator is pinned by equality: this run walked {} code objects, \
         the published figure names {FULL_CODE_OBJECTS} (CPython {PINNED_CPYTHON}, measured \
         {}). A different denominator is a different population, so re-measure and re-publish \
         both halves of the fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.objects_ok >= FULL_OBJECTS_OK_FLOOR,
        "{FULL_POPULATION} per-code-object recompile-equivalence regressed: {} / {} recovered, \
         floor {FULL_OBJECTS_OK_FLOOR} / {FULL_CODE_OBJECTS} ({FULL_OBJECT_PCT_FLOOR}%) on \
         CPython {}. The floor is the exact figure this population measures, so any drop is a \
         real regression and the floor only ever rises",
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
    assert!(
        m.object_pct >= FULL_OBJECT_PCT_FLOOR,
        "{FULL_POPULATION} measured {:.2}%, below the published {FULL_OBJECT_PCT_FLOOR}% \
         ({} / {} on {} modules, CPython {})",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= FULL_MODULES_EXACT_FLOOR,
        "{FULL_POPULATION} whole-module normalized opcode-structure matches regressed: {} / {} modules had \
         every code object's normalized opcode structure match, floor {FULL_MODULES_EXACT_FLOOR} / {FULL_MODULES}",
        m.modules_exact,
        m.modules
    );
    assert!(
        m.code_objects != PINNED_CODE_OBJECTS && m.modules != PINNED_MODULES,
        "this run measured {} code objects over {} modules, which is the {PINNED_POPULATION} \
         population, not {FULL_POPULATION}; the two must never be measured as one",
        m.code_objects,
        m.modules
    );

    let measurement: serde_json::Value = serde_json::json!({
        "candidate_source_identity": candidate_source_identity,
        "original_executable_sha256": report["original_executable_sha256"],
        "measured_executable_sha256": report["measured_executable_sha256"],
        "snapshot_file": snapshot.file_name().and_then(std::ffi::OsStr::to_str).expect("measurement snapshot name"),
        "module_list_sha256": report["module_list_sha256"],
        "interpreter_sha256": report["interpreter_sha256"],
        "runtime_library": report["runtime_library"],
        "runtime_library_sha256": report["runtime_library_sha256"],
        "sys_version": report["sys_version"],
        "implementation": report["implementation"],
        "harness_sha256": sha256_path(&python, &harness),
        "stdout_sha256": sha256_path(&python, &stdout_path),
        "stderr_sha256": sha256_path(&python, &stderr_path),
        "ledger_sha256": sha256_path(&python, &ledger),
        "source_manifest_sha256": sha256_path(&python, &source_manifest),
        "report": report,
    });
    let measurement_path: PathBuf = evidence.join("measurement.json");
    if reuse {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &fs::read_to_string(&measurement_path).unwrap_or_else(|error: std::io::Error| {
                    panic!("read {}: {error}", measurement_path.display())
                }),
            )
            .expect("parse reusable measurement receipt"),
            measurement,
            "reusable measurement receipt does not describe its captured evidence"
        );
    } else {
        fs::write(
            &measurement_path,
            serde_json::to_string_pretty(&measurement).expect("render measurement receipt"),
        )
        .unwrap_or_else(|error: std::io::Error| {
            panic!("write {}: {error}", measurement_path.display())
        });
    }

    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    assert_eq!(
        (full.num, full.den),
        (FULL_OBJECTS_OK_FLOOR, FULL_CODE_OBJECTS),
        "xtask/data/recovery.json publishes {}/{} for {FULL_POPULATION} and every document renders \
         that pair, but this gate enforces {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS}",
        full.num,
        full.den
    );
    assert_eq!(
        (m.objects_ok, m.code_objects),
        (full.num, full.den),
        "this run recovered {}/{} code objects, but the published accepted measurement is {}/{}; \
         update the published figure from this fresh durable evidence before accepting an improvement",
        m.objects_ok,
        m.code_objects,
        full.num,
        full.den
    );
    let accepted: serde_json::Value = serde_json::json!({
        "candidate_source_identity": candidate_source_identity,
        "candidate_source_identity_attestation": "caller-supplied",
        "original_executable_sha256": report["original_executable_sha256"],
        "measured_executable_sha256": report["measured_executable_sha256"],
        "interpreter_sha256": report["interpreter_sha256"],
        "runtime_library": report["runtime_library"],
        "runtime_library_sha256": report["runtime_library_sha256"],
        "harness_sha256": sha256_path(&python, &harness),
        "stdout_sha256": sha256_path(&python, &stdout_path),
        "stderr_sha256": sha256_path(&python, &stderr_path),
        "ledger_sha256": sha256_path(&python, &ledger),
        "source_manifest_sha256": sha256_path(&python, &source_manifest),
        "sys_version": report["sys_version"],
        "implementation": report["implementation"],
    });
    let accepted_path: PathBuf = evidence.join("accepted.json");
    fs::write(
        &accepted_path,
        serde_json::to_string_pretty(&accepted).expect("render accepted evidence"),
    )
    .unwrap_or_else(|e: std::io::Error| panic!("write {}: {e}", accepted_path.display()));
}

#[test]
fn evidence_row_guards_reject_malformed_claims() {
    let expected: BTreeSet<String> = BTreeSet::from(["a.py".to_owned()]);
    let hash: String = "a".repeat(64);
    let sources: Vec<serde_json::Value> = vec![serde_json::json!({"path": "a.py", "sha256": hash})];
    let valid: &str = "a.py\t<module>\t0\tOK\na.py\tf\t0\tcode\n";
    assert_eq!(
        validate_evidence_rows(&sources, &expected, valid, 2, 1),
        Ok(format!("a.py\t{hash}\n"))
    );
    for ledger in [
        "a.py\t<module>\t0\tinvented\n",
        "a.py\t<module>\t0\tOK\na.py\t<module>\t0\tcode\n",
        "b.py\t<module>\t0\tOK\n",
        "a.py\t\t0\tOK\n",
        "a.py\t<module>\tnot-a-number\tOK\n",
        "a.py\t<module>\t0\n",
    ] {
        assert!(
            validate_evidence_rows(&sources, &expected, ledger, 1, 1).is_err(),
            "accepted malformed ledger: {ledger}"
        );
    }
    assert!(validate_evidence_rows(&sources, &expected, valid, 2, 2).is_err());
    assert!(validate_evidence_rows(&sources, &expected, valid, 3, 1).is_err());
    for rows in [
        vec![serde_json::json!({"path": "b.py", "sha256": hash})],
        vec![serde_json::json!({"path": "a.py", "sha256": "invalid"})],
        vec![sources[0].clone(), sources[0].clone()],
        vec![serde_json::json!({"path": "a.py"})],
    ] {
        assert!(validate_evidence_rows(&rows, &expected, valid, 2, 1).is_err());
    }
}
