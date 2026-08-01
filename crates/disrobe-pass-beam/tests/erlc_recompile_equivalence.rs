#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{
    BeamFile, Disassembly, ErlangSurface, Operand, RecoverySource, disassemble, recover_erlang,
};

mod common;

#[cfg(target_os = "linux")]
use common::erlang_toolchain::otp_version;
use common::erlang_toolchain::{Erlang, require_erlang, run_bounded};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("beam")
        .join("recompile_oracle")
}

fn strip_chunk(bytes: &[u8], target: &[u8; 4]) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor: usize = 12;
    while cursor + 8 <= bytes.len() {
        let tag: [u8; 4] = [
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ];
        let len: usize = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let padded: usize = len.div_ceil(4) * 4;
        let total: usize = 8 + padded;
        if &tag != target {
            inner.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
    let mut out: Vec<u8> = Vec::with_capacity(12 + inner.len());
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(
        &u32::try_from(4 + inner.len())
            .expect("form fits")
            .to_be_bytes(),
    );
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&inner);
    out
}

fn erlc_compile(erlc: &Path, src: &Path, out_dir: &Path) -> (bool, String) {
    let mut cmd: Command = Command::new(erlc);
    cmd.arg("-o").arg(out_dir).arg(src);
    match run_bounded(cmd) {
        Some((ok, so, se)) => (ok, format!("stdout:\n{so}\nstderr:\n{se}")),
        None => (false, "erlc timed out".to_owned()),
    }
}

const GRADED: &str = "stripped core-lift recompile equivalence over the erlang corpus";
const PUBLISHED_HEADING: &str = "BEAM stripped Core Erlang";
const PUBLISHED_BAR: &str = "recompile-execution";
#[cfg(target_os = "linux")]
const PUBLISHED_OTP_VERSION: &str = "27.3.4";
const CORPUS_MODULES: [&str; 19] = [
    "arith",
    "bigint",
    "binaries",
    "bincomp",
    "bitwise",
    "boolean",
    "casesif",
    "catchexpr",
    "comprehensions",
    "funs",
    "guards",
    "lists_ops",
    "maps2",
    "nested_data",
    "records2",
    "recursion",
    "strings",
    "trycatch",
    "tuples",
];

fn run_test0(erl: &Path, code_dir: &Path, module: &str) -> (bool, String) {
    let eval: String = format!("io:format(\"~p~n\", [{module}:test()]), halt().");
    let mut cmd: Command = Command::new(erl);
    cmd.current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&eval);
    match run_bounded(cmd) {
        Some((ok, so, _)) => (ok, so),
        None => (false, "<timed out>".to_owned()),
    }
}

fn semantic_exports(beam: &BeamFile) -> BTreeSet<(String, u32)> {
    let mut out: BTreeSet<(String, u32)> = BTreeSet::new();
    for entry in &beam.chunks.exports {
        let Some(name): Option<&str> = beam.chunks.atoms.get(entry.function_atom_index) else {
            continue;
        };
        if name == "module_info" {
            continue;
        }
        out.insert((name.to_owned(), entry.arity));
    }
    out
}

fn opcode_sequences(beam: &BeamFile) -> Vec<((String, u32), Vec<&'static str>)> {
    let Some(code) = beam.chunks.code.as_ref() else {
        return Vec::new();
    };
    let Ok(dis): Result<Disassembly, _> = disassemble(code) else {
        return Vec::new();
    };
    let mut out: Vec<((String, u32), Vec<&'static str>)> = Vec::new();
    let mut current: Option<((String, u32), Vec<&'static str>)> = None;
    for instr in &dis.instructions {
        if instr.name == "func_info" {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            let name: String = match instr.operands.get(1) {
                Some(Operand::Atom(a)) => beam.chunks.atoms.get(*a).unwrap_or("?").to_owned(),
                _ => "?".to_owned(),
            };
            let arity: u32 = match instr.operands.get(2) {
                Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
                _ => 0,
            };
            current = Some(((name, arity), Vec::new()));
            continue;
        }
        if let Some((_, ops)) = current.as_mut()
            && instr.name != "label"
            && instr.name != "line"
        {
            ops.push(instr.name);
        }
    }
    if let Some(prev) = current.take() {
        out.push(prev);
    }
    out.retain(|((n, _), _)| n != "module_info" && n != "?");
    out
}

struct Fidelity {
    module: String,
    recompiled: bool,
    exports_match: bool,
    runtime_identical: bool,
    fn_total: usize,
    fn_opcode_exact: usize,
    detail: String,
    rejected_source: Option<String>,
}

impl Fidelity {
    fn behaviorally_equivalent(&self) -> bool {
        self.recompiled && self.exports_match && self.runtime_identical
    }
}

fn measure(
    erlc: &Path,
    erl: Option<&Path>,
    module: &str,
    src: &Path,
    transform: fn(&str) -> String,
) -> Fidelity {
    let purpose: String = format!("disrobe_recompile_eq_{module}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let base: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = base.join("orig");
    let rec_dir: PathBuf = base.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let (compiled, msg): (bool, String) = erlc_compile(erlc, src, &orig_dir);
    assert!(compiled, "corpus module {module} must compile:\n{msg}");

    let raw: Vec<u8> =
        std::fs::read(orig_dir.join(format!("{module}.beam"))).expect("read orig beam");
    let original: BeamFile = BeamFile::parse(&raw).expect("parse original beam");
    let original_exports: BTreeSet<(String, u32)> = semantic_exports(&original);
    let stripped_bytes: Vec<u8> = strip_chunk(&strip_chunk(&raw, b"Dbgi"), b"Docs");
    let stripped: BeamFile = BeamFile::parse(&stripped_bytes).expect("parse stripped");
    assert!(
        stripped.chunks.dbgi.is_none(),
        "{module}: Dbgi must be stripped so the debug-info path cannot fire"
    );
    assert!(
        stripped.chunks.docs.is_none(),
        "{module}: Docs must be stripped so documentation metadata cannot influence recovery"
    );
    let stripped_exports: BTreeSet<(String, u32)> = semantic_exports(&stripped);
    assert_eq!(
        stripped_exports, original_exports,
        "{module}: stripping Dbgi and Docs changed the original export set"
    );

    let surface: ErlangSurface = recover_erlang(&stripped).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "{module}: recovery must fall back to bytecode core-lift with Dbgi/Docs stripped"
    );

    let recovered_source: String = transform(&surface.source);
    let rec_src: PathBuf = rec_dir.join(format!("{module}.erl"));
    std::fs::write(&rec_src, &recovered_source).expect("write recovered");
    let (recompiled, rec_msg): (bool, String) = erlc_compile(erlc, &rec_src, &rec_dir);

    let mut exports_match: bool = false;
    let mut runtime_identical: bool = false;
    let mut fn_total: usize = 0;
    let mut fn_opcode_exact: usize = 0;
    let mut detail: String = String::new();

    if recompiled {
        let rec_beam: BeamFile = BeamFile::parse(
            &std::fs::read(rec_dir.join(format!("{module}.beam"))).expect("read recompiled"),
        )
        .expect("parse recompiled");
        exports_match = semantic_exports(&rec_beam) == original_exports;
        if !exports_match {
            detail = format!(
                "exports differ: orig={:?} rec={:?}",
                original_exports,
                semantic_exports(&rec_beam)
            );
        }

        let orig_seqs: Vec<((String, u32), Vec<&str>)> = opcode_sequences(&stripped);
        let rec_seqs: Vec<((String, u32), Vec<&str>)> = opcode_sequences(&rec_beam);
        fn_total = orig_seqs.len();
        for (key, ops) in &orig_seqs {
            if let Some((_, rec_ops)) = rec_seqs.iter().find(|(k, _)| k == key)
                && rec_ops == ops
            {
                fn_opcode_exact += 1;
            }
        }

        if let Some(erl) = erl {
            let (orig_ok, orig_out): (bool, String) = run_test0(erl, &orig_dir, module);
            assert!(
                orig_ok,
                "{module}:test() must succeed on the original (corpus precondition):\n{orig_out}"
            );
            let (rec_ok, rec_out): (bool, String) = run_test0(erl, &rec_dir, module);
            runtime_identical = rec_ok && rec_out == orig_out;
            if !runtime_identical {
                detail = format!(
                    "runtime differs:\n  orig: {}\n  rec:  {}",
                    orig_out.trim_end(),
                    rec_out.trim_end()
                );
            }
        }
    } else {
        detail = format!("recompile rejected:\n{rec_msg}");
    }

    Fidelity {
        module: module.to_owned(),
        recompiled,
        exports_match,
        runtime_identical,
        fn_total,
        fn_opcode_exact,
        detail,
        rejected_source: (!recompiled).then_some(recovered_source),
    }
}

const MAX_DETAIL_LINES: usize = 60;
const MAX_SOURCE_LINES: usize = 200;

fn print_verdict(r: &Fidelity) {
    let status: &str = if r.behaviorally_equivalent() {
        "PASS"
    } else if !r.recompiled {
        "FAIL(recompile)"
    } else if !r.exports_match {
        "FAIL(exports)"
    } else {
        "FAIL(runtime)"
    };
    let op_pct: f64 = if r.fn_total == 0 {
        0.0
    } else {
        (r.fn_opcode_exact as f64) * 100.0 / (r.fn_total as f64)
    };
    println!(
        "  {status:<16} {:<16} opcode-exact {}/{} ({op_pct:.0}%)",
        r.module, r.fn_opcode_exact, r.fn_total
    );
    if r.behaviorally_equivalent() {
        return;
    }
    for line in r.detail.lines().take(MAX_DETAIL_LINES) {
        println!("       {line}");
    }
    let Some(source): Option<&String> = r.rejected_source.as_ref() else {
        return;
    };
    println!("       --- recovered {}.erl as erlc saw it ---", r.module);
    for (n, line) in source.lines().take(MAX_SOURCE_LINES).enumerate() {
        println!("       {:>4} | {line}", n + 1);
    }
    let total: usize = source.lines().count();
    if total > MAX_SOURCE_LINES {
        println!(
            "       ... {} further lines elided",
            total - MAX_SOURCE_LINES
        );
    }
}

fn corpus_modules() -> Vec<(String, PathBuf)> {
    let directory: PathBuf = corpus_dir();
    let discovered: BTreeSet<String> = std::fs::read_dir(&directory)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p: &PathBuf| p.extension().is_some_and(|x| x == "erl"))
        .map(|p: PathBuf| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = CORPUS_MODULES
        .iter()
        .map(|module: &&str| (*module).to_owned())
        .collect();
    assert_eq!(
        discovered, expected,
        "the committed BEAM recompile-execution corpus membership changed; review the population before changing its published denominator"
    );
    CORPUS_MODULES
        .iter()
        .map(|module: &&str| {
            let name: String = (*module).to_owned();
            (name, directory.join(format!("{module}.erl")))
        })
        .collect()
}

fn published_bar() -> serde_json::Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    let groups: &[serde_json::Value] = document["groups"].as_array().expect("recovery.json groups");
    for group in groups {
        let heading: &str = group["heading"].as_str().unwrap_or_default();
        if !heading.contains(PUBLISHED_HEADING) {
            continue;
        }
        let bars: &[serde_json::Value] =
            group["bars"].as_array().expect("published BEAM group bars");
        found.extend(
            bars.iter()
                .filter(|bar: &&serde_json::Value| bar["label"].as_str() == Some(PUBLISHED_BAR))
                .cloned(),
        );
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one `{PUBLISHED_BAR}` bar under a heading containing `{PUBLISHED_HEADING}`"
    );
    found.pop().expect("one published BEAM bar")
}

const EQUIVALENCE_FLOOR: usize = 18;
const PUBLISHED_DENOMINATOR: usize = CORPUS_MODULES.len();

#[test]
fn published_beam_bar_matches_the_enforced_floor() {
    let bar: serde_json::Value = published_bar();
    let published_num: u64 = bar["num"]
        .as_u64()
        .expect("the published BEAM bar must carry a numerator");
    let published_den: u64 = bar["den"]
        .as_u64()
        .expect("the published BEAM bar must carry a denominator");
    let published_value: f64 = bar["value"]
        .as_f64()
        .expect("the published BEAM bar must carry a percentage");
    let expected_num: u64 = u64::try_from(EQUIVALENCE_FLOOR).expect("floor fits u64");
    let expected_den: u64 = u64::try_from(PUBLISHED_DENOMINATOR).expect("denominator fits u64");
    let expected_value: f64 = expected_num as f64 * 100.0 / expected_den as f64;

    assert_eq!(
        published_num, expected_num,
        "recovery.json publishes {published_num} equivalent modules while this crate enforces {expected_num}"
    );
    assert_eq!(
        published_den, expected_den,
        "recovery.json publishes a {published_den}-module population while this crate pins {expected_den}"
    );
    assert!(
        (published_value - expected_value).abs() < 1.0e-12,
        "recovery.json plots {published_value}% for {published_num} of {published_den}, but their exact percentage is {expected_value}%"
    );
    let detail: &str = bar["detail"]
        .as_str()
        .expect("the published BEAM bar must carry its measured scope");
    assert!(
        detail.contains("OTP 27.3.4") && detail.contains("test/0"),
        "the published BEAM detail must name OTP 27.3.4 and the test/0 observation scope"
    );
}

fn unchanged_recovered_source(source: &str) -> String {
    source.to_owned()
}

#[cfg(target_os = "linux")]
fn recovered_source_with_raising_test(source: &str) -> String {
    const TARGET: &str = "test() ->\n";
    const MUTANT: &str = "test() ->\n    erlang:error(disrobe_mutant),\n";
    let sites: usize = source.matches(TARGET).count();
    assert_eq!(
        sites, 1,
        "the mutation control expected one recovered test/0 head and found {sites}"
    );
    source.replacen(TARGET, MUTANT, 1)
}

#[cfg(target_os = "linux")]
#[test]
fn real_erlang_runtime_rejects_a_recompiled_wrong_test_result() {
    let erlang: Erlang = require_erlang(GRADED).unwrap_or_else(|| {
        panic!(
            "the Linux mutation control requires erlc and erl; CI provisions OTP 27.3.4 and must fail rather than report an unmeasured success"
        )
    });
    let source: PathBuf = corpus_dir().join("arith.erl");
    let result: Fidelity = measure(
        &erlang.erlc,
        Some(&erlang.erl),
        "arith",
        &source,
        recovered_source_with_raising_test,
    );
    assert!(
        result.recompiled,
        "the mutation control must remain valid Erlang source: {}",
        result.detail
    );
    assert!(
        result.exports_match,
        "the mutation control must preserve the module's export surface: {}",
        result.detail
    );
    assert!(
        !result.runtime_identical && !result.behaviorally_equivalent(),
        "the real erl runtime accepted a recovered test/0 that raises instead of returning the original result"
    );
    assert!(
        result.detail.contains("runtime differs"),
        "the mutation must be rejected by the runtime differential rather than another leg: {}",
        result.detail
    );
}

struct CorpusMeasurement {
    equivalent: usize,
    total: usize,
    release: String,
    failing: Vec<String>,
}

fn measure_corpus(erlang: Erlang) -> CorpusMeasurement {
    let (erlc, erl, release): (PathBuf, PathBuf, String) =
        (erlang.erlc, erlang.erl, erlang.release);

    let modules: Vec<(String, PathBuf)> = corpus_modules();
    assert_eq!(modules.len(), PUBLISHED_DENOMINATOR);

    let mut results: Vec<Fidelity> = Vec::with_capacity(modules.len());
    for (module, src) in &modules {
        results.push(measure(
            &erlc,
            Some(&erl),
            module,
            src,
            unchanged_recovered_source,
        ));
    }

    let equivalent: usize = results
        .iter()
        .filter(|r| r.behaviorally_equivalent())
        .count();
    let recompiled: usize = results.iter().filter(|r| r.recompiled).count();
    let fn_total: usize = results.iter().map(|r| r.fn_total).sum();
    let fn_exact: usize = results.iter().map(|r| r.fn_opcode_exact).sum();

    println!(
        "\n=== STRIPPED CORE-LIFT RECOMPILE-EQUIVALENCE (erlc and erl from OTP {release}) ==="
    );
    for r in &results {
        print_verdict(r);
    }
    let failing: Vec<String> = results
        .iter()
        .filter(|r: &&Fidelity| !r.behaviorally_equivalent())
        .map(|r: &Fidelity| r.module.clone())
        .collect();
    if !failing.is_empty() {
        println!("not equivalent under OTP {release}: {}", failing.join(", "));
    }
    let op_overall: f64 = if fn_total == 0 {
        0.0
    } else {
        (fn_exact as f64) * 100.0 / (fn_total as f64)
    };
    println!(
        "behavioral equivalence: {equivalent}/{} = {:.1}%   (recompile {recompiled}/{})",
        modules.len(),
        (equivalent as f64) * 100.0 / (modules.len() as f64),
        modules.len()
    );
    println!(
        "structural opcode fidelity: {fn_exact}/{fn_total} functions byte-for-byte opcode-identical = {op_overall:.1}%\n"
    );

    CorpusMeasurement {
        equivalent,
        total: modules.len(),
        release,
        failing,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn stripped_core_lift_is_recompile_equivalent() {
    let erlang: Erlang = require_erlang(GRADED).unwrap_or_else(|| {
        panic!(
            "the Linux claim-backing test requires erlc and erl; CI provisions OTP 27.3.4 and must fail rather than report an unmeasured success"
        )
    });
    let full_version: String = otp_version(&erlang.erl)
        .unwrap_or_else(|defect: String| panic!("the full OTP version probe failed: {defect}"));
    assert_eq!(
        full_version, PUBLISHED_OTP_VERSION,
        "the published measurement requires OTP {PUBLISHED_OTP_VERSION}, but the OTP_VERSION file reports {}",
        full_version
    );
    let measurement: CorpusMeasurement = measure_corpus(erlang);
    assert_eq!(
        measurement.release, "27",
        "OTP_VERSION reports {PUBLISHED_OTP_VERSION}, but erlang:system_info(otp_release) reports major release {}",
        measurement.release
    );
    let bar: serde_json::Value = published_bar();
    let published_num: usize = usize::try_from(
        bar["num"]
            .as_u64()
            .expect("the published BEAM bar must carry a numerator"),
    )
    .expect("published numerator fits usize");
    let published_den: usize = usize::try_from(
        bar["den"]
            .as_u64()
            .expect("the published BEAM bar must carry a denominator"),
    )
    .expect("published denominator fits usize");

    assert_eq!(
        measurement.total, published_den,
        "the measured corpus has {} entries but recovery.json publishes {published_den}",
        measurement.total
    );
    assert_eq!(
        measurement.equivalent,
        published_num,
        "recovery.json publishes {published_num} of {published_den}, but OTP {} measured {} of {}; non-equivalent entries: {}",
        measurement.release,
        measurement.equivalent,
        measurement.total,
        measurement.failing.join(", ")
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn stripped_core_lift_is_recompile_equivalent_when_erlang_is_available() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let measurement: CorpusMeasurement = measure_corpus(erlang);
    assert_eq!(measurement.total, PUBLISHED_DENOMINATOR);
    assert!(
        measurement.equivalent >= EQUIVALENCE_FLOOR,
        "recompile-execution regressed to {} of {} under OTP {}; non-equivalent entries: {}",
        measurement.equivalent,
        measurement.total,
        measurement.release,
        measurement.failing.join(", ")
    );
}
