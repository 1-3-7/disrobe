#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/lua_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod lua_toolchain;

mod common;

#[path = "support/prometheus_residue.rs"]
#[allow(clippy::redundant_pub_crate)]
mod prometheus_residue;

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::lua_toolchain::{Dialect, interpreter};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
use disrobe_pass_lua::{prometheus, prometheus_vmlift};
use lua_toolchain::{LuaInterpreter, require_interpreter, require_interpreter_present, run_lua};
use prometheus_residue::assert_no_prometheus_layer;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

#[test]
fn fold_reconstruction_preserves_inter_span_text() {
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let offsets: Vec<(usize, usize, String)> = prometheus_vmlift::folded_span_offsets(&obf);
        let folded: String = prometheus_vmlift::fold_numeric_expressions(&obf);
        let mut rebuilt: String = String::with_capacity(folded.len());
        let mut cursor: usize = 0;
        let mut prev_end: usize = 0;
        for (start, end, value) in &offsets {
            assert!(
                *start >= prev_end,
                "{rel}: fold spans must not overlap ({prev_end} > {start})"
            );
            rebuilt.push_str(&obf[cursor..*start]);
            rebuilt.push_str(value);
            cursor = *end;
            prev_end = *end;
        }
        rebuilt.push_str(&obf[cursor..]);
        let strip_ws = |s: &str| -> String {
            s.chars()
                .filter(|c: &char| !c.is_ascii_whitespace())
                .collect()
        };
        assert_eq!(
            strip_ws(&rebuilt),
            strip_ws(&folded),
            "{rel}: fold output must equal original-text + folded-values (ignoring guard whitespace)"
        );
        eprintln!("{rel}: {} spans, inter-span text preserved", offsets.len());
    }
}

fn assert_admitted_arithmetic(rel: &str, role: &str, text: &str) {
    assert!(
        prometheus_vmlift::fold_one_expression(text).is_some() && !text.contains("--"),
        "{rel}: the {role} {text:?} is not an arithmetic expression the vmlift lexer admits, so \
         it must not reach lua"
    );
}

fn span_check_program(rel: &str, pairs: &[(String, String)]) -> String {
    let mut prog: String = String::new();
    for (idx, (orig, folded)) in pairs.iter().enumerate() {
        assert_admitted_arithmetic(rel, "sample span", orig);
        assert_admitted_arithmetic(rel, "folded value", folded);
        let _ = writeln!(
            prog,
            "do local a={folded} local b=({orig}) if a~=b then print({idx},a,b) end end"
        );
    }
    prog
}

const NAMES_AND_CALLS: [&str; 14] = [
    "os.execute('echo reached')",
    "1 + os.exit(1)",
    "2 * f(3)",
    "(1)(2)",
    "1 + a",
    "-x + 1",
    "#t + 1",
    "('x'):rep(3)",
    "1 .. 2",
    "2 ^ n",
    "load('return 1')() + 1",
    "1 + ...",
    "1 + 2 + f(3)",
    "f(1 + 2) * 2",
];

#[test]
fn the_vmlift_lexer_refuses_names_and_calls_before_lua_starts() {
    for hostile in NAMES_AND_CALLS {
        assert_eq!(
            prometheus_vmlift::fold_one_expression(hostile),
            None,
            "the vmlift lexer admitted {hostile:?}, which names a variable or makes a call"
        );
        let source: String = format!("local v = {hostile}\n");
        for (span, folded) in prometheus_vmlift::folded_span_pairs(&source) {
            assert_admitted_arithmetic(hostile, "sample span", &span);
            assert_admitted_arithmetic(hostile, "folded value", &folded);
        }
    }
    let folded: String = prometheus_vmlift::fold_numeric_expressions("local v = 1 + 2 + f(3)\n");
    assert_eq!(
        folded, "local v = 3 + f(3)\n",
        "the arithmetic beside a call folds and the call is left as written"
    );
}

#[test]
#[should_panic(
    expected = "the sample span \"os.exit(1)\" is not an arithmetic expression the vmlift lexer admits"
)]
fn a_span_that_calls_a_function_is_refused_before_lua_starts() {
    span_check_program("seeded", &[("os.exit(1)".to_owned(), "1".to_owned())]);
}

#[test]
#[should_panic(
    expected = "the sample span \"1--2\" is not an arithmetic expression the vmlift lexer admits"
)]
fn a_span_that_opens_a_lua_comment_is_refused_before_lua_starts() {
    span_check_program("seeded", &[("1--2".to_owned(), "3".to_owned())]);
}

#[test]
fn every_folded_span_matches_lua_evaluation() {
    let Some(interp): Option<LuaInterpreter> =
        require_interpreter("the per-span Prometheus fold verification")
    else {
        return;
    };
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let pairs: Vec<(String, String)> = prometheus_vmlift::folded_span_pairs(&obf);
        if pairs.is_empty() {
            eprintln!("{rel}: no NumbersToExpressions layer present (nothing to fold)");
            continue;
        }
        let prog: String = span_check_program(rel, &pairs);
        let out: String = run_lua(&interp, &format!("{rel} (span check)"), &prog);
        assert!(
            out.trim().is_empty(),
            "{rel}: {} folded spans disagree with Lua evaluation:\n{out}",
            out.lines().count()
        );
        eprintln!("{rel}: all {} folded spans match Lua exactly", pairs.len());
    }
}

#[test]
fn the_numeric_fold_leaves_the_minify_sample_untouched() {
    let minify: String = load("obfuscators/edge_cases.prometheus_minify.lua");
    assert_eq!(
        prometheus_vmlift::fold_numeric_expressions(&minify),
        minify,
        "the minify preset's only arithmetic text sits inside a string literal, so the fold must \
         hand the sample back unchanged"
    );
}

const WEAK_MEGAFILE: &str = "obfuscators/edge_cases.prometheus_weak.lua";
const MEGAFILE_SOURCE: &str = "megafile/edge_cases.lua";
const MEGAFILE_DRIVER: &str = "megafile/edge_cases_drive.lua";
const MEGAFILE_DRIVER_LINES: usize = 116;
const MEGAFILE_FUNCTIONS: &str = "functions 171/171";
const MEGAFILE_HANDLERS: &str = "handlers 630/630 (100%)";
const MEGAFILE_DEAD_LEAVES: &str =
    "; 1 dispatch-tree leaf(ves) with real statements were never reached";
const MULTRET_PACK_HELPER: &str =
    "local function __vmpack(...) return { n = select(\"#\", ...), ... } end";
const TRUNCATING_PACK_HELPER: &str = "local function __vmpack(...) return { ... } end";
const DRIVER_RUN_TIMEOUT: Duration = Duration::from_mins(1);

fn megafile_interpreters() -> Vec<(Dialect, String)> {
    let found: Vec<(Dialect, String)> = [Dialect::Lua51, Dialect::Lua54]
        .into_iter()
        .filter_map(|dialect: Dialect| interpreter(dialect).map(|lua: String| (dialect, lua)))
        .collect();
    assert_eq!(
        found.len(),
        2,
        "the weak megafile recovery is graded under both lua5.1 and lua5.4, because its source \
         branches on the running dialect; found only {found:?}"
    );
    found
}

fn drive(lua: &str, label: &str, program: &str) -> String {
    let scratch: ScratchDir = ScratchDir::create(&format!(
        "disrobe_prometheus_megafile_{}_{label}",
        std::process::id()
    ))
    .expect("create scratch dir");
    let program_path: PathBuf = scratch.path().join("program.lua");
    fs::write(&program_path, program).expect("stage the program");
    let stdout_path: PathBuf = scratch.path().join("stdout.txt");
    let stderr_path: PathBuf = scratch.path().join("stderr.txt");
    let mut child: Child = Command::new(lua)
        .arg(corpus_path(MEGAFILE_DRIVER))
        .arg(&program_path)
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("create stdout"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create stderr"),
        ))
        .spawn()
        .unwrap_or_else(|err: std::io::Error| panic!("{label}: {lua} does not start: {err}"));
    let deadline: Instant = Instant::now() + DRIVER_RUN_TIMEOUT;
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait().expect("poll lua") {
            break status;
        }
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            panic!("{label}: {lua} did not finish within {DRIVER_RUN_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout: String = fs::read_to_string(&stdout_path).expect("read stdout");
    let stderr: String = fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        status.success(),
        "{label}: {lua} exited {status} under the megafile driver\n--- stderr ---\n{stderr}"
    );
    stdout.replace("\r\n", "\n")
}

fn first_divergence(expected: &str, actual: &str) -> Option<String> {
    expected
        .lines()
        .zip(actual.lines())
        .find(|(want, got): &(&str, &str)| want != got)
        .map(|(want, got): (&str, &str)| format!("expected {want:?}\n     got {got:?}"))
        .or_else(|| {
            (expected.lines().count() != actual.lines().count()).then(|| {
                format!(
                    "{} lines expected, {} produced",
                    expected.lines().count(),
                    actual.lines().count()
                )
            })
        })
}

fn peel_weak_megafile() -> (PeelResult, String) {
    let obf: String = load(WEAK_MEGAFILE);
    let out: PeelResult =
        prometheus::peel(obf.as_bytes(), &DeobfOptions::default()).expect("peel the weak megafile");
    let recovered: String =
        String::from_utf8(out.deobfuscated.clone()).expect("the recovered megafile is UTF-8");
    (out, recovered)
}

#[test]
fn the_weak_megafile_peel_recovers_every_function_and_reexecutes_like_its_source() {
    let (out, recovered): (PeelResult, String) = peel_weak_megafile();
    assert_no_prometheus_layer("peeled weak megafile", &recovered);
    assert!(
        out.passes_run
            .iter()
            .any(|pass: &String| pass == "prometheus-vmify-container-devirt"),
        "the weak megafile is devirtualized; passes={:?}",
        out.passes_run
    );
    let summary: &String = out
        .residual_markers
        .iter()
        .find(|marker: &&String| marker.contains("Vmify container devirtualized"))
        .unwrap_or_else(|| panic!("no devirtualization summary in {:?}", out.residual_markers));
    assert!(
        summary.contains(MEGAFILE_FUNCTIONS)
            && summary.contains(MEGAFILE_HANDLERS)
            && summary.contains(MEGAFILE_DEAD_LEAVES),
        "every one of the 171 Vmify functions is structured and all 630 reached handlers are \
         lifted; the one unreached leaf is an implicit trailing return after bodies that always \
         return first: {summary}"
    );
    assert!(
        out.fully_recovered,
        "a peel that structures every function reports a full recovery; residual={:?}",
        out.residual_markers
    );
    assert!(
        !recovered.contains("__pc"),
        "no function falls back to a dispatch state machine"
    );
    assert!(
        recovered.starts_with(MULTRET_PACK_HELPER),
        "the multiple-value calling convention is restored through the pack helper"
    );

    let source: String = load(MEGAFILE_SOURCE);
    for (dialect, lua) in megafile_interpreters() {
        let expected: String = drive(&lua, &format!("{dialect:?}_source"), &source);
        assert_eq!(
            expected.lines().count(),
            MEGAFILE_DRIVER_LINES,
            "{dialect:?}: the driver prints the load line and one line per exercised export"
        );
        let actual: String = drive(&lua, &format!("{dialect:?}_recovered"), &recovered);
        if let Some(divergence) = first_divergence(&expected, &actual) {
            panic!(
                "{dialect:?}: the recovered weak megafile behaves differently from \
                 corpus/lua/{MEGAFILE_SOURCE}:\n{divergence}"
            );
        }
    }
}

#[test]
fn the_weak_megafile_grade_fails_when_calls_drop_trailing_nil_results() {
    let (_out, recovered): (PeelResult, String) = peel_weak_megafile();
    let mutated: String = recovered.replacen(MULTRET_PACK_HELPER, TRUNCATING_PACK_HELPER, 1);
    assert_ne!(
        mutated, recovered,
        "the mutation replaces the pack helper with Prometheus's own truncating pack"
    );
    let source: String = load(MEGAFILE_SOURCE);
    for (dialect, lua) in megafile_interpreters() {
        let expected: String = drive(&lua, &format!("{dialect:?}_source_control"), &source);
        let actual: String = drive(&lua, &format!("{dialect:?}_mutated"), &mutated);
        let divergence: Option<String> = first_divergence(&expected, &actual);
        let first_export: &str = match dialect {
            Dialect::Lua51 => "deep_clone",
            Dialect::Lua54 | Dialect::Lua55 | Dialect::LuaJit => "math_type_compat",
        };
        assert!(
            divergence
                .as_deref()
                .is_some_and(|text: &str| text.contains(first_export)),
            "{dialect:?}: a recovery whose calls drop trailing nil results must fail the grade \
             at {first_export}, the first export returning one; divergence={divergence:?}"
        );
    }
}

#[test]
fn fold_hello_strips_numbers_to_expressions_layer() {
    let obf: String = load("obfuscators/hello.prometheus.lua");
    let static_before: usize = prometheus_vmlift::count_arithmetic_operators(&obf);
    let static_after: usize = prometheus_vmlift::count_arithmetic_operators(
        &prometheus_vmlift::fold_numeric_expressions(&obf),
    );
    assert!(
        static_before > 800,
        "hello carries the NumbersToExpressions layer; expected >800 arithmetic ops, got \
         {static_before}"
    );
    assert!(
        static_after * 2 < static_before,
        "fold must remove the majority of the NumbersToExpressions layer ({static_before} -> \
         {static_after})"
    );
}

#[test]
fn peel_path_applies_fold_and_dispatch_recovery() {
    let obf: String = load("obfuscators/hello.prometheus.lua");
    let out: PeelResult =
        prometheus::peel(obf.as_bytes(), &DeobfOptions::default()).expect("peel hello");

    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-numbers-to-expressions-fold"),
        "peel must run the numeric fold; passes={:?}",
        out.passes_run
    );
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-vmify-container-devirt"),
        "peel must devirtualize the container; passes={:?}",
        out.passes_run
    );
    assert!(
        out.fully_recovered,
        "the baseline greeting must recover fully; residual={:?}",
        out.residual_markers
    );

    let deob: &str = std::str::from_utf8(&out.deobfuscated).expect("recovered output is utf8");
    assert!(
        !deob.trim_start().starts_with("return(function")
            && !deob.contains("__pc")
            && !deob.contains("prometheus-vmify:"),
        "recovered output must contain no VM wrapper, dispatcher or recovery stub; got {:?}",
        deob.chars().take(80).collect::<String>(),
    );
    assert_no_prometheus_layer("peeled greeting", deob);
    let interpreter: LuaInterpreter =
        require_interpreter_present("Prometheus baseline greeting recovery");
    let baseline: String = load("baseline/hello.lua");
    let expected: String = run_lua(&interpreter, "baseline greeting", &baseline);
    assert_eq!(expected, "hello world\n");
    assert_eq!(run_lua(&interpreter, "recovered greeting", deob), expected);
    {
        use disrobe_core::chain::Pass;
        use disrobe_core::{Artifact, Rung};
        let input: Artifact = Artifact::new(Rung::Raw, obf.into_bytes(), [0; 32]);
        let output: Artifact = disrobe_pass_lua::chain_detector::LUA_PASS
            .run(&input)
            .expect("recover greeting through the chain pass");
        let source: &str = std::str::from_utf8(&output.envelope).expect("chain source is UTF-8");
        assert_no_prometheus_layer("chain greeting", source);
        assert_eq!(run_lua(&interpreter, "chain greeting", source), expected);
    }
}

#[test]
fn dispatch_cfg_recovered_on_real_vmify_samples() {
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let folded: String = prometheus_vmlift::fold_numeric_expressions(&obf);
        let report: prometheus_vmlift::DispatchReport =
            prometheus_vmlift::analyze_dispatch(&folded)
                .unwrap_or_else(|| panic!("{rel}: must recover the Vmify dispatch state machine"));
        assert!(
            report.comparison_count >= 10,
            "{rel}: a Vmify dispatch tree must have many state comparisons, got {}",
            report.comparison_count
        );
        assert!(
            report.block_count() >= 5,
            "{rel}: must recover distinct constant leaf states, got {}",
            report.block_count()
        );
        assert!(
            report.successor_edges >= report.block_count(),
            "{rel}: edges {} must be >= blocks {}",
            report.successor_edges,
            report.block_count()
        );
        eprintln!(
            "{rel}: dispatch state-var '{}' comparisons={} leaf-states={} edges={} conditional={}",
            report.state_variable,
            report.comparison_count,
            report.block_count(),
            report.successor_edges,
            report.conditional_blocks
        );
    }
}
