#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the correct visibility for helpers shared between this crate root and \
              the support/juliet_corpus.rs submodule; redundant_pub_crate (nursery) and the \
              workspace unreachable_pub lint cannot both hold for a private submodule, matching the \
              allow already shipped in disrobe-taint's own src/lib.rs"
)]

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_nir::NirModule;
use disrobe_taint::{TaintConfig, TaintReport};

#[path = "support/juliet_corpus.rs"]
mod juliet_corpus;

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
static CLI_PATH: OnceLock<PathBuf> = OnceLock::new();
static HOST_C_COMPILER: OnceLock<Option<&'static str>> = OnceLock::new();

const C_COMPILER_CANDIDATES: [&str; 3] = ["cc", "gcc", "clang"];

const PORTABLE_PRELUDE: &str = r#"
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#define TAINT_EXPORT __declspec(dllexport)
#else
#define TAINT_EXPORT __attribute__((visibility("default"), used))
#endif
"#;

const FLOWING_BODY: &str = r"
TAINT_EXPORT int taint_entry(void) {
    char input[64];
    return system(fgets(input, sizeof input, stdin));
}

int main(void) {
    return taint_entry();
}
";

const OVERWRITTEN_BODY: &str = r#"
TAINT_EXPORT int taint_entry(void) {
    char input[64];
    char * volatile command = fgets(input, sizeof input, stdin);
    command = "dir";
    return system(command);
}

int main(void) {
    return taint_entry();
}
"#;

struct FixtureDirectory {
    path: PathBuf,
}

struct CompiledFixture {
    _directory: FixtureDirectory,
    executable: PathBuf,
}

impl FixtureDirectory {
    fn create(name: &str) -> Self {
        let fixture_id: u64 = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-taint-{name}-{}-{fixture_id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create fixture directory");
        Self { path }
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _result: std::io::Result<()> = fs::remove_dir_all(&self.path);
    }
}

fn tool_runs(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|probe: Output| probe.status.success())
}

fn host_c_compiler() -> &'static str {
    let resolved: Option<&'static str> = *HOST_C_COMPILER.get_or_init(|| {
        C_COMPILER_CANDIDATES
            .into_iter()
            .find(|candidate: &&'static str| tool_runs(candidate))
    });
    let Some(compiler): Option<&'static str> = resolved else {
        panic!(
            "no host c compiler is callable: tried {}; the fgets-to-system taint flow was not graded",
            C_COMPILER_CANDIDATES.join(", ")
        )
    };
    compiler
}

fn host_executable_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

fn compile_program(name: &str, body: &str) -> CompiledFixture {
    let compiler: &'static str = host_c_compiler();
    let fixture_dir: FixtureDirectory = FixtureDirectory::create(name);
    let source_path: PathBuf = fixture_dir.path.join("fixture.c");
    let executable_path: PathBuf = fixture_dir.path.join(host_executable_name("fixture"));
    let source: String = format!("{PORTABLE_PRELUDE}{body}");
    fs::write(&source_path, &source).expect("write fixture source");
    let output: Output = Command::new(compiler)
        .args(["-O2", "-fno-builtin"])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("run {compiler}: {error}"));
    assert!(
        output.status.success(),
        "{compiler} failed to build the taint fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    CompiledFixture {
        _directory: fixture_dir,
        executable: executable_path,
    }
}

fn workspace_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn target_profile_dir() -> PathBuf {
    let test_executable: PathBuf = std::env::current_exe().expect("current test executable");
    let mut dir: PathBuf = test_executable
        .parent()
        .expect("test executable directory")
        .to_path_buf();
    while dir.file_name().and_then(OsStr::to_str) != Some("debug")
        && dir.file_name().and_then(OsStr::to_str) != Some("release")
    {
        assert!(
            dir.pop(),
            "no debug or release directory above the test executable"
        );
    }
    dir
}

fn build_cli() -> PathBuf {
    let workspace: PathBuf = workspace_path();
    let profile_dir: PathBuf = target_profile_dir();
    let mut args: Vec<&str> = vec!["build", "--quiet", "-p", "disrobe-cli"];
    if profile_dir.file_name().and_then(OsStr::to_str) == Some("release") {
        args.push("--release");
    }
    let output: Output = Command::new(env!("CARGO"))
        .current_dir(&workspace)
        .args(&args)
        .output()
        .expect("build disrobe CLI");
    assert!(
        output.status.success(),
        "disrobe CLI build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    profile_dir.join(host_executable_name("disrobe"))
}

fn cli_path() -> &'static PathBuf {
    CLI_PATH.get_or_init(build_cli)
}

fn run_taint(fixture: &CompiledFixture) -> String {
    let output: Output = Command::new(cli_path())
        .args(["--json", "taint"])
        .arg(&fixture.executable)
        .args(["--source", "fgets", "--sink", "system"])
        .output()
        .expect("run disrobe taint");
    assert!(
        output.status.success(),
        "disrobe taint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("taint output is utf-8")
}

fn compact_json(value: &str) -> String {
    value
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect()
}

fn finding_count(json: &str) -> usize {
    let compact: String = compact_json(json);
    let prefix: &str = "\"finding_count\":";
    let count: &str = compact
        .split(prefix)
        .nth(1)
        .and_then(|tail: &str| tail.split(',').next())
        .expect("taint JSON carries finding_count");
    count.parse::<usize>().expect("finding_count is numeric")
}

fn names_symbol(json: &str, field: &str, symbol: &str) -> bool {
    let bare: String = format!("\"{field}\":\"{symbol}\"");
    let underscored: String = format!("\"{field}\":\"_{symbol}\"");
    json.contains(&bare) || json.contains(&underscored)
}

#[test]
fn compiled_fgets_to_system_flow_is_attributed_to_its_exported_function() {
    let fixture: CompiledFixture = compile_program("flowing", FLOWING_BODY);
    let json: String = compact_json(&run_taint(&fixture));
    let count: usize = finding_count(&json);
    assert!(
        count >= 1,
        "pinned native-flow floor is one finding; the graded flow needs an image whose imported fgets and system land at named call targets, which takes two things the lifted IR does not supply on every host: import-thunk naming for the object format, since an elf plt entry and a mach-o __stubs entry both resolve to an unnamed thunk while a pe import thunk carries its own symbol, and per-instruction flow facts for the architecture, since disasm_ir::instruction_facts only decodes x86 and x86-64 and hands every other architecture a default fact set with no call flow and no branch target: {json}"
    );
    assert_eq!(
        count, 1,
        "the reference image has one source-to-sink finding: {json}"
    );
    assert!(
        names_symbol(&json, "function", "taint_entry")
            && names_symbol(&json, "source_symbol", "fgets")
            && names_symbol(&json, "sink_symbol", "system"),
        "fgets feeding system must be attributed to taint_entry: {json}"
    );
}

#[test]
fn overwriting_the_fgets_result_before_system_kills_the_native_flow() {
    let control: CompiledFixture = compile_program("kill-control", FLOWING_BODY);
    let control_json: String = run_taint(&control);
    assert!(
        finding_count(&control_json) >= 1,
        "a zero on the mutated program only means the overwrite killed the flow if this host reports the unmutated flow; it reports none, so the kill is not graded here and the analysis may simply be blind to this source and sink pair: {control_json}"
    );
    let fixture: CompiledFixture = compile_program("overwritten", OVERWRITTEN_BODY);
    let json: String = run_taint(&fixture);
    assert!(
        finding_count(&json) == 0,
        "the mutation overwrites the source result before system: {json}"
    );
}

const SAFE_SIBLING_BODY: &str = r#"
TAINT_EXPORT int safe_sibling(void) {
    return system("dir");
}
"#;

const TAINTED_SIBLING_BODY: &str = r"
TAINT_EXPORT int taint_sibling(void) {
    char input[64];
    return system(fgets(input, sizeof input, stdin));
}
";

const COMBINED_DRIVER_BODY: &str = r"
int main(void) {
    safe_sibling();
    taint_sibling();
    return 0;
}
";

fn compile_combined(name: &str, bodies: &[&str]) -> CompiledFixture {
    let compiler: &'static str = host_c_compiler();
    let fixture_dir: FixtureDirectory = FixtureDirectory::create(name);
    let source_path: PathBuf = fixture_dir.path.join("fixture.c");
    let executable_path: PathBuf = fixture_dir.path.join(host_executable_name("fixture"));
    let mut source: String = PORTABLE_PRELUDE.to_owned();
    for body in bodies {
        source.push_str(body);
    }
    fs::write(&source_path, &source).expect("write combined fixture source");
    let output: Output = Command::new(compiler)
        .args(["-O2", "-fno-builtin"])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("run {compiler}: {error}"));
    assert!(
        output.status.success(),
        "{compiler} failed to build the combined fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    CompiledFixture {
        _directory: fixture_dir,
        executable: executable_path,
    }
}

#[test]
fn juliet_harness_lift_and_analyze_path_sees_a_known_positive_control() {
    let fixture: CompiledFixture = compile_program("positive-control", FLOWING_BODY);
    let bytes: Vec<u8> = fs::read(&fixture.executable).expect("read compiled positive control");
    let module: NirModule = juliet_corpus::lift_native_module(&bytes);
    let config: TaintConfig = juliet_corpus::default_taint_config();
    let report: TaintReport = disrobe_taint::analyze(&module, &config);
    assert!(
        report
            .findings()
            .iter()
            .any(|f: &disrobe_taint::TaintFinding| {
                f.function == "taint_entry"
                    && f.source_symbol == "fgets"
                    && f.sink_symbol == "system"
            }),
        "the in-process lift-plus-analyze path the corpus grader uses must see the same fgets-to-system \
         flow the CLI subprocess path already proves in \
         compiled_fgets_to_system_flow_is_attributed_to_its_exported_function; if this fails, no number \
         the corpus grader produces is trustworthy: {report:?}"
    );

    let cli_json: String = run_taint(&fixture);
    assert!(
        finding_count(&cli_json) >= 1,
        "the CLI surface must also reach the same flow the library surface reaches, proving taint is \
         wired to both consumer surfaces: {cli_json}"
    );
}

#[test]
fn a_deliberately_broken_source_config_lowers_recall_on_a_known_flow() {
    let fixture: CompiledFixture = compile_program("recall-control", FLOWING_BODY);
    let bytes: Vec<u8> = fs::read(&fixture.executable).expect("read compiled recall control");
    let module: NirModule = juliet_corpus::lift_native_module(&bytes);

    let intact_config: TaintConfig = juliet_corpus::default_taint_config();
    let intact_report: TaintReport = disrobe_taint::analyze(&module, &intact_config);
    assert!(
        intact_report
            .findings()
            .iter()
            .any(|f: &disrobe_taint::TaintFinding| f.function == "taint_entry"),
        "the intact default source list must recover the known flow before it can be broken on purpose: \
         {intact_report:?}"
    );

    let broken_sources: Vec<&str> = juliet_corpus::DEFAULT_SOURCES
        .iter()
        .copied()
        .filter(|source: &&str| *source != "fgets")
        .collect();
    let broken_config: TaintConfig =
        TaintConfig::from_lists(broken_sources, juliet_corpus::DEFAULT_SINKS.iter().copied());
    let broken_report: TaintReport = disrobe_taint::analyze(&module, &broken_config);
    assert!(
        !broken_report
            .findings()
            .iter()
            .any(|f: &disrobe_taint::TaintFinding| f.function == "taint_entry"),
        "removing fgets from the source list must lower recall on the known flow to zero, proving a \
         broken propagation rule moves the grade rather than being absorbed silently: {broken_report:?}"
    );
}

#[test]
fn an_overbroad_match_rule_lowers_precision_against_the_strict_rule() {
    let fixture: CompiledFixture = compile_combined(
        "match-rule-control",
        &[
            SAFE_SIBLING_BODY,
            TAINTED_SIBLING_BODY,
            COMBINED_DRIVER_BODY,
        ],
    );
    let bytes: Vec<u8> = fs::read(&fixture.executable).expect("read compiled match-rule control");
    let module: NirModule = juliet_corpus::lift_native_module(&bytes);
    let config: TaintConfig = juliet_corpus::default_taint_config();
    let report: TaintReport = disrobe_taint::analyze(&module, &config);
    assert!(
        report
            .findings()
            .iter()
            .any(|f: &disrobe_taint::TaintFinding| f.function == "taint_sibling"),
        "taint_sibling must show a real flow for this control to mean anything: {report:?}"
    );

    let strict_flags_safe_sibling: bool = report
        .findings()
        .iter()
        .any(|f: &disrobe_taint::TaintFinding| f.function == "safe_sibling");
    let overbroad_flags_safe_sibling: bool = !report.findings().is_empty();
    assert!(
        !strict_flags_safe_sibling,
        "the strict per-function match rule must correctly clear safe_sibling, which never calls a \
         configured source: {report:?}"
    );
    assert!(
        overbroad_flags_safe_sibling,
        "the over-broad any-finding-in-the-binary match rule must incorrectly flag safe_sibling too; \
         that wrongness is exactly what this test proves moves the score"
    );

    let true_positives: usize = 1;
    let strict_false_positives: usize = usize::from(strict_flags_safe_sibling);
    let overbroad_false_positives: usize = usize::from(overbroad_flags_safe_sibling);
    let strict_precision: f64 = f64::from(true_positives as u32)
        / f64::from((true_positives + strict_false_positives) as u32);
    let overbroad_precision: f64 = f64::from(true_positives as u32)
        / f64::from((true_positives + overbroad_false_positives) as u32);
    assert!(
        overbroad_precision < strict_precision,
        "an over-broad matching rule must lower the precision figure: strict={strict_precision} \
         overbroad={overbroad_precision}"
    );
}

fn assert_no_case_is_silently_dropped(report: &juliet_corpus::GradedReport) {
    for tally in report.tallies.values() {
        let accounted: usize = tally.true_positives
            + tally.false_positives
            + tally.false_negatives
            + tally.true_negatives
            + tally.timeouts
            + tally.unanalysable;
        assert_eq!(
            accounted,
            tally.groups * 2,
            "every group contributes exactly one bad-side and one good-side verdict; a group whose \
             verdicts do not sum to groups*2 was silently excluded rather than recorded as a miss or a \
             timeout"
        );
    }
}

fn expected_group_counts() -> Vec<(juliet_corpus::Category, usize)> {
    use juliet_corpus::Category;
    vec![
        (Category::DirectFlow, 15),
        (Category::Field, 10),
        (Category::ArrayElement, 5),
        (Category::Container, 0),
        (Category::Callback, 0),
        (Category::VirtualCall, 0),
        (Category::FunctionPointer, 10),
        (Category::StringOperation, 0),
        (Category::SanitizerSevers, 0),
        (Category::ControlDependence, 85),
        (Category::Loop, 10),
        (Category::Recursion, 0),
        (Category::InterproceduralDepthOne, 40),
        (Category::InterproceduralDepthGtOne, 15),
        (Category::LibraryBoundary, 0),
    ]
}

#[test]
fn juliet_corpus_selection_matches_the_declared_population() {
    let case: &str = "juliet_corpus_selection_matches_the_declared_population";
    let Some(content) = juliet_corpus::load_corpus_content(case) else {
        return;
    };
    let mut actual: std::collections::BTreeMap<juliet_corpus::Category, usize> =
        std::collections::BTreeMap::new();
    for group in &content.groups {
        *actual.entry(group.category).or_insert(0) += 1;
    }
    for (category, expected) in expected_group_counts() {
        let got: usize = actual.get(&category).copied().unwrap_or(0);
        assert_eq!(
            got,
            expected,
            "{}: expected {expected} testcase groups selected from the pinned Juliet corpus slice, found {got}",
            category.label()
        );
    }
    assert_eq!(
        content.groups.len(),
        190,
        "the char/system-sink/.c-only CWE-78 slice must total 190 testcase groups"
    );
}

fn run_juliet_corpus_grading(opt_flag: &'static str, case: &str) {
    let Some(content) = juliet_corpus::load_corpus_content(case) else {
        return;
    };
    let _compiler: &std::path::Path = juliet_corpus::require_host_compiler(case);
    let config: TaintConfig = juliet_corpus::default_taint_config();
    let report: juliet_corpus::GradedReport =
        juliet_corpus::grade_corpus(&content, opt_flag, &config);
    println!("{}", report.render());
    assert_no_case_is_silently_dropped(&report);
}

#[test]
fn juliet_cwe78_command_injection_precision_recall_o0() {
    run_juliet_corpus_grading("-O0", "juliet_cwe78_command_injection_precision_recall_o0");
}

#[test]
fn juliet_cwe78_command_injection_precision_recall_o2() {
    run_juliet_corpus_grading("-O2", "juliet_cwe78_command_injection_precision_recall_o2");
}
