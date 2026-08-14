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
#[path = "support/published.rs"]
mod published;

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

fn finding_functions(json: &str) -> Vec<String> {
    let prefix: &str = "\"function\":\"";
    let mut names: Vec<String> = Vec::new();
    let mut rest: &str = json;
    while let Some(at) = rest.find(prefix) {
        let after: &str = &rest[at + prefix.len()..];
        let Some(end) = after.find('"') else {
            break;
        };
        names.push(after[..end].trim_start_matches('_').to_owned());
        rest = &after[end..];
    }
    names
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
    let functions: Vec<String> = finding_functions(&json);
    assert!(
        functions.iter().any(|f: &String| f == "taint_entry"),
        "the reference image's exported taint_entry must carry its own source-to-sink finding: {json}"
    );
    assert!(
        functions
            .iter()
            .all(|f: &String| f == "taint_entry" || f == "main"),
        "taint_entry and its FLOWING_BODY source can only produce the fgets-to-system sequence in \
         taint_entry itself, or in main when the host compiler inlines the exported function's body \
         into its one caller at -O2; a finding attributed to any other function is a false positive \
         this compiled reference image cannot produce: {json}"
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
    let Some(content) = juliet_corpus::load_corpus_content(
        case,
        juliet_corpus::CorpusSlice::C,
        juliet_corpus::SinkFamily::System,
    ) else {
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

fn run_juliet_corpus_grading(
    opt_flag: &'static str,
    slice: juliet_corpus::CorpusSlice,
    family: juliet_corpus::SinkFamily,
    case: &str,
) -> Option<juliet_corpus::GradedReport> {
    let content: juliet_corpus::JulietCorpusContent =
        juliet_corpus::load_corpus_content(case, slice, family)?;
    let _compiler: &std::path::Path = juliet_corpus::require_host_compiler(case, slice);
    let config: TaintConfig = juliet_corpus::taint_config_for(family);
    let report: juliet_corpus::GradedReport =
        juliet_corpus::grade_corpus(&content, opt_flag, &config);
    println!("{}", report.render());
    assert_no_case_is_silently_dropped(&report);
    Some(report)
}

struct GradeFloor {
    category: juliet_corpus::Category,
    label: &'static str,
    groups: u64,
    true_positive_floor: u64,
}

const O0_CATEGORY_FLOORS: [GradeFloor; 8] = [
    GradeFloor {
        category: juliet_corpus::Category::DirectFlow,
        label: "direct flow, gcc -O0",
        groups: 15,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::Field,
        label: "flow through a field, gcc -O0",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::ArrayElement,
        label: "flow through an array element, gcc -O0",
        groups: 5,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::FunctionPointer,
        label: "flow across a function pointer, gcc -O0",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::ControlDependence,
        label: "implicit flow through a control dependence, gcc -O0",
        groups: 85,
        true_positive_floor: 6,
    },
    GradeFloor {
        category: juliet_corpus::Category::Loop,
        label: "flow through a loop, gcc -O0",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthOne,
        label: "inter-procedural flow at depth one, gcc -O0",
        groups: 40,
        true_positive_floor: 6,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthGtOne,
        label: "inter-procedural flow at depth greater than one, gcc -O0",
        groups: 15,
        true_positive_floor: 0,
    },
];

const O0_AGGREGATE_GROUPS: u64 = 190;
const O0_AGGREGATE_TP_FLOOR: u64 = 12;

fn assert_fresh_grade_clears_named_floors(
    report: &juliet_corpus::GradedReport,
    floors: &[GradeFloor],
    aggregate_groups_floor: u64,
    aggregate_tp_floor: u64,
    aggregate_label: &str,
) {
    let mut aggregate_groups: u64 = 0;
    let mut aggregate_true_positives: u64 = 0;
    for floor in floors {
        let tally: juliet_corpus::CategoryTally = report
            .tallies
            .get(&floor.category)
            .copied()
            .unwrap_or_default();
        let groups: u64 = tally.groups as u64;
        let true_positives: u64 = tally.true_positives as u64;
        assert_eq!(
            groups, floor.groups,
            "{}: the pinned Juliet corpus selection changed size, was {} testcase groups and is \
             now {groups}",
            floor.label, floor.groups
        );
        assert_eq!(
            tally.false_positives, 0,
            "{}: a false positive appeared where the published figure states precision 100%: \
             {tally:?}",
            floor.label
        );
        assert_eq!(
            tally.timeouts, 0,
            "{}: a compile or analyze timeout appeared, which must not silently lower recall by \
             timing cases out: {tally:?}",
            floor.label
        );
        assert_eq!(
            tally.unanalysable, 0,
            "{}: an unanalysable group appeared where every group counts as graded: {tally:?}",
            floor.label
        );
        assert!(
            true_positives >= floor.true_positive_floor,
            "{}: true positives dropped to {true_positives} of {groups}, below the {} the \
             published figure states as a floor",
            floor.label,
            floor.true_positive_floor
        );
        aggregate_groups += groups;
        aggregate_true_positives += true_positives;
    }
    assert_eq!(
        aggregate_groups, aggregate_groups_floor,
        "{aggregate_label}: the populated categories no longer sum to the published \
         {aggregate_groups_floor}-group population"
    );
    assert!(
        aggregate_true_positives >= aggregate_tp_floor,
        "{aggregate_label}: aggregate true positives dropped to {aggregate_true_positives} of \
         {aggregate_groups}, below the published floor of {aggregate_tp_floor}"
    );
}

#[test]
fn juliet_cwe78_command_injection_precision_recall_o0() {
    let Some(report): Option<juliet_corpus::GradedReport> = run_juliet_corpus_grading(
        "-O0",
        juliet_corpus::CorpusSlice::C,
        juliet_corpus::SinkFamily::System,
        "juliet_cwe78_command_injection_precision_recall_o0",
    ) else {
        return;
    };
    assert_fresh_grade_clears_named_floors(
        &report,
        &O0_CATEGORY_FLOORS,
        O0_AGGREGATE_GROUPS,
        O0_AGGREGATE_TP_FLOOR,
        "aggregate 12 of 190 (6.3%) at -O0, published in docs/src/anti-analysis.md and in the \
         taint-juliet-cwe78 evidence descriptor's note",
    );
}

#[test]
fn every_selectable_sink_family_matches_the_system_family_population() {
    let case: &str = "every_selectable_sink_family_matches_the_system_family_population";
    for family in IMPORT_INDIRECT_FAMILIES {
        let label: &str = family.label();
        let Some(content) =
            juliet_corpus::load_corpus_content(case, juliet_corpus::CorpusSlice::C, family)
        else {
            return;
        };
        let token: String = format!("_{label}_");
        let mut actual: std::collections::BTreeMap<juliet_corpus::Category, usize> =
            std::collections::BTreeMap::new();
        for group in &content.groups {
            *actual.entry(group.category).or_insert(0) += 1;
            assert!(
                group.flaw_file.contains(token.as_str()),
                "{}: the {label} selection took a file that sink family does not name",
                group.flaw_file
            );
        }
        for (category, expected) in expected_group_counts() {
            let got: usize = actual.get(&category).copied().unwrap_or(0);
            assert_eq!(
                got,
                expected,
                "{label}, {}: this sink family is generated from the same flow-variant templates \
                 as the system family, so its per-category population must match group for group; \
                 expected {expected}, found {got}",
                category.label()
            );
        }
        assert_eq!(
            content.groups.len(),
            190,
            "{label}: the char/.c-only CWE-78 slice for this sink family must total 190 testcase \
             groups"
        );
    }
}

const EXECL_EXCLUSION_PROBE_GROUPS: usize = 2;

const IMPORT_INDIRECT_FAMILIES: [juliet_corpus::SinkFamily; 3] = [
    juliet_corpus::SinkFamily::Execl,
    juliet_corpus::SinkFamily::Execlp,
    juliet_corpus::SinkFamily::Popen,
];

fn group_named<'a>(
    content: &'a juliet_corpus::JulietCorpusContent,
    flaw_file: &str,
) -> &'a juliet_corpus::TestcaseGroup {
    content
        .groups
        .iter()
        .find(|group: &&juliet_corpus::TestcaseGroup| group.flaw_file == flaw_file)
        .unwrap_or_else(|| {
            panic!(
                "the {} slice has no group named {flaw_file}; the two sink families are generated \
                 from the same templates, so a missing counterpart means the paired control is \
                 comparing different testcases",
                content.family.label()
            )
        })
}

#[test]
fn sink_families_reached_through_the_import_table_stay_excluded_until_the_lift_path_names_them() {
    let case: &str = "sink_families_reached_through_the_import_table_stay_excluded_until_the_lift_path_names_them";
    let slice: juliet_corpus::CorpusSlice = juliet_corpus::CorpusSlice::C;
    let system: juliet_corpus::SinkFamily = juliet_corpus::SinkFamily::System;
    let Some(system_content): Option<juliet_corpus::JulietCorpusContent> =
        juliet_corpus::load_corpus_content(case, slice, system)
    else {
        return;
    };
    let compiler: &std::path::Path = juliet_corpus::require_host_compiler(case, slice);
    let system_config: TaintConfig = juliet_corpus::taint_config_for(system);
    let system_run: juliet_corpus::GradeRun<'_> =
        juliet_corpus::GradeRun::new(compiler, "-O2", &system_content, &system_config);

    for family in IMPORT_INDIRECT_FAMILIES {
        let label: &str = family.label();
        let Some(content): Option<juliet_corpus::JulietCorpusContent> =
            juliet_corpus::load_corpus_content(case, slice, family)
        else {
            return;
        };
        assert_eq!(
            content.groups.len(),
            190,
            "{label}: every CWE-78 sink family ships the same 190 char/.c testcase groups, so a \
             different count means the selection is probing something other than this family"
        );
        let config: TaintConfig = juliet_corpus::taint_config_for(family);
        for sink in family.corpus_sink_names() {
            assert!(
                config.is_sink(sink),
                "{label}: {sink} must be a configured sink, or a miss would only mean nobody asked \
                 for it"
            );
        }
        let run: juliet_corpus::GradeRun<'_> =
            juliet_corpus::GradeRun::new(compiler, "-O2", &content, &config);
        let console_token: String = format!("_console_{label}_");
        let probed: Vec<&juliet_corpus::TestcaseGroup> = content
            .groups
            .iter()
            .filter(|group: &&juliet_corpus::TestcaseGroup| {
                group.flaw_file.contains(console_token.as_str())
            })
            .take(EXECL_EXCLUSION_PROBE_GROUPS)
            .collect();
        assert_eq!(
            probed.len(),
            EXECL_EXCLUSION_PROBE_GROUPS,
            "{label}: the console source family supplies the pair's fixed variable, a source the \
             lift path names in both arms, and the selection no longer holds \
             {EXECL_EXCLUSION_PROBE_GROUPS} of its groups"
        );

        for group in probed {
            let grade: juliet_corpus::GroupGrade =
                juliet_corpus::grade_group(&run, &content, group);
            assert_eq!(
                grade.unanalysable_reason, None,
                "{}: this family builds on this host, so its exclusion must rest on import naming \
                 rather than on a compile failure like the w32_spawnv family's",
                group.flaw_file
            );
            assert_ne!(
                grade.bad_verdict,
                juliet_corpus::CaseVerdict::Timeout,
                "{}: a timeout would make this probe measure the clock, not import naming",
                group.flaw_file
            );
            assert!(
                grade.source_resolved,
                "{}: the lift path could not even name this binary's fgets source, so a missing \
                 sink name proves nothing about the sink; the pair needs a source both arms resolve",
                group.flaw_file
            );
            assert!(
                !grade.sink_resolved,
                "{}: the lifted module now names this binary's {label} call. gcc reaches the \
                 underscore-prefixed C runtime entry points through an indirect call on the import \
                 address table, while it reaches system through a named local thunk, and \
                 ImportThunks keys names by a direct call target. A host or lifter that does name \
                 this one removes the reason the family is left out of the graded population, and \
                 it must be enrolled and graded instead of excluded",
                group.flaw_file
            );
            assert_eq!(
                grade.bad_verdict,
                juliet_corpus::CaseVerdict::FalseNegative,
                "{}: an unnamed sink cannot produce a source-to-sink finding",
                group.flaw_file
            );
            assert_eq!(
                grade.reported_flows, 0,
                "{}: no configured sink is named in this binary, so it can report no flow at all",
                group.flaw_file
            );

            let counterpart_file: String = group
                .flaw_file
                .replace(console_token.as_str(), "_console_system_");
            let counterpart: &juliet_corpus::TestcaseGroup =
                group_named(&system_content, &counterpart_file);
            let counterpart_grade: juliet_corpus::GroupGrade =
                juliet_corpus::grade_group(&system_run, &system_content, counterpart);
            assert_eq!(
                counterpart_grade.unanalysable_reason, None,
                "{counterpart_file}: the system counterpart must build for the pair to isolate the \
                 sink as the only difference"
            );
            assert!(
                counterpart_grade.source_resolved,
                "{counterpart_file}: both arms of the pair must name the same source for the sink \
                 to be the only difference between them"
            );
            assert!(
                counterpart_grade.sink_resolved,
                "{counterpart_file}: the pair is what proves the {label} exclusion is a property \
                 of how that import is called rather than of these testcases, and it stops holding \
                 once the control stops naming its own sink"
            );
        }
    }
}

const SPAWNV_EXCLUSION_PROBE_GROUPS: usize = 3;

#[test]
fn the_w32_spawnv_family_stays_excluded_only_while_this_host_cannot_build_it() {
    let case: &str = "the_w32_spawnv_family_stays_excluded_only_while_this_host_cannot_build_it";
    let slice: juliet_corpus::CorpusSlice = juliet_corpus::CorpusSlice::C;
    let family: juliet_corpus::SinkFamily = juliet_corpus::SinkFamily::Win32SpawnV;
    let Some(content): Option<juliet_corpus::JulietCorpusContent> =
        juliet_corpus::load_corpus_content(case, slice, family)
    else {
        return;
    };
    let compiler: &std::path::Path = juliet_corpus::require_host_compiler(case, slice);
    let config: TaintConfig = juliet_corpus::taint_config_for(family);
    assert_eq!(
        content.groups.len(),
        190,
        "{case}: the char/w32_spawnv-sink/.c-only CWE-78 slice must select the same 190 testcase \
         groups the other sink families ship; a probe over an empty selection would prove nothing"
    );
    let run: juliet_corpus::GradeRun<'_> =
        juliet_corpus::GradeRun::new(compiler, "-O2", &content, &config);

    for group in content.groups.iter().take(SPAWNV_EXCLUSION_PROBE_GROUPS) {
        let grade: juliet_corpus::GroupGrade = juliet_corpus::grade_group(&run, &content, group);
        let reason: &str = grade.unanalysable_reason.as_deref().unwrap_or("");
        assert_eq!(
            grade.bad_verdict,
            juliet_corpus::CaseVerdict::Unanalysable,
            "{}: this host built a w32_spawnv testcase. The family is left out of the graded \
             population only because the host toolchain rejects the `char *argv[]` Juliet passes \
             to _spawnv's `const char * const *` parameter, so a host that accepts it removes the \
             reason for the exclusion and the family must be enrolled and graded instead of \
             skipped. Recorded outcome: {reason}",
            group.flaw_file
        );
        assert_eq!(
            grade.good_verdict,
            juliet_corpus::CaseVerdict::Unanalysable,
            "{}: a group that cannot be built must record the same unanalysable verdict on both \
             sides rather than crediting its good side as a true negative",
            group.flaw_file
        );
        assert!(
            reason.contains("compiler exited"),
            "{}: the exclusion must be carried by a captured compiler diagnostic, not by an \
             unexplained absence; recorded outcome: {reason}",
            group.flaw_file
        );
        assert_eq!(
            grade.reported_flows, 0,
            "{}: a group that never produced a binary cannot have produced findings",
            group.flaw_file
        );
    }
}

fn expected_cpp_group_counts() -> Vec<(juliet_corpus::Category, usize)> {
    use juliet_corpus::Category;
    vec![
        (Category::DirectFlow, 5),
        (Category::Field, 10),
        (Category::ArrayElement, 0),
        (Category::Container, 15),
        (Category::Callback, 0),
        (Category::VirtualCall, 10),
        (Category::FunctionPointer, 0),
        (Category::StringOperation, 0),
        (Category::SanitizerSevers, 0),
        (Category::ControlDependence, 0),
        (Category::Loop, 0),
        (Category::Recursion, 0),
        (Category::InterproceduralDepthOne, 10),
        (Category::InterproceduralDepthGtOne, 0),
        (Category::LibraryBoundary, 0),
    ]
}

#[test]
fn juliet_cpp_corpus_selection_matches_the_declared_population() {
    let case: &str = "juliet_cpp_corpus_selection_matches_the_declared_population";
    let Some(content) = juliet_corpus::load_corpus_content(
        case,
        juliet_corpus::CorpusSlice::Cpp,
        juliet_corpus::SinkFamily::System,
    ) else {
        return;
    };
    let mut actual: std::collections::BTreeMap<juliet_corpus::Category, usize> =
        std::collections::BTreeMap::new();
    let mut by_variant: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for group in &content.groups {
        *actual.entry(group.category).or_insert(0) += 1;
        *by_variant.entry(group.variant.clone()).or_insert(0) += 1;
    }
    for (category, expected) in expected_cpp_group_counts() {
        let got: usize = actual.get(&category).copied().unwrap_or(0);
        assert_eq!(
            got,
            expected,
            "{}: expected {expected} testcase groups selected from the pinned Juliet corpus c++ \
             slice, found {got}",
            category.label()
        );
    }
    let variants: Vec<(&str, usize)> = by_variant
        .iter()
        .map(|(variant, count): (&String, &usize)| (variant.as_str(), *count))
        .collect();
    assert_eq!(
        variants,
        vec![
            ("33", 5),
            ("43", 5),
            ("62", 5),
            ("72", 5),
            ("73", 5),
            ("74", 5),
            ("81", 5),
            ("82", 5),
            ("83", 5),
            ("84", 5),
        ],
        "the char/system-sink/.cpp-only CWE-78 slice must select every flow variant Juliet ships \
         for that combination, five bad-source flavours each"
    );
    assert_eq!(
        content.groups.len(),
        50,
        "the char/system-sink/.cpp-only CWE-78 slice must total 50 testcase groups"
    );
    for group in &content.groups {
        assert!(
            group.namespace.is_some(),
            "{}: every c++ group must carry the namespace its own sources declare",
            group.flaw_file
        );
        assert_eq!(
            group.bad_entry, "bad",
            "{}: Juliet's c++ templates always name the outer bad entry `bad`",
            group.flaw_file
        );
        assert_eq!(
            group.good_entry, "good",
            "{}: Juliet's c++ templates always name the outer good entry `good`",
            group.flaw_file
        );
    }
}

const CPP_O2_AGGREGATE_LABEL: &str = "aggregate (5 populated c++ categories), g++ -O2";
const CPP_O2_AGGREGATE_GROUPS: u64 = 50;
const CPP_O2_AGGREGATE_TP_FLOOR: u64 = 10;

const CPP_O2_CATEGORY_FLOORS: [GradeFloor; 5] = [
    GradeFloor {
        category: juliet_corpus::Category::DirectFlow,
        label: "direct flow, g++ -O2",
        groups: 5,
        true_positive_floor: 3,
    },
    GradeFloor {
        category: juliet_corpus::Category::Field,
        label: "flow through a field, g++ -O2",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::Container,
        label: "flow through a container, g++ -O2",
        groups: 15,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::VirtualCall,
        label: "flow across a virtual call, g++ -O2",
        groups: 10,
        true_positive_floor: 4,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthOne,
        label: "inter-procedural flow at depth one, g++ -O2",
        groups: 10,
        true_positive_floor: 3,
    },
];

const CPP_O0_AGGREGATE_LABEL: &str = "aggregate (5 populated c++ categories), g++ -O0";
const CPP_O0_AGGREGATE_TP_FLOOR: u64 = 0;

const CPP_O0_CATEGORY_FLOORS: [GradeFloor; 5] = [
    GradeFloor {
        category: juliet_corpus::Category::DirectFlow,
        label: "direct flow, g++ -O0",
        groups: 5,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::Field,
        label: "flow through a field, g++ -O0",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::Container,
        label: "flow through a container, g++ -O0",
        groups: 15,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::VirtualCall,
        label: "flow across a virtual call, g++ -O0",
        groups: 10,
        true_positive_floor: 0,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthOne,
        label: "inter-procedural flow at depth one, g++ -O0",
        groups: 10,
        true_positive_floor: 0,
    },
];

#[test]
fn juliet_cwe78_cpp_precision_recall_o2() {
    let Some(report): Option<juliet_corpus::GradedReport> = run_juliet_corpus_grading(
        "-O2",
        juliet_corpus::CorpusSlice::Cpp,
        juliet_corpus::SinkFamily::System,
        "juliet_cwe78_cpp_precision_recall_o2",
    ) else {
        return;
    };
    assert_fresh_grade_clears_named_floors(
        &report,
        &CPP_O2_CATEGORY_FLOORS,
        CPP_O2_AGGREGATE_GROUPS,
        CPP_O2_AGGREGATE_TP_FLOOR,
        CPP_O2_AGGREGATE_LABEL,
    );
}

#[test]
fn juliet_cwe78_cpp_precision_recall_o0() {
    let Some(report): Option<juliet_corpus::GradedReport> = run_juliet_corpus_grading(
        "-O0",
        juliet_corpus::CorpusSlice::Cpp,
        juliet_corpus::SinkFamily::System,
        "juliet_cwe78_cpp_precision_recall_o0",
    ) else {
        return;
    };
    assert_fresh_grade_clears_named_floors(
        &report,
        &CPP_O0_CATEGORY_FLOORS,
        CPP_O2_AGGREGATE_GROUPS,
        CPP_O0_AGGREGATE_TP_FLOOR,
        CPP_O0_AGGREGATE_LABEL,
    );
}

const MATCH_RULE_CONTROL_SCAN_LIMIT: usize = 50;

#[test]
fn leaving_a_cpp_symbol_mangled_turns_a_recovered_flow_into_a_miss() {
    let case: &str = "leaving_a_cpp_symbol_mangled_turns_a_recovered_flow_into_a_miss";
    let slice: juliet_corpus::CorpusSlice = juliet_corpus::CorpusSlice::Cpp;
    let Some(content): Option<juliet_corpus::JulietCorpusContent> =
        juliet_corpus::load_corpus_content(case, slice, juliet_corpus::SinkFamily::System)
    else {
        return;
    };
    let compiler: &std::path::Path = juliet_corpus::require_host_compiler(case, slice);
    let config: TaintConfig = juliet_corpus::default_taint_config();
    assert!(
        content.groups.len() <= MATCH_RULE_CONTROL_SCAN_LIMIT,
        "{case}: the c++ selection grew to {} groups, past the {MATCH_RULE_CONTROL_SCAN_LIMIT} this \
         control is bounded to compile",
        content.groups.len()
    );
    let demangling_run: juliet_corpus::GradeRun<'_> = juliet_corpus::GradeRun {
        compiler,
        opt_flag: "-O2",
        resolution: juliet_corpus::NameResolution::Demangled,
        config: &config,
    };
    let as_reported_run: juliet_corpus::GradeRun<'_> = juliet_corpus::GradeRun {
        compiler,
        opt_flag: "-O2",
        resolution: juliet_corpus::NameResolution::AsReported,
        config: &config,
    };

    let mut control: Option<(&juliet_corpus::TestcaseGroup, juliet_corpus::GroupGrade)> = None;
    for group in content.groups.iter().take(MATCH_RULE_CONTROL_SCAN_LIMIT) {
        let grade: juliet_corpus::GroupGrade =
            juliet_corpus::grade_group(&demangling_run, &content, group);
        if grade.bad_verdict == juliet_corpus::CaseVerdict::TruePositive {
            control = Some((group, grade));
            break;
        }
    }
    let Some((group, resolved_grade)): Option<(
        &juliet_corpus::TestcaseGroup,
        juliet_corpus::GroupGrade,
    )> = control
    else {
        panic!(
            "{case}: none of the first {MATCH_RULE_CONTROL_SCAN_LIMIT} c++ groups produced a true \
             positive under the resolving match rule, so there is no recovered flow whose loss a \
             wrong rule could demonstrate; a control that cannot be established is never a pass"
        )
    };
    assert_eq!(
        resolved_grade.good_verdict,
        juliet_corpus::CaseVerdict::TrueNegative,
        "{}: the resolving rule must clear the good side of the control before the wrong rule can \
         be blamed for anything",
        group.flaw_file
    );

    let unresolved_grade: juliet_corpus::GroupGrade =
        juliet_corpus::grade_group(&as_reported_run, &content, group);
    assert_eq!(
        unresolved_grade.reported_flows, resolved_grade.reported_flows,
        "{}: only the match rule changed, so the engine must report the same number of flows both \
         ways; a different count means this control compared two different analyses",
        group.flaw_file
    );
    assert_eq!(
        unresolved_grade.bad_verdict,
        juliet_corpus::CaseVerdict::FalseNegative,
        "{}: comparing the raw mangled symbol against the source-level name the corpus declares \
         must lose the recovered flow, proving the match rule between a report entry and a \
         manifest entry is what moves this score",
        group.flaw_file
    );
    assert_eq!(
        unresolved_grade.good_verdict,
        juliet_corpus::CaseVerdict::FalsePositive,
        "{}: the same wrong rule must also stop crediting the good side, so it lowers precision as \
         well as recall",
        group.flaw_file
    );
}

const PUBLISHED_O2_HEADING: &str = "Native taint source-to-sink flow (Juliet CWE-78 char/system corpus, gcc 16.1.0 -O2 -fno-builtin, Windows x86-64)";
const PUBLISHED_O2_AGGREGATE_LABEL: &str = "aggregate (8 populated categories), gcc -O2";
const PUBLISHED_O2_AGGREGATE_GROUPS: u64 = 190;
const PUBLISHED_O2_AGGREGATE_TP_FLOOR: u64 = 93;

const PUBLISHED_O2_CATEGORY_FLOORS: [GradeFloor; 8] = [
    GradeFloor {
        category: juliet_corpus::Category::DirectFlow,
        label: "direct flow, gcc -O2",
        groups: 15,
        true_positive_floor: 9,
    },
    GradeFloor {
        category: juliet_corpus::Category::Field,
        label: "flow through a field, gcc -O2",
        groups: 10,
        true_positive_floor: 6,
    },
    GradeFloor {
        category: juliet_corpus::Category::ArrayElement,
        label: "flow through an array element, gcc -O2",
        groups: 5,
        true_positive_floor: 1,
    },
    GradeFloor {
        category: juliet_corpus::Category::FunctionPointer,
        label: "flow across a function pointer, gcc -O2",
        groups: 10,
        true_positive_floor: 6,
    },
    GradeFloor {
        category: juliet_corpus::Category::ControlDependence,
        label: "implicit flow through a control dependence, gcc -O2",
        groups: 85,
        true_positive_floor: 49,
    },
    GradeFloor {
        category: juliet_corpus::Category::Loop,
        label: "flow through a loop, gcc -O2",
        groups: 10,
        true_positive_floor: 6,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthOne,
        label: "inter-procedural flow at depth one, gcc -O2",
        groups: 40,
        true_positive_floor: 16,
    },
    GradeFloor {
        category: juliet_corpus::Category::InterproceduralDepthGtOne,
        label: "inter-procedural flow at depth greater than one, gcc -O2",
        groups: 15,
        true_positive_floor: 0,
    },
];

#[test]
fn juliet_cwe78_command_injection_precision_recall_o2() {
    let Some(report): Option<juliet_corpus::GradedReport> = run_juliet_corpus_grading(
        "-O2",
        juliet_corpus::CorpusSlice::C,
        juliet_corpus::SinkFamily::System,
        "juliet_cwe78_command_injection_precision_recall_o2",
    ) else {
        return;
    };
    assert_fresh_grade_clears_named_floors(
        &report,
        &PUBLISHED_O2_CATEGORY_FLOORS,
        PUBLISHED_O2_AGGREGATE_GROUPS,
        PUBLISHED_O2_AGGREGATE_TP_FLOOR,
        PUBLISHED_O2_AGGREGATE_LABEL,
    );
}

fn assert_published_value_matches_its_own_num_and_den(
    heading: &str,
    label: &str,
    num: u64,
    den: u64,
) {
    let published_value: f64 = published::published_f64(heading, label, "value");
    let true_ratio: f64 = 100.0 * (num as f64) / (den as f64);
    assert!(
        published_value <= true_ratio,
        "{label}: xtask/data/recovery.json's value {published_value} overstates the {true_ratio} \
         its own num/den compute; a published percentage must never round up past what its own \
         counts prove"
    );
    assert!(
        true_ratio - published_value <= 0.1,
        "{label}: xtask/data/recovery.json's value {published_value} understates the {true_ratio} \
         its own num/den compute by more than one-decimal rounding accounts for"
    );
}

#[test]
fn published_juliet_o2_bars_match_the_pinned_floors() {
    for floor in &PUBLISHED_O2_CATEGORY_FLOORS {
        let published_num: u64 = published::published_u64(PUBLISHED_O2_HEADING, floor.label, "num");
        let published_den: u64 = published::published_u64(PUBLISHED_O2_HEADING, floor.label, "den");
        assert_eq!(
            published_den, floor.groups,
            "{}: xtask/data/recovery.json's den disagrees with the population this file pins",
            floor.label
        );
        assert_eq!(
            published_num, floor.true_positive_floor,
            "{}: xtask/data/recovery.json's num disagrees with the true-positive floor this file \
             pins; editing either alone must fail this test",
            floor.label
        );
        assert_published_value_matches_its_own_num_and_den(
            PUBLISHED_O2_HEADING,
            floor.label,
            published_num,
            published_den,
        );
    }
    let published_aggregate_num: u64 =
        published::published_u64(PUBLISHED_O2_HEADING, PUBLISHED_O2_AGGREGATE_LABEL, "num");
    let published_aggregate_den: u64 =
        published::published_u64(PUBLISHED_O2_HEADING, PUBLISHED_O2_AGGREGATE_LABEL, "den");
    assert_eq!(
        published_aggregate_den, PUBLISHED_O2_AGGREGATE_GROUPS,
        "{PUBLISHED_O2_AGGREGATE_LABEL}: xtask/data/recovery.json's den disagrees with the \
         population this file pins"
    );
    assert_eq!(
        published_aggregate_num, PUBLISHED_O2_AGGREGATE_TP_FLOOR,
        "{PUBLISHED_O2_AGGREGATE_LABEL}: xtask/data/recovery.json's num disagrees with the \
         true-positive floor this file pins; editing either alone must fail this test"
    );
    assert_published_value_matches_its_own_num_and_den(
        PUBLISHED_O2_HEADING,
        PUBLISHED_O2_AGGREGATE_LABEL,
        published_aggregate_num,
        published_aggregate_den,
    );
}
