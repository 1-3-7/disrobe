#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_nir::{NirFunction, NirModule, SourceLang};
use disrobe_nir_lift::lower_x86_64;
use disrobe_pass_native::disasm_ir::build_disasm_payload;
use disrobe_query::disasm_to_nir;
use disrobe_semdiff::{
    Indeterminate, LineageReport, LineageVariant, MatchTier, StructuralMatchReport, VariantFamily,
    structural_match, variant_lineage,
};
use object::{Object as _, ObjectSymbol as _};

const BATTERY_SOURCE: &str = r"
#include <stdint.h>

__attribute__((noinline)) int32_t add_two(int32_t a, int32_t b) { return a + b; }
__attribute__((noinline)) int32_t sub_two(int32_t a, int32_t b) { return a - b; }
__attribute__((noinline)) int32_t mul_two(int32_t a, int32_t b) { return a * b; }
__attribute__((noinline)) int32_t xor_two(int32_t a, int32_t b) { return a ^ b; }
__attribute__((noinline)) int32_t and_shift(int32_t a, int32_t b) { return (a & b) << 3; }
__attribute__((noinline)) int32_t or_mix(int32_t a, int32_t b) { return (a | b) + 17; }
__attribute__((noinline)) int32_t poly3(int32_t a, int32_t b) { return a * 3 + b * 5 - 9; }
__attribute__((noinline)) int32_t clamp3(int32_t v, int32_t lo, int32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
__attribute__((noinline)) int32_t sum_loop(int32_t n) {
    int32_t s = 0;
    for (int32_t i = 0; i < n; i++) { s += i; }
    return s;
}
__attribute__((noinline)) int32_t combo_a(int32_t x, int32_t y) {
    return clamp3(add_two(x, y), 0, 1000);
}
__attribute__((noinline)) int32_t top_level(int32_t x, int32_t y) {
    return mul_two(combo_a(x, y), 1) + sum_loop(sub_two(x, y)) + xor_two(x, y);
}
int main(int argc, char **argv) {
    (void)argv;
    int32_t x = argc * 7;
    int32_t y = argc * 3 + 11;
    return (top_level(x, y) + and_shift(x, y) + or_mix(x, y) + poly3(x, y)) & 0xff;
}
";

const LTO_PROBE_SOURCE: &str = r"
__attribute__((noinline)) int probe_leaf(int a) { return a * 3 + 1; }
int main(void) { return probe_leaf(2) & 1; }
";

const TRACKED_NAMES: &[&str] = &[
    "add_two",
    "sub_two",
    "mul_two",
    "xor_two",
    "and_shift",
    "or_mix",
    "poly3",
    "clamp3",
    "sum_loop",
    "combo_a",
    "top_level",
];

const CANDIDATE_COMPILERS: [&str; 2] = ["gcc", "clang"];
const CANDIDATE_STRIP_TOOLS: [&str; 2] = ["llvm-strip", "strip"];
const REQUIRE_VAR: &str = "DISROBE_REQUIRE_NATIVE_TOOLCHAIN";
const INSTALL_HINT: &str = "install a native C compiler (gcc or clang) and a strip tool (llvm-strip or strip) and put them on PATH";
const BASE_OPT_LEVELS: [&str; 5] = ["-O0", "-O1", "-O2", "-O3", "-Os"];
const LTO_OPT_LEVEL: &str = "-flto";
const REFERENCE_OPT_LEVEL: &str = "-O2";
const LOWEST_OPT_LEVEL: &str = "-O0";

const MAX_LIFTED_FUNCTIONS: usize = 4096;
const MAX_FUNCTION_BYTES: usize = 8192;

const MIN_TRACKED_SUMMARY_NAMES_ACROSS_THE_OPTIMIZATION_GAP: usize = 4;
const MIN_COMPLETE_TRACKED_FAMILIES: usize = 4;
const MIN_SUMMARY_TIER_COMMITMENTS: usize = 40;

fn tool_responds(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output: Output| output.status.success())
}

fn available_compilers() -> Vec<&'static str> {
    CANDIDATE_COMPILERS
        .into_iter()
        .filter(|compiler: &&str| tool_responds(compiler))
        .collect()
}

fn strip_tool() -> Option<&'static str> {
    CANDIDATE_STRIP_TOOLS
        .into_iter()
        .find(|tool: &&str| tool_responds(tool))
}

struct Toolchain {
    compilers: Vec<&'static str>,
    strip: &'static str,
    primary: &'static str,
}

fn toolchain_is_mandatory(value: Option<&std::ffi::OsStr>) -> bool {
    let Some(raw): Option<&std::ffi::OsStr> = value else {
        return false;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    !matches!(
        text.as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn refuse_or_announce(defect: &str) {
    assert!(
        !toolchain_is_mandatory(std::env::var_os(REQUIRE_VAR).as_deref()),
        "{REQUIRE_VAR} makes a native toolchain mandatory for this run, so the optimization-lineage grade cannot reach its reference and must not report success: {defect}. To fix it, {INSTALL_HINT}; to permit a run that measures nothing here, clear {REQUIRE_VAR}."
    );
    eprintln!(
        "NOT MEASURED: the optimization-lineage grade was skipped because {defect}. Set {REQUIRE_VAR}=1 to fail instead of skipping when a native toolchain is absent. To fix it, {INSTALL_HINT}."
    );
}

fn require_toolchain() -> Option<Toolchain> {
    let compilers: Vec<&'static str> = available_compilers();
    let Some(&primary): Option<&&'static str> = compilers.first() else {
        refuse_or_announce("neither `gcc` nor `clang` is callable on PATH");
        return None;
    };
    let Some(strip): Option<&'static str> = strip_tool() else {
        refuse_or_announce("neither `llvm-strip` nor `strip` is callable on PATH");
        return None;
    };
    Some(Toolchain {
        compilers,
        strip,
        primary,
    })
}

fn run_compiler(compiler: &str, opt: &str, source: &Path, out: &Path) -> std::io::Result<Output> {
    let target_args: Vec<&str> = if compiler == "clang" {
        vec!["-target", "x86_64-w64-mingw32"]
    } else {
        Vec::new()
    };
    Command::new(compiler)
        .args(&target_args)
        .args([opt, "-g", "-o"])
        .arg(out)
        .arg(source)
        .output()
}

fn compiler_diagnostic(compiler: &str, opt: &str, outcome: &std::io::Result<Output>) -> String {
    match outcome {
        Ok(output) => {
            let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if stderr.is_empty() {
                format!(
                    "{compiler} {opt} exited with {} and no diagnostic",
                    output.status
                )
            } else {
                stderr
            }
        }
        Err(error) => format!("{compiler} {opt} could not be launched: {error}"),
    }
}

fn lto_refusal(compiler: &str, scratch: &Path) -> Option<String> {
    let source: PathBuf = scratch.join(format!("lto-probe-{compiler}.c"));
    std::fs::write(&source, LTO_PROBE_SOURCE).expect("write the link-time-optimization probe");
    let out: PathBuf = scratch.join(format!("lto-probe-{compiler}.exe"));
    let outcome: std::io::Result<Output> = run_compiler(compiler, LTO_OPT_LEVEL, &source, &out);
    let linked: bool = outcome
        .as_ref()
        .is_ok_and(|output: &Output| output.status.success())
        && out.is_file();
    if linked {
        return None;
    }
    Some(compiler_diagnostic(compiler, LTO_OPT_LEVEL, &outcome))
}

struct CompilerPlan {
    compiler: &'static str,
    opt_levels: Vec<&'static str>,
    lto_refusal: Option<String>,
}

fn plan_matrix(toolchain: &Toolchain, scratch: &Path) -> Vec<CompilerPlan> {
    toolchain
        .compilers
        .iter()
        .map(|&compiler: &&'static str| {
            let mut opt_levels: Vec<&'static str> = BASE_OPT_LEVELS.to_vec();
            let refusal: Option<String> = lto_refusal(compiler, scratch);
            if refusal.is_none() {
                opt_levels.push(LTO_OPT_LEVEL);
            }
            CompilerPlan {
                compiler,
                opt_levels,
                lto_refusal: refusal,
            }
        })
        .collect()
}

fn strip_copy(strip: &str, source: &Path, out: &Path) -> bool {
    std::fs::copy(source, out).is_ok()
        && Command::new(strip)
            .arg(out)
            .status()
            .is_ok_and(|status: std::process::ExitStatus| status.success())
}

fn bare_name(raw: &str) -> &str {
    raw.trim_start_matches('_')
}

fn text_definitions(bytes: &[u8]) -> BTreeMap<String, BTreeSet<u64>> {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return BTreeMap::new();
    };
    let mut definitions: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for sym in file.symbols() {
        if !sym.is_definition() || sym.kind() != object::SymbolKind::Text {
            continue;
        }
        if sym.section_index().is_none() {
            continue;
        }
        let address: u64 = sym.address();
        if address == 0 {
            continue;
        }
        let Ok(raw): Result<&str, object::Error> = sym.name() else {
            continue;
        };
        let bare: &str = bare_name(raw);
        if bare.is_empty() || bare.starts_with('.') {
            continue;
        }
        match definitions.entry(bare.to_owned()) {
            Entry::Vacant(slot) => {
                slot.insert(BTreeSet::from([address]));
            }
            Entry::Occupied(mut slot) => {
                slot.get_mut().insert(address);
            }
        }
    }
    definitions
}

fn named_addresses(bytes: &[u8]) -> BTreeMap<String, u64> {
    text_definitions(bytes)
        .into_iter()
        .filter_map(|(name, addresses): (String, BTreeSet<u64>)| {
            let mut unique: std::collections::btree_set::IntoIter<u64> = addresses.into_iter();
            let first: u64 = unique.next()?;
            unique.next().is_none().then_some((name, first))
        })
        .collect()
}

fn ambiguous_definitions(bytes: &[u8]) -> Vec<String> {
    text_definitions(bytes)
        .into_iter()
        .filter_map(|(name, addresses): (String, BTreeSet<u64>)| {
            (addresses.len() > 1).then_some(name)
        })
        .collect()
}

fn placeholder_definitions(bytes: &[u8], wanted: &str) -> usize {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return 0;
    };
    file.symbols()
        .filter(|sym: &object::Symbol<'_, '_>| sym.is_definition() && sym.address() == 0)
        .filter(|sym: &object::Symbol<'_, '_>| {
            sym.name().is_ok_and(|raw: &str| bare_name(raw) == wanted)
        })
        .count()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LiftStats {
    lowered: usize,
    lower_failed: usize,
    oversized: usize,
}

fn lift_pcode_module(image: &[u8]) -> (NirModule, LiftStats) {
    let payload = build_disasm_payload(image).expect("disasm payload");
    let mut ordered: Vec<(u64, Vec<u8>)> = payload
        .instructions
        .iter()
        .map(|instruction| (instruction.offset, instruction.bytes.clone()))
        .collect();
    ordered.sort_by_key(|(offset, _): &(u64, Vec<u8>)| *offset);
    let coarse: NirModule = disasm_to_nir(&payload);
    let mut functions: Vec<NirFunction> = Vec::new();
    let mut stats: LiftStats = LiftStats::default();
    for function in coarse.functions.iter().take(MAX_LIFTED_FUNCTIONS) {
        let low: usize =
            ordered.partition_point(|(offset, _): &(u64, Vec<u8>)| *offset < function.address);
        let high: usize =
            ordered.partition_point(|(offset, _): &(u64, Vec<u8>)| *offset < function.end);
        let mut bytes: Vec<u8> = Vec::new();
        let mut oversized: bool = false;
        for (_, chunk) in &ordered[low..high] {
            if bytes.len() + chunk.len() > MAX_FUNCTION_BYTES {
                oversized = true;
                break;
            }
            bytes.extend_from_slice(chunk);
        }
        if oversized {
            stats.oversized += 1;
            continue;
        }
        if bytes.is_empty() {
            continue;
        }
        let Ok(mut lifted): Result<NirFunction, _> =
            lower_x86_64(&bytes, function.address, &function.name)
        else {
            stats.lower_failed += 1;
            continue;
        };
        lifted.name.clear();
        stats.lowered += 1;
        functions.push(lifted);
    }
    let module: NirModule = NirModule {
        source_hash: coarse.source_hash,
        lang: SourceLang::NativeX86,
        functions,
        symbols: Vec::new(),
    };
    (module, stats)
}

struct Build {
    label: String,
    compiler: &'static str,
    opt: &'static str,
    reference_bytes: Vec<u8>,
    reference_named: BTreeMap<String, u64>,
    stripped_module: NirModule,
    stripped_lift: LiftStats,
    target_named: BTreeMap<String, u64>,
    missing_tracked: Vec<&'static str>,
    ambiguous_names: Vec<String>,
}

fn prepare_builds(
    scratch: &Path,
    plans: &[CompilerPlan],
    strip: &str,
    source_path: &Path,
) -> Vec<Build> {
    let mut builds: Vec<Build> = Vec::new();
    for plan in plans {
        for &opt in &plan.opt_levels {
            let tag: String = format!("{}{opt}", plan.compiler);
            let target_path: PathBuf = scratch.join(format!("target-{tag}.exe"));
            let outcome: std::io::Result<Output> =
                run_compiler(plan.compiler, opt, source_path, &target_path);
            assert!(
                outcome
                    .as_ref()
                    .is_ok_and(|output: &Output| output.status.success())
                    && target_path.is_file(),
                "{tag} is in this grade's declared build matrix and the host toolchain accepted the same option in its capability probe, so a failure here is a real defect and not a missing reference: {}",
                compiler_diagnostic(plan.compiler, opt, &outcome)
            );
            let target_bytes: Vec<u8> = std::fs::read(&target_path).expect("read target");
            let target_named: BTreeMap<String, u64> = named_addresses(&target_bytes);
            let ambiguous_names: Vec<String> = ambiguous_definitions(&target_bytes);
            assert!(
                ambiguous_names
                    .iter()
                    .all(|name: &String| !TRACKED_NAMES.contains(&name.as_str())),
                "{tag} defines a tracked name at more than one text address, so its ground truth is ambiguous and must not be graded as a one-to-one pair: {ambiguous_names:?}"
            );
            let missing_tracked: Vec<&'static str> = TRACKED_NAMES
                .iter()
                .filter(|tracked: &&&'static str| !target_named.contains_key(**tracked))
                .copied()
                .collect();
            assert!(
                missing_tracked.len() < TRACKED_NAMES.len(),
                "{tag} exposed none of the tracked symbols, so this build carries no ground truth at all and the grade must fail rather than quietly drop it"
            );
            let stripped_path: PathBuf = scratch.join(format!("{tag}.stripped.exe"));
            assert!(
                strip_copy(strip, &target_path, &stripped_path),
                "real strip must succeed on {tag}"
            );
            let stripped_bytes: Vec<u8> = std::fs::read(&stripped_path).expect("read stripped");
            assert!(
                named_addresses(&stripped_bytes).is_empty(),
                "strip must remove the tracked function symbols for {tag}"
            );
            let (stripped_module, stripped_lift): (NirModule, LiftStats) =
                lift_pcode_module(&stripped_bytes);
            builds.push(Build {
                label: tag,
                compiler: plan.compiler,
                opt,
                reference_bytes: target_bytes,
                reference_named: target_named.clone(),
                stripped_module,
                stripped_lift,
                target_named,
                missing_tracked,
                ambiguous_names,
            });
        }
    }
    builds
}

struct Battery {
    _scratch: ScratchDir,
    directory: PathBuf,
    toolchain: Toolchain,
    plans: Vec<CompilerPlan>,
    builds: Vec<Build>,
}

impl Battery {
    fn primary_builds(&self) -> Vec<&Build> {
        self.builds
            .iter()
            .filter(|build: &&Build| build.compiler == self.toolchain.primary)
            .collect()
    }

    fn build_at(&self, compiler: &str, opt: &str) -> &Build {
        self.builds
            .iter()
            .find(|build: &&Build| build.compiler == compiler && build.opt == opt)
            .unwrap_or_else(|| {
                panic!("the declared matrix must contain the {compiler} {opt} build")
            })
    }

    fn report_matrix(&self) {
        for plan in &self.plans {
            match &plan.lto_refusal {
                None => eprintln!(
                    "matrix {}: {} including {LTO_OPT_LEVEL}",
                    plan.compiler,
                    plan.opt_levels.join(" ")
                ),
                Some(diagnostic) => eprintln!(
                    "matrix {}: {} and this toolchain refused {LTO_OPT_LEVEL}: {diagnostic}",
                    plan.compiler,
                    plan.opt_levels.join(" ")
                ),
            }
        }
        for build in &self.builds {
            eprintln!(
                "build {} lifted={} lower_failed={} oversized={} ground_truth={} ambiguous_dropped={} missing_tracked={:?}",
                build.label,
                build.stripped_lift.lowered,
                build.stripped_lift.lower_failed,
                build.stripped_lift.oversized,
                build.target_named.len(),
                build.ambiguous_names.len(),
                build.missing_tracked
            );
        }
    }
}

fn prepare_battery() -> Option<Battery> {
    let toolchain: Toolchain = require_toolchain()?;
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-semdiff-lineage").expect("create scratch directory");
    let directory: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = directory.join("battery.c");
    std::fs::write(&source_path, BATTERY_SOURCE).expect("write source");
    let plans: Vec<CompilerPlan> = plan_matrix(&toolchain, &directory);
    let planned: usize = plans
        .iter()
        .map(|plan: &CompilerPlan| plan.opt_levels.len())
        .sum();
    let builds: Vec<Build> = prepare_builds(&directory, &plans, toolchain.strip, &source_path);
    assert_eq!(
        builds.len(),
        planned,
        "every planned build must be produced, because a grade over a partial matrix reports a number for a population it did not measure"
    );
    Some(Battery {
        _scratch: scratch,
        directory,
        toolchain,
        plans,
        builds,
    })
}

#[derive(Debug)]
struct CaseResult {
    label: String,
    ground_truth_pairs: usize,
    predicted_pairs: usize,
    true_positive_pairs: usize,
    summary_predicted: usize,
    summary_correct: usize,
    tracked_ground_truth_pairs: usize,
    tracked_true_positive_pairs: usize,
    tracked_summary_names: BTreeSet<String>,
}

fn grade(
    label: &str,
    reference_module: &NirModule,
    reference_named: &BTreeMap<String, u64>,
    target_module: &NirModule,
    target_named: &BTreeMap<String, u64>,
) -> CaseResult {
    let ground_truth: BTreeMap<u64, (u64, String)> = reference_named
        .iter()
        .filter_map(|(name, &reference_address): (&String, &u64)| {
            target_named
                .get(name)
                .map(|&target_address: &u64| (reference_address, (target_address, name.clone())))
        })
        .collect();
    let tracked_ground_truth_pairs: usize = ground_truth
        .values()
        .filter(|(_, name): &&(u64, String)| TRACKED_NAMES.contains(&name.as_str()))
        .count();

    let report: StructuralMatchReport = structural_match(reference_module, target_module);
    let named_reference_addresses: BTreeSet<u64> = reference_named.values().copied().collect();

    let mut predicted_pairs: usize = 0;
    let mut true_positive_pairs: usize = 0;
    let mut summary_predicted: usize = 0;
    let mut summary_correct: usize = 0;
    let mut tracked_true_positive_pairs: usize = 0;
    let mut tracked_summary_names: BTreeSet<String> = BTreeSet::new();
    for pair in &report.matches {
        if !named_reference_addresses.contains(&pair.base_address) {
            continue;
        }
        predicted_pairs += 1;
        let is_summary: bool = pair.tier == MatchTier::SymbolicSummary;
        if is_summary {
            summary_predicted += 1;
        }
        let Some((expected, name)): Option<&(u64, String)> = ground_truth.get(&pair.base_address)
        else {
            continue;
        };
        if *expected != pair.other_address {
            continue;
        }
        true_positive_pairs += 1;
        if is_summary {
            summary_correct += 1;
        }
        if TRACKED_NAMES.contains(&name.as_str()) {
            tracked_true_positive_pairs += 1;
            if is_summary {
                tracked_summary_names.insert(name.clone());
            }
        }
    }

    CaseResult {
        label: label.to_owned(),
        ground_truth_pairs: ground_truth.len(),
        predicted_pairs,
        true_positive_pairs,
        summary_predicted,
        summary_correct,
        tracked_ground_truth_pairs,
        tracked_true_positive_pairs,
        tracked_summary_names,
    }
}

#[test]
fn symbolic_summary_recovers_optimization_variants_without_a_wrong_commit() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    battery.report_matrix();

    let reference: &Build = battery.build_at(battery.toolchain.primary, REFERENCE_OPT_LEVEL);
    let (reference_module, reference_lift): (NirModule, LiftStats) =
        lift_pcode_module(&reference.reference_bytes);
    assert!(
        !reference_module.functions.is_empty(),
        "the reference build must lift to a non-empty p-code module, lift stats {reference_lift:?}"
    );
    eprintln!(
        "reference build {} ({} {}) lifted {} functions with {} named ground-truth symbols",
        reference.label,
        reference.compiler,
        reference.opt,
        reference_lift.lowered,
        reference.reference_named.len()
    );

    let mut results: Vec<CaseResult> = Vec::new();
    for build in &battery.builds {
        results.push(grade(
            &format!("{} -> {}", reference.label, build.label),
            &reference_module,
            &reference.reference_named,
            &build.stripped_module,
            &build.target_named,
        ));
    }

    eprintln!(
        "case,ground_truth,predicted,correct,summary_predicted,summary_correct,tracked_truth,tracked_correct,summary_names"
    );
    let mut total_predicted: usize = 0;
    let mut total_correct: usize = 0;
    let mut total_summary_predicted: usize = 0;
    let mut total_summary_correct: usize = 0;
    for result in &results {
        eprintln!(
            "{},{},{},{},{},{},{},{},{}",
            result.label,
            result.ground_truth_pairs,
            result.predicted_pairs,
            result.true_positive_pairs,
            result.summary_predicted,
            result.summary_correct,
            result.tracked_ground_truth_pairs,
            result.tracked_true_positive_pairs,
            result
                .tracked_summary_names
                .iter()
                .cloned()
                .collect::<Vec<String>>()
                .join("|")
        );
        total_predicted += result.predicted_pairs;
        total_correct += result.true_positive_pairs;
        total_summary_predicted += result.summary_predicted;
        total_summary_correct += result.summary_correct;
        assert_eq!(
            result.summary_correct, result.summary_predicted,
            "the symbolic summary tier committed to a wrong pair for {}: {}/{} correct",
            result.label, result.summary_correct, result.summary_predicted
        );
    }
    eprintln!(
        "aggregate,predicted={total_predicted},correct={total_correct},summary_predicted={total_summary_predicted},summary_correct={total_summary_correct}"
    );

    assert_eq!(
        total_correct, total_predicted,
        "the matcher must commit to no wrong pair across the optimization matrix: {total_correct}/{total_predicted}"
    );
    assert!(
        total_summary_predicted >= MIN_SUMMARY_TIER_COMMITMENTS,
        "the symbolic summary tier must commit to at least {MIN_SUMMARY_TIER_COMMITMENTS} pairs across the declared matrix, a floor measured on this matrix, committed {total_summary_predicted}"
    );

    let lowest_label: String = format!(
        "{} -> {}{LOWEST_OPT_LEVEL}",
        reference.label, battery.toolchain.primary
    );
    let lowest: &CaseResult = results
        .iter()
        .find(|result: &&CaseResult| result.label == lowest_label)
        .unwrap_or_else(|| panic!("the {lowest_label} comparison must run"));
    assert!(
        lowest.tracked_summary_names.len() >= MIN_TRACKED_SUMMARY_NAMES_ACROSS_THE_OPTIMIZATION_GAP,
        "the symbolic summary tier must recover at least {MIN_TRACKED_SUMMARY_NAMES_ACROSS_THE_OPTIMIZATION_GAP} curated functions across the {REFERENCE_OPT_LEVEL} to {LOWEST_OPT_LEVEL} optimization gap, a floor measured on the declared matrix, recovered {:?}",
        lowest.tracked_summary_names
    );
}

#[test]
fn variant_lineage_clusters_one_source_function_across_optimization_levels() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    let primary_builds: Vec<&Build> = battery.primary_builds();
    let planned_primary: usize = battery
        .plans
        .iter()
        .find(|plan: &&CompilerPlan| plan.compiler == battery.toolchain.primary)
        .map_or(0, |plan: &CompilerPlan| plan.opt_levels.len());
    assert_eq!(
        primary_builds.len(),
        planned_primary,
        "the lineage grade must see every optimization level planned for {}",
        battery.toolchain.primary
    );

    let anchor_build: &Build = battery.build_at(battery.toolchain.primary, REFERENCE_OPT_LEVEL);
    let (anchor_module, _anchor_lift): (NirModule, LiftStats) =
        lift_pcode_module(&anchor_build.reference_bytes);
    let variants: Vec<LineageVariant<'_>> = primary_builds
        .iter()
        .map(|build: &&Build| LineageVariant {
            label: build.label.as_str(),
            module: &build.stripped_module,
        })
        .collect();
    let anchor: LineageVariant<'_> = LineageVariant {
        label: anchor_build.label.as_str(),
        module: &anchor_module,
    };
    let report: LineageReport = variant_lineage(&anchor, &variants);
    assert_eq!(report.variant_labels.len(), primary_builds.len());
    assert!(
        report.refused.is_empty(),
        "same-language variants must not refuse"
    );

    let (matched, possible): (usize, usize) = report.membership();
    eprintln!(
        "lineage anchor {} membership {matched}/{possible} across {} variants",
        anchor_build.label,
        primary_builds.len()
    );

    let mut complete_tracked: BTreeSet<String> = BTreeSet::new();
    for tracked in TRACKED_NAMES {
        let Some(&address): Option<&u64> = anchor_build.reference_named.get(*tracked) else {
            continue;
        };
        let Some(family): Option<&VariantFamily> = report.family(address) else {
            continue;
        };
        eprintln!(
            "family {tracked} matched {}/{}",
            family.matched_count(),
            family.members.len()
        );
        for (index, member) in family.members.iter().enumerate() {
            assert_eq!(
                member.is_matched(),
                family.tier_of(index).is_some(),
                "every matched lineage member must record the tier that produced it"
            );
        }
        if family.is_complete() {
            complete_tracked.insert((*tracked).to_owned());
        }
    }
    eprintln!(
        "complete tracked families: {complete_tracked:?} of {} families",
        report.complete_families()
    );
    assert!(
        complete_tracked.len() >= MIN_COMPLETE_TRACKED_FAMILIES,
        "at least {MIN_COMPLETE_TRACKED_FAMILIES} curated functions must cluster as one family across every {} optimization level in the declared matrix, a floor measured over {} variants, complete: {complete_tracked:?}",
        battery.toolchain.primary,
        primary_builds.len()
    );
}

#[test]
fn matching_is_invariant_to_function_order_in_the_module() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    let reference: &Build = battery.build_at(battery.toolchain.primary, REFERENCE_OPT_LEVEL);
    let target: &Build = battery.build_at(battery.toolchain.primary, LOWEST_OPT_LEVEL);
    let (reference_module, _lift): (NirModule, LiftStats) =
        lift_pcode_module(&reference.reference_bytes);
    let baseline: StructuralMatchReport =
        structural_match(&reference_module, &target.stripped_module);

    let mut shuffled: NirModule = target.stripped_module.clone();
    shuffled.functions.reverse();
    let reversed: StructuralMatchReport = structural_match(&reference_module, &shuffled);
    assert_eq!(
        baseline, reversed,
        "reordering the functions in a module must not change the report"
    );

    let mut rotated: NirModule = reference_module;
    if rotated.functions.len() > 2 {
        rotated.functions.rotate_left(1);
    }
    let rotated_report: StructuralMatchReport = structural_match(&rotated, &target.stripped_module);
    assert_eq!(
        baseline, rotated_report,
        "rotating the reference functions must not change the report"
    );
}

#[test]
fn a_cross_architecture_pair_is_refused_with_a_named_reason() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    let build: &Build = battery.build_at(battery.toolchain.primary, REFERENCE_OPT_LEVEL);
    let mut foreign: NirModule = build.stripped_module.clone();
    foreign.lang = SourceLang::NativeArm;
    let report: StructuralMatchReport = structural_match(&build.stripped_module, &foreign);
    assert_eq!(
        report.match_count(),
        0,
        "a cross-architecture pair must not match"
    );
    assert!(
        !report.unmatched_base.is_empty(),
        "a refused cross-architecture pair must still account for every function it declined"
    );
    assert!(
        report
            .unmatched_base
            .iter()
            .all(|&(_, reason): &(u64, Indeterminate)| {
                matches!(
                    reason,
                    Indeterminate::SourceLanguageMismatch {
                        base: SourceLang::NativeX86,
                        other: SourceLang::NativeArm
                    }
                )
            }),
        "every refused function must carry the language mismatch reason"
    );
}

#[test]
fn the_declared_build_matrix_covers_every_optimization_level_it_claims() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    battery.report_matrix();
    let source_path: PathBuf = battery.directory.join("battery.c");
    assert!(
        source_path.is_file(),
        "the battery source must exist on disk so the matrix is reproducible"
    );
    for plan in &battery.plans {
        for level in BASE_OPT_LEVELS {
            assert!(
                plan.opt_levels.contains(&level),
                "{} must build every declared size and speed optimization level, missing {level}",
                plan.compiler
            );
            let build: &Build = battery.build_at(plan.compiler, level);
            assert!(
                !build.stripped_module.functions.is_empty(),
                "{} must lift to a non-empty stripped module, lift stats {:?}",
                build.label,
                build.stripped_lift
            );
        }
        match &plan.lto_refusal {
            None => {
                let build: &Build = battery.build_at(plan.compiler, LTO_OPT_LEVEL);
                assert!(
                    !build.stripped_module.functions.is_empty(),
                    "{} must lift to a non-empty stripped module, lift stats {:?}",
                    build.label,
                    build.stripped_lift
                );
            }
            Some(diagnostic) => assert!(
                !diagnostic.is_empty(),
                "{} declined link-time optimization and must carry the toolchain's own diagnostic as the reason",
                plan.compiler
            ),
        }
    }
}

#[test]
fn a_placeholder_symbol_never_wins_over_the_real_text_address() {
    let Some(battery): Option<Battery> = prepare_battery() else {
        return;
    };
    let mut exercised_builds: usize = 0;
    let mut placeholders_seen: usize = 0;
    for plan in &battery.plans {
        if plan.lto_refusal.is_some() {
            continue;
        }
        let build: &Build = battery.build_at(plan.compiler, LTO_OPT_LEVEL);
        exercised_builds += 1;
        for tracked in TRACKED_NAMES {
            let placeholders: usize = placeholder_definitions(&build.reference_bytes, tracked);
            placeholders_seen += placeholders;
            let Some(&resolved): Option<&u64> = build.target_named.get(*tracked) else {
                continue;
            };
            assert_ne!(
                resolved, 0,
                "{} resolved {tracked} to address zero, so every pair graded against it would be measured against a placeholder rather than the real text address",
                build.label
            );
            let in_text: bool = build
                .stripped_module
                .functions
                .iter()
                .any(|function: &NirFunction| function.address == resolved);
            assert!(
                in_text,
                "{} resolved {tracked} to {resolved:#x}, which is not the address of any lifted function, so the ground truth does not point at real code",
                build.label
            );
        }
    }
    eprintln!(
        "link-time-optimized builds checked for placeholder symbols: {exercised_builds}, zero-address definitions found and rejected: {placeholders_seen}"
    );
    assert!(
        exercised_builds > 0
            || battery
                .plans
                .iter()
                .all(|plan: &CompilerPlan| plan.lto_refusal.is_some()),
        "a link-time-optimized build must either be checked or refused by every compiler in the matrix"
    );
}

#[test]
fn an_absent_toolchain_is_optional_only_when_the_requirement_is_unset_or_falsy() {
    assert!(!toolchain_is_mandatory(None));
    for falsy in ["", "0", "false", "no", "off", "optional", "OFF", "False"] {
        assert!(
            !toolchain_is_mandatory(Some(std::ffi::OsStr::new(falsy))),
            "{falsy} must leave the grade free to announce that it measured nothing"
        );
    }
}

#[test]
fn an_absent_toolchain_is_mandatory_whenever_the_requirement_is_set() {
    for truthy in ["1", "true", "yes", "on", "mandatory", "anything"] {
        assert!(
            toolchain_is_mandatory(Some(std::ffi::OsStr::new(truthy))),
            "{truthy} must turn an unreachable reference into a failure rather than a skip"
        );
    }
}
