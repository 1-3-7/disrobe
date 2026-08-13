#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

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

const MAX_LIFTED_FUNCTIONS: usize = 4096;
const MAX_FUNCTION_BYTES: usize = 8192;

fn available_compilers() -> Vec<&'static str> {
    ["gcc", "clang"]
        .into_iter()
        .filter(|c: &&str| {
            Command::new(c)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
        })
        .collect()
}

fn strip_tool() -> Option<&'static str> {
    ["llvm-strip", "strip"].into_iter().find(|tool: &&str| {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
    })
}

fn compile(compiler: &str, opt: &str, source: &Path, out: &Path) -> bool {
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
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn strip_copy(strip: &str, source: &Path, out: &Path) -> bool {
    std::fs::copy(source, out).is_ok()
        && Command::new(strip)
            .arg(out)
            .status()
            .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn named_addresses(bytes: &[u8]) -> BTreeMap<String, u64> {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return BTreeMap::new();
    };
    file.symbols()
        .filter(|sym: &object::Symbol<'_, '_>| {
            sym.is_definition() && sym.kind() == object::SymbolKind::Text
        })
        .filter_map(|sym: object::Symbol<'_, '_>| {
            let name: &str = sym.name().ok()?;
            let bare: &str = name.trim_start_matches('_');
            if bare.is_empty() {
                return None;
            }
            Some((bare.to_owned(), sym.address()))
        })
        .collect()
}

fn lift_pcode_module(image: &[u8]) -> NirModule {
    let payload = build_disasm_payload(image).expect("disasm payload");
    let mut ordered: Vec<(u64, Vec<u8>)> = payload
        .instructions
        .iter()
        .map(|instruction| (instruction.offset, instruction.bytes.clone()))
        .collect();
    ordered.sort_by_key(|(offset, _): &(u64, Vec<u8>)| *offset);
    let coarse: NirModule = disasm_to_nir(&payload);
    let mut functions: Vec<NirFunction> = Vec::new();
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
        if oversized || bytes.is_empty() {
            continue;
        }
        let Ok(mut lifted): Result<NirFunction, _> =
            lower_x86_64(&bytes, function.address, &function.name)
        else {
            continue;
        };
        lifted.name.clear();
        functions.push(lifted);
    }
    NirModule {
        source_hash: coarse.source_hash,
        lang: SourceLang::NativeX86,
        functions,
        symbols: Vec::new(),
    }
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

struct Build {
    label: String,
    reference_bytes: Vec<u8>,
    reference_named: BTreeMap<String, u64>,
    stripped_module: NirModule,
    target_named: BTreeMap<String, u64>,
}

fn prepare_builds(
    scratch: &Path,
    compilers: &[&str],
    strip: &str,
    source_path: &Path,
) -> Vec<Build> {
    let opt_levels: [&str; 4] = ["-O0", "-O1", "-O2", "-O3"];
    let mut builds: Vec<Build> = Vec::new();
    for &compiler in compilers {
        for &opt in &opt_levels {
            let tag: String = format!("{compiler}{opt}");
            let target_path: PathBuf = scratch.join(format!("target-{tag}.exe"));
            if !compile(compiler, opt, source_path, &target_path) {
                eprintln!("skip {tag}: compile failed");
                continue;
            }
            let target_bytes: Vec<u8> = std::fs::read(&target_path).expect("read target");
            let target_named: BTreeMap<String, u64> = named_addresses(&target_bytes);
            if !TRACKED_NAMES
                .iter()
                .all(|tracked: &&str| target_named.contains_key(*tracked))
            {
                eprintln!("skip {tag}: build does not expose every tracked symbol");
                continue;
            }
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
            builds.push(Build {
                label: tag,
                reference_bytes: target_bytes,
                reference_named: target_named.clone(),
                stripped_module: lift_pcode_module(&stripped_bytes),
                target_named,
            });
        }
    }
    builds
}

fn battery_scratch() -> Option<(ScratchDir, PathBuf, Vec<&'static str>, &'static str)> {
    let compilers: Vec<&str> = available_compilers();
    let Some(strip): Option<&str> = strip_tool() else {
        eprintln!("skipping: no strip tool (llvm-strip/strip) found on PATH");
        return None;
    };
    if compilers.is_empty() {
        eprintln!("skipping: neither gcc nor clang found on PATH");
        return None;
    }
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-semdiff-lineage").expect("create scratch directory");
    let directory: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = directory.join("battery.c");
    std::fs::write(&source_path, BATTERY_SOURCE).expect("write source");
    Some((scratch, directory, compilers, strip))
}

#[test]
fn symbolic_summary_recovers_optimization_variants_without_a_wrong_commit() {
    let Some((_scratch, directory, compilers, strip)) = battery_scratch() else {
        return;
    };
    let source_path: PathBuf = directory.join("battery.c");
    let builds: Vec<Build> = prepare_builds(&directory, &compilers, strip, &source_path);
    assert!(!builds.is_empty(), "at least one build must be prepared");

    let reference: &Build = builds
        .iter()
        .find(|build: &&Build| build.label.ends_with("-O2"))
        .expect("an -O2 reference build must exist");
    let reference_module: NirModule = lift_pcode_module(&reference.reference_bytes);
    assert!(
        !reference_module.functions.is_empty(),
        "the reference build must lift to a non-empty p-code module"
    );

    let mut results: Vec<CaseResult> = Vec::new();
    for build in &builds {
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
        total_summary_predicted > 0,
        "the symbolic summary tier must fire on the real optimization matrix"
    );

    let lowest: &CaseResult = results
        .iter()
        .find(|result: &&CaseResult| result.label.ends_with("gcc-O0"))
        .expect("the gcc -O0 comparison must run");
    assert!(
        lowest.tracked_summary_names.len() >= 4,
        "the symbolic summary tier must recover at least four curated functions across the -O2 to -O0 optimization gap, recovered {:?}",
        lowest.tracked_summary_names
    );
}

#[test]
fn variant_lineage_clusters_one_source_function_across_optimization_levels() {
    let Some((_scratch, directory, compilers, strip)) = battery_scratch() else {
        return;
    };
    let source_path: PathBuf = directory.join("battery.c");
    let builds: Vec<Build> = prepare_builds(&directory, &compilers, strip, &source_path);
    let gcc_builds: Vec<&Build> = builds
        .iter()
        .filter(|build: &&Build| build.label.starts_with("gcc"))
        .collect();
    if gcc_builds.len() < 4 {
        eprintln!("skipping: fewer than four gcc optimization levels built");
        return;
    }

    let anchor_build: &Build = gcc_builds
        .iter()
        .copied()
        .find(|build: &&Build| build.label.ends_with("-O2"))
        .expect("gcc -O2 anchor");
    let anchor_module: NirModule = lift_pcode_module(&anchor_build.reference_bytes);
    let variants: Vec<LineageVariant<'_>> = gcc_builds
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
    assert_eq!(report.variant_labels.len(), gcc_builds.len());
    assert!(
        report.refused.is_empty(),
        "same-language variants must not refuse"
    );

    let (matched, possible): (usize, usize) = report.membership();
    eprintln!("lineage membership {matched}/{possible}");

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
        complete_tracked.len() >= 3,
        "at least three curated functions must cluster as one family across every gcc optimization level, complete: {complete_tracked:?}"
    );
}

#[test]
fn matching_is_invariant_to_function_order_in_the_module() {
    let Some((_scratch, directory, compilers, strip)) = battery_scratch() else {
        return;
    };
    let source_path: PathBuf = directory.join("battery.c");
    let builds: Vec<Build> = prepare_builds(&directory, &compilers, strip, &source_path);
    let Some(reference): Option<&Build> = builds
        .iter()
        .find(|build: &&Build| build.label.ends_with("-O2"))
    else {
        eprintln!("skipping: no -O2 build");
        return;
    };
    let Some(target): Option<&Build> = builds
        .iter()
        .find(|build: &&Build| build.label.ends_with("-O0"))
    else {
        eprintln!("skipping: no -O0 build");
        return;
    };
    let reference_module: NirModule = lift_pcode_module(&reference.reference_bytes);
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
    let Some((_scratch, directory, compilers, strip)) = battery_scratch() else {
        return;
    };
    let source_path: PathBuf = directory.join("battery.c");
    let builds: Vec<Build> = prepare_builds(&directory, &compilers, strip, &source_path);
    let Some(build): Option<&Build> = builds.first() else {
        eprintln!("skipping: no build available");
        return;
    };
    let mut foreign: NirModule = build.stripped_module.clone();
    foreign.lang = SourceLang::NativeArm;
    let report: StructuralMatchReport = structural_match(&build.stripped_module, &foreign);
    assert_eq!(
        report.match_count(),
        0,
        "a cross-architecture pair must not match"
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
