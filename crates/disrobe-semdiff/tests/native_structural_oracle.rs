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

use disrobe_nir::NirModule;
use disrobe_pass_native::disasm_ir::build_disasm_payload;
use disrobe_query::disasm_to_nir;
use disrobe_semdiff::{StructuralMatchReport, structural_match};
use object::{Object as _, ObjectSymbol as _};

const BATTERY_SOURCE: &str = r"
#include <stdint.h>

__attribute__((noinline)) int32_t add_two(int32_t a, int32_t b) { return a + b; }
__attribute__((noinline)) int32_t sub_two(int32_t a, int32_t b) { return a - b; }
__attribute__((noinline)) int32_t mul_two(int32_t a, int32_t b) { return a * b; }
__attribute__((noinline)) int32_t xor_two(int32_t a, int32_t b) { return a ^ b; }
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
__attribute__((noinline)) int32_t parity_loop(int32_t n) {
    int32_t p = 0;
    for (int32_t i = 0; i < n; i++) { if (i & 1) { p ^= i; } else { p += i; } }
    return p;
}
__attribute__((noinline)) int32_t combo_a(int32_t x, int32_t y) {
    return clamp3(add_two(x, y), 0, 1000);
}
__attribute__((noinline)) int32_t combo_b(int32_t x, int32_t y) {
    return sum_loop(sub_two(x, y));
}
__attribute__((noinline)) int32_t combo_c(int32_t x, int32_t y) {
    return parity_loop(xor_two(x, y));
}
__attribute__((noinline)) int32_t top_level(int32_t x, int32_t y) {
    return mul_two(combo_a(x, y), 1) + combo_b(x, y) + combo_c(x, y);
}
int main(int argc, char **argv) {
    (void)argv;
    int32_t x = argc * 7;
    int32_t y = argc * 3 + 11;
    return top_level(x, y) & 0xff;
}
";

const TRACKED_NAMES: &[&str] = &[
    "add_two",
    "sub_two",
    "mul_two",
    "xor_two",
    "clamp3",
    "sum_loop",
    "parity_loop",
    "combo_a",
    "combo_b",
    "combo_c",
    "top_level",
];

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

fn scratch_dir() -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-semdiff-structural-oracle-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn compile(compiler: &str, opt: &str, source: &Path, out: &Path) -> bool {
    let target_args: Vec<&str> = if compiler == "clang" {
        vec!["-target", "x86_64-w64-mingw32"]
    } else {
        Vec::new()
    };
    let status = Command::new(compiler)
        .args(&target_args)
        .args([opt, "-g", "-o"])
        .arg(out)
        .arg(source)
        .status();
    status.is_ok_and(|s: std::process::ExitStatus| s.success())
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

fn anonymized(mut module: NirModule) -> NirModule {
    for function in &mut module.functions {
        function.name.clear();
    }
    module.symbols.clear();
    module
}

fn lift(bytes: &[u8]) -> NirModule {
    let payload = build_disasm_payload(bytes).expect("disasm payload");
    anonymized(disasm_to_nir(&payload))
}

struct CaseResult {
    label: String,
    ground_truth_pairs: usize,
    predicted_pairs: usize,
    true_positive_pairs: usize,
    tracked_ground_truth_pairs: usize,
    tracked_true_positive_pairs: usize,
}

impl CaseResult {
    fn precision(&self) -> f64 {
        if self.predicted_pairs == 0 {
            return 1.0;
        }
        self.true_positive_pairs as f64 / self.predicted_pairs as f64
    }

    fn recall(&self) -> f64 {
        if self.ground_truth_pairs == 0 {
            return 1.0;
        }
        self.true_positive_pairs as f64 / self.ground_truth_pairs as f64
    }

    fn tracked_recall(&self) -> f64 {
        if self.tracked_ground_truth_pairs == 0 {
            return 1.0;
        }
        self.tracked_true_positive_pairs as f64 / self.tracked_ground_truth_pairs as f64
    }
}

fn grade_pair(
    label: &str,
    ref_bytes: &[u8],
    ref_named: &BTreeMap<String, u64>,
    target_bytes: &[u8],
    target_named: &BTreeMap<String, u64>,
    strip: &str,
    scratch: &Path,
    tag: &str,
) -> CaseResult {
    let stripped_path: PathBuf = scratch.join(format!("{tag}.stripped.exe"));
    std::fs::write(scratch.join(format!("{tag}.target.exe")), target_bytes).expect("write target");
    assert!(
        strip_copy(
            strip,
            &scratch.join(format!("{tag}.target.exe")),
            &stripped_path
        ),
        "real strip must succeed on {tag}"
    );
    let stripped_bytes: Vec<u8> = std::fs::read(&stripped_path).expect("read stripped");
    assert!(
        named_addresses(&stripped_bytes).is_empty(),
        "strip must genuinely remove the tracked function symbols for {tag}"
    );

    let ref_module: NirModule = lift(ref_bytes);
    let stripped_module: NirModule = lift(&stripped_bytes);

    let ground_truth: BTreeMap<u64, (u64, &str)> = ref_named
        .iter()
        .filter_map(|(name, &ref_addr): (&String, &u64)| {
            target_named
                .get(name)
                .map(|&target_addr: &u64| (ref_addr, (target_addr, name.as_str())))
        })
        .collect();
    let tracked_ground_truth_pairs: usize = ground_truth
        .values()
        .filter(|&&(_, name): &&(u64, &str)| TRACKED_NAMES.contains(&name))
        .count();

    let report: StructuralMatchReport = structural_match(&ref_module, &stripped_module);
    let all_named_ref_addresses: BTreeSet<u64> = ref_named.values().copied().collect();

    let mut predicted_pairs: usize = 0;
    let mut true_positive_pairs: usize = 0;
    let mut tracked_true_positive_pairs: usize = 0;
    for pair in &report.matches {
        if !all_named_ref_addresses.contains(&pair.base_address) {
            continue;
        }
        predicted_pairs += 1;
        if let Some(&(expected, name)) = ground_truth.get(&pair.base_address)
            && expected == pair.other_address
        {
            true_positive_pairs += 1;
            if TRACKED_NAMES.contains(&name) {
                tracked_true_positive_pairs += 1;
            }
        }
    }

    CaseResult {
        label: label.to_owned(),
        ground_truth_pairs: ground_truth.len(),
        predicted_pairs,
        true_positive_pairs,
        tracked_ground_truth_pairs,
        tracked_true_positive_pairs,
    }
}

#[test]
fn stripped_vs_symbolized_reference_matches_are_structurally_grounded() {
    let compilers: Vec<&str> = available_compilers();
    let Some(strip): Option<&str> = strip_tool() else {
        eprintln!("skipping: no strip tool (llvm-strip/strip) found on PATH");
        return;
    };
    if compilers.is_empty() {
        eprintln!("skipping: neither gcc nor clang found on PATH");
        return;
    }

    let scratch: PathBuf = scratch_dir();
    let source_path: PathBuf = scratch.join("battery.c");
    std::fs::write(&source_path, BATTERY_SOURCE).expect("write source");

    let opt_levels: [&str; 4] = ["-O0", "-O1", "-O2", "-O3"];
    let reference_compiler: &str = compilers[0];
    let reference_opt: &str = "-O2";
    let reference_path: PathBuf = scratch.join("reference.exe");
    assert!(
        compile(
            reference_compiler,
            reference_opt,
            &source_path,
            &reference_path
        ),
        "reference compile must succeed"
    );
    let reference_bytes: Vec<u8> = std::fs::read(&reference_path).expect("read reference");
    let reference_named: BTreeMap<String, u64> = named_addresses(&reference_bytes);
    assert!(
        TRACKED_NAMES
            .iter()
            .all(|tracked: &&str| reference_named.contains_key(*tracked)),
        "reference build must expose every tracked symbol"
    );
    assert!(
        reference_named.len() >= TRACKED_NAMES.len(),
        "reference build must expose every tracked symbol plus whatever else the compiler names"
    );

    let mut results: Vec<CaseResult> = Vec::new();
    for &compiler in &compilers {
        for &opt in &opt_levels {
            let tag: String = format!("{compiler}-{opt}");
            let target_path: PathBuf = scratch.join(format!("target-{tag}.exe"));
            if !compile(compiler, opt, &source_path, &target_path) {
                eprintln!("skip {tag}: compile failed");
                continue;
            }
            let target_bytes: Vec<u8> = std::fs::read(&target_path).expect("read target");
            let target_named: BTreeMap<String, u64> = named_addresses(&target_bytes);
            let result: CaseResult = grade_pair(
                &format!("{reference_compiler}{reference_opt} -> {tag}"),
                &reference_bytes,
                &reference_named,
                &target_bytes,
                &target_named,
                strip,
                &scratch,
                &tag,
            );
            results.push(result);
        }
    }

    assert!(!results.is_empty(), "at least one comparison must run");

    eprintln!(
        "case,ground_truth_pairs,predicted_pairs,true_positive_pairs,precision,recall,tracked_recall"
    );
    let mut total_ground_truth: usize = 0;
    let mut total_predicted: usize = 0;
    let mut total_true_positive: usize = 0;
    for result in &results {
        eprintln!(
            "{},{},{},{},{:.3},{:.3},{:.3}",
            result.label,
            result.ground_truth_pairs,
            result.predicted_pairs,
            result.true_positive_pairs,
            result.precision(),
            result.recall(),
            result.tracked_recall()
        );
        total_ground_truth += result.ground_truth_pairs;
        total_predicted += result.predicted_pairs;
        total_true_positive += result.true_positive_pairs;
        assert!(
            result.precision() >= 0.9,
            "structural matcher committed to a wrong pair for {}: precision {:.3}",
            result.label,
            result.precision()
        );
    }
    let aggregate_precision: f64 = if total_predicted == 0 {
        1.0
    } else {
        total_true_positive as f64 / total_predicted as f64
    };
    let aggregate_recall: f64 = if total_ground_truth == 0 {
        1.0
    } else {
        total_true_positive as f64 / total_ground_truth as f64
    };
    eprintln!(
        "aggregate,{total_ground_truth},{total_predicted},{total_true_positive},{aggregate_precision:.3},{aggregate_recall:.3}"
    );
    assert!(
        aggregate_precision >= 0.9,
        "aggregate precision must stay high even as recall falls off with codegen divergence: {aggregate_precision:.3}"
    );

    let same_compiler_same_opt: &CaseResult = results
        .iter()
        .find(|r: &&CaseResult| {
            r.label.ends_with(reference_opt) && r.label.starts_with(reference_compiler)
        })
        .expect("same-compiler same-optimization-level case must exist");
    assert!(
        same_compiler_same_opt.tracked_recall() >= 0.9,
        "identical compiler and optimization level must recover almost every curated battery function: tracked recall {:.3}",
        same_compiler_same_opt.tracked_recall()
    );
}
