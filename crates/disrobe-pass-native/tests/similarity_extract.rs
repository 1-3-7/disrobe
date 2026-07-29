#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind};
use disrobe_pass_native::{
    Arch, Error, FunctionSpan, build_disasm_payload, extract_function_features, function_spans,
    image_arch,
};
use disrobe_similarity::{
    CallRelation, DataReference, FunctionFeatures, FunctionId, MatchReport, Verdict,
    match_functions,
};
use tempfile::TempDir;

const PROBE_SOURCE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static unsigned long long mix64(unsigned long long v) {
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 29;
    v *= 0xc4ceb9fe1a85ec53ULL;
    v ^= v >> 32;
    return v;
}

__attribute__((noinline)) static unsigned int fnv1a(const char *s) {
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

__attribute__((noinline)) static int parse_header(const char *buf, int len) {
    if (len < 4) {
        fputs("header truncated below four bytes\n", stderr);
        return -1;
    }
    if (memcmp(buf, "DRB1", 4) != 0) {
        fputs("header magic mismatch, expected DRB1\n", stderr);
        return -2;
    }
    return 0;
}

__attribute__((noinline)) static int checksum_block(const unsigned char *p, int n) {
    unsigned int acc = 305419896u;
    for (int i = 0; i < n; i++) {
        acc = (acc << 7) ^ (acc >> 25) ^ p[i];
    }
    if (acc == 3735928559u) {
        fputs("checksum landed on the poison value\n", stderr);
    }
    return (int)acc;
}

__attribute__((noinline)) static void report_stats(int blocks, int bytes) {
    printf("processed %d blocks totalling %d bytes\n", blocks, bytes);
    if (blocks > 1234567) {
        printf("block ceiling exceeded, truncating the report\n");
    }
}

__attribute__((noinline)) static char *duplicate_tag(const char *tag) {
    size_t n = strlen(tag) + 1;
    char *out = (char *)malloc(n);
    if (out == NULL) {
        fputs("allocation for the tag copy failed\n", stderr);
        return NULL;
    }
    memcpy(out, tag, n);
    return out;
}

int main(int argc, char **argv) {
    const char *tag = argc > 1 ? argv[1] : "default-tag-value";
    char *copy = duplicate_tag(tag);
    if (copy == NULL) {
        return 1;
    }
    if (parse_header("DRB1zzzz", 8) != 0) {
        free(copy);
        return 2;
    }
    int sum = checksum_block((const unsigned char *)copy, (int)strlen(copy));
    unsigned long long m = mix64((unsigned long long)sum);
    unsigned int h = fnv1a(copy);
    report_stats(sum & 7, (int)strlen(copy));
    printf("tag=%s hash=%08x mix=%016llx\n", copy, h, m);
    free(copy);
    return 0;
}
"#;

const FREESTANDING_SOURCE: &str = r#"
typedef unsigned long long u64;
typedef unsigned int u32;

__attribute__((noinline)) static long sys_write(int fd, const char *buf, u64 len) {
    register long x8 __asm__("x8") = 64;
    register long x0 __asm__("x0") = fd;
    register const char *x1 __asm__("x1") = buf;
    register u64 x2 __asm__("x2") = len;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

__attribute__((noinline)) static u64 measure(const char *s) {
    u64 n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

__attribute__((noinline)) static void emit_banner(void) {
    const char *msg = "disrobe similarity probe banner\n";
    sys_write(1, msg, measure(msg));
}

__attribute__((noinline)) static void emit_failure(void) {
    const char *msg = "the requested block could not be decoded\n";
    sys_write(2, msg, measure(msg));
}

__attribute__((noinline)) static void emit_summary(u64 value) {
    const char *msg = "summary record written to the trace sink\n";
    if (value == 3735928559ULL) {
        sys_write(2, msg, measure(msg));
    }
}

__attribute__((noinline)) static u64 mix64(u64 v) {
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 29;
    v *= 0xc4ceb9fe1a85ec53ULL;
    v ^= v >> 32;
    return v;
}

__attribute__((noinline)) static u32 fnv1a(const char *s) {
    u32 h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

__attribute__((noinline)) static u32 checksum(const unsigned char *p, u64 n) {
    u32 acc = 305419896u;
    for (u64 i = 0; i < n; i++) {
        acc = (acc << 7) ^ (acc >> 25) ^ p[i];
    }
    return acc;
}

void _start(void) {
    const char *tag = "constant-tag-for-the-probe";
    emit_banner();
    u64 h = mix64(fnv1a(tag));
    u32 c = checksum((const unsigned char *)tag, measure(tag));
    if ((h ^ c) == 0) {
        emit_failure();
    }
    emit_summary(h);
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
}
"#;

const AARCH64_DYNAMIC_EXPORT_SOURCE: &str = r#"
typedef unsigned long long u64;

volatile u64 sink;

__attribute__((noinline)) static u64 internal_mix(u64 value) {
    value ^= value >> 17;
    value *= 0x9e3779b97f4a7c15ULL;
    return value ^ (value >> 29);
}

__attribute__((visibility("default"))) void _start(void) {
    sink = internal_mix(7);
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    for (;;) {
    }
}
"#;

const REFERENCE_FREE_SOURCE: &str = r"
typedef unsigned int u32;

__attribute__((noinline)) static u32 rotate_mix(u32 x, int rounds) {
    u32 acc = x;
    for (int i = 0; i < rounds; i++) {
        acc = (acc << 5) | (acc >> 27);
        acc ^= (u32)i;
    }
    return acc;
}

__attribute__((noinline)) static int count_bits(u32 v) {
    int n = 0;
    while (v != 0) {
        if (v & 1u) {
            n++;
        }
        v >>= 1;
    }
    return n;
}

__attribute__((noinline)) static int clamp_scale(int v, int lo, int hi) {
    int scaled = v * 2;
    if (scaled < lo) {
        scaled = lo;
    }
    if (scaled > hi) {
        scaled = hi;
    }
    return scaled + 3;
}

__attribute__((noinline)) static u32 alternating_sum(const int *values, int count) {
    u32 total = 0;
    for (int i = 0; i < count; i++) {
        if ((i & 1) == 0) {
            total += (u32)values[i];
        } else {
            total -= (u32)values[i];
        }
    }
    return total;
}
";

const VERSION_ONE_TAIL: &str = r"
__attribute__((noinline)) static int classify(int v) {
    if (v < 10) {
        return v + 1;
    }
    if (v < 40) {
        return v * 3;
    }
    if (v < 90) {
        return v - 7;
    }
    return v >> 1;
}

int main(int argc, char **argv) {
    (void)argv;
    int seed = argc;
    int values[8];
    for (int i = 0; i < 8; i++) {
        values[i] = seed + i;
    }
    int a = classify(seed * 7);
    u32 b = rotate_mix((u32)seed, 6);
    int c = count_bits(b);
    int d = clamp_scale(a, 2, 60);
    u32 e = alternating_sum(values, 8);
    return (int)((u32)(a + c + d) ^ b ^ e);
}
";

const VERSION_TWO_TAIL: &str = r"
__attribute__((noinline)) static int classify(int v) {
    if (v < 12) {
        return v + 1;
    }
    if (v < 44) {
        return v * 3;
    }
    if (v < 96) {
        return v - 7;
    }
    return v >> 1;
}

__attribute__((noinline)) static int checksum_pairs(const int *values, int count) {
    int acc = 0;
    for (int i = 0; i + 1 < count; i += 2) {
        acc += values[i] * 3 - values[i + 1];
    }
    return acc;
}

int main(int argc, char **argv) {
    (void)argv;
    int seed = argc;
    int values[8];
    for (int i = 0; i < 8; i++) {
        values[i] = seed + i;
    }
    int a = classify(seed * 7);
    u32 b = rotate_mix((u32)seed, 6);
    int c = count_bits(b);
    int d = clamp_scale(a, 2, 60);
    u32 e = alternating_sum(values, 8);
    int f = checksum_pairs(values, 8);
    return (int)((u32)(a + c + d + f) ^ b ^ e);
}
";

fn fixture(name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read(path).ok()
}

fn tool(name: &str) -> Option<PathBuf> {
    Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .filter(|out: &std::process::Output| out.status.success())
        .map(|_| PathBuf::from(name))
}

fn host_c_compiler() -> Option<PathBuf> {
    ["gcc", "clang", "cc"]
        .into_iter()
        .find_map(|candidate: &str| tool(candidate))
}

fn run(command: &mut Command) -> bool {
    command
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success())
}

fn compile(compiler: &Path, source: &Path, output: &Path, flags: &[&str]) -> Option<Vec<u8>> {
    let mut command: Command = Command::new(compiler);
    command.args(flags).arg("-o").arg(output).arg(source);
    if !run(&mut command) {
        return None;
    }
    std::fs::read(output).ok()
}

fn stripped_copy(source: &Path, output: &Path) -> Option<Vec<u8>> {
    for name in ["llvm-strip", "strip"] {
        let Some(stripper): Option<PathBuf> = tool(name) else {
            continue;
        };
        std::fs::copy(source, output).ok()?;
        if run(Command::new(stripper).arg("-s").arg(output)) {
            let bytes: Option<Vec<u8>> = std::fs::read(output).ok();
            if bytes.is_some() {
                return bytes;
            }
        }
    }
    None
}

struct Side {
    names: BTreeMap<u64, String>,
    shapes: BTreeMap<u64, Vec<String>>,
}

impl Side {
    fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

fn side(bytes: &[u8]) -> Side {
    let (Ok(payload), Some(arch)): (Result<DisasmPayload, Error>, Option<Arch>) =
        (build_disasm_payload(bytes), image_arch(bytes))
    else {
        return Side {
            names: BTreeMap::new(),
            shapes: BTreeMap::new(),
        };
    };
    let mut sorted: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
    sorted.sort_by_key(|insn: &&DisasmInstruction| insn.offset);
    let spans: Vec<FunctionSpan> = function_spans(&payload, arch);
    let names: BTreeMap<u64, String> = spans
        .iter()
        .map(|span: &FunctionSpan| (span.address, span.name.clone()))
        .collect();
    let shapes: BTreeMap<u64, Vec<String>> = spans
        .iter()
        .map(|span: &FunctionSpan| {
            let low: usize =
                sorted.partition_point(|insn: &&DisasmInstruction| insn.offset < span.address);
            let high: usize =
                sorted.partition_point(|insn: &&DisasmInstruction| insn.offset < span.end);
            let shape: Vec<String> = sorted
                .get(low..high)
                .unwrap_or_default()
                .iter()
                .map(|insn: &&DisasmInstruction| insn.mnemonic.clone())
                .collect();
            (span.address, shape)
        })
        .collect();
    Side { names, shapes }
}

fn anchored(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| entry.has_anchor())
        .count()
}

fn structured(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| entry.structure().is_some())
        .count()
}

fn keyed(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| entry.structural_key().is_some())
        .count()
}

fn corroborable(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| entry.corroborating_key().is_some())
        .count()
}

fn call_edges(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .map(|entry: &FunctionFeatures| entry.call_targets().len())
        .sum()
}

struct Verification {
    agreed: usize,
    disagreed: Vec<(String, String)>,
    unnamed: usize,
    recompiled: usize,
}

struct PairGrade {
    exact: Verification,
    structural: Verification,
    propagated: Verification,
}

fn verify_against_symbols(
    pairs: &[(FunctionId, FunctionId)],
    left: &Side,
    right: &Side,
) -> Verification {
    let mut agreed: usize = 0;
    let mut disagreed: Vec<(String, String)> = Vec::new();
    let mut unnamed: usize = 0;
    let mut recompiled: usize = 0;
    for (a, b) in pairs.iter().copied() {
        let (a, b): (FunctionId, FunctionId) = (a, b);
        if left.shapes.get(&a.0) != right.shapes.get(&b.0) {
            recompiled += 1;
        }
        match (left.names.get(&a.0), right.names.get(&b.0)) {
            (Some(name_a), Some(name_b)) => {
                if name_a == name_b {
                    agreed += 1;
                } else {
                    disagreed.push((name_a.clone(), name_b.clone()));
                }
            }
            _ => unnamed += 1,
        }
    }
    Verification {
        agreed,
        disagreed,
        unnamed,
        recompiled,
    }
}

fn describe(label: &str, features: &[FunctionFeatures]) {
    let mut strings: usize = 0;
    let mut constants: usize = 0;
    let mut imports: usize = 0;
    for entry in features {
        for reference in entry.references() {
            match reference {
                DataReference::StringLiteral(_) => strings += 1,
                DataReference::UnusualConstant(_) => constants += 1,
                DataReference::ImportedCall(_) => imports += 1,
            }
        }
    }
    println!(
        "{label}: {} functions, {} carrying an anchor, {} carrying a structure, {} carrying a distinguishing structural key, {} carrying a corroborating key, {} resolved call edges, references {strings} string / {constants} constant / {imports} import",
        features.len(),
        anchored(features),
        structured(features),
        keyed(features),
        corroborable(features),
        call_edges(features)
    );
}

fn self_match_count(features: &[FunctionFeatures]) -> usize {
    let report: MatchReport = match_functions(features, features);
    for (a, b) in report.matched_pairs() {
        assert_eq!(
            a, b,
            "an image matched against itself must map every function to its own address"
        );
    }
    report.matched_count()
}

fn graded_pair(
    label: &str,
    left: &[FunctionFeatures],
    right: &[FunctionFeatures],
    left_side: &Side,
    right_side: &Side,
) -> PairGrade {
    let report: MatchReport = match_functions(left, right);
    let exact: Verification = verify_against_symbols(&report.exact_pairs(), left_side, right_side);
    let structural: Verification =
        verify_against_symbols(&report.structural_pairs(), left_side, right_side);
    let propagated: Verification =
        verify_against_symbols(&report.propagated_pairs(), left_side, right_side);
    report_stage(label, "data-reference", report.exact_count(), &exact);
    report_stage(
        label,
        "control-flow",
        report.structural_count(),
        &structural,
    );
    report_stage(label, "propagation", report.propagated_count(), &propagated);
    report_hops(label, &report);
    PairGrade {
        exact,
        structural,
        propagated,
    }
}

fn report_hops(label: &str, report: &MatchReport) {
    let mut hops: BTreeMap<u32, usize> = BTreeMap::new();
    let mut relations: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &report.left {
        let Verdict::Propagated {
            hops: distance,
            relation,
            ..
        } = entry.verdict
        else {
            continue;
        };
        *hops.entry(distance).or_default() += 1;
        let named: &str = match relation {
            CallRelation::Callee => "callee",
            CallRelation::Caller => "caller",
        };
        *relations.entry(named).or_default() += 1;
    }
    if hops.is_empty() {
        return;
    }
    let spread: Vec<String> = hops
        .iter()
        .map(|(distance, count): (&u32, &usize)| format!("{count} at {distance} hop"))
        .collect();
    let over: Vec<String> = relations
        .iter()
        .map(|(named, count): (&&str, &usize)| format!("{count} over a {named}"))
        .collect();
    println!(
        "{label} [propagation]: {}, {}",
        spread.join(", "),
        over.join(", ")
    );
}

fn report_stage(label: &str, stage: &str, pairs: usize, verification: &Verification) {
    println!(
        "{label} [{stage}]: {pairs} pairs, {} verified by symbol name, {} unverifiable, {} disagreements, {} over two different instruction sequences",
        verification.agreed,
        verification.unnamed,
        verification.disagreed.len(),
        verification.recompiled
    );
    for (name_a, name_b) in &verification.disagreed {
        println!("  {stage} disagreement: {name_a} paired with {name_b}");
    }
}

#[test]
fn a_real_shared_object_yields_only_references_that_exist_in_its_bytes() {
    let Some(image): Option<Vec<u8>> = fixture("cxx_hierarchy_itanium.so") else {
        eprintln!("skipping: cxx_hierarchy_itanium.so fixture absent");
        return;
    };
    let features: Vec<FunctionFeatures> = extract_function_features(&image).expect("real ELF");
    describe("cxx_hierarchy_itanium.so", &features);
    assert!(
        !features.is_empty(),
        "a real g++ built shared object must expose functions"
    );

    let mut strings: usize = 0;
    let mut imports: usize = 0;
    for entry in &features {
        for reference in entry.references() {
            match reference {
                DataReference::StringLiteral(value) => {
                    strings += 1;
                    assert!(
                        image
                            .windows(value.len())
                            .any(|window: &[u8]| window == value.as_bytes()),
                        "reported string {value:?} is not present in the image bytes"
                    );
                }
                DataReference::ImportedCall(name) => {
                    imports += 1;
                    assert!(
                        image
                            .windows(name.len())
                            .any(|window: &[u8]| window == name.as_bytes()),
                        "reported import {name:?} is not present in the image bytes"
                    );
                }
                DataReference::UnusualConstant(_) => {}
            }
        }
    }
    println!("cxx_hierarchy_itanium.so: {strings} string refs, {imports} import refs");
}

#[test]
fn extraction_is_deterministic_and_a_binary_matches_itself() {
    let Some(image): Option<Vec<u8>> = fixture("cxx_hierarchy_itanium.so") else {
        eprintln!("skipping: cxx_hierarchy_itanium.so fixture absent");
        return;
    };
    let first: Vec<FunctionFeatures> = extract_function_features(&image).expect("first pass");
    let second: Vec<FunctionFeatures> = extract_function_features(&image).expect("second pass");
    assert_eq!(first, second, "extraction must be deterministic");
    println!(
        "self match: {} of {} functions paired",
        self_match_count(&first),
        first.len()
    );
}

#[test]
fn a_truncated_real_binary_is_refused_without_panicking() {
    let Some(image): Option<Vec<u8>> = fixture("cxx_hierarchy_itanium.so") else {
        eprintln!("skipping: cxx_hierarchy_itanium.so fixture absent");
        return;
    };
    let mut refused: usize = 0;
    let mut accepted: usize = 0;
    for keep in (0..image.len()).step_by(97) {
        match extract_function_features(&image[..keep]) {
            Ok(_) => accepted += 1,
            Err(_) => refused += 1,
        }
    }
    println!("truncation sweep: {refused} refused, {accepted} still parsed");
    assert!(refused > 0, "a header-length prefix cannot be extractable");
}

#[test]
fn a_two_optimization_level_pair_matches_functions_across_stripped_images() {
    let Some(compiler): Option<PathBuf> = host_c_compiler() else {
        eprintln!("skipping: no host C compiler on PATH");
        return;
    };
    let scratch: TempDir = TempDir::new().expect("scratch directory");
    let source: PathBuf = scratch.path().join("probe.c");
    std::fs::write(&source, PROBE_SOURCE).expect("write probe source");

    let low_path: PathBuf = scratch.path().join("probe_o0.exe");
    let high_path: PathBuf = scratch.path().join("probe_o2.exe");
    let (Some(low), Some(high)): (Option<Vec<u8>>, Option<Vec<u8>>) = (
        compile(&compiler, &source, &low_path, &["-O0"]),
        compile(&compiler, &source, &high_path, &["-O2"]),
    ) else {
        eprintln!("skipping: host C compiler cannot link a hosted executable");
        return;
    };

    let low_side: Side = side(&low);
    let high_side: Side = side(&high);
    assert!(
        !low_side.is_empty() && !high_side.is_empty(),
        "the unstripped builds must carry symbols to grade against"
    );

    let low_stripped: Vec<u8> = stripped_copy(&low_path, &scratch.path().join("probe_o0.strip"))
        .unwrap_or_else(|| low.clone());
    let high_stripped: Vec<u8> = stripped_copy(&high_path, &scratch.path().join("probe_o2.strip"))
        .unwrap_or_else(|| high.clone());

    let left: Vec<FunctionFeatures> = extract_function_features(&low_stripped).expect("O0 extract");
    let right: Vec<FunctionFeatures> =
        extract_function_features(&high_stripped).expect("O2 extract");
    describe("O0 stripped", &left);
    describe("O2 stripped", &right);
    println!(
        "self match: O0 {} of {}, O2 {} of {}",
        self_match_count(&left),
        left.len(),
        self_match_count(&right),
        right.len()
    );

    let symbol_left: Vec<FunctionFeatures> =
        extract_function_features(&low).expect("O0 symbol extract");
    let symbol_right: Vec<FunctionFeatures> =
        extract_function_features(&high).expect("O2 symbol extract");
    describe("O0 with symbols", &symbol_left);
    describe("O2 with symbols", &symbol_right);
    graded_pair(
        "O0 vs O2 with symbols",
        &symbol_left,
        &symbol_right,
        &low_side,
        &high_side,
    );

    let grade: PairGrade = graded_pair("O0 vs O2 stripped", &left, &right, &low_side, &high_side);
    assert!(
        grade.exact.disagreed.is_empty(),
        "every symbol-named pair must name the same function on both sides"
    );
    assert!(
        grade.structural.disagreed.is_empty(),
        "a structural pair that names two different functions is a wrong match"
    );
    assert!(
        grade.propagated.disagreed.is_empty(),
        "a propagated pair that names two different functions is a wrong match"
    );
    assert!(
        grade.exact.agreed > 0,
        "the pair must anchor at least one function through its data references"
    );
}

#[test]
fn two_adjacent_versions_at_one_optimization_level_grade_the_structural_stage() {
    let Some(compiler): Option<PathBuf> = host_c_compiler() else {
        eprintln!("skipping: no host C compiler on PATH");
        return;
    };
    let scratch: TempDir = TempDir::new().expect("scratch directory");
    let one_source: PathBuf = scratch.path().join("version_one.c");
    let two_source: PathBuf = scratch.path().join("version_two.c");
    std::fs::write(
        &one_source,
        format!("{REFERENCE_FREE_SOURCE}{VERSION_ONE_TAIL}"),
    )
    .expect("write version one");
    std::fs::write(
        &two_source,
        format!("{REFERENCE_FREE_SOURCE}{VERSION_TWO_TAIL}"),
    )
    .expect("write version two");

    let one_path: PathBuf = scratch.path().join("version_one.exe");
    let two_path: PathBuf = scratch.path().join("version_two.exe");
    let (Some(one), Some(two)): (Option<Vec<u8>>, Option<Vec<u8>>) = (
        compile(&compiler, &one_source, &one_path, &["-O2"]),
        compile(&compiler, &two_source, &two_path, &["-O2"]),
    ) else {
        eprintln!("skipping: host C compiler cannot link a hosted executable");
        return;
    };

    let one_side: Side = side(&one);
    let two_side: Side = side(&two);
    assert!(
        !one_side.is_empty() && !two_side.is_empty(),
        "the unstripped builds must carry symbols to grade against"
    );

    let left: Vec<FunctionFeatures> = extract_function_features(&one).expect("version one extract");
    let right: Vec<FunctionFeatures> =
        extract_function_features(&two).expect("version two extract");
    describe("adjacent versions: v1 -O2 with symbols", &left);
    describe("adjacent versions: v2 -O2 with symbols", &right);
    let grade: PairGrade = graded_pair(
        "adjacent versions: v1 vs v2 -O2 with symbols",
        &left,
        &right,
        &one_side,
        &two_side,
    );
    assert!(
        grade.exact.disagreed.is_empty(),
        "every symbol-named pair must name the same function on both sides"
    );
    assert!(
        grade.structural.disagreed.is_empty(),
        "a structural pair that names two different functions is a wrong match"
    );
    assert!(
        grade.propagated.disagreed.is_empty(),
        "a propagated pair that names two different functions is a wrong match"
    );

    let one_stripped: Vec<u8> = stripped_copy(&one_path, &scratch.path().join("version_one.strip"))
        .unwrap_or_else(|| one.clone());
    let two_stripped: Vec<u8> = stripped_copy(&two_path, &scratch.path().join("version_two.strip"))
        .unwrap_or_else(|| two.clone());
    let left: Vec<FunctionFeatures> =
        extract_function_features(&one_stripped).expect("version one stripped extract");
    let right: Vec<FunctionFeatures> =
        extract_function_features(&two_stripped).expect("version two stripped extract");
    describe("adjacent versions: v1 -O2 stripped", &left);
    describe("adjacent versions: v2 -O2 stripped", &right);
    let stripped_grade: PairGrade = graded_pair(
        "adjacent versions: v1 vs v2 -O2 stripped",
        &left,
        &right,
        &one_side,
        &two_side,
    );
    assert!(
        stripped_grade.exact.disagreed.is_empty(),
        "every symbol-named pair must name the same function on both sides"
    );
    assert!(
        stripped_grade.structural.disagreed.is_empty(),
        "a structural pair that names two different functions is a wrong match"
    );
    assert!(
        stripped_grade.propagated.disagreed.is_empty(),
        "a propagated pair that names two different functions is a wrong match"
    );
}

#[test]
fn an_aarch64_pair_matches_functions_through_adrp_pairs_and_wide_moves() {
    let Some(compiler): Option<PathBuf> = tool("clang") else {
        eprintln!("skipping: clang absent, no aarch64 cross build");
        return;
    };
    let scratch: TempDir = TempDir::new().expect("scratch directory");
    let source: PathBuf = scratch.path().join("free.c");
    std::fs::write(&source, FREESTANDING_SOURCE).expect("write freestanding source");

    let flags: [&str; 5] = [
        "-target",
        "aarch64-unknown-linux-gnu",
        "-nostdlib",
        "-ffreestanding",
        "-fuse-ld=lld",
    ];
    let mut low_flags: Vec<&str> = flags.to_vec();
    low_flags.push("-O0");
    let mut high_flags: Vec<&str> = flags.to_vec();
    high_flags.push("-O2");

    let (Some(low), Some(high)): (Option<Vec<u8>>, Option<Vec<u8>>) = (
        compile(
            &compiler,
            &source,
            &scratch.path().join("free_o0.elf"),
            &low_flags,
        ),
        compile(
            &compiler,
            &source,
            &scratch.path().join("free_o2.elf"),
            &high_flags,
        ),
    ) else {
        eprintln!("skipping: clang cannot cross link an aarch64 image here");
        return;
    };

    let left: Vec<FunctionFeatures> = extract_function_features(&low).expect("aarch64 O0 extract");
    let right: Vec<FunctionFeatures> =
        extract_function_features(&high).expect("aarch64 O2 extract");
    describe("aarch64 O0", &left);
    describe("aarch64 O2", &right);

    let grade: PairGrade =
        graded_pair("aarch64 O0 vs O2", &left, &right, &side(&low), &side(&high));
    assert!(
        grade.exact.disagreed.is_empty(),
        "every symbol-named aarch64 pair must name the same function on both sides"
    );
    assert!(
        grade.structural.disagreed.is_empty(),
        "a structural pair that names two different functions is a wrong match"
    );
    assert!(
        grade.propagated.disagreed.is_empty(),
        "a propagated aarch64 pair that names two different functions is a wrong match"
    );
    assert!(
        grade.exact.agreed > 0,
        "adrp pairs and wide moves must anchor at least one aarch64 function"
    );
}

#[test]
fn a_stripped_aarch64_dynamic_export_does_not_suppress_internal_call_targets() {
    let Some(compiler): Option<PathBuf> = tool("clang") else {
        eprintln!("skipping: clang absent, no aarch64 dynamic-export build");
        return;
    };
    let scratch: TempDir = TempDir::new().expect("scratch directory");
    let source: PathBuf = scratch.path().join("dynamic_export.c");
    let unstripped_path: PathBuf = scratch.path().join("dynamic_export.elf");
    let stripped_path: PathBuf = scratch.path().join("dynamic_export.stripped.elf");
    std::fs::write(&source, AARCH64_DYNAMIC_EXPORT_SOURCE).expect("write aarch64 source");
    let flags: [&str; 7] = [
        "-target",
        "aarch64-unknown-linux-gnu",
        "-nostdlib",
        "-ffreestanding",
        "-fuse-ld=lld",
        "-Wl,--export-dynamic",
        "-O0",
    ];
    let Some(unstripped): Option<Vec<u8>> = compile(&compiler, &source, &unstripped_path, &flags)
    else {
        eprintln!("skipping: clang cannot cross link an aarch64 dynamic-export image");
        return;
    };
    let unstripped_payload: DisasmPayload =
        build_disasm_payload(&unstripped).expect("build unstripped payload");
    let internal_address: u64 = unstripped_payload
        .symbol_table
        .iter()
        .find(|symbol: &&DisasmSymbol| symbol.name == "internal_mix")
        .map(|symbol: &DisasmSymbol| symbol.address)
        .expect("unstripped internal_mix symbol");
    let Some(stripped): Option<Vec<u8>> = stripped_copy(&unstripped_path, &stripped_path) else {
        eprintln!("skipping: strip cannot process the aarch64 dynamic-export image");
        return;
    };
    let payload: DisasmPayload = build_disasm_payload(&stripped).expect("build stripped payload");
    let functions: Vec<&DisasmSymbol> = payload
        .symbol_table
        .iter()
        .filter(|symbol: &&DisasmSymbol| {
            matches!(
                symbol.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .collect();

    let start_address: u64 = functions
        .iter()
        .find(|symbol: &&&DisasmSymbol| symbol.name == "_start")
        .map(|symbol: &&DisasmSymbol| symbol.address)
        .expect("stripped _start export");
    let recovered_internal: Vec<&DisasmSymbol> = functions
        .iter()
        .copied()
        .filter(|symbol: &&DisasmSymbol| symbol.address == internal_address)
        .collect();
    assert_eq!(recovered_internal.len(), 1, "{functions:?}");
    assert!(
        recovered_internal[0].name.starts_with("sub_"),
        "{functions:?}"
    );

    let features: Vec<FunctionFeatures> =
        extract_function_features(&stripped).expect("extract stripped features");
    let start_features: &FunctionFeatures = features
        .iter()
        .find(|feature: &&FunctionFeatures| feature.id() == FunctionId::from(start_address))
        .expect("_start features");
    assert!(
        start_features
            .call_targets()
            .contains(&FunctionId::from(internal_address)),
        "{features:?}"
    );
}
