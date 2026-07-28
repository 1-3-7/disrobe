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

use disrobe_pass_native::{
    FunctionSpan, build_disasm_payload, extract_function_features, function_spans,
};
use disrobe_similarity::{
    DataReference, FunctionFeatures, FunctionId, MatchReport, match_functions,
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
    let stripper: PathBuf = tool("strip")?;
    std::fs::copy(source, output).ok()?;
    if !run(Command::new(stripper).arg("-s").arg(output)) {
        return None;
    }
    std::fs::read(output).ok()
}

fn symbol_names(bytes: &[u8]) -> BTreeMap<u64, String> {
    let Ok(payload) = build_disasm_payload(bytes) else {
        return BTreeMap::new();
    };
    function_spans(&payload)
        .into_iter()
        .map(|span: FunctionSpan| (span.address, span.name))
        .collect()
}

fn anchored(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| entry.has_anchor())
        .count()
}

struct Verification {
    agreed: usize,
    disagreed: Vec<(String, String)>,
    unnamed: usize,
}

fn verify_against_symbols(
    report: &MatchReport,
    left: &BTreeMap<u64, String>,
    right: &BTreeMap<u64, String>,
) -> Verification {
    let mut agreed: usize = 0;
    let mut disagreed: Vec<(String, String)> = Vec::new();
    let mut unnamed: usize = 0;
    for (a, b) in report.exact_pairs() {
        let (a, b): (FunctionId, FunctionId) = (a, b);
        match (left.get(&a.0), right.get(&b.0)) {
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
        "{label}: {} functions, {} carrying an anchor, references {strings} string / {constants} constant / {imports} import",
        features.len(),
        anchored(features)
    );
}

fn self_match_count(features: &[FunctionFeatures]) -> usize {
    let report: MatchReport = match_functions(features, features);
    for (a, b) in report.exact_pairs() {
        assert_eq!(
            a, b,
            "an image matched against itself must map every anchor to its own address"
        );
    }
    report.exact_count()
}

fn graded_pair(
    label: &str,
    left: &[FunctionFeatures],
    right: &[FunctionFeatures],
    left_names: &BTreeMap<u64, String>,
    right_names: &BTreeMap<u64, String>,
) -> Verification {
    let report: MatchReport = match_functions(left, right);
    let verification: Verification = verify_against_symbols(&report, left_names, right_names);
    println!(
        "{label}: {} exact pairs, {} verified by symbol name, {} unnamed, {} disagreements",
        report.exact_count(),
        verification.agreed,
        verification.unnamed,
        verification.disagreed.len()
    );
    for (name_a, name_b) in &verification.disagreed {
        println!("  disagreement: {name_a} paired with {name_b}");
    }
    verification
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

    let low_names: BTreeMap<u64, String> = symbol_names(&low);
    let high_names: BTreeMap<u64, String> = symbol_names(&high);
    assert!(
        !low_names.is_empty() && !high_names.is_empty(),
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
        &low_names,
        &high_names,
    );

    let verification: Verification =
        graded_pair("O0 vs O2 stripped", &left, &right, &low_names, &high_names);
    assert!(
        verification.disagreed.is_empty(),
        "every symbol-named pair must name the same function on both sides"
    );
    assert!(
        verification.agreed > 0,
        "the pair must anchor at least one function through its data references"
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

    let verification: Verification = graded_pair(
        "aarch64 O0 vs O2",
        &left,
        &right,
        &symbol_names(&low),
        &symbol_names(&high),
    );
    assert!(
        verification.disagreed.is_empty(),
        "every symbol-named aarch64 pair must name the same function on both sides"
    );
    assert!(
        verification.agreed > 0,
        "adrp pairs and wide moves must anchor at least one aarch64 function"
    );
}
