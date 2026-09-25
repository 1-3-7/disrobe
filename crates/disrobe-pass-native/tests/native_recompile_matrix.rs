#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::{
    CompileOutcome, CompilerFamily, CompilerId, RunOutcome, available_compilers, codegen_flags,
    compile_object_reasoned, function_code, link_and_run_reasoned, link_objects_to_exe,
    msvc_probe_reason, object_compiler, scratch_dir, strip_includes,
};
use disrobe_core::rng::seeded;
use disrobe_ir::{Envelope, RawPayload, Rung, Sidecar, decode_raw, encode_raw};
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction as LibRecoveredFunction,
    RecoveredProgram as LibRecoveredProgram, build_disasm_payload, function_spans, image_arch,
    recover_program as lib_recover_program, text_section_window,
};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};

const MASTER_SEED: u64 = 0xD15C_0BE5_7E57_C0DE;
const SAFE_MAGNITUDE: i64 = 1i64 << 40;
const SMALL_MAGNITUDE: i64 = 40;
const RANDOM_DRAWS_PER_ROW: usize = 8;
const RESAMPLE_ATTEMPTS: usize = 64;
const ENTRY_RETURN_WIDTH: u32 = 64;
const WORKER_COUNT: usize = 4;
const LEDGER_FILE: &str = "native-recompile-matrix-truth.dr";
const TRUTH_LEDGER_SCHEMA_VERSION: u16 = 1;
const TRUTH_WITNESS_SOURCE: &str = "disrobe.native-recompile-matrix-truth/v1";
const HARNESS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkShape {
    ObjectInPlace,
    LinkedExecutable,
}

impl LinkShape {
    const fn tag(self) -> &'static str {
        match self {
            Self::ObjectInPlace => "object_in_place",
            Self::LinkedExecutable => "linked_executable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbiTarget {
    MsX64,
    SysV,
}

impl AbiTarget {
    const fn tag(self) -> &'static str {
        match self {
            Self::MsX64 => "ms_x64",
            Self::SysV => "sysv",
        }
    }

    const fn as_pseudo(self) -> PseudoAbi {
        match self {
            Self::MsX64 => PseudoAbi::MsX64,
            Self::SysV => PseudoAbi::SysV,
        }
    }
}

struct ShapeCase {
    shape_tag: &'static str,
    entry: &'static str,
    entry_arity: usize,
    functions: &'static [&'static str],
    c_source: &'static str,
    magnitude: i64,
    extra_boundaries: &'static [i64],
    permit_sibling_calls: bool,
    ub_check: fn(i64, i64, i64) -> bool,
}

fn ub_leaf(a: i64, b: i64, c: i64) -> bool {
    b.checked_mul(2)
        .and_then(|bm2: i64| a.checked_add(bm2))
        .and_then(|s: i64| s.checked_sub(c))
        .is_some()
}

fn ub_direct_call(a: i64, b: i64, c: i64) -> bool {
    a.checked_mul(2)
        .and_then(|am2: i64| am2.checked_add(b))
        .and_then(|s: i64| s.checked_add(c))
        .is_some()
}

fn ub_indirect_call(a: i64, b: i64, c: i64) -> bool {
    b.checked_mul(3)
        .and_then(|bm3: i64| a.checked_sub(bm3))
        .and_then(|s: i64| s.checked_add(c))
        .is_some()
}

const fn within_small_magnitude(v: i64) -> bool {
    v >= -SMALL_MAGNITUDE && v <= SMALL_MAGNITUDE
}

fn triangular(n: i64) -> Option<i64> {
    if n <= 0 {
        return Some(0);
    }
    let mut acc: i64 = 0;
    let mut i: i64 = 1;
    while i <= n {
        acc = acc.checked_add(i)?;
        i = i.checked_add(1)?;
    }
    Some(acc)
}

fn ub_recursive(a: i64, b: i64, c: i64) -> bool {
    if !within_small_magnitude(a) || !within_small_magnitude(b) || !within_small_magnitude(c) {
        return false;
    }
    triangular(a)
        .and_then(|h: i64| h.checked_add(b))
        .and_then(|s: i64| s.checked_sub(c))
        .is_some()
}

#[allow(clippy::many_single_char_names)]
const fn ub_loop_carried(a: i64, b: i64, c: i64) -> bool {
    if !within_small_magnitude(a) || !within_small_magnitude(b) || !within_small_magnitude(c) {
        return false;
    }
    let mut s: i64 = 0;
    let mut i: i64 = 0;
    while i < a {
        let Some(term) = i.checked_add(b) else {
            return false;
        };
        let Some(next) = s.checked_add(term) else {
            return false;
        };
        s = next;
        let Some(next_i) = i.checked_add(1) else {
            return false;
        };
        i = next_i;
    }
    s.checked_add(c).is_some()
}

const fn switch_dense_value(k: i64) -> i64 {
    match k {
        0 => 11,
        1 => 22,
        2 => 33,
        3 => 44,
        4 => 55,
        5 => 66,
        6 => 77,
        7 => 88,
        _ => -1,
    }
}

fn ub_switch_dense(a: i64, b: i64, c: i64) -> bool {
    switch_dense_value(a)
        .checked_add(b)
        .and_then(|s: i64| s.checked_sub(c))
        .is_some()
}

const fn switch_sparse_value(k: i64) -> i64 {
    match k {
        2 => 5,
        19 => 40,
        250 => 900,
        _ => -7,
    }
}

fn ub_switch_sparse(a: i64, b: i64, c: i64) -> bool {
    switch_sparse_value(a)
        .checked_add(b)
        .and_then(|s: i64| s.checked_sub(c))
        .is_some()
}

fn early_return_value(a: i64, b: i64) -> Option<i64> {
    if a < 0 {
        return Some(-1);
    }
    if b < 0 {
        return Some(-2);
    }
    if a > b {
        return a.checked_sub(b)?.checked_add(100);
    }
    b.checked_sub(a)?.checked_add(200)
}

fn ub_early_return(a: i64, b: i64, c: i64) -> bool {
    early_return_value(a, b)
        .and_then(|h: i64| h.checked_add(c))
        .is_some()
}

fn ub_varargs(a: i64, b: i64, c: i64) -> bool {
    a.checked_add(b)
        .and_then(|s: i64| s.checked_add(c))
        .and_then(|s: i64| s.checked_add(1))
        .is_some()
}

fn ub_tail_call(a: i64, b: i64, _c: i64) -> bool {
    b.checked_mul(3)
        .and_then(|bm3: i64| a.checked_add(bm3))
        .is_some()
}

fn ub_struct_by_value(a: i64, b: i64, c: i64) -> bool {
    ub_leaf(a, b, c)
}

fn ub_struct_return_hidden_ptr(a: i64, b: i64, c: i64) -> bool {
    a.checked_mul(3)
        .and_then(|am3: i64| am3.checked_add(3))
        .and_then(|s: i64| s.checked_add(b))
        .and_then(|s: i64| s.checked_sub(c))
        .is_some()
}

const SHAPES: &[ShapeCase] = &[
    ShapeCase {
        shape_tag: "leaf",
        entry: "mx_leaf_entry",
        entry_arity: 3,
        functions: &["mx_leaf_entry"],
        c_source: "long long mx_leaf_entry(long long a, long long b, long long c){ return a + b * 2 - c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_leaf,
    },
    ShapeCase {
        shape_tag: "direct_call",
        entry: "mx_direct_entry",
        entry_arity: 3,
        functions: &["mx_direct_entry", "mx_direct_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_direct_h(long long x, long long y){ return x * 2 + y; }\n\
                    long long mx_direct_entry(long long a, long long b, long long c){ return mx_direct_h(a, b) + c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_direct_call,
    },
    ShapeCase {
        shape_tag: "indirect_call",
        entry: "mx_indirect_entry",
        entry_arity: 3,
        functions: &["mx_indirect_entry", "mx_indirect_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_indirect_h(long long x, long long y){ return x - y * 3; }\n\
                    typedef long long (*mx_indirect_fn)(long long, long long);\n\
                    long long mx_indirect_entry(long long a, long long b, long long c){ mx_indirect_fn f = &mx_indirect_h; return f(a, b) + c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_indirect_call,
    },
    ShapeCase {
        shape_tag: "recursive",
        entry: "mx_recursive_entry",
        entry_arity: 3,
        functions: &["mx_recursive_entry", "mx_recursive_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_recursive_h(long long n){ if (n <= 0) return 0; return n + mx_recursive_h(n - 1); }\n\
                    long long mx_recursive_entry(long long a, long long b, long long c){ return mx_recursive_h(a) + b - c; }",
        magnitude: SMALL_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_recursive,
    },
    ShapeCase {
        shape_tag: "loop_carried",
        entry: "mx_loop_entry",
        entry_arity: 3,
        functions: &["mx_loop_entry"],
        c_source: "long long mx_loop_entry(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < a; i++) { s += i + b; } return s + c; }",
        magnitude: SMALL_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_loop_carried,
    },
    ShapeCase {
        shape_tag: "switch_jumptable",
        entry: "mx_switch_dense_entry",
        entry_arity: 3,
        functions: &["mx_switch_dense_entry", "mx_switch_dense_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_switch_dense_h(long long k){ switch(k){ case 0: return 11; case 1: return 22; case 2: return 33; case 3: return 44; case 4: return 55; case 5: return 66; case 6: return 77; case 7: return 88; default: return -1; } }\n\
                    long long mx_switch_dense_entry(long long a, long long b, long long c){ return mx_switch_dense_h(a) + b - c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        permit_sibling_calls: false,
        ub_check: ub_switch_dense,
    },
    ShapeCase {
        shape_tag: "switch_cmpchain",
        entry: "mx_switch_sparse_entry",
        entry_arity: 3,
        functions: &["mx_switch_sparse_entry", "mx_switch_sparse_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_switch_sparse_h(long long k){ switch(k){ case 2: return 5; case 19: return 40; case 250: return 900; default: return -7; } }\n\
                    long long mx_switch_sparse_entry(long long a, long long b, long long c){ return mx_switch_sparse_h(a) + b - c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[2, 19, 250],
        permit_sibling_calls: false,
        ub_check: ub_switch_sparse,
    },
    ShapeCase {
        shape_tag: "early_return",
        entry: "mx_early_entry",
        entry_arity: 3,
        functions: &["mx_early_entry", "mx_early_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_early_h(long long a, long long b){ if (a < 0) return -1; if (b < 0) return -2; if (a > b) return a - b + 100; return b - a + 200; }\n\
                    long long mx_early_entry(long long a, long long b, long long c){ return mx_early_h(a, b) + c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_early_return,
    },
    ShapeCase {
        shape_tag: "varargs",
        entry: "mx_varargs_entry",
        entry_arity: 3,
        functions: &["mx_varargs_entry", "mx_varargs_h"],
        c_source: "#include <stdarg.h>\n\
                    __attribute__((noinline,noclone)) long long mx_varargs_h(long long count, ...){ long long s = 0; va_list ap; va_start(ap, count); for (long long i = 0; i < count; i++) { s += va_arg(ap, long long); } va_end(ap); return s; }\n\
                    long long mx_varargs_entry(long long a, long long b, long long c){ return mx_varargs_h(3, a, b, c) + 1; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_varargs,
    },
    ShapeCase {
        shape_tag: "tail_call",
        entry: "mx_tail_entry",
        entry_arity: 3,
        functions: &["mx_tail_entry", "mx_tail_h"],
        c_source: "__attribute__((noinline,noclone)) long long mx_tail_h(long long a, long long b){ return a + b * 3; }\n\
                    long long mx_tail_entry(long long a, long long b, long long c){ (void)c; return mx_tail_h(a, b); }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: true,
        ub_check: ub_tail_call,
    },
    ShapeCase {
        shape_tag: "struct_by_value",
        entry: "mx_struct_arg_entry",
        entry_arity: 3,
        functions: &["mx_struct_arg_entry", "mx_struct_arg_h"],
        c_source: "typedef struct { long long x; long long y; } mx_pair_t;\n\
                    __attribute__((noinline,noclone)) long long mx_struct_arg_h(mx_pair_t p){ return p.x + p.y * 2; }\n\
                    long long mx_struct_arg_entry(long long a, long long b, long long c){ mx_pair_t p; p.x = a; p.y = b; return mx_struct_arg_h(p) + c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_struct_by_value,
    },
    ShapeCase {
        shape_tag: "struct_return_hidden_ptr",
        entry: "mx_struct_ret_entry",
        entry_arity: 3,
        functions: &["mx_struct_ret_entry", "mx_struct_ret_h"],
        c_source: "typedef struct { long long a; long long b; long long c; } mx_triple_t;\n\
                    __attribute__((noinline,noclone)) mx_triple_t mx_struct_ret_h(long long x){ mx_triple_t t; t.a = x; t.b = x + 1; t.c = x + 2; return t; }\n\
                    long long mx_struct_ret_entry(long long a, long long b, long long c){ mx_triple_t t = mx_struct_ret_h(a); return t.a + t.b + t.c + b - c; }",
        magnitude: SAFE_MAGNITUDE,
        extra_boundaries: &[],
        permit_sibling_calls: false,
        ub_check: ub_struct_return_hidden_ptr,
    },
];

#[derive(Debug, Clone)]
enum Verdict {
    Equivalent,
    Mismatch(String),
    SoundRejected(String),
    SignatureMismatch(String),
    NotGraded(String),
}

impl Verdict {
    const fn label(&self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Mismatch(_) => "MISMATCH",
            Self::SoundRejected(_) => "sound_rejected",
            Self::SignatureMismatch(_) => "signature_mismatch",
            Self::NotGraded(_) => "not_graded",
        }
    }
}

fn verdict_for_run(outcome: RunOutcome, row_seed: u64) -> Verdict {
    match outcome {
        RunOutcome::Completed(captured) => {
            let stdout: String = String::from_utf8_lossy(&captured.stdout).into_owned();
            if captured.exit_code == Some(0)
                && stdout.contains("OK")
                && !stdout.contains("MISMATCH")
            {
                Verdict::Equivalent
            } else {
                Verdict::Mismatch(format!(
                    "seed={row_seed} exit_code={:?} stdout={} stderr={}",
                    captured.exit_code,
                    stdout.trim(),
                    String::from_utf8_lossy(&captured.stderr).trim()
                ))
            }
        }
        RunOutcome::TimedOut { seconds } => Verdict::Mismatch(format!(
            "seed={row_seed} harness timed out after {seconds}s"
        )),
        RunOutcome::ExecutionFailed(reason) => {
            Verdict::Mismatch(format!("seed={row_seed} {reason}"))
        }
        RunOutcome::Failed(reason) => Verdict::NotGraded(format!("link/run: {reason}")),
    }
}

#[test]
fn launched_harness_failures_are_mismatches() {
    let compiler: String =
        common::cc().expect("a C compiler is required for harness classification");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("native-run-classification");
    let object: Vec<u8> = match compile_object_reasoned(
        &compiler,
        "-O1",
        &["-c"],
        "int baseline(void) { return 0; }",
        &scratch.path().join("baseline.o"),
    ) {
        CompileOutcome::Object(bytes) => bytes,
        CompileOutcome::Rejected(reason) => {
            panic!("classification fixture failed to compile: {reason}")
        }
    };

    let timed_out: RunOutcome = link_and_run_reasoned(
        &compiler,
        "int main(void) { for (;;) {} }",
        &object,
        "timeout",
        1,
    );
    assert!(matches!(timed_out, RunOutcome::TimedOut { seconds: 1 }));
    assert!(matches!(
        verdict_for_run(timed_out, MASTER_SEED),
        Verdict::Mismatch(_)
    ));

    for exit_code in [0, 7] {
        let driver: String =
            format!("#include <stdio.h>\nint main(void) {{ puts(\"OK\"); return {exit_code}; }}");
        let outcome: RunOutcome =
            link_and_run_reasoned(&compiler, &driver, &object, "exit_status", 5);
        let RunOutcome::Completed(captured) = &outcome else {
            panic!("exit-status fixture did not complete: {outcome:?}");
        };
        assert_eq!(captured.exit_code, Some(exit_code));
        assert_eq!(String::from_utf8_lossy(&captured.stdout).trim(), "OK");
        let verdict: Verdict = verdict_for_run(outcome, MASTER_SEED);
        if exit_code == 0 {
            assert!(matches!(verdict, Verdict::Equivalent));
        } else {
            assert!(matches!(verdict, Verdict::Mismatch(_)));
        }
    }

    let capture_failed: RunOutcome = link_and_run_reasoned(
        &compiler,
        "#include <stdio.h>\nint main(void) { char block[4096] = {0}; for (int i = 0; i < 1025; ++i) fwrite(block, 1, sizeof block, stdout); return 0; }",
        &object,
        "capture_failure",
        5,
    );
    assert!(matches!(capture_failed, RunOutcome::ExecutionFailed(_)));
    assert!(matches!(
        verdict_for_run(capture_failed, MASTER_SEED),
        Verdict::Mismatch(_)
    ));

    let unavailable: RunOutcome = link_and_run_reasoned(
        scratch
            .path()
            .join("missing-compiler")
            .to_str()
            .expect("compiler path"),
        "int main(void) { return 0; }",
        &object,
        "unavailable",
        5,
    );
    assert!(matches!(unavailable, RunOutcome::Failed(_)));
    assert!(matches!(
        verdict_for_run(unavailable, MASTER_SEED),
        Verdict::NotGraded(_)
    ));
}

#[derive(Debug, Clone)]
struct MatrixRow {
    shape: &'static str,
    reference_compiler: String,
    reference_compiler_version: String,
    recovery_input_compiler: String,
    recovery_input_compiler_version: String,
    recovery_input_root: Option<[u8; 32]>,
    opt: &'static str,
    abi: &'static str,
    arch: &'static str,
    link_shape: &'static str,
    verdict: Verdict,
    seed: Option<u64>,
    teeth_confirmed: bool,
    linked_functions_extracted: Option<usize>,
}

#[derive(Debug, Clone)]
struct ProducerIdentity {
    program: String,
    version: String,
}

fn row_key(row: &MatrixRow) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.shape,
        row.reference_compiler,
        row.reference_compiler_version,
        row.recovery_input_compiler,
        row.recovery_input_compiler_version,
        row.opt,
        row.abi,
        row.arch,
        row.link_shape
    )
}

fn row_hash(row: &MatrixRow, source: &str, entry: &str) -> [u8; 32] {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    let row_key: String = row_key(row);
    for segment in [row_key.as_bytes(), source.as_bytes(), entry.as_bytes()] {
        let length: u64 = segment.len() as u64;
        hasher.update(&length.to_le_bytes());
        hasher.update(segment);
    }
    hasher.update(&HARNESS_VERSION.to_le_bytes());
    match row.recovery_input_root {
        Some(root) => hasher.update(&root),
        None => hasher.update(b"no-recovery-input"),
    };
    match row.seed {
        Some(seed) => {
            hasher.update(b"seed-present");
            hasher.update(&seed.to_le_bytes());
        }
        None => {
            hasher.update(b"seed-absent");
        }
    }
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
enum TruthLabel {
    Equivalent,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct TruthEntry {
    input_root: [u8; 32],
    label: TruthLabel,
}

#[derive(Debug, Serialize, Deserialize)]
struct TruthLedger {
    schema_version: u16,
    entries: BTreeMap<String, TruthEntry>,
}

impl Default for TruthLedger {
    fn default() -> Self {
        Self {
            schema_version: TRUTH_LEDGER_SCHEMA_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

fn ledger_path() -> Result<PathBuf, String> {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !root.join("Cargo.lock").is_file() {
        if !root.pop() {
            return Err(
                "could not resolve the workspace root for the native truth witness".to_owned(),
            );
        }
    }
    Ok(root.join(".disrobe").join(LEDGER_FILE))
}

fn load_ledger(path: &Path) -> Result<(TruthLedger, bool), String> {
    let exists: bool = path.try_exists().map_err(|error: std::io::Error| {
        format!("cannot inspect truth witness {}: {error}", path.display())
    })?;
    if !exists {
        return Ok((TruthLedger::default(), false));
    }
    let envelope: Envelope = Envelope::read_from_path(path)
        .map_err(|error| format!("cannot read truth witness {}: {error}", path.display()))?;
    if envelope.rung != Rung::Raw {
        return Err(format!(
            "truth witness {} has {:?} rung, expected Raw",
            path.display(),
            envelope.rung
        ));
    }
    let sidecar: Sidecar = Sidecar::decode(&envelope.cold).map_err(|error| {
        format!(
            "cannot decode truth witness sidecar {}: {error}",
            path.display()
        )
    })?;
    if sidecar.produced_by != "disrobe-pass-native/native-recompile-matrix"
        || sidecar.provenance.get("schema").map(String::as_str) != Some(TRUTH_WITNESS_SOURCE)
    {
        return Err(format!(
            "truth witness {} has an unexpected sidecar identity",
            path.display()
        ));
    }
    let raw: RawPayload = decode_raw(&envelope.hot).map_err(|error| {
        format!(
            "cannot decode truth witness payload {}: {error}",
            path.display()
        )
    })?;
    if raw.source_path != TRUTH_WITNESS_SOURCE
        || raw.detected_format.as_deref() != Some(TRUTH_WITNESS_SOURCE)
    {
        return Err(format!(
            "truth witness {} has an unexpected raw payload identity",
            path.display()
        ));
    }
    if raw.source_hash != *blake3::hash(&raw.source_bytes).as_bytes() {
        return Err(format!(
            "truth witness {} has a mismatched raw payload hash",
            path.display()
        ));
    }
    let ledger: TruthLedger =
        serde_json::from_slice(&raw.source_bytes).map_err(|error: serde_json::Error| {
            format!("cannot decode truth witness {}: {error}", path.display())
        })?;
    if ledger.schema_version != TRUTH_LEDGER_SCHEMA_VERSION {
        return Err(format!(
            "truth witness {} uses schema {}, expected {}",
            path.display(),
            ledger.schema_version,
            TRUTH_LEDGER_SCHEMA_VERSION
        ));
    }
    Ok((ledger, true))
}

fn save_ledger(path: &Path, ledger: &TruthLedger) -> Result<(), String> {
    let parent: &Path = path
        .parent()
        .ok_or_else(|| format!("truth witness {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
        format!(
            "cannot create truth witness directory {}: {error}",
            parent.display()
        )
    })?;
    let ledger_bytes: Vec<u8> =
        serde_json::to_vec(ledger).map_err(|error: serde_json::Error| {
            format!("cannot encode truth witness {}: {error}", path.display())
        })?;
    let hot: Vec<u8> = encode_raw(&RawPayload {
        source_path: TRUTH_WITNESS_SOURCE.to_owned(),
        source_hash: *blake3::hash(&ledger_bytes).as_bytes(),
        source_bytes: ledger_bytes,
        detected_format: Some(TRUTH_WITNESS_SOURCE.to_owned()),
    })
    .map_err(|error| {
        format!(
            "cannot encode truth witness payload {}: {error}",
            path.display()
        )
    })?;
    let sidecar: Sidecar = Sidecar {
        produced_by: "disrobe-pass-native/native-recompile-matrix".to_owned(),
        produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: Vec::new(),
        provenance: BTreeMap::from([("schema".to_owned(), TRUTH_WITNESS_SOURCE.to_owned())]),
    };
    let cold: Vec<u8> = sidecar.encode().map_err(|error| {
        format!(
            "cannot encode truth witness sidecar {}: {error}",
            path.display()
        )
    })?;
    Envelope::new(Rung::Raw, hot, cold)
        .write_to_path_with(path, false)
        .map_err(|error| format!("cannot write truth witness {}: {error}", path.display()))
}

fn entry_for_row(row: &MatrixRow) -> Result<&'static str, String> {
    SHAPES
        .iter()
        .find(|shape: &&ShapeCase| shape.shape_tag == row.shape)
        .map(|shape: &ShapeCase| shape.entry)
        .ok_or_else(|| format!("truth witness has no entrypoint for shape {}", row.shape))
}

fn entry_key(row: &MatrixRow, entry: &str) -> String {
    format!("{}|entry={entry}", row_key(row))
}

fn truth_label(row: &MatrixRow) -> Option<TruthLabel> {
    matches!(row.verdict, Verdict::Equivalent).then_some(TruthLabel::Equivalent)
}

fn reconcile_ledger_at(path: &Path, rows: &[(MatrixRow, [u8; 32])]) -> Result<(), String> {
    let (mut ledger, ledger_existed): (TruthLedger, bool) = load_ledger(path)?;
    if !ledger_existed {
        println!(
            "truth ledger: no prior ledger at {}; this is a first run, recording fresh truth for every row",
            path.display()
        );
    }
    let mut regressions: Vec<String> = Vec::new();
    for (row, input_root) in rows {
        let entry: &str = entry_for_row(row)?;
        let key: String = entry_key(row, entry);
        let label: Option<TruthLabel> = truth_label(row);
        if let Some(prior) = ledger.entries.get(&key)
            && prior.input_root == *input_root
            && prior.label == TruthLabel::Equivalent
            && label != Some(TruthLabel::Equivalent)
        {
            regressions.push(format!(
                "{key}: was equivalent under input root {:?}, now {}",
                prior.input_root,
                row.verdict.label()
            ));
        }
        match label {
            Some(label) => {
                ledger.entries.insert(
                    key,
                    TruthEntry {
                        input_root: *input_root,
                        label,
                    },
                );
            }
            None => {
                ledger.entries.remove(&key);
            }
        }
    }
    if !regressions.is_empty() {
        return Err(format!(
            "truth ledger detected a regression versus the last recorded equivalence: {regressions:?}"
        ));
    }
    save_ledger(path, &ledger)
}

fn reconcile_ledger(rows: &[(MatrixRow, [u8; 32])]) -> Result<(), String> {
    let path: PathBuf = ledger_path()?;
    reconcile_ledger_at(&path, rows)
}

fn ledger_test_row(verdict: Verdict) -> MatrixRow {
    MatrixRow {
        shape: "leaf",
        reference_compiler: "gcc".to_owned(),
        reference_compiler_version: "gcc test".to_owned(),
        recovery_input_compiler: "clang".to_owned(),
        recovery_input_compiler_version: "clang test".to_owned(),
        recovery_input_root: Some([0xA5; 32]),
        opt: "-O0",
        abi: "sysv",
        arch: "x86_64",
        link_shape: "object_in_place",
        verdict,
        seed: Some(MASTER_SEED),
        teeth_confirmed: true,
        linked_functions_extracted: None,
    }
}

#[test]
fn truth_witness_persists_only_the_graded_entry_in_a_dr_envelope() {
    let scratch = scratch_dir("disrobe-native-truth-witness-reread");
    let path: PathBuf = scratch.path().join(LEDGER_FILE);
    let row: MatrixRow = ledger_test_row(Verdict::Equivalent);
    let entry: &str = entry_for_row(&row).expect("leaf entry");
    let input_root: [u8; 32] = row_hash(&row, "original source", entry);

    reconcile_ledger_at(&path, &[(row.clone(), input_root)]).expect("write truth witness");

    let (ledger, existed): (TruthLedger, bool) = load_ledger(&path).expect("re-read truth witness");
    assert!(existed);
    assert_eq!(ledger.schema_version, TRUTH_LEDGER_SCHEMA_VERSION);
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(
        ledger.entries.get(&entry_key(&row, entry)),
        Some(&TruthEntry {
            input_root,
            label: TruthLabel::Equivalent,
        })
    );
    assert!(
        ledger
            .entries
            .keys()
            .all(|key: &String| key.ends_with(&format!("entry={entry}"))),
        "a row-level result must not assert a truth label for an ungraded helper"
    );
}

#[test]
fn truth_witness_rederives_a_stale_input_root() {
    let scratch = scratch_dir("disrobe-native-truth-witness-stale");
    let path: PathBuf = scratch.path().join(LEDGER_FILE);
    let row: MatrixRow = ledger_test_row(Verdict::Equivalent);
    let entry: &str = entry_for_row(&row).expect("leaf entry");
    let stale_root: [u8; 32] = row_hash(&row, "old source", entry);
    let mut reseeded: MatrixRow = row.clone();
    reseeded.seed = Some(MASTER_SEED ^ 1);
    let current_root: [u8; 32] = row_hash(&reseeded, "old source", entry);
    assert_ne!(
        stale_root, current_root,
        "the driver seed must bind the truth witness"
    );

    reconcile_ledger_at(&path, &[(row.clone(), stale_root)]).expect("write stale witness");
    reconcile_ledger_at(&path, &[(reseeded.clone(), current_root)])
        .expect("re-derive stale witness");

    let (ledger, _): (TruthLedger, bool) = load_ledger(&path).expect("read re-derived witness");
    assert_eq!(
        ledger
            .entries
            .get(&entry_key(&reseeded, entry))
            .map(|entry: &TruthEntry| entry.input_root),
        Some(current_root)
    );
}

#[test]
fn truth_witness_rejects_matching_input_regression_without_overwriting_equivalence() {
    let scratch = scratch_dir("disrobe-native-truth-witness-regression");
    let path: PathBuf = scratch.path().join(LEDGER_FILE);
    let equivalent: MatrixRow = ledger_test_row(Verdict::Equivalent);
    let entry: &str = entry_for_row(&equivalent).expect("leaf entry");
    let input_root: [u8; 32] = row_hash(&equivalent, "stable source", entry);
    reconcile_ledger_at(&path, &[(equivalent.clone(), input_root)])
        .expect("write equivalent witness");

    let rejected: MatrixRow =
        ledger_test_row(Verdict::SoundRejected("recovery refused".to_owned()));
    let error: String = reconcile_ledger_at(&path, &[(rejected, input_root)])
        .expect_err("matching input must not lose its equivalent truth claim");
    assert!(error.contains("regression"));

    let (ledger, _): (TruthLedger, bool) = load_ledger(&path).expect("read preserved witness");
    assert_eq!(
        ledger.entries.get(&entry_key(&equivalent, entry)),
        Some(&TruthEntry {
            input_root,
            label: TruthLabel::Equivalent,
        })
    );
}

#[test]
fn truth_witness_surfaces_read_and_write_failures() {
    let scratch = scratch_dir("disrobe-native-truth-witness-io");
    let malformed: PathBuf = scratch.path().join(LEDGER_FILE);
    std::fs::write(&malformed, b"not a disrobe envelope").expect("write malformed witness");
    let read_error: String = load_ledger(&malformed).expect_err("malformed witness must fail");
    assert!(read_error.contains("cannot read truth witness"));

    let blocked_parent: PathBuf = scratch.path().join("not-a-directory");
    std::fs::write(&blocked_parent, b"file").expect("write blocking parent");
    let write_error: String =
        save_ledger(&blocked_parent.join(LEDGER_FILE), &TruthLedger::default())
            .expect_err("truth witness write failure must propagate");
    assert!(write_error.contains("cannot create truth witness directory"));
}

fn clamp_ub_safe(shape: &ShapeCase, seed: u64, candidate: (i64, i64, i64)) -> (i64, i64, i64) {
    let (a, b, c) = candidate;
    if (shape.ub_check)(a, b, c) {
        return candidate;
    }
    let mut rng = seeded(seed ^ 0x5EED_5EED_5EED_5EEDu64);
    for _ in 0..RESAMPLE_ATTEMPTS {
        let ra: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
        let rb: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
        let rc: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
        if (shape.ub_check)(ra, rb, rc) {
            return (ra, rb, rc);
        }
    }
    (0, 0, 0)
}

fn boundary_inputs(shape: &ShapeCase, seed: u64) -> Vec<(i64, i64, i64)> {
    [
        0i64,
        1,
        -1,
        i64::MIN,
        i64::MAX,
        -shape.magnitude,
        shape.magnitude,
    ]
    .into_iter()
    .chain(shape.extra_boundaries.iter().copied())
    .map(|v: i64| clamp_ub_safe(shape, seed, (v, v, v)))
    .collect()
}

fn random_inputs(shape: &ShapeCase, seed: u64) -> Vec<(i64, i64, i64)> {
    let mut rng = seeded(seed);
    (0..RANDOM_DRAWS_PER_ROW)
        .map(|_| {
            let a: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
            let b: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
            let c: i64 = rng.random_range(-shape.magnitude..=shape.magnitude);
            clamp_ub_safe(shape, seed, (a, b, c))
        })
        .collect()
}

fn build_driver(
    shape: &ShapeCase,
    inputs: &[(i64, i64, i64)],
    entry_params: usize,
    tu: &str,
) -> String {
    let orig_args: String = (0..shape.entry_arity)
        .map(|i: usize| format!("in[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let rec_args: String = (0..entry_params)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let entry: &str = shape.entry;
    let name: &str = shape.shape_tag;
    let inputs_literal: String = inputs
        .iter()
        .map(|(a, b, c): &(i64, i64, i64)| format!("{{{a}LL,{b}LL,{c}LL}}"))
        .collect::<Vec<String>>()
        .join(",");
    let sig: String = vec!["long long"; shape.entry_arity].join(", ");
    let mut body: String = String::new();
    let _: core::fmt::Result = write!(
        body,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){entry}({orig_args}) & 0xFFFFFFFFFFFFFFFFULL;\n\
         \x20       unsigned long long got = (unsigned long long)rec_{entry}({rec_args}) & 0xFFFFFFFFFFFFFFFFULL;\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {name} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
    );
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{tu}\n\
         extern long long {entry}({sig});\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{ {inputs_literal} }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
    )
}

struct RecoveredProgram {
    tu: String,
    entry_params: usize,
    entry_return_width: u32,
    function_count: usize,
}

enum RecoverOutcome {
    Ok(RecoveredProgram),
    SoundRejected {
        reason: String,
        function_count: usize,
    },
    Prerequisite(String),
}

fn recover_shape(
    object: &[u8],
    shape: &ShapeCase,
    abi: PseudoAbi,
    linked_input: bool,
) -> RecoverOutcome {
    let functions: Vec<ProgramFunction> = match program_functions(object, shape, linked_input) {
        Ok(functions) => functions,
        Err(reason) => return RecoverOutcome::Prerequisite(reason),
    };
    let function_count: usize = functions.len();
    let result: LibRecoveredProgram = lib_recover_program(object, &functions, abi);
    if !result.unrecovered.is_empty() {
        let reasons: String = result
            .unrecovered
            .iter()
            .map(|u| format!("{}: {}", u.name, u.reason))
            .collect::<Vec<String>>()
            .join("; ");
        return RecoverOutcome::SoundRejected {
            reason: reasons,
            function_count,
        };
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 64;
    for (idx, &fname) in shape.functions.iter().enumerate() {
        let rec: &LibRecoveredFunction = &result.recovered[idx];
        tu.push_str(&strip_includes(&rec.source));
        tu.push('\n');
        if fname == shape.entry {
            entry_params = rec.signature.callable_arity();
            entry_return_width = rec.return_width_bits;
        }
    }
    RecoverOutcome::Ok(RecoveredProgram {
        tu,
        entry_params,
        entry_return_width,
        function_count,
    })
}

fn program_functions(
    object: &[u8],
    shape: &ShapeCase,
    linked_input: bool,
) -> Result<Vec<ProgramFunction>, String> {
    let from_symbols: Option<Vec<ProgramFunction>> = shape
        .functions
        .iter()
        .map(|&name: &&str| {
            function_code(object, name).map(|(code, address): (Vec<u8>, u64)| ProgramFunction {
                name: format!("rec_{name}"),
                address,
                code,
            })
        })
        .collect();
    if let Some(functions) = from_symbols {
        return Ok(functions);
    }
    if !linked_input || !cfg!(windows) || !object.starts_with(b"MZ") {
        return Err("input is missing a requested function symbol".to_owned());
    }

    let payload: disrobe_ir::payload::DisasmPayload = build_disasm_payload(object)
        .map_err(|error| format!("build linked executable function inventory: {error}"))?;
    let arch: disrobe_pass_native::Arch = image_arch(object)
        .ok_or_else(|| "linked executable does not name a supported architecture".to_owned())?;
    let spans: Vec<disrobe_pass_native::FunctionSpan> = function_spans(&payload, arch);
    let (text_base, _, text): (u64, u32, &[u8]) = text_section_window(object)
        .ok_or_else(|| "linked executable has no readable x86 text section".to_owned())?;
    let mut functions: Vec<ProgramFunction> = Vec::with_capacity(shape.functions.len());
    for &fname in shape.functions {
        let span: &disrobe_pass_native::FunctionSpan = spans
            .iter()
            .find(|span| span.name == fname || span.name == format!("_{fname}"))
            .ok_or_else(|| format!("{fname} symbol not located in linked executable"))?;
        let start: usize = usize::try_from(
            span.address
                .checked_sub(text_base)
                .ok_or_else(|| format!("{fname} span begins before the linked text section"))?,
        )
        .map_err(|_| format!("{fname} linked span start does not fit host indexing"))?;
        let end: usize = usize::try_from(
            span.end
                .checked_sub(text_base)
                .ok_or_else(|| format!("{fname} span ends before the linked text section"))?,
        )
        .map_err(|_| format!("{fname} linked span end does not fit host indexing"))?;
        let code: Vec<u8> = text
            .get(start..end)
            .filter(|code: &&[u8]| !code.is_empty())
            .ok_or_else(|| {
                format!(
                    "{fname} linked executable span {:#x}..{:#x} is outside its text section",
                    span.address, span.end
                )
            })?
            .to_vec();
        functions.push(ProgramFunction {
            name: format!("rec_{fname}"),
            address: span.address,
            code,
        });
    }
    Ok(functions)
}

fn corrupt_every_return(tu: &str, fn_marker: &str) -> Option<String> {
    let start_sig: usize = tu.find(fn_marker)?;
    let body_open_rel: usize = tu[start_sig..].find('{')?;
    let body_open: usize = start_sig + body_open_rel;
    let mut depth: i32 = 0;
    let mut body_close: Option<usize> = None;
    for (i, ch) in tu[body_open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_close = Some(body_open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let body_close: usize = body_close?;
    let body: &str = &tu[body_open..=body_close];
    let mut mutated_body: String = String::with_capacity(body.len().saturating_add(64));
    let mut rest: &str = body;
    let mut any: bool = false;
    while let Some(pos) = rest.find("return ") {
        let marker_len: usize = "return ".len();
        mutated_body.push_str(&rest[..pos.saturating_add(marker_len)]);
        let after: &str = &rest[pos.saturating_add(marker_len)..];
        let Some(semi) = after.find(';') else {
            mutated_body.push_str(after);
            rest = "";
            break;
        };
        let expr: &str = &after[..semi];
        mutated_body.push('(');
        mutated_body.push_str(expr);
        mutated_body.push_str(") + 1");
        rest = &after[semi..];
        any = true;
    }
    mutated_body.push_str(rest);
    if !any {
        return None;
    }
    let mut out: String = String::with_capacity(tu.len().saturating_add(64));
    out.push_str(&tu[..body_open]);
    out.push_str(&mutated_body);
    out.push_str(&tu[body_close.saturating_add(1)..]);
    Some(out)
}

fn compile_flags(family: CompilerFamily, permit_sibling_calls: bool) -> Vec<&'static str> {
    let mut flags: Vec<&'static str> = codegen_flags(family).to_vec();
    if permit_sibling_calls {
        flags.retain(|f: &&str| *f != "-fno-optimize-sibling-calls");
    }
    flags
}

fn build_original_object(
    compiler: &str,
    family: CompilerFamily,
    shape: &ShapeCase,
    opt: &str,
    tag: &str,
) -> CompileOutcome {
    let mut flags: Vec<&str> = compile_flags(family, shape.permit_sibling_calls);
    flags.push("-c");
    let scratch = scratch_dir("disrobe-native-matrix-orig");
    let out: PathBuf = scratch.path().join(format!("{tag}.o"));
    compile_object_reasoned(compiler, opt, &flags, shape.c_source, &out)
}

fn recovery_input_program(compiler: &CompilerId, abi: AbiTarget) -> String {
    let (program, _): (String, Vec<&'static str>) = object_compiler(compiler.bin, abi.as_pseudo());
    program
}

fn resolve_producer_identity(
    compiler: &CompilerId,
    abi: AbiTarget,
    versions: &mut BTreeMap<String, String>,
) -> Result<ProducerIdentity, String> {
    let program: String = recovery_input_program(compiler, abi);
    let version: String = if program == compiler.bin {
        compiler.version.clone()
    } else if let Some(cached) = versions.get(&program) {
        cached.clone()
    } else {
        let probed: String = common::probe_version(&program)
            .ok_or_else(|| format!("{program} did not provide a usable --version response"))?;
        versions.insert(program.clone(), probed.clone());
        probed
    };
    Ok(ProducerIdentity { program, version })
}

fn build_recovery_object(
    compiler: &CompilerId,
    abi: AbiTarget,
    shape: &ShapeCase,
    opt: &str,
    tag: &str,
) -> CompileOutcome {
    let mut flags: Vec<&str> = compile_flags(compiler.family, shape.permit_sibling_calls);
    if matches!(abi, AbiTarget::SysV) {
        flags.push("-fcf-protection=none");
    }
    flags.push("-c");
    let scratch = scratch_dir("disrobe-native-matrix-recovery");
    let out: PathBuf = scratch.path().join(format!("{tag}.o"));
    common::compile_x86_object_reasoned(
        compiler.bin,
        abi.as_pseudo(),
        opt,
        &flags,
        shape.c_source,
        &out,
    )
}

fn link_executable_and_extract(
    compiler: &str,
    family: CompilerFamily,
    shape: &ShapeCase,
    opt: &str,
    plain_object: &[u8],
    tag: &str,
) -> Result<Vec<u8>, String> {
    let scratch = scratch_dir("disrobe-native-matrix-exe");
    let dir: PathBuf = scratch.path().to_path_buf();
    let obj_path: PathBuf = dir.join(format!("{tag}_orig.o"));
    std::fs::write(&obj_path, plain_object).map_err(|e: std::io::Error| e.to_string())?;
    let mut stub_flags: Vec<&str> = compile_flags(family, shape.permit_sibling_calls);
    stub_flags.push("-c");
    let stub_out: PathBuf = dir.join(format!("{tag}_stub.o"));
    let stub_source: String = linked_stub_source(shape);
    match compile_object_reasoned(compiler, opt, &stub_flags, &stub_source, &stub_out) {
        CompileOutcome::Object(_) => {}
        CompileOutcome::Rejected(reason) => return Err(format!("stub main compile: {reason}")),
    }
    let exe: PathBuf = dir.join(format!("{tag}.exe"));
    let link_inputs: [&Path; 2] = [obj_path.as_path(), stub_out.as_path()];
    let mut link_extra: Vec<String> = Vec::new();
    if cfg!(windows) {
        if compiler_uses_msvc_linker(compiler)? {
            let exports_path: PathBuf = dir.join(format!("{tag}_exports.def"));
            let exports: String = linked_export_definition(shape);
            std::fs::write(&exports_path, exports).map_err(|e: std::io::Error| {
                format!(
                    "write linked export definition {}: {e}",
                    exports_path.display()
                )
            })?;
            link_extra.push("-Xlinker".to_owned());
            link_extra.push(format!("/DEF:{}", exports_path.display()));
        } else {
            link_extra.push("-Wl,--export-all-symbols".to_owned());
        }
    }
    let link_extra: Vec<&str> = link_extra.iter().map(String::as_str).collect();
    match link_objects_to_exe(compiler, opt, &link_extra, &link_inputs, &exe) {
        CompileOutcome::Object(bytes) => Ok(bytes),
        CompileOutcome::Rejected(reason) => Err(format!("link: {reason}")),
    }
}

fn compiler_uses_msvc_linker(compiler: &str) -> Result<bool, String> {
    static TARGETS: Mutex<BTreeMap<String, Result<bool, String>>> = Mutex::new(BTreeMap::new());
    let mut targets: std::sync::MutexGuard<'_, BTreeMap<String, Result<bool, String>>> = TARGETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    targets
        .entry(compiler.to_owned())
        .or_insert_with(|| {
            let output: disrobe_core::subprocess::CapturedOutput =
                disrobe_core::subprocess::run_captured(
                    Path::new(compiler),
                    &["-dumpmachine"],
                    std::time::Duration::from_secs(5),
                    4096,
                )
                .map_err(|error| format!("{compiler} target probe failed: {error}"))?
                .ok_or_else(|| format!("{compiler} target probe timed out"))?;
            if output.exit_code != Some(0) {
                return Err(format!(
                    "{compiler} target probe exited {:?}",
                    output.exit_code
                ));
            }
            let target: &str = std::str::from_utf8(&output.stdout)
                .map_err(|error| format!("{compiler} target is not UTF-8: {error}"))?
                .trim();
            if target.ends_with("-windows-msvc") {
                Ok(true)
            } else if target.ends_with("-mingw32") || target.ends_with("-windows-gnu") {
                Ok(false)
            } else {
                Err(format!(
                    "{compiler} has unsupported PE linker target {target}"
                ))
            }
        })
        .clone()
}

fn linked_stub_source(shape: &ShapeCase) -> String {
    let params: String = (0..shape.entry_arity)
        .map(|_: usize| "long long")
        .collect::<Vec<&str>>()
        .join(", ");
    let args: String = (0..shape.entry_arity)
        .map(|_: usize| "0")
        .collect::<Vec<&str>>()
        .join(", ");
    format!(
        "extern long long {}({params});\nint main(void){{ return (int){}({args}); }}\n",
        shape.entry, shape.entry
    )
}

fn linked_export_definition(shape: &ShapeCase) -> String {
    let names: String = shape
        .functions
        .iter()
        .copied()
        .chain(std::iter::once("main"))
        .collect::<Vec<&str>>()
        .join("\n");
    format!("EXPORTS\n{names}\n")
}

fn link_sysv_executable_and_extract(
    opt: &str,
    sysv_flags: &[&str],
    plain_sysv_object: &[u8],
    tag: &str,
) -> Result<Vec<u8>, String> {
    let scratch = scratch_dir("disrobe-native-matrix-sysv-exe");
    let dir: PathBuf = scratch.path().to_path_buf();
    let obj_path: PathBuf = dir.join(format!("{tag}_orig.o"));
    std::fs::write(&obj_path, plain_sysv_object).map_err(|e: std::io::Error| e.to_string())?;
    let stub_out: PathBuf = dir.join(format!("{tag}_stub.o"));
    let mut stub_flags: Vec<&str> = sysv_flags.to_vec();
    stub_flags.push("-c");
    match compile_object_reasoned(
        "clang",
        opt,
        &stub_flags,
        "int main(void){ return 0; }\n",
        &stub_out,
    ) {
        CompileOutcome::Object(_) => {}
        CompileOutcome::Rejected(reason) => {
            return Err(format!("sysv stub main compile: {reason}"));
        }
    }
    let exe: PathBuf = dir.join(format!("{tag}.elf"));
    let link_extra: [&str; 6] = [
        "--target=x86_64-unknown-linux-gnu",
        "-fuse-ld=lld",
        "-nostdlib",
        "-static",
        "-Wl,-e,main",
        "-w",
    ];
    match link_objects_to_exe(
        "clang",
        opt,
        &link_extra,
        &[obj_path.as_path(), stub_out.as_path()],
        &exe,
    ) {
        CompileOutcome::Object(bytes) => Ok(bytes),
        CompileOutcome::Rejected(reason) => Err(format!("sysv freestanding link: {reason}")),
    }
}

fn grade_row(task: &Task, row_seed: u64) -> MatrixRow {
    let (shape, compiler, recovery_compiler, recovery_producer, opt, abi, link_shape): &Task = task;
    let opt: &'static str = opt;
    let abi: AbiTarget = *abi;
    let link_shape: LinkShape = *link_shape;
    let recovery_compiler: Option<&CompilerId> = match abi {
        AbiTarget::MsX64 => Some(compiler),
        AbiTarget::SysV => recovery_compiler.as_ref(),
    };
    let mut row: MatrixRow = MatrixRow {
        shape: shape.shape_tag,
        reference_compiler: compiler.bin.to_owned(),
        reference_compiler_version: compiler.version.clone(),
        recovery_input_compiler: recovery_producer.as_ref().map_or_else(
            |_| "unavailable".to_owned(),
            |identity| identity.program.clone(),
        ),
        recovery_input_compiler_version: recovery_producer.as_ref().map_or_else(
            |_| "unavailable".to_owned(),
            |identity| identity.version.clone(),
        ),
        recovery_input_root: None,
        opt,
        abi: abi.tag(),
        arch: "x86_64",
        link_shape: link_shape.tag(),
        verdict: Verdict::NotGraded("ungraded".to_owned()),
        seed: Some(row_seed),
        teeth_confirmed: false,
        linked_functions_extracted: None,
    };

    if let Err(reason) = recovery_producer {
        row.verdict = Verdict::NotGraded(reason.clone());
        return row;
    }

    let Some(recovery_compiler): Option<&CompilerId> = recovery_compiler else {
        row.verdict = Verdict::NotGraded(
            "SysV recovery input requires clang, which is not available on PATH".to_owned(),
        );
        return row;
    };

    let tag: String = format!(
        "mx_{}_{}_{}_{}_{}",
        shape.shape_tag,
        compiler.bin,
        opt.trim_start_matches('-'),
        abi.tag(),
        link_shape.tag()
    );

    let plain_object: Vec<u8> = match build_original_object(
        compiler.bin,
        compiler.family,
        shape,
        opt,
        &format!("{tag}_plain"),
    ) {
        CompileOutcome::Object(bytes) => bytes,
        CompileOutcome::Rejected(reason) => {
            row.verdict = Verdict::NotGraded(reason);
            return row;
        }
    };

    let recovery_object: Vec<u8> = match build_recovery_object(
        recovery_compiler,
        abi,
        shape,
        opt,
        &format!("{tag}_recovery"),
    ) {
        CompileOutcome::Object(bytes) => bytes,
        CompileOutcome::Rejected(reason) => {
            row.verdict = Verdict::NotGraded(reason);
            return row;
        }
    };

    let object_for_recovery: Vec<u8> = match (abi, link_shape) {
        (AbiTarget::MsX64, LinkShape::ObjectInPlace) => recovery_object,
        (AbiTarget::MsX64, LinkShape::LinkedExecutable) => {
            match link_executable_and_extract(
                compiler.bin,
                compiler.family,
                shape,
                opt,
                &recovery_object,
                &tag,
            ) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    row.verdict = Verdict::NotGraded(reason);
                    return row;
                }
            }
        }
        (AbiTarget::SysV, sysv_link_shape) => {
            let mut sysv_flags: Vec<&str> = vec![
                "--target=x86_64-unknown-linux-gnu",
                "-fno-stack-protector",
                "-fcf-protection=none",
            ];
            if !shape.permit_sibling_calls {
                sysv_flags.push("-fno-optimize-sibling-calls");
            }
            match sysv_link_shape {
                LinkShape::ObjectInPlace => recovery_object,
                LinkShape::LinkedExecutable => {
                    match link_sysv_executable_and_extract(opt, &sysv_flags, &recovery_object, &tag)
                    {
                        Ok(bytes) => bytes,
                        Err(reason) => {
                            row.verdict = Verdict::NotGraded(reason);
                            return row;
                        }
                    }
                }
            }
        }
    };
    row.recovery_input_root = Some(*blake3::hash(&object_for_recovery).as_bytes());

    let linked_input: bool = matches!(link_shape, LinkShape::LinkedExecutable);
    let recovered: RecoveredProgram =
        match recover_shape(&object_for_recovery, shape, abi.as_pseudo(), linked_input) {
            RecoverOutcome::Ok(r) => {
                if linked_input {
                    row.linked_functions_extracted = Some(r.function_count);
                }
                r
            }
            RecoverOutcome::SoundRejected {
                reason,
                function_count,
            } => {
                if linked_input {
                    row.linked_functions_extracted = Some(function_count);
                }
                row.verdict = Verdict::SoundRejected(reason);
                return row;
            }
            RecoverOutcome::Prerequisite(reason) => {
                row.verdict = Verdict::NotGraded(reason);
                return row;
            }
        };

    if recovered.entry_params != shape.entry_arity
        || recovered.entry_return_width != ENTRY_RETURN_WIDTH
    {
        row.verdict = Verdict::SignatureMismatch(format!(
            "expected arity {} width {ENTRY_RETURN_WIDTH}, recovered arity {} width {}",
            shape.entry_arity, recovered.entry_params, recovered.entry_return_width
        ));
        return row;
    }

    let mut inputs: Vec<(i64, i64, i64)> = boundary_inputs(shape, row_seed);
    inputs.extend(random_inputs(shape, row_seed));

    let driver: String = build_driver(
        shape,
        &inputs,
        recovered.entry_params,
        &strip_includes(&recovered.tu),
    );

    row.verdict = verdict_for_run(
        link_and_run_reasoned(compiler.bin, &driver, &plain_object, &tag, 20),
        row_seed,
    );

    if matches!(row.verdict, Verdict::Equivalent) {
        let marker: String = format!("rec_{}(", shape.entry);
        let mutated_tu: String = corrupt_every_return(&recovered.tu, &marker).unwrap_or_else(|| {
            panic!(
                "teeth setup FAILED for shape {}: the recovered body of rec_{} contains no `return` statement to corrupt, so this row can never demonstrate a seeded-wrong rejection",
                shape.shape_tag, shape.entry
            )
        });
        let mutated_driver: String = build_driver(
            shape,
            &inputs,
            recovered.entry_params,
            &strip_includes(&mutated_tu),
        );
        let teeth_tag: String = format!("{tag}_teeth");
        match link_and_run_reasoned(compiler.bin, &mutated_driver, &plain_object, &teeth_tag, 20) {
            RunOutcome::Completed(captured) => {
                let stdout: String = String::from_utf8_lossy(&captured.stdout).into_owned();
                assert!(
                    captured.exit_code == Some(1)
                        && stdout.contains("MISMATCH")
                        && !stdout.contains("OK"),
                    "teeth FAILED for shape {}: corrupting every return in the recovered body must diverge from the original, exit_code={:?}, got: {stdout}",
                    shape.shape_tag,
                    captured.exit_code
                );
                row.teeth_confirmed = true;
            }
            RunOutcome::TimedOut { seconds } => {
                panic!(
                    "teeth harness for shape {} timed out after {seconds}s",
                    shape.shape_tag
                );
            }
            RunOutcome::ExecutionFailed(reason) | RunOutcome::Failed(reason) => {
                panic!(
                    "teeth harness for shape {} failed to build/run: {reason}",
                    shape.shape_tag
                );
            }
        }
    }

    row
}

fn compute_row_seed(
    shape: &ShapeCase,
    compiler: &str,
    opt: &str,
    abi: AbiTarget,
    link_shape: LinkShape,
) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher: std::collections::hash_map::DefaultHasher =
        std::collections::hash_map::DefaultHasher::new();
    MASTER_SEED.hash(&mut hasher);
    shape.shape_tag.hash(&mut hasher);
    compiler.hash(&mut hasher);
    opt.hash(&mut hasher);
    abi.tag().hash(&mut hasher);
    link_shape.tag().hash(&mut hasher);
    hasher.finish()
}

type Task = (
    &'static ShapeCase,
    CompilerId,
    Option<CompilerId>,
    Result<ProducerIdentity, String>,
    &'static str,
    AbiTarget,
    LinkShape,
);

const OPT_LEVELS: [&str; 6] = ["-O0", "-O1", "-O2", "-O3", "-Os", "-Og"];
const LINK_SHAPES: [LinkShape; 2] = [LinkShape::ObjectInPlace, LinkShape::LinkedExecutable];
const ABI_TARGETS: [AbiTarget; 2] = [AbiTarget::MsX64, AbiTarget::SysV];

#[test]
fn whole_function_recompile_matrix_grades_every_shape() {
    let compilers: Vec<CompilerId> = available_compilers();
    assert!(
        !compilers.is_empty(),
        "the native recompile matrix requires at least one of gcc, clang, or cc on PATH"
    );

    let mut not_graded: Vec<MatrixRow> = Vec::new();
    for shape in SHAPES {
        not_graded.push(MatrixRow {
            shape: shape.shape_tag,
            reference_compiler: "n/a".to_owned(),
            reference_compiler_version: "n/a".to_owned(),
            recovery_input_compiler: "n/a".to_owned(),
            recovery_input_compiler_version: "n/a".to_owned(),
            recovery_input_root: None,
            opt: "n/a",
            abi: "n/a",
            arch: "aarch64",
            link_shape: "n/a",
            verdict: Verdict::NotGraded(
                "aarch64 corpus rows belong to TEST-011; this matrix runs on x86-64 only"
                    .to_owned(),
            ),
            seed: None,
            teeth_confirmed: false,
            linked_functions_extracted: None,
        });
    }
    not_graded.push(MatrixRow {
        shape: "scalar_float_double",
        reference_compiler: "n/a".to_owned(),
        reference_compiler_version: "n/a".to_owned(),
        recovery_input_compiler: "n/a".to_owned(),
        recovery_input_compiler_version: "n/a".to_owned(),
        recovery_input_root: None,
        opt: "n/a",
        abi: "n/a",
        arch: "x86_64",
        link_shape: "n/a",
        verdict: Verdict::NotGraded(
            "the float and double scalar surface is graded by TEST-010, not this integer whole-function matrix"
                .to_owned(),
        ),
        seed: None,
        teeth_confirmed: false,
        linked_functions_extracted: None,
    });
    let msvc_reason: String = msvc_probe_reason().unwrap_or_else(|| {
        "cl.exe is available but this GCC-attribute-based matrix has no MSVC source/flag adapter"
            .to_owned()
    });
    not_graded.push(MatrixRow {
        shape: "any",
        reference_compiler: "cl".to_owned(),
        reference_compiler_version: "n/a".to_owned(),
        recovery_input_compiler: "cl".to_owned(),
        recovery_input_compiler_version: "n/a".to_owned(),
        recovery_input_root: None,
        opt: "n/a",
        abi: "ms_x64",
        arch: "x86_64",
        link_shape: "n/a",
        verdict: Verdict::NotGraded(msvc_reason),
        seed: None,
        teeth_confirmed: false,
        linked_functions_extracted: None,
    });

    let mut tasks: Vec<Task> = Vec::new();
    let mut producer_versions: BTreeMap<String, String> = BTreeMap::new();
    let msx64_recovery_producers: BTreeMap<&'static str, Result<ProducerIdentity, String>> =
        compilers
            .iter()
            .map(|compiler: &CompilerId| {
                (
                    compiler.bin,
                    resolve_producer_identity(compiler, AbiTarget::MsX64, &mut producer_versions),
                )
            })
            .collect();
    let sysv_recovery_compiler: Option<CompilerId> = compilers
        .iter()
        .find(|compiler: &&CompilerId| compiler.bin == "clang")
        .cloned();
    let sysv_recovery_producer: Result<ProducerIdentity, String> =
        sysv_recovery_compiler.as_ref().map_or_else(
            || Err("SysV recovery input requires clang, which is not available on PATH".to_owned()),
            |compiler: &CompilerId| {
                resolve_producer_identity(compiler, AbiTarget::SysV, &mut producer_versions)
            },
        );
    for shape in SHAPES {
        for compiler in &compilers {
            for &opt in &OPT_LEVELS {
                for &abi in &ABI_TARGETS {
                    for &link_shape in &LINK_SHAPES {
                        let recovery_compiler: Option<CompilerId> = match abi {
                            AbiTarget::MsX64 => Some(compiler.clone()),
                            AbiTarget::SysV => sysv_recovery_compiler.clone(),
                        };
                        let recovery_producer: Result<ProducerIdentity, String> = match abi {
                            AbiTarget::MsX64 => msx64_recovery_producers
                                .get(compiler.bin)
                                .cloned()
                                .unwrap_or_else(|| {
                                    Err(format!(
                                        "missing cached MS x64 recovery producer for {}",
                                        compiler.bin
                                    ))
                                }),
                            AbiTarget::SysV => sysv_recovery_producer.clone(),
                        };
                        tasks.push((
                            shape,
                            compiler.clone(),
                            recovery_compiler,
                            recovery_producer,
                            opt,
                            abi,
                            link_shape,
                        ));
                    }
                }
            }
        }
    }
    let total_tasks: usize = tasks.len();
    let indexed_tasks: Vec<(usize, Task)> = tasks.into_iter().enumerate().collect();

    let queue: Mutex<Vec<(usize, Task)>> = Mutex::new(indexed_tasks);
    let results: Mutex<Vec<(usize, MatrixRow, [u8; 32])>> =
        Mutex::new(Vec::with_capacity(total_tasks));
    let workers: usize = WORKER_COUNT
        .min(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get));

    std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                loop {
                    let next = {
                        let mut q = queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        q.pop()
                    };
                    let Some((idx, task)) = next else {
                        break;
                    };
                    let (shape, compiler, _, _, opt, abi, link_shape): &Task = &task;
                    let row_seed: u64 =
                        compute_row_seed(shape, compiler.bin, opt, *abi, *link_shape);
                    let row: MatrixRow = grade_row(&task, row_seed);
                    let hash: [u8; 32] = row_hash(&row, shape.c_source, shape.entry);
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((idx, row, hash));
                }
            });
        }
    });

    let mut graded: Vec<(usize, MatrixRow, [u8; 32])> = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    graded.sort_by_key(|(idx, _, _)| *idx);

    let expected_graded_rows: usize = SHAPES
        .len()
        .saturating_mul(compilers.len())
        .saturating_mul(OPT_LEVELS.len())
        .saturating_mul(ABI_TARGETS.len())
        .saturating_mul(LINK_SHAPES.len());
    assert_eq!(
        graded.len(),
        expected_graded_rows,
        "the matrix must retain one row for every scheduled shape/compiler/optimization/ABI/link combination"
    );
    let unique_row_keys: std::collections::BTreeSet<String> = graded
        .iter()
        .map(|(_, row, _): &(usize, MatrixRow, [u8; 32])| row_key(row))
        .collect();
    assert_eq!(
        unique_row_keys.len(),
        expected_graded_rows,
        "the matrix must retain a unique row key for every scheduled shape/compiler/optimization/ABI/link combination"
    );
    let (_, sysv_leaf, _): &(usize, MatrixRow, [u8; 32]) = graded
        .iter()
        .find(|(_, row, _)| {
            row.shape == "leaf"
                && row.reference_compiler == "clang"
                && row.opt == "-O0"
                && row.abi == "sysv"
                && row.link_shape == "linked_executable"
        })
        .expect("the linked SysV regression requires clang and lld on PATH");
    assert!(
        matches!(sysv_leaf.verdict, Verdict::Equivalent),
        "the linked SysV leaf must recover and match its native reference: {:?}",
        sysv_leaf.verdict
    );
    assert!(sysv_leaf.teeth_confirmed);

    if cfg!(windows) {
        let (_, ms_leaf, _): &(usize, MatrixRow, [u8; 32]) = graded
            .iter()
            .find(|(_, row, _)| {
                row.shape == "leaf"
                    && row.reference_compiler == "clang"
                    && row.opt == "-O0"
                    && row.abi == "ms_x64"
                    && row.link_shape == "linked_executable"
            })
            .expect("the linked MS x64 regression requires clang on PATH");
        assert!(
            matches!(ms_leaf.verdict, Verdict::Equivalent),
            "the linked MS x64 leaf must recover and match its native reference: {:?}",
            ms_leaf.verdict
        );
        assert!(ms_leaf.teeth_confirmed);
    }

    let incomplete_linked_rows: Vec<String> = graded
        .iter()
        .filter_map(|(_, row, _): &(usize, MatrixRow, [u8; 32])| {
            let expected_function_count: usize = SHAPES
                .iter()
                .find(|shape: &&ShapeCase| shape.shape_tag == row.shape)
                .expect("every scheduled row names a declared shape")
                .functions
                .len();
            (cfg!(windows)
                && row.abi == "ms_x64"
                && row.link_shape == LinkShape::LinkedExecutable.tag()
                && row.linked_functions_extracted != Some(expected_function_count))
            .then(|| row_key(row))
        })
        .collect();
    assert!(
        incomplete_linked_rows.is_empty(),
        "every scheduled linked row must reach recovery with the complete requested function inventory: {incomplete_linked_rows:?}"
    );

    let ledger_input: Vec<(MatrixRow, [u8; 32])> = graded
        .iter()
        .map(|(_, row, hash): &(usize, MatrixRow, [u8; 32])| (row.clone(), *hash))
        .collect();
    reconcile_ledger(&ledger_input).unwrap_or_else(|error: String| panic!("{error}"));

    let mut equivalent: usize = 0;
    let mut mismatched: Vec<String> = Vec::new();
    let mut sound_rejected: Vec<String> = Vec::new();
    let mut signature_mismatch: Vec<String> = Vec::new();
    let mut env_not_graded: Vec<String> = Vec::new();
    let mut shapes_seen: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    let mut shapes_with_teeth: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    let mut shapes_with_equivalent: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();

    for (_, row, _) in &graded {
        shapes_seen.insert(row.shape);
        if matches!(row.verdict, Verdict::Equivalent) {
            shapes_with_equivalent.insert(row.shape);
        }
        println!(
            "row: shape={} reference_compiler={} reference_compiler_version={:?} recovery_input_compiler={} recovery_input_compiler_version={:?} opt={} abi={} arch={} link_shape={} seed={:?} verdict={}",
            row.shape,
            row.reference_compiler,
            row.reference_compiler_version,
            row.recovery_input_compiler,
            row.recovery_input_compiler_version,
            row.opt,
            row.abi,
            row.arch,
            row.link_shape,
            row.seed,
            row.verdict.label()
        );
        if row.teeth_confirmed {
            shapes_with_teeth.insert(row.shape);
        }
        match &row.verdict {
            Verdict::Equivalent => equivalent += 1,
            Verdict::Mismatch(detail) => mismatched.push(format!("{}: {detail}", row_key(row))),
            Verdict::SoundRejected(reason) => {
                sound_rejected.push(format!("{}: {reason}", row_key(row)));
            }
            Verdict::SignatureMismatch(detail) => {
                signature_mismatch.push(format!("{}: {detail}", row_key(row)));
            }
            Verdict::NotGraded(reason) => {
                env_not_graded.push(format!("{}: {reason}", row_key(row)));
            }
        }
    }

    println!(
        "native recompile matrix: {equivalent} equivalent, {} sound-rejected, {} signature-mismatch, {} env-not-graded of {} attempted rows across {} shapes, plus {} explicit not-graded rows (aarch64/float-double/msvc)",
        sound_rejected.len(),
        signature_mismatch.len(),
        env_not_graded.len(),
        graded.len(),
        shapes_seen.len(),
        not_graded.len()
    );
    for reason in &sound_rejected {
        println!("sound-rejected: {reason}");
    }
    for reason in &signature_mismatch {
        println!("signature-mismatch: {reason}");
    }
    for reason in &env_not_graded {
        println!("env-not-graded: {reason}");
    }
    for row in &not_graded {
        if let Verdict::NotGraded(reason) = &row.verdict {
            println!("not-graded: {} ({}): {reason}", row.shape, row.arch);
        }
    }

    assert!(
        mismatched.is_empty(),
        "the native recompile matrix has UNSOUND recoveries (recovered but behaviorally wrong): {mismatched:?}"
    );
    assert_eq!(
        shapes_seen.len(),
        SHAPES.len(),
        "every declared function shape must appear in at least one graded row"
    );
    let shapes_never_equivalent: Vec<&'static str> = SHAPES
        .iter()
        .map(|s: &ShapeCase| s.shape_tag)
        .filter(|tag: &&'static str| !shapes_with_equivalent.contains(tag))
        .collect();
    for tag in &shapes_never_equivalent {
        println!(
            "ceiling: shape {tag} never reached an equivalent recovery in any row, so it has no successful baseline to inject a seeded-wrong mutation into; see its sound-rejected/signature-mismatch rows above for the real reason"
        );
    }
    let shapes_missing_teeth: Vec<&'static str> = SHAPES
        .iter()
        .map(|s: &ShapeCase| s.shape_tag)
        .filter(|tag: &&'static str| {
            shapes_with_equivalent.contains(tag) && !shapes_with_teeth.contains(tag)
        })
        .collect();
    assert!(
        shapes_missing_teeth.is_empty(),
        "every function shape that reached an equivalent recovery must have at least one row where a seeded-wrong recovery was injected and rejected; missing teeth for: {shapes_missing_teeth:?}"
    );
    assert!(
        equivalent > 0,
        "the native recompile matrix graded {} rows and found zero behaviorally equivalent recoveries; the environment likely lacks a working compiler pair",
        graded.len()
    );
}
