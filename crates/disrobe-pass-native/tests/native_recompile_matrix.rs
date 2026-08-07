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
    msvc_probe_reason, scratch_dir, strip_includes,
};
use disrobe_core::rng::seeded;
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction as LibRecoveredFunction,
    RecoveredProgram as LibRecoveredProgram, recover_program as lib_recover_program,
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
const LEDGER_FILE: &str = "native_recompile_matrix_truth.json";
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

#[derive(Debug, Clone)]
struct MatrixRow {
    shape: &'static str,
    compiler: String,
    compiler_version: String,
    opt: &'static str,
    abi: &'static str,
    arch: &'static str,
    link_shape: &'static str,
    verdict: Verdict,
    seed: Option<u64>,
    teeth_confirmed: bool,
}

fn row_key(row: &MatrixRow) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        row.shape, row.compiler, row.opt, row.abi, row.arch, row.link_shape
    )
}

fn row_hash(row: &MatrixRow, source: &str) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher: std::collections::hash_map::DefaultHasher =
        std::collections::hash_map::DefaultHasher::new();
    row_key(row).hash(&mut hasher);
    source.hash(&mut hasher);
    HARNESS_VERSION.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TruthEntry {
    input_hash: u64,
    verdict_label: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TruthLedger {
    entries: BTreeMap<String, TruthEntry>,
}

fn ledger_path() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(LEDGER_FILE)
}

fn load_ledger(path: &Path) -> TruthLedger {
    std::fs::read(path)
        .ok()
        .and_then(|bytes: Vec<u8>| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_ledger(path: &Path, ledger: &TruthLedger) {
    if let Ok(bytes) = serde_json::to_vec_pretty(ledger) {
        let _: std::io::Result<()> = std::fs::write(path, bytes);
    }
}

fn reconcile_ledger(rows: &[(MatrixRow, u64)]) {
    let path: PathBuf = ledger_path();
    let ledger_existed: bool = path.is_file();
    let mut ledger: TruthLedger = load_ledger(&path);
    if !ledger_existed {
        println!(
            "truth ledger: no prior ledger at {}; this is a first run, recording fresh truth for every row",
            path.display()
        );
    }
    let mut regressions: Vec<String> = Vec::new();
    for (row, hash) in rows {
        let key: String = row_key(row);
        if let Some(prior) = ledger.entries.get(&key)
            && prior.input_hash == *hash
            && prior.verdict_label == "equivalent"
            && row.verdict.label() != "equivalent"
        {
            regressions.push(format!(
                "{key}: was equivalent under input_hash {hash}, now {}",
                row.verdict.label()
            ));
        }
        ledger.entries.insert(
            key,
            TruthEntry {
                input_hash: *hash,
                verdict_label: row.verdict.label().to_owned(),
            },
        );
    }
    save_ledger(&path, &ledger);
    assert!(
        regressions.is_empty(),
        "truth ledger detected a regression versus the last recorded equivalence: {regressions:?}"
    );
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
}

enum RecoverOutcome {
    Ok(RecoveredProgram),
    SoundRejected(String),
}

fn recover_shape(object: &[u8], shape: &ShapeCase, abi: PseudoAbi) -> RecoverOutcome {
    let mut functions: Vec<ProgramFunction> = Vec::with_capacity(shape.functions.len());
    for &fname in shape.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, fname) else {
            return RecoverOutcome::SoundRejected(format!("{fname} symbol not located in object"));
        };
        functions.push(ProgramFunction {
            name: format!("rec_{fname}"),
            address: base,
            code,
        });
    }
    let result: LibRecoveredProgram = lib_recover_program(object, &functions, abi);
    if !result.unrecovered.is_empty() {
        let reasons: String = result
            .unrecovered
            .iter()
            .map(|u| format!("{}: {}", u.name, u.reason))
            .collect::<Vec<String>>()
            .join("; ");
        return RecoverOutcome::SoundRejected(reasons);
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 64;
    for (idx, &fname) in shape.functions.iter().enumerate() {
        let rec: &LibRecoveredFunction = &result.recovered[idx];
        tu.push_str(&strip_includes(&rec.source));
        tu.push('\n');
        if fname == shape.entry {
            entry_params = rec.params.len();
            entry_return_width = rec.return_width_bits;
        }
    }
    RecoverOutcome::Ok(RecoveredProgram {
        tu,
        entry_params,
        entry_return_width,
    })
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
    match compile_object_reasoned(
        compiler,
        opt,
        &stub_flags,
        "int main(void){ return 0; }\n",
        &stub_out,
    ) {
        CompileOutcome::Object(_) => {}
        CompileOutcome::Rejected(reason) => return Err(format!("stub main compile: {reason}")),
    }
    let exe: PathBuf = dir.join(format!("{tag}.exe"));
    match link_objects_to_exe(
        compiler,
        opt,
        &[],
        &[obj_path.as_path(), stub_out.as_path()],
        &exe,
    ) {
        CompileOutcome::Object(bytes) => Ok(bytes),
        CompileOutcome::Rejected(reason) => Err(format!("link: {reason}")),
    }
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
    match compile_object_reasoned(
        "clang",
        opt,
        sysv_flags,
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

fn grade_row(
    shape: &ShapeCase,
    compiler: &CompilerId,
    opt: &'static str,
    abi: AbiTarget,
    link_shape: LinkShape,
    row_seed: u64,
) -> MatrixRow {
    let mut row: MatrixRow = MatrixRow {
        shape: shape.shape_tag,
        compiler: compiler.bin.to_owned(),
        compiler_version: compiler.version.clone(),
        opt,
        abi: abi.tag(),
        arch: "x86_64",
        link_shape: link_shape.tag(),
        verdict: Verdict::NotGraded("ungraded".to_owned()),
        seed: Some(row_seed),
        teeth_confirmed: false,
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

    let object_for_recovery: Vec<u8> = match (abi, link_shape) {
        (AbiTarget::MsX64, LinkShape::ObjectInPlace) => plain_object.clone(),
        (AbiTarget::MsX64, LinkShape::LinkedExecutable) => {
            match link_executable_and_extract(
                compiler.bin,
                compiler.family,
                shape,
                opt,
                &plain_object,
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
            let mut sysv_object_flags: Vec<&str> = sysv_flags.clone();
            sysv_object_flags.push("-c");
            let scratch = scratch_dir("disrobe-native-matrix-sysv");
            let out: PathBuf = scratch.path().join(format!("{tag}_sysv.o"));
            let sysv_object: Vec<u8> = match compile_object_reasoned(
                "clang",
                opt,
                &sysv_object_flags,
                shape.c_source,
                &out,
            ) {
                CompileOutcome::Object(bytes) => bytes,
                CompileOutcome::Rejected(reason) => {
                    row.verdict =
                        Verdict::NotGraded(format!("sysv cross-compile via clang: {reason}"));
                    return row;
                }
            };
            match sysv_link_shape {
                LinkShape::ObjectInPlace => sysv_object,
                LinkShape::LinkedExecutable => {
                    sysv_object_flags.push("-w");
                    match link_sysv_executable_and_extract(
                        opt,
                        &sysv_object_flags,
                        &sysv_object,
                        &tag,
                    ) {
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

    let recovered: RecoveredProgram =
        match recover_shape(&object_for_recovery, shape, abi.as_pseudo()) {
            RecoverOutcome::Ok(r) => r,
            RecoverOutcome::SoundRejected(reason) => {
                row.verdict = Verdict::SoundRejected(reason);
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

    match link_and_run_reasoned(compiler.bin, &driver, &plain_object, &tag, 20) {
        RunOutcome::Ok(stdout) => {
            if stdout.contains("OK") && !stdout.contains("MISMATCH") {
                row.verdict = Verdict::Equivalent;
            } else {
                row.verdict =
                    Verdict::Mismatch(format!("seed={row_seed} stdout={}", stdout.trim()));
            }
        }
        RunOutcome::Failed(reason) => {
            row.verdict = Verdict::NotGraded(format!("link/run: {reason}"));
        }
    }

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
            RunOutcome::Ok(stdout) => {
                assert!(
                    stdout.contains("MISMATCH") && !stdout.contains("OK"),
                    "teeth FAILED for shape {}: corrupting every return in the recovered body must diverge from the original, got: {stdout}",
                    shape.shape_tag
                );
                row.teeth_confirmed = true;
            }
            RunOutcome::Failed(reason) => {
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
    &'static str,
    AbiTarget,
    LinkShape,
);

const GRADED_OPT_LEVELS: [&str; 3] = ["-O0", "-O1", "-O2"];
const LINK_SHAPES: [LinkShape; 2] = [LinkShape::ObjectInPlace, LinkShape::LinkedExecutable];
const ABI_TARGETS: [AbiTarget; 2] = [AbiTarget::MsX64, AbiTarget::SysV];

#[test]
fn whole_function_recompile_matrix_grades_every_shape() {
    let compilers: Vec<CompilerId> = available_compilers();
    if compilers.is_empty() {
        eprintln!("skipping the native recompile matrix: no gcc/clang/cc on PATH");
        return;
    }

    let mut not_graded: Vec<MatrixRow> = Vec::new();
    for shape in SHAPES {
        not_graded.push(MatrixRow {
            shape: shape.shape_tag,
            compiler: "n/a".to_owned(),
            compiler_version: "n/a".to_owned(),
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
        });
    }
    not_graded.push(MatrixRow {
        shape: "scalar_float_double",
        compiler: "n/a".to_owned(),
        compiler_version: "n/a".to_owned(),
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
    });
    if let Some(reason) = msvc_probe_reason() {
        not_graded.push(MatrixRow {
            shape: "any",
            compiler: "cl".to_owned(),
            compiler_version: "n/a".to_owned(),
            opt: "n/a",
            abi: "ms_x64",
            arch: "x86_64",
            link_shape: "n/a",
            verdict: Verdict::NotGraded(reason),
            seed: None,
            teeth_confirmed: false,
        });
    }

    let mut tasks: Vec<Task> = Vec::new();
    for shape in SHAPES {
        for compiler in &compilers {
            for &opt in &GRADED_OPT_LEVELS {
                for &abi in &ABI_TARGETS {
                    for &link_shape in &LINK_SHAPES {
                        tasks.push((shape, compiler.clone(), opt, abi, link_shape));
                    }
                }
            }
        }
    }
    let total_tasks: usize = tasks.len();
    let indexed_tasks: Vec<(usize, Task)> = tasks.into_iter().enumerate().collect();

    let queue: Mutex<Vec<(usize, Task)>> = Mutex::new(indexed_tasks);
    let results: Mutex<Vec<(usize, MatrixRow, u64)>> = Mutex::new(Vec::with_capacity(total_tasks));
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
                    let Some((idx, (shape, compiler, opt, abi, link_shape))) = next else {
                        break;
                    };
                    let row_seed: u64 = compute_row_seed(shape, compiler.bin, opt, abi, link_shape);
                    let row: MatrixRow =
                        grade_row(shape, &compiler, opt, abi, link_shape, row_seed);
                    let hash: u64 = row_hash(&row, shape.c_source);
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((idx, row, hash));
                }
            });
        }
    });

    let mut graded: Vec<(usize, MatrixRow, u64)> = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    graded.sort_by_key(|(idx, _, _)| *idx);

    let ledger_input: Vec<(MatrixRow, u64)> = graded
        .iter()
        .map(|(_, row, hash): &(usize, MatrixRow, u64)| (row.clone(), *hash))
        .collect();
    reconcile_ledger(&ledger_input);

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
            "row: shape={} compiler={} compiler_version={:?} opt={} abi={} arch={} link_shape={} seed={:?} verdict={}",
            row.shape,
            row.compiler,
            row.compiler_version,
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
