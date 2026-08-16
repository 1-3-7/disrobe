#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use disrobe_pass_native::{
    LeafRecovery, RecoveredFunction, RecoveredProgram, recover_aarch64_function,
    recover_aarch64_function_with_image, recover_aarch64_program,
};

#[path = "aarch64_grade/battery.rs"]
mod battery;

use battery::fp_model;
use battery::{CASES, FP_DRIVER_HELPERS, ORACLE_FLAGS, cc, ground_truth_source, shared_prelude};

const SWEEP_FLAGS: &[&str] = &["-O2", "-fno-strict-aliasing", "-ffp-contract=off"];

const DIRECTED_F32: &str = r"static const uint32_t directed32[] = {
    0x00000000u, 0x80000000u, 0x00000001u, 0x80000001u, 0x007fffffu, 0x807fffffu,
    0x00800000u, 0x80800000u, 0x3f000000u, 0xbf000000u, 0x3f800000u, 0xbf800000u,
    0x3fc00000u, 0xbfc00000u, 0x40000000u, 0xc0000000u, 0x40200000u, 0xc0200000u,
    0x4b7fffffu, 0x4b800000u, 0xcb800000u, 0xcb7fffffu, 0x4effffffu, 0x4f000000u,
    0xcf000000u, 0xcf000001u, 0x4f7fffffu, 0x4f800000u, 0x5f000000u, 0xdf000000u,
    0x5f800000u, 0xdf800000u, 0x7f7fffffu, 0xff7fffffu, 0x7f800000u, 0xff800000u,
    0x7fc00000u, 0xffc00000u, 0x7fc00001u, 0xffc00001u, 0x7f800001u, 0xff800001u,
    0x7fbfffffu, 0xffbfffffu, 0x3f7fffffu, 0xbf7fffffu, 0x3f800001u, 0xbf800001u,
    0x477fff00u, 0x47800000u, 0x33800000u, 0xb3800000u, 0x4f000001u, 0x5effffffu
};";

const DIRECTED_F64: &str = r"static const uint64_t directed64[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x0000000000000001ull, 0x8000000000000001ull,
    0x000fffffffffffffull, 0x0010000000000000ull, 0x8010000000000000ull,
    0x3fe0000000000000ull, 0xbfe0000000000000ull, 0x3ff0000000000000ull, 0xbff0000000000000ull,
    0x3ff8000000000000ull, 0xbff8000000000000ull, 0x4000000000000000ull, 0xc000000000000000ull,
    0x4004000000000000ull, 0xc004000000000000ull, 0x4330000000000000ull, 0x4330000000000001ull,
    0x41dfffffffffffffull, 0x41e0000000000000ull, 0xc1e0000000000000ull, 0xc1e0000000000001ull,
    0x43dfffffffffffffull, 0x43e0000000000000ull, 0xc3e0000000000000ull, 0xc3e0000000000001ull,
    0x7fefffffffffffffull, 0xffefffffffffffffull, 0x7ff0000000000000ull, 0xfff0000000000000ull,
    0x7ff8000000000000ull, 0xfff8000000000000ull, 0x7ff8000000000001ull, 0xfff8000000000001ull,
    0x7ff0000000000001ull, 0xfff0000000000001ull, 0x7ff7ffffffffffffull, 0xfff7ffffffffffffull,
    0x3fefffffffffffffull, 0xbfefffffffffffffull, 0x3ff0000000000001ull, 0xbff0000000000001ull,
    0x4341c37937e07fffull, 0x43e0000000000001ull, 0x41e0000000000001ull, 0x3e70000000000000ull
};";

const HARNESS_BODY: &str = r#"
static long long checked = 0;
static long long mismatches = 0;
static long long sign_only = 0;
#define A64S_SLOTS 64
static const char *tally_op[A64S_SLOTS];
static long long tally_count[A64S_SLOTS];
static int tally_used = 0;

static void tally(const char *op) {
    int i;
    for (i = 0; i < tally_used; i++) {
        if (tally_op[i] == op) { tally_count[i]++; return; }
    }
    if (tally_used < A64S_SLOTS) {
        tally_op[tally_used] = op;
        tally_count[tally_used] = 1;
        tally_used++;
    }
}

static void report(const char *op, unsigned long long a, unsigned long long b, unsigned long long c,
                   unsigned long long helper, unsigned long long model) {
    if (mismatches < 24) {
        printf("MISMATCH %s a=%llx b=%llx c=%llx helper=%llx model=%llx\n", op, a, b, c, helper, model);
    }
    mismatches++;
    tally(op);
}

static void check(const char *op, unsigned long long a, unsigned long long b, unsigned long long c,
                  unsigned long long helper, unsigned long long model) {
    checked++;
    if (helper != model) report(op, a, b, c, helper, model);
}

static void check_host(const char *op, unsigned long long a, unsigned long long b,
                       unsigned long long helper, unsigned long long model,
                       unsigned long long default_nan, unsigned long long sign_bit) {
    checked++;
    if (helper == model) return;
    if (model == default_nan && helper == (default_nan | sign_bit)) { sign_only++; return; }
    report(op, a, b, 0, helper, model);
}

static uint64_t rng(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *state = x;
    return x;
}

static void unary32(uint32_t u) {
    float x = fp_f_from_bits(u);
    unsigned long long key = (unsigned long long)u;
    check("frintn_f32", key, 0, 0, a64m_f32_to_bits(fpx_rintn_f32(x)), a64m_f32_to_bits(a64m_rint_f32(x, 0)));
    check("frintm_f32", key, 0, 0, a64m_f32_to_bits(fpx_rintm_f32(x)), a64m_f32_to_bits(a64m_rint_f32(x, 1)));
    check("frintp_f32", key, 0, 0, a64m_f32_to_bits(fpx_rintp_f32(x)), a64m_f32_to_bits(a64m_rint_f32(x, 2)));
    check("frintz_f32", key, 0, 0, a64m_f32_to_bits(fpx_rintz_f32(x)), a64m_f32_to_bits(a64m_rint_f32(x, 3)));
    check("frinta_f32", key, 0, 0, a64m_f32_to_bits(fpx_rinta_f32(x)), a64m_f32_to_bits(a64m_rint_f32(x, 4)));
    check("fsqrt_f32", key, 0, 0, a64m_f32_to_bits(fpx_sqrt_f32(x)), a64m_f32_to_bits(a64m_sqrt_f32(x)));
    check("fcvtzs_w_f32", key, 0, 0, (uint32_t)fpx_cvtsat_i32_f32(x), (uint32_t)a64m_cvt_i32_f32(x, 3, 0));
    check("fcvtzu_w_f32", key, 0, 0, fpx_cvtsat_u32_f32(x), a64m_cvt_u32_f32(x, 3, 0));
    check("fcvtzs_x_f32", key, 0, 0, (uint64_t)fpx_cvtsat_i64_f32(x), (uint64_t)a64m_cvt_i64_f32(x, 3, 0));
    check("fcvtzu_x_f32", key, 0, 0, fpx_cvtsat_u64_f32(x), a64m_cvt_u64_f32(x, 3, 0));
    check("fcvtms_w_f32", key, 0, 0, (uint32_t)fpx_cvtsat_i32_f32(fpx_rintm_f32(x)), (uint32_t)a64m_cvt_i32_f32(x, 1, 0));
    check("fcvtps_w_f32", key, 0, 0, (uint32_t)fpx_cvtsat_i32_f32(fpx_rintp_f32(x)), (uint32_t)a64m_cvt_i32_f32(x, 2, 0));
    check("fcvtas_w_f32", key, 0, 0, (uint32_t)fpx_cvtsat_i32_f32(fpx_rinta_f32(x)), (uint32_t)a64m_cvt_i32_f32(x, 4, 0));
    check("fcvtmu_w_f32", key, 0, 0, fpx_cvtsat_u32_f32(fpx_rintm_f32(x)), a64m_cvt_u32_f32(x, 1, 0));
    check("fcvtpu_w_f32", key, 0, 0, fpx_cvtsat_u32_f32(fpx_rintp_f32(x)), a64m_cvt_u32_f32(x, 2, 0));
    check("fcvtau_w_f32", key, 0, 0, fpx_cvtsat_u32_f32(fpx_rinta_f32(x)), a64m_cvt_u32_f32(x, 4, 0));
    check("fcvtms_x_f32", key, 0, 0, (uint64_t)fpx_cvtsat_i64_f32(fpx_rintm_f32(x)), (uint64_t)a64m_cvt_i64_f32(x, 1, 0));
    check("fcvtmu_x_f32", key, 0, 0, fpx_cvtsat_u64_f32(fpx_rintm_f32(x)), a64m_cvt_u64_f32(x, 1, 0));
    check("fcvtzs_w_f32_fx16", key, 0, 0, (uint32_t)fpx_cvtsat_i32_f32(x * 0x1p16f), (uint32_t)a64m_cvt_i32_f32(x, 3, 16));
    check("fcvtzu_x_f32_fx16", key, 0, 0, fpx_cvtsat_u64_f32(x * 0x1p16f), a64m_cvt_u64_f32(x, 3, 16));
    check("fcvtzs_x_f32_fx32", key, 0, 0, (uint64_t)fpx_cvtsat_i64_f32(x * 0x1p32f), (uint64_t)a64m_cvt_i64_f32(x, 3, 32));
    check("fcvtzu_w_f32_fx32", key, 0, 0, fpx_cvtsat_u32_f32(x * 0x1p32f), a64m_cvt_u32_f32(x, 3, 32));
}

static void unary64(uint64_t u) {
    double x = fp_d_from_bits(u);
    check("frintn_f64", u, 0, 0, a64m_f64_to_bits(fpx_rintn_f64(x)), a64m_f64_to_bits(a64m_rint_f64(x, 0)));
    check("frintm_f64", u, 0, 0, a64m_f64_to_bits(fpx_rintm_f64(x)), a64m_f64_to_bits(a64m_rint_f64(x, 1)));
    check("frintp_f64", u, 0, 0, a64m_f64_to_bits(fpx_rintp_f64(x)), a64m_f64_to_bits(a64m_rint_f64(x, 2)));
    check("frintz_f64", u, 0, 0, a64m_f64_to_bits(fpx_rintz_f64(x)), a64m_f64_to_bits(a64m_rint_f64(x, 3)));
    check("frinta_f64", u, 0, 0, a64m_f64_to_bits(fpx_rinta_f64(x)), a64m_f64_to_bits(a64m_rint_f64(x, 4)));
    check("fsqrt_f64", u, 0, 0, a64m_f64_to_bits(fpx_sqrt_f64(x)), a64m_f64_to_bits(a64m_sqrt_f64(x)));
    check("fcvtzs_w_f64", u, 0, 0, (uint32_t)fpx_cvtsat_i32_f64(x), (uint32_t)a64m_cvt_i32_f64(x, 3, 0));
    check("fcvtzu_w_f64", u, 0, 0, fpx_cvtsat_u32_f64(x), a64m_cvt_u32_f64(x, 3, 0));
    check("fcvtzs_x_f64", u, 0, 0, (uint64_t)fpx_cvtsat_i64_f64(x), (uint64_t)a64m_cvt_i64_f64(x, 3, 0));
    check("fcvtzu_x_f64", u, 0, 0, fpx_cvtsat_u64_f64(x), a64m_cvt_u64_f64(x, 3, 0));
    check("fcvtms_x_f64", u, 0, 0, (uint64_t)fpx_cvtsat_i64_f64(fpx_rintm_f64(x)), (uint64_t)a64m_cvt_i64_f64(x, 1, 0));
    check("fcvtps_x_f64", u, 0, 0, (uint64_t)fpx_cvtsat_i64_f64(fpx_rintp_f64(x)), (uint64_t)a64m_cvt_i64_f64(x, 2, 0));
    check("fcvtas_x_f64", u, 0, 0, (uint64_t)fpx_cvtsat_i64_f64(fpx_rinta_f64(x)), (uint64_t)a64m_cvt_i64_f64(x, 4, 0));
    check("fcvtmu_x_f64", u, 0, 0, fpx_cvtsat_u64_f64(fpx_rintm_f64(x)), a64m_cvt_u64_f64(x, 1, 0));
    check("fcvtzs_w_f64_fx4", u, 0, 0, (uint32_t)fpx_cvtsat_i32_f64(x * 0x1p4), (uint32_t)a64m_cvt_i32_f64(x, 3, 4));
    check("fcvtzs_x_f64_fx64", u, 0, 0, (uint64_t)fpx_cvtsat_i64_f64(x * 0x1p64), (uint64_t)a64m_cvt_i64_f64(x, 3, 64));
    check("fcvtzu_x_f64_fx64", u, 0, 0, fpx_cvtsat_u64_f64(x * 0x1p64), a64m_cvt_u64_f64(x, 3, 64));
}

static void binary32(uint32_t u, uint32_t v) {
    float a = fp_f_from_bits(u), b = fp_f_from_bits(v);
    check("fmaxnm_f32", u, v, 0, a64m_f32_to_bits(fpx_maxnum_f32(a, b)), a64m_f32_to_bits(a64m_maxnm_f32(a, b)));
    check("fminnm_f32", u, v, 0, a64m_f32_to_bits(fpx_minnum_f32(a, b)), a64m_f32_to_bits(a64m_minnm_f32(a, b)));
    check("fmax_f32", u, v, 0, a64m_f32_to_bits(fpx_max_f32(a, b)), a64m_f32_to_bits(a64m_max_f32(a, b)));
    check("fmin_f32", u, v, 0, a64m_f32_to_bits(fpx_min_f32(a, b)), a64m_f32_to_bits(a64m_min_f32(a, b)));
}

static void binary64(uint64_t u, uint64_t v) {
    double a = fp_d_from_bits(u), b = fp_d_from_bits(v);
    check("fmaxnm_f64", u, v, 0, a64m_f64_to_bits(fpx_maxnum_f64(a, b)), a64m_f64_to_bits(a64m_maxnm_f64(a, b)));
    check("fminnm_f64", u, v, 0, a64m_f64_to_bits(fpx_minnum_f64(a, b)), a64m_f64_to_bits(a64m_minnm_f64(a, b)));
    check("fmax_f64", u, v, 0, a64m_f64_to_bits(fpx_max_f64(a, b)), a64m_f64_to_bits(a64m_max_f64(a, b)));
    check("fmin_f64", u, v, 0, a64m_f64_to_bits(fpx_min_f64(a, b)), a64m_f64_to_bits(a64m_min_f64(a, b)));
}

static void ternary32(uint32_t u, uint32_t v, uint32_t w) {
    float a = fp_f_from_bits(u), b = fp_f_from_bits(v), c = fp_f_from_bits(w);
    check("fmadd_f32", u, v, w, a64m_f32_to_bits(fpx_fma_f32(a, b, c)), a64m_f32_to_bits(a64m_fma_f32(a, b, c)));
}

static void ternary64(uint64_t u, uint64_t v, uint64_t w) {
    double a = fp_d_from_bits(u), b = fp_d_from_bits(v), c = fp_d_from_bits(w);
    check("fmadd_f64", u, v, w, a64m_f64_to_bits(fpx_fma_f64(a, b, c)), a64m_f64_to_bits(a64m_fma_f64(a, b, c)));
}

static void allowlist32(uint32_t u, uint32_t v) {
    float a = fp_f_from_bits(u), b = fp_f_from_bits(v);
    check_host("host_fadd_f32", u, v, a64m_f32_to_bits(a + b), a64m_f32_to_bits(a64m_arith_f32(a, b, 0)), 0x7fc00000ull, 0x80000000ull);
    check_host("host_fsub_f32", u, v, a64m_f32_to_bits(a - b), a64m_f32_to_bits(a64m_arith_f32(a, b, 1)), 0x7fc00000ull, 0x80000000ull);
    check_host("host_fmul_f32", u, v, a64m_f32_to_bits(a * b), a64m_f32_to_bits(a64m_arith_f32(a, b, 2)), 0x7fc00000ull, 0x80000000ull);
    check_host("host_fdiv_f32", u, v, a64m_f32_to_bits(a / b), a64m_f32_to_bits(a64m_arith_f32(a, b, 3)), 0x7fc00000ull, 0x80000000ull);
}

static void allowlist64(uint64_t u, uint64_t v) {
    double a = fp_d_from_bits(u), b = fp_d_from_bits(v);
    check_host("host_fadd_f64", u, v, a64m_f64_to_bits(a + b), a64m_f64_to_bits(a64m_arith_f64(a, b, 0)), 0x7ff8000000000000ull, 0x8000000000000000ull);
    check_host("host_fsub_f64", u, v, a64m_f64_to_bits(a - b), a64m_f64_to_bits(a64m_arith_f64(a, b, 1)), 0x7ff8000000000000ull, 0x8000000000000000ull);
    check_host("host_fmul_f64", u, v, a64m_f64_to_bits(a * b), a64m_f64_to_bits(a64m_arith_f64(a, b, 2)), 0x7ff8000000000000ull, 0x8000000000000000ull);
    check_host("host_fdiv_f64", u, v, a64m_f64_to_bits(a / b), a64m_f64_to_bits(a64m_arith_f64(a, b, 3)), 0x7ff8000000000000ull, 0x8000000000000000ull);
}

static int is_nan32(uint32_t u) { return (u & 0x7fffffffu) > 0x7f800000u; }
static int is_nan64(uint64_t u) { return (u & 0x7fffffffffffffffull) > 0x7ff0000000000000ull; }

static void run_directed(void) {
    int n32 = (int)(sizeof(directed32) / sizeof(directed32[0]));
    int n64 = (int)(sizeof(directed64) / sizeof(directed64[0]));
    uint64_t state = 0x243f6a8885a308d3ull;
    int i, j, k;
    for (i = 0; i < n32; i++) unary32(directed32[i]);
    for (i = 0; i < n64; i++) unary64(directed64[i]);
    for (i = 0; i < n32; i++) {
        for (j = 0; j < n32; j++) {
            binary32(directed32[i], directed32[j]);
            if (is_nan32(directed32[i]) + is_nan32(directed32[j]) < 2) allowlist32(directed32[i], directed32[j]);
        }
    }
    for (i = 0; i < n64; i++) {
        for (j = 0; j < n64; j++) {
            binary64(directed64[i], directed64[j]);
            if (is_nan64(directed64[i]) + is_nan64(directed64[j]) < 2) allowlist64(directed64[i], directed64[j]);
        }
    }
    for (i = 0; i < n32; i++) {
        for (j = 0; j < n32; j++) {
            for (k = 0; k < n32; k++) ternary32(directed32[i], directed32[j], directed32[k]);
        }
    }
    for (i = 0; i < n64; i++) {
        for (j = 0; j < n64; j++) {
            for (k = 0; k < n64; k++) ternary64(directed64[i], directed64[j], directed64[k]);
        }
    }
    for (i = 0; i < 200000; i++) {
        uint32_t a = (uint32_t)rng(&state), b = (uint32_t)rng(&state), c = (uint32_t)rng(&state);
        uint64_t d = rng(&state), e = rng(&state), f = rng(&state);
        unary32(a); unary64(d);
        binary32(a, b); binary64(d, e);
        ternary32(a, b, c); ternary64(d, e, f);
        if (is_nan32(a) + is_nan32(b) < 2) allowlist32(a, b);
        if (is_nan64(d) + is_nan64(e) < 2) allowlist64(d, e);
    }
    for (i = 0; i < n32; i++) {
        for (j = 0; j < 20000; j++) {
            uint32_t b = (uint32_t)rng(&state);
            binary32(directed32[i], b);
            binary32(b, directed32[i]);
            ternary32(directed32[i], b, (uint32_t)rng(&state));
        }
    }
    for (i = 0; i < n64; i++) {
        for (j = 0; j < 20000; j++) {
            uint64_t b = rng(&state);
            binary64(directed64[i], b);
            binary64(b, directed64[i]);
            ternary64(directed64[i], b, rng(&state));
        }
    }
}

static void run_exhaustive32(void) {
    uint64_t u;
    for (u = 0; u <= 0xffffffffull; u++) {
        unary32((uint32_t)u);
        if ((u & 0x03ffffffull) == 0ull) { printf("PROGRESS %llx\n", (unsigned long long)u); fflush(stdout); }
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'e') run_exhaustive32();
    else run_directed();
    {
        int i;
        for (i = 0; i < tally_used; i++) {
            printf("TALLY %s %lld\n", tally_op[i], tally_count[i]);
        }
    }
    printf("SWEEPDONE checked=%lld mismatches=%lld signonly=%lld\n", checked, mismatches, sign_only);
    fflush(stdout);
    return 0;
}
"#;

fn build_harness(compiler: &str, dir: &std::path::Path) -> Result<PathBuf, String> {
    let source: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         {FP_DRIVER_HELPERS}\n\
         {}\n{}\n{DIRECTED_F32}\n{DIRECTED_F64}\n{HARNESS_BODY}",
        shared_prelude(),
        fp_model::MODEL_C
    );
    let harness_c: PathBuf = dir.join("fp_semantics_sweep.c");
    std::fs::write(&harness_c, source.as_bytes()).expect("write sweep harness");
    let exe: PathBuf = dir.join(if cfg!(windows) { "sweep.exe" } else { "sweep" });
    let built: std::process::Output = Command::new(compiler)
        .args(SWEEP_FLAGS)
        .arg("-o")
        .arg(&exe)
        .arg(&harness_c)
        .output()
        .expect("invoke cc for the fp semantics sweep");
    if built.status.success() {
        Ok(exe)
    } else {
        Err(String::from_utf8_lossy(&built.stderr).into_owned())
    }
}

struct SweepResult {
    checked: i64,
    mismatches: i64,
    sign_only: i64,
    detail: Vec<String>,
}

fn run_sweep(exe: &std::path::Path, mode: &str, budget: Duration) -> SweepResult {
    let mut child: std::process::Child = Command::new(exe)
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fp semantics sweep");
    let status: Option<std::process::ExitStatus> = {
        use wait_timeout::ChildExt as _;
        child.wait_timeout(budget).expect("wait_timeout sweep")
    };
    assert!(status.is_some(), "fp semantics sweep exceeded its budget");
    let output: std::process::Output = child.wait_with_output().expect("collect sweep output");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut checked: i64 = -1;
    let mut mismatches: i64 = -1;
    let mut sign_only: i64 = -1;
    let mut detail: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("SWEEPDONE ") {
            for token in rest.split_whitespace() {
                if let Some(value) = token.strip_prefix("checked=") {
                    checked = value.parse().unwrap_or(-1);
                } else if let Some(value) = token.strip_prefix("mismatches=") {
                    mismatches = value.parse().unwrap_or(-1);
                } else if let Some(value) = token.strip_prefix("signonly=") {
                    sign_only = value.parse().unwrap_or(-1);
                }
            }
        } else if line.starts_with("MISMATCH ") || line.starts_with("TALLY ") {
            detail.push(line.to_owned());
        }
    }
    SweepResult {
        checked,
        mismatches,
        sign_only,
        detail,
    }
}

#[test]
fn reference_routes_every_strict_operation_through_the_integer_model() {
    let reference: String = ground_truth_source();
    let body: &str = reference
        .split_once("typedef unsigned int u32;")
        .expect("reference battery body")
        .1;
    for banned in fp_model::HOST_PRIMITIVES_BANNED_IN_REFERENCE {
        assert!(
            !body.contains(banned),
            "the reference battery must not express an aarch64 floating-point operation with the host primitive `{banned}`"
        );
    }
    for name in [
        "a64m_fma_f32",
        "a64m_fma_f64",
        "a64m_maxnm_f32",
        "a64m_minnm_f32",
        "a64m_maxnm_f64",
        "a64m_minnm_f64",
        "a64m_rint_f32",
        "a64m_rint_f64",
        "a64m_sqrt_f32",
        "a64m_sqrt_f64",
        "a64m_cvt_i32_f32",
        "a64m_cvt_u32_f32",
        "a64m_cvt_i64_f64",
        "a64m_cvt_u64_f64",
    ] {
        assert!(
            body.contains(name),
            "the reference battery must reach the integer model entry point `{name}`"
        );
    }
    let allowed: Vec<&str> = fp_model::HOST_ALLOWLIST
        .iter()
        .map(|entry: &fp_model::HostCoincidence| entry.operation)
        .collect();
    for operation in fp_model::STRICT_OPERATIONS {
        assert!(
            !allowed.contains(operation),
            "`{operation}` is a strict per-instruction operation and must never appear on the host allowlist"
        );
    }
}

#[test]
fn emitted_c_and_rust_reach_the_instruction_faithful_helpers() {
    let mut seen_c: usize = 0;
    let mut seen_rust: usize = 0;
    for (_, name, bytes) in CASES {
        if !matches!(*name, "fma_madd_f" | "fp_max_f" | "fp_ceil_f" | "fs_sqrt_f") {
            continue;
        }
        let Ok(recovery): Result<LeafRecovery, _> = recover_aarch64_function(bytes, 0) else {
            continue;
        };
        let helper: &str = match *name {
            "fma_madd_f" => "fpx_fma_f32",
            "fp_max_f" => "fpx_maxnum_f32",
            "fp_ceil_f" => "fpx_rintp_f32",
            _ => "fpx_sqrt_f32",
        };
        assert!(
            recovery.source.contains(helper),
            "recovered c for `{name}` must lower through `{helper}`:\n{}",
            recovery.source
        );
        seen_c += 1;
        if let Some(rust) = recovery.rust_source.as_deref() {
            assert!(
                rust.contains(helper),
                "recovered rust for `{name}` must lower through `{helper}`:\n{rust}"
            );
            seen_rust += 1;
        }
    }
    assert!(
        seen_c >= 4,
        "no corpus case exercised the c helper lowering"
    );
    assert!(
        seen_rust >= 4,
        "no corpus case exercised the rust helper lowering"
    );
}

const FMAX_PROPAGATE_PROBE_NM_F32: &[u8] = &[0x00, 0x68, 0x21, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FMAX_PROPAGATE_PROBE_PROP_F32: &[u8] = &[0x00, 0x48, 0x21, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FMAX_PROPAGATE_PROBE_NM_F64: &[u8] = &[0x00, 0x78, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FMAX_PROPAGATE_PROBE_PROP_F64: &[u8] = &[0x00, 0x58, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];

const FRINT32Z_F32: &[u8] = &[0x00, 0x40, 0x28, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT32Z_F64: &[u8] = &[0x00, 0x40, 0x68, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT32X_F32: &[u8] = &[0x00, 0xc0, 0x28, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT32X_F64: &[u8] = &[0x00, 0xc0, 0x68, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT64Z_F32: &[u8] = &[0x00, 0x40, 0x29, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT64Z_F64: &[u8] = &[0x00, 0x40, 0x69, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT64X_F32: &[u8] = &[0x00, 0xc0, 0x29, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FRINT64X_F64: &[u8] = &[0x00, 0xc0, 0x69, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];

const LDR_LITERAL_F32: &[u8] = &[0x40, 0x00, 0x00, 0x1c, 0xc0, 0x03, 0x5f, 0xd6];
const LITERAL_F32_BYTES: &[u8] = &[0x00, 0x00, 0xc0, 0x3f];
const LDR_LITERAL_F64_BACKWARD: &[u8] = &[0xc0, 0xff, 0xff, 0x5c, 0xc0, 0x03, 0x5f, 0xd6];
const LITERAL_F64_BYTES: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
const WRITES_FPCR: &[u8] = &[0x00, 0x44, 0x1b, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
const FJCVTZS_RETURN: &[u8] = &[0x00, 0x00, 0x7e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
const FJCVTZS_LIVE_FLAGS: &[u8] = &[
    0x00, 0x00, 0x7e, 0x1e, 0x20, 0x00, 0x00, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
];
const FJCVTZS_ACCEPTED_TAIL_FUNCTIONS: &[(&str, &str)] = &[
    (
        "fjcvtzs_safe_tail",
        "nop\n    mov w1, #0\n    add w1, w1, #1",
    ),
    (
        "fjcvtzs_cmn_overwrite",
        "mov w1, #0\n    cmn w1, #0\n    mov w2, w1",
    ),
    (
        "fjcvtzs_tst_overwrite",
        "mov w1, #0\n    tst w1, w1\n    mov w2, w1",
    ),
];
const FJCVTZS_REJECTED_TAIL_FUNCTIONS: &[(&str, &str)] = &[
    (
        "fjcvtzs_flag_consumer",
        "mov w1, w0\n    csel w0, w0, wzr, eq",
    ),
    (
        "fjcvtzs_control_split",
        "mov w1, w0\n    cbz w1, 1f\n    add w1, w1, #1\n1:",
    ),
];
const LITERAL_POOL_ELF: &[u8] = include_bytes!("fixtures/aarch64_recovery/literal_pool.elf");

fn recovered_fixture<'program>(
    program: &'program RecoveredProgram,
    name: &str,
) -> &'program RecoveredFunction {
    program
        .recovered
        .iter()
        .find(|function: &&RecoveredFunction| function.name == name)
        .unwrap_or_else(|| {
            panic!(
                "the toolchain-built fixture function {name} must recover: {:?}",
                program.unrecovered
            )
        })
}

fn unrecovered_reason<'program>(program: &'program RecoveredProgram, name: &str) -> &'program str {
    program
        .unrecovered
        .iter()
        .find(|function| function.name == name)
        .map_or_else(
            || panic!("the toolchain-built fixture function {name} must refuse"),
            |function| function.reason.as_str(),
        )
}

fn toolchain_fjcvtzs_dead_flags_fixture() -> &'static RecoveredProgram {
    static PROGRAM: std::sync::OnceLock<RecoveredProgram> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| {
        use std::fmt::Write as _;

        let directory: tempfile::TempDir = tempfile::tempdir().expect("aarch64 fixture scratch");
        let assembly_path: PathBuf = directory.path().join("fjcvtzs_dead_flags.s");
        let elf_path: PathBuf = directory.path().join("fjcvtzs_dead_flags.elf");
        let mut assembly: String = ".text\n.arch armv8.3-a\n".to_owned();
        for (name, tail) in FJCVTZS_ACCEPTED_TAIL_FUNCTIONS
            .iter()
            .chain(FJCVTZS_REJECTED_TAIL_FUNCTIONS)
        {
            writeln!(
                assembly,
                ".p2align 2\n.globl {name}\n.type {name},%function\n{name}:\n    fjcvtzs w0, d0\n    {tail}\n    ret\n.size {name}, .-{name}"
            )
            .expect("format aarch64 fjcvtzs fixture");
        }
        std::fs::write(&assembly_path, assembly).expect("write aarch64 fjcvtzs fixture");
        let mut build: Command = Command::new("clang");
        build
            .args([
                "--target=aarch64-unknown-linux-gnu",
                "-nostdlib",
                "-fuse-ld=lld",
                "-shared",
                "-Wl,--hash-style=both",
            ])
            .arg(&assembly_path)
            .arg("-o")
            .arg(&elf_path);
        let output: std::process::Output = run_bounded(build, "aarch64 fjcvtzs fixture build");
        assert!(
            output.status.success(),
            "aarch64 fjcvtzs fixture failed to build:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let elf: Vec<u8> = std::fs::read(&elf_path).expect("read aarch64 fjcvtzs fixture");
        recover_aarch64_program(&elf)
    })
}

#[test]
fn toolchain_built_literal_pool_fixture_reaches_program_recovery() {
    let program: RecoveredProgram = recover_aarch64_program(LITERAL_POOL_ELF);
    let f32_function: &RecoveredFunction = recovered_fixture(&program, "literal_f");
    assert!(
        f32_function.source.contains("fp_f_from_bits(0x3fc00000"),
        "the ELF image context must recover the f32 literal's exact bits:\n{}",
        f32_function.source
    );
    let f64_function: &RecoveredFunction = recovered_fixture(&program, "literal_d");
    assert!(
        f64_function
            .source
            .contains("fp_d_from_bits(0x8000000000000000ULL)"),
        "the ELF image context must recover the f64 literal's exact bits:\n{}",
        f64_function.source
    );
}

#[test]
fn scalar_fp_literal_pool_load_uses_the_image_context() {
    let recovery: LeafRecovery = recover_aarch64_function_with_image(
        LDR_LITERAL_F32,
        0,
        &|address: u64| (address == 8).then_some(LITERAL_F32_BYTES),
        &|_: u64| None,
    )
    .expect("ldr s0, #8 must recover the bounded f32 literal at image address 8");
    assert!(
        recovery.source.contains("fp_f_from_bits(0x3fc00000"),
        "the recovered C must carry the literal's exact f32 bits:\n{}",
        recovery.source
    );
    let rust: &str = recovery
        .rust_source
        .as_deref()
        .expect("the image-backed scalar literal must reach pseudo-Rust too");
    assert!(
        rust.contains("f32::from_bits(0x3fc00000u32)"),
        "the recovered Rust must carry the literal's exact f32 bits:\n{rust}"
    );
}

#[test]
fn scalar_fp_literal_pool_load_sign_extends_a_backward_f64_target() {
    let recovery: LeafRecovery = recover_aarch64_function_with_image(
        LDR_LITERAL_F64_BACKWARD,
        8,
        &|address: u64| (address == 0).then_some(LITERAL_F64_BYTES),
        &|_: u64| None,
    )
    .expect("ldr d0, #0 must sign-extend the negative literal displacement from address 8");
    assert!(
        recovery
            .source
            .contains("fp_d_from_bits(0x8000000000000000ULL)"),
        "the recovered C must preserve the backward literal's negative-zero bits:\n{}",
        recovery.source
    );
    let rust: &str = recovery
        .rust_source
        .as_deref()
        .expect("the backward f64 literal must reach pseudo-Rust too");
    assert!(
        rust.contains("f64::from_bits(0x8000000000000000u64)"),
        "the recovered Rust must preserve the backward literal's negative-zero bits:\n{rust}"
    );
}

#[test]
fn scalar_fp_literal_pool_load_rejects_missing_and_truncated_image_bytes() {
    let missing: String =
        recover_aarch64_function_with_image(LDR_LITERAL_F32, 0, &|_: u64| None, &|_: u64| None)
            .expect_err("a literal outside the available image must refuse")
            .to_string();
    assert!(
        missing.contains("literal") && missing.contains("image"),
        "the refusal must identify the unavailable literal image bytes: {missing}"
    );
    let truncated: String = recover_aarch64_function_with_image(
        LDR_LITERAL_F32,
        0,
        &|address: u64| (address == 8).then_some(&LITERAL_F32_BYTES[..3]),
        &|_: u64| None,
    )
    .expect_err("a three-byte image tail cannot satisfy an f32 literal")
    .to_string();
    assert!(
        truncated.contains("literal") && truncated.contains("truncated"),
        "the refusal must identify the bounded literal read: {truncated}"
    );
}

#[test]
fn fpcr_dependent_semantics_refuse_with_a_distinct_reason() {
    let refusal: String = recover_aarch64_function(WRITES_FPCR, 0)
        .expect_err("msr fpcr, x0 changes scalar floating-point semantics")
        .to_string();
    assert!(
        refusal.contains("FPCR-dependent scalar floating-point semantics"),
        "the refusal must name the unsupported architectural control state: {refusal}"
    );
}

#[test]
fn javascript_float_to_integer_return_recovers_with_modular_semantics() {
    let recovery: LeafRecovery = recover_aarch64_function(FJCVTZS_RETURN, 0)
        .expect("fjcvtzs w0, d0; ret has dead exactness flags and must recover");
    assert!(
        recovery.source.contains("fpx_js_i32_f64"),
        "recovered C must use exact JavaScript ToInt32 semantics:\n{}",
        recovery.source
    );
    let rust: &str = recovery
        .rust_source
        .as_deref()
        .expect("fjcvtzs must recover Rust too");
    assert!(
        rust.contains("fpx_js_i32_f64"),
        "recovered Rust must use exact JavaScript ToInt32 semantics:\n{rust}"
    );
}

#[test]
fn toolchain_built_javascript_conversions_require_a_safe_terminating_tail() {
    let program: &RecoveredProgram = toolchain_fjcvtzs_dead_flags_fixture();
    for (name, _) in FJCVTZS_ACCEPTED_TAIL_FUNCTIONS {
        let recovery: &RecoveredFunction = recovered_fixture(program, name);
        assert!(
            recovery.source.contains("fpx_js_i32_f64"),
            "{name} C must preserve JavaScript ToInt32 semantics:\n{}",
            recovery.source
        );
        let rust: &str = recovery
            .rust_source
            .as_deref()
            .unwrap_or_else(|| panic!("{name} must recover Rust"));
        assert!(
            rust.contains("fpx_js_i32_f64"),
            "{name} Rust must preserve JavaScript ToInt32 semantics:\n{rust}"
        );
    }
    for (name, _) in FJCVTZS_REJECTED_TAIL_FUNCTIONS {
        let refusal: &str = unrecovered_reason(program, name);
        assert!(
            refusal.contains("exactness flags remain live"),
            "{name} must refuse before consuming flags or splitting control flow: {refusal}"
        );
    }
}

#[test]
fn javascript_float_to_integer_executes_directed_boundaries() {
    let compiler: String = cc().expect("javascript conversion execution needs a host C compiler");
    let recovery: RecoveredFunction =
        recovered_fixture(toolchain_fjcvtzs_dead_flags_fixture(), "fjcvtzs_safe_tail").clone();
    let c_function: String =
        recovery
            .source
            .replacen(&format!(" {}(", recovery.name), " recovered(", 1);
    let directory: tempfile::TempDir = tempfile::tempdir().expect("javascript conversion scratch");
    let c_source: String = format!(
        "{c_function}\nint main(void) {{ return recovered(0.0) == 0u && recovered(-0.0) == 0u && recovered(1.75) == 1u && recovered(-1.75) == UINT32_MAX && recovered(2147483648.0) == UINT32_C(0x80000000) && recovered(4294967297.75) == 1u && recovered(-4294967297.75) == UINT32_MAX && recovered(fp_d_from_bits(UINT64_C(0x7ff8000000000001))) == 0u && recovered(fp_d_from_bits(UINT64_C(0x7ff0000000000000))) == 0u && recovered(0x1p84) == 0u ? 0 : 1; }}\n"
    );
    let c_path: PathBuf = directory.path().join("javascript_conversion.c");
    let c_exe: PathBuf = directory.path().join("javascript_conversion.exe");
    std::fs::write(&c_path, c_source).expect("write javascript conversion C");
    let mut c_build: Command = Command::new(&compiler);
    c_build
        .args(["-std=c11", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(&c_exe);
    let built: std::process::Output = run_bounded(c_build, "javascript conversion C build");
    assert!(
        built.status.success(),
        "javascript conversion C failed to build:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(
        run_bounded(Command::new(&c_exe), "javascript conversion C execution")
            .status
            .success(),
        "javascript conversion C boundary execution failed"
    );

    let rust: &str = recovery
        .rust_source
        .as_deref()
        .expect("javascript conversion must recover Rust");
    let rust_function: String = rust.replacen(
        &format!("pub fn {}(", recovery.name),
        "pub fn recovered(",
        1,
    );
    let rust_path: PathBuf = directory.path().join("javascript_conversion.rs");
    let rust_exe: PathBuf = directory.path().join("javascript_conversion_rust.exe");
    let assertions: &str = "assert_eq!(recovered(0.0) as u32, 0); assert_eq!(recovered(-0.0) as u32, 0); assert_eq!(recovered(1.75) as u32, 1); assert_eq!(recovered(-1.75) as u32, u32::MAX); assert_eq!(recovered(2_147_483_648.0) as u32, 0x8000_0000); assert_eq!(recovered(4_294_967_297.75) as u32, 1); assert_eq!(recovered(-4_294_967_297.75) as u32, u32::MAX); assert_eq!(recovered(f64::from_bits(0x7ff8_0000_0000_0001)) as u32, 0); assert_eq!(recovered(f64::INFINITY) as u32, 0); assert_eq!(recovered(2_f64.powi(84)) as u32, 0);";
    std::fs::write(
        &rust_path,
        format!("{rust_function}\n#[test]\nfn boundaries() {{ {assertions} }}\n"),
    )
    .expect("write javascript conversion Rust");
    let mut rust_build: Command = Command::new("rustc");
    rust_build
        .args(["--edition", "2024", "--test", "-D", "warnings"])
        .arg(&rust_path)
        .arg("-o")
        .arg(&rust_exe);
    let built: std::process::Output = run_bounded(rust_build, "javascript conversion Rust build");
    assert!(
        built.status.success(),
        "javascript conversion Rust failed to build:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(
        run_bounded(
            Command::new(&rust_exe),
            "javascript conversion Rust execution"
        )
        .status
        .success(),
        "javascript conversion Rust boundary execution failed"
    );
}

#[test]
fn javascript_float_to_integer_refuses_when_exactness_flags_are_live() {
    let refusal: String = recover_aarch64_function(FJCVTZS_LIVE_FLAGS, 0)
        .expect_err("fjcvtzs followed by b.eq consumes the exactness flag")
        .to_string();
    assert!(
        refusal.contains("exactness flags remain live"),
        "the refusal must name the unmodelled live flag state: {refusal}"
    );
}

#[test]
fn scalar_range_limited_rounding_recovers_through_exact_helpers() {
    for (bytes, helper) in [
        (FRINT32Z_F32, "fpx_rint32z_f32"),
        (FRINT32Z_F64, "fpx_rint32z_f64"),
        (FRINT64Z_F32, "fpx_rint64z_f32"),
        (FRINT64Z_F64, "fpx_rint64z_f64"),
    ] {
        let recovery: LeafRecovery = recover_aarch64_function(bytes, 0)
            .unwrap_or_else(|error| panic!("scalar range-limited round must recover: {error}"));
        assert!(
            recovery.source.contains(helper),
            "recovered c must call {helper}:\n{}",
            recovery.source
        );
        let rust: &str = recovery
            .rust_source
            .as_deref()
            .expect("scalar range-limited round must recover rust");
        assert!(
            rust.contains(helper),
            "recovered rust must call {helper}:\n{rust}"
        );
    }
}

#[test]
fn fpcr_selected_range_limited_rounding_refuses_instead_of_assuming_nearest() {
    for bytes in [FRINT32X_F32, FRINT32X_F64, FRINT64X_F32, FRINT64X_F64] {
        let refusal: String = recover_aarch64_function(bytes, 0)
            .expect_err("the caller's FPCR rounding mode is not statically known")
            .to_string();
        assert!(
            refusal.contains("untracked FPCR rounding mode"),
            "the refusal must identify the missing architectural state: {refusal}"
        );
    }
}

fn run_bounded(mut command: Command, label: &str) -> std::process::Output {
    let mut child: std::process::Child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let status: Option<std::process::ExitStatus> = {
        use wait_timeout::ChildExt as _;
        child
            .wait_timeout(Duration::from_secs(20))
            .unwrap_or_else(|error| panic!("wait for {label}: {error}"))
    };
    if status.is_none() {
        child
            .kill()
            .unwrap_or_else(|error| panic!("kill timed-out {label}: {error}"));
    }
    let output: std::process::Output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("collect {label}: {error}"));
    assert!(status.is_some(), "{label} exceeded its 20 second budget");
    output
}

#[test]
fn scalar_range_limited_rounding_executes_boundary_values() {
    let compiler: String = cc().expect("range-limited execution needs a host C compiler");
    let cases: [(&[u8], &str, &str); 4] = [
        (
            FRINT32Z_F32,
            "fp_f_to_bits(recovered(fp_f_from_bits(0x80000000u))) == 0x80000000u && recovered(1.75f) == 1.0f && recovered(-1.75f) == -1.0f && recovered(0x1p31f) == -0x1p31f && recovered(fp_f_from_bits(0x7f800000u)) == -0x1p31f && recovered(fp_f_from_bits(0x7fc00000u)) == -0x1p31f",
            "assert_eq!(recovered(f32::from_bits(0x8000_0000)).to_bits(), 0x8000_0000); assert_eq!(recovered(1.75), 1.0); assert_eq!(recovered(-1.75), -1.0); assert_eq!(recovered(2_147_483_648.0), -2_147_483_648.0); assert_eq!(recovered(f32::INFINITY), -2_147_483_648.0); assert_eq!(recovered(f32::NAN), -2_147_483_648.0);",
        ),
        (
            FRINT32Z_F64,
            "fp_d_to_bits(recovered(fp_d_from_bits(UINT64_C(0x8000000000000000)))) == UINT64_C(0x8000000000000000) && recovered(1.75) == 1.0 && recovered(-1.75) == -1.0 && recovered(0x1p31) == -0x1p31 && recovered(fp_d_from_bits(UINT64_C(0x7ff0000000000000))) == -0x1p31 && recovered(fp_d_from_bits(UINT64_C(0x7ff8000000000000))) == -0x1p31",
            "assert_eq!(recovered(f64::from_bits(0x8000_0000_0000_0000)).to_bits(), 0x8000_0000_0000_0000); assert_eq!(recovered(1.75), 1.0); assert_eq!(recovered(-1.75), -1.0); assert_eq!(recovered(2_147_483_648.0), -2_147_483_648.0); assert_eq!(recovered(f64::INFINITY), -2_147_483_648.0); assert_eq!(recovered(f64::NAN), -2_147_483_648.0);",
        ),
        (
            FRINT64Z_F32,
            "fp_f_to_bits(recovered(fp_f_from_bits(0x80000000u))) == 0x80000000u && recovered(1.75f) == 1.0f && recovered(-1.75f) == -1.0f && recovered(0x1p63f) == -0x1p63f && recovered(fp_f_from_bits(0x7f800000u)) == -0x1p63f && recovered(fp_f_from_bits(0x7fc00000u)) == -0x1p63f",
            "assert_eq!(recovered(f32::from_bits(0x8000_0000)).to_bits(), 0x8000_0000); assert_eq!(recovered(1.75), 1.0); assert_eq!(recovered(-1.75), -1.0); assert_eq!(recovered(9_223_372_036_854_775_808.0), -9_223_372_036_854_775_808.0); assert_eq!(recovered(f32::INFINITY), -9_223_372_036_854_775_808.0); assert_eq!(recovered(f32::NAN), -9_223_372_036_854_775_808.0);",
        ),
        (
            FRINT64Z_F64,
            "fp_d_to_bits(recovered(fp_d_from_bits(UINT64_C(0x8000000000000000)))) == UINT64_C(0x8000000000000000) && recovered(1.75) == 1.0 && recovered(-1.75) == -1.0 && recovered(0x1p63) == -0x1p63 && recovered(fp_d_from_bits(UINT64_C(0x7ff0000000000000))) == -0x1p63 && recovered(fp_d_from_bits(UINT64_C(0x7ff8000000000000))) == -0x1p63",
            "assert_eq!(recovered(f64::from_bits(0x8000_0000_0000_0000)).to_bits(), 0x8000_0000_0000_0000); assert_eq!(recovered(1.75), 1.0); assert_eq!(recovered(-1.75), -1.0); assert_eq!(recovered(9_223_372_036_854_775_808.0), -9_223_372_036_854_775_808.0); assert_eq!(recovered(f64::INFINITY), -9_223_372_036_854_775_808.0); assert_eq!(recovered(f64::NAN), -9_223_372_036_854_775_808.0);",
        ),
    ];
    let directory: tempfile::TempDir = tempfile::tempdir().expect("range-limited scratch dir");
    for (index, (bytes, c_assertion, rust_assertions)) in cases.into_iter().enumerate() {
        let recovery: LeafRecovery = recover_aarch64_function(bytes, 0)
            .unwrap_or_else(|error| panic!("recover range-limited case {index}: {error}"));
        let c_source: String = format!(
            "{}\nint main(void) {{ return {c_assertion} ? 0 : 1; }}\n",
            recovery.source
        );
        let c_path: PathBuf = directory.path().join(format!("range_{index}.c"));
        let c_exe: PathBuf = directory.path().join(format!("range_{index}.exe"));
        std::fs::write(&c_path, c_source).expect("write range-limited C source");
        let mut c_build: Command = Command::new(&compiler);
        c_build
            .args(["-std=c11", "-Werror"])
            .arg(&c_path)
            .arg("-o")
            .arg(&c_exe);
        let built: std::process::Output = run_bounded(c_build, "range-limited C build");
        assert!(
            built.status.success(),
            "range-limited C case {index} failed to build:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executed: std::process::Output =
            run_bounded(Command::new(&c_exe), "range-limited C execution");
        assert!(
            executed.status.success(),
            "range-limited C case {index} failed"
        );

        let rust_source: &str = recovery
            .rust_source
            .as_deref()
            .expect("range-limited Rust recovery");
        let rust_path: PathBuf = directory.path().join(format!("range_{index}.rs"));
        let rust_exe: PathBuf = directory.path().join(format!("range_rust_{index}.exe"));
        std::fs::write(
            &rust_path,
            format!("{rust_source}\n#[test]\nfn boundaries() {{ {rust_assertions} }}\n"),
        )
        .expect("write range-limited Rust source");
        let mut rust_build: Command = Command::new("rustc");
        rust_build
            .args(["--edition", "2024", "--test", "-D", "warnings"])
            .arg(&rust_path)
            .arg("-o")
            .arg(&rust_exe);
        let built: std::process::Output = run_bounded(rust_build, "range-limited Rust build");
        assert!(
            built.status.success(),
            "range-limited Rust case {index} failed to build:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executed: std::process::Output =
            run_bounded(Command::new(&rust_exe), "range-limited Rust execution");
        assert!(
            executed.status.success(),
            "range-limited Rust case {index} failed:\n{}",
            String::from_utf8_lossy(&executed.stdout)
        );
    }
}

#[test]
fn fmax_and_fmaxnm_decode_to_distinct_nan_semantics() {
    let nm32: LeafRecovery =
        recover_aarch64_function(FMAX_PROPAGATE_PROBE_NM_F32, 0).expect("fmaxnm s0, s0, s1");
    let prop32: LeafRecovery =
        recover_aarch64_function(FMAX_PROPAGATE_PROBE_PROP_F32, 0).expect("fmax s0, s0, s1");
    let nm64: LeafRecovery =
        recover_aarch64_function(FMAX_PROPAGATE_PROBE_NM_F64, 0).expect("fminnm d0, d0, d1");
    let prop64: LeafRecovery =
        recover_aarch64_function(FMAX_PROPAGATE_PROBE_PROP_F64, 0).expect("fmin d0, d0, d1");
    assert!(
        nm32.source.contains("fpx_maxnum_f32"),
        "fmaxnm must lower through the ignore-a-single-nan helper:\n{}",
        nm32.source
    );
    assert!(
        prop32.source.contains("fpx_max_f32") && !prop32.source.contains("fpx_maxnum_f32"),
        "fmax must lower through the nan-propagating helper, not the fmaxnm one:\n{}",
        prop32.source
    );
    assert!(
        nm64.source.contains("fpx_minnum_f64"),
        "fminnm must lower through the ignore-a-single-nan helper:\n{}",
        nm64.source
    );
    assert!(
        prop64.source.contains("fpx_min_f64") && !prop64.source.contains("fpx_minnum_f64"),
        "fmin must lower through the nan-propagating helper, not the fminnm one:\n{}",
        prop64.source
    );
    assert_ne!(
        nm32.source, prop32.source,
        "fmaxnm and fmax must recover to different source, since they diverge on a nan operand"
    );
    let nm32_rust: &str = nm32
        .rust_source
        .as_deref()
        .expect("fmaxnm recovers a pseudo-rust body too");
    let prop32_rust: &str = prop32
        .rust_source
        .as_deref()
        .expect("fmax recovers a pseudo-rust body too");
    assert!(
        nm32_rust.contains("fpx_maxnum_f32"),
        "recovered rust for fmaxnm must lower through the ignore-a-single-nan helper:\n{nm32_rust}"
    );
    assert!(
        prop32_rust.contains("fpx_max_f32") && !prop32_rust.contains("fpx_maxnum_f32"),
        "recovered rust for fmax must lower through the nan-propagating helper, not the fmaxnm one:\n{prop32_rust}"
    );
}

const VREG_PROBE_V16_V31_F32: &[u8] = &[
    0x10, 0x40, 0x20, 0x1e, 0x31, 0x40, 0x20, 0x1e, 0x10, 0x2a, 0x31, 0x1e, 0x5f, 0x40, 0x20, 0x1e,
    0x00, 0x2a, 0x3f, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
];
const VREG_PROBE_V16_V31_F64: &[u8] = &[
    0x14, 0x40, 0x60, 0x1e, 0x39, 0x40, 0x60, 0x1e, 0x94, 0x2a, 0x79, 0x1e, 0x80, 0x42, 0x60, 0x1e,
    0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn scalar_fp_registers_v16_to_v31_recover_instead_of_rejecting() {
    let f32_case: LeafRecovery = recover_aarch64_function(VREG_PROBE_V16_V31_F32, 0).expect(
        "fmov s16,s0; fmov s17,s1; fadd s16,s16,s17; fmov s31,s2; fadd s0,s16,s31; ret must recover",
    );
    assert!(
        f32_case.source.contains("x_xmm16")
            && f32_case.source.contains("x_xmm17")
            && f32_case.source.contains("x_xmm31"),
        "the recovered c must name v16, v17 and v31 through the widened register file:\n{}",
        f32_case.source
    );
    let f64_case: LeafRecovery = recover_aarch64_function(VREG_PROBE_V16_V31_F64, 0)
        .expect("fmov d20,d0; fmov d25,d1; fadd d20,d20,d25; fmov d0,d20; ret must recover");
    assert!(
        f64_case.source.contains("x_xmm20") && f64_case.source.contains("x_xmm25"),
        "the recovered c must name v20 and v25 through the widened register file:\n{}",
        f64_case.source
    );
    let f32_rust: &str = f32_case
        .rust_source
        .as_deref()
        .expect("v16..v31 recovers a pseudo-rust body too");
    assert!(
        f32_rust.contains("x_xmm16") && f32_rust.contains("x_xmm31"),
        "the recovered rust must name v16 and v31 through the widened register file:\n{f32_rust}"
    );
}

const USES_D8_ACROSS_CALL: &[u8] = &[
    0xe8, 0x0f, 0x1f, 0xfc, 0xfe, 0x07, 0x00, 0xf9, 0x28, 0x40, 0x60, 0x1e, 0x00, 0x00, 0x00, 0x94,
    0xfe, 0x07, 0x40, 0xf9, 0x00, 0x28, 0x68, 0x1e, 0xe8, 0x07, 0x41, 0xfc, 0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn callee_saved_d8_across_a_call_recovers() {
    let recovery: LeafRecovery = recover_aarch64_function(USES_D8_ACROSS_CALL, 0).expect(
        "a real clang -O1 lowering of `double f(double a, double b) { return helper(a) + b; }`, which spills b through d8 across the call to helper, must recover",
    );
    assert!(
        recovery.source.contains("x_xmm8"),
        "the callee-saved half of the register file (d8) must thread through as an ordinary local:\n{}",
        recovery.source
    );
}

const SUM9_EIGHT_REGISTER_PLUS_ONE_STACKED_FLOAT_ARG: &[u8] = &[
    0x00, 0x28, 0x21, 0x1e, 0xe1, 0x03, 0x40, 0xbd, 0x00, 0x28, 0x22, 0x1e, 0x00, 0x28, 0x23, 0x1e,
    0x00, 0x28, 0x24, 0x1e, 0x00, 0x28, 0x25, 0x1e, 0x00, 0x28, 0x26, 0x1e, 0x00, 0x28, 0x27, 0x1e,
    0x00, 0x28, 0x21, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn a_ninth_float_argument_spilled_to_the_stack_is_attributed() {
    let recovery: LeafRecovery =
        recover_aarch64_function(SUM9_EIGHT_REGISTER_PLUS_ONE_STACKED_FLOAT_ARG, 0).expect(
            "a real clang -O1 lowering of `float sum9(float a,...,float i)`, which reads the ninth argument from `[sp]`, must recover rather than abstain",
        );
    assert!(
        recovery.source.contains("x_xmm0") && recovery.source.contains("x_xmm7"),
        "all eight register-passed float arguments must thread through:\n{}",
        recovery.source
    );
    assert!(
        recovery.source.contains("r_a64_stack0"),
        "the ninth, stack-spilled float argument must be attributed rather than silently dropped:\n{}",
        recovery.source
    );
}

#[test]
#[ignore = "needs a host c compiler; grades the emitter helpers against the independent integer model on directed corner vectors plus random bit patterns"]
fn helpers_agree_with_the_integer_model_on_directed_vectors() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("SKIP fp semantics sweep: no host C compiler on PATH");
        return;
    };
    assert!(
        !ORACLE_FLAGS
            .iter()
            .any(|flag: &&str| matches!(*flag, "-ffast-math" | "-Ofast")),
        "sweep flags must preserve strict floating-point behavior"
    );
    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let exe: PathBuf = match build_harness(&compiler, dir.path()) {
        Ok(path) => path,
        Err(error) => panic!("fp semantics sweep failed to build: {error}"),
    };
    let result: SweepResult = run_sweep(&exe, "directed", Duration::from_mins(15));
    eprintln!("============ AARCH64 FP SEMANTICS SWEEP (DIRECTED) ============");
    eprintln!("comparisons          {}", result.checked);
    eprintln!("mismatches           {}", result.mismatches);
    eprintln!(
        "host default-nan sign-only divergences {}   (host multiply and divide raise a negative default nan where aarch64 raises a positive one)",
        result.sign_only
    );
    for line in &result.detail {
        eprintln!("  {line}");
    }
    eprintln!("===============================================================");
    assert!(result.checked > 0, "the sweep performed no comparison");
    assert_eq!(
        result.mismatches, 0,
        "the emitter helpers and the independent integer model must agree bit for bit"
    );
}

#[test]
#[ignore = "exhaustive 2^32 sweep over every f32 bit pattern; minutes of compute, opt-in"]
fn helpers_agree_with_the_integer_model_on_every_f32_pattern() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("SKIP exhaustive f32 sweep: no host C compiler on PATH");
        return;
    };
    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let exe: PathBuf = match build_harness(&compiler, dir.path()) {
        Ok(path) => path,
        Err(error) => panic!("fp semantics sweep failed to build: {error}"),
    };
    let result: SweepResult = run_sweep(&exe, "exhaustive", Duration::from_hours(8));
    eprintln!("=========== AARCH64 FP SEMANTICS SWEEP (EXHAUSTIVE F32) ===========");
    eprintln!("comparisons          {}", result.checked);
    eprintln!("mismatches           {}", result.mismatches);
    for line in &result.detail {
        eprintln!("  {line}");
    }
    eprintln!("===================================================================");
    assert!(
        result.checked >= 4_294_967_296,
        "the exhaustive sweep must cover every f32 bit pattern at least once"
    );
    assert_eq!(
        result.mismatches, 0,
        "the emitter helpers and the independent integer model must agree on every f32 bit pattern"
    );
}
