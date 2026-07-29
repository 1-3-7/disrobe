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

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};

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
}

static void binary64(uint64_t u, uint64_t v) {
    double a = fp_d_from_bits(u), b = fp_d_from_bits(v);
    check("fmaxnm_f64", u, v, 0, a64m_f64_to_bits(fpx_maxnum_f64(a, b)), a64m_f64_to_bits(a64m_maxnm_f64(a, b)));
    check("fminnm_f64", u, v, 0, a64m_f64_to_bits(fpx_minnum_f64(a, b)), a64m_f64_to_bits(a64m_minnm_f64(a, b)));
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
