#![allow(dead_code, clippy::too_many_lines, clippy::redundant_pub_crate)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_pass_native::PseudoScalarType as ScalarType;
use disrobe_pass_native::pseudo_c::fp_semantics;
use wait_timeout::ChildExt as _;

#[path = "fp_model.rs"]
pub(crate) mod fp_model;

pub(crate) const CASES: &[(&str, &str, &[u8])] = &include!("../aarch64_recovery_corpus.inc");
pub(crate) const ORACLE_FLAGS: &[&str] = &[
    "-O1",
    "-funsigned-char",
    "-fno-stack-protector",
    "-fno-strict-aliasing",
    "-ffp-contract=off",
];

pub(crate) const GROUND_TRUTH_C_BODY: &str = r"
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;

#pragma clang fp contract(off)

int idx_int(int *a, int i) { return a[i]; }
unsigned idx_uint(unsigned *a, unsigned i) { return a[i]; }
long long idx_long8(long long *a, int i) { return a[i]; }
char idx_byte(char *a, int i) { return a[i]; }
int idx_two(int *a, int i, int j) { return a[i] + a[j]; }
void idx_store(int *a, int i, int v) { a[i] = v; }

int sum_int_idx(int *a, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) acc += a[i];
    return acc;
}

int find_key(const int *a, int n, int key) {
    for (int i = 0; i < n; i++) {
        if (a[i] == key) return i;
    }
    return -1;
}

int find_early(const int *a, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] < 0) return -1;
        acc += a[i];
    }
    return acc;
}

int popcount_loop(unsigned x) {
    int c = 0;
    while (x) { c += x & 1u; x >>= 1; }
    return c;
}

int clamp_sel(int a, int b, int lo, int hi) {
    int v = a > b ? a : b;
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    return v;
}

int abs_diff(int a, int b) { return a > b ? a - b : b - a; }

u64 mul_widen(u32 a, u32 b) { return (u64)a * (u64)b; }
i64 mul_widen_s(i32 a, i32 b) { return (i64)a * (i64)b; }
int div_s(int a, int b) { return a / b; }
unsigned div_u(unsigned a, unsigned b) { return a / b; }
int mod_s(int a, int b) { return a % b; }

u64 shifts(u64 x, int n) { return (x << n) | (x >> (64 - n)); }
u32 bitmix(u32 x) { x ^= x >> 16; x *= 0x7feb352du; x ^= x >> 15; return x; }
u64 mask_hi(u64 x) { return x & ~7ull; }

int str_len_manual(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

int str_cmp_manual(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

void mem_copy_manual(char *d, const char *s, int n) {
    for (int i = 0; i < n; i++) d[i] = s[i];
}

int nested_sum(int *a, int rows, int cols) {
    int acc = 0;
    for (int r = 0; r < rows; r++)
        for (int c = 0; c < cols; c++)
            acc += a[r * cols + c];
    return acc;
}

int arr_max(const int *a, int n) {
    int m = a[0];
    for (int i = 1; i < n; i++) if (a[i] > m) m = a[i];
    return m;
}

int even_count(const int *a, int n) {
    int c = 0;
    for (int i = 0; i < n; i++) if ((a[i] & 1) == 0) c++;
    return c;
}

int sw_small(int x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        case 3: return 40;
        default: return -1;
    }
}

int sw_sparse(int x) {
    switch (x) {
        case 1: return 100;
        case 7: return 200;
        case 19: return 300;
        case 45: return 400;
        default: return 0;
    }
}

struct Pt { int x; int y; };
int pt_dot(const struct Pt *p, const struct Pt *q) { return p->x * q->x + p->y * q->y; }
int pt_arr(const struct Pt *p, int i) { return p[i].x + p[i].y; }

int do_while_sum(int n) {
    int acc = 0;
    int i = 0;
    do { acc += i; i++; } while (i < n);
    return acc;
}

int and_or_cond(int a, int b, int c, int d) {
    if (a > b && c < d) return 1;
    if (a == b || c == d) return 2;
    return 3;
}

u64 ld_st_pair(u64 *a) { u64 x = a[0]; u64 y = a[1]; a[0] = y; a[1] = x; return x + y; }

int min3(int a, int b, int c) {
    int m = a < b ? a : b;
    return m < c ? m : c;
}

unsigned rotate_left(unsigned x, unsigned n) { return (x << n) | (x >> (32 - n)); }

int sign_of(int x) { return (x > 0) - (x < 0); }

u64 accum_u64(const u64 *a, int n) {
    u64 acc = 0;
    for (int i = 0; i < n; i++) acc += a[i];
    return acc;
}

int saturating_add(int a, int b) {
    long long s = (long long)a + (long long)b;
    if (s > 2147483647LL) return 2147483647;
    if (s < -2147483648LL) return -2147483648;
    return (int)s;
}

u32 clz32(u32 x) { return x == 0 ? 32u : (u32)__builtin_clz(x); }
u32 ctz32(u32 x) { return x == 0 ? 32u : (u32)__builtin_ctz(x); }
u32 bswap32(u32 x) { return __builtin_bswap32(x); }
u64 bswap64(u64 x) { return __builtin_bswap64(x); }
int abs_i32(int x) { return x < 0 ? -x : x; }
u32 bfx(u32 x) { return (x >> 5) & 0x3fu; }
u32 bfi_merge(u32 x, u32 y) { return (x & ~0xff0u) | ((y << 4) & 0xff0u); }
unsigned max_u(unsigned a, unsigned b) { return a > b ? a : b; }
unsigned clamp_u(unsigned x, unsigned hi) { return x > hi ? hi : x; }
int neg_if(int x, int c) { return c ? -x : x; }
u64 hi_mul_u(u64 a, u64 b) { return (u64)(((unsigned __int128)a * (unsigned __int128)b) >> 64); }
i64 hi_mul_s(i64 a, i64 b) { return (i64)(((__int128)a * (__int128)b) >> 64); }
u64 funnel_shift(u64 a, u64 b) { return (a << 40) | (b >> 24); }
unsigned avg_floor_u(unsigned a, unsigned b) { return (a & b) + ((a ^ b) >> 1); }
int select4(int a, int b, int c, int d) { int m = a > b ? a : b; int n = c > d ? c : d; return m > n ? m : n; }
int sat_sub(int a, int b) {
    long long s = (long long)a - (long long)b;
    if (s > 2147483647LL) return 2147483647;
    if (s < -2147483648LL) return -2147483648;
    return (int)s;
}

float fp_id_f(float x) { return x; }
double fp_id_d(double x) { return x; }
double fp_second(double a, double b) { return b; }
float fp_get(const float *a, int i) { return a[i]; }
double fp_get_d(const double *a, int i) { return a[i]; }
void fp_put(float *a, int i, float v) { a[i] = v; }
float fp_bits_gpr(unsigned x) { float f; __builtin_memcpy(&f, &x, 4); return f; }
double fp_pick3(double a, double b, double c) { return c; }
float fp_add_f(float a, float b) { return a + b; }
double fp_sub_d(double a, double b) { return a - b; }
double fp_mul_d(double a, double b) { return a * b; }
double fp_div_d(double a, double b) { return a / b; }
float fp_div_f(float a, float b) { return a / b; }
float fp_axpy(float a, float x, float y) { return a * x + y; }
int fp_to_int_s(float x) { return a64m_cvt_i32_f32(x, 3, 0); }
unsigned fp_to_uint_s(float x) { return a64m_cvt_u32_f32(x, 3, 0); }
u64 fp_to_ulong_d(double x) { return a64m_cvt_u64_f64(x, 3, 0); }
double fp_from_int(int x) { return (double)x; }
float fp_from_uint(unsigned x) { return (float)(u64)x; }
double fp_widen(float x) { return (double)x; }
float fp_narrow(double x) { return (float)x; }
double fp_iavg(const int *a, int n) {
    volatile double zero = (double)n;
    double s = zero - zero;
#pragma clang loop vectorize(disable) interleave(disable)
    for (int i = n; i > 0; i--) s += (double)a[i - 1];
    return s / (double)(n ? n : 1);
}
double fp_floor_d(double x) { return a64m_rint_f64(x, 1); }
float fp_ceil_f(float x) { return a64m_rint_f32(x, 2); }
double fp_trunc_d(double x) { return a64m_rint_f64(x, 3); }
double fp_round_d(double x) { return a64m_rint_f64(x, 4); }
double fp_rint_d(double x) { return a64m_rint_f64(x, 0); }
float fp_max_f(float a, float b) { return a64m_maxnm_f32(a, b); }
float fp_min_f(float a, float b) { return a64m_minnm_f32(a, b); }
double fp_max_d(double a, double b) { return a64m_maxnm_f64(a, b); }
double fp_min_d(double a, double b) { return a64m_minnm_f64(a, b); }
float fp_clamp_f(float x, float lo, float hi) { return a64m_minnm_f32(a64m_maxnm_f32(x, lo), hi); }
float fma_madd_f(float a, float b, float c) { return a64m_fma_f32(a, b, c); }
float fma_msub_f(float a, float b, float c) { return a64m_fma_f32(-a, b, c); }
float fma_nmadd_f(float a, float b, float c) { return a64m_fma_f32(-a, b, -c); }
float fma_nmsub_f(float a, float b, float c) { return a64m_fma_f32(a, b, -c); }
double fma_madd_d(double a, double b, double c) { return a64m_fma_f64(a, b, c); }
double fma_msub_d(double a, double b, double c) { return a64m_fma_f64(-a, b, c); }
double fma_nmadd_d(double a, double b, double c) { return a64m_fma_f64(-a, b, -c); }
double fma_nmsub_d(double a, double b, double c) { return a64m_fma_f64(a, b, -c); }
float mul_add_unfused_f(float a, float b, float c) { return a * b + c; }
double mul_add_unfused_d(double a, double b, double c) { return a * b + c; }
float sub_mul_unfused_f(float a, float b, float c) { return c - a * b; }
double sub_mul_unfused_d(double a, double b, double c) { return c - a * b; }
float fma_mixed_f(float a, float b, float c) { return a64m_fma_f32(a, b, c) + a * b; }
double fma_mixed_d(double a, double b, double c) { return a64m_fma_f64(a, b, c) + a * b; }
float fma_chained_f(float a, float b, float c) { return a64m_fma_f32(a, a, a64m_fma_f32(b, c, a)); }
double fma_chained_d(double a, double b, double c) { return a64m_fma_f64(a, a, a64m_fma_f64(b, c, a)); }
int fc_lt_f(float a, float b) { return a < b; }
int fc_le_f(float a, float b) { return a <= b; }
int fc_gt_f(float a, float b) { return a > b; }
int fc_ge_f(float a, float b) { return a >= b; }
int fc_eq_f(float a, float b) { return a == b; }
int fc_ne_f(float a, float b) { return a != b; }
int fc_nlt_f(float a, float b) { return !(a < b); }
int fc_nle_f(float a, float b) { return !(a <= b); }
int fc_ngt_f(float a, float b) { return !(a > b); }
int fc_nge_f(float a, float b) { return !(a >= b); }
int fc_isnan_f(float x) { return x != x; }
int fc_lt_d(double a, double b) { return a < b; }
int fc_le_d(double a, double b) { return a <= b; }
int fc_gt_d(double a, double b) { return a > b; }
int fc_ge_d(double a, double b) { return a >= b; }
int fc_eq_d(double a, double b) { return a == b; }
int fc_ne_d(double a, double b) { return a != b; }
int fc_nlt_d(double a, double b) { return !(a < b); }
int fc_nle_d(double a, double b) { return !(a <= b); }
int fc_ngt_d(double a, double b) { return !(a > b); }
int fc_nge_d(double a, double b) { return !(a >= b); }
int fc_isnan_d(double x) { return x != x; }
float fc_sel_f(float a, float b, float x, float y) { return a < b ? x : y; }
float fc_tmin_f(float a, float b) { return a < b ? a : b; }
float fc_tmax_f(float a, float b) { return a > b ? a : b; }
float fc_pickeq_f(float a, float b) { return a == b ? a : b; }
double fc_sel_d(double a, double b, double x, double y) { return a < b ? x : y; }
double fc_tmin_d(double a, double b) { return a < b ? a : b; }
double fc_tmax_d(double a, double b) { return a > b ? a : b; }
double fc_pickeq_d(double a, double b) { return a == b ? a : b; }
float fc_seland_f(float a, float b, float c, float d, float x, float y) { return (a < b && c < d) ? x : y; }
float fu_neg_f(float x) { return -x; }
double fu_neg_d(double x) { return -x; }
float fu_abs_f(float x) { return __builtin_fabsf(x); }
double fu_abs_d(double x) { return __builtin_fabs(x); }
float fu_nabs_f(float x) { return -__builtin_fabsf(x); }
double fu_nabs_d(double x) { return -__builtin_fabs(x); }
float fs_sqrt_f(float x) { return a64m_sqrt_f32(x); }
double fs_sqrt_d(double x) { return a64m_sqrt_f64(x); }
float fs_hypot_f(float a, float b) { return a64m_sqrt_f32(a * a + b * b); }
double fs_norm3_d(double a, double b, double c) { return a64m_sqrt_f64(a * a + b * b + c * c); }
float fs_rsqrt_f(float x) { return 1.0f / a64m_sqrt_f32(x); }
double fs_sqrt_sum_d(double a, double b) { return a64m_sqrt_f64(a) + a64m_sqrt_f64(b); }
float fs_sqrt_scaled_f(float x, float k) { return k * a64m_sqrt_f32(x); }
double fs_sqrt_diff_d(double a, double b) { return a64m_sqrt_f64(a) - b; }
float fb_ge_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (a >= b) r = x;
    return r;
}
double fb_ge_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (a >= b) r = x;
    return r;
}
float fb_le_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (a <= b) r = x;
    return r;
}
double fb_le_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (a <= b) r = x;
    return r;
}
float fb_ne_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (a != b) r = x;
    return r;
}
double fb_ne_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (a != b) r = x;
    return r;
}
float fb_nlt_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (!(a < b)) r = x;
    return r;
}
double fb_nlt_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (!(a < b)) r = x;
    return r;
}
float fb_nle_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (!(a <= b)) r = x;
    return r;
}
double fb_nle_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (!(a <= b)) r = x;
    return r;
}
float fb_ngt_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (!(a > b)) r = x;
    return r;
}
double fb_ngt_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (!(a > b)) r = x;
    return r;
}
float fb_nge_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (!(a >= b)) r = x;
    return r;
}
double fb_nge_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (!(a >= b)) r = x;
    return r;
}
float fb_uno_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (__builtin_isunordered(a, b)) r = x;
    return r;
}
double fb_uno_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (__builtin_isunordered(a, b)) r = x;
    return r;
}
float fb_ord_f(float a, float b, float x, float y) {
    volatile float r = y;
    if (!__builtin_isunordered(a, b)) r = x;
    return r;
}
double fb_ord_d(double a, double b, double x, double y) {
    volatile double r = y;
    if (!__builtin_isunordered(a, b)) r = x;
    return r;
}
float fc_selor_f(float a, float b, float c, float d, float x, float y) {
    return (a < b || c < d) ? x : y;
}
double fc_selor_d(double a, double b, double c, double d, double x, double y) {
    return (a < b || c < d) ? x : y;
}
double fc_seland_d(double a, double b, double c, double d, double x, double y) {
    return (a < b && c < d) ? x : y;
}
float fc_selor3_f(float a, float b, float c, float d, float e, float f, float x, float y) {
    return (a < b || c < d || e < f) ? x : y;
}
float fc_seland3_f(float a, float b, float c, float d, float e, float f, float x, float y) {
    return (a < b && c < d && e < f) ? x : y;
}
float fc_seland3_mix_f(float a, float b, float c, float d, float e, float f, float x, float y) {
    return (a < b && c > d && e == f) ? x : y;
}
float fb_and3_f(float a, float b, float c, float d, float e, float f, float x, float y) {
    volatile float r = y;
    if (a < b && c < d && e < f) r = x;
    return r;
}
float fp_ninth_f(float a, float b, float c, float d, float e, float f, float g, float h, float i) {
  return a + b + c + d + e + f + g + h + i;
}
double fp_ninth_d(double a, double b, double c, double d, double e, double f, double g, double h, double i) {
  return a + b + c + d + e + f + g + h + i;
}
float fp_mixed_i_then_f(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i,
                        float p, float q, float r, float s, float t, float u, float v, float w, float x) {
  return (float)(a + b + c + d + e + f + g + h + i) + p + q + r + s + t + u + v + w + x;
}
double fp_mixed_i_then_d(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i,
                         double p, double q, double r, double s, double t, double u, double v, double w, double x) {
  return (double)(a + b + c + d + e + f + g + h + i) + p + q + r + s + t + u + v + w + x;
}
float fp_mixed_f_then_i(float a, float b, float c, float d, float e, float f, float g, float h, float i,
                        u64 p, u64 q, u64 r, u64 s, u64 t, u64 u, u64 v, u64 w, u64 x) {
  return a + b + c + d + e + f + g + h + i + (float)(p + q + r + s + t + u + v + w + x);
}
double fp_mixed_d_then_i(double a, double b, double c, double d, double e, double f, double g, double h, double i,
                         u64 p, u64 q, u64 r, u64 s, u64 t, u64 u, u64 v, u64 w, u64 x) {
  return a + b + c + d + e + f + g + h + i + (double)(p + q + r + s + t + u + v + w + x);
}
unsigned rev16_w(unsigned x) { return ((x & 0xff00ff00u) >> 8) | ((x & 0x00ff00ffu) << 8); }
u64 rev16_x(u64 x) { return ((x & 0xff00ff00ff00ff00ull) >> 8) | ((x & 0x00ff00ff00ff00ffull) << 8); }
u64 rev32_x(u64 x) { return ((u64)__builtin_bswap32((unsigned)(x >> 32)) << 32) | (u64)__builtin_bswap32((unsigned)x); }
float tsel_f(float x) { return x < 2.0f ? 3.0f : 4.0f; }
double tsel_d(double x) { return x < 2.0 ? 3.0 : 4.0; }
float tsel2_f(float x) { return x > 5.0f ? 1.0f : 2.0f; }
double tsel2_d(double x) { return x > 5.0 ? 1.0 : 2.0; }
float tclamp0_f(float x) { return x < 0.0f ? 0.0f : x; }
double tclamp0_d(double x) { return x < 0.0 ? 0.0 : x; }
float tclamp1_f(float x) { return x > 1.0f ? 1.0f : x; }
double tclamp1_d(double x) { return x > 1.0 ? 1.0 : x; }
float ret1_f(void) { return 1.0f; }
float ret2_f(void) { return 2.0f; }
float ret25_f(void) { return 2.5f; }
float rethalf_f(void) { return 0.5f; }
float retn1_f(void) { return -1.0f; }
double ret1_d(void) { return 1.0; }
double ret25_d(void) { return 2.5; }
double rethalf_d(void) { return 0.5; }
double retn3_d(void) { return -3.0; }
double retn1_d(void) { return -1.0; }
float kadd_f(float x) { return x + 2.5f; }
double kadd_d(double x) { return x + 2.5; }
float kmul_f(float x) { return x * 0.5f; }
double kmul_d(double x) { return x * 0.5; }
float kmadd_f(float x) { return x * 4.0f + 2.0f; }
double kmadd_d(double x) { return x * 4.0 + 2.0; }
float ksub_f(float x) { return 1.5f - x; }
double ksub_d(double x) { return 1.5 - x; }
float fabsdiff_f(float a, float b) { return __builtin_fabsf(a - b); }
double fabsdiff_d(double a, double b) { return __builtin_fabs(a - b); }
float fnegmul_f(float a, float b) { return -(a * b); }
double fnegmul_d(double a, double b) { return -(a * b); }
float fnabsdiff_f(float a, float b) { return -__builtin_fabsf(a - b); }
double fnabsdiff_d(double a, double b) { return -__builtin_fabs(a - b); }
float fz_relu_f(float x) { return a64m_maxnm_f32(x, 0.0f); }
double fz_relu_d(double x) { return a64m_maxnm_f64(x, 0.0); }
float fz_nrelu_f(float x) { return a64m_minnm_f32(x, 0.0f); }
double fz_nrelu_d(double x) { return a64m_minnm_f64(x, 0.0); }
float fz_mulz_f(float x) { return x * 0.0f; }
double fz_mulz_d(double x) { return x * 0.0; }
float fz_zsub_f(float x) { return 0.0f - x; }
double fz_zsub_d(double x) { return 0.0 - x; }
float fz_addz_f(float x) { return x + 0.0f; }
double fz_addz_d(double x) { return x + 0.0; }
i32 fcvt_floor_s(float x) { return a64m_cvt_i32_f32(x, 1, 0); }
i32 fcvt_ceil_s(float x) { return a64m_cvt_i32_f32(x, 2, 0); }
i32 fcvt_away_s(float x) { return a64m_cvt_i32_f32(x, 4, 0); }
u32 fcvt_floor_us(float x) { return a64m_cvt_u32_f32(x, 1, 0); }
u32 fcvt_ceil_us(float x) { return a64m_cvt_u32_f32(x, 2, 0); }
u32 fcvt_away_us(float x) { return a64m_cvt_u32_f32(x, 4, 0); }
int vol_four_slots(int a) {
    volatile int p = a;
    volatile int q = a + 1;
    volatile int r = a + 2;
    volatile int s = a + 3;
    return p + q + r + s;
}
int vol_two_guards(int a, int b, int c) {
    volatile int t = a;
    if (a > b) t = b;
    if (b > c) t = c;
    return t;
}
i64 fcvt_floor_d(double x) { return a64m_cvt_i64_f64(x, 1, 0); }
i64 fcvt_ceil_d(double x) { return a64m_cvt_i64_f64(x, 2, 0); }
i64 fcvt_away_d(double x) { return a64m_cvt_i64_f64(x, 4, 0); }
u64 fcvt_floor_ud(double x) { return a64m_cvt_u64_f64(x, 1, 0); }

float fx_scvtf_f_w(int a, int b) { return (float)(a + b) / 65536.0f; }
double fx_scvtf_d_w(int a, int b) { return (double)(a + b) / 4294967296.0; }
float fx_scvtf_f_x(long long a, long long b) { return (float)(a + b) / 18446744073709551616.0f; }
double fx_scvtf_d_x(long long a, long long b) { return (double)(a + b) / 65536.0; }
float fx_ucvtf_f_w(unsigned a, unsigned b) { return (float)(a + b) / 65536.0f; }
double fx_ucvtf_d_w(unsigned a, unsigned b) { return (double)(a + b) / 2.0; }
float fx_ucvtf_f_x(u64 a, u64 b) { return (float)(a + b) / 65536.0f; }
double fx_ucvtf_d_x(u64 a, u64 b) { return (double)(a + b) / 4294967296.0; }
i32 fx_fcvtzs_w_f(float x) { return a64m_cvt_i32_f32(x, 3, 16); }
i32 fx_fcvtzs_w_d(double x) { return a64m_cvt_i32_f64(x, 3, 4); }
i64 fx_fcvtzs_x_f(float x) { return a64m_cvt_i64_f32(x, 3, 32); }
i64 fx_fcvtzs_x_d(double x) { return a64m_cvt_i64_f64(x, 3, 64); }
u32 fx_fcvtzu_w_f(float x) { return a64m_cvt_u32_f32(x, 3, 32); }
u32 fx_fcvtzu_w_d(double x) { return a64m_cvt_u32_f64(x, 3, 4); }
u64 fx_fcvtzu_x_f(float x) { return a64m_cvt_u64_f32(x, 3, 16); }
u64 fx_fcvtzu_x_d(double x) { return a64m_cvt_u64_f64(x, 3, 64); }
";

pub(crate) const EXTERNS: &str = r"struct Pt { int x; int y; };
extern int idx_int(int *a, int i);
extern unsigned idx_uint(unsigned *a, unsigned i);
extern long long idx_long8(long long *a, int i);
extern char idx_byte(char *a, int i);
extern int idx_two(int *a, int i, int j);
extern void idx_store(int *a, int i, int v);
extern int sum_int_idx(int *a, int n);
extern int find_key(const int *a, int n, int key);
extern int find_early(const int *a, int n);
extern int popcount_loop(unsigned x);
extern int clamp_sel(int a, int b, int lo, int hi);
extern int abs_diff(int a, int b);
extern unsigned long long mul_widen(unsigned a, unsigned b);
extern long long mul_widen_s(int a, int b);
extern int div_s(int a, int b);
extern unsigned div_u(unsigned a, unsigned b);
extern int mod_s(int a, int b);
extern unsigned long long shifts(unsigned long long x, int n);
extern unsigned bitmix(unsigned x);
extern unsigned long long mask_hi(unsigned long long x);
extern int str_len_manual(const char *s);
extern int str_cmp_manual(const char *a, const char *b);
extern void mem_copy_manual(char *d, const char *s, int n);
extern int nested_sum(int *a, int rows, int cols);
extern int arr_max(const int *a, int n);
extern int even_count(const int *a, int n);
extern int sw_small(int x);
extern int sw_sparse(int x);
extern int pt_dot(const struct Pt *p, const struct Pt *q);
extern int pt_arr(const struct Pt *p, int i);
extern int do_while_sum(int n);
extern int and_or_cond(int a, int b, int c, int d);
extern unsigned long long ld_st_pair(unsigned long long *a);
extern int min3(int a, int b, int c);
extern unsigned rotate_left(unsigned x, unsigned n);
extern int sign_of(int x);
extern unsigned long long accum_u64(const unsigned long long *a, int n);
extern int saturating_add(int a, int b);
extern unsigned clz32(unsigned x);
extern unsigned ctz32(unsigned x);
extern unsigned bswap32(unsigned x);
extern unsigned long long bswap64(unsigned long long x);
extern int abs_i32(int x);
extern unsigned bfx(unsigned x);
extern unsigned bfi_merge(unsigned x, unsigned y);
extern unsigned max_u(unsigned a, unsigned b);
extern unsigned clamp_u(unsigned x, unsigned hi);
extern int neg_if(int x, int c);
extern unsigned long long hi_mul_u(unsigned long long a, unsigned long long b);
extern long long hi_mul_s(long long a, long long b);
extern unsigned long long funnel_shift(unsigned long long a, unsigned long long b);
extern unsigned avg_floor_u(unsigned a, unsigned b);
extern int select4(int a, int b, int c, int d);
extern int sat_sub(int a, int b);
extern float fp_id_f(float x);
extern double fp_id_d(double x);
extern double fp_second(double a, double b);
extern float fp_get(const float *a, int i);
extern double fp_get_d(const double *a, int i);
extern void fp_put(float *a, int i, float v);
extern float fp_bits_gpr(unsigned x);
extern double fp_pick3(double a, double b, double c);
extern float fp_add_f(float a, float b);
extern double fp_sub_d(double a, double b);
extern double fp_mul_d(double a, double b);
extern double fp_div_d(double a, double b);
extern float fp_div_f(float a, float b);
extern float fp_axpy(float a, float x, float y);
extern int fp_to_int_s(float x);
extern unsigned fp_to_uint_s(float x);
extern unsigned long long fp_to_ulong_d(double x);
extern double fp_from_int(int x);
extern float fp_from_uint(unsigned x);
extern double fp_widen(float x);
extern float fp_narrow(double x);
extern double fp_iavg(const int *a, int n);
extern double fp_floor_d(double x);
extern float fp_ceil_f(float x);
extern double fp_trunc_d(double x);
extern double fp_round_d(double x);
extern double fp_rint_d(double x);
extern float fp_max_f(float a, float b);
extern float fp_min_f(float a, float b);
extern double fp_max_d(double a, double b);
extern double fp_min_d(double a, double b);
extern float fp_clamp_f(float x, float lo, float hi);
extern float fma_madd_f(float a, float b, float c);
extern float fma_msub_f(float a, float b, float c);
extern float fma_nmadd_f(float a, float b, float c);
extern float fma_nmsub_f(float a, float b, float c);
extern double fma_madd_d(double a, double b, double c);
extern double fma_msub_d(double a, double b, double c);
extern double fma_nmadd_d(double a, double b, double c);
extern double fma_nmsub_d(double a, double b, double c);
extern float mul_add_unfused_f(float a, float b, float c);
extern double mul_add_unfused_d(double a, double b, double c);
extern float sub_mul_unfused_f(float a, float b, float c);
extern double sub_mul_unfused_d(double a, double b, double c);
extern float fma_mixed_f(float a, float b, float c);
extern double fma_mixed_d(double a, double b, double c);
extern float fma_chained_f(float a, float b, float c);
extern double fma_chained_d(double a, double b, double c);
extern int fc_lt_f(float a, float b);
extern int fc_le_f(float a, float b);
extern int fc_gt_f(float a, float b);
extern int fc_ge_f(float a, float b);
extern int fc_eq_f(float a, float b);
extern int fc_ne_f(float a, float b);
extern int fc_nlt_f(float a, float b);
extern int fc_nle_f(float a, float b);
extern int fc_ngt_f(float a, float b);
extern int fc_nge_f(float a, float b);
extern int fc_isnan_f(float x);
extern int fc_lt_d(double a, double b);
extern int fc_le_d(double a, double b);
extern int fc_gt_d(double a, double b);
extern int fc_ge_d(double a, double b);
extern int fc_eq_d(double a, double b);
extern int fc_ne_d(double a, double b);
extern int fc_nlt_d(double a, double b);
extern int fc_nle_d(double a, double b);
extern int fc_ngt_d(double a, double b);
extern int fc_nge_d(double a, double b);
extern int fc_isnan_d(double x);
extern float fc_sel_f(float a, float b, float x, float y);
extern float fc_tmin_f(float a, float b);
extern float fc_tmax_f(float a, float b);
extern float fc_pickeq_f(float a, float b);
extern double fc_sel_d(double a, double b, double x, double y);
extern double fc_tmin_d(double a, double b);
extern double fc_tmax_d(double a, double b);
extern double fc_pickeq_d(double a, double b);
extern float fc_seland_f(float a, float b, float c, float d, float x, float y);
extern float fu_neg_f(float x);
extern double fu_neg_d(double x);
extern float fu_abs_f(float x);
extern double fu_abs_d(double x);
extern float fu_nabs_f(float x);
extern double fu_nabs_d(double x);
extern float fs_sqrt_f(float x);
extern double fs_sqrt_d(double x);
extern float fs_hypot_f(float a, float b);
extern double fs_norm3_d(double a, double b, double c);
extern float fs_rsqrt_f(float x);
extern double fs_sqrt_sum_d(double a, double b);
extern float fs_sqrt_scaled_f(float x, float k);
extern double fs_sqrt_diff_d(double a, double b);
extern float fb_ge_f(float a, float b, float x, float y);
extern float fb_le_f(float a, float b, float x, float y);
extern float fb_ne_f(float a, float b, float x, float y);
extern float fb_nlt_f(float a, float b, float x, float y);
extern float fb_nle_f(float a, float b, float x, float y);
extern float fb_ngt_f(float a, float b, float x, float y);
extern float fb_nge_f(float a, float b, float x, float y);
extern float fb_uno_f(float a, float b, float x, float y);
extern double fb_uno_d(double a, double b, double x, double y);
extern float fb_ord_f(float a, float b, float x, float y);
extern double fb_ge_d(double a, double b, double x, double y);
extern double fb_le_d(double a, double b, double x, double y);
extern double fb_ne_d(double a, double b, double x, double y);
extern double fb_nlt_d(double a, double b, double x, double y);
extern double fb_nle_d(double a, double b, double x, double y);
extern double fb_ngt_d(double a, double b, double x, double y);
extern double fb_nge_d(double a, double b, double x, double y);
extern double fb_ord_d(double a, double b, double x, double y);
extern float fc_selor_f(float a, float b, float c, float d, float x, float y);
extern double fc_selor_d(double a, double b, double c, double d, double x, double y);
extern double fc_seland_d(double a, double b, double c, double d, double x, double y);
extern float fc_selor3_f(float a, float b, float c, float d, float e, float f, float x, float y);
extern float fc_seland3_f(float a, float b, float c, float d, float e, float f, float x, float y);
extern float fc_seland3_mix_f(float a, float b, float c, float d, float e, float f, float x, float y);
extern float fb_and3_f(float a, float b, float c, float d, float e, float f, float x, float y);
extern float fp_ninth_f(float a, float b, float c, float d, float e, float f, float g, float h, float i);
extern double fp_ninth_d(double a, double b, double c, double d, double e, double f, double g, double h, double i);
extern float fp_mixed_i_then_f(unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f, unsigned long long g, unsigned long long h, unsigned long long i, float p, float q, float r, float s, float t, float u, float v, float w, float x);
extern double fp_mixed_i_then_d(unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f, unsigned long long g, unsigned long long h, unsigned long long i, double p, double q, double r, double s, double t, double u, double v, double w, double x);
extern float fp_mixed_f_then_i(float a, float b, float c, float d, float e, float f, float g, float h, float i, unsigned long long p, unsigned long long q, unsigned long long r, unsigned long long s, unsigned long long t, unsigned long long u, unsigned long long v, unsigned long long w, unsigned long long x);
extern double fp_mixed_d_then_i(double a, double b, double c, double d, double e, double f, double g, double h, double i, unsigned long long p, unsigned long long q, unsigned long long r, unsigned long long s, unsigned long long t, unsigned long long u, unsigned long long v, unsigned long long w, unsigned long long x);
extern unsigned rev16_w(unsigned x);
extern unsigned long long rev16_x(unsigned long long x);
extern unsigned long long rev32_x(unsigned long long x);
extern float tsel_f(float x);
extern double tsel_d(double x);
extern float tsel2_f(float x);
extern double tsel2_d(double x);
extern float tclamp0_f(float x);
extern double tclamp0_d(double x);
extern float tclamp1_f(float x);
extern double tclamp1_d(double x);
extern float ret1_f(void);
extern float ret2_f(void);
extern float ret25_f(void);
extern float rethalf_f(void);
extern float retn1_f(void);
extern double ret1_d(void);
extern double ret25_d(void);
extern double rethalf_d(void);
extern double retn3_d(void);
extern double retn1_d(void);
extern float kadd_f(float x);
extern double kadd_d(double x);
extern float kmul_f(float x);
extern double kmul_d(double x);
extern float kmadd_f(float x);
extern double kmadd_d(double x);
extern float ksub_f(float x);
extern double ksub_d(double x);
extern float fabsdiff_f(float a, float b);
extern double fabsdiff_d(double a, double b);
extern float fnegmul_f(float a, float b);
extern double fnegmul_d(double a, double b);
extern float fnabsdiff_f(float a, float b);
extern double fnabsdiff_d(double a, double b);
extern float fz_relu_f(float x);
extern double fz_relu_d(double x);
extern float fz_nrelu_f(float x);
extern double fz_nrelu_d(double x);
extern float fz_mulz_f(float x);
extern double fz_mulz_d(double x);
extern float fz_zsub_f(float x);
extern double fz_zsub_d(double x);
extern float fz_addz_f(float x);
extern double fz_addz_d(double x);
extern int fcvt_floor_s(float x);
extern int fcvt_ceil_s(float x);
extern int fcvt_away_s(float x);
extern unsigned fcvt_floor_us(float x);
extern unsigned fcvt_ceil_us(float x);
extern unsigned fcvt_away_us(float x);
extern long long fcvt_floor_d(double x);
extern long long fcvt_ceil_d(double x);
extern long long fcvt_away_d(double x);
extern unsigned long long fcvt_floor_ud(double x);
extern int vol_four_slots(int a);
extern int vol_two_guards(int a, int b, int c);
extern float fx_scvtf_f_w(int a, int b);
extern double fx_scvtf_d_w(int a, int b);
extern float fx_scvtf_f_x(long long a, long long b);
extern double fx_scvtf_d_x(long long a, long long b);
extern float fx_ucvtf_f_w(unsigned a, unsigned b);
extern double fx_ucvtf_d_w(unsigned a, unsigned b);
extern float fx_ucvtf_f_x(unsigned long long a, unsigned long long b);
extern double fx_ucvtf_d_x(unsigned long long a, unsigned long long b);
extern int fx_fcvtzs_w_f(float x);
extern int fx_fcvtzs_w_d(double x);
extern long long fx_fcvtzs_x_f(float x);
extern long long fx_fcvtzs_x_d(double x);
extern unsigned fx_fcvtzu_w_f(float x);
extern unsigned fx_fcvtzu_w_d(double x);
extern unsigned long long fx_fcvtzu_x_f(float x);
extern unsigned long long fx_fcvtzu_x_d(double x);
";

pub(crate) fn cc() -> Option<String> {
    for candidate in ["gcc", "clang", "cc"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

#[derive(Clone, Copy)]
pub(crate) struct FpExpectation {
    pub(crate) params: &'static [ScalarType],
    pub(crate) returns: Option<ScalarType>,
    pub(crate) return_width_bits: u32,
}

pub(crate) fn fp_expectation(name: &str) -> Option<FpExpectation> {
    let expectation: FpExpectation = match name {
        "fp_id_f" | "fp_ceil_f" | "fu_neg_f" | "fu_abs_f" | "fu_nabs_f" | "fz_relu_f"
        | "fz_nrelu_f" | "fz_mulz_f" | "fz_zsub_f" | "fz_addz_f" | "kadd_f" | "kmul_f"
        | "kmadd_f" | "ksub_f" | "tclamp0_f" | "tclamp1_f" | "tsel_f" | "tsel2_f" | "fs_sqrt_f"
        | "fs_rsqrt_f" => FpExpectation {
            params: &[ScalarType::Float],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_id_d" | "fp_floor_d" | "fp_trunc_d" | "fp_round_d" | "fp_rint_d" | "fu_neg_d"
        | "fu_abs_d" | "fu_nabs_d" | "fz_relu_d" | "fz_nrelu_d" | "fz_mulz_d" | "fz_zsub_d"
        | "fz_addz_d" | "kadd_d" | "kmul_d" | "kmadd_d" | "ksub_d" | "tclamp0_d" | "tclamp1_d"
        | "tsel_d" | "tsel2_d" | "fs_sqrt_d" => FpExpectation {
            params: &[ScalarType::Double],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_second" | "fp_sub_d" | "fp_mul_d" | "fp_div_d" | "fp_max_d" | "fp_min_d"
        | "fc_tmin_d" | "fc_tmax_d" | "fc_pickeq_d" | "fabsdiff_d" | "fnegmul_d"
        | "fnabsdiff_d" | "fs_sqrt_sum_d" | "fs_sqrt_diff_d" => FpExpectation {
            params: &[ScalarType::Double, ScalarType::Double],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_get" | "fx_scvtf_f_w" | "fx_scvtf_f_x" | "fx_ucvtf_f_w" | "fx_ucvtf_f_x" => {
            FpExpectation {
                params: &[ScalarType::Int, ScalarType::Int],
                returns: Some(ScalarType::Float),
                return_width_bits: 32,
            }
        }
        "fp_get_d" | "fp_iavg" | "fx_scvtf_d_w" | "fx_scvtf_d_x" | "fx_ucvtf_d_w"
        | "fx_ucvtf_d_x" => FpExpectation {
            params: &[ScalarType::Int, ScalarType::Int],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_put" => FpExpectation {
            params: &[ScalarType::Float, ScalarType::Int, ScalarType::Int],
            returns: None,
            return_width_bits: 0,
        },
        "fp_bits_gpr" | "fp_from_uint" => FpExpectation {
            params: &[ScalarType::Int],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_pick3" | "fma_madd_d" | "fma_msub_d" | "fma_nmadd_d" | "fma_nmsub_d"
        | "mul_add_unfused_d" | "sub_mul_unfused_d" | "fma_mixed_d" | "fma_chained_d"
        | "fs_norm3_d" => FpExpectation {
            params: &[ScalarType::Double, ScalarType::Double, ScalarType::Double],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_add_f" | "fp_div_f" | "fp_max_f" | "fp_min_f" | "fc_tmin_f" | "fc_tmax_f"
        | "fc_pickeq_f" | "fabsdiff_f" | "fnegmul_f" | "fnabsdiff_f" | "fs_hypot_f"
        | "fs_sqrt_scaled_f" => FpExpectation {
            params: &[ScalarType::Float, ScalarType::Float],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_axpy" | "fp_clamp_f" | "fma_madd_f" | "fma_msub_f" | "fma_nmadd_f" | "fma_nmsub_f"
        | "mul_add_unfused_f" | "sub_mul_unfused_f" | "fma_mixed_f" | "fma_chained_f" => {
            FpExpectation {
                params: &[ScalarType::Float, ScalarType::Float, ScalarType::Float],
                returns: Some(ScalarType::Float),
                return_width_bits: 32,
            }
        }
        "fp_to_int_s" | "fp_to_uint_s" | "fc_isnan_f" | "fcvt_floor_s" | "fcvt_ceil_s"
        | "fcvt_away_s" | "fcvt_floor_us" | "fcvt_ceil_us" | "fcvt_away_us" | "fx_fcvtzs_w_f"
        | "fx_fcvtzu_w_f" => FpExpectation {
            params: &[ScalarType::Float],
            returns: None,
            return_width_bits: 32,
        },
        "fp_to_ulong_d" | "fcvt_floor_d" | "fcvt_ceil_d" | "fcvt_away_d" | "fcvt_floor_ud"
        | "fx_fcvtzs_x_d" | "fx_fcvtzu_x_d" => FpExpectation {
            params: &[ScalarType::Double],
            returns: None,
            return_width_bits: 64,
        },
        "fp_from_int" => FpExpectation {
            params: &[ScalarType::Int],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_widen" => FpExpectation {
            params: &[ScalarType::Float],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_narrow" => FpExpectation {
            params: &[ScalarType::Double],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fc_lt_f" | "fc_le_f" | "fc_gt_f" | "fc_ge_f" | "fc_eq_f" | "fc_ne_f" | "fc_nlt_f"
        | "fc_nle_f" | "fc_ngt_f" | "fc_nge_f" => FpExpectation {
            params: &[ScalarType::Float, ScalarType::Float],
            returns: None,
            return_width_bits: 32,
        },
        "fc_lt_d" | "fc_le_d" | "fc_gt_d" | "fc_ge_d" | "fc_eq_d" | "fc_ne_d" | "fc_nlt_d"
        | "fc_nle_d" | "fc_ngt_d" | "fc_nge_d" => FpExpectation {
            params: &[ScalarType::Double, ScalarType::Double],
            returns: None,
            return_width_bits: 32,
        },
        "fc_isnan_d" | "fx_fcvtzs_w_d" | "fx_fcvtzu_w_d" => FpExpectation {
            params: &[ScalarType::Double],
            returns: None,
            return_width_bits: 32,
        },
        "fc_sel_f" | "fb_ge_f" | "fb_le_f" | "fb_ne_f" | "fb_nlt_f" | "fb_nle_f" | "fb_ngt_f"
        | "fb_nge_f" | "fb_ord_f" | "fb_uno_f" => FpExpectation {
            params: &[
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
            ],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fc_sel_d" | "fb_ge_d" | "fb_le_d" | "fb_ne_d" | "fb_nlt_d" | "fb_nle_d" | "fb_ngt_d"
        | "fb_nge_d" | "fb_ord_d" | "fb_uno_d" => FpExpectation {
            params: &[
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
            ],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fc_seland_f" | "fc_selor_f" => FpExpectation {
            params: &[
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
            ],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fc_selor_d" | "fc_seland_d" => FpExpectation {
            params: &[
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
            ],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fc_selor3_f" | "fc_seland3_f" | "fc_seland3_mix_f" | "fb_and3_f" => FpExpectation {
            params: &[
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
            ],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_ninth_f" => FpExpectation {
            params: &[ScalarType::Float; 9],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_ninth_d" => FpExpectation {
            params: &[ScalarType::Double; 9],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_mixed_i_then_f" => FpExpectation {
            params: &[
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
            ],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_mixed_i_then_d" => FpExpectation {
            params: &[
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
            ],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fp_mixed_f_then_i" => FpExpectation {
            params: &[
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Float,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
            ],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "fp_mixed_d_then_i" => FpExpectation {
            params: &[
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
                ScalarType::Int,
            ],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        "fx_fcvtzs_x_f" | "fx_fcvtzu_x_f" => FpExpectation {
            params: &[ScalarType::Float],
            returns: None,
            return_width_bits: 64,
        },
        "ret1_f" | "ret2_f" | "ret25_f" | "rethalf_f" | "retn1_f" => FpExpectation {
            params: &[],
            returns: Some(ScalarType::Float),
            return_width_bits: 32,
        },
        "ret1_d" | "ret25_d" | "rethalf_d" | "retn3_d" | "retn1_d" => FpExpectation {
            params: &[],
            returns: Some(ScalarType::Double),
            return_width_bits: 64,
        },
        _ => return None,
    };
    Some(expectation)
}
pub(crate) fn expected_arity(name: &str) -> Option<usize> {
    let arity: usize = match name {
        "popcount_loop" | "bitmix" | "mask_hi" | "str_len_manual" | "sw_small" | "sw_sparse"
        | "do_while_sum" | "ld_st_pair" | "sign_of" | "clz32" | "ctz32" | "bswap32" | "bswap64"
        | "abs_i32" | "bfx" | "rev16_w" | "rev16_x" | "rev32_x" | "vol_four_slots" => 1,
        "idx_int" | "idx_uint" | "idx_long8" | "idx_byte" | "sum_int_idx" | "find_early"
        | "abs_diff" | "mul_widen" | "mul_widen_s" | "div_s" | "div_u" | "mod_s" | "shifts"
        | "str_cmp_manual" | "arr_max" | "even_count" | "pt_dot" | "pt_arr" | "rotate_left"
        | "accum_u64" | "saturating_add" | "bfi_merge" | "max_u" | "clamp_u" | "neg_if"
        | "hi_mul_u" | "hi_mul_s" | "funnel_shift" | "avg_floor_u" | "sat_sub" => 2,
        "idx_two" | "idx_store" | "find_key" | "mem_copy_manual" | "nested_sum" | "min3"
        | "vol_two_guards" => 3,
        "clamp_sel" | "and_or_cond" | "select4" => 4,
        _ => return None,
    };
    Some(arity)
}

pub(crate) struct Arg {
    draw: &'static str,
    ocast: &'static str,
}

pub(crate) fn scalar_block(
    opt: &str,
    name: &str,
    rec: &str,
    seed: u64,
    args: &[Arg],
    u64ret: bool,
    guard: Option<&str>,
) -> String {
    let mut draws: String = String::new();
    for (index, arg) in args.iter().enumerate() {
        let _ = writeln!(draws, "        uint64_t a{index} = {};", arg.draw);
    }
    let orig_args: String = args
        .iter()
        .enumerate()
        .map(|(index, arg): (usize, &Arg)| format!("({})a{index}", arg.ocast))
        .collect::<Vec<String>>()
        .join(", ");
    let rec_args: String = (0..args.len())
        .map(|index: usize| format!("a{index}"))
        .collect::<Vec<String>>()
        .join(", ");
    let guard_line: String = guard.map_or_else(String::new, |condition: &str| {
        format!("        if (!({condition})) {{ it--; continue; }}\n")
    });
    let want_expr: String = if u64ret {
        format!("uint64_t w = (uint64_t)({name}({orig_args}));")
    } else {
        format!("uint64_t w = ((uint64_t)(uint32_t)({name}({orig_args}))) & 0xffffffffULL;")
    };
    let got_mask: &str = if u64ret { "" } else { " & 0xffffffffULL" };
    format!(
        "    {{\n\
         \x20       uint64_t s = 0x{seed:x}ULL; int ok = 1;\n\
         \x20       for (int it = 0; it < ITER; it++) {{\n\
         {draws}\
         {guard_line}\
         \x20           {want_expr}\n\
         \x20           uint64_t g = {rec}({rec_args}){got_mask};\n\
         \x20           if (w != g) {{ printf(\"FAIL {opt} {name} it=%d w=%llu g=%llu\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }}\n\
         \x20       }}\n\
         \x20       if (ok) passed++; else fails++;\n\
         \x20   }}\n"
    )
}

pub(crate) fn fixed_int_to_fp_block(
    opt: &str,
    name: &str,
    rec: &str,
    seed: u64,
    param_ty: &str,
    double_result: bool,
) -> String {
    let wide: bool = param_ty.contains("long");
    let arg_cast: &str = if wide {
        "(uint64_t)"
    } else {
        "(uint64_t)(uint32_t)"
    };
    let to_bits: &str = if double_result {
        "fp_d_to_bits"
    } else {
        "fp_f_to_bits"
    };
    format!(
        "    {{\n\
         \x20       uint64_t s = 0x{seed:x}ULL; int ok = 1;\n\
         \x20       for (int it = 0; it < ITER; it++) {{\n\
         \x20           uint64_t raw = fixed_int_input(&s, it);\n\
         \x20           {param_ty} t = ({param_ty})raw;\n\
         \x20           {param_ty} a = t / 2;\n\
         \x20           {param_ty} b = ({param_ty})(t - a);\n\
         \x20           unsigned long long w = (unsigned long long){to_bits}({name}(a, b));\n\
         \x20           unsigned long long g = (unsigned long long){to_bits}({rec}({arg_cast}a, {arg_cast}b));\n\
         \x20           if (w != g) {{ printf(\"FAIL {opt} {name} it=%d raw=%llx w=%llx g=%llx\\n\", it, (unsigned long long)raw, w, g); ok = 0; break; }}\n\
         \x20       }}\n\
         \x20       if (ok) passed++; else fails++;\n\
         \x20   }}\n"
    )
}

pub(crate) fn fixed_fp_to_int_block(
    opt: &str,
    name: &str,
    rec: &str,
    seed: u64,
    double_source: bool,
    dest_bits: u32,
    signed_dest: bool,
    scale: u32,
) -> String {
    let source_ty: &str = if double_source { "double" } else { "float" };
    let suffix: &str = if double_source { "" } else { "f" };
    let to_bits: &str = if double_source {
        "fp_d_to_bits"
    } else {
        "fp_f_to_bits"
    };
    let from_bits: &str = if double_source {
        "fp_d_from_bits"
    } else {
        "fp_f_from_bits"
    };
    let bit_ty: &str = if double_source {
        "uint64_t"
    } else {
        "uint32_t"
    };
    let step: &str = if double_source { "1ULL" } else { "1u" };
    let pool: &str = if double_source {
        "fp64_input"
    } else {
        "fp32_input"
    };
    let dest_ty: String = format!("uint{dest_bits}_t");
    let saturation_exponent: i32 = i32::try_from(dest_bits).unwrap_or(0)
        - i32::from(signed_dest)
        - i32::try_from(scale).unwrap_or(0);
    format!(
        "    {{\n\
         \x20       uint64_t s = 0x{seed:x}ULL; int ok = 1;\n\
         \x20       {source_ty} edge = 0x1p{saturation_exponent}{suffix};\n\
         \x20       {source_ty} below = {from_bits}(({bit_ty})({to_bits}(edge) - {step}));\n\
         \x20       {source_ty} above = {from_bits}(({bit_ty})({to_bits}(edge) + {step}));\n\
         \x20       {source_ty} directed[] = {{ 0.0{suffix}, -0.0{suffix}, 1.0{suffix}, -1.0{suffix},\n\
         \x20           edge, -edge, below, -below, above, -above, edge * 0.5{suffix}, -edge * 0.5{suffix},\n\
         \x20           edge * 2.0{suffix}, -edge * 2.0{suffix} }};\n\
         \x20       int dcount = (int)(sizeof(directed) / sizeof(directed[0]));\n\
         \x20       for (int it = 0; it < ITER; it++) {{\n\
         \x20           {source_ty} x = it < dcount ? directed[it] : {from_bits}({pool}(&s, it - dcount, 0));\n\
         \x20           unsigned long long w = (unsigned long long)({dest_ty}){name}(x);\n\
         \x20           unsigned long long g = (unsigned long long)({dest_ty}){rec}(x);\n\
         \x20           if (w != g) {{ printf(\"FAIL {opt} {name} it=%d w=%llx g=%llx\\n\", it, w, g); ok = 0; break; }}\n\
         \x20       }}\n\
         \x20       if (ok) passed++; else fails++;\n\
         \x20   }}\n"
    )
}

pub(crate) fn fill_template(template: &str, opt: &str, name: &str, rec: &str, seed: u64) -> String {
    template
        .replace("$REC", rec)
        .replace("$OPT", opt)
        .replace("$NAME", name)
        .replace("$SEED", &format!("0x{seed:x}ULL"))
}

pub(crate) fn idx_block(
    opt: &str,
    name: &str,
    rec: &str,
    seed: u64,
    elem: &str,
    fill: &str,
    u64ret: bool,
) -> String {
    let want_expr: String = if u64ret {
        format!("uint64_t w = (uint64_t)({name}(({elem}*)buf, i));")
    } else {
        format!("uint64_t w = ((uint64_t)(uint32_t)({name}(({elem}*)buf, i))) & 0xffffffffULL;")
    };
    let got_mask: &str = if u64ret { "" } else { " & 0xffffffffULL" };
    format!(
        "    {{\n\
         \x20       uint64_t s = 0x{seed:x}ULL; int ok = 1;\n\
         \x20       for (int it = 0; it < ITER; it++) {{\n\
         \x20           {elem} buf[BUFN];\n\
         \x20           for (int b = 0; b < BUFN; b++) buf[b] = {fill};\n\
         \x20           int i = (int)(xs(&s) % BUFN);\n\
         \x20           {want_expr}\n\
         \x20           uint64_t g = {rec}((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)i){got_mask};\n\
         \x20           if (w != g) {{ printf(\"FAIL {opt} {name} it=%d i=%d w=%llu g=%llu\\n\", it, i, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }}\n\
         \x20       }}\n\
         \x20       if (ok) passed++; else fails++;\n\
         \x20   }}\n"
    )
}

pub(crate) fn count_block(
    opt: &str,
    name: &str,
    rec: &str,
    seed: u64,
    elem: &str,
    fill: &str,
    u64ret: bool,
    min_count: usize,
) -> String {
    let want_expr: String = if u64ret {
        format!("uint64_t w = (uint64_t)({name}(({elem}*)buf, n));")
    } else {
        format!("uint64_t w = ((uint64_t)(uint32_t)({name}(({elem}*)buf, n))) & 0xffffffffULL;")
    };
    let got_mask: &str = if u64ret { "" } else { " & 0xffffffffULL" };
    let span: usize = 16 + 1 - min_count;
    format!(
        "    {{\n\
         \x20       uint64_t s = 0x{seed:x}ULL; int ok = 1;\n\
         \x20       for (int it = 0; it < ITER; it++) {{\n\
         \x20           {elem} buf[BUFN];\n\
         \x20           for (int b = 0; b < BUFN; b++) buf[b] = {fill};\n\
         \x20           int n = {min_count} + (int)(xs(&s) % {span});\n\
         \x20           {want_expr}\n\
         \x20           uint64_t g = {rec}((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)n){got_mask};\n\
         \x20           if (w != g) {{ printf(\"FAIL {opt} {name} it=%d n=%d w=%llu g=%llu\\n\", it, n, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }}\n\
         \x20       }}\n\
         \x20       if (ok) passed++; else fails++;\n\
         \x20   }}\n"
    )
}

pub(crate) const INT_FILL: &str = "(int)((int)(xs(&s) % 200001) - 100000)";
pub(crate) const UINT_FILL: &str = "(unsigned)((int)(xs(&s) % 200001) - 100000)";
pub(crate) const LONG_FILL: &str = "(long long)((int)(xs(&s) % 200001) - 100000)";
pub(crate) const CHAR_FILL: &str = "(char)(xs(&s) & 0xff)";
pub(crate) const U64_FILL: &str = "(unsigned long long)xs(&s)";

pub(crate) const FP_DRIVER_HELPERS: &str = r#"
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
static inline double fp_d_from_bits(uint64_t b) { double v; __builtin_memcpy(&v, &b, 8); return v; }
static inline uint64_t fp_d_to_bits(double v) { uint64_t b; __builtin_memcpy(&b, &v, 8); return b; }
static inline float fp_f_from_bits(uint32_t b) { float v; __builtin_memcpy(&v, &b, 4); return v; }
static inline uint32_t fp_f_to_bits(float v) { uint32_t b; __builtin_memcpy(&b, &v, 4); return b; }
static long long fp_nan_canonicalized = 0;
static void fp_note_nan_canonicalization(unsigned long long wide, unsigned long long got) {
    if (fp_nan_canonicalized < 32) {
        printf("NANEQ w=%llx g=%llx\n", wide, got);
    }
    fp_nan_canonicalized++;
}
static inline int fp_d_bits_equal(uint64_t a, uint64_t b) {
    uint64_t a_abs = a & 0x7fffffffffffffffULL;
    uint64_t b_abs = b & 0x7fffffffffffffffULL;
    if (a == b) {
        return 1;
    }
    if (a_abs > 0x7ff0000000000000ULL && b_abs > 0x7ff0000000000000ULL) {
        fp_note_nan_canonicalization((unsigned long long)a, (unsigned long long)b);
        return 1;
    }
    return 0;
}
static inline int fp_f_bits_equal(uint32_t a, uint32_t b) {
    uint32_t a_abs = a & 0x7fffffffU;
    uint32_t b_abs = b & 0x7fffffffU;
    if (a == b) {
        return 1;
    }
    if (a_abs > 0x7f800000U && b_abs > 0x7f800000U) {
        fp_note_nan_canonicalization((unsigned long long)a, (unsigned long long)b);
        return 1;
    }
    return 0;
}
static inline _Float16 fp_h_from_bits(uint16_t b) { _Float16 v; __builtin_memcpy(&v, &b, 2); return v; }
static inline uint16_t fp_h_to_bits(_Float16 v) { uint16_t b; __builtin_memcpy(&b, &v, 2); return b; }
static const uint32_t fp32_specials[] = {
    0x00000000U, 0x80000000U, 0x7f800000U, 0xff800000U,
    0x7fc00001U, 0xffc00001U, 0x7f800001U, 0xff800001U,
    0x00000001U, 0x007fffffU, 0x00800000U, 0x7f7fffffU,
    0x80800000U, 0xff7fffffU,
    0x3f800000U, 0xbf800000U, 0x40000000U, 0x40800000U, 0x40a00000U
};
static const uint64_t fp64_specials[] = {
    0x0000000000000000ULL, 0x8000000000000000ULL,
    0x7ff0000000000000ULL, 0xfff0000000000000ULL,
    0x7ff8000000000001ULL, 0xfff8000000000001ULL,
    0x7ff0000000000001ULL, 0xfff0000000000001ULL,
    0x0000000000000001ULL, 0x000fffffffffffffULL,
    0x0010000000000000ULL, 0x7fefffffffffffffULL,
    0x8010000000000000ULL, 0xffefffffffffffffULL,
    0x3ff0000000000000ULL, 0xbff0000000000000ULL,
    0x4000000000000000ULL, 0x4010000000000000ULL,
    0x4014000000000000ULL
};
static const uint64_t fp64_narrow_rounding[] = {
    0x3ff000000fffffffULL, 0x3ff0000010000000ULL,
    0x3ff0000010000001ULL, 0xbff000000fffffffULL,
    0xbff0000010000000ULL, 0xbff0000010000001ULL,
    0x3690000000000000ULL, 0x3690000000000001ULL,
    0x36a0000000000000ULL, 0x47efffffe0000000ULL,
    0x47efffffe0000001ULL
};
static uint32_t fp32_input(uint64_t *state, int iteration, int lane) {
    int count = (int)(sizeof(fp32_specials) / sizeof(fp32_specials[0]));
    if (iteration < count) return fp32_specials[(iteration + lane) % count];
    return (uint32_t)xs(state);
}
static uint64_t fp64_input(uint64_t *state, int iteration, int lane) {
    int count = (int)(sizeof(fp64_specials) / sizeof(fp64_specials[0]));
    if (iteration < count) return fp64_specials[(iteration + lane) % count];
    return xs(state);
}
static uint64_t fp64_narrow_input(uint64_t *state, int iteration) {
    int general = (int)(sizeof(fp64_specials) / sizeof(fp64_specials[0]));
    if (iteration < general) return fp64_specials[iteration];
    int narrowed = iteration - general;
    int count = (int)(sizeof(fp64_narrow_rounding) / sizeof(fp64_narrow_rounding[0]));
    if (narrowed < count) return fp64_narrow_rounding[narrowed];
    return xs(state);
}
static const uint64_t fixed_int_specials[] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0xffffffffffffffffULL,
    0x0000000080000000ULL, 0x000000007fffffffULL, 0x0000000080000001ULL,
    0x00000000fffffffeULL, 0x0000000000ffffffULL, 0x0000000001000000ULL,
    0x0000000001000001ULL, 0x8000000000000000ULL, 0x7fffffffffffffffULL,
    0x001fffffffffffffULL, 0x0020000000000000ULL, 0x0020000000000001ULL,
    0xffe0000000000000ULL, 0x0000000100000000ULL, 0x00000000ffffffffULL,
    0xffff800000000000ULL, 0x0000800000000000ULL
};
static uint64_t fixed_int_input(uint64_t *state, int iteration) {
    int count = (int)(sizeof(fixed_int_specials) / sizeof(fixed_int_specials[0]));
    if (iteration < count) return fixed_int_specials[iteration];
    return xs(state);
}
static const uint32_t fp32_pairs[][2] = {
    {0x3f800000U, 0x40000000U}, {0x40000000U, 0x3f800000U}, {0x3f800000U, 0x3f800000U},
    {0x00000000U, 0x80000000U}, {0x80000000U, 0x00000000U},
    {0x7fc00000U, 0x3f800000U}, {0x3f800000U, 0x7fc00000U},
    {0x7f800001U, 0x3f800000U}, {0x3f800000U, 0x7f800001U},
    {0x7f800000U, 0x7f800000U}, {0x7f800000U, 0xff800000U}, {0xff800000U, 0x7f800000U},
    {0x3f800000U, 0x7f800000U}, {0x00000001U, 0x80000001U}
};
static const uint64_t fp64_pairs[][2] = {
    {0x3ff0000000000000ULL, 0x4000000000000000ULL}, {0x4000000000000000ULL, 0x3ff0000000000000ULL},
    {0x3ff0000000000000ULL, 0x3ff0000000000000ULL},
    {0x0000000000000000ULL, 0x8000000000000000ULL}, {0x8000000000000000ULL, 0x0000000000000000ULL},
    {0x7ff8000000000000ULL, 0x3ff0000000000000ULL}, {0x3ff0000000000000ULL, 0x7ff8000000000000ULL},
    {0x7ff0000000000001ULL, 0x3ff0000000000000ULL}, {0x3ff0000000000000ULL, 0x7ff0000000000001ULL},
    {0x7ff0000000000000ULL, 0x7ff0000000000000ULL}, {0x7ff0000000000000ULL, 0xfff0000000000000ULL},
    {0xfff0000000000000ULL, 0x7ff0000000000000ULL},
    {0x3ff0000000000000ULL, 0x7ff0000000000000ULL}, {0x0000000000000001ULL, 0x8000000000000001ULL}
};
static uint64_t grade_seed;
static int grade_seed_valid;
static int grade_printf(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    if (strncmp(format, "FAIL ", 5) == 0 && grade_seed_valid) {
        char line[4096];
        int written = vsnprintf(line, sizeof(line), format, arguments);
        va_end(arguments);
        if (written < 0) return written;
        size_t length = (size_t)written;
        if (length >= sizeof(line)) length = sizeof(line) - 1;
        if (length > 0 && line[length - 1] == '\n') length--;
        return fprintf(stdout, "%.*s seed=0x%llx\n", (int)length, line, (unsigned long long)grade_seed);
    }
    int result = vfprintf(stdout, format, arguments);
    va_end(arguments);
    return result;
}
#define printf grade_printf
"#;

pub(crate) const HOST_FP_PRECHECK: &str = r#"
    volatile float fp32_min_normal = fp_f_from_bits(0x00800000U);
    volatile double fp64_min_normal = fp_d_from_bits(0x0010000000000000ULL);
    volatile float fp32_half = 0.5f;
    volatile double fp64_half = 0.5;
    uint32_t fp32_subnormal = fp_f_to_bits(fp32_min_normal * fp32_half);
    uint64_t fp64_subnormal = fp_d_to_bits(fp64_min_normal * fp64_half);
    if (fp32_subnormal != 0x00400000U || fp64_subnormal != 0x0008000000000000ULL) {
        printf("HOSTFP flush-to-zero detected f32=%08x f64=%016llx\n", fp32_subnormal, (unsigned long long)fp64_subnormal);
        return 97;
    }
"#;

pub(crate) const FP_ID_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint32_t bits = fp32_input(&s, it, 0); float x = fp_f_from_bits(bits);\n\
     \x20           uint32_t w = fp_f_to_bits(fp_id_f(x)); uint32_t g = fp_f_to_bits($REC(x));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_ID_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint64_t bits = fp64_input(&s, it, 0); double x = fp_d_from_bits(bits);\n\
     \x20           uint64_t w = fp_d_to_bits(fp_id_d(x)); uint64_t g = fp_d_to_bits($REC(x));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_UNARY_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint64_t bits = fp64_input(&s, it, 0); double x = fp_d_from_bits(bits);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(x)); uint64_t g = fp_d_to_bits($REC(x));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_UNARY_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint32_t bits = fp32_input(&s, it, 0); float x = fp_f_from_bits(bits);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(x)); uint32_t g = fp_f_to_bits($REC(x));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SECOND_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           uint64_t w = fp_d_to_bits(fp_second(a, b)); uint64_t g = fp_d_to_bits($REC(a, b));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PICK3_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5)); double c = fp_d_from_bits(fp64_input(&s, it, 9));\n\
     \x20           uint64_t w = fp_d_to_bits(fp_pick3(a, b, c)); uint64_t g = fp_d_to_bits($REC(a, b, c));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_GET_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { uint32_t bits = fp32_input(&s, it, b); __builtin_memcpy(&buf[b], &bits, 4); }\n\
     \x20           int i = (int)(xs(&s) % BUFN);\n\
     \x20           uint32_t w = fp_f_to_bits(fp_get(buf, i)); uint32_t g = fp_f_to_bits($REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)i));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d i=%d w=%08x g=%08x\\n\", it, i, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_GET_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { uint64_t bits = fp64_input(&s, it, b); __builtin_memcpy(&buf[b], &bits, 8); }\n\
     \x20           int i = (int)(xs(&s) % BUFN);\n\
     \x20           uint64_t w = fp_d_to_bits(fp_get_d(buf, i)); uint64_t g = fp_d_to_bits($REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)i));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d i=%d w=%llx g=%llx\\n\", it, i, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PUT_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float o[BUFN]; float r[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { uint32_t bits = fp32_input(&s, it, b); __builtin_memcpy(&o[b], &bits, 4); __builtin_memcpy(&r[b], &bits, 4); }\n\
     \x20           int i = (int)(xs(&s) % BUFN); float v = fp_f_from_bits(fp32_input(&s, it, BUFN + 1));\n\
     \x20           fp_put(o, i, v); $REC(v, (uint64_t)(uintptr_t)r, (uint64_t)(uint32_t)i);\n\
     \x20           if (memcmp(o, r, sizeof(o)) != 0) { printf(\"FAIL $OPT $NAME it=%d i=%d\\n\", it, i); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_BITS_GPR_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint32_t bits = fp32_input(&s, it, 0);\n\
     \x20           uint32_t w = fp_f_to_bits(fp_bits_gpr(bits)); uint32_t g = fp_f_to_bits($REC((uint64_t)bits));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_BIN_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint32_t ba = fp32_input(&s, it, 0); uint32_t bb = fp32_input(&s, it, 5);\n\
     \x20           int nn = (((ba & 0x7f800000U) == 0x7f800000U) && (ba & 0x7fffffU) ? 1 : 0) + (((bb & 0x7f800000U) == 0x7f800000U) && (bb & 0x7fffffU) ? 1 : 0);\n\
     \x20           if (nn > 1) continue;\n\
     \x20           float a = fp_f_from_bits(ba); float b = fp_f_from_bits(bb);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b)); uint32_t g = fp_f_to_bits($REC(a, b));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_BIN_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           uint64_t ba = fp64_input(&s, it, 0); uint64_t bb = fp64_input(&s, it, 5);\n\
     \x20           int nn = (((ba & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (ba & 0xfffffffffffffULL) ? 1 : 0) + (((bb & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (bb & 0xfffffffffffffULL) ? 1 : 0);\n\
     \x20           if (nn > 1) continue;\n\
     \x20           double a = fp_d_from_bits(ba); double b = fp_d_from_bits(bb);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b)); uint64_t g = fp_d_to_bits($REC(a, b));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_AXPY_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float x = fp_f_from_bits(fp32_input(&s, it, 5)); float y = fp_f_from_bits(fp32_input(&s, it, 9));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, x, y)); uint32_t g = fp_f_to_bits($REC(a, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_FMA_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       static const uint32_t fma_f_triples[][3] = {\n\
     \x20           {0x45800800U,0x45800800U,0xcb801000U}, {0x7f7fffffU,0x40000000U,0xff7fffffU},\n\
     \x20           {0x40000000U,0x40400000U,0x40a00000U}, {0x7f800000U,0x40000000U,0xff800000U},\n\
     \x20           {0x7fc00000U,0x3f800000U,0x3f800000U}, {0x3f800000U,0x7fc00000U,0x3f800000U},\n\
     \x20           {0x3f800000U,0x3f800000U,0x7fc00000U}, {0x7f800001U,0x3f800000U,0x3f800000U},\n\
     \x20           {0x3f800000U,0x7f800001U,0x3f800000U}, {0x3f800000U,0x3f800000U,0x7f800001U},\n\
     \x20           {0x3f800000U,0x00000000U,0x80000000U}, {0x3f800000U,0x80000000U,0x00000000U},\n\
     \x20           {0x3f800000U,0x00000000U,0x00000000U}, {0x3f800000U,0x80000000U,0x80000000U},\n\
     \x20           {0x40000000U,0x40400000U,0xc0c00000U}, {0x40000000U,0x40400000U,0x40c00000U}\n\
     \x20       };\n\
     \x20       int ntf = (int)(sizeof(fma_f_triples) / sizeof(fma_f_triples[0]));\n\
     \x20       for (int t = 0; t < ntf; t++) {\n\
     \x20           float a = fp_f_from_bits(fma_f_triples[t][0]); float b = fp_f_from_bits(fma_f_triples[t][1]); float c = fp_f_from_bits(fma_f_triples[t][2]);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c)); uint32_t g = fp_f_to_bits($REC(a, b, c));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME triple=%d w=%08x g=%08x\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           uint32_t ba = fp32_input(&s, it, 0); uint32_t bb = fp32_input(&s, it, 5); uint32_t bc = fp32_input(&s, it, 9);\n\
     \x20           int nn = (((ba & 0x7f800000U) == 0x7f800000U) && (ba & 0x7fffffU) ? 1 : 0) + (((bb & 0x7f800000U) == 0x7f800000U) && (bb & 0x7fffffU) ? 1 : 0) + (((bc & 0x7f800000U) == 0x7f800000U) && (bc & 0x7fffffU) ? 1 : 0);\n\
     \x20           if (nn > 1) continue;\n\
     \x20           float a = fp_f_from_bits(ba); float b = fp_f_from_bits(bb); float c = fp_f_from_bits(bc);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c)); uint32_t g = fp_f_to_bits($REC(a, b, c));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_FMA_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       static const uint64_t fma_d_triples[][3] = {\n\
     \x20           {0x41a0000002000000ULL,0x41a0000002000000ULL,0xc350000004000000ULL}, {0x7fefffffffffffffULL,0x4000000000000000ULL,0xffefffffffffffffULL},\n\
     \x20           {0x4000000000000000ULL,0x4008000000000000ULL,0x4014000000000000ULL}, {0x7ff0000000000000ULL,0x4000000000000000ULL,0xfff0000000000000ULL},\n\
     \x20           {0x7ff8000000000000ULL,0x3ff0000000000000ULL,0x3ff0000000000000ULL}, {0x3ff0000000000000ULL,0x7ff8000000000000ULL,0x3ff0000000000000ULL},\n\
     \x20           {0x3ff0000000000000ULL,0x3ff0000000000000ULL,0x7ff8000000000000ULL}, {0x7ff0000000000001ULL,0x3ff0000000000000ULL,0x3ff0000000000000ULL},\n\
     \x20           {0x3ff0000000000000ULL,0x7ff0000000000001ULL,0x3ff0000000000000ULL}, {0x3ff0000000000000ULL,0x3ff0000000000000ULL,0x7ff0000000000001ULL},\n\
     \x20           {0x3ff0000000000000ULL,0x0000000000000000ULL,0x8000000000000000ULL}, {0x3ff0000000000000ULL,0x8000000000000000ULL,0x0000000000000000ULL},\n\
     \x20           {0x3ff0000000000000ULL,0x0000000000000000ULL,0x0000000000000000ULL}, {0x3ff0000000000000ULL,0x8000000000000000ULL,0x8000000000000000ULL},\n\
     \x20           {0x4000000000000000ULL,0x4008000000000000ULL,0xc018000000000000ULL}, {0x4000000000000000ULL,0x4008000000000000ULL,0x4018000000000000ULL}\n\
     \x20       };\n\
     \x20       int ntd = (int)(sizeof(fma_d_triples) / sizeof(fma_d_triples[0]));\n\
     \x20       for (int t = 0; t < ntd; t++) {\n\
     \x20           double a = fp_d_from_bits(fma_d_triples[t][0]); double b = fp_d_from_bits(fma_d_triples[t][1]); double c = fp_d_from_bits(fma_d_triples[t][2]);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, c)); uint64_t g = fp_d_to_bits($REC(a, b, c));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME triple=%d w=%llx g=%llx\\n\", t, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           uint64_t ba = fp64_input(&s, it, 0); uint64_t bb = fp64_input(&s, it, 5); uint64_t bc = fp64_input(&s, it, 9);\n\
     \x20           int nn = (((ba & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (ba & 0xfffffffffffffULL) ? 1 : 0) + (((bb & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (bb & 0xfffffffffffffULL) ? 1 : 0) + (((bc & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (bc & 0xfffffffffffffULL) ? 1 : 0);\n\
     \x20           if (nn > 1) continue;\n\
     \x20           double a = fp_d_from_bits(ba); double b = fp_d_from_bits(bb); double c = fp_d_from_bits(bc);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, c)); uint64_t g = fp_d_to_bits($REC(a, b, c));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PRED2_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp32_pairs) / sizeof(fp32_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           float a = fp_f_from_bits(fp32_pairs[t][0]); float b = fp_f_from_bits(fp32_pairs[t][1]);\n\
     \x20           int w = $NAME(a, b); int g = $REC(a, b);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME pair=%d w=%d g=%d\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           int w = $NAME(a, b); int g = $REC(a, b);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%d g=%d\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PRED2_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp64_pairs) / sizeof(fp64_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           double a = fp_d_from_bits(fp64_pairs[t][0]); double b = fp_d_from_bits(fp64_pairs[t][1]);\n\
     \x20           int w = $NAME(a, b); int g = $REC(a, b);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME pair=%d w=%d g=%d\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           int w = $NAME(a, b); int g = $REC(a, b);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%d g=%d\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PRED1_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 0));\n\
     \x20           int w = $NAME(x); int g = $REC(x);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%d g=%d\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_PRED1_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double x = fp_d_from_bits(fp64_input(&s, it, 0));\n\
     \x20           int w = $NAME(x); int g = $REC(x);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%d g=%d\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL2_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp32_pairs) / sizeof(fp32_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           float a = fp_f_from_bits(fp32_pairs[t][0]); float b = fp_f_from_bits(fp32_pairs[t][1]);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b)); uint32_t g = fp_f_to_bits($REC(a, b));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%08x g=%08x\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b)); uint32_t g = fp_f_to_bits($REC(a, b));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL2_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp64_pairs) / sizeof(fp64_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           double a = fp_d_from_bits(fp64_pairs[t][0]); double b = fp_d_from_bits(fp64_pairs[t][1]);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b)); uint64_t g = fp_d_to_bits($REC(a, b));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%llx g=%llx\\n\", t, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b)); uint64_t g = fp_d_to_bits($REC(a, b));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL4_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp32_pairs) / sizeof(fp32_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           float a = fp_f_from_bits(fp32_pairs[t][0]); float b = fp_f_from_bits(fp32_pairs[t][1]);\n\
     \x20           float x = fp_f_from_bits(0x00000000U); float y = fp_f_from_bits(0x80000000U);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%08x g=%08x\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 9)); float y = fp_f_from_bits(fp32_input(&s, it, 2));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL4_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp64_pairs) / sizeof(fp64_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           double a = fp_d_from_bits(fp64_pairs[t][0]); double b = fp_d_from_bits(fp64_pairs[t][1]);\n\
     \x20           double x = fp_d_from_bits(0x0000000000000000ULL); double y = fp_d_from_bits(0x8000000000000000ULL);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, x, y)); uint64_t g = fp_d_to_bits($REC(a, b, x, y));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%llx g=%llx\\n\", t, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           double x = fp_d_from_bits(fp64_input(&s, it, 9)); double y = fp_d_from_bits(fp64_input(&s, it, 2));\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, x, y)); uint64_t g = fp_d_to_bits($REC(a, b, x, y));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL6_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp32_pairs) / sizeof(fp32_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           float a = fp_f_from_bits(fp32_pairs[t][0]); float b = fp_f_from_bits(fp32_pairs[t][1]);\n\
     \x20           float c = fp_f_from_bits(fp32_pairs[(t + 3) % np][0]); float d = fp_f_from_bits(fp32_pairs[(t + 3) % np][1]);\n\
     \x20           float x = fp_f_from_bits(0x00000000U); float y = fp_f_from_bits(0x80000000U);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c, d, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, c, d, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%08x g=%08x\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           float c = fp_f_from_bits(fp32_input(&s, it, 9)); float d = fp_f_from_bits(fp32_input(&s, it, 2));\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 7)); float y = fp_f_from_bits(fp32_input(&s, it, 11));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c, d, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, c, d, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL6_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp64_pairs) / sizeof(fp64_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           double a = fp_d_from_bits(fp64_pairs[t][0]); double b = fp_d_from_bits(fp64_pairs[t][1]);\n\
     \x20           double c = fp_d_from_bits(fp64_pairs[(t + 3) % np][0]); double d = fp_d_from_bits(fp64_pairs[(t + 3) % np][1]);\n\
     \x20           double x = fp_d_from_bits(0x0000000000000000ULL); double y = fp_d_from_bits(0x8000000000000000ULL);\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, c, d, x, y)); uint64_t g = fp_d_to_bits($REC(a, b, c, d, x, y));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%llx g=%llx\\n\", t, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           double c = fp_d_from_bits(fp64_input(&s, it, 9)); double d = fp_d_from_bits(fp64_input(&s, it, 2));\n\
     \x20           double x = fp_d_from_bits(fp64_input(&s, it, 7)); double y = fp_d_from_bits(fp64_input(&s, it, 11));\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, c, d, x, y)); uint64_t g = fp_d_to_bits($REC(a, b, c, d, x, y));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_SEL8_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       int np = (int)(sizeof(fp32_pairs) / sizeof(fp32_pairs[0]));\n\
     \x20       for (int t = 0; t < np; t++) {\n\
     \x20           float a = fp_f_from_bits(fp32_pairs[t][0]); float b = fp_f_from_bits(fp32_pairs[t][1]);\n\
     \x20           float c = fp_f_from_bits(fp32_pairs[(t + 3) % np][0]); float d = fp_f_from_bits(fp32_pairs[(t + 3) % np][1]);\n\
     \x20           float e = fp_f_from_bits(fp32_pairs[(t + 5) % np][0]); float f = fp_f_from_bits(fp32_pairs[(t + 5) % np][1]);\n\
     \x20           float x = fp_f_from_bits(0x00000000U); float y = fp_f_from_bits(0x80000000U);\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c, d, e, f, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, c, d, e, f, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME pair=%d w=%08x g=%08x\\n\", t, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       for (int it = 0; ok && it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           float c = fp_f_from_bits(fp32_input(&s, it, 9)); float d = fp_f_from_bits(fp32_input(&s, it, 2));\n\
     \x20           float e = fp_f_from_bits(fp32_input(&s, it, 7)); float f = fp_f_from_bits(fp32_input(&s, it, 11));\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 13)); float y = fp_f_from_bits(fp32_input(&s, it, 3));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c, d, e, f, x, y)); uint32_t g = fp_f_to_bits($REC(a, b, c, d, e, f, x, y));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_NINTH_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float a = fp_f_from_bits(fp32_input(&s, it, 0)); float b = fp_f_from_bits(fp32_input(&s, it, 1));\n\
     \x20           float c = fp_f_from_bits(fp32_input(&s, it, 2)); float d = fp_f_from_bits(fp32_input(&s, it, 3));\n\
     \x20           float e = fp_f_from_bits(fp32_input(&s, it, 4)); float f = fp_f_from_bits(fp32_input(&s, it, 5));\n\
     \x20           float g = fp_f_from_bits(fp32_input(&s, it, 6)); float h = fp_f_from_bits(fp32_input(&s, it, 7));\n\
     \x20           float i = fp_f_from_bits(fp32_input(&s, it, 8));\n\
     \x20           uint32_t w = fp_f_to_bits($NAME(a, b, c, d, e, f, g, h, i)); uint32_t got = fp_f_to_bits($REC(a, b, c, d, e, f, g, h, i));\n\
     \x20           if (!fp_f_bits_equal(w, got)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, got); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_NINTH_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double a = fp_d_from_bits(fp64_input(&s, it, 0)); double b = fp_d_from_bits(fp64_input(&s, it, 1));\n\
     \x20           double c = fp_d_from_bits(fp64_input(&s, it, 2)); double d = fp_d_from_bits(fp64_input(&s, it, 3));\n\
     \x20           double e = fp_d_from_bits(fp64_input(&s, it, 4)); double f = fp_d_from_bits(fp64_input(&s, it, 5));\n\
     \x20           double g = fp_d_from_bits(fp64_input(&s, it, 6)); double h = fp_d_from_bits(fp64_input(&s, it, 7));\n\
     \x20           double i = fp_d_from_bits(fp64_input(&s, it, 8));\n\
     \x20           uint64_t w = fp_d_to_bits($NAME(a, b, c, d, e, f, g, h, i)); uint64_t got = fp_d_to_bits($REC(a, b, c, d, e, f, g, h, i));\n\
     \x20           if (!fp_d_bits_equal(w, got)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)got); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_MIXED_I_THEN_F_TMPL: &str = r#"    {
        uint64_t s = $SEED; int ok = 1;
        for (int it = 0; it < ITER; it++) {
            uint64_t a = xs(&s), b = xs(&s), c = xs(&s), d = xs(&s), e = xs(&s), f = xs(&s), g = xs(&s), h = xs(&s);
            uint64_t i = 0x100000000ULL | (xs(&s) & 0xffffULL);
            float p = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float q = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float r = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float s_arg = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float t = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float u = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float v = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float w = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float x = 1.0f + (float)(xs(&s) % 1000) * 0.25f;
            uint32_t expected = fp_f_to_bits($NAME(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            uint32_t recovered = fp_f_to_bits($REC(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            if (!fp_f_bits_equal(expected, recovered)) { printf("FAIL $OPT $NAME it=%d stack_i=%llx stack_f=%08x w=%08x g=%08x\n", it, (unsigned long long)i, fp_f_to_bits(x), expected, recovered); ok = 0; break; }
        }
        if (ok) passed++; else fails++;
    }
"#;

pub(crate) const FP_MIXED_I_THEN_D_TMPL: &str = r#"    {
        uint64_t s = $SEED; int ok = 1;
        for (int it = 0; it < ITER; it++) {
            uint64_t a = xs(&s), b = xs(&s), c = xs(&s), d = xs(&s), e = xs(&s), f = xs(&s), g = xs(&s), h = xs(&s);
            uint64_t i = 0x100000000ULL | (xs(&s) & 0xffffULL);
            double p = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double q = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double r = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double s_arg = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double t = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double u = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double v = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double w = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double x = 1.0 + (double)(xs(&s) % 1000) * 0.25;
            uint64_t expected = fp_d_to_bits($NAME(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            uint64_t recovered = fp_d_to_bits($REC(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            if (!fp_d_bits_equal(expected, recovered)) { printf("FAIL $OPT $NAME it=%d stack_i=%llx stack_d=%llx w=%llx g=%llx\n", it, (unsigned long long)i, (unsigned long long)fp_d_to_bits(x), (unsigned long long)expected, (unsigned long long)recovered); ok = 0; break; }
        }
        if (ok) passed++; else fails++;
    }
"#;

pub(crate) const FP_MIXED_F_THEN_I_TMPL: &str = r#"    {
        uint64_t s = $SEED; int ok = 1;
        for (int it = 0; it < ITER; it++) {
            float a = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float b = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float c = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float d = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float e = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float f = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float g = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float h = (float)((int)(xs(&s) % 2001) - 1000) * 0.25f;
            float i = 1.0f + (float)(xs(&s) % 1000) * 0.25f;
            uint64_t p = xs(&s), q = xs(&s), r = xs(&s), s_arg = xs(&s), t = xs(&s), u = xs(&s), v = xs(&s), w = xs(&s);
            uint64_t x = 0x100000000ULL | (xs(&s) & 0xffffULL);
            uint32_t expected = fp_f_to_bits($NAME(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            uint32_t recovered = fp_f_to_bits($REC(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            if (!fp_f_bits_equal(expected, recovered)) { printf("FAIL $OPT $NAME it=%d stack_f=%08x stack_i=%llx w=%08x g=%08x\n", it, fp_f_to_bits(i), (unsigned long long)x, expected, recovered); ok = 0; break; }
        }
        if (ok) passed++; else fails++;
    }
"#;

pub(crate) const FP_MIXED_D_THEN_I_TMPL: &str = r#"    {
        uint64_t s = $SEED; int ok = 1;
        for (int it = 0; it < ITER; it++) {
            double a = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double b = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double c = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double d = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double e = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double f = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double g = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double h = (double)((int)(xs(&s) % 2001) - 1000) * 0.25;
            double i = 1.0 + (double)(xs(&s) % 1000) * 0.25;
            uint64_t p = xs(&s), q = xs(&s), r = xs(&s), s_arg = xs(&s), t = xs(&s), u = xs(&s), v = xs(&s), w = xs(&s);
            uint64_t x = 0x100000000ULL | (xs(&s) & 0xffffULL);
            uint64_t expected = fp_d_to_bits($NAME(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            uint64_t recovered = fp_d_to_bits($REC(a, b, c, d, e, f, g, h, i, p, q, r, s_arg, t, u, v, w, x));
            if (!fp_d_bits_equal(expected, recovered)) { printf("FAIL $OPT $NAME it=%d stack_d=%llx stack_i=%llx w=%llx g=%llx\n", it, (unsigned long long)fp_d_to_bits(i), (unsigned long long)x, (unsigned long long)expected, (unsigned long long)recovered); ok = 0; break; }
        }
        if (ok) passed++; else fails++;
    }
"#;

pub(crate) const FP_TO_I32_F_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 0));\n\
     \x20           uint32_t w = (uint32_t)$NAME(x); uint32_t g = (uint32_t)$REC(x);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_TO_U64_D_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double x = fp_d_from_bits(fp64_input(&s, it, 0));\n\
     \x20           uint64_t w = (uint64_t)$NAME(x); uint64_t g = (uint64_t)$REC(x);\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_CONST_F_TMPL: &str = "    {\n\
     \x20       uint32_t w = fp_f_to_bits($NAME()); uint32_t g = fp_f_to_bits($REC());\n\
     \x20       if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME w=%08x g=%08x\\n\", w, g); fails++; } else { passed++; }\n\
     \x20   }\n";

pub(crate) const FP_CONST_D_TMPL: &str = "    {\n\
     \x20       uint64_t w = fp_d_to_bits($NAME()); uint64_t g = fp_d_to_bits($REC());\n\
     \x20       if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME w=%llx g=%llx\\n\", (unsigned long long)w, (unsigned long long)g); fails++; } else { passed++; }\n\
     \x20   }\n";

pub(crate) const FP_FROM_I32_D_TMPL: &str = "    {\n\
     \x20       static const int directed[] = { (-2147483647 - 1), 0, 2147483647, 16777215, 16777216, 16777217, -16777215, -16777216, -16777217 };\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int count = (int)(sizeof(directed) / sizeof(directed[0])); int x = it < count ? directed[it] : (int)(uint32_t)xs(&s);\n\
     \x20           uint64_t w = fp_d_to_bits(fp_from_int(x)); uint64_t g = fp_d_to_bits($REC((uint64_t)(uint32_t)x));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d x=%d w=%llx g=%llx\\n\", it, x, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_FROM_U32_F_TMPL: &str = "    {\n\
     \x20       static const uint32_t directed[] = { 0U, 0xffffffffU, 0x7fffffffU, 0x80000000U, 16777215U, 16777216U, 16777217U, 33554431U, 33554432U, 33554433U };\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int count = (int)(sizeof(directed) / sizeof(directed[0])); uint32_t x = it < count ? directed[it] : (uint32_t)xs(&s);\n\
     \x20           uint32_t w = fp_f_to_bits(fp_from_uint(x)); uint32_t g = fp_f_to_bits($REC((uint64_t)x));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d x=%u w=%08x g=%08x\\n\", it, x, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_WIDEN_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           float x = fp_f_from_bits(fp32_input(&s, it, 0));\n\
     \x20           uint64_t w = fp_d_to_bits(fp_widen(x)); uint64_t g = fp_d_to_bits($REC(x));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%llx g=%llx\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_NARROW_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           double x = fp_d_from_bits(fp64_narrow_input(&s, it));\n\
     \x20           uint32_t w = fp_f_to_bits(fp_narrow(x)); uint32_t g = fp_f_to_bits($REC(x));\n\
     \x20           if (!fp_f_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d w=%08x g=%08x\\n\", it, w, g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FP_IAVG_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) buf[b] = (int)(uint32_t)xs(&s);\n\
     \x20           int n = it <= BUFN ? it : (int)(xs(&s) % (BUFN + 1));\n\
     \x20           uint64_t w = fp_d_to_bits(fp_iavg(buf, n)); uint64_t g = fp_d_to_bits($REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)n));\n\
     \x20           if (!fp_d_bits_equal(w, g)) { printf(\"FAIL $OPT $NAME it=%d n=%d w=%llx g=%llx\\n\", it, n, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const IDX_STORE_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int o[BUFN]; int r[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { int v = (int)(xs(&s) % 200001) - 100000; o[b] = v; r[b] = v; }\n\
     \x20           int i = (int)(xs(&s) % BUFN);\n\
     \x20           int v = (int)(xs(&s) % 200001) - 100000;\n\
     \x20           idx_store(o, i, v);\n\
     \x20           (void)$REC((uint64_t)(uintptr_t)r, (uint64_t)(uint32_t)i, (uint64_t)(uint32_t)v);\n\
     \x20           if (memcmp(o, r, sizeof(o)) != 0) { printf(\"FAIL $OPT $NAME it=%d i=%d v=%d\\n\", it, i, v); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const MEM_COPY_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           unsigned char src[BUFN]; unsigned char od[BUFN]; unsigned char rd[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { src[b] = (unsigned char)(xs(&s) & 0xff); unsigned char f = (unsigned char)(xs(&s) & 0xff); od[b] = f; rd[b] = f; }\n\
     \x20           int n = (int)(xs(&s) % (BUFN + 1));\n\
     \x20           mem_copy_manual((char*)od, (const char*)src, n);\n\
     \x20           (void)$REC((uint64_t)(uintptr_t)rd, (uint64_t)(uintptr_t)src, (uint64_t)(uint32_t)n);\n\
     \x20           if (memcmp(od, rd, BUFN) != 0) { printf(\"FAIL $OPT $NAME it=%d n=%d\\n\", it, n); ok = 0; break; }\n\
     \x20       }\n\
     \x20       {\n\
     \x20           static const int NS[] = { 0, -1, -3, -32, (-2147483647 - 1), 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 96, 127, 160 };\n\
     \x20           unsigned char lsrc[160]; unsigned char lod[160]; unsigned char lrd[160];\n\
     \x20           for (int k = 0; ok && k < (int)(sizeof(NS) / sizeof(NS[0])); k++) {\n\
     \x20               int n = NS[k];\n\
     \x20               for (int b = 0; b < 160; b++) { lsrc[b] = (unsigned char)(xs(&s) & 0xff); unsigned char f = (unsigned char)(xs(&s) & 0xff); lod[b] = f; lrd[b] = f; }\n\
     \x20               mem_copy_manual((char*)lod, (const char*)lsrc, n);\n\
     \x20               (void)$REC((uint64_t)(uintptr_t)lrd, (uint64_t)(uintptr_t)lsrc, (uint64_t)(uint32_t)n);\n\
     \x20               if (memcmp(lod, lrd, 160) != 0) { printf(\"FAIL $OPT $NAME directed n=%d\\n\", n); ok = 0; }\n\
     \x20           }\n\
     \x20       }\n\
     \x20       {\n\
     \x20           static const int OFFS[] = { 1, 2, 4, 8, 15, 16, 31, 32, 33, 40, 64, 96 };\n\
     \x20           unsigned char ob[320]; unsigned char rb[320];\n\
     \x20           for (int k = 0; ok && k < (int)(sizeof(OFFS) / sizeof(OFFS[0])); k++) {\n\
     \x20               for (int dir = 0; ok && dir < 2; dir++) {\n\
     \x20                   int off = OFFS[k];\n\
     \x20                   int dst = dir ? off : 0; int from = dir ? 0 : off;\n\
     \x20                   for (int b = 0; b < 320; b++) { unsigned char f = (unsigned char)(xs(&s) & 0xff); ob[b] = f; rb[b] = f; }\n\
     \x20                   mem_copy_manual((char*)(ob + dst), (const char*)(ob + from), 128);\n\
     \x20                   (void)$REC((uint64_t)(uintptr_t)(rb + dst), (uint64_t)(uintptr_t)(rb + from), (uint64_t)128);\n\
     \x20                   if (memcmp(ob, rb, 320) != 0) { printf(\"FAIL $OPT $NAME overlap off=%d dir=%d\\n\", off, dir); ok = 0; }\n\
     \x20               }\n\
     \x20           }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const LD_ST_PAIR_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           unsigned long long o[2]; unsigned long long r[2];\n\
     \x20           o[0] = r[0] = xs(&s); o[1] = r[1] = xs(&s);\n\
     \x20           unsigned long long w = ld_st_pair(o);\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)r);\n\
     \x20           if ((uint64_t)w != g || o[0] != r[0] || o[1] != r[1]) { printf(\"FAIL $OPT $NAME it=%d w=%llu g=%llu\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const STR_LEN_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           unsigned char buf[BUFN + 1];\n\
     \x20           int L = (int)(xs(&s) % BUFN);\n\
     \x20           for (int b = 0; b < L; b++) buf[b] = (unsigned char)(1 + (xs(&s) % 255));\n\
     \x20           buf[L] = 0;\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(str_len_manual((const char*)buf))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)buf) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d L=%d w=%llu g=%llu\\n\", it, L, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const STR_CMP_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           unsigned char a[BUFN + 1]; unsigned char b[BUFN + 1];\n\
     \x20           int la = (int)(xs(&s) % BUFN); int lb = (int)(xs(&s) % BUFN);\n\
     \x20           for (int k = 0; k < la; k++) a[k] = (unsigned char)(1 + (xs(&s) % 255));\n\
     \x20           a[la] = 0;\n\
     \x20           for (int k = 0; k < lb; k++) b[k] = (unsigned char)(1 + (xs(&s) % 255));\n\
     \x20           b[lb] = 0;\n\
     \x20           int mn = la < lb ? la : lb; int p = (int)(xs(&s) % (BUFN)); if (p > mn) p = mn;\n\
     \x20           for (int k = 0; k < p; k++) b[k] = a[k];\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(str_cmp_manual((const char*)a, (const char*)b))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)a, (uint64_t)(uintptr_t)b) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%llu g=%llu\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const PT_DOT_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           struct Pt p; struct Pt q;\n\
     \x20           p.x = (int)(xs(&s) % 40001) - 20000; p.y = (int)(xs(&s) % 40001) - 20000;\n\
     \x20           q.x = (int)(xs(&s) % 40001) - 20000; q.y = (int)(xs(&s) % 40001) - 20000;\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(pt_dot(&p, &q))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)&p, (uint64_t)(uintptr_t)&q) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d w=%llu g=%llu\\n\", it, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const PT_ARR_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           struct Pt buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { buf[b].x = (int)(xs(&s) % 40001) - 20000; buf[b].y = (int)(xs(&s) % 40001) - 20000; }\n\
     \x20           int i = (int)(xs(&s) % BUFN);\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(pt_arr(buf, i))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)i) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d i=%d w=%llu g=%llu\\n\", it, i, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const IDX_TWO_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) buf[b] = (int)(xs(&s) % 200001) - 100000;\n\
     \x20           int i = (int)(xs(&s) % BUFN); int j = (int)(xs(&s) % BUFN);\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(idx_two(buf, i, j))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)i, (uint64_t)(uint32_t)j) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d i=%d j=%d w=%llu g=%llu\\n\", it, i, j, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const FIND_KEY_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) buf[b] = (int)(xs(&s) % 200001) - 100000;\n\
     \x20           int n = (int)(xs(&s) % (BUFN + 1));\n\
     \x20           int key = (xs(&s) & 1) ? buf[(int)(xs(&s) % BUFN)] : ((int)(xs(&s) % 200001) - 100000);\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(find_key(buf, n, key))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)n, (uint64_t)(uint32_t)key) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d n=%d key=%d w=%llu g=%llu\\n\", it, n, key, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) const NESTED_SUM_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           int buf[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) buf[b] = (int)(xs(&s) % 200001) - 100000;\n\
     \x20           int rows = (int)(xs(&s) % 5); int cols = (int)(xs(&s) % 5);\n\
     \x20           uint64_t w = ((uint64_t)(uint32_t)(nested_sum(buf, rows, cols))) & 0xffffffffULL;\n\
     \x20           uint64_t g = $REC((uint64_t)(uintptr_t)buf, (uint64_t)(uint32_t)rows, (uint64_t)(uint32_t)cols) & 0xffffffffULL;\n\
     \x20           if (w != g) { printf(\"FAIL $OPT $NAME it=%d rows=%d cols=%d w=%llu g=%llu\\n\", it, rows, cols, (unsigned long long)w, (unsigned long long)g); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

pub(crate) fn compare_block(opt: &str, name: &str, rec: &str, seed: u64) -> Option<String> {
    let block: String = match name {
        "fp_add_f" | "fp_div_f" | "fp_max_f" | "fp_min_f" | "fabsdiff_f" | "fnegmul_f"
        | "fnabsdiff_f" | "fs_hypot_f" | "fs_sqrt_scaled_f" => {
            fill_template(FP_BIN_F_TMPL, opt, name, rec, seed)
        }
        "fp_sub_d" | "fp_mul_d" | "fp_div_d" | "fp_max_d" | "fp_min_d" | "fabsdiff_d"
        | "fnegmul_d" | "fnabsdiff_d" | "fs_sqrt_sum_d" | "fs_sqrt_diff_d" => {
            fill_template(FP_BIN_D_TMPL, opt, name, rec, seed)
        }
        "fp_axpy" | "fp_clamp_f" => fill_template(FP_AXPY_TMPL, opt, name, rec, seed),
        "fma_madd_f" | "fma_msub_f" | "fma_nmadd_f" | "fma_nmsub_f" | "mul_add_unfused_f"
        | "sub_mul_unfused_f" | "fma_mixed_f" | "fma_chained_f" => {
            fill_template(FP_FMA_F_TMPL, opt, name, rec, seed)
        }
        "fma_madd_d" | "fma_msub_d" | "fma_nmadd_d" | "fma_nmsub_d" | "mul_add_unfused_d"
        | "sub_mul_unfused_d" | "fma_mixed_d" | "fma_chained_d" | "fs_norm3_d" => {
            fill_template(FP_FMA_D_TMPL, opt, name, rec, seed)
        }
        "fc_lt_f" | "fc_le_f" | "fc_gt_f" | "fc_ge_f" | "fc_eq_f" | "fc_ne_f" | "fc_nlt_f"
        | "fc_nle_f" | "fc_ngt_f" | "fc_nge_f" => {
            fill_template(FP_PRED2_F_TMPL, opt, name, rec, seed)
        }
        "fc_lt_d" | "fc_le_d" | "fc_gt_d" | "fc_ge_d" | "fc_eq_d" | "fc_ne_d" | "fc_nlt_d"
        | "fc_nle_d" | "fc_ngt_d" | "fc_nge_d" => {
            fill_template(FP_PRED2_D_TMPL, opt, name, rec, seed)
        }
        "fc_isnan_f" => fill_template(FP_PRED1_F_TMPL, opt, name, rec, seed),
        "fc_isnan_d" => fill_template(FP_PRED1_D_TMPL, opt, name, rec, seed),
        "fc_sel_f" | "fb_ge_f" | "fb_le_f" | "fb_ne_f" | "fb_nlt_f" | "fb_nle_f" | "fb_ngt_f"
        | "fb_nge_f" | "fb_ord_f" | "fb_uno_f" => {
            fill_template(FP_SEL4_F_TMPL, opt, name, rec, seed)
        }
        "fc_sel_d" | "fb_ge_d" | "fb_le_d" | "fb_ne_d" | "fb_nlt_d" | "fb_nle_d" | "fb_ngt_d"
        | "fb_nge_d" | "fb_ord_d" | "fb_uno_d" => {
            fill_template(FP_SEL4_D_TMPL, opt, name, rec, seed)
        }
        "fc_selor_d" | "fc_seland_d" => fill_template(FP_SEL6_D_TMPL, opt, name, rec, seed),
        "fc_selor3_f" | "fc_seland3_f" | "fc_seland3_mix_f" | "fb_and3_f" => {
            fill_template(FP_SEL8_F_TMPL, opt, name, rec, seed)
        }
        "fp_ninth_f" => fill_template(FP_NINTH_F_TMPL, opt, name, rec, seed),
        "fp_ninth_d" => fill_template(FP_NINTH_D_TMPL, opt, name, rec, seed),
        "fp_mixed_i_then_f" => fill_template(FP_MIXED_I_THEN_F_TMPL, opt, name, rec, seed),
        "fp_mixed_i_then_d" => fill_template(FP_MIXED_I_THEN_D_TMPL, opt, name, rec, seed),
        "fp_mixed_f_then_i" => fill_template(FP_MIXED_F_THEN_I_TMPL, opt, name, rec, seed),
        "fp_mixed_d_then_i" => fill_template(FP_MIXED_D_THEN_I_TMPL, opt, name, rec, seed),
        "fc_tmin_f" | "fc_tmax_f" | "fc_pickeq_f" => {
            fill_template(FP_SEL2_F_TMPL, opt, name, rec, seed)
        }
        "fc_tmin_d" | "fc_tmax_d" | "fc_pickeq_d" => {
            fill_template(FP_SEL2_D_TMPL, opt, name, rec, seed)
        }
        "fc_seland_f" | "fc_selor_f" => fill_template(FP_SEL6_F_TMPL, opt, name, rec, seed),
        "fp_to_int_s" | "fp_to_uint_s" | "fcvt_floor_s" | "fcvt_ceil_s" | "fcvt_away_s"
        | "fcvt_floor_us" | "fcvt_ceil_us" | "fcvt_away_us" => {
            fill_template(FP_TO_I32_F_TMPL, opt, name, rec, seed)
        }
        "fp_to_ulong_d" | "fcvt_floor_d" | "fcvt_ceil_d" | "fcvt_away_d" | "fcvt_floor_ud" => {
            fill_template(FP_TO_U64_D_TMPL, opt, name, rec, seed)
        }
        "fx_scvtf_f_w" => fixed_int_to_fp_block(opt, name, rec, seed, "int", false),
        "fx_scvtf_d_w" => fixed_int_to_fp_block(opt, name, rec, seed, "int", true),
        "fx_scvtf_f_x" => fixed_int_to_fp_block(opt, name, rec, seed, "long long", false),
        "fx_scvtf_d_x" => fixed_int_to_fp_block(opt, name, rec, seed, "long long", true),
        "fx_ucvtf_f_w" => fixed_int_to_fp_block(opt, name, rec, seed, "unsigned", false),
        "fx_ucvtf_d_w" => fixed_int_to_fp_block(opt, name, rec, seed, "unsigned", true),
        "fx_ucvtf_f_x" => fixed_int_to_fp_block(opt, name, rec, seed, "unsigned long long", false),
        "fx_ucvtf_d_x" => fixed_int_to_fp_block(opt, name, rec, seed, "unsigned long long", true),
        "fx_fcvtzs_w_f" => fixed_fp_to_int_block(opt, name, rec, seed, false, 32, true, 16),
        "fx_fcvtzs_w_d" => fixed_fp_to_int_block(opt, name, rec, seed, true, 32, true, 4),
        "fx_fcvtzs_x_f" => fixed_fp_to_int_block(opt, name, rec, seed, false, 64, true, 32),
        "fx_fcvtzs_x_d" => fixed_fp_to_int_block(opt, name, rec, seed, true, 64, true, 64),
        "fx_fcvtzu_w_f" => fixed_fp_to_int_block(opt, name, rec, seed, false, 32, false, 32),
        "fx_fcvtzu_w_d" => fixed_fp_to_int_block(opt, name, rec, seed, true, 32, false, 4),
        "fx_fcvtzu_x_f" => fixed_fp_to_int_block(opt, name, rec, seed, false, 64, false, 16),
        "fx_fcvtzu_x_d" => fixed_fp_to_int_block(opt, name, rec, seed, true, 64, false, 64),
        "fp_from_int" => fill_template(FP_FROM_I32_D_TMPL, opt, name, rec, seed),
        "fp_from_uint" => fill_template(FP_FROM_U32_F_TMPL, opt, name, rec, seed),
        "fp_widen" => fill_template(FP_WIDEN_TMPL, opt, name, rec, seed),
        "fp_narrow" => fill_template(FP_NARROW_TMPL, opt, name, rec, seed),
        "fp_iavg" => fill_template(FP_IAVG_TMPL, opt, name, rec, seed),
        "fp_id_f" => fill_template(FP_ID_F_TMPL, opt, name, rec, seed),
        "fp_id_d" => fill_template(FP_ID_D_TMPL, opt, name, rec, seed),
        "ret1_f" | "ret2_f" | "ret25_f" | "rethalf_f" | "retn1_f" => {
            fill_template(FP_CONST_F_TMPL, opt, name, rec, seed)
        }
        "ret1_d" | "ret25_d" | "rethalf_d" | "retn3_d" | "retn1_d" => {
            fill_template(FP_CONST_D_TMPL, opt, name, rec, seed)
        }
        "fp_floor_d" | "fp_trunc_d" | "fp_round_d" | "fp_rint_d" | "fu_neg_d" | "fu_abs_d"
        | "fu_nabs_d" | "fz_relu_d" | "fz_nrelu_d" | "fz_mulz_d" | "fz_zsub_d" | "fz_addz_d"
        | "kadd_d" | "kmul_d" | "kmadd_d" | "ksub_d" | "tclamp0_d" | "tclamp1_d" | "tsel_d"
        | "tsel2_d" | "fs_sqrt_d" => fill_template(FP_UNARY_D_TMPL, opt, name, rec, seed),
        "fp_ceil_f" | "fu_neg_f" | "fu_abs_f" | "fu_nabs_f" | "fz_relu_f" | "fz_nrelu_f"
        | "fz_mulz_f" | "fz_zsub_f" | "fz_addz_f" | "kadd_f" | "kmul_f" | "kmadd_f" | "ksub_f"
        | "tclamp0_f" | "tclamp1_f" | "tsel_f" | "tsel2_f" | "fs_sqrt_f" | "fs_rsqrt_f" => {
            fill_template(FP_UNARY_F_TMPL, opt, name, rec, seed)
        }
        "fp_second" => fill_template(FP_SECOND_TMPL, opt, name, rec, seed),
        "fp_pick3" => fill_template(FP_PICK3_TMPL, opt, name, rec, seed),
        "fp_get" => fill_template(FP_GET_F_TMPL, opt, name, rec, seed),
        "fp_get_d" => fill_template(FP_GET_D_TMPL, opt, name, rec, seed),
        "fp_put" => fill_template(FP_PUT_TMPL, opt, name, rec, seed),
        "fp_bits_gpr" => fill_template(FP_BITS_GPR_TMPL, opt, name, rec, seed),
        "abs_diff" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 60001) - 30000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 60001) - 30000)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "clamp_sel" | "select4" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "and_or_cond" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 7) - 3)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 7) - 3)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 7) - 3)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 7) - 3)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "vol_four_slots" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                ocast: "int",
            }],
            false,
            None,
        ),
        "vol_two_guards" | "min3" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 100001) - 50000)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "sign_of" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 7) - 3)",
                ocast: "int",
            }],
            false,
            None,
        ),
        "saturating_add" | "sat_sub" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "do_while_sum" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 64) - 3)",
                ocast: "int",
            }],
            false,
            None,
        ),
        "sw_small" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 10) - 2)",
                ocast: "int",
            }],
            false,
            None,
        ),
        "sw_sparse" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int[]){1,7,19,45,0,2,8,44,46,-1,100}[xs(&s) % 11])",
                ocast: "int",
            }],
            false,
            None,
        ),
        "popcount_loop" | "bitmix" | "bswap32" | "clz32" | "bfx" | "ctz32" | "rev16_w" => {
            scalar_block(
                opt,
                name,
                rec,
                seed,
                &[Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                }],
                false,
                None,
            )
        }
        "mask_hi" | "bswap64" | "rev16_x" | "rev32_x" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "xs(&s)",
                ocast: "unsigned long long",
            }],
            true,
            None,
        ),
        "mul_widen" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
            ],
            true,
            None,
        ),
        "mul_widen_s" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
            ],
            true,
            None,
        ),
        "div_s" | "mod_s" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "int",
                },
            ],
            false,
            Some("(int)a1 != 0 && !((int)a0 == (-2147483647-1) && (int)a1 == -1)"),
        ),
        "div_u" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
            ],
            false,
            Some("(unsigned)a1 != 0"),
        ),
        "shifts" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "xs(&s)",
                    ocast: "unsigned long long",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)(1 + (int)(xs(&s) % 63))",
                    ocast: "int",
                },
            ],
            true,
            None,
        ),
        "rotate_left" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)(1 + (unsigned)(xs(&s) % 31))",
                    ocast: "unsigned",
                },
            ],
            false,
            None,
        ),
        "idx_int" => idx_block(opt, name, rec, seed, "int", INT_FILL, false),
        "idx_uint" => idx_block(opt, name, rec, seed, "unsigned", UINT_FILL, false),
        "idx_long8" => idx_block(opt, name, rec, seed, "long long", LONG_FILL, true),
        "idx_byte" => idx_block(opt, name, rec, seed, "char", CHAR_FILL, false),
        "pt_arr" => fill_template(PT_ARR_TMPL, opt, name, rec, seed),
        "sum_int_idx" | "find_early" | "even_count" => {
            count_block(opt, name, rec, seed, "int", INT_FILL, false, 0)
        }
        "arr_max" => count_block(opt, name, rec, seed, "int", INT_FILL, false, 1),
        "accum_u64" => count_block(
            opt,
            name,
            rec,
            seed,
            "unsigned long long",
            U64_FILL,
            true,
            0,
        ),
        "idx_two" => fill_template(IDX_TWO_TMPL, opt, name, rec, seed),
        "find_key" => fill_template(FIND_KEY_TMPL, opt, name, rec, seed),
        "nested_sum" => fill_template(NESTED_SUM_TMPL, opt, name, rec, seed),
        "idx_store" => fill_template(IDX_STORE_TMPL, opt, name, rec, seed),
        "mem_copy_manual" => fill_template(MEM_COPY_TMPL, opt, name, rec, seed),
        "ld_st_pair" => fill_template(LD_ST_PAIR_TMPL, opt, name, rec, seed),
        "str_len_manual" => fill_template(STR_LEN_TMPL, opt, name, rec, seed),
        "str_cmp_manual" => fill_template(STR_CMP_TMPL, opt, name, rec, seed),
        "pt_dot" => fill_template(PT_DOT_TMPL, opt, name, rec, seed),
        "abs_i32" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[Arg {
                draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 200001) - 100000)",
                ocast: "int",
            }],
            false,
            None,
        ),
        "bfi_merge" | "max_u" | "clamp_u" | "avg_floor_u" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)xs(&s)",
                    ocast: "unsigned",
                },
            ],
            false,
            None,
        ),
        "neg_if" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 200001) - 100000)",
                    ocast: "int",
                },
                Arg {
                    draw: "(uint64_t)(uint32_t)((int)(xs(&s) % 4) - 2)",
                    ocast: "int",
                },
            ],
            false,
            None,
        ),
        "hi_mul_u" | "funnel_shift" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "xs(&s)",
                    ocast: "unsigned long long",
                },
                Arg {
                    draw: "xs(&s)",
                    ocast: "unsigned long long",
                },
            ],
            true,
            None,
        ),
        "hi_mul_s" => scalar_block(
            opt,
            name,
            rec,
            seed,
            &[
                Arg {
                    draw: "xs(&s)",
                    ocast: "long long",
                },
                Arg {
                    draw: "xs(&s)",
                    ocast: "long long",
                },
            ],
            true,
            None,
        ),
        _ => return None,
    };
    let seeded: bool = block.contains("uint64_t s =");
    let block: String = block.replace(
        "; int ok = 1;",
        "; grade_seed = s; grade_seed_valid = 1; int ok = 1;",
    );
    if seeded {
        Some(block)
    } else {
        Some(format!("    grade_seed_valid = 0;\n{block}"))
    }
}

pub(crate) fn ground_truth_source() -> String {
    format!(
        "#include <stdint.h>\n{}\n{GROUND_TRUTH_C_BODY}",
        fp_model::MODEL_C
    )
}

pub(crate) fn build_ground_truth_object(compiler: &str, dir: &Path) -> Result<PathBuf, String> {
    let battery_c: PathBuf = dir.join("gt_battery.c");
    std::fs::write(&battery_c, ground_truth_source().as_bytes())
        .expect("write ground-truth battery");
    let battery_o: PathBuf = dir.join("gt_battery.o");
    let compiled: std::process::Output = Command::new(compiler)
        .args(ORACLE_FLAGS)
        .args(["-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for ground-truth battery");
    if compiled.status.success() {
        Ok(battery_o)
    } else {
        Err(String::from_utf8_lossy(&compiled.stderr).into_owned())
    }
}

pub(crate) fn run_with_watchdog(exe: &Path, budget: Duration) -> Option<std::process::Output> {
    let mut child: std::process::Child = Command::new(exe)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn grade harness");
    if child
        .wait_timeout(budget)
        .expect("wait_timeout grade harness")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    Some(child.wait_with_output().expect("collect harness output"))
}

fn shared_prelude_lines() -> &'static BTreeSet<String> {
    static LINES: OnceLock<BTreeSet<String>> = OnceLock::new();
    LINES.get_or_init(|| fp_semantics::prelude_lines().into_iter().collect())
}

pub(crate) fn shared_prelude() -> String {
    fp_semantics::prelude_source()
}

pub(crate) fn rename_recovered(source: &str, rec: &str) -> String {
    let prelude: &BTreeSet<String> = shared_prelude_lines();
    let lines: Vec<&str> = source.lines().collect();
    let mut start: usize = 0;
    while let Some(line) = lines.get(start) {
        let shared: bool = line.starts_with("#include")
            || line.starts_with("static inline double fp_d_from_bits")
            || line.starts_with("static inline uint64_t fp_d_to_bits")
            || line.starts_with("static inline float fp_f_from_bits")
            || line.starts_with("static inline uint32_t fp_f_to_bits")
            || line.starts_with("static inline _Float16 fp_h_from_bits")
            || line.starts_with("static inline uint16_t fp_h_to_bits")
            || prelude.contains(*line);
        if !shared {
            break;
        }
        start = start.saturating_add(1);
    }
    lines.get(start..).unwrap_or_default().join("\n").replacen(
        " recovered(",
        &format!(" {rec}("),
        1,
    )
}
