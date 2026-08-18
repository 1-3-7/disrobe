typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;

#pragma clang fp contract(off)

int idx_int(int *a, int i) { return a[i]; }
unsigned idx_uint(unsigned *a, unsigned i) { return a[i]; }
long idx_long8(long *a, int i) { return a[i]; }
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
int fp_to_int_s(float x) { return (int)x; }
unsigned fp_to_uint_s(float x) { return (unsigned)x; }
u64 fp_to_ulong_d(double x) { return (u64)x; }
double fp_from_int(int x) { return (double)x; }
float fp_from_uint(unsigned x) { return (float)(u64)x; }
double fp_widen(float x) { return (double)x; }
float fp_narrow(double x) { return (float)x; }

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

float fz_relu_f(float x) { return __builtin_fmaxf(x, 0.0f); }
double fz_relu_d(double x) { return __builtin_fmax(x, 0.0); }
float fz_nrelu_f(float x) { return __builtin_fminf(x, 0.0f); }
double fz_nrelu_d(double x) { return __builtin_fmin(x, 0.0); }
float fz_mulz_f(float x) { return x * 0.0f; }
double fz_mulz_d(double x) { return x * 0.0; }
float fz_zsub_f(float x) { return 0.0f - x; }
double fz_zsub_d(double x) { return 0.0 - x; }
float fz_addz_f(float x) { return x + 0.0f; }
double fz_addz_d(double x) { return x + 0.0; }

i32 fcvt_floor_s(float x) { return (i32)__builtin_floorf(x); }
i32 fcvt_ceil_s(float x) { return (i32)__builtin_ceilf(x); }
i32 fcvt_away_s(float x) { return (i32)__builtin_roundf(x); }
u32 fcvt_floor_us(float x) { return (u32)__builtin_floorf(x); }
u32 fcvt_ceil_us(float x) { return (u32)__builtin_ceilf(x); }
u32 fcvt_away_us(float x) { return (u32)__builtin_roundf(x); }
i64 fcvt_floor_d(double x) { return (i64)__builtin_floor(x); }
i64 fcvt_ceil_d(double x) { return (i64)__builtin_ceil(x); }
i64 fcvt_away_d(double x) { return (i64)__builtin_round(x); }
u64 fcvt_floor_ud(double x) { return (u64)__builtin_floor(x); }

double fp_iavg(const int *a, int n) {
    volatile double zero = (double)n;
    double s = zero - zero;
#pragma clang loop vectorize(disable) interleave(disable)
    for (int i = n; i > 0; i--) s += (double)a[i - 1];
    return s / (double)(n ? n : 1);
}

double fp_floor_d(double x) { return __builtin_floor(x); }
float fp_ceil_f(float x) { return __builtin_ceilf(x); }
double fp_trunc_d(double x) { return __builtin_trunc(x); }
double fp_round_d(double x) { return __builtin_round(x); }
double fp_rint_d(double x) { return __builtin_rint(x); }

float fp_max_f(float a, float b) { return __builtin_fmaxf(a, b); }
float fp_min_f(float a, float b) { return __builtin_fminf(a, b); }
double fp_max_d(double a, double b) { return __builtin_fmax(a, b); }
double fp_min_d(double a, double b) { return __builtin_fmin(a, b); }
float fp_clamp_f(float x, float lo, float hi) { return __builtin_fminf(__builtin_fmaxf(x, lo), hi); }

float fma_madd_f(float a, float b, float c) { return __builtin_fmaf(a, b, c); }
float fma_msub_f(float a, float b, float c) { return __builtin_fmaf(-a, b, c); }
float fma_nmadd_f(float a, float b, float c) { return __builtin_fmaf(-a, b, -c); }
float fma_nmsub_f(float a, float b, float c) { return __builtin_fmaf(a, b, -c); }
double fma_madd_d(double a, double b, double c) { return __builtin_fma(a, b, c); }
double fma_msub_d(double a, double b, double c) { return __builtin_fma(-a, b, c); }
double fma_nmadd_d(double a, double b, double c) { return __builtin_fma(-a, b, -c); }
double fma_nmsub_d(double a, double b, double c) { return __builtin_fma(a, b, -c); }
float mul_add_unfused_f(float a, float b, float c) { return a * b + c; }
double mul_add_unfused_d(double a, double b, double c) { return a * b + c; }
float sub_mul_unfused_f(float a, float b, float c) { return c - a * b; }
double sub_mul_unfused_d(double a, double b, double c) { return c - a * b; }
float fma_mixed_f(float a, float b, float c) { return __builtin_fmaf(a, b, c) + a * b; }
double fma_mixed_d(double a, double b, double c) { return __builtin_fma(a, b, c) + a * b; }
float fma_chained_f(float a, float b, float c) { return __builtin_fmaf(a, a, __builtin_fmaf(b, c, a)); }
double fma_chained_d(double a, double b, double c) { return __builtin_fma(a, a, __builtin_fma(b, c, a)); }

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
unsigned rev16_w(unsigned x) { return ((x & 0xff00ff00u) >> 8) | ((x & 0x00ff00ffu) << 8); }
u64 rev16_x(u64 x) { return ((x & 0xff00ff00ff00ff00ull) >> 8) | ((x & 0x00ff00ff00ff00ffull) << 8); }
u64 rev32_x(u64 x) { return ((u64)__builtin_bswap32((unsigned)(x >> 32)) << 32) | (u64)__builtin_bswap32((unsigned)x); }
float fs_sqrt_f(float x) { return __builtin_sqrtf(x); }
double fs_sqrt_d(double x) { return __builtin_sqrt(x); }
float fs_hypot_f(float a, float b) { return __builtin_sqrtf(a * a + b * b); }
double fs_norm3_d(double a, double b, double c) { return __builtin_sqrt(a * a + b * b + c * c); }
float fs_rsqrt_f(float x) { return 1.0f / __builtin_sqrtf(x); }
double fs_sqrt_sum_d(double a, double b) { return __builtin_sqrt(a) + __builtin_sqrt(b); }
float fs_sqrt_scaled_f(float x, float k) { return k * __builtin_sqrtf(x); }
double fs_sqrt_diff_d(double a, double b) { return __builtin_sqrt(a) - b; }
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

float fx_scvtf_f_w(int a, int b) { return (float)(a + b) / 65536.0f; }
double fx_scvtf_d_w(int a, int b) { return (double)(a + b) / 4294967296.0; }
float fx_scvtf_f_x(long long a, long long b) { return (float)(a + b) / 18446744073709551616.0f; }
double fx_scvtf_d_x(long long a, long long b) { return (double)(a + b) / 65536.0; }
float fx_ucvtf_f_w(unsigned a, unsigned b) { return (float)(a + b) / 65536.0f; }
double fx_ucvtf_d_w(unsigned a, unsigned b) { return (double)(a + b) / 2.0; }
float fx_ucvtf_f_x(u64 a, u64 b) { return (float)(a + b) / 65536.0f; }
double fx_ucvtf_d_x(u64 a, u64 b) { return (double)(a + b) / 4294967296.0; }
i32 fx_fcvtzs_w_f(float x) { return (i32)(x * 65536.0f); }
i32 fx_fcvtzs_w_d(double x) { return (i32)(x * 16.0); }
i64 fx_fcvtzs_x_f(float x) { return (i64)(x * 4294967296.0f); }
i64 fx_fcvtzs_x_d(double x) { return (i64)(x * 18446744073709551616.0); }
u32 fx_fcvtzu_w_f(float x) { return (u32)(x * 4294967296.0f); }
u32 fx_fcvtzu_w_d(double x) { return (u32)(x * 16.0); }
u64 fx_fcvtzu_x_f(float x) { return (u64)(x * 65536.0f); }
u64 fx_fcvtzu_x_d(double x) { return (u64)(x * 18446744073709551616.0); }
