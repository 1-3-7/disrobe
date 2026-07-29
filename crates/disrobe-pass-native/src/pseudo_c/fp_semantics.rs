use std::collections::BTreeSet;

use super::{FpWidth, RoundMode, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpHelper {
    pub name: &'static str,
    pub deps: &'static [&'static str],
    pub source: &'static str,
}

const SIGNED_WRAP: &str = "static inline int32_t fpx_i32_of(uint32_t v) { return v < 0x80000000u ? (int32_t)v : -(int32_t)(0xffffffffu - v) - 1; }
static inline int64_t fpx_i64_of(uint64_t v) { return v < 0x8000000000000000ull ? (int64_t)v : -(int64_t)(0xffffffffffffffffull - v) - 1; }";

const WIDE: &str = r"typedef struct { uint64_t hi; uint64_t lo; } fpx_w128;
static inline fpx_w128 fpx_w128_of(uint64_t v) { fpx_w128 r; r.hi = 0; r.lo = v; return r; }
static inline fpx_w128 fpx_w128_shl(fpx_w128 v, unsigned n) {
    fpx_w128 r;
    if (n == 0u) return v;
    if (n >= 128u) { r.hi = 0; r.lo = 0; return r; }
    if (n >= 64u) { r.hi = v.lo << (n - 64u); r.lo = 0; return r; }
    r.hi = (v.hi << n) | (v.lo >> (64u - n));
    r.lo = v.lo << n;
    return r;
}
static inline fpx_w128 fpx_w128_shr(fpx_w128 v, unsigned n) {
    fpx_w128 r;
    if (n == 0u) return v;
    if (n >= 128u) { r.hi = 0; r.lo = 0; return r; }
    if (n >= 64u) { r.lo = v.hi >> (n - 64u); r.hi = 0; return r; }
    r.lo = (v.lo >> n) | (v.hi << (64u - n));
    r.hi = v.hi >> n;
    return r;
}
static inline fpx_w128 fpx_w128_add(fpx_w128 a, fpx_w128 b) {
    fpx_w128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1ull : 0ull);
    return r;
}
static inline fpx_w128 fpx_w128_sub(fpx_w128 a, fpx_w128 b) {
    fpx_w128 r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1ull : 0ull);
    return r;
}
static inline int fpx_w128_cmp(fpx_w128 a, fpx_w128 b) {
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
    return 0;
}
static inline unsigned fpx_w128_bit(fpx_w128 v, unsigned n) {
    if (n >= 128u) return 0u;
    if (n >= 64u) return (unsigned)((v.hi >> (n - 64u)) & 1ull);
    return (unsigned)((v.lo >> n) & 1ull);
}
static inline int fpx_w128_low_set(fpx_w128 v, unsigned n) {
    if (n == 0u) return 0;
    if (n >= 128u) return (v.hi | v.lo) != 0ull;
    if (n > 64u) return (v.lo != 0ull) || ((v.hi & ((((uint64_t)1 << (n - 64u)) - 1ull))) != 0ull);
    if (n == 64u) return v.lo != 0ull;
    return (v.lo & (((uint64_t)1 << n) - 1ull)) != 0ull;
}
static inline int fpx_w128_msb(fpx_w128 v) {
    unsigned i;
    if (v.hi != 0ull) { for (i = 64u; i > 0u; i--) { if ((v.hi >> (i - 1u)) & 1ull) return (int)(63u + i); } }
    if (v.lo != 0ull) { for (i = 64u; i > 0u; i--) { if ((v.lo >> (i - 1u)) & 1ull) return (int)(i - 1u); } }
    return -1;
}
static inline fpx_w128 fpx_w128_mul(uint64_t a, uint64_t b) {
    uint64_t al = a & 0xffffffffull, ah = a >> 32, bl = b & 0xffffffffull, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (lh & 0xffffffffull) + (hl & 0xffffffffull);
    fpx_w128 r;
    r.lo = (ll & 0xffffffffull) | (mid << 32);
    r.hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    return r;
}";

const ROUND_PACK: &str = r"static inline uint64_t fpx_round_pack(unsigned sign, int exp2, fpx_w128 sig, int sticky, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    uint64_t sign_bit = (uint64_t)sign << (mbits + ebits);
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    int msb = fpx_w128_msb(sig);
    int top, unit, shift, field;
    uint64_t m;
    unsigned round_bit;
    if (msb < 0) return sign_bit;
    top = msb + exp2;
    unit = top - (int)prec + 1;
    if (unit < 1 - bias - (int)mbits) unit = 1 - bias - (int)mbits;
    shift = unit - exp2;
    if (shift > 0) {
        round_bit = fpx_w128_bit(sig, (unsigned)(shift - 1));
        if (fpx_w128_low_set(sig, (unsigned)(shift - 1))) sticky = 1;
        m = fpx_w128_shr(sig, (unsigned)shift).lo;
    } else {
        round_bit = 0u;
        m = fpx_w128_shl(sig, (unsigned)(-shift)).lo;
    }
    if (round_bit != 0u && (sticky != 0 || (m & 1ull) != 0ull)) m += 1ull;
    if ((m >> prec) != 0ull) { m >>= 1; unit += 1; }
    if (m == 0ull) return sign_bit;
    if ((m >> mbits) != 0ull) {
        field = unit + (int)mbits + bias;
        if (field >= (int)((1u << ebits) - 1u)) return sign_bit | ((uint64_t)((1u << ebits) - 1u) << mbits);
        return sign_bit | ((uint64_t)(unsigned)field << mbits) | (m & frac_mask);
    }
    return sign_bit | m;
}";

const FMA_CORE: &str = r"static inline uint64_t fpx_fma_core(uint64_t ba, uint64_t bb, uint64_t bc, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    uint64_t inf_bits = (uint64_t)emax << mbits;
    uint64_t default_nan = inf_bits | quiet;
    unsigned sa = (bc & sign_mask) != 0ull, s1 = (ba & sign_mask) != 0ull, s2 = (bb & sign_mask) != 0ull;
    unsigned ea = (unsigned)((bc >> mbits) & emax), e1 = (unsigned)((ba >> mbits) & emax), e2 = (unsigned)((bb >> mbits) & emax);
    uint64_t fa = bc & frac_mask, f1 = ba & frac_mask, f2 = bb & frac_mask;
    int nan_a = (ea == emax && fa != 0ull), nan_1 = (e1 == emax && f1 != 0ull), nan_2 = (e2 == emax && f2 != 0ull);
    int inf_a = (ea == emax && fa == 0ull), inf_1 = (e1 == emax && f1 == 0ull), inf_2 = (e2 == emax && f2 == 0ull);
    int zero_a = (ea == 0u && fa == 0ull), zero_1 = (e1 == 0u && f1 == 0ull), zero_2 = (e2 == 0u && f2 == 0ull);
    unsigned sp = s1 ^ s2;
    int bad_product = (inf_1 && zero_2) || (zero_1 && inf_2);
    uint64_t m1, m2, ma;
    int x1, x2, xa, xp, top_p, top_a, frame, shift_p, shift_a, sticky_p = 0, sticky_a = 0, sticky = 0, order;
    fpx_w128 prod, add, acc;
    unsigned sr;
    if (nan_a && (fa & quiet) != 0ull && bad_product) return default_nan;
    if (nan_a && (fa & quiet) == 0ull) return bc | quiet;
    if (nan_1 && (f1 & quiet) == 0ull) return ba | quiet;
    if (nan_2 && (f2 & quiet) == 0ull) return bb | quiet;
    if (nan_a) return bc;
    if (nan_1) return ba;
    if (nan_2) return bb;
    if (bad_product) return default_nan;
    if (inf_a && (inf_1 || inf_2) && sa != sp) return default_nan;
    if ((inf_a && sa == 0u) || ((inf_1 || inf_2) && sp == 0u)) return inf_bits;
    if (inf_a || inf_1 || inf_2) return sign_mask | inf_bits;
    if (zero_a && (zero_1 || zero_2)) return (sa == sp && sa != 0u) ? sign_mask : (uint64_t)0;
    if (zero_1 || zero_2) return bc;
    m1 = (e1 == 0u) ? f1 : (((uint64_t)1 << mbits) | f1);
    x1 = (e1 == 0u) ? (1 - bias - (int)mbits) : ((int)e1 - bias - (int)mbits);
    m2 = (e2 == 0u) ? f2 : (((uint64_t)1 << mbits) | f2);
    x2 = (e2 == 0u) ? (1 - bias - (int)mbits) : ((int)e2 - bias - (int)mbits);
    ma = (ea == 0u) ? fa : (((uint64_t)1 << mbits) | fa);
    xa = (ea == 0u) ? (1 - bias - (int)mbits) : ((int)ea - bias - (int)mbits);
    prod = fpx_w128_mul(m1, m2);
    add = fpx_w128_of(ma);
    xp = x1 + x2;
    top_p = fpx_w128_msb(prod) + xp;
    top_a = (ma == 0ull) ? (top_p - 1) : (fpx_w128_msb(add) + xa);
    frame = ((top_p > top_a) ? top_p : top_a) - 126;
    shift_p = xp - frame;
    if (shift_p >= 0) { prod = fpx_w128_shl(prod, (unsigned)shift_p); }
    else { sticky_p = fpx_w128_low_set(prod, (unsigned)(-shift_p)); prod = fpx_w128_shr(prod, (unsigned)(-shift_p)); }
    shift_a = xa - frame;
    if (shift_a >= 0) { add = fpx_w128_shl(add, (unsigned)shift_a); }
    else { sticky_a = fpx_w128_low_set(add, (unsigned)(-shift_a)); add = fpx_w128_shr(add, (unsigned)(-shift_a)); }
    if (sa == sp) {
        acc = fpx_w128_add(prod, add);
        sticky = sticky_p | sticky_a;
        sr = sp;
    } else {
        order = fpx_w128_cmp(prod, add);
        if (order > 0) {
            acc = fpx_w128_sub(prod, add);
            sr = sp;
            if (sticky_a != 0) { acc = fpx_w128_sub(acc, fpx_w128_of(1)); sticky = 1; }
        } else if (order < 0) {
            acc = fpx_w128_sub(add, prod);
            sr = sa;
            if (sticky_p != 0) { acc = fpx_w128_sub(acc, fpx_w128_of(1)); sticky = 1; }
        } else {
            return 0;
        }
    }
    return fpx_round_pack(sr, frame, acc, sticky, prec, ebits);
}";

const FMA_F32: &str = "static inline float fpx_fma_f32(float a, float b, float c) { return fp_f_from_bits((uint32_t)fpx_fma_core((uint64_t)fp_f_to_bits(a), (uint64_t)fp_f_to_bits(b), (uint64_t)fp_f_to_bits(c), 24u, 8u)); }";

const FMA_F64: &str = "static inline double fpx_fma_f64(double a, double b, double c) { return fp_d_from_bits(fpx_fma_core(fp_d_to_bits(a), fp_d_to_bits(b), fp_d_to_bits(c), 53u, 11u)); }";

const RINT_CORE: &str = r"static inline uint64_t fpx_rint_core(uint64_t b, unsigned prec, unsigned ebits, unsigned mode) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign = b & ((uint64_t)1 << (mbits + ebits));
    unsigned exp = (unsigned)((b >> mbits) & emax);
    uint64_t frac = b & frac_mask;
    int unbiased, up, msb;
    unsigned shift;
    uint64_t sig, ip, rem, half, man;
    if (exp == emax) return (frac != 0ull) ? (b | ((uint64_t)1 << (mbits - 1u))) : b;
    if (exp == 0u && frac == 0ull) return b;
    unbiased = (int)exp - bias;
    if (unbiased >= (int)mbits) return b;
    if (unbiased < 0) {
        int above = (exp != 0u) && (unbiased == -1) && (frac != 0ull);
        int at_half = (exp != 0u) && (unbiased == -1) && (frac == 0ull);
        if (mode == 1u) up = (sign != 0ull);
        else if (mode == 2u) up = (sign == 0ull);
        else if (mode == 3u) up = 0;
        else if (mode == 4u) up = above || at_half;
        else up = above;
        return up ? (sign | ((uint64_t)(unsigned)bias << mbits)) : sign;
    }
    shift = mbits - (unsigned)unbiased;
    sig = ((uint64_t)1 << mbits) | frac;
    ip = sig >> shift;
    rem = sig & ((((uint64_t)1 << shift) - 1ull));
    half = (uint64_t)1 << (shift - 1u);
    if (mode == 1u) up = (sign != 0ull) && rem != 0ull;
    else if (mode == 2u) up = (sign == 0ull) && rem != 0ull;
    else if (mode == 3u) up = 0;
    else if (mode == 4u) up = rem >= half;
    else up = (rem > half) || (rem == half && (ip & 1ull) != 0ull);
    ip += up ? 1ull : 0ull;
    msb = 63;
    while (((ip >> (unsigned)msb) & 1ull) == 0ull) msb--;
    man = (msb <= (int)mbits) ? ((ip << (unsigned)((int)mbits - msb)) & frac_mask) : ((ip >> (unsigned)(msb - (int)mbits)) & frac_mask);
    return sign | ((uint64_t)(unsigned)(msb + bias) << mbits) | man;
}";

const MINMAX_CORE: &str = r"static inline uint64_t fpx_minmax_core(uint64_t a, uint64_t b, unsigned prec, unsigned ebits, int is_max) {
    unsigned mbits = prec - 1u;
    unsigned emax = (1u << ebits) - 1u;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    uint64_t inf_bits = (uint64_t)emax << mbits;
    uint64_t full = (sign_mask << 1) - 1ull;
    uint64_t abs_a = a & (sign_mask - 1ull);
    uint64_t abs_b = b & (sign_mask - 1ull);
    int nan_a = abs_a > inf_bits, nan_b = abs_b > inf_bits;
    uint64_t ka, kb;
    if (nan_a && (a & quiet) == 0ull) return a | quiet;
    if (nan_b && (b & quiet) == 0ull) return b | quiet;
    if (nan_a && nan_b) return a;
    if (nan_a) return b;
    if (nan_b) return a;
    if (abs_a == 0ull && abs_b == 0ull) return is_max ? ((a & b) & sign_mask) : ((a | b) & sign_mask);
    ka = (a & sign_mask) != 0ull ? (~a & full) : (a | sign_mask);
    kb = (b & sign_mask) != 0ull ? (~b & full) : (b | sign_mask);
    if (is_max) return ka > kb ? a : b;
    return ka < kb ? a : b;
}";

const CVT_CORE: &str = r"static inline uint64_t fpx_cvt_core(uint64_t b, unsigned prec, unsigned ebits, int is_signed, unsigned dbits, int saturate) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t dmask = dbits >= 64u ? ~(uint64_t)0 : ((((uint64_t)1 << dbits) - 1ull));
    uint64_t indefinite = (uint64_t)1 << (dbits - 1u);
    unsigned sign = (b & sign_mask) != 0ull;
    unsigned exp = (unsigned)((b >> mbits) & emax);
    uint64_t frac = b & frac_mask;
    unsigned limit;
    uint64_t sig, mag;
    int unbiased;
    if (exp == emax && frac != 0ull) return saturate ? (uint64_t)0 : indefinite;
    unbiased = (int)exp - bias;
    if (exp == 0u || unbiased < 0) return 0;
    limit = is_signed ? dbits - 1u : dbits;
    if ((unsigned)unbiased >= limit) {
        if (is_signed && sign != 0u && frac == 0ull && (unsigned)unbiased == limit) return indefinite;
        if (!saturate) return indefinite;
        if (!is_signed) return sign != 0u ? (uint64_t)0 : dmask;
        return sign != 0u ? indefinite : (dmask >> 1);
    }
    sig = ((uint64_t)1 << mbits) | frac;
    mag = ((unsigned)unbiased >= mbits) ? (sig << ((unsigned)unbiased - mbits)) : (sig >> (mbits - (unsigned)unbiased));
    if (!is_signed) return sign != 0u ? (uint64_t)0 : mag;
    return sign != 0u ? (((uint64_t)0 - mag) & dmask) : mag;
}";

const SQRT_F32: &str = r"static inline float fpx_sqrt_f32(float x) {
    uint32_t b = fp_f_to_bits(x);
    uint32_t magnitude = b & 0x7fffffffu;
    if (magnitude > 0x7f800000u) return fp_f_from_bits(b | 0x00400000u);
    if (magnitude == 0u) return x;
    if ((b & 0x80000000u) != 0u) return fp_f_from_bits(0x7fc00000u);
    if (magnitude == 0x7f800000u) return x;
    return __builtin_sqrtf(x);
}";

const SQRT_F64: &str = r"static inline double fpx_sqrt_f64(double x) {
    uint64_t b = fp_d_to_bits(x);
    uint64_t magnitude = b & 0x7fffffffffffffffull;
    if (magnitude > 0x7ff0000000000000ull) return fp_d_from_bits(b | 0x0008000000000000ull);
    if (magnitude == 0ull) return x;
    if ((b & 0x8000000000000000ull) != 0ull) return fp_d_from_bits(0x7ff8000000000000ull);
    if (magnitude == 0x7ff0000000000000ull) return x;
    return __builtin_sqrt(x);
}";

const SQRT_X86_F32: &str = r"static inline float fpx_sqrt_x86_f32(float x) {
    uint32_t b = fp_f_to_bits(x);
    uint32_t magnitude = b & 0x7fffffffu;
    if (magnitude > 0x7f800000u) return fp_f_from_bits(b | 0x00400000u);
    if (magnitude == 0u) return x;
    if ((b & 0x80000000u) != 0u) return fp_f_from_bits(0xffc00000u);
    if (magnitude == 0x7f800000u) return x;
    return __builtin_sqrtf(x);
}";

const SQRT_X86_F64: &str = r"static inline double fpx_sqrt_x86_f64(double x) {
    uint64_t b = fp_d_to_bits(x);
    uint64_t magnitude = b & 0x7fffffffffffffffull;
    if (magnitude > 0x7ff0000000000000ull) return fp_d_from_bits(b | 0x0008000000000000ull);
    if (magnitude == 0ull) return x;
    if ((b & 0x8000000000000000ull) != 0ull) return fp_d_from_bits(0xfff8000000000000ull);
    if (magnitude == 0x7ff0000000000000ull) return x;
    return __builtin_sqrt(x);
}";

const RINT_WRAPPERS: &[(&str, &str)] = &[
    (
        "fpx_rintn_f32",
        "static inline float fpx_rintn_f32(float x) { return fp_f_from_bits((uint32_t)fpx_rint_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 0u)); }",
    ),
    (
        "fpx_rintm_f32",
        "static inline float fpx_rintm_f32(float x) { return fp_f_from_bits((uint32_t)fpx_rint_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 1u)); }",
    ),
    (
        "fpx_rintp_f32",
        "static inline float fpx_rintp_f32(float x) { return fp_f_from_bits((uint32_t)fpx_rint_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 2u)); }",
    ),
    (
        "fpx_rintz_f32",
        "static inline float fpx_rintz_f32(float x) { return fp_f_from_bits((uint32_t)fpx_rint_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 3u)); }",
    ),
    (
        "fpx_rinta_f32",
        "static inline float fpx_rinta_f32(float x) { return fp_f_from_bits((uint32_t)fpx_rint_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 4u)); }",
    ),
    (
        "fpx_rintn_f64",
        "static inline double fpx_rintn_f64(double x) { return fp_d_from_bits(fpx_rint_core(fp_d_to_bits(x), 53u, 11u, 0u)); }",
    ),
    (
        "fpx_rintm_f64",
        "static inline double fpx_rintm_f64(double x) { return fp_d_from_bits(fpx_rint_core(fp_d_to_bits(x), 53u, 11u, 1u)); }",
    ),
    (
        "fpx_rintp_f64",
        "static inline double fpx_rintp_f64(double x) { return fp_d_from_bits(fpx_rint_core(fp_d_to_bits(x), 53u, 11u, 2u)); }",
    ),
    (
        "fpx_rintz_f64",
        "static inline double fpx_rintz_f64(double x) { return fp_d_from_bits(fpx_rint_core(fp_d_to_bits(x), 53u, 11u, 3u)); }",
    ),
    (
        "fpx_rinta_f64",
        "static inline double fpx_rinta_f64(double x) { return fp_d_from_bits(fpx_rint_core(fp_d_to_bits(x), 53u, 11u, 4u)); }",
    ),
];

const MINMAX_WRAPPERS: &[(&str, &str)] = &[
    (
        "fpx_maxnum_f32",
        "static inline float fpx_maxnum_f32(float a, float b) { return fp_f_from_bits((uint32_t)fpx_minmax_core((uint64_t)fp_f_to_bits(a), (uint64_t)fp_f_to_bits(b), 24u, 8u, 1)); }",
    ),
    (
        "fpx_minnum_f32",
        "static inline float fpx_minnum_f32(float a, float b) { return fp_f_from_bits((uint32_t)fpx_minmax_core((uint64_t)fp_f_to_bits(a), (uint64_t)fp_f_to_bits(b), 24u, 8u, 0)); }",
    ),
    (
        "fpx_maxnum_f64",
        "static inline double fpx_maxnum_f64(double a, double b) { return fp_d_from_bits(fpx_minmax_core(fp_d_to_bits(a), fp_d_to_bits(b), 53u, 11u, 1)); }",
    ),
    (
        "fpx_minnum_f64",
        "static inline double fpx_minnum_f64(double a, double b) { return fp_d_from_bits(fpx_minmax_core(fp_d_to_bits(a), fp_d_to_bits(b), 53u, 11u, 0)); }",
    ),
];

const CVT_WRAPPERS: &[(&str, &str)] = &[
    (
        "fpx_cvtsat_i32_f32",
        "static inline int32_t fpx_cvtsat_i32_f32(float x) { return fpx_i32_of((uint32_t)fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 1, 32u, 1)); }",
    ),
    (
        "fpx_cvtsat_i64_f32",
        "static inline int64_t fpx_cvtsat_i64_f32(float x) { return fpx_i64_of(fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 1, 64u, 1)); }",
    ),
    (
        "fpx_cvtsat_u32_f32",
        "static inline uint32_t fpx_cvtsat_u32_f32(float x) { return (uint32_t)fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 0, 32u, 1); }",
    ),
    (
        "fpx_cvtsat_u64_f32",
        "static inline uint64_t fpx_cvtsat_u64_f32(float x) { return fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 0, 64u, 1); }",
    ),
    (
        "fpx_cvtsat_i32_f64",
        "static inline int32_t fpx_cvtsat_i32_f64(double x) { return fpx_i32_of((uint32_t)fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 1, 32u, 1)); }",
    ),
    (
        "fpx_cvtsat_i64_f64",
        "static inline int64_t fpx_cvtsat_i64_f64(double x) { return fpx_i64_of(fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 1, 64u, 1)); }",
    ),
    (
        "fpx_cvtsat_u32_f64",
        "static inline uint32_t fpx_cvtsat_u32_f64(double x) { return (uint32_t)fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 0, 32u, 1); }",
    ),
    (
        "fpx_cvtsat_u64_f64",
        "static inline uint64_t fpx_cvtsat_u64_f64(double x) { return fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 0, 64u, 1); }",
    ),
    (
        "fpx_cvtind_i32_f32",
        "static inline int32_t fpx_cvtind_i32_f32(float x) { return fpx_i32_of((uint32_t)fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 1, 32u, 0)); }",
    ),
    (
        "fpx_cvtind_i64_f32",
        "static inline int64_t fpx_cvtind_i64_f32(float x) { return fpx_i64_of(fpx_cvt_core((uint64_t)fp_f_to_bits(x), 24u, 8u, 1, 64u, 0)); }",
    ),
    (
        "fpx_cvtind_i32_f64",
        "static inline int32_t fpx_cvtind_i32_f64(double x) { return fpx_i32_of((uint32_t)fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 1, 32u, 0)); }",
    ),
    (
        "fpx_cvtind_i64_f64",
        "static inline int64_t fpx_cvtind_i64_f64(double x) { return fpx_i64_of(fpx_cvt_core(fp_d_to_bits(x), 53u, 11u, 1, 64u, 0)); }",
    ),
];

fn wrapper_table(
    entries: &'static [(&'static str, &'static str)],
    deps: &'static [&'static str],
) -> Vec<FpHelper> {
    entries
        .iter()
        .map(|(name, source): &(&'static str, &'static str)| FpHelper { name, deps, source })
        .collect()
}

#[must_use]
pub fn helpers() -> Vec<FpHelper> {
    let mut out: Vec<FpHelper> = vec![
        FpHelper {
            name: "fpx_signed_wrap",
            deps: &[],
            source: SIGNED_WRAP,
        },
        FpHelper {
            name: "fpx_w128",
            deps: &[],
            source: WIDE,
        },
        FpHelper {
            name: "fpx_round_pack",
            deps: &["fpx_w128"],
            source: ROUND_PACK,
        },
        FpHelper {
            name: "fpx_fma_core",
            deps: &["fpx_w128", "fpx_round_pack"],
            source: FMA_CORE,
        },
        FpHelper {
            name: "fpx_rint_core",
            deps: &[],
            source: RINT_CORE,
        },
        FpHelper {
            name: "fpx_minmax_core",
            deps: &[],
            source: MINMAX_CORE,
        },
        FpHelper {
            name: "fpx_cvt_core",
            deps: &[],
            source: CVT_CORE,
        },
    ];
    out.extend(wrapper_table(RINT_WRAPPERS, &["fpx_rint_core"]));
    out.extend(wrapper_table(MINMAX_WRAPPERS, &["fpx_minmax_core"]));
    out.extend(wrapper_table(
        CVT_WRAPPERS,
        &["fpx_cvt_core", "fpx_signed_wrap"],
    ));
    out.push(FpHelper {
        name: "fpx_fma_f32",
        deps: &["fpx_fma_core"],
        source: FMA_F32,
    });
    out.push(FpHelper {
        name: "fpx_fma_f64",
        deps: &["fpx_fma_core"],
        source: FMA_F64,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_f32",
        deps: &[],
        source: SQRT_F32,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_f64",
        deps: &[],
        source: SQRT_F64,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_x86_f32",
        deps: &[],
        source: SQRT_X86_F32,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_x86_f64",
        deps: &[],
        source: SQRT_X86_F64,
    });
    out
}

const RS_RINT_F32: &str = r"#[allow(dead_code)]
fn fpx_rint_f32(x: f32, mode: u32) -> f32 {
    if x.is_nan() {
        return f32::from_bits(x.to_bits() | 0x0040_0000);
    }
    match mode {
        1 => x.floor(),
        2 => x.ceil(),
        3 => x.trunc(),
        4 => x.round(),
        _ => x.round_ties_even(),
    }
}";

const RS_RINT_F64: &str = r"#[allow(dead_code)]
fn fpx_rint_f64(x: f64, mode: u32) -> f64 {
    if x.is_nan() {
        return f64::from_bits(x.to_bits() | 0x0008_0000_0000_0000);
    }
    match mode {
        1 => x.floor(),
        2 => x.ceil(),
        3 => x.trunc(),
        4 => x.round(),
        _ => x.round_ties_even(),
    }
}";

const RS_MINMAX_F32: &str = r"#[allow(dead_code)]
fn fpx_minmax_f32(a: f32, b: f32, is_max: bool) -> f32 {
    let quiet: u32 = 0x0040_0000;
    let left: u32 = a.to_bits();
    let right: u32 = b.to_bits();
    if a.is_nan() && (left & quiet) == 0 {
        return f32::from_bits(left | quiet);
    }
    if b.is_nan() && (right & quiet) == 0 {
        return f32::from_bits(right | quiet);
    }
    if a.is_nan() && b.is_nan() {
        return a;
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        let merged: u32 = if is_max { left & right } else { left | right };
        return f32::from_bits(merged & 0x8000_0000);
    }
    if is_max { a.max(b) } else { a.min(b) }
}";

const RS_MINMAX_F64: &str = r"#[allow(dead_code)]
fn fpx_minmax_f64(a: f64, b: f64, is_max: bool) -> f64 {
    let quiet: u64 = 0x0008_0000_0000_0000;
    let left: u64 = a.to_bits();
    let right: u64 = b.to_bits();
    if a.is_nan() && (left & quiet) == 0 {
        return f64::from_bits(left | quiet);
    }
    if b.is_nan() && (right & quiet) == 0 {
        return f64::from_bits(right | quiet);
    }
    if a.is_nan() && b.is_nan() {
        return a;
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        let merged: u64 = if is_max { left & right } else { left | right };
        return f64::from_bits(merged & 0x8000_0000_0000_0000);
    }
    if is_max { a.max(b) } else { a.min(b) }
}";

const RS_FMA_F32: &str = r"#[allow(dead_code)]
fn fpx_fma_f32(a: f32, b: f32, c: f32) -> f32 {
    let quiet: u32 = 0x0040_0000;
    let default_nan: f32 = f32::from_bits(0x7fc0_0000);
    let left: u32 = a.to_bits();
    let right: u32 = b.to_bits();
    let addend: u32 = c.to_bits();
    if c.is_nan() && (addend & quiet) == 0 {
        return f32::from_bits(addend | quiet);
    }
    if a.is_nan() && (left & quiet) == 0 {
        return f32::from_bits(left | quiet);
    }
    if b.is_nan() && (right & quiet) == 0 {
        return f32::from_bits(right | quiet);
    }
    let invalid: bool = (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite());
    if c.is_nan() {
        return if invalid { default_nan } else { c };
    }
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if invalid {
        return default_nan;
    }
    let product_negative: bool = a.is_sign_negative() != b.is_sign_negative();
    if c.is_infinite()
        && (a.is_infinite() || b.is_infinite())
        && c.is_sign_negative() != product_negative
    {
        return default_nan;
    }
    a.mul_add(b, c)
}";

const RS_FMA_F64: &str = r"#[allow(dead_code)]
fn fpx_fma_f64(a: f64, b: f64, c: f64) -> f64 {
    let quiet: u64 = 0x0008_0000_0000_0000;
    let default_nan: f64 = f64::from_bits(0x7ff8_0000_0000_0000);
    let left: u64 = a.to_bits();
    let right: u64 = b.to_bits();
    let addend: u64 = c.to_bits();
    if c.is_nan() && (addend & quiet) == 0 {
        return f64::from_bits(addend | quiet);
    }
    if a.is_nan() && (left & quiet) == 0 {
        return f64::from_bits(left | quiet);
    }
    if b.is_nan() && (right & quiet) == 0 {
        return f64::from_bits(right | quiet);
    }
    let invalid: bool = (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite());
    if c.is_nan() {
        return if invalid { default_nan } else { c };
    }
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if invalid {
        return default_nan;
    }
    let product_negative: bool = a.is_sign_negative() != b.is_sign_negative();
    if c.is_infinite()
        && (a.is_infinite() || b.is_infinite())
        && c.is_sign_negative() != product_negative
    {
        return default_nan;
    }
    a.mul_add(b, c)
}";

const RS_SQRT_F32: &str = r"#[allow(dead_code)]
fn fpx_sqrt_f32(x: f32) -> f32 {
    if x.is_nan() {
        return f32::from_bits(x.to_bits() | 0x0040_0000);
    }
    if x == 0.0 {
        return x;
    }
    if x < 0.0 {
        return f32::from_bits(0x7fc0_0000);
    }
    x.sqrt()
}";

const RS_SQRT_F64: &str = r"#[allow(dead_code)]
fn fpx_sqrt_f64(x: f64) -> f64 {
    if x.is_nan() {
        return f64::from_bits(x.to_bits() | 0x0008_0000_0000_0000);
    }
    if x == 0.0 {
        return x;
    }
    if x < 0.0 {
        return f64::from_bits(0x7ff8_0000_0000_0000);
    }
    x.sqrt()
}";

const RS_SQRT_X86_F32: &str = r"#[allow(dead_code)]
fn fpx_sqrt_x86_f32(x: f32) -> f32 {
    if x.is_nan() {
        return f32::from_bits(x.to_bits() | 0x0040_0000);
    }
    if x == 0.0 {
        return x;
    }
    if x < 0.0 {
        return f32::from_bits(0xffc0_0000);
    }
    x.sqrt()
}";

const RS_SQRT_X86_F64: &str = r"#[allow(dead_code)]
fn fpx_sqrt_x86_f64(x: f64) -> f64 {
    if x.is_nan() {
        return f64::from_bits(x.to_bits() | 0x0008_0000_0000_0000);
    }
    if x == 0.0 {
        return x;
    }
    if x < 0.0 {
        return f64::from_bits(0xfff8_0000_0000_0000);
    }
    x.sqrt()
}";

const RS_WRAPPERS: &[(&str, &str, &str)] = &[
    (
        "fpx_rintn_f32",
        "fpx_rint_f32",
        "#[allow(dead_code)]\nfn fpx_rintn_f32(x: f32) -> f32 { fpx_rint_f32(x, 0) }",
    ),
    (
        "fpx_rintm_f32",
        "fpx_rint_f32",
        "#[allow(dead_code)]\nfn fpx_rintm_f32(x: f32) -> f32 { fpx_rint_f32(x, 1) }",
    ),
    (
        "fpx_rintp_f32",
        "fpx_rint_f32",
        "#[allow(dead_code)]\nfn fpx_rintp_f32(x: f32) -> f32 { fpx_rint_f32(x, 2) }",
    ),
    (
        "fpx_rintz_f32",
        "fpx_rint_f32",
        "#[allow(dead_code)]\nfn fpx_rintz_f32(x: f32) -> f32 { fpx_rint_f32(x, 3) }",
    ),
    (
        "fpx_rinta_f32",
        "fpx_rint_f32",
        "#[allow(dead_code)]\nfn fpx_rinta_f32(x: f32) -> f32 { fpx_rint_f32(x, 4) }",
    ),
    (
        "fpx_rintn_f64",
        "fpx_rint_f64",
        "#[allow(dead_code)]\nfn fpx_rintn_f64(x: f64) -> f64 { fpx_rint_f64(x, 0) }",
    ),
    (
        "fpx_rintm_f64",
        "fpx_rint_f64",
        "#[allow(dead_code)]\nfn fpx_rintm_f64(x: f64) -> f64 { fpx_rint_f64(x, 1) }",
    ),
    (
        "fpx_rintp_f64",
        "fpx_rint_f64",
        "#[allow(dead_code)]\nfn fpx_rintp_f64(x: f64) -> f64 { fpx_rint_f64(x, 2) }",
    ),
    (
        "fpx_rintz_f64",
        "fpx_rint_f64",
        "#[allow(dead_code)]\nfn fpx_rintz_f64(x: f64) -> f64 { fpx_rint_f64(x, 3) }",
    ),
    (
        "fpx_rinta_f64",
        "fpx_rint_f64",
        "#[allow(dead_code)]\nfn fpx_rinta_f64(x: f64) -> f64 { fpx_rint_f64(x, 4) }",
    ),
    (
        "fpx_maxnum_f32",
        "fpx_minmax_f32",
        "#[allow(dead_code)]\nfn fpx_maxnum_f32(a: f32, b: f32) -> f32 { fpx_minmax_f32(a, b, true) }",
    ),
    (
        "fpx_minnum_f32",
        "fpx_minmax_f32",
        "#[allow(dead_code)]\nfn fpx_minnum_f32(a: f32, b: f32) -> f32 { fpx_minmax_f32(a, b, false) }",
    ),
    (
        "fpx_maxnum_f64",
        "fpx_minmax_f64",
        "#[allow(dead_code)]\nfn fpx_maxnum_f64(a: f64, b: f64) -> f64 { fpx_minmax_f64(a, b, true) }",
    ),
    (
        "fpx_minnum_f64",
        "fpx_minmax_f64",
        "#[allow(dead_code)]\nfn fpx_minnum_f64(a: f64, b: f64) -> f64 { fpx_minmax_f64(a, b, false) }",
    ),
];

fn rust_helpers() -> Vec<FpHelper> {
    let mut out: Vec<FpHelper> = vec![
        FpHelper {
            name: "fpx_rint_f32",
            deps: &[],
            source: RS_RINT_F32,
        },
        FpHelper {
            name: "fpx_rint_f64",
            deps: &[],
            source: RS_RINT_F64,
        },
        FpHelper {
            name: "fpx_minmax_f32",
            deps: &[],
            source: RS_MINMAX_F32,
        },
        FpHelper {
            name: "fpx_minmax_f64",
            deps: &[],
            source: RS_MINMAX_F64,
        },
    ];
    for (name, dep, source) in RS_WRAPPERS {
        out.push(FpHelper {
            name,
            deps: std::slice::from_ref(dep),
            source,
        });
    }
    out.push(FpHelper {
        name: "fpx_fma_f32",
        deps: &[],
        source: RS_FMA_F32,
    });
    out.push(FpHelper {
        name: "fpx_fma_f64",
        deps: &[],
        source: RS_FMA_F64,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_f32",
        deps: &[],
        source: RS_SQRT_F32,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_f64",
        deps: &[],
        source: RS_SQRT_F64,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_x86_f32",
        deps: &[],
        source: RS_SQRT_X86_F32,
    });
    out.push(FpHelper {
        name: "fpx_sqrt_x86_f64",
        deps: &[],
        source: RS_SQRT_X86_F64,
    });
    out
}

pub(super) fn rust_resolved_sources(requested: &BTreeSet<&'static str>) -> Vec<&'static str> {
    let table: Vec<FpHelper> = rust_helpers();
    let mut needed: BTreeSet<&'static str> = requested.clone();
    for helper in table.iter().rev() {
        if needed.contains(helper.name) {
            for dep in helper.deps {
                needed.insert(dep);
            }
        }
    }
    table
        .iter()
        .filter(|helper: &&FpHelper| needed.contains(helper.name))
        .map(|helper: &FpHelper| helper.source)
        .collect()
}

#[must_use]
pub fn prelude_source() -> String {
    let mut out: String = String::new();
    for helper in helpers() {
        out.push_str(helper.source);
        out.push('\n');
    }
    out
}

#[must_use]
pub fn prelude_lines() -> Vec<String> {
    prelude_source()
        .lines()
        .map(str::to_owned)
        .filter(|line: &String| !line.is_empty())
        .collect()
}

pub(super) fn resolved_sources(requested: &BTreeSet<&'static str>) -> Vec<&'static str> {
    let table: Vec<FpHelper> = helpers();
    let mut needed: BTreeSet<&'static str> = requested.clone();
    for helper in table.iter().rev() {
        if needed.contains(helper.name) {
            for dep in helper.deps {
                needed.insert(dep);
            }
        }
    }
    table
        .iter()
        .filter(|helper: &&FpHelper| needed.contains(helper.name))
        .map(|helper: &FpHelper| helper.source)
        .collect()
}

pub(super) const fn rint_helper(mode: RoundMode, width: FpWidth) -> &'static str {
    match (mode, width) {
        (RoundMode::Nearest, FpWidth::F32) => "fpx_rintn_f32",
        (RoundMode::Floor, FpWidth::F32) => "fpx_rintm_f32",
        (RoundMode::Ceil, FpWidth::F32) => "fpx_rintp_f32",
        (RoundMode::Trunc, FpWidth::F32) => "fpx_rintz_f32",
        (RoundMode::TiesAway, FpWidth::F32) => "fpx_rinta_f32",
        (RoundMode::Nearest, FpWidth::F64) => "fpx_rintn_f64",
        (RoundMode::Floor, FpWidth::F64) => "fpx_rintm_f64",
        (RoundMode::Ceil, FpWidth::F64) => "fpx_rintp_f64",
        (RoundMode::Trunc, FpWidth::F64) => "fpx_rintz_f64",
        (RoundMode::TiesAway, FpWidth::F64) => "fpx_rinta_f64",
    }
}

pub(super) const fn minmax_helper(is_max: bool, width: FpWidth) -> &'static str {
    match (is_max, width) {
        (true, FpWidth::F32) => "fpx_maxnum_f32",
        (false, FpWidth::F32) => "fpx_minnum_f32",
        (true, FpWidth::F64) => "fpx_maxnum_f64",
        (false, FpWidth::F64) => "fpx_minnum_f64",
    }
}

pub(super) const fn fma_helper(width: FpWidth) -> &'static str {
    match width {
        FpWidth::F32 => "fpx_fma_f32",
        FpWidth::F64 => "fpx_fma_f64",
    }
}

pub(super) const fn sqrt_helper(saturating: bool, width: FpWidth) -> &'static str {
    match (saturating, width) {
        (true, FpWidth::F32) => "fpx_sqrt_f32",
        (true, FpWidth::F64) => "fpx_sqrt_f64",
        (false, FpWidth::F32) => "fpx_sqrt_x86_f32",
        (false, FpWidth::F64) => "fpx_sqrt_x86_f64",
    }
}

pub(super) fn cvt_helper(
    saturating: bool,
    signed: bool,
    dest: Width,
    width: FpWidth,
) -> Option<&'static str> {
    let dest_tag: &str = match (signed, dest) {
        (true, Width::W32) => "i32",
        (true, Width::W64) => "i64",
        (false, Width::W32) => "u32",
        (false, Width::W64) => "u64",
        _ => return None,
    };
    let source_tag: &str = match width {
        FpWidth::F32 => "f32",
        FpWidth::F64 => "f64",
    };
    let policy: &str = if saturating { "cvtsat" } else { "cvtind" };
    let name: String = format!("fpx_{policy}_{dest_tag}_{source_tag}");
    helpers()
        .into_iter()
        .find(|helper: &FpHelper| helper.name == name)
        .map(|helper: FpHelper| helper.name)
}
