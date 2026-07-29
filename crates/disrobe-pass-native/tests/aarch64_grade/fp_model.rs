#![allow(dead_code)]

pub(crate) const MODEL_C: &str = r"
#define A64M_LIMBS 136
#define A64M_BITS (A64M_LIMBS * 32)
typedef struct { int used; uint32_t w[A64M_LIMBS]; } a64m_big;

static void a64m_clear(a64m_big *b, int limbs) {
    int i;
    if (limbs < 1) limbs = 1;
    if (limbs > A64M_LIMBS) limbs = A64M_LIMBS;
    for (i = 0; i < limbs; i++) b->w[i] = 0u;
    b->used = limbs;
}

static void a64m_place(a64m_big *b, uint64_t hi, uint64_t lo, int shift) {
    uint32_t parts[5];
    int limb, off, i, span;
    if (shift < 0) shift = 0;
    limb = shift >> 5;
    off = shift & 31;
    parts[0] = (uint32_t)lo;
    parts[1] = (uint32_t)(lo >> 32);
    parts[2] = (uint32_t)hi;
    parts[3] = (uint32_t)(hi >> 32);
    parts[4] = 0u;
    span = limb + 5;
    a64m_clear(b, span);
    for (i = 0; i < 5; i++) {
        int dest = limb + i;
        uint32_t value;
        if (dest >= A64M_LIMBS) break;
        if (off == 0) value = parts[i];
        else value = (uint32_t)((parts[i] << off) | (i == 0 ? 0u : (parts[i - 1] >> (32 - off))));
        b->w[dest] = value;
    }
}

static int a64m_msb(const a64m_big *b) {
    int i, k;
    for (i = b->used - 1; i >= 0; i--) {
        if (b->w[i] == 0u) continue;
        for (k = 31; k >= 0; k--) { if ((b->w[i] >> k) & 1u) return i * 32 + k; }
    }
    return -1;
}

static int a64m_cmp(const a64m_big *a, const a64m_big *b) {
    int n = a->used > b->used ? a->used : b->used;
    int i;
    for (i = n - 1; i >= 0; i--) {
        uint32_t x = (i < a->used) ? a->w[i] : 0u;
        uint32_t y = (i < b->used) ? b->w[i] : 0u;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

static void a64m_add(a64m_big *r, const a64m_big *a, const a64m_big *b) {
    int n = a->used > b->used ? a->used : b->used;
    uint64_t carry = 0ull;
    int i;
    if (n < A64M_LIMBS) n++;
    for (i = 0; i < n; i++) {
        uint64_t t = (uint64_t)((i < a->used) ? a->w[i] : 0u)
                   + (uint64_t)((i < b->used) ? b->w[i] : 0u) + carry;
        r->w[i] = (uint32_t)t;
        carry = t >> 32;
    }
    r->used = n;
}

static void a64m_sub(a64m_big *r, const a64m_big *a, const a64m_big *b) {
    uint64_t borrow = 0ull;
    int i;
    for (i = 0; i < a->used; i++) {
        uint64_t t = (uint64_t)a->w[i] - (uint64_t)((i < b->used) ? b->w[i] : 0u) - borrow;
        r->w[i] = (uint32_t)t;
        borrow = ((t >> 32) != 0ull) ? 1ull : 0ull;
    }
    r->used = a->used;
}

static uint64_t a64m_extract(const a64m_big *b, int shift) {
    uint32_t parts[3];
    uint64_t low, high;
    int limb, off, i;
    if (shift < 0) return 0ull;
    limb = shift >> 5;
    off = shift & 31;
    for (i = 0; i < 3; i++) {
        int idx = limb + i;
        parts[i] = (idx >= 0 && idx < b->used) ? b->w[idx] : 0u;
    }
    low = (uint64_t)parts[0] | ((uint64_t)parts[1] << 32);
    high = (uint64_t)parts[2];
    if (off == 0) return low;
    return (low >> off) | (high << (64 - off));
}

static uint64_t a64m_pack(unsigned sign, int exp2, const a64m_big *sig, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    uint64_t sign_bit = (uint64_t)sign << (mbits + ebits);
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    int msb = a64m_msb(sig);
    int lowest = 1 - bias - (int)mbits;
    int unit, shift, field, order;
    uint64_t m;
    if (msb < 0) return sign_bit;
    unit = (msb + exp2) - (int)prec + 1;
    if (unit < lowest) unit = lowest;
    shift = unit - exp2;
    if (shift <= 0) {
        m = a64m_extract(sig, 0) << (unsigned)(-shift);
    } else {
        a64m_big kept, rest, doubled, boundary;
        m = a64m_extract(sig, shift);
        a64m_place(&kept, 0ull, m, shift);
        a64m_sub(&rest, sig, &kept);
        a64m_add(&doubled, &rest, &rest);
        a64m_place(&boundary, 0ull, 1ull, shift);
        order = a64m_cmp(&doubled, &boundary);
        if (order > 0 || (order == 0 && (m & 1ull) != 0ull)) m += 1ull;
    }
    if ((m >> prec) != 0ull) { m >>= 1; unit += 1; }
    if (m == 0ull) return sign_bit;
    if ((m >> mbits) != 0ull) {
        field = unit + (int)mbits + bias;
        if (field >= (int)((1u << ebits) - 1u)) return sign_bit | ((uint64_t)((1u << ebits) - 1u) << mbits);
        return sign_bit | ((uint64_t)(unsigned)field << mbits) | (m & frac_mask);
    }
    return sign_bit | m;
}

static uint64_t a64m_fma(uint64_t ba, uint64_t bb, uint64_t bc, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    uint64_t infinity = (uint64_t)emax << mbits;
    uint64_t default_nan = infinity | quiet;
    unsigned ea = (unsigned)((bc >> mbits) & emax);
    unsigned e1 = (unsigned)((ba >> mbits) & emax);
    unsigned e2 = (unsigned)((bb >> mbits) & emax);
    uint64_t fa = bc & frac_mask, f1 = ba & frac_mask, f2 = bb & frac_mask;
    unsigned sa = (unsigned)((bc & sign_mask) != 0ull);
    unsigned s1 = (unsigned)((ba & sign_mask) != 0ull);
    unsigned s2 = (unsigned)((bb & sign_mask) != 0ull);
    unsigned sp = s1 ^ s2;
    int a_is_nan = (ea == emax) && (fa != 0ull);
    int p1_is_nan = (e1 == emax) && (f1 != 0ull);
    int p2_is_nan = (e2 == emax) && (f2 != 0ull);
    int a_is_inf = (ea == emax) && (fa == 0ull);
    int p1_is_inf = (e1 == emax) && (f1 == 0ull);
    int p2_is_inf = (e2 == emax) && (f2 == 0ull);
    int a_is_zero = (ea == 0u) && (fa == 0ull);
    int p1_is_zero = (e1 == 0u) && (f1 == 0ull);
    int p2_is_zero = (e2 == 0u) && (f2 == 0ull);
    int product_invalid = (p1_is_inf && p2_is_zero) || (p1_is_zero && p2_is_inf);
    int product_inf = p1_is_inf || p2_is_inf;
    int product_zero = p1_is_zero || p2_is_zero;
    uint64_t m1, m2, ma;
    int x1, x2, xa, base, order;
    unsigned sr;
    a64m_big product, addend, total;
    unsigned __int128 wide;
    if (a_is_nan && (fa & quiet) == 0ull) return bc | quiet;
    if (p1_is_nan && (f1 & quiet) == 0ull) return ba | quiet;
    if (p2_is_nan && (f2 & quiet) == 0ull) return bb | quiet;
    if (a_is_nan) return product_invalid ? default_nan : bc;
    if (p1_is_nan) return ba;
    if (p2_is_nan) return bb;
    if (product_invalid) return default_nan;
    if (a_is_inf && product_inf && sa != sp) return default_nan;
    if (a_is_inf) return sa != 0u ? (sign_mask | infinity) : infinity;
    if (product_inf) return sp != 0u ? (sign_mask | infinity) : infinity;
    if (a_is_zero && product_zero) return (sa == sp && sa != 0u) ? sign_mask : 0ull;
    if (product_zero) return bc;
    m1 = (e1 == 0u) ? f1 : (((uint64_t)1 << mbits) | f1);
    m2 = (e2 == 0u) ? f2 : (((uint64_t)1 << mbits) | f2);
    ma = (ea == 0u) ? fa : (((uint64_t)1 << mbits) | fa);
    x1 = (e1 == 0u) ? (1 - bias - (int)mbits) : ((int)e1 - bias - (int)mbits);
    x2 = (e2 == 0u) ? (1 - bias - (int)mbits) : ((int)e2 - bias - (int)mbits);
    xa = (ea == 0u) ? (1 - bias - (int)mbits) : ((int)ea - bias - (int)mbits);
    base = 2 * (1 - bias - (int)mbits);
    wide = (unsigned __int128)m1 * (unsigned __int128)m2;
    a64m_place(&product, (uint64_t)(wide >> 64), (uint64_t)wide, (x1 + x2) - base);
    a64m_place(&addend, 0ull, ma, xa - base);
    if (sa == sp) {
        a64m_add(&total, &product, &addend);
        sr = sp;
    } else {
        order = a64m_cmp(&product, &addend);
        if (order == 0) return 0ull;
        if (order > 0) { a64m_sub(&total, &product, &addend); sr = sp; }
        else { a64m_sub(&total, &addend, &product); sr = sa; }
    }
    return a64m_pack(sr, base, &total, prec, ebits);
}

static uint64_t a64m_rint(uint64_t b, unsigned prec, unsigned ebits, int mode) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    unsigned exp = (unsigned)((b >> mbits) & emax);
    uint64_t frac = b & frac_mask;
    unsigned sign = (unsigned)((b & sign_mask) != 0ull);
    uint64_t m, whole = 0ull, rest, half;
    int e, shift, order = -1, nonzero = 0, up = 0;
    a64m_big sig;
    if (exp == emax) return (frac != 0ull) ? (b | quiet) : b;
    if (exp == 0u && frac == 0ull) return b;
    m = (exp == 0u) ? frac : (((uint64_t)1 << mbits) | frac);
    e = (exp == 0u) ? (1 - bias - (int)mbits) : ((int)exp - bias - (int)mbits);
    if (e >= 0) return b;
    shift = -e;
    if (shift >= 64) { whole = 0ull; nonzero = (m != 0ull); order = -1; }
    else {
        whole = m >> (unsigned)shift;
        rest = m & ((((uint64_t)1 << (unsigned)shift) - 1ull));
        half = (uint64_t)1 << (unsigned)(shift - 1);
        nonzero = rest != 0ull;
        order = (rest > half) ? 1 : ((rest == half) ? 0 : -1);
    }
    if (nonzero) {
        if (mode == 1) up = (sign != 0u);
        else if (mode == 2) up = (sign == 0u);
        else if (mode == 3) up = 0;
        else if (mode == 4) up = (order >= 0);
        else up = (order > 0) || (order == 0 && (whole & 1ull) != 0ull);
    }
    whole += up ? 1ull : 0ull;
    a64m_place(&sig, 0ull, whole, 0);
    return a64m_pack(sign, 0, &sig, prec, ebits);
}

static uint64_t a64m_cvt(uint64_t b, unsigned prec, unsigned ebits, int is_signed, unsigned dbits, int mode, unsigned fbits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t dmask = (dbits >= 64u) ? ~(uint64_t)0 : ((((uint64_t)1 << dbits) - 1ull));
    uint64_t floor_pattern = (uint64_t)1 << (dbits - 1u);
    unsigned exp = (unsigned)((b >> mbits) & emax);
    uint64_t frac = b & frac_mask;
    unsigned sign = (unsigned)((b & sign_mask) != 0ull);
    uint64_t m, magnitude = 0ull, rest, half;
    int e, shift, order = -1, nonzero = 0, up = 0, overflow = 0;
    if (exp == emax && frac != 0ull) return 0ull;
    if (exp == 0u && frac == 0ull) return 0ull;
    m = (exp == 0u) ? frac : (((uint64_t)1 << mbits) | frac);
    e = ((exp == 0u) ? (1 - bias - (int)mbits) : ((int)exp - bias - (int)mbits)) + (int)fbits;
    if (e == 0) { magnitude = m; }
    else if (e > 0) {
        if (e >= 64) overflow = (m != 0ull);
        else if ((m >> (unsigned)(64 - e)) != 0ull) overflow = 1;
        else magnitude = m << (unsigned)e;
    } else {
        shift = -e;
        if (shift >= 64) { magnitude = 0ull; nonzero = (m != 0ull); order = -1; }
        else {
            magnitude = m >> (unsigned)shift;
            rest = m & ((((uint64_t)1 << (unsigned)shift) - 1ull));
            half = (uint64_t)1 << (unsigned)(shift - 1);
            nonzero = rest != 0ull;
            order = (rest > half) ? 1 : ((rest == half) ? 0 : -1);
        }
        if (nonzero) {
            if (mode == 1) up = (sign != 0u);
            else if (mode == 2) up = (sign == 0u);
            else if (mode == 3) up = 0;
            else if (mode == 4) up = (order >= 0);
            else up = (order > 0) || (order == 0 && (magnitude & 1ull) != 0ull);
        }
        magnitude += up ? 1ull : 0ull;
    }
    if (!is_signed) {
        if (sign != 0u) return 0ull;
        if (overflow) return dmask;
        return magnitude > dmask ? dmask : magnitude;
    }
    if (overflow) return sign != 0u ? floor_pattern : (dmask >> 1);
    if (sign != 0u) return (magnitude >= floor_pattern) ? floor_pattern : ((0ull - magnitude) & dmask);
    return magnitude > (dmask >> 1) ? (dmask >> 1) : magnitude;
}

static uint64_t a64m_arith(uint64_t ba, uint64_t bb, int op, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    uint64_t infinity = (uint64_t)emax << mbits;
    uint64_t default_nan = infinity | quiet;
    unsigned e1 = (unsigned)((ba >> mbits) & emax), e2 = (unsigned)((bb >> mbits) & emax);
    uint64_t f1 = ba & frac_mask, f2 = bb & frac_mask;
    unsigned s1 = (unsigned)((ba & sign_mask) != 0ull);
    unsigned s2 = (unsigned)((bb & sign_mask) != 0ull);
    int nan1 = (e1 == emax) && (f1 != 0ull), nan2 = (e2 == emax) && (f2 != 0ull);
    int inf1 = (e1 == emax) && (f1 == 0ull), inf2 = (e2 == emax) && (f2 == 0ull);
    int zero1 = (e1 == 0u) && (f1 == 0ull), zero2 = (e2 == 0u) && (f2 == 0ull);
    uint64_t m1, m2, quotient = 0ull, remainder, packed, probe;
    int x1, x2, base, order, i, length1 = 0, length2 = 0, target;
    unsigned sr, sx;
    a64m_big lhs, rhs, total, sig;
    unsigned __int128 wide;
    if (nan1 && (f1 & quiet) == 0ull) return ba | quiet;
    if (nan2 && (f2 & quiet) == 0ull) return bb | quiet;
    if (nan1) return ba;
    if (nan2) return bb;
    sx = (op == 1) ? (s2 ^ 1u) : s2;
    m1 = (e1 == 0u) ? f1 : (((uint64_t)1 << mbits) | f1);
    m2 = (e2 == 0u) ? f2 : (((uint64_t)1 << mbits) | f2);
    x1 = (e1 == 0u) ? (1 - bias - (int)mbits) : ((int)e1 - bias - (int)mbits);
    x2 = (e2 == 0u) ? (1 - bias - (int)mbits) : ((int)e2 - bias - (int)mbits);
    if (op == 0 || op == 1) {
        if (inf1 && inf2 && s1 != sx) return default_nan;
        if (inf1) return s1 != 0u ? (sign_mask | infinity) : infinity;
        if (inf2) return sx != 0u ? (sign_mask | infinity) : infinity;
        if (zero1 && zero2) return (s1 == sx && s1 != 0u) ? sign_mask : 0ull;
        if (zero1) return sx != 0u ? (bb | sign_mask) : (bb & ~sign_mask);
        if (zero2) return ba;
        base = 1 - bias - (int)mbits;
        a64m_place(&lhs, 0ull, m1, x1 - base);
        a64m_place(&rhs, 0ull, m2, x2 - base);
        if (s1 == sx) { a64m_add(&total, &lhs, &rhs); sr = s1; }
        else {
            order = a64m_cmp(&lhs, &rhs);
            if (order == 0) return 0ull;
            if (order > 0) { a64m_sub(&total, &lhs, &rhs); sr = s1; }
            else { a64m_sub(&total, &rhs, &lhs); sr = sx; }
        }
        return a64m_pack(sr, base, &total, prec, ebits);
    }
    sr = s1 ^ sx;
    if (op == 2) {
        if ((inf1 && zero2) || (zero1 && inf2)) return default_nan;
        if (inf1 || inf2) return (sr != 0u ? sign_mask : 0ull) | infinity;
        if (zero1 || zero2) return sr != 0u ? sign_mask : 0ull;
        base = 2 * (1 - bias - (int)mbits);
        wide = (unsigned __int128)m1 * (unsigned __int128)m2;
        a64m_place(&total, (uint64_t)(wide >> 64), (uint64_t)wide, (x1 + x2) - base);
        return a64m_pack(sr, base, &total, prec, ebits);
    }
    if ((inf1 && inf2) || (zero1 && zero2)) return default_nan;
    if (inf1 || zero2) return (sr != 0u ? sign_mask : 0ull) | infinity;
    if (zero1 || inf2) return sr != 0u ? sign_mask : 0ull;
    probe = m1;
    while (probe != 0ull) { length1++; probe >>= 1; }
    probe = m2;
    while (probe != 0ull) { length2++; probe >>= 1; }
    m1 <<= (unsigned)((int)prec - length1);
    x1 -= ((int)prec - length1);
    m2 <<= (unsigned)((int)prec - length2);
    x2 -= ((int)prec - length2);
    target = (int)prec + 3;
    remainder = m1;
    if (remainder >= m2) { remainder -= m2; quotient = 1ull; }
    for (i = 0; i < target; i++) {
        remainder <<= 1;
        quotient <<= 1;
        if (remainder >= m2) { remainder -= m2; quotient |= 1ull; }
    }
    packed = (quotient << 1) | ((remainder != 0ull) ? 1ull : 0ull);
    a64m_place(&sig, 0ull, packed, 0);
    return a64m_pack(sr, (x1 - x2) - target - 1, &sig, prec, ebits);
}

static int a64m_greater(uint64_t a, uint64_t b, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t abs_a = a & (sign_mask - 1ull);
    uint64_t abs_b = b & (sign_mask - 1ull);
    int sa = (a & sign_mask) != 0ull;
    int sb = (b & sign_mask) != 0ull;
    if (abs_a == 0ull && abs_b == 0ull) return 0;
    if (sa != sb) return sb;
    if (sa) return abs_a < abs_b;
    return abs_a > abs_b;
}

static uint64_t a64m_minmax(uint64_t a, uint64_t b, unsigned prec, unsigned ebits, int is_max) {
    unsigned mbits = prec - 1u;
    unsigned emax = (1u << ebits) - 1u;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    uint64_t infinity = (uint64_t)emax << mbits;
    uint64_t abs_a = a & (sign_mask - 1ull);
    uint64_t abs_b = b & (sign_mask - 1ull);
    int a_nan = abs_a > infinity;
    int b_nan = abs_b > infinity;
    if (a_nan && (a & quiet) == 0ull) return a | quiet;
    if (b_nan && (b & quiet) == 0ull) return b | quiet;
    if (a_nan && b_nan) return a;
    if (a_nan) return b;
    if (b_nan) return a;
    if (abs_a == 0ull && abs_b == 0ull) return is_max ? ((a & b) & sign_mask) : ((a | b) & sign_mask);
    if (is_max) return a64m_greater(a, b, prec, ebits) ? a : b;
    return a64m_greater(b, a, prec, ebits) ? a : b;
}

static uint64_t a64m_sqrt(uint64_t b, unsigned prec, unsigned ebits) {
    unsigned mbits = prec - 1u;
    int bias = (int)((1u << (ebits - 1u)) - 1u);
    unsigned emax = (1u << ebits) - 1u;
    uint64_t frac_mask = ((uint64_t)1 << mbits) - 1ull;
    uint64_t sign_mask = (uint64_t)1 << (mbits + ebits);
    uint64_t quiet = (uint64_t)1 << (mbits - 1u);
    unsigned exp = (unsigned)((b >> mbits) & emax);
    uint64_t frac = b & frac_mask;
    uint64_t m, root = 0ull, rest = 0ull, packed, probe;
    int e, length = 0, pad, groups, i;
    a64m_big sig;
    if (exp == emax && frac != 0ull) return b | quiet;
    if (exp == 0u && frac == 0ull) return b;
    if ((b & sign_mask) != 0ull) return ((uint64_t)emax << mbits) | quiet;
    if (exp == emax) return b;
    m = (exp == 0u) ? frac : (((uint64_t)1 << mbits) | frac);
    e = (exp == 0u) ? (1 - bias - (int)mbits) : ((int)exp - bias - (int)mbits);
    if ((e & 1) != 0) { m <<= 1; e -= 1; }
    probe = m;
    while (probe != 0ull) { length++; probe >>= 1; }
    pad = 2 * ((int)prec + 3) - length;
    if (pad < 0) pad = 0;
    if ((pad & 1) != 0) pad -= 1;
    groups = (length + pad + 1) / 2;
    for (i = groups - 1; i >= 0; i--) {
        int high = 2 * i + 1, low = 2 * i;
        uint64_t pair = 0ull, trial;
        if (high >= pad && (high - pad) < 64 && ((m >> (unsigned)(high - pad)) & 1ull) != 0ull) pair |= 2ull;
        if (low >= pad && (low - pad) < 64 && ((m >> (unsigned)(low - pad)) & 1ull) != 0ull) pair |= 1ull;
        rest = (rest << 2) | pair;
        root <<= 1;
        trial = 2ull * root + 1ull;
        if (trial <= rest) { rest -= trial; root |= 1ull; }
    }
    packed = (root << 1) | ((rest != 0ull) ? 1ull : 0ull);
    a64m_place(&sig, 0ull, packed, 0);
    return a64m_pack(0u, (e - pad) / 2 - 1, &sig, prec, ebits);
}

static float a64m_bits_to_f32(uint32_t v) { float f; __builtin_memcpy(&f, &v, 4); return f; }
static uint32_t a64m_f32_to_bits(float v) { uint32_t b; __builtin_memcpy(&b, &v, 4); return b; }
static double a64m_bits_to_f64(uint64_t v) { double f; __builtin_memcpy(&f, &v, 8); return f; }
static uint64_t a64m_f64_to_bits(double v) { uint64_t b; __builtin_memcpy(&b, &v, 8); return b; }

static float a64m_fma_f32(float a, float b, float c) { return a64m_bits_to_f32((uint32_t)a64m_fma((uint64_t)a64m_f32_to_bits(a), (uint64_t)a64m_f32_to_bits(b), (uint64_t)a64m_f32_to_bits(c), 24u, 8u)); }
static double a64m_fma_f64(double a, double b, double c) { return a64m_bits_to_f64(a64m_fma(a64m_f64_to_bits(a), a64m_f64_to_bits(b), a64m_f64_to_bits(c), 53u, 11u)); }
static float a64m_rint_f32(float x, int mode) { return a64m_bits_to_f32((uint32_t)a64m_rint((uint64_t)a64m_f32_to_bits(x), 24u, 8u, mode)); }
static double a64m_rint_f64(double x, int mode) { return a64m_bits_to_f64(a64m_rint(a64m_f64_to_bits(x), 53u, 11u, mode)); }
static float a64m_maxnm_f32(float a, float b) { return a64m_bits_to_f32((uint32_t)a64m_minmax((uint64_t)a64m_f32_to_bits(a), (uint64_t)a64m_f32_to_bits(b), 24u, 8u, 1)); }
static float a64m_minnm_f32(float a, float b) { return a64m_bits_to_f32((uint32_t)a64m_minmax((uint64_t)a64m_f32_to_bits(a), (uint64_t)a64m_f32_to_bits(b), 24u, 8u, 0)); }
static double a64m_maxnm_f64(double a, double b) { return a64m_bits_to_f64(a64m_minmax(a64m_f64_to_bits(a), a64m_f64_to_bits(b), 53u, 11u, 1)); }
static double a64m_minnm_f64(double a, double b) { return a64m_bits_to_f64(a64m_minmax(a64m_f64_to_bits(a), a64m_f64_to_bits(b), 53u, 11u, 0)); }
static float a64m_sqrt_f32(float x) { return a64m_bits_to_f32((uint32_t)a64m_sqrt((uint64_t)a64m_f32_to_bits(x), 24u, 8u)); }
static double a64m_sqrt_f64(double x) { return a64m_bits_to_f64(a64m_sqrt(a64m_f64_to_bits(x), 53u, 11u)); }
static int32_t a64m_cvt_i32_f32(float x, int mode, unsigned fbits) { return (int32_t)(uint32_t)a64m_cvt((uint64_t)a64m_f32_to_bits(x), 24u, 8u, 1, 32u, mode, fbits); }
static int64_t a64m_cvt_i64_f32(float x, int mode, unsigned fbits) { return (int64_t)a64m_cvt((uint64_t)a64m_f32_to_bits(x), 24u, 8u, 1, 64u, mode, fbits); }
static uint32_t a64m_cvt_u32_f32(float x, int mode, unsigned fbits) { return (uint32_t)a64m_cvt((uint64_t)a64m_f32_to_bits(x), 24u, 8u, 0, 32u, mode, fbits); }
static uint64_t a64m_cvt_u64_f32(float x, int mode, unsigned fbits) { return a64m_cvt((uint64_t)a64m_f32_to_bits(x), 24u, 8u, 0, 64u, mode, fbits); }
static int32_t a64m_cvt_i32_f64(double x, int mode, unsigned fbits) { return (int32_t)(uint32_t)a64m_cvt(a64m_f64_to_bits(x), 53u, 11u, 1, 32u, mode, fbits); }
static int64_t a64m_cvt_i64_f64(double x, int mode, unsigned fbits) { return (int64_t)a64m_cvt(a64m_f64_to_bits(x), 53u, 11u, 1, 64u, mode, fbits); }
static uint32_t a64m_cvt_u32_f64(double x, int mode, unsigned fbits) { return (uint32_t)a64m_cvt(a64m_f64_to_bits(x), 53u, 11u, 0, 32u, mode, fbits); }
static uint64_t a64m_cvt_u64_f64(double x, int mode, unsigned fbits) { return a64m_cvt(a64m_f64_to_bits(x), 53u, 11u, 0, 64u, mode, fbits); }
static float a64m_arith_f32(float a, float b, int op) { return a64m_bits_to_f32((uint32_t)a64m_arith((uint64_t)a64m_f32_to_bits(a), (uint64_t)a64m_f32_to_bits(b), op, 24u, 8u)); }
static double a64m_arith_f64(double a, double b, int op) { return a64m_bits_to_f64(a64m_arith(a64m_f64_to_bits(a), a64m_f64_to_bits(b), op, 53u, 11u)); }
";

pub(crate) struct HostCoincidence {
    pub(crate) operation: &'static str,
    pub(crate) host_expression: &'static str,
    pub(crate) model_expression: &'static str,
    pub(crate) domain: HostDomain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostDomain {
    F32Exhaustive,
    F64Sampled,
}

pub(crate) const HOST_ALLOWLIST: &[HostCoincidence] = &[
    HostCoincidence {
        operation: "fadd f32",
        host_expression: "a64m_f32_to_bits(fp_f_from_bits(u) + fp_f_from_bits(v))",
        model_expression: "a64m_f32_to_bits(a64m_fma_f32(fp_f_from_bits(u), 1.0f, fp_f_from_bits(v)))",
        domain: HostDomain::F64Sampled,
    },
    HostCoincidence {
        operation: "fmul f32",
        host_expression: "a64m_f32_to_bits(fp_f_from_bits(u) * fp_f_from_bits(v))",
        model_expression: "a64m_f32_to_bits(a64m_fma_f32(fp_f_from_bits(u), fp_f_from_bits(v), 0.0f))",
        domain: HostDomain::F64Sampled,
    },
    HostCoincidence {
        operation: "fsqrt f32",
        host_expression: "a64m_f32_to_bits(fpx_sqrt_f32(fp_f_from_bits(u)))",
        model_expression: "a64m_f32_to_bits(a64m_sqrt_f32(fp_f_from_bits(u)))",
        domain: HostDomain::F32Exhaustive,
    },
    HostCoincidence {
        operation: "fsqrt f64",
        host_expression: "a64m_f64_to_bits(fpx_sqrt_f64(fp_d_from_bits(w)))",
        model_expression: "a64m_f64_to_bits(a64m_sqrt_f64(fp_d_from_bits(w)))",
        domain: HostDomain::F64Sampled,
    },
];

pub(crate) const STRICT_OPERATIONS: &[&str] = &[
    "fmadd", "fmsub", "fnmadd", "fnmsub", "fmaxnm", "fminnm", "frintn", "frintm", "frintp",
    "frintz", "frinta", "fcvtzs", "fcvtzu", "fcvtms", "fcvtmu", "fcvtps", "fcvtpu", "fcvtas",
    "fcvtau",
];

pub(crate) const HOST_PRIMITIVES_BANNED_IN_REFERENCE: &[&str] = &[
    "__builtin_fma",
    "__builtin_fmaf",
    "__builtin_fmax",
    "__builtin_fmaxf",
    "__builtin_fmin",
    "__builtin_fminf",
    "__builtin_floor",
    "__builtin_floorf",
    "__builtin_ceil",
    "__builtin_ceilf",
    "__builtin_trunc",
    "__builtin_truncf",
    "__builtin_round",
    "__builtin_roundf",
    "__builtin_rint",
    "__builtin_rintf",
    "__builtin_sqrt",
    "__builtin_sqrtf",
];
