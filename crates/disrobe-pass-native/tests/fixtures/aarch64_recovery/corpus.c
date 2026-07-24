typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;

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
