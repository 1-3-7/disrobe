#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};
use wait_timeout::ChildExt as _;

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");

const GROUND_TRUTH_C: &str = r"
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int i32;
typedef signed long long i64;

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
unsigned avg_floor_u(unsigned a, unsigned b) { return (a & b) + ((a ^ b) >> 1); }
int select4(int a, int b, int c, int d) { int m = a > b ? a : b; int n = c > d ? c : d; return m > n ? m : n; }
int sat_sub(int a, int b) {
    long long s = (long long)a - (long long)b;
    if (s > 2147483647LL) return 2147483647;
    if (s < -2147483648LL) return -2147483648;
    return (int)s;
}
";

const EXTERNS: &str = r"struct Pt { int x; int y; };
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
extern unsigned avg_floor_u(unsigned a, unsigned b);
extern int select4(int a, int b, int c, int d);
extern int sat_sub(int a, int b);
";

fn cc() -> Option<String> {
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

fn expected_arity(name: &str) -> Option<usize> {
    let arity: usize = match name {
        "popcount_loop" | "bitmix" | "mask_hi" | "str_len_manual" | "sw_small" | "sw_sparse"
        | "do_while_sum" | "ld_st_pair" | "sign_of" | "clz32" | "ctz32" | "bswap32" | "bswap64"
        | "abs_i32" | "bfx" => 1,
        "idx_int" | "idx_uint" | "idx_long8" | "idx_byte" | "sum_int_idx" | "find_early"
        | "abs_diff" | "mul_widen" | "mul_widen_s" | "div_s" | "div_u" | "mod_s" | "shifts"
        | "str_cmp_manual" | "arr_max" | "even_count" | "pt_dot" | "pt_arr" | "rotate_left"
        | "accum_u64" | "saturating_add" | "bfi_merge" | "max_u" | "clamp_u" | "neg_if"
        | "hi_mul_u" | "avg_floor_u" | "sat_sub" => 2,
        "idx_two" | "idx_store" | "find_key" | "mem_copy_manual" | "nested_sum" | "min3" => 3,
        "clamp_sel" | "and_or_cond" | "select4" => 4,
        _ => return None,
    };
    Some(arity)
}

struct Arg {
    draw: &'static str,
    ocast: &'static str,
}

fn scalar_block(
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

fn fill_template(template: &str, opt: &str, name: &str, rec: &str, seed: u64) -> String {
    template
        .replace("$REC", rec)
        .replace("$OPT", opt)
        .replace("$NAME", name)
        .replace("$SEED", &format!("0x{seed:x}ULL"))
}

fn idx_block(
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

fn count_block(
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

const INT_FILL: &str = "(int)((int)(xs(&s) % 200001) - 100000)";
const UINT_FILL: &str = "(unsigned)((int)(xs(&s) % 200001) - 100000)";
const LONG_FILL: &str = "(long long)((int)(xs(&s) % 200001) - 100000)";
const CHAR_FILL: &str = "(char)(xs(&s) & 0xff)";
const U64_FILL: &str = "(unsigned long long)xs(&s)";

const IDX_STORE_TMPL: &str = "    {\n\
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

const MEM_COPY_TMPL: &str = "    {\n\
     \x20       uint64_t s = $SEED; int ok = 1;\n\
     \x20       for (int it = 0; it < ITER; it++) {\n\
     \x20           unsigned char src[BUFN]; unsigned char od[BUFN]; unsigned char rd[BUFN];\n\
     \x20           for (int b = 0; b < BUFN; b++) { src[b] = (unsigned char)(xs(&s) & 0xff); unsigned char f = (unsigned char)(xs(&s) & 0xff); od[b] = f; rd[b] = f; }\n\
     \x20           int n = (int)(xs(&s) % (BUFN + 1));\n\
     \x20           mem_copy_manual((char*)od, (const char*)src, n);\n\
     \x20           (void)$REC((uint64_t)(uintptr_t)rd, (uint64_t)(uintptr_t)src, (uint64_t)(uint32_t)n);\n\
     \x20           if (memcmp(od, rd, BUFN) != 0) { printf(\"FAIL $OPT $NAME it=%d n=%d\\n\", it, n); ok = 0; break; }\n\
     \x20       }\n\
     \x20       if (ok) passed++; else fails++;\n\
     \x20   }\n";

const LD_ST_PAIR_TMPL: &str = "    {\n\
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

const STR_LEN_TMPL: &str = "    {\n\
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

const STR_CMP_TMPL: &str = "    {\n\
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

const PT_DOT_TMPL: &str = "    {\n\
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

const PT_ARR_TMPL: &str = "    {\n\
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

const IDX_TWO_TMPL: &str = "    {\n\
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

const FIND_KEY_TMPL: &str = "    {\n\
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

const NESTED_SUM_TMPL: &str = "    {\n\
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

fn compare_block(opt: &str, name: &str, rec: &str, seed: u64) -> Option<String> {
    let block: String = match name {
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
        "min3" => scalar_block(
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
        "popcount_loop" | "bitmix" | "bswap32" | "clz32" | "bfx" | "ctz32" => scalar_block(
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
        ),
        "mask_hi" | "bswap64" => scalar_block(
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
        "hi_mul_u" => scalar_block(
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
        _ => return None,
    };
    Some(block)
}

fn rename_recovered(source: &str, rec: &str) -> String {
    source
        .lines()
        .filter(|line: &&str| !line.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
        .replacen("uint64_t recovered(", &format!("uint64_t {rec}("), 1)
}

#[test]
#[ignore = "recompile-differential over the whole corpus; needs a host c compiler and is codegen-sensitive, so it is opt-in via --ignored until the ci platform matrix is verified green"]
fn corpus_grade_report() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!(
            "SKIP corpus grade: no host C compiler (gcc/clang/cc) on PATH; cannot recompile-differential"
        );
        return;
    };

    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let battery_c: PathBuf = dir.path().join("gt_battery.c");
    std::fs::write(&battery_c, GROUND_TRUTH_C.as_bytes()).expect("write ground-truth battery");
    let battery_o: PathBuf = dir.path().join("gt_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args([
            "-O1",
            "-funsigned-char",
            "-fno-stack-protector",
            "-fno-strict-aliasing",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for ground-truth battery");
    if !compile_battery.status.success() {
        eprintln!(
            "SKIP corpus grade: host compiler could not build the ground-truth battery: {}",
            String::from_utf8_lossy(&compile_battery.stderr)
        );
        return;
    }

    let mut attempted: usize = 0;
    let mut recovered: usize = 0;
    let mut driven: usize = 0;
    let mut skips: Vec<(String, String, String)> = Vec::new();
    let mut decls: String = String::new();
    let mut blocks: String = String::new();

    for (index, (opt, name, bytes)) in CASES.iter().enumerate() {
        attempted += 1;
        let recovery: LeafRecovery = match recover_aarch64_function(bytes, 0) {
            Ok(value) => value,
            Err(_) => continue,
        };
        recovered += 1;

        let Some(expected): Option<usize> = expected_arity(name) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "no driver descriptor".to_owned(),
            ));
            continue;
        };
        if recovery.returns_fp.is_some() || !recovery.fp_params.is_empty() {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "unexpected floating-point signature".to_owned(),
            ));
            continue;
        }
        if recovery.params.len() != expected {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                format!(
                    "arity mismatch (recovered {}, expected {expected})",
                    recovery.params.len()
                ),
            ));
            continue;
        }

        let rec_symbol: String = format!("rec_{opt}_{name}");
        let seed: u64 = 0x9E37_79B9_7F4A_7C15u64
            ^ (index as u64)
                .wrapping_add(1)
                .wrapping_mul(0x0000_0100_0000_01B3);
        let seed: u64 = if seed == 0 {
            0xDEAD_BEEF_CAFE_F00D
        } else {
            seed
        };
        let Some(block): Option<String> = compare_block(opt, name, &rec_symbol, seed) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "no driver descriptor".to_owned(),
            ));
            continue;
        };

        decls.push_str(&rename_recovered(&recovery.source, &rec_symbol));
        decls.push('\n');
        blocks.push_str(&block);
        driven += 1;
    }

    if driven == 0 {
        eprintln!("SKIP corpus grade: no recovered case had a runnable driver descriptor");
        return;
    }

    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stddef.h>\n\
         #define BUFN 16\n#define ITER 400\n\
         {EXTERNS}\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         static long long passed = 0;\n\
         static long long fails = 0;\n\
         {decls}\n\
         int main(void) {{\n\
         {blocks}\
         \x20   printf(\"GRADEDONE passed=%lld fails=%lld\\n\", passed, fails);\n\
         \x20   return 0;\n\
         }}\n"
    );

    let driver_c: PathBuf = dir.path().join("grade_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write grade driver");
    let harness_exe: PathBuf = dir
        .path()
        .join(if cfg!(windows) { "grade.exe" } else { "grade" });
    let link: std::process::Output = Command::new(&compiler)
        .args([
            "-O1",
            "-funsigned-char",
            "-fno-strict-aliasing",
            "-fno-stack-protector",
            "-o",
        ])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link grade harness");
    assert!(
        link.status.success(),
        "grade harness failed to compile/link ({driven} driven cases): {}\n--- driver head ---\n{}",
        String::from_utf8_lossy(&link.stderr),
        driver.lines().take(40).collect::<Vec<&str>>().join("\n")
    );

    let mut child: std::process::Child = Command::new(&harness_exe)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn grade harness");
    let finished: bool = child
        .wait_timeout(Duration::from_secs(100))
        .expect("wait_timeout grade harness")
        .is_some();
    assert!(
        finished,
        "grade harness exceeded the watchdog window; a recovered loop is non-terminating"
    );
    let output: std::process::Output = child
        .wait_with_output()
        .expect("collect grade harness output");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();

    let mut wrong: Vec<(String, String, String)> = Vec::new();
    let mut graded_done: Option<(i64, i64)> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("FAIL ") {
            let mut parts = rest.splitn(3, ' ');
            let opt: &str = parts.next().unwrap_or("?");
            let name: &str = parts.next().unwrap_or("?");
            let detail: &str = parts.next().unwrap_or("");
            wrong.push((opt.to_owned(), name.to_owned(), detail.to_owned()));
        } else if let Some(rest) = line.strip_prefix("GRADEDONE ") {
            let mut p: i64 = 0;
            let mut f: i64 = 0;
            for token in rest.split_whitespace() {
                if let Some(v) = token.strip_prefix("passed=") {
                    p = v.parse().unwrap_or(0);
                } else if let Some(v) = token.strip_prefix("fails=") {
                    f = v.parse().unwrap_or(0);
                }
            }
            graded_done = Some((p, f));
        }
    }

    let Some((passed, driver_fails)): Option<(i64, i64)> = graded_done else {
        panic!(
            "grade harness produced no GRADEDONE summary; run did not complete:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    let graded_equivalent: i64 = passed;
    eprintln!("================ AARCH64 CORPUS GRADE ================");
    eprintln!("attempted            {attempted}");
    eprintln!("recovered            {recovered}   (non-rejection; NOT a correctness claim)");
    eprintln!("driven (graded)      {driven}");
    eprintln!(
        "graded-equivalent    {graded_equivalent}   (recompiled + behaviorally matched on 400 random inputs)"
    );
    eprintln!(
        "recovered-but-wrong  {driver_fails}   (recovered, driven, diverged from ground truth)"
    );
    eprintln!("skipped-from-grading {}", skips.len());

    if !wrong.is_empty() {
        eprintln!("---- recovered-but-wrong (CORRECTNESS BUGS) ----");
        for (opt, name, detail) in &wrong {
            eprintln!("  WRONG {opt} {name}  {detail}");
        }
    }
    if !skips.is_empty() {
        eprintln!("---- skipped-from-grading (with reason) ----");
        let mut reason_counts: BTreeMap<String, usize> = BTreeMap::new();
        for (opt, name, reason) in &skips {
            eprintln!("  SKIP {opt} {name}: {reason}");
            *reason_counts.entry(reason.clone()).or_default() += 1;
        }
        eprintln!("  reason tally:");
        for (reason, count) in &reason_counts {
            eprintln!("    {count}x  {reason}");
        }
    }
    eprintln!("=====================================================");

    assert_eq!(
        i64::try_from(driven).unwrap_or(-1),
        passed + driver_fails,
        "every driven case must be accounted for as pass or fail"
    );
    assert_eq!(
        driver_fails as usize,
        wrong.len(),
        "driver fail count must match the enumerated recovered-but-wrong list"
    );
}
