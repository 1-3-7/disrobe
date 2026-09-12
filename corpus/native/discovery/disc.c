#define NOINLINE __attribute__((noinline))

NOINLINE static int add(int a, int b) { return a + b; }
NOINLINE static int mul(int a, int b) { return a * b; }
NOINLINE static int clamp_val(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
NOINLINE static int sum_to(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) acc = add(acc, i);
    return acc;
}
NOINLINE static int dispatch(int sel, int x) {
    switch (sel) {
        case 0: return add(x, 1);
        case 1: return mul(x, 2);
        case 2: return sum_to(x);
        case 3: return clamp_val(x, 0, 10);
        case 4: return x - 1;
        case 5: return x ^ 7;
        case 6: return x << 1;
        default: return x;
    }
}
NOINLINE static int compute(int n) {
    int s = sum_to(n);
    int m = mul(s, 2);
    int d = dispatch(s & 7, m);
    return clamp_val(d, 0, 1000);
}
void _start(void) {
    volatile int r = compute(17);
    (void)r;
    for (;;) {}
}
