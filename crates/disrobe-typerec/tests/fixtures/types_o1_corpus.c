int sink;

__attribute__((noinline)) long long reuse_shift(int sel) {
    long long r;
    if (sel > 0) {
        volatile long long a = (long long)sel * 7;
        a = a >> 2;
        r = a;
    } else {
        volatile unsigned long long b = (unsigned long long)(sel + 3);
        b = b >> 1;
        r = (long long)b;
    }
    return r;
}

__attribute__((noinline)) long long reuse_shift_rev(int sel) {
    long long r;
    if (sel > 0) {
        volatile unsigned long long a = (unsigned long long)(sel + 5);
        a = a >> 3;
        r = (long long)a;
    } else {
        volatile long long b = (long long)sel * 9;
        b = b >> 2;
        r = b;
    }
    return r;
}

__attribute__((noinline)) long long reuse_div(int sel, int d) {
    long long r;
    if (sel > 0) {
        volatile long long a = (long long)sel * 100;
        a = a / (long long)d;
        r = a;
    } else {
        volatile unsigned long long b = (unsigned long long)(sel + 7);
        b = b / (unsigned long long)(unsigned)d;
        r = (long long)b;
    }
    return r;
}

__attribute__((noinline)) long long no_reuse(long long x, long long y) {
    volatile long long p = x >> 1;
    volatile long long q = y >> 2;
    return p + q;
}

void _start(void) {
    sink = (int)reuse_shift(11);
    sink += (int)reuse_shift_rev(-4);
    sink += (int)reuse_div(20, 3);
    sink += (int)no_reuse(64, -128);
}
