long g_acc;

long noargs(void) {
    volatile long r = 42;
    return r;
}

int add2(int a, int b) {
    return a + b;
}

long add4(long a, long b, long c, long d) {
    return a + b + c + d;
}

double fadd(double a, double b) {
    volatile int touch = 0;
    (void)touch;
    return a + b;
}

double fmix(int a, double b, long c) {
    return (double)a + b + (double)c;
}

void vconsume(int a) {
    g_acc += a;
}

long onearg(long a) {
    return a * 3;
}

long add6(long a, long b, long c, long d, long e, long f) {
    return a + b + c + d + e + f;
}

struct Big {
    long a, b, c;
};

struct Big make_big(long x) {
    struct Big r;
    r.a = x;
    r.b = x + 1;
    r.c = x + 2;
    return r;
}

void _start(void) {
    volatile long n = noargs();
    volatile int s = add2(3, 4);
    volatile long q = add4(1, 2, 3, 4);
    volatile double d = fadd(1.5, 2.5);
    volatile double m = fmix(2, 3.5, 4);
    vconsume(9);
    volatile long o = onearg(7);
    volatile long six = add6(1, 2, 3, 4, 5, 6);
    struct Big b = make_big(10);
    (void)n;
    (void)s;
    (void)q;
    (void)d;
    (void)m;
    (void)o;
    (void)six;
    (void)b;
}
