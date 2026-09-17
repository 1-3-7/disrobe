signed char f_sc(signed char a) {
    if (a < 0) {
        return (signed char)-a;
    }
    return a;
}

unsigned char f_uc(unsigned char a) {
    return (unsigned char)(a >> 1);
}

short f_s(short a, short b) {
    return (short)(a / b);
}

unsigned short f_us(unsigned short a, unsigned short b) {
    return (unsigned short)(a / b);
}

int f_i(int a, int b) {
    return a < b;
}

unsigned int f_u(unsigned int a, unsigned int b) {
    return a < b;
}

long long f_ll(long long a) {
    return a >> 3;
}

unsigned long long f_ull(unsigned long long a) {
    return a >> 3;
}

int f_pass(int a) {
    return a;
}

unsigned int f_upass(unsigned int a) {
    return a;
}

void _start(void) {
    volatile signed char sc = f_sc(-5);
    volatile unsigned char uc = f_uc(200);
    volatile short s = f_s(30000, 3);
    volatile unsigned short us = f_us(60000, 3);
    volatile int i = f_i(7, 9);
    volatile unsigned int u = f_u(7u, 9u);
    volatile long long ll = f_ll(-64);
    volatile unsigned long long ull = f_ull(64ull);
    volatile int p = f_pass(11);
    volatile unsigned int up = f_upass(11u);
    (void)sc;
    (void)uc;
    (void)s;
    (void)us;
    (void)i;
    (void)u;
    (void)ll;
    (void)ull;
    (void)p;
    (void)up;
}
