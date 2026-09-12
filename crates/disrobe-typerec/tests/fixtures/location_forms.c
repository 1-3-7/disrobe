int global_counter = 7;
static int file_counter = 11;

struct pair {
    long a;
    long b;
};

struct wide {
    double x;
    long y;
};

int reg_resident(int a, int b) {
    int t = a * 3;
    int u = b - 1;
    while (u > 0) {
        t += u;
        u -= 1;
    }
    return t;
}

long split_pieces(struct pair p) {
    return p.a ^ p.b;
}

double mixed_pieces(struct wide w) {
    return w.x + (double)w.y;
}

int constant_folded(void) {
    int gone = 41;
    return gone + 1;
}

int address_taken(int a) {
    int local = a;
    int *p = &local;
    *p += 2;
    return local;
}

int uses_globals(int a) {
    global_counter += a;
    file_counter -= a;
    return global_counter + file_counter;
}

long long spilled(long long a, long long b, long long c, long long d, long long e,
                  long long f, long long g, long long h) {
    long long acc = a + b + c + d + e + f + g + h;
    long long i = 0;
    while (i < e) {
        acc ^= i * b;
        i += 1;
    }
    return acc + a * h;
}

void _start(void) {
    struct pair p = {3, 5};
    struct wide w = {1.5, 9};
    volatile long sink = 0;
    sink += reg_resident(2, 40);
    sink += split_pieces(p);
    sink += (long)mixed_pieces(w);
    sink += constant_folded();
    sink += address_taken(4);
    sink += uses_globals(6);
    sink += (long)spilled(1, 2, 3, 4, 5, 6, 7, 8);
    (void)sink;
}
