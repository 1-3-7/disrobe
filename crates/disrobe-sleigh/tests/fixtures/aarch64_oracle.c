__attribute__((noinline)) long add_pair(long a, long b) {
    return a + b;
}

__attribute__((noinline)) long mix_pair(long a, long b) {
    return (a * 3 + b) ^ 0x55;
}

__attribute__((noinline)) int branch_zero(int x) {
    if (x == 0) {
        return 7;
    }
    return x - 1;
}

__attribute__((noinline)) long memory_add(long *p, long x) {
    long old = *p;
    *p = old + x;
    return old;
}

__attribute__((noinline)) long multiply_pair(long a, long b) {
    return a * b + a;
}

__attribute__((noinline)) unsigned long bit_pair(unsigned long a, unsigned long b) {
    return (a & b) | (a ^ 0x1234);
}

__attribute__((noinline)) unsigned long shift_pair(unsigned long a) {
    return (a << 5) ^ (a >> 3);
}

__attribute__((noinline)) long signed_shift(long a) {
    return a >> 7;
}

__attribute__((noinline)) long call_pair(long a, long b) {
    return add_pair(a, b) + 1;
}
