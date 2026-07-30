int carry_add_shift(int a, int b) {
    return (a ^ b) + ((a & b) << 1);
}

int carry_add_double(int a, int b) {
    return (a ^ b) + ((a & b) * 2);
}

int carry_add_bytes(unsigned char a, unsigned char b) {
    return (a ^ b) + ((a & b) << 1);
}

int always_even_predicate(int x) {
    if (((x * x + x) & 1) == 0) {
        return 1;
    }
    return 0;
}

int data_dependent_predicate(int x) {
    if (x > 10) {
        return 1;
    }
    return 0;
}
