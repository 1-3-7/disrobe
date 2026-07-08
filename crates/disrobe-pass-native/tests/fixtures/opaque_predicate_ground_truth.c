int check_even_add(int x) {
    if (((x * x + x) & 1) == 0) {
        return 11;
    } else {
        return 12;
    }
}

int check_even_sub(int x) {
    if (((x * x - x) % 2) == 0) {
        return 21;
    } else {
        return 22;
    }
}

int check_bit_tautology(int x) {
    if (((x & 1) | (~x & 1)) != 0) {
        return 31;
    } else {
        return 32;
    }
}

int check_square_never_equal(int x, int y) {
    if ((7 * y * y - 1) != (x * x)) {
        return 41;
    } else {
        return 42;
    }
}

int check_even_mul(int x) {
    if (((x * (x + 1)) & 1) == 0) {
        return 51;
    } else {
        return 52;
    }
}

int check_odd_add_never(int x) {
    if (((x * x + x) & 1) == 1) {
        return 61;
    } else {
        return 62;
    }
}

int check_self_and_complement(int x) {
    if ((x & (~x)) != 0) {
        return 71;
    } else {
        return 72;
    }
}

int check_square_equal_never(int x, int y) {
    if ((7 * y * y - 1) == (x * x)) {
        return 81;
    } else {
        return 82;
    }
}

int check_odd_mul_never(int x) {
    if (((x * (x + 1)) & 1) == 1) {
        return 91;
    } else {
        return 92;
    }
}

int check_data_gt(int x) {
    if (x > 5) {
        return 101;
    } else {
        return 102;
    }
}

int check_data_eq(int x) {
    if (x == 42) {
        return 111;
    } else {
        return 112;
    }
}

int check_data_mod(int x) {
    if ((x % 4) == 0) {
        return 121;
    } else {
        return 122;
    }
}

int check_data_and(int x) {
    if ((x & 0x10) != 0) {
        return 131;
    } else {
        return 132;
    }
}

int check_data_mul_cmp(int x, int y) {
    if (x * y > 100) {
        return 141;
    } else {
        return 142;
    }
}

int check_data_xor_eq(int x, int y) {
    if ((x ^ y) == 0) {
        return 151;
    } else {
        return 152;
    }
}

int opaque_predicate_ground_truth_main(int x, int y) {
    int total = 0;
    total += check_even_add(x);
    total += check_even_sub(x);
    total += check_bit_tautology(x);
    total += check_square_never_equal(x, y);
    total += check_even_mul(x);
    total += check_odd_add_never(x);
    total += check_self_and_complement(x);
    total += check_square_equal_never(x, y);
    total += check_odd_mul_never(x);
    total += check_data_gt(x);
    total += check_data_eq(x);
    total += check_data_mod(x);
    total += check_data_and(x);
    total += check_data_mul_cmp(x, y);
    total += check_data_xor_eq(x, y);
    return total;
}
