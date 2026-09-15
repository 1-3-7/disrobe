int powerpc_add(int left, int right) {
    return left + right;
}

int powerpc_mix(int *value, int left, int right) {
    int prior = *value;
    *value = left + right;
    return prior ^ right;
}

int powerpc_mul(int left, int right) {
    return left * right;
}

int powerpc_div(int left, int right) {
    return left / right;
}
