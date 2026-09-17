unsigned long riscv_mix(unsigned long left, unsigned long right, unsigned long *output) {
    unsigned long mixed = (left + right) ^ (left - right);
    output[1] = mixed;
    return output[0] + mixed;
}

unsigned long riscv_product(unsigned long left, unsigned long right) {
    return left * right;
}

unsigned long riscv_quotient(unsigned long left, unsigned long right) {
    return left / right;
}
