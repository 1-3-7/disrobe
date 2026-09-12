unsigned long riscv_atomic_add(volatile unsigned long *value, unsigned long operand) {
    return __atomic_fetch_add(value, operand, __ATOMIC_ACQ_REL);
}

unsigned long riscv_atomic_exchange(volatile unsigned long *value, unsigned long operand) {
    return __atomic_exchange_n(value, operand, __ATOMIC_SEQ_CST);
}

unsigned long riscv_atomic_xor(volatile unsigned long *value, unsigned long operand) {
    return __atomic_fetch_xor(value, operand, __ATOMIC_RELAXED);
}

int riscv_atomic_compare_exchange(
    volatile unsigned long *value,
    unsigned long *expected,
    unsigned long desired
) {
    return __atomic_compare_exchange_n(
        value,
        expected,
        desired,
        0,
        __ATOMIC_ACQ_REL,
        __ATOMIC_ACQUIRE
    );
}
