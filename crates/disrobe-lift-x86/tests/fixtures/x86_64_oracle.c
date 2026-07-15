#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) uint64_t add_pair(uint64_t left, uint64_t right) {
    return left + right;
}

__attribute__((noinline)) uint64_t mix_pair(uint64_t left, uint64_t right) {
    return ((left * 3U) + right) ^ UINT64_C(0x55aa);
}

__attribute__((noinline)) int branch_zero(int value) {
    if (value == 0) {
        return 7;
    }
    return value - 1;
}

__attribute__((noinline)) uint64_t memory_add(uint64_t *pointer, uint64_t value) {
    uint64_t previous = *pointer;
    *pointer = previous + value;
    return previous;
}

__attribute__((noinline)) uint64_t multiply_pair(uint64_t left, uint64_t right) {
    return (left * right) + left;
}

__attribute__((noinline)) uint64_t bit_pair(uint64_t left, uint64_t right) {
    return (left & right) | (left ^ UINT64_C(0x1234));
}

__attribute__((noinline)) uint64_t shift_pair(uint64_t value) {
    return (value << 5U) ^ (value >> 3U);
}

__attribute__((noinline)) int64_t signed_shift(int64_t value) {
    return value >> 7U;
}

__attribute__((noinline)) uint64_t divide_pair(uint64_t dividend, uint64_t divisor) {
    return dividend / (divisor | UINT64_C(1));
}

__attribute__((noinline)) int64_t signed_divide_pair(int64_t dividend, int64_t divisor) {
    return dividend / (divisor | INT64_C(1));
}

__attribute__((noinline)) uint64_t extend_bytes(const uint8_t *left, const int8_t *right) {
    return (uint64_t)*left + (uint64_t)(int64_t)*right;
}

__attribute__((noinline)) uint64_t indexed_load(const uint64_t *pointer, size_t index) {
    return pointer[index + 3U];
}

__attribute__((noinline)) uint64_t call_pair(uint64_t left, uint64_t right) {
    return add_pair(left, right) + UINT64_C(1);
}
