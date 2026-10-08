#include "common.h"

#if defined(ARMED)
#define RDTSC_THRESHOLD 0ull
#else
#define RDTSC_THRESHOLD 100000000ull
#endif

static inline __attribute__((always_inline)) uint64_t read_tsc(void) {
    uint32_t lo;
    uint32_t hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(void) {
    uint64_t start = read_tsc();
    volatile int sink = 0;
    for (int i = 0; i < 16; i++) {
        sink += i;
    }
    uint64_t end = read_tsc();
    uint64_t delta = end - start;
    if (delta > RDTSC_THRESHOLD) {
        report("rdtsc_delta", 1);
    } else {
        report("rdtsc_delta", 0);
    }
    return sink == 120 ? 0 : 1;
}
