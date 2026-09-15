#include "corpus.h"

void *memset(void *dst, int value, u64 count) {
    volatile u8 *out = (volatile u8 *)dst;
    for (u64 i = 0; i < count; i++) {
        out[i] = (u8)value;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, u64 count) {
    volatile u8 *out = (volatile u8 *)dst;
    const volatile u8 *in = (const volatile u8 *)src;
    for (u64 i = 0; i < count; i++) {
        out[i] = in[i];
    }
    return dst;
}

int memcmp(const void *left, const void *right, u64 count) {
    const volatile u8 *a = (const volatile u8 *)left;
    const volatile u8 *b = (const volatile u8 *)right;
    for (u64 i = 0; i < count; i++) {
        if (a[i] != b[i]) {
            return (int)a[i] - (int)b[i];
        }
    }
    return 0;
}

static void leave(int code) {
#if defined(__x86_64__)
    register long rax __asm__("rax") = 60;
    register long rdi __asm__("rdi") = code;
    __asm__ volatile("syscall" : : "r"(rax), "r"(rdi) : "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
#endif
    for (;;) {
    }
}

void _start(void) {
    u64 result = corpus_main(3);
    leave((int)((result ^ (result >> 32)) & 0x7f));
}
