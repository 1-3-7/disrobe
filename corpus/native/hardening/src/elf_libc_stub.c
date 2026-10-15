unsigned long __stack_chk_guard = 0x2f8a6b1d9c3e5047UL;

void __stack_chk_fail(void) {
    for (;;) {
    }
}

int printf(const char *format, ...) {
    return format[0];
}

int __printf_chk(int flag, const char *format, ...) {
    return flag + format[0];
}

void *memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n-- != 0) {
        *d++ = *s++;
    }
    return dst;
}

void *__memcpy_chk(void *dst, const void *src, unsigned long n, unsigned long dst_len) {
    if (n > dst_len) {
        __stack_chk_fail();
    }
    return memcpy(dst, src, n);
}

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++) != 0) {
    }
    return dst;
}

char *__strcpy_chk(char *dst, const char *src, unsigned long dst_len) {
    (void)dst_len;
    return strcpy(dst, src);
}
