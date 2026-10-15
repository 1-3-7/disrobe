#include "fortify_shim.h"

int copy_and_print(const char *src, unsigned long n) {
    char buf[32];
    memcpy(buf, src, n);
    return printf("%d:%s", (int)n, buf);
}

char *forward(char *dst, const char *src) {
    return strcpy(dst, src);
}

void _start(void) {
    char out[16];
    forward(out, "mitigation");
    copy_and_print(out, 10);
    for (;;) {
    }
}
