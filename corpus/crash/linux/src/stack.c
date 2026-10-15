#include <stdio.h>

__attribute__((noinline)) static int recurse(int depth, volatile char *previous) {
    volatile char frame[512];
    frame[0] = (char)depth;
    frame[511] = previous ? previous[0] : 0;
    return recurse(depth + 1, frame) + frame[511];
}

int main(void) {
    printf("recursing\n");
    fflush(stdout);
    return recurse(0, NULL);
}
