#include <stdio.h>

static volatile int *target;

__attribute__((noinline)) static int read_through(volatile int *pointer) {
    return *pointer + 1;
}

__attribute__((noinline)) static int outer(int depth) {
    if (depth == 0) {
        return read_through(target);
    }
    return outer(depth - 1) + 1;
}

int main(void) {
    printf("before fault\n");
    fflush(stdout);
    return outer(3);
}
