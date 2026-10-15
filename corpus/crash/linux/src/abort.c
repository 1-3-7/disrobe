#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) static void check(int value) {
    if (value != 42) {
        abort();
    }
}

int main(void) {
    printf("checking\n");
    fflush(stdout);
    check(7);
    return 0;
}
