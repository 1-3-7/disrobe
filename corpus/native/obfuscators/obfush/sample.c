#include <stdio.h>

int classify(int n) {
    if (n > 10) {
        return n * 2;
    } else {
        return n + 1;
    }
}

int main(void) {
    printf("classify=%d,%d\n", classify(7), classify(20));
    printf("secret=%s\n", "the-hidden-flag-value");
    return 0;
}
