#include <stdio.h>

int classify(int n) {
    if (n > 10) {
        return n * 2;
    } else {
        return n + 1;
    }
}

int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) {
        s += i;
    }
    return s;
}

int main(void) {
    printf("%d\n", classify(15));
    printf("%d\n", classify(3));
    printf("%d\n", sum_to(5));
    return 0;
}
