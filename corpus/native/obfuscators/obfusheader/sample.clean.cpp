#include <cstdio>

int main() {
    const char* secret = "the-hidden-flag-value";
    int n = 7;
    printf("classify=%d\n", (n + 1) * 3 ^ 0x5a);
    printf("secret=%s\n", secret);
    return 0;
}
