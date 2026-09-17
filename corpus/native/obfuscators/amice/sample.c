#include <stdio.h>

__attribute__((annotate("+string_encryption +fla +mba +bcf")))
int compute(int n) {
    const char *c2 = "https://c2.amice-demo.example/gate?id=victim-7f3a";
    printf("%s\n", c2);
    return (n + 1) * 3;
}

int main(void) {
    return compute(7);
}
