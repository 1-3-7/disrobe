#include <cstdio>

int classify(int n) {
    if (n < 10) return 1;
    if (n < 100) return 2;
    return 3;
}

int main() {
    int secret = 1337;
    const char* greeting = "disrobe sample greeting payload";
    std::printf("classify=%d,%d secret=%d msg=%s\n",
                classify(8), classify(40), secret, greeting);
    return 0;
}
