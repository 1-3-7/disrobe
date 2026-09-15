int acc(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i * 3;
    }
    return s;
}

int pick(int a, int b) {
    return a > b ? a - b : b - a;
}

int chain(int n) {
    return acc(n) + pick(n, 7);
}

void _start(void) {
    chain(11);
}
