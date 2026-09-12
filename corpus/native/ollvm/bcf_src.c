int classify(int n) {
    if (n > 10) {
        return n * 2;
    } else {
        return n + 1;
    }
}

int mixer(int a, int b) {
    return (a + b) ^ (a - b);
}
