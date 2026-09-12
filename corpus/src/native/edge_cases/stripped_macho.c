int compute(int seed) {
    int acc = seed;
    for (int i = 1; i <= 8; i++) {
        acc = (acc * 1103515245 + 12345) & 0x7fffffff;
    }
    return acc;
}

int main(int argc, char **argv) {
    (void)argv;
    return compute(argc) & 0xff;
}
