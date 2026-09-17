int probe(int seed) {
    int acc = seed;
    for (int i = 0; i < 16; i++) {
        acc = (acc << 1) ^ (acc >> 3);
    }
    return acc;
}

int main(int argc, char **argv) {
    (void)argv;
    return probe(argc) & 0xff;
}
