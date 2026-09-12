unsigned mips_mix(unsigned a, unsigned b, unsigned *p) {
    unsigned c = (a + b) ^ (a - b);
    p[1] = c;
    return p[0] + c;
}

unsigned mips_accumulate(const unsigned *p, unsigned count) {
    unsigned value = 0;
    for (unsigned index = 0; index < count; ++index) {
        value += p[index];
    }
    return value;
}
