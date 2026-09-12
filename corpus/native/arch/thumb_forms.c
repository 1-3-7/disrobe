int checksum(const unsigned char *data, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += data[i] * 3;
        if (total > 4096) {
            total -= 4096;
        }
    }
    return total;
}

int scale(int value, int factor) {
    return value * factor + 7;
}

void _start(void) {
    static const unsigned char buf[4] = {1, 2, 3, 4};
    volatile int r = checksum(buf, 4);
    r = scale(r, 3);
    (void)r;
}
