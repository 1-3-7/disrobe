extern void consume_bytes(volatile char *bytes, int count);

int checksum(int count) {
    volatile char buf[48];
    for (int i = 0; i < count; i++) {
        buf[i % 48] = (char)(i * 7);
    }
    consume_bytes(buf, count);
    return buf[count % 48];
}

int main(void) {
    return checksum(19);
}
