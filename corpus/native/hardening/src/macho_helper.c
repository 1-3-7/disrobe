__attribute__((noinline)) void consume_bytes(volatile char *bytes, int count) {
    if (count > 0) {
        bytes[0] = (char)count;
    }
}

__attribute__((noinline)) void *make_object(void) {
    static long storage[4];
    return storage;
}

__attribute__((noinline)) void consume_object(void *object) {
    ((volatile long *)object)[1] = 1;
}
