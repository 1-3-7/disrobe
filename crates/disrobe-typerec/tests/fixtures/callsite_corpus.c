extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memset(void *s, int c, unsigned long n);
extern unsigned long strlen(const char *s);
extern void *malloc(unsigned long n);
extern long read(int fd, void *buf, unsigned long count);

char *dup_prefix(const char *s) {
    unsigned long len = strlen(s);
    char *buf = malloc(len + 1);
    memcpy(buf, s, len);
    return buf;
}

void fill_and_read(int fd, char *dst, unsigned long n) {
    memset(dst, 0, n);
    read(fd, dst, n);
}

long roundtrip(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);
    return read(0, dst, n);
}
