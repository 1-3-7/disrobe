extern void *malloc(unsigned long n);
extern void *calloc(unsigned long count, unsigned long size);
extern void free(void *p);

int g_counter = 3;
__attribute__((visibility("hidden"))) long g_reserved = 0;

int fill(int n) {
    int *p = (int *)malloc(16);
    if (!p) {
        return -1;
    }
    p[0] = n;
    p[1] = g_counter;
    int total = p[0] + p[1];
    free(p);
    return total;
}

long reserve(unsigned long count) {
    long *p = (long *)calloc(count, 8);
    if (!p) {
        return -1;
    }
    p[0] = (long)count;
    g_reserved = p[0];
    long first = p[0];
    free(p);
    return first;
}

int through_pointer(int *q, int n) {
    q[0] = n;
    q[1] = g_counter;
    return q[0] + q[1];
}
