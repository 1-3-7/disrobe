extern int puts(const char *s);
extern void *malloc(unsigned long n);
extern void free(void *p);
extern unsigned long strlen(const char *s);
extern int printf(const char *fmt, ...);
extern int atoi(const char *s);
extern int external_counter;

int run(const char *s) {
    void *p = malloc(strlen(s) + 1);
    if (!p) return -1;
    puts(s);
    printf("%s=%d n=%d\n", s, atoi(s), external_counter);
    free(p);
    return external_counter;
}
