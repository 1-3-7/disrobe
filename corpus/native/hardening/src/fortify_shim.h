extern int printf(const char *format, ...);
extern int __printf_chk(int flag, const char *format, ...);
extern void *memcpy(void *dst, const void *src, unsigned long n);
extern char *strcpy(char *dst, const char *src);

#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE > 0 && defined(__OPTIMIZE__)
#define printf(...) __printf_chk(_FORTIFY_SOURCE - 1, __VA_ARGS__)
#define memcpy(dst, src, n) __builtin___memcpy_chk(dst, src, n, __builtin_object_size(dst, 0))
#define strcpy(dst, src) __builtin___strcpy_chk(dst, src, __builtin_object_size(dst, 1))
#endif
