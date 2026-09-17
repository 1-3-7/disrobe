typedef long long_t;

long_t exported_entry(long_t v);
long_t exported_second(long_t v);
long_t exported_third(long_t v);

__attribute__((noinline)) static long_t fold_three(long_t v) {
  return exported_entry(v) + exported_second(v) + exported_third(v);
}

__attribute__((used)) void _start(void) {
  volatile long_t sink = fold_three(3);
  (void)sink;
  for (;;) {
  }
}
