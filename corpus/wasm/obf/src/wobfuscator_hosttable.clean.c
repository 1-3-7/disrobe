__attribute__((export_name("eval0"))) int eval0(int a, int b) {
  return a - b;
}

__attribute__((export_name("eval1"))) int eval1(int a, int b) {
  return a << b;
}

__attribute__((export_name("mix"))) int mix(int a, int b) {
  return (a ^ b) + (a & b);
}

__attribute__((export_name("hash"))) int hash(int a, int b) {
  int h = (int)((unsigned)a * 2654435761u);
  h = h ^ (int)((unsigned)b >> 16);
  return h - b;
}
