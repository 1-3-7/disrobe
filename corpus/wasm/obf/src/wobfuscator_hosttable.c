__attribute__((import_module("env"), import_name("k0"))) int k0(int a, int b);
__attribute__((import_module("env"), import_name("k1"))) int k1(int a, int b);
__attribute__((import_module("env"), import_name("k2"))) int k2(int a, int b);
__attribute__((import_module("env"), import_name("k3"))) int k3(int a, int b);
__attribute__((import_module("env"), import_name("k4"))) int k4(int a, int b);
__attribute__((import_module("env"), import_name("k5"))) int k5(int a, int b);
__attribute__((import_module("env"), import_name("k6"))) int k6(int a, int b);

__attribute__((export_name("eval0"))) int eval0(int a, int b) {
  return a - b;
}

__attribute__((export_name("eval1"))) int eval1(int a, int b) {
  return a << b;
}

__attribute__((export_name("mix"))) int mix(int a, int b) {
  return k1(k0(a, b), k2(a, b));
}

__attribute__((export_name("hash"))) int hash(int a, int b) {
  int h = k3(a, 2654435761u);
  h = k4(h, k5(b, 16));
  return k6(h, b);
}
