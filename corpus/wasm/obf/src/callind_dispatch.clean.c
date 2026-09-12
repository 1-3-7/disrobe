static int op_add(int a, int b) { return a + b; }
static int op_mul(int a, int b) { return a * b; }
static int op_sub(int a, int b) { return a - b; }

int run(int a, int b) {
  int s = op_add(a, b);
  int p = op_mul(s, b);
  return op_sub(p, a);
}
