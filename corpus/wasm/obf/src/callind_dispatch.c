static int op_add(int a, int b) { return a + b; }
static int op_mul(int a, int b) { return a * b; }
static int op_sub(int a, int b) { return a - b; }

typedef int (*binop)(int, int);

static binop table[3] = { op_add, op_mul, op_sub };

int run(int a, int b) {
  int s = table[0](a, b);
  int p = table[1](s, b);
  return table[2](p, a);
}
