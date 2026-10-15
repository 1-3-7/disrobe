__attribute__((export_name("sum_squares"))) int sum_squares(int n) {
  int s = 0;
  for (int i = 0; i < n; i++) {
    s += i * i;
  }
  return s;
}

__attribute__((export_name("collatz_steps"))) int collatz_steps(int n) {
  int steps = 0;
  if (n < 1) {
    return -1;
  }
  while (n != 1 && steps < 1000) {
    if (n % 2 == 0) {
      n = n / 2;
    } else {
      n = 3 * n + 1;
    }
    steps++;
  }
  return steps;
}

__attribute__((export_name("classify"))) int classify(int x) {
  int r;
  if (x < 0) {
    r = -1;
  } else if (x == 0) {
    r = 0;
  } else if (x < 100) {
    r = 1;
  } else {
    r = 2;
  }
  return r * 10 + collatz_steps(x & 63);
}
