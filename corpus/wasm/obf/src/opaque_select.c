static int collatz_steps(int n) {
  int v = n;
  int steps = 0;
  while (v != 1 && steps < 1000) {
    if ((v & 1) == 0) {
      v = v / 2;
    } else {
      v = 3 * v + 1;
    }
    steps++;
  }
  return v;
}

int pick(int a, int b) {
  if (collatz_steps(9) == 1) {
    return (a + b) * 7;
  } else {
    return (a - b) * 13 + 999;
  }
}

int scale(int x) {
  if (collatz_steps(27) == 1) {
    return x * 3 + 11;
  } else {
    return x * 31 - 7;
  }
}
