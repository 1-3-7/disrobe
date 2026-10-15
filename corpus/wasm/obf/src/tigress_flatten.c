__attribute__((export_name("sum_squares"))) int sum_squares(int n) {
  int s;
  int i;
  int _1_sum_squares_next;

  _1_sum_squares_next = 7;
  while (1) {
    switch (_1_sum_squares_next) {
    case 7:
      s = 0;
      i = 0;
      _1_sum_squares_next = 3;
      break;
    case 3:
      if (i < n) {
        _1_sum_squares_next = 12;
      } else {
        _1_sum_squares_next = 1;
      }
      break;
    case 12:
      s += i * i;
      i++;
      _1_sum_squares_next = 3;
      break;
    case 1:
      return s;
    }
  }
}

__attribute__((export_name("collatz_steps"))) int collatz_steps(int n) {
  int steps;
  int _1_collatz_steps_next;

  _1_collatz_steps_next = 4;
  while (1) {
    switch (_1_collatz_steps_next) {
    case 4:
      steps = 0;
      if (n < 1) {
        _1_collatz_steps_next = 9;
      } else {
        _1_collatz_steps_next = 2;
      }
      break;
    case 9:
      return -1;
    case 2:
      if (n != 1) {
        _1_collatz_steps_next = 13;
      } else {
        _1_collatz_steps_next = 0;
      }
      break;
    case 13:
      if (steps < 1000) {
        _1_collatz_steps_next = 11;
      } else {
        _1_collatz_steps_next = 0;
      }
      break;
    case 11:
      if (n % 2 == 0) {
        _1_collatz_steps_next = 6;
      } else {
        _1_collatz_steps_next = 8;
      }
      break;
    case 6:
      n = n / 2;
      _1_collatz_steps_next = 5;
      break;
    case 8:
      n = 3 * n + 1;
      _1_collatz_steps_next = 5;
      break;
    case 5:
      steps++;
      _1_collatz_steps_next = 2;
      break;
    case 0:
      return steps;
    }
  }
}

__attribute__((export_name("classify"))) int classify(int x) {
  int r;
  int _1_classify_next;

  _1_classify_next = 5;
  while (1) {
    switch (_1_classify_next) {
    case 5:
      if (x < 0) {
        _1_classify_next = 2;
      } else {
        _1_classify_next = 8;
      }
      break;
    case 2:
      r = -1;
      _1_classify_next = 0;
      break;
    case 8:
      if (x == 0) {
        _1_classify_next = 3;
      } else {
        _1_classify_next = 6;
      }
      break;
    case 3:
      r = 0;
      _1_classify_next = 0;
      break;
    case 6:
      if (x < 100) {
        _1_classify_next = 1;
      } else {
        _1_classify_next = 4;
      }
      break;
    case 1:
      r = 1;
      _1_classify_next = 0;
      break;
    case 4:
      r = 2;
      _1_classify_next = 0;
      break;
    case 0:
      return r * 10 + collatz_steps(x & 63);
    }
  }
}
