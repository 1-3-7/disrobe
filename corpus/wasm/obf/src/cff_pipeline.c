int pipeline(int x) {
  int state = 0;
  int v = x;
  for (;;) {
    switch (state) {
      case 0:
        v = v + 3;
        state = 1;
        break;
      case 1:
        v = v * 5;
        state = 2;
        break;
      case 2:
        v = v ^ 17;
        state = 3;
        break;
      default:
        return v;
    }
  }
}
