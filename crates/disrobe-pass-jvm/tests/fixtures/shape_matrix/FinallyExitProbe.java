public class FinallyExitProbe {
    static int log;

    static int returning(int k) {
        try {
            if (k == 3) {
                return 33;
            }
            log += k;
        } finally {
            if (k > 1) {
                log *= 2;
            }
        }
        return log;
    }

    static int nested(int k) {
        try {
            try {
                if (k == 3) {
                    return 33;
                }
                log += k;
            } finally {
                if (k > 1) {
                    log *= 2;
                }
            }
        } finally {
            log -= k > 2 ? 1 : 4;
        }
        return log;
    }

    static int breaking(int n) {
        int t = 0;
        for (int i = 0; i < n; i++) {
            try {
                if (i == 4) {
                    break;
                }
                t += i;
            } finally {
                if (t > 3) {
                    log += t;
                }
            }
        }
        return t;
    }

    static int caught(int k) {
        try {
            if (k == 5) {
                return 50;
            }
            if (k == 2) {
                throw new IllegalStateException();
            }
            log += k;
        } catch (IllegalStateException e) {
            log -= 7;
        } finally {
            if (k > 1) {
                log *= 3;
            }
        }
        return log;
    }

    static int switching(int k) {
        int r = 0;
        switch (k & 3) {
            case 0:
                try {
                    if (k > 4) {
                        break;
                    }
                    r = 5;
                } finally {
                    log += k > 2 ? 2 : 1;
                }
                r += 1;
                break;
            default:
                r = -1;
        }
        return r;
    }

    static void returningVoid(int k) {
        try {
            if (k > 3) {
                return;
            }
            log += 11;
        } finally {
            if ((k & 1) == 0) {
                log -= 5;
            }
        }
        log += 1;
    }
}
