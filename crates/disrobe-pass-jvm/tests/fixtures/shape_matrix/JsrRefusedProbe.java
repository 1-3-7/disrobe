public class JsrRefusedProbe {
    static int log;

    static int branchy(int n) {
        int total = 0;
        try {
            for (int i = 0; i < n; i++) {
                total += i;
                if (total > 20) {
                    return total;
                }
            }
        } finally {
            if (n % 2 == 0) {
                log = log * 3 + 1;
            } else {
                log = log * 5 - 2;
            }
        }
        return -total;
    }

    static int looping(int k) {
        int r = k;
        try {
            r = r * 2 + 1;
        } finally {
            for (int j = 0; j < (k & 3); j++) {
                if (j == 2) {
                    break;
                }
                log = log * 7 + j;
            }
        }
        return r;
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
}
