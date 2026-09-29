public class JsrShapesProbe {
    static int log;

    static void risky(int k) {
        if (k == 2) {
            throw new IllegalStateException("two");
        }
        log += k;
    }

    static int switchy(int k) {
        try {
            if (k < 0) {
                throw new IllegalArgumentException("neg");
            }
            return k * 7;
        } finally {
            switch (k & 3) {
                case 0:
                    log += 11;
                    break;
                case 1:
                    log -= 13;
                    break;
                case 2:
                    log ^= 17;
                default:
                    log += 19;
            }
        }
    }

    static int catching(int k) {
        try {
            log += 3;
            return k + 1;
        } finally {
            try {
                risky(k);
            } catch (IllegalStateException e) {
                log = -log;
            }
        }
    }

    static int innerFinally(int k) {
        try {
            log++;
        } finally {
            try {
                log *= 3;
            } finally {
                log -= k;
            }
        }
        return log;
    }
}
