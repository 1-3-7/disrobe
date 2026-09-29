public class FinallyBranchExitProbe {
    static int log;
    static int after;

    static int threeReturns(int k) {
        try {
            if (k < 0) {
                return -1;
            }
            if (k == 0) {
                return 0;
            }
            log += k;
        } finally {
            log = log * 3 + 1;
        }
        return log;
    }

    static void voidExits(int k) {
        try {
            if (k % 3 == 0) {
                return;
            }
            if (k % 3 == 1) {
                return;
            }
        } finally {
            log += 7;
        }
        after++;
    }
}
