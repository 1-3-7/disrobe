public class CompoundLoops {
    static int limit = 7;
    int count;
    String tag;

    static boolean check(int i) {
        return i * i < 40;
    }

    static int andChainWithAssignment(boolean a, int y, boolean b) {
        int x = 0;
        int n = 0;
        while (a && (x += y) < 20 && b) {
            n = n * 3 + x;
        }
        return n * 100 + x;
    }

    static int orChain(int i, String s) {
        int steps = 0;
        while (i < 3 || s.length() < 5) {
            i++;
            s = s + "z";
            steps++;
        }
        return steps * 1000 + i * 10 + s.length();
    }

    static int mixedChain(int i, int n, boolean flag) {
        int total = 0;
        while ((i < n || flag) && i < 12) {
            total += i;
            i += 2;
            if (total > 30) {
                flag = false;
            }
        }
        return total * 100 + i;
    }

    static int forWithCall(int n) {
        int sum = 0;
        int i;
        for (i = 0; i < n && check(i); i++) {
            sum += i * 3;
        }
        return sum * 100 + i;
    }

    static int doWhileCompound(int i, int n) {
        int acc = 1;
        do {
            acc = acc * 3 + i;
            i++;
        } while (i < n && (acc & 1) == 0);
        return acc * 100 + i;
    }

    int fieldCondition(String next) {
        int rounds = 0;
        while (this.count < limit && tag != null) {
            count += 2;
            rounds++;
            if (count > 4) {
                tag = next;
            }
        }
        return rounds * 100 + count;
    }

    static int headerAssignsBeforeTest(int[] values, int bound) {
        int i = 0;
        int seen = 0;
        int v;
        while ((v = values[i++]) != 0 && seen + v < bound) {
            seen += v;
        }
        return seen * 100 + i;
    }

    static int assignInCondition(int x, int y) {
        if ((x += y) < 20) {
            return x * 2;
        }
        return x;
    }

    static int postIncrementIndex(int[] values, int i) {
        int v = values[i++];
        return v * 10 + i;
    }
}
