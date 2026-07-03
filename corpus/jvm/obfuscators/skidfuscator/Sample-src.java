public class Sample {
    public static int classify(int n) {
        if (n > 10) {
            return n * 2;
        } else {
            return n + 1;
        }
    }

    public static int sumTo(int n) {
        int acc = 0;
        for (int i = 0; i < n; i++) {
            acc += i;
        }
        return acc;
    }

    public static String pick(int k) {
        switch (k) {
            case 0: return "zero";
            case 1: return "one";
            case 2: return "two";
            default: return "many";
        }
    }

    public static void main(String[] args) {
        System.out.println(classify(7) + "," + classify(20));
        System.out.println(sumTo(5));
        System.out.println(pick(1) + "," + pick(9));
    }
}
