package com.disrobe.bench;

public final class SeedRotateCrypt {
    private static String decode(String s, int seed) {
        char[] c = s.toCharArray();
        for (int i = 0; i < c.length; i++) {
            switch ((i + seed) % 5) {
                case 0: c[i] = (char) (c[i] ^ 124); break;
                case 1: c[i] = (char) (c[i] ^ 3); break;
                case 2: c[i] = (char) (c[i] ^ 4); break;
                case 3: c[i] = (char) (c[i] ^ 73); break;
                default: c[i] = (char) (c[i] ^ 94); break;
            }
        }
        return new String(c).intern();
    }

    public static String endpoint() {
        return decode("\u0016gf*d\u0011zw82F,+xnR3*ypI97znJ,f 2\u0010jj.", 0);
    }

    public static String header() {
        return decode("\\d\u0017\u0012wa;0\u001do)\u0008+\u0008k>ig\u001a;a~:J`", 2);
    }

    public static String query() {
        return decode("\r9OA\n\n\\pa*,\u0019w$\u000f\u000c3N$??\topi\t4FV\u000c~\u0008fj(0\u0008#9ia", 4);
    }

    public static String token() {
        return decode("BA\u001aq;@If\u0010\u0013Se-:\u0015mc", 1);
    }

    public static String flag() {
        return decode("/;\u001dwq;;Rhm%2Qps *\u001fk9,0\u001dah,:", 3);
    }

    public static void main(String[] args) {
        System.out.println(endpoint());
        System.out.println(header());
        System.out.println(query());
        System.out.println(token());
        System.out.println(flag());
    }
}
