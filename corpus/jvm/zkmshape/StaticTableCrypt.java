package com.disrobe.bench;

public final class StaticTableCrypt {
    private static final char[] KEY = buildKey();

    private StaticTableCrypt() {}

    private static char[] buildKey() {
        char[] k = new char[16];
        int s = 0x1F;
        for (int i = 0; i < k.length; i++) {
            s = (s * 33 + 15) & 0x7F;
            k[i] = (char) s;
        }
        return k;
    }

    private static String decrypt(String cipher) {
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (char) (in[i] ^ KEY[i % KEY.length]);
        }
        return new String(out);
    }

    public static String url() {
        return decrypt("d9nx04qdw9><-`0!>s<5?c;$6c+qk=lf`:");
    }

    public static String token() {
        return decrypt("VpEu~<zyg9)Rw%h5.dj#onl!e");
    }

    public static void main(String[] args) {
        System.out.println(url());
        System.out.println(token());
    }
}
