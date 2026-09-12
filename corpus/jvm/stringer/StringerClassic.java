package com.disrobe.bench;

public final class StringerClassic {
    private static final int KEY = buildKey("com/disrobe/bench/StringerClassic");

    private StringerClassic() {}

    private static int buildKey(String className) {
        int k = 0x1505;
        for (int i = 0; i < className.length(); i++) {
            k = ((k << 5) + k) + className.charAt(i);
        }
        return k & 0x7FFFFFFF;
    }

    private static String decrypt(String s) {
        char[] in = s.toCharArray();
        char[] out = new char[in.length];
        int rot = KEY;
        for (int i = 0; i < in.length; i++) {
            int mask = (rot ^ (i * 0x21)) & 0x3F;
            out[i] = (char) (in[i] ^ mask);
            rot = (rot * 0x1000193 + in[i]) & 0x7FFFFFFF;
        }
        return new String(out);
    }

    public static String dbUrl() {
        return decrypt("cKuD.HuPja@uDD1\020??\016\017\010\034\017\033.\002>\002\026\037\007VO:aTS\\D@");
    }

    public static String authHeader() {
        return decrypt("HgF]TVFLf^tmZ\025\025[h_\\FP\007<w9u*p&i");
    }

    public static String vaultUrl() {
        return decrypt("aYKA`\0120\003jn\177x]\037T\\gttmHV\012R\022%GomL~V2YFq");
    }

    public static String role() {
        return decrypt("[hTdQ~XpBtC^qLH\177D");
    }

    public static String keyPath() {
        return decrypt("&FjD8vZl\014gAcjnzf\013w~Q\035\\qY");
    }

    public static void main(String[] args) {
        System.out.println(dbUrl());
        System.out.println(authHeader());
        System.out.println(vaultUrl());
        System.out.println(role());
        System.out.println(keyPath());
    }
}
