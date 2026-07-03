package com.disrobe.bench;

public final class DashOStrings {
    private static final String KEY = buildKey("com/disrobe/bench/DashOStrings");

    private DashOStrings() {}

    private static String buildKey(String className) {
        int a = 0x5A5A_5A5A;
        for (int i = 0; i < className.length(); i++) {
            a = (a * 31 + className.charAt(i)) & 0x7FFFFFFF;
        }
        char[] k = new char[8];
        for (int i = 0; i < 8; i++) {
            a = (a * 1103515245 + 12345) & 0x7FFFFFFF;
            k[i] = (char) (0x21 + (a % 0x5E));
        }
        return new String(k);
    }

    private static String d(String cipher) {
        char[] k = KEY.toCharArray();
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (char) (in[i] ^ (k[i % k.length] & 0x3F) ^ (i & 0x1F));
        }
        return new String(out);
    }

    public static String dbUrl() {
        return d("WOi|\5XmhVOf-CW~o\27{k}@C\"}G\11\"2\25\36(^ohG");
    }

    public static String serviceToken() {
        return d("e\6XzMAvjP\16Wx\\Zy;\15\17y>K\36j");
    }

    public static String chargeEndpoint() {
        return d("U_\177oL\0150&WJo{^Qp/DUoj]Inu\12Rcn\10LopOLn");
    }

    public static String role() {
        return d("odGZ`dJYpqVDrm");
    }

    public static String secretsPath() {
        return d("\22N\177|\20Voy\32PftEZcr\3Ki`_B}mLV`");
    }

    public static void main(String[] args) {
        System.out.println(dbUrl());
        System.out.println(serviceToken());
        System.out.println(chargeEndpoint());
        System.out.println(role());
        System.out.println(secretsPath());
    }
}
