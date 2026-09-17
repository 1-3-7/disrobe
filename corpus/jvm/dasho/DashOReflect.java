package com.disrobe.bench;

import java.lang.reflect.Method;

public final class DashOReflect {
    private static final String KEY = buildKey("com/disrobe/bench/DashOReflect");

    private DashOReflect() {}

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

    public static String readProperty() throws Exception {
        Class<?> c = Class.forName(d("Vsjw\34xWRS4GgIh[Y"));
        Method m = c.getMethod(d("[whF@{FYFnm"), String.class);
        return (String) m.invoke(null, d("Vsjw\34bSNGs{p"));
    }

    public static void main(String[] args) throws Exception {
        System.out.println(readProperty());
    }
}
