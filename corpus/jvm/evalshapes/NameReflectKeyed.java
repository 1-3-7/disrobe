package com.disrobe.bench;

public final class NameReflectKeyed {
    private NameReflectKeyed() {}

    private static int seed() {
        String n = NameReflectKeyed.class.getName();
        int h = 0;
        for (int i = 0; i < n.length(); i++) {
            h = (h * 31 + n.charAt(i)) & 0x7FFFFFFF;
        }
        return h & 0x7F;
    }

    private static String decrypt(String cipher) {
        int base = seed();
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            int k = (base + i) & 0x7F;
            out[i] = (char) (in[i] ^ k);
        }
        return new String(out);
    }

    public static String registryUrl() {
        return decrypt("\u0005\u001d\u001e\u0013\b\b\u000f\u0007Qiovfvkgk21>??\"x=");
    }

    public static String serviceAccount() {
        return decrypt("\u0004\u000e\u001aW\u000b\u001d\u0004\u0013\u001anuq.twic");
    }

    public static String webhookSecret() {
        return decrypt("\u0000\u0010\n\u001f\u0018#N\u0018Fa3`4g4b?m=:>:");
    }

    public static void main(String[] args) {
        System.out.println(registryUrl());
        System.out.println(serviceAccount());
        System.out.println(webhookSecret());
    }
}
