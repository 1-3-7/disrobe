package com.disrobe.bench;

public final class EnvKeyed {
    private EnvKeyed() {}

    private static String decrypt(String cipher) {
        String secret = System.getProperty("com.disrobe.bench.licenseKey");
        if (secret == null) {
            secret = Long.toString(System.currentTimeMillis());
        }
        int key = secret.hashCode() & 0x7F;
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (char) (in[i] ^ ((key + i) & 0x7F));
        }
        return new String(out);
    }

    public static String loadEndpoint() {
        return decrypt("placeholder-ciphertext-opaque");
    }

    public static void main(String[] args) {
        System.out.println(loadEndpoint());
    }
}
