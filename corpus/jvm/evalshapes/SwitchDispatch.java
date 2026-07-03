package com.disrobe.bench;

public final class SwitchDispatch {
    private SwitchDispatch() {}

    private static String decrypt(String cipher) {
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            int sel = i % 4;
            int k;
            switch (sel) {
                case 0: k = 0x13; break;
                case 1: k = 0x2C; break;
                case 2: k = 0x4F; break;
                default: k = 0x6A; break;
            }
            k = (k + (i & 0x0F)) & 0x7F;
            out[i] = (char) (in[i] ^ k);
        }
        return new String(out);
    }

    public static String streamUrl() {
        return decrypt("xL7vz^hA+~Ts}Y4yP9K\"`G0X(zY");
    }

    public static String bearer() {
        return decrypt("QH0rCub1XZ46zg8mxd?r`");
    }

    public static String masterKeyUri() {
        return decrypt("`kB8P'rS8kJp\taB5B|T,4X8k\\/");
    }

    public static void main(String[] args) {
        System.out.println(streamUrl());
        System.out.println(bearer());
        System.out.println(masterKeyUri());
    }
}
