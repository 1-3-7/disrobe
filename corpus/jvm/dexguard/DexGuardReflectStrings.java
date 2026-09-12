package com.disrobe.sample;

import java.lang.reflect.Method;

public final class DexGuardReflectStrings {

    private static final String[] ENC = new String[] {
        "\016\022\022\026\025\134\111\111\007\026\017\110\003\036\007\013\026\012\003\110\005\011\013\111\020\127\111\007\023\022\016",
        "\076\113\047\026\017\113\055\003\037",
        "\002\003\005\024\037\026\022\062\011\015\003\010",
        "\065\043\052\043\045\062\106\114\106\040\064\051\053\106\025\003\005\024\003\022\025\106\061\056\043\064\043\106\017\002\106\133\106\131",
        "\047\043\065\111\045\044\045\111\066\055\045\065\123\066\007\002\002\017\010\001",
        "\005\011\013\110\002\017\025\024\011\004\003\110\025\007\013\026\012\003\110\065\003\005\024\003\022",
    };

    private static final int KEY = 0x66;

    public static String decrypt(int idx) {
        char[] src = ENC[idx].toCharArray();
        char[] out = new char[src.length];
        for (int i = 0; i < src.length; i++) {
            out[i] = (char) (src[i] ^ KEY);
        }
        return String.valueOf(out);
    }

    private static String fetch(int idx) {
        try {
            Method m = DexGuardReflectStrings.class.getDeclaredMethod("decrypt", int.class);
            return (String) m.invoke(null, Integer.valueOf(idx));
        } catch (Exception e) {
            return "";
        }
    }

    public static void main(String[] args) {
        for (int i = 0; i < ENC.length; i++) {
            System.out.println(fetch(i));
        }
    }
}
