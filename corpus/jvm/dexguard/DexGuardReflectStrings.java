package com.disrobe.sample;

import java.lang.reflect.Method;

public final class DexGuardReflectStrings {
private static final String[] ENC = new String[] {
        "\u000e\u0012\u0012\u0016\u0015\u005c\u0049\u0049\u0007\u0016\u000f\u0048\u0003\u001e\u0007\u000b\u0016\u000a\u0003\u0048\u0005\u0009\u000b\u0049\u0010\u0057\u0049\u0007\u0013\u0012\u000e",
        "\u003e\u004b\u0027\u0016\u000f\u004b\u002d\u0003\u001f",
        "\u0002\u0003\u0005\u0014\u001f\u0016\u0012\u0032\u0009\u000d\u0003\u0008",
        "\u0035\u0023\u002a\u0023\u0025\u0032\u0046\u004c\u0046\u0020\u0034\u0029\u002b\u0046\u0015\u0003\u0005\u0014\u0003\u0012\u0015\u0046\u0031\u002e\u0023\u0034\u0023\u0046\u000f\u0002\u0046\u005b\u0046\u0059",
        "\u0027\u0023\u0035\u0049\u0025\u0024\u0025\u0049\u0036\u002d\u0025\u0035\u0053\u0036\u0007\u0002\u0002\u000f\u0008\u0001",
        "\u0005\u0009\u000b\u0048\u0002\u000f\u0015\u0014\u0009\u0004\u0003\u0048\u0015\u0007\u000b\u0016\u000a\u0003\u0048\u0035\u0003\u0005\u0014\u0003\u0012",
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

/*
Ground-truth plaintext (the decrypt routine maps ENC[i] ^ KEY back to these):
        PLAINTEXT[0] = "https://api.example.com/v1/auth"
        PLAINTEXT[1] = "X-Api-Key"
        PLAINTEXT[2] = "decryptToken"
        PLAINTEXT[3] = "SELECT * FROM secrets WHERE id = ?"
        PLAINTEXT[4] = "AES/CBC/PKCS5Padding"
        PLAINTEXT[5] = "com.disrobe.sample.Secret"
*/
