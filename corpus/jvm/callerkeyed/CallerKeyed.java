package com.disrobe.bench;

public final class CallerKeyed {
    private CallerKeyed() {}

    private static int callerKey(String className, String methodName) {
        int h = 0;
        for (int i = 0; i < className.length(); i++) {
            h = h * 31 + className.charAt(i);
        }
        for (int i = 0; i < methodName.length(); i++) {
            h = h * 31 + methodName.charAt(i);
        }
        return h & 0x7F;
    }

    private static String decrypt(String cipher) {
        StackTraceElement frame = new Throwable().getStackTrace()[1];
        String owner = frame.getClassName().replace('.', '/');
        int key = callerKey(owner, frame.getMethodName());
        char[] in = cipher.toCharArray();
        char[] out = new char[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (char) (in[i] ^ ((key + i) & 0x7F));
        }
        return new String(out);
    }

    public static String runConnect(int which) {
        if (which == 0) {
            return decrypt("nadd2yexxj|jc`~);:ru6ptoyop~L\u001b\u0017\u0017\u0017\u0017\tHZMOY_");
        }
        return decrypt("W@JBK]*\u007fcfka0W@\\Y5erkjstrn>Hhdpf\u0004LB\u0007\u0015\t\u0015");
    }

    public static String runAuth(int which) {
        if (which == 0) {
            return decrypt("\u000f:$9=!=/7#164a|\u001f;>\u0012\u0004\u0010C\u0010\n\r\u0002\u0006");
        }
        return decrypt("\u0016b\u0011!;~\u001f0/");
    }

    public static String emitConfig() {
        return decrypt("|~}ikmE\u000fPLHIIR\\\u0007OEMOBJT\fFAAP");
    }

    public static void main(String[] args) {
        System.out.println(runConnect(0));
        System.out.println(runConnect(1));
        System.out.println(runAuth(0));
        System.out.println(runAuth(1));
        System.out.println(emitConfig());
    }
}
