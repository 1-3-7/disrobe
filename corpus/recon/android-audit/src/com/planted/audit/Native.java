package com.planted.audit;

public final class Native {
    static {
        System.loadLibrary("antidebug");
        System.loadLibrary("clean");
    }

    private Native() {}

    public static native boolean antidebugPtraceSelf();

    public static native boolean antidebugTracerPid();

    public static native int cleanAdd(int left, int right);

    public static boolean traced() {
        return antidebugPtraceSelf() || antidebugTracerPid();
    }
}
