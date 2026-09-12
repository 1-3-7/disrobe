package com.example.jni;

public class NativeSurface {

    static {
        System.loadLibrary("native_surface");
    }

    public native boolean retBoolean();
    public native byte retByte();
    public native char retChar();
    public native short retShort();
    public native int retInt();
    public native long retLong();
    public native float retFloat();
    public native double retDouble();
    public native void retVoid();

    public static native int primParams(boolean z, byte b, char c, short s, int i, long j, float f, double d);

    public static native void staticSink(int x);

    public native int[] intArrayOp(int[] a);
    public native long[] longArrayOp(long[] a);
    public native boolean[] boolArrayOp(boolean[] a);
    public native Object[] objectArrayOp(String[] a);
    public native int[][] nestedArrayOp(int[][] a);

    public native String stringOp(String s);
    public native Class classOp(Class c);
    public native Object objectOp(Object o);
    public native Throwable throwableOp(Throwable t);
    public native Object exceptionOp(Exception e);
    public native Object widgetOp(Widget w);

    public native int over(int x);
    public native int over(String s);
    public native int over(int x, long y);

    public native void with_underscore(int x);
    public native void with$dollar(int x);
    public native void valueπ(int x);
}

class Widget {
}
