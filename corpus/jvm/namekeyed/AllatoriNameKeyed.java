package com.disrobe.bench;

public final class AllatoriNameKeyed {
    private AllatoriNameKeyed() {}

    public static String dbUrl() {
        return SharedDecryptor.a("YPWU\rUXHR]Y\\\u0005onssjwhwf~px\u007f}x`<4641'");
    }

    public static String apiKey() {
        return SharedDecryptor.a("k\u0019tZ[YMUIU\u0010uZ9{bt'v v)");
    }

    public static String region() {
        return SharedDecryptor.a("VA\u0018ARKM\u0017\n");
    }

    public static void main(String[] args) {
        System.out.println(dbUrl());
        System.out.println(apiKey());
        System.out.println(region());
    }
}
