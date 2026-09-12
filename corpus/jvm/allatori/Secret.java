package com.disrobe.sample;

public class Secret {
    public static String dbUrl() {
        return "jdbc:postgresql://10.4.2.9:5432/ledger_main";
    }

    public static String apiToken() {
        return "sk-live-7f3a9c1d-2b8e-4f60-a1d2-payments-prod";
    }

    public static String greeting(String who) {
        return "Hello, " + who + "! Welcome to the disrobe sample harness.";
    }

    public static String[] paths() {
        return new String[] {
            "/opt/disrobe/conf/keystore.p12",
            "s3://disrobe-artifacts/build/release",
            "config-key=disrobe-static-test-marker"
        };
    }

    public static void main(String[] args) {
        System.out.println(dbUrl());
        System.out.println(apiToken());
        System.out.println(greeting("operator"));
        for (String p : paths()) {
            System.out.println(p);
        }
    }
}
