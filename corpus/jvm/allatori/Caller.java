package com.disrobe.sample;

public class Caller {
    public static String secretA() {
        return "kafka://broker.internal:9092/disrobe-events-topic";
    }

    public static String secretB() {
        return "Authorization: Bearer disrobe-cross-class-marker-9z";
    }
}
