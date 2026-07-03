package com.example.app;

public class Calculator {
    private static final String GREETING = "calc engine ready";
    private static final String FAREWELL = "calc engine shutdown";
    private static final int SCALE_FACTOR = 7;

    private final Ledger ledger;

    public Calculator() {
        this.ledger = new Ledger();
    }

    public String banner() {
        return GREETING + " v" + SCALE_FACTOR;
    }

    public int accumulate(int upTo) {
        int total = 0;
        for (int i = 1; i <= upTo; i++) {
            if (i % 2 == 0) {
                total += i * SCALE_FACTOR;
            } else {
                total += i;
            }
            this.ledger.record(i, total);
        }
        return total;
    }

    public int fibonacci(int n) {
        if (n < 2) {
            return n;
        }
        int a = 0;
        int b = 1;
        for (int i = 2; i <= n; i++) {
            int next = a + b;
            a = b;
            b = next;
        }
        return b;
    }

    public String describe(int value) {
        if (value > 100) {
            return "large:" + value;
        }
        if (value > 10) {
            return "medium:" + value;
        }
        return "small:" + value;
    }

    public String shutdown() {
        return FAREWELL + " entries=" + this.ledger.size();
    }

    public static void main(String[] args) {
        Calculator calc = new Calculator();
        System.out.println(calc.banner());
        System.out.println("accumulate(10)=" + calc.accumulate(10));
        System.out.println("fibonacci(12)=" + calc.fibonacci(12));
        System.out.println(calc.describe(250));
        System.out.println(calc.shutdown());
    }

    static final class Ledger {
        private int count;
        private long checksum;

        void record(int index, int value) {
            this.count++;
            this.checksum += (long) index * value;
        }

        int size() {
            return this.count;
        }

        long checksum() {
            return this.checksum;
        }
    }
}
