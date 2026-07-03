package com.example.app;

public class Widget {
    private int counter;
    private final Ledger ledger;

    public Widget() {
        this.counter = 0;
        this.ledger = new Ledger();
    }

    public String banner() {
        return "R8_GAUNTLET_BANNER v5";
    }

    public int accumulate(int n) {
        int total = 0;
        for (int i = 1; i <= n; i++) {
            if ((i & 1) == 0) {
                total += i * 3;
            } else {
                total += i;
            }
            this.counter++;
            this.ledger.record(total);
        }
        return total;
    }

    public String classify(int value) {
        if (value > 1000) {
            return "tier:large:" + value;
        } else if (value > 100) {
            return "tier:medium:" + value;
        }
        return "tier:small:" + value;
    }

    public String report() {
        int acc = accumulate(15);
        return banner() + " acc=" + acc + " " + classify(acc) + " entries=" + this.ledger.size();
    }

    public static void main(String[] args) {
        Widget w = new Widget();
        System.out.println(w.report());
    }

    static final class Ledger {
        private int entries;
        private long sum;

        Ledger() {
            this.entries = 0;
            this.sum = 2166136261L;
        }

        void record(int value) {
            this.entries++;
            this.sum = (this.sum ^ value) * 16777619L;
        }

        int size() {
            return this.entries;
        }

        long checksum() {
            return this.sum;
        }
    }
}
