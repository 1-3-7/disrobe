package com.example.app;

public class Sample {
    private int counter;
    private long checksum;

    public Sample() {
        this.counter = 0;
        this.checksum = 1469598103934665603L;
    }

    public String banner() {
        return "JBCO_GAUNTLET_BANNER v3";
    }

    public int accumulate(int n) {
        int total = 0;
        for (int i = 1; i <= n; i++) {
            if ((i & 1) == 0) {
                total += i * 2;
            } else {
                total += i;
            }
            this.counter++;
        }
        return total;
    }

    public long fold(String text) {
        long h = this.checksum;
        for (int i = 0; i < text.length(); i++) {
            h ^= text.charAt(i);
            h *= 1099511628211L;
        }
        return h;
    }

    public String classify(int value) {
        if (value > 1000) {
            return "large:" + value;
        } else if (value > 100) {
            return "medium:" + value;
        }
        return "small:" + value;
    }

    public String report() {
        int acc = accumulate(12);
        long folded = fold("DISROBE");
        return banner() + " acc=" + acc + " fold=" + folded + " " + classify(acc);
    }

    public static void main(String[] args) {
        Sample s = new Sample();
        System.out.println(s.report());
    }
}
