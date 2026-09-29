public class IncrementProbe {
    static int calls;
    static long big;
    int n;
    byte small;
    int[] arr = new int[4];

    static int postStatic() {
        return calls++;
    }

    static int preStatic() {
        return ++calls;
    }

    static int addStatic() {
        return calls += 5;
    }

    int postField() {
        return n++;
    }

    int preField() {
        return ++n;
    }

    int addField() {
        return n += 3;
    }

    int postByte() {
        return small++;
    }

    static long postLong() {
        return big++;
    }

    int postArray(int i) {
        return arr[i]++;
    }

    int preArray(int i) {
        return ++arr[i];
    }

    static int sum() {
        int a = calls++ + calls++;
        return a + (calls = 7);
    }
}
