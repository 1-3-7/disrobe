public class RecordDriver {
    public static void main(String[] args) {
        RecordProbe p = new RecordProbe(3, "x");
        RecordProbe q = new RecordProbe(3, "x");
        RecordProbe r = new RecordProbe(4, null);
        System.out.println(p + "," + r + "," + p.equals(q) + "," + p.equals(r) + "," + (p.hashCode() == q.hashCode()));
    }
}
