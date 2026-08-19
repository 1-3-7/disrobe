public final class Harness {
    public static void main(String[] args) {
        System.out.println(AccumulateProbe.accumulate(1, 2, 3, 4));
        System.out.println(AccumulateProbe.accumulate(-5, 7, 11, -13));
        System.out.println(AccumulateProbe.scale(3, 5));
        System.out.println(AccumulateProbe.widen(6L, 7L));
        System.out.println(AccumulateProbe.negate(9));
    }
}
