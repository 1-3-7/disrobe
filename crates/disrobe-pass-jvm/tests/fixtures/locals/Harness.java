public final class Harness {
    public static void main(String[] args) {
        System.out.println(ParamProbe.paramReassign(5, 1));
        System.out.println(ParamProbe.paramReassign(5, 0));
        System.out.println(ParamProbe.paramConstChain(3, 4));
        System.out.println(ParamProbe.paramConstChain(-2, 9));
        System.out.println(ParamProbe.paramTextLength("ab", 1));
        System.out.println(ParamProbe.paramTextLength("abcdef", 0));
    }
}
