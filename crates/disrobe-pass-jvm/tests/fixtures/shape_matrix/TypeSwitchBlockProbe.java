public class TypeSwitchBlockProbe {
    static int total;

    public static String describe(Object o) {
        StringBuilder sb = new StringBuilder();
        switch (o) {
            case Integer i when i > 10 -> {
                sb.append("big");
                total += i;
            }
            case Integer i -> {
                sb.append("int");
                total -= i;
            }
            case String s -> sb.append("str").append(s.length());
            case null -> sb.append("null");
            default -> {
                sb.append("other");
                total++;
            }
        }
        return sb.toString();
    }
}
