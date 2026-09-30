public class SlotReuseDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < 3; k++) {
            out.append(SlotReuseProbe.arraysThenList(k)).append(',')
                    .append(SlotReuseProbe.textThenBuilder(k)).append(',')
                    .append(SlotReuseProbe.namesThenCounts(k)).append(',')
                    .append(SlotReuseProbe.charSteps(k)).append(';');
        }
        System.out.println(out);
    }
}
