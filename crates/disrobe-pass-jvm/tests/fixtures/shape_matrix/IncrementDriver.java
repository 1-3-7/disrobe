public class IncrementDriver {
    public static void main(String[] args) {
        IncrementProbe p = new IncrementProbe();
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < 3; k++) {
            sb.append(IncrementProbe.postStatic()).append(',').append(IncrementProbe.preStatic()).append(',');
            sb.append(IncrementProbe.addStatic()).append(',').append(p.postField()).append(',');
            sb.append(p.preField()).append(',').append(p.addField()).append(',').append(p.postByte()).append(',');
            sb.append(IncrementProbe.postLong()).append(',').append(p.postArray(k)).append(',');
            sb.append(p.preArray(k)).append(',').append(IncrementProbe.sum()).append(';');
        }
        System.out.println(sb);
    }
}
