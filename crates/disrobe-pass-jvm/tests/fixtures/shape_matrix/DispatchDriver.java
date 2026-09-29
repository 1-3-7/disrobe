public class DispatchDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 7; seed++) {
            out.append(DispatchProbe.dispatch(seed)).append(';');
        }
        System.out.println(out);
    }
}
