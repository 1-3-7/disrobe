public class StateMachineDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 7; seed++) {
            out.append(StateMachineProbe.walk(seed)).append(',');
            out.append(StateMachineProbe.dispatch(seed)).append(';');
        }
        System.out.println(out);
    }
}
