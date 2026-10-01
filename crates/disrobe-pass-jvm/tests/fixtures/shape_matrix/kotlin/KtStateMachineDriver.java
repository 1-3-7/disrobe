public class KtStateMachineDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 10; seed++) {
            out.append(KtStateMachine.walk(seed)).append(',');
            out.append(KtStateMachine.dispatch(seed)).append(';');
        }
        System.out.println(out);
    }
}
