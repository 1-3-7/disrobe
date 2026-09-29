public class StateMachineProbe {
    public static String walk(int seed) {
        StringBuilder sb = new StringBuilder();
        int state = 0;
        int steps = 0;
        while (state != 4 && steps < 20) {
            steps++;
            switch (state) {
                case 0:
                    sb.append('a');
                    state = seed % 3 == 0 ? 2 : 1;
                    break;
                case 1:
                    sb.append(state);
                    state = state + seed > 3 ? 3 : 2;
                    break;
                case 2:
                    sb.append('c').append(state * seed);
                    state = 3;
                    break;
                case 3:
                    sb.append('d');
                    state = sb.length() > 5 ? 4 : 0;
                    break;
                default:
                    state = 4;
                    break;
            }
        }
        return sb.toString() + ":" + state;
    }

    public static int dispatch(int x) {
        int state = 1;
        int acc = x;
        int guard = 0;
        while (state != 4 && guard < 50) {
            guard++;
            switch (state) {
                case 1:
                    acc = acc * 3 + state;
                    state = acc % 2 == 0 ? 2 : 3;
                    break;
                case 2:
                    acc += state * 10;
                    state = 4;
                    break;
                case 3:
                    acc -= state;
                    state = acc > 20 ? 4 : 1;
                    break;
                default:
                    state = 4;
                    break;
            }
        }
        return acc * 100 + state;
    }
}
