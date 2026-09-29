public class RelayProbe {
    public static int relay(int x) {
        int state = 0;
        int acc = x;
        for (;;) {
            switch (state) {
                case 0:
                    acc += 1;
                    state = 2;
                    break;
                case 2:
                    acc = acc * 10 + state;
                    state = 5;
                    break;
                case 5:
                    acc -= state;
                    state = 9;
                    break;
                default:
                    return acc * 100 + state;
            }
        }
    }
}
