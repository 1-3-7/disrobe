public class DispatchProbe {
    public static int dispatch(int x) {
        int state = 1;
        int acc = x;
        for (;;) {
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
                case 4:
                    return acc * 100 + state;
                default:
                    return -1;
            }
        }
    }
}
