public class FlatteningProbe {
    public static int original(int n) {
        int acc = 1;
        int i = 0;
        while (i < n) {
            if (acc > i) {
                acc -= i;
            } else {
                acc += acc;
                acc += i;
            }
            i++;
        }
        return acc;
    }

    public static int flattened(int n) {
        int acc = 0;
        int i = 0;
        int state = 0;
        while (true) {
            switch (state) {
                case 0:
                    acc = 1;
                    i = 0;
                    state = 1;
                    break;
                case 1:
                    if (i < n) {
                        state = 2;
                    } else {
                        state = 6;
                    }
                    break;
                case 2:
                    if (acc > i) {
                        state = 3;
                    } else {
                        state = 4;
                    }
                    break;
                case 3:
                    acc -= i;
                    state = 5;
                    break;
                case 4:
                    acc += acc;
                    acc += i;
                    state = 5;
                    break;
                case 5:
                    i++;
                    state = 1;
                    break;
                case 6:
                    return acc;
                default:
                    throw new IllegalStateException();
            }
        }
    }
}
