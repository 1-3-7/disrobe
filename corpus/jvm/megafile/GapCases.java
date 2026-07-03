public class GapCases {
    enum Mood { CALM, HAPPY, ANGRY }

    static int doublePositive(int x) {
        assert x > 0;
        return x * 2;
    }

    static long scaled(long v) {
        assert v > 0L : "must be positive";
        return v * 3L;
    }

    static String classify(String s) {
        switch (s) {
            case "one":
                return "1";
            case "two":
                return "2";
            case "three":
                return "3";
            default:
                return "?";
        }
    }

    static int bucket(String s) {
        int r = 0;
        switch (s) {
            case "x":
            case "y":
                r = 1;
                break;
            case "Aa":
            case "BB":
                r = 2;
                break;
            default:
                r = -1;
        }
        return r;
    }

    static String moodName(Mood m) {
        switch (m) {
            case CALM:
                return "calm";
            case HAPPY:
                return "happy";
            case ANGRY:
                return "angry";
            default:
                return "unknown";
        }
    }

    static String seasonColor(Season s) {
        switch (s) {
            case WINTER:
                return "white";
            case SPRING:
                return "green";
            case SUMMER:
                return "gold";
            default:
                return "gray";
        }
    }
}
