public class FallThroughProbe {
    public static int tail(byte[] data, int len) {
        int k = 0;
        switch (len & 3) {
            case 3:
                k ^= (data[2] & 0xff) << 16;
            case 2:
                k ^= (data[1] & 0xff) << 8;
            case 1:
                k ^= data[0] & 0xff;
                k *= 0x1b873593;
        }
        return k;
    }

    public static String letters(int n) {
        StringBuilder sb = new StringBuilder();
        switch (n) {
            case 0:
                sb.append('a');
            case 1:
                sb.append('b');
                break;
            case 5:
                sb.append('c');
            default:
                sb.append('d');
            case 9:
                sb.append('e');
        }
        return sb.toString();
    }
}
