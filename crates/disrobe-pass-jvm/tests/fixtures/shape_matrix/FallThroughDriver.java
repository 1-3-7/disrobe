public class FallThroughDriver {
    public static void main(String[] args) {
        byte[] data = {(byte) 0x91, 0x22, (byte) 0xf3, 0x04};
        StringBuilder out = new StringBuilder();
        for (int len = 0; len < 8; len++) {
            out.append(FallThroughProbe.tail(data, len)).append(',');
        }
        for (int n = -1; n < 11; n++) {
            out.append(FallThroughProbe.letters(n)).append(',');
        }
        System.out.println(out);
    }
}
