public class JsrShapesDriver {
    public static void main(String[] args) {
        StringBuffer out = new StringBuffer();
        for (int n = -2; n < 9; n++) {
            int s;
            try {
                s = JsrShapesProbe.switchy(n);
            } catch (IllegalArgumentException e) {
                s = -99;
            }
            out.append(s).append(' ').append(JsrShapesProbe.catching(n)).append(' ');
            out.append(JsrShapesProbe.innerFinally(n)).append(' ').append(JsrShapesProbe.log).append(';');
        }
        System.out.println(out);
    }
}
