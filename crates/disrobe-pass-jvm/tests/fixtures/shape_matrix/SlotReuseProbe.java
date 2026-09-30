import java.util.ArrayList;
import java.util.List;

public class SlotReuseProbe {
    static String arraysThenList(int k) {
        StringBuilder out = new StringBuilder();
        for (int n : new int[] {k, k + 1, k + 2}) {
            out.append(n).append(' ');
        }
        List<Integer> items = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            items.add(i * i);
        }
        return out.toString().trim() + items;
    }

    static int textThenBuilder(int k) {
        int total = 0;
        {
            String text = "v" + k;
            total += text.length();
        }
        {
            StringBuilder builder = new StringBuilder();
            builder.append(k).append(k);
            total += builder.length();
        }
        return total;
    }

    static String namesThenCounts(int k) {
        StringBuilder out = new StringBuilder();
        {
            String[] names = {"a", "b", "c"};
            out.append(names[k % 3]);
        }
        {
            int[] counts = {k, k * 2};
            out.append(counts[1]);
        }
        return out.toString();
    }

    static String charSteps(int k) {
        char c = 'a';
        c += 2;
        char d = 'x';
        d += k;
        StringBuilder out = new StringBuilder();
        out.append(c).append(d);
        return c + ":" + d + ":" + (int) c + out;
    }
}
