public class Hello {
    private static final String GREETING = "hello, jvm";

    private int counter;
    private String name;

    public Hello(String name) {
        this.name = name;
        this.counter = 0;
    }

    public int bumpCounter() {
        counter = counter + 1;
        return counter;
    }

    public String describe() {
        if (counter > 0) {
            return GREETING + " from " + name + " (#" + counter + ")";
        }
        return GREETING + " from " + name;
    }

    public static void main(String[] args) {
        Hello hello = new Hello(args.length > 0 ? args[0] : "world");
        hello.bumpCounter();
        System.out.println(hello.describe());
    }
}
