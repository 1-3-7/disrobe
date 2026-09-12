public final class SwitchPattern {
    sealed interface Event permits Login, Logout, Error {}
    record Login(String user) implements Event {}
    record Logout(String user, String reason) implements Event {}
    record Error(int code, String message) implements Event {}

    static String describe(Event event) {
        return switch (event) {
            case Login(String u) -> "login:" + u;
            case Logout(String u, String r) when r != null -> "logout:" + u + ":" + r;
            case Logout(String u, String r) -> "logout:" + u;
            case Error(int c, String m) -> "error:" + c + ":" + m;
        };
    }

    public static void main(String[] args) {
        System.out.println(describe(new Login("ada")));
        System.out.println(describe(new Logout("ada", "expired")));
        System.out.println(describe(new Error(500, "boom")));
    }
}
