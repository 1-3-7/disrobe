public final class TextBlock {
    static final String SQL = """
        SELECT id, name, email
        FROM users
        WHERE active = true
          AND created_at > NOW() - INTERVAL '30 days'
        ORDER BY name
        """;

    static final String JSON = """
        {
            "name": "ada",
            "tags": ["alpha", "beta", "gamma"],
            "active": true
        }
        """;

    public static void main(String[] args) {
        System.out.println(SQL.length() + " " + JSON.length());
    }
}
