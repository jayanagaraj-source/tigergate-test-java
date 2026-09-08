public class Vulnerable { public static String unsafeQuery(String input) { return "SELECT * FROM users WHERE name = '" + input + "'"; } }
