public class Vulnerable { public static String unsafeQuery(String input) { return "SELECT * FROM users WHERE name = '" + input + "'"; } } // FINDING: SAST-009 CWE-89 sqli-query-builder-no-sink
