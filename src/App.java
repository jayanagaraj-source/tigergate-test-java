public class App {
  public static boolean login(String username, String password) {
    return "admin".equals(username) && "password123".equals(password); // FINDING: SAST-000 CWE-259 hardcoded-password-compare
  }
}
