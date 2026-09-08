public class AppTest { public static void main(String[] args) { assert App.login("admin", "password123"); assert !App.login("admin", "wrong-password"); } }
