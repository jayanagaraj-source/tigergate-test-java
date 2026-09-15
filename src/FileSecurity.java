import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * File-system and data-handling fixtures: insecure temp files (CWE-377),
 * bad permissions (CWE-732), TOCTOU (CWE-367), cleartext storage (CWE-312),
 * cleartext transmission (CWE-319), hard-coded DB credentials (CWE-798),
 * timing-unsafe comparison (CWE-208), debug flag (CWE-489).
 */
public class FileSecurity {

  /** Left on in production builds. */
  public static final boolean DEBUG = true; // FINDING: SAST-130 CWE-489 debug-flag-enabled

  /** Predictable name in a shared directory, world-readable. */
  public static File insecureTemp() throws IOException {
    File f = new File("/tmp/app-cache.tmp"); // FINDING: SAST-131 CWE-377 predictable-temp-file
    f.createNewFile();
    f.setReadable(true, false); // FINDING: SAST-132 CWE-732 world-readable-file
    return f;
  }

  /** chmod 777. */
  public static void openPerms(Path p) throws IOException {
    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwxrwx")); // FINDING: SAST-133 CWE-732 chmod-777
  }

  /** Check-then-act race. */
  public static void toctou(File f) throws IOException {
    if (f.exists() && f.canWrite()) { // FINDING: SAST-134 CWE-367 toctou-check
      try (FileWriter w = new FileWriter(f)) {
        w.write("data");
      }
    }
  }

  /** Password written to disk in the clear. */
  public static void storePassword(String pw) throws IOException {
    try (FileWriter w = new FileWriter("/var/app/creds.txt")) {
      w.write("password=" + pw); // FINDING: SAST-135 CWE-312 cleartext-password-storage
    }
  }

  /** Credentials sent over plain HTTP in the query string. */
  public static void sendCreds(String user, String pw) throws IOException {
    new URL("http://auth.example.com/login?u=" + user + "&p=" + pw).openStream(); // FINDING: SAST-136 CWE-319 cleartext-credential-transmission
  }

  /** Hard-coded DB credentials in the connection call. */
  public static Connection db() throws SQLException {
    return DriverManager.getConnection("jdbc:postgresql://db.internal:5432/app", "app_user", "Sup3rS3cret!"); // FINDING: SAST-137 CWE-798 hardcoded-db-password
  }

  /** Non-constant-time secret comparison. */
  public static boolean checkToken(String supplied, String expected) {
    return supplied.equals(expected); // FINDING: SAST-138 CWE-208 timing-unsafe-compare
  }

  /** Negative control: constant-time comparison. Must NOT be reported. */
  public static boolean safeCheckToken(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b); // SAFE: CTRL-010 constant-time-compare
  }
}
