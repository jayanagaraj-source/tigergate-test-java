import java.io.IOException;

/** CWE-78 OS command injection fixtures. */
public class CommandInjection {

  /** Untrusted input inside a shell command string. */
  public static Process ping(String host) throws IOException {
    return Runtime.getRuntime().exec("ping -c 1 " + host); // FINDING: SAST-010 CWE-78 cmdi-runtime-exec-concat
  }

  /** sh -c with interpolated argument allows metacharacter injection. */
  public static Process listDir(String dir) throws IOException {
    return new ProcessBuilder("sh", "-c", "ls -la " + dir).start(); // FINDING: SAST-011 CWE-78 cmdi-processbuilder-shell
  }

  /** Whole command from user input. */
  public static Process run(String cmd) throws IOException {
    String[] parts = cmd.split(" ");
    return Runtime.getRuntime().exec(parts); // FINDING: SAST-012 CWE-78 cmdi-user-controlled-command
  }

  /** Negative control: fixed argv, argument passed as a discrete element. */
  public static Process safePing(String host) throws IOException {
    if (!host.matches("[A-Za-z0-9.-]+")) throw new IllegalArgumentException("bad host");
    return new ProcessBuilder("ping", "-c", "1", host).start(); // SAFE: CTRL-002 argv-array-validated
  }
}
