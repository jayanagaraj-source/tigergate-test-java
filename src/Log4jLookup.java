import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Reachability fixtures: code that actually invokes the vulnerable API of
 * a vulnerable dependency. A scanner that correlates SCA with call-graph
 * reachability should rank these SCA findings higher than the unused ones.
 */
public class Log4jLookup {

  private static final Logger LOG = LogManager.getLogger(Log4jLookup.class);

  /** CVE-2021-44228: untrusted string reaches log4j 2.14.1 message lookup. */
  public static void logUser(String userAgent) {
    LOG.info("client user-agent: " + userAgent); // FINDING: SAST-120 CWE-917 log4shell-reachable-sink
  }

  /** CVE-2022-42889: commons-text 1.9 interpolator on untrusted input. */
  public static String interpolate(String template) {
    return StringSubstitutor.createInterpolator().replace(template); // FINDING: SAST-121 CWE-917 text4shell-reachable-sink
  }
}
