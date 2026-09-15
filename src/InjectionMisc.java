import java.util.Hashtable;
import java.util.regex.Pattern;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

/**
 * Less common injection classes: LDAP (CWE-90), XPath (CWE-643),
 * expression/script injection (CWE-94/95), unsafe reflection (CWE-470),
 * JNDI lookup (CWE-74), regex DoS (CWE-1333).
 */
public class InjectionMisc {

  /** LDAP filter built from user input. */
  public static NamingEnumeration<SearchResult> ldap(String user) throws NamingException {
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, "ldap://ldap.internal:389");
    DirContext ctx = new InitialDirContext(env);
    return ctx.search("ou=people,dc=example,dc=com", "(uid=" + user + ")", new SearchControls()); // FINDING: SAST-110 CWE-90 ldap-injection
  }

  /** XPath expression built from user input. */
  public static Object xpath(Document doc, String user) throws XPathExpressionException {
    XPath xp = XPathFactory.newInstance().newXPath();
    return xp.evaluate("//user[@name='" + user + "']/password", doc); // FINDING: SAST-111 CWE-643 xpath-injection
  }

  /** Script engine evaluating a caller-supplied string. */
  public static Object eval(String expr) throws ScriptException {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
    return engine.eval(expr); // FINDING: SAST-112 CWE-95 script-engine-eval
  }

  /** Class name from user input instantiated reflectively. */
  public static Object instantiate(String className) throws Exception {
    return Class.forName(className).getDeclaredConstructor().newInstance(); // FINDING: SAST-113 CWE-470 unsafe-reflection
  }

  /** JNDI lookup with attacker-controlled name (ldap://, rmi://). */
  public static Object jndi(String name) throws NamingException {
    return new javax.naming.InitialContext().lookup(name); // FINDING: SAST-114 CWE-74 jndi-injection
  }

  /** User input compiled as a regex (ReDoS / arbitrary pattern). */
  public static boolean matches(String userPattern, String text) {
    return Pattern.compile(userPattern).matcher(text).matches(); // FINDING: SAST-115 CWE-1333 regex-from-user-input
  }

  /** Static catastrophic-backtracking pattern applied to user input. */
  private static final Pattern EVIL = Pattern.compile("^(a+)+$"); // FINDING: SAST-116 CWE-1333 catastrophic-backtracking-regex
  public static boolean redos(String text) {
    return EVIL.matcher(text).matches();
  }

  /** Negative control: reflection restricted to an allow-list. */
  public static Object safeInstantiate(String key) throws Exception {
    String cls = switch (key) {
      case "json" -> "com.fasterxml.jackson.databind.ObjectMapper";
      case "yaml" -> "org.yaml.snakeyaml.Yaml";
      default -> throw new IllegalArgumentException(key);
    };
    return Class.forName(cls).getDeclaredConstructor().newInstance(); // SAFE: CTRL-009 reflection-allowlist
  }
}
