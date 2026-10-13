import freemarker.template.Configuration;
import freemarker.template.Template;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;
import org.apache.commons.text.StringSubstitutor;

/**
 * Server-side template and expression injection (CWE-1336, CWE-917, CWE-94).
 *
 * Every sink here uses a library that is actually resolved in this project's
 * dependency tree, so these are REACHABILITY fixtures: a scanner that
 * correlates SCA with SAST should rank the corresponding dependency findings
 * higher because the vulnerable API is demonstrably called.
 *
 *   freemarker 2.3.31  -- transitive via struts2-core
 *   ognl 3.1.29        -- transitive via struts2-core (the Struts RCE vector)
 *   commons-text 1.9   -- direct (CVE-2022-42889, Text4Shell)
 */
public class TemplateInjection {

  private static final Configuration CFG = new Configuration(Configuration.VERSION_2_3_31);

  /** The whole template body is attacker-controlled: full SSTI to RCE. */
  public static String renderUserTemplate(String userTemplate) throws Exception {
    Template t = new Template("user", new StringReader(userTemplate), CFG); // FINDING: SAST-170 CWE-1336 freemarker-template-from-user-input
    StringWriter out = new StringWriter();
    t.process(new HashMap<String, Object>(), out);
    return out.toString();
  }

  /** Untrusted value concatenated into a trusted template still yields SSTI. */
  public static String renderGreeting(String name) throws Exception {
    String src = "<h1>Hello ${" + name + "}</h1>"; // FINDING: SAST-171 CWE-1336 freemarker-concatenated-template
    Template t = new Template("greet", new StringReader(src), CFG);
    StringWriter out = new StringWriter();
    t.process(new HashMap<String, Object>(), out);
    return out.toString();
  }

  /** Exposing the object wrapper lets a template reach arbitrary classes. */
  public static String renderWithModel(String userTemplate, Object bean) throws Exception {
    Map<String, Object> model = new HashMap<>();
    model.put("bean", bean);
    model.put("statics", CFG.getObjectWrapper()); // FINDING: SAST-172 CWE-1336 freemarker-object-wrapper-exposed
    Template t = new Template("m", new StringReader(userTemplate), CFG);
    StringWriter out = new StringWriter();
    t.process(model, out);
    return out.toString();
  }

  /** OGNL expression from user input: the classic Struts2 RCE sink. */
  public static Object evaluate(String expression, Object root) throws OgnlException {
    return Ognl.getValue(expression, root); // FINDING: SAST-173 CWE-917 ognl-expression-from-user-input
  }

  /** Same via an explicit context, which is how Struts actions reach it. */
  public static Object evaluateInContext(String expression, Object root) throws OgnlException {
    OgnlContext ctx = new OgnlContext(null, null, new ognl.DefaultMemberAccess(true)); // FINDING: SAST-174 CWE-917 ognl-unrestricted-member-access
    return Ognl.getValue(Ognl.parseExpression(expression), ctx, root); // FINDING: SAST-175 CWE-917 ognl-parsed-expression-user-input
  }

  /** Untrusted field name compiled into an OGNL setter. */
  public static void bind(Object target, String field, Object value) throws OgnlException {
    Ognl.setValue(field, target, value); // FINDING: SAST-176 CWE-915 ognl-mass-assignment
  }

  /**
   * commons-text 1.9 interpolator: ${script:...}, ${dns:...} and ${url:...}
   * lookups are enabled by default (CVE-2022-42889, Text4Shell).
   */
  public static String interpolate(String userInput) {
    return StringSubstitutor.createInterpolator().replace(userInput); // FINDING: SAST-177 CWE-917 text4shell-interpolator-user-input
  }

  // --------------------------------------------------------------------
  // Negative controls. Correctly written; must NOT be reported.
  // --------------------------------------------------------------------

  /** Template is a fixed resource; only the DATA is user-supplied. */
  public static String safeRender(String name) throws IOException, Exception {
    Template t = new Template("safe", new StringReader("<h1>Hello ${name?html}</h1>"), CFG); // SAFE: CTRL-037 freemarker-fixed-template-data-only
    Map<String, Object> model = new HashMap<>();
    model.put("name", name);
    StringWriter out = new StringWriter();
    t.process(model, out);
    return out.toString();
  }

  /** Field name checked against an allow-list before binding. */
  public static void safeBind(Object target, String field, Object value) throws OgnlException {
    switch (field) { // SAFE: CTRL-038 ognl-allowlisted-field
      case "name":
      case "email":
        Ognl.setValue(field, target, value);
        return;
      default:
        throw new IllegalArgumentException(field);
    }
  }

  /** Substitutor limited to a fixed map: no script/url/dns lookups. */
  public static String safeInterpolate(String template, Map<String, String> values) {
    return new StringSubstitutor(values).replace(template); // SAFE: CTRL-039 commons-text-fixed-map-substitutor
  }
}
