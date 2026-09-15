import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Web-tier fixtures: XSS (CWE-79), open redirect (CWE-601), HTTP response
 * splitting (CWE-113), log injection (CWE-117), insecure cookies (CWE-614/1004),
 * sensitive data in logs (CWE-532), trust-boundary (CWE-501).
 */
public class WebServlet extends HttpServlet {

  private static final Logger LOG = Logger.getLogger("web");

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String name = req.getParameter("name");
    String next = req.getParameter("next");
    String pw = req.getParameter("password");

    // Reflected XSS: parameter written unencoded into HTML.
    PrintWriter out = resp.getWriter();
    out.println("<h1>Hello " + name + "</h1>"); // FINDING: SAST-090 CWE-79 reflected-xss-printwriter

    // XSS via attribute context.
    out.write("<a href=\"" + next + "\">continue</a>"); // FINDING: SAST-091 CWE-79 reflected-xss-attribute

    // Open redirect.
    resp.sendRedirect(next); // FINDING: SAST-092 CWE-601 open-redirect

    // Header injection / response splitting.
    resp.setHeader("X-Original-Name", name); // FINDING: SAST-093 CWE-113 http-header-injection
    resp.addHeader("Location", "/home?u=" + name); // FINDING: SAST-094 CWE-113 http-response-splitting

    // Log injection (unsanitised CR/LF) and password in logs.
    LOG.info("login attempt for " + name); // FINDING: SAST-095 CWE-117 log-injection
    LOG.info("password was " + pw); // FINDING: SAST-096 CWE-532 sensitive-data-in-log

    // Cookie without Secure / HttpOnly and with the raw parameter as value.
    Cookie c = new Cookie("session", name);
    c.setSecure(false); // FINDING: SAST-097 CWE-614 cookie-not-secure
    c.setHttpOnly(false); // FINDING: SAST-098 CWE-1004 cookie-not-httponly
    c.setMaxAge(60 * 60 * 24 * 365 * 10); // FINDING: SAST-099 CWE-539 cookie-excessive-lifetime
    resp.addCookie(c);

    // Untrusted data placed straight into the session (trust boundary).
    req.getSession().setAttribute("role", req.getParameter("role")); // FINDING: SAST-100 CWE-501 trust-boundary-violation

    // Stack trace to the client.
    try {
      Integer.parseInt(req.getParameter("n"));
    } catch (NumberFormatException e) {
      e.printStackTrace(out); // FINDING: SAST-101 CWE-209 stacktrace-to-client
    }
  }

  /** Negative control: encoded output. Must NOT be reported. */
  protected void safeGreeting(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String name = req.getParameter("name");
    String enc = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    resp.getWriter().println("<h1>Hello " + enc + "</h1>"); // SAFE: CTRL-008 html-encoded-output
  }
}
