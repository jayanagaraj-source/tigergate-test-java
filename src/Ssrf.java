import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** CWE-918 server-side request forgery fixtures. */
public class Ssrf {

  /** User-controlled URL fetched by the server. */
  public static InputStream fetch(String url) throws IOException {
    return new URL(url).openStream(); // FINDING: SAST-080 CWE-918 ssrf-url-openstream
  }

  /** HttpURLConnection to a caller-supplied host. */
  public static int status(String url) throws IOException {
    HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection(); // FINDING: SAST-081 CWE-918 ssrf-httpurlconnection
    return c.getResponseCode();
  }

  /** java.net.http client with a user-supplied URI. */
  public static String get(String uri) throws Exception {
    HttpRequest req = HttpRequest.newBuilder(URI.create(uri)).build(); // FINDING: SAST-082 CWE-918 ssrf-httpclient
    return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString()).body();
  }

  /** Partial control: only the path is untrusted, but a `@` or `../` still redirects. */
  public static InputStream fetchPath(String path) throws IOException {
    return new URL("http://internal-api/" + path).openStream(); // FINDING: SAST-083 CWE-918 ssrf-partial-url-control
  }

  /** Negative control: host allow-list. Must NOT be reported. */
  public static InputStream safeFetch(String host, String path) throws IOException {
    if (!host.equals("api.example.com") && !host.equals("cdn.example.com")) throw new SecurityException("host");
    return new URL("https", host, "/" + path.replace("..", "")).openStream(); // SAFE: CTRL-007 ssrf-host-allowlist
  }
}
