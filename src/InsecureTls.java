import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** CWE-295 improper certificate validation fixtures. */
public class InsecureTls {

  /** TrustManager that accepts every certificate chain. */
  public static final TrustManager[] TRUST_ALL = new TrustManager[] {
    new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] c, String a) {} // FINDING: SAST-070 CWE-295 trust-all-client
      public void checkServerTrusted(X509Certificate[] c, String a) {} // FINDING: SAST-071 CWE-295 trust-all-server
      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
  };

  /** HostnameVerifier that accepts any host. */
  public static final HostnameVerifier ALLOW_ALL = new HostnameVerifier() {
    public boolean verify(String host, SSLSession s) { return true; } // FINDING: SAST-072 CWE-295 hostname-verifier-allow-all
  };

  /** Installs both globally and pins an obsolete protocol. */
  public static void disableVerification() throws Exception {
    SSLContext ctx = SSLContext.getInstance("TLSv1"); // FINDING: SAST-073 CWE-326 obsolete-tls-version
    ctx.init(null, TRUST_ALL, new java.security.SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier(ALLOW_ALL); // FINDING: SAST-074 CWE-295 default-hostname-verifier-disabled
  }

  /** Legacy SSLv3. */
  public static SSLContext sslv3() throws Exception {
    return SSLContext.getInstance("SSLv3"); // FINDING: SAST-075 CWE-326 obsolete-sslv3
  }
}
