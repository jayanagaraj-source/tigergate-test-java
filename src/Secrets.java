/**
 * Hard-coded credential fixtures (CWE-798) in source. Every value is fake and
 * shaped only to match common secret-scanner regexes / entropy thresholds.
 */
public class Secrets {
  static final String API_KEY = "test-fixture-not-a-real-secret"; // FINDING: SEC-001 CWE-798 generic-api-key
  static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // FINDING: SEC-002 CWE-798 aws-access-key-id
  static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // FINDING: SEC-003 CWE-798 aws-secret-access-key
  static final String GITHUB_TOKEN = "ghp_F1xTuR3n0tR3aLt0k3nAbCdEfGhIjKlMnOpQr"; // FINDING: SEC-004 CWE-798 github-pat
  static final String SLACK_BOT_TOKEN = "xoxb-000000000000-000000000000-F1xTuR3F4k3T0k3nAbCdEfGh"; // FINDING: SEC-005 CWE-798 slack-bot-token
  static final String STRIPE_KEY = "sk_test_F1xTuR3F4k3K3yAbCdEfGhIjKl"; // FINDING: SEC-006 CWE-798 stripe-secret-key
  static final String GOOGLE_API_KEY = "AIzaSyF1xTuR3F4k3K3y-AbCdEfGhIjKlMnOpQ"; // FINDING: SEC-007 CWE-798 google-api-key
  static final String JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlIiwiaWF0IjoxNTE2MjM5MDIyfQ.F1xTuR3F4k3S1gnAtUr3AbCdEfGhIjKlMnOpQrStUvW"; // FINDING: SEC-008 CWE-798 jwt-token
  static final String DB_URL = "jdbc:mysql://app_user:Sup3rS3cret!@db.internal:3306/app"; // FINDING: SEC-009 CWE-798 credentials-in-connection-url
  static final String BASIC_AUTH_URL = "https://admin:Passw0rd123@internal.example.com/api"; // FINDING: SEC-010 CWE-798 credentials-in-url
  static final String SENDGRID_KEY = "SG.F1xTuR3F4k3K3yAbCdEfGh.IjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW"; // FINDING: SEC-011 CWE-798 sendgrid-api-key
  static final String TWILIO_SID = "ACf1x7ur3f4k3s1d0000000000000000"; // FINDING: SEC-012 CWE-798 twilio-account-sid
  static final String PRIVATE_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKfixture-not-a-real-key\n-----END RSA PRIVATE KEY-----"; // FINDING: SEC-013 CWE-798 private-key-in-source
  static final char[] PASSWORD = "Adm1n!Passw0rd".toCharArray(); // FINDING: SEC-014 CWE-259 hardcoded-password-char-array
}
