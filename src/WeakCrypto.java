import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** CWE-327/328/330/338/321 weak cryptography fixtures. */
public class WeakCrypto {

  /** Hard-coded symmetric key (CWE-321). */
  private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // FINDING: SAST-050 CWE-321 hardcoded-crypto-key

  /** Static IV reused for every message (CWE-329). */
  private static final byte[] IV = new byte[16]; // FINDING: SAST-051 CWE-329 static-iv

  /** MD5 for password hashing. */
  public static byte[] hashPasswordMd5(String pw) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("MD5").digest(pw.getBytes(StandardCharsets.UTF_8)); // FINDING: SAST-052 CWE-328 weak-hash-md5
  }

  /** SHA-1 for integrity. */
  public static byte[] sha1(byte[] data) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("SHA-1").digest(data); // FINDING: SAST-053 CWE-328 weak-hash-sha1
  }

  /** DES, 56-bit effective key. */
  public static byte[] des(byte[] data) throws Exception {
    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding"); // FINDING: SAST-054 CWE-327 weak-cipher-des
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, 0, 8, "DES"));
    return c.doFinal(data);
  }

  /** AES in ECB mode leaks plaintext structure. */
  public static byte[] aesEcb(byte[] data) throws Exception {
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); // FINDING: SAST-055 CWE-327 aes-ecb-mode
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
    return c.doFinal(data);
  }

  /** AES/CBC but with the static IV above. */
  public static byte[] aesCbcStaticIv(byte[] data) throws Exception {
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV)); // FINDING: SAST-056 CWE-329 static-iv-use
    return c.doFinal(data);
  }

  /** RC4 stream cipher. */
  public static Cipher rc4() throws Exception {
    return Cipher.getInstance("ARCFOUR"); // FINDING: SAST-057 CWE-327 weak-cipher-rc4
  }

  /** 512-bit RSA key. */
  public static KeyPairGenerator weakRsa() throws NoSuchAlgorithmException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(512); // FINDING: SAST-058 CWE-326 rsa-key-too-short
    return kpg;
  }

  /** java.util.Random for a security token. */
  public static String sessionToken() {
    Random r = new Random(); // FINDING: SAST-059 CWE-338 insecure-random-token
    return Long.toHexString(r.nextLong());
  }

  /** Seeded SecureRandom with a constant makes it deterministic. */
  public static SecureRandom seededSecureRandom() {
    SecureRandom sr = new SecureRandom();
    sr.setSeed(42L); // FINDING: SAST-060 CWE-336 secure-random-constant-seed
    return sr;
  }

  /** Negative control: SHA-256 + AES-GCM with random nonce. Must NOT be reported. */
  public static byte[] safeAesGcm(byte[] data, byte[] key) throws Exception {
    byte[] nonce = new byte[12];
    new SecureRandom().nextBytes(nonce);
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // SAFE: CTRL-006 aes-gcm-random-nonce
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new javax.crypto.spec.GCMParameterSpec(128, nonce));
    return c.doFinal(data);
  }
}
