import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** CWE-22 path traversal and CWE-22 Zip Slip fixtures. */
public class PathTraversal {

  private static final String BASE = "/var/app/uploads/";

  /** ../ in the filename escapes BASE. */
  public static InputStream read(String filename) throws IOException {
    return new FileInputStream(new File(BASE + filename)); // FINDING: SAST-020 CWE-22 path-traversal-read
  }

  /** Same via java.nio. */
  public static byte[] readNio(String filename) throws IOException {
    Path p = Paths.get(BASE, filename);
    return Files.readAllBytes(p); // FINDING: SAST-021 CWE-22 path-traversal-nio-read
  }

  /** Arbitrary file write. */
  public static void write(String filename, byte[] data) throws IOException {
    try (FileOutputStream out = new FileOutputStream(BASE + filename)) { // FINDING: SAST-022 CWE-22 path-traversal-write
      out.write(data);
    }
  }

  /** Arbitrary file delete. */
  public static boolean delete(String filename) {
    return new File(BASE + filename).delete(); // FINDING: SAST-023 CWE-22 path-traversal-delete
  }

  /** Zip Slip: entry name used verbatim as destination path. */
  public static void unzip(InputStream zip, File dest) throws IOException {
    try (ZipInputStream zis = new ZipInputStream(zip)) {
      ZipEntry e;
      while ((e = zis.getNextEntry()) != null) {
        File out = new File(dest, e.getName()); // FINDING: SAST-024 CWE-22 zip-slip
        try (FileOutputStream fos = new FileOutputStream(out)) {
          zis.transferTo(fos);
        }
      }
    }
  }

  /** Negative control: canonical path is verified to stay inside BASE. */
  public static InputStream safeRead(String filename) throws IOException {
    File f = new File(BASE, filename).getCanonicalFile();
    if (!f.getPath().startsWith(new File(BASE).getCanonicalPath() + File.separator)) {
      throw new SecurityException("traversal");
    }
    return new FileInputStream(f); // SAFE: CTRL-003 canonical-path-checked
  }
}
