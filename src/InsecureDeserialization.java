import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import org.yaml.snakeyaml.Yaml;

/**
 * CWE-502 deserialization of untrusted data. These sinks pair with the
 * vulnerable library versions in pom.xml (commons-collections gadget chain,
 * XStream, Jackson polymorphic typing, SnakeYAML constructors) so a scanner
 * can correlate SCA + SAST into an exploitable finding.
 */
public class InsecureDeserialization {

  /** Native Java deserialization of a network stream. */
  public static Object fromStream(InputStream untrusted) throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(untrusted);
    return ois.readObject(); // FINDING: SAST-040 CWE-502 java-objectinputstream
  }

  /** XStream with no security framework / allow-list configured. */
  public static Object fromXml(String untrusted) {
    XStream xs = new XStream();
    return xs.fromXML(untrusted); // FINDING: SAST-041 CWE-502 xstream-fromxml
  }

  /** Jackson with default typing enabled: arbitrary gadget instantiation. */
  public static Object fromJson(String untrusted) throws IOException {
    ObjectMapper om = new ObjectMapper();
    om.enableDefaultTyping(); // FINDING: SAST-042 CWE-502 jackson-enable-default-typing
    return om.readValue(untrusted, Object.class);
  }

  /** SnakeYAML default constructor resolves arbitrary !!classes. */
  public static Object fromYaml(String untrusted) {
    Yaml yaml = new Yaml();
    return yaml.load(untrusted); // FINDING: SAST-043 CWE-502 snakeyaml-load
  }

  /** Negative control: Jackson bound to a concrete DTO with no default typing. */
  public static Config safeFromJson(String json) throws IOException {
    return new ObjectMapper().readValue(json, Config.class); // SAFE: CTRL-005 jackson-typed-binding
  }

  public static class Config {
    public String name;
    public int port;
  }
}
