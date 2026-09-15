import java.io.InputStream;
import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

/** CWE-611 XML External Entity fixtures across the JDK XML APIs. */
public class Xxe {

  /** DocumentBuilderFactory with default (entity-resolving) settings. */
  public static Document parseDom(InputStream xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // FINDING: SAST-030 CWE-611 xxe-documentbuilderfactory
    return dbf.newDocumentBuilder().parse(xml);
  }

  /** SAXParserFactory with defaults. */
  public static void parseSax(InputStream xml) throws Exception {
    SAXParserFactory spf = SAXParserFactory.newInstance(); // FINDING: SAST-031 CWE-611 xxe-saxparserfactory
    spf.newSAXParser().parse(xml, new DefaultHandler());
  }

  /** StAX with external entities and DTD support left on. */
  public static XMLStreamReader parseStax(InputStream xml) throws Exception {
    XMLInputFactory xif = XMLInputFactory.newInstance(); // FINDING: SAST-032 CWE-611 xxe-xmlinputfactory
    return xif.createXMLStreamReader(xml);
  }

  /** TransformerFactory processing untrusted stylesheet/document. */
  public static void transform(String xml) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance(); // FINDING: SAST-033 CWE-611 xxe-transformerfactory
    tf.newTransformer().transform(new StreamSource(new StringReader(xml)), new javax.xml.transform.stream.StreamResult(System.out));
  }

  /** SchemaFactory with external access unrestricted. */
  public static void schema(String xsd) throws Exception {
    SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI); // FINDING: SAST-034 CWE-611 xxe-schemafactory
    sf.newSchema(new StreamSource(new StringReader(xsd)));
  }

  /** Negative control: DTDs disabled, external entities off. Must NOT be reported. */
  public static Document safeParseDom(String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // SAFE: CTRL-004 xxe-hardened-dbf
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    return dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
  }
}
