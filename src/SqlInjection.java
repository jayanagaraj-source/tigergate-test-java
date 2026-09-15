import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * CWE-89 SQL injection fixtures. Each method builds a query with untrusted
 * input reaching a JDBC sink. {@link #safeLookup} is a negative control.
 */
public class SqlInjection {

  private static Connection connect() throws SQLException {
    return DriverManager.getConnection("jdbc:h2:mem:fixture", "sa", "");
  }

  /** Classic string concatenation into Statement.executeQuery. */
  public static ResultSet findUser(String username) throws SQLException {
    Statement st = connect().createStatement();
    return st.executeQuery("SELECT * FROM users WHERE name = '" + username + "'"); // FINDING: SAST-001 CWE-89 sqli-statement-concat
  }

  /** Concatenation via StringBuilder, sink is executeUpdate. */
  public static int deleteUser(String id) throws SQLException {
    StringBuilder sb = new StringBuilder("DELETE FROM users WHERE id = ");
    sb.append(id);
    return connect().createStatement().executeUpdate(sb.toString()); // FINDING: SAST-002 CWE-89 sqli-stringbuilder
  }

  /** String.format is not parameterisation. */
  public static ResultSet byEmail(String email) throws SQLException {
    String q = String.format("SELECT * FROM users WHERE email = '%s'", email);
    return connect().createStatement().executeQuery(q); // FINDING: SAST-003 CWE-89 sqli-string-format
  }

  /** PreparedStatement misuse: input concatenated before prepare. */
  public static ResultSet orderBy(String column) throws SQLException {
    PreparedStatement ps = connect().prepareStatement("SELECT * FROM users ORDER BY " + column); // FINDING: SAST-004 CWE-89 sqli-preparedstatement-concat
    return ps.executeQuery();
  }

  /** Stored-procedure call with concatenated argument. */
  public static boolean callProc(String arg) throws SQLException {
    return connect().prepareCall("{call audit('" + arg + "')}").execute(); // FINDING: SAST-005 CWE-89 sqli-callablestatement
  }

  /** Negative control: correctly parameterised. Must NOT be reported. */
  public static ResultSet safeLookup(String username) throws SQLException {
    PreparedStatement ps = connect().prepareStatement("SELECT * FROM users WHERE name = ?"); // SAFE: CTRL-001 parameterised-query
    ps.setString(1, username);
    return ps.executeQuery();
  }
}
