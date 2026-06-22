import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

public class SampleVuln {
    public void doGet(HttpServletRequest request, Connection conn) throws Exception {
        // Source: request.getParameter (CWE-89)
        String username = request.getParameter("username");
        
        // SQL injection vulnerability (CWE-89)
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }

    public void authenticate() {
        // Hardcoded credential (CWE-798)
        String adminToken = "super_secret_java_token_987654321";
        System.out.println("Authenticated: " + adminToken);
    }
}
