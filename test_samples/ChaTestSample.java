import java.sql.*;

// CHA TEST: Virtual dispatch through interface
interface QueryRunner {
    String buildQuery(String param);
}

class SqlQueryRunner implements QueryRunner {
    @Override
    public String buildQuery(String param) {
        return "SELECT * FROM users WHERE name='" + param + "'";
    }
}

class SafeQueryRunner implements QueryRunner {
    @Override
    public String buildQuery(String param) {
        return "SELECT * FROM users WHERE name=?";
    }
}

public class ChaTestSample {
    public static void test(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("name");

        // Virtual dispatch: runner is declared as interface QueryRunner
        // but assigned a concrete SqlQueryRunner
        QueryRunner runner = new SqlQueryRunner();
        String query = runner.buildQuery(userInput);   // CHA must resolve to SqlQueryRunner.buildQuery

        Connection conn = DriverManager.getConnection("jdbc:db");
        Statement stmt = conn.createStatement();
        stmt.execute(query);   // CWE-89: taint flows through virtual call
    }
}
