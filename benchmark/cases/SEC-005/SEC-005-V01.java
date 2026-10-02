package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Sec005SqlInjectionVulnerable {

    public ResultSet findUserByUsername(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        // INTENTIONAL VULNERABILITY: Raw dynamic string concatenation passed to executeQuery
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(sql);
    }
}
