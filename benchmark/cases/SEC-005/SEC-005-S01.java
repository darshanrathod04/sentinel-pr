package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Sec005SqlInjectionSafe {

    public ResultSet findUserByUsername(Connection conn, String username) throws SQLException {
        // SAFE: Parameterized query with PreparedStatement and bound parameter
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, username);
        return stmt.executeQuery();
    }
}
