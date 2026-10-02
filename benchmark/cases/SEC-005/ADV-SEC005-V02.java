package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005MultiParamVulnerable {

    public ResultSet findUser(Connection connection, String username, String role) throws SQLException {
        Statement stmt = connection.createStatement();
        String query = "SELECT id, active FROM users WHERE username = '" + username + "' AND role = '" + role + "'";
        return stmt.executeQuery(query);
    }
}
