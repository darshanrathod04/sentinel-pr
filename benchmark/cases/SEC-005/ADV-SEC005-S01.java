package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AdvSec005PreparedStatementSafe {

    public ResultSet findUserProfile(Connection connection, String username) throws SQLException {
        String sql = "SELECT id, email, created_at FROM profiles WHERE username = ?";
        PreparedStatement ps = connection.prepareStatement(sql);
        ps.setString(1, username);
        return ps.executeQuery();
    }
}
