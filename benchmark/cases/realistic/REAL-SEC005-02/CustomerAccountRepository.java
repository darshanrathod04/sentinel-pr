package com.sentinelpr.benchmark.realistic.sec005_02;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class CustomerAccountRepository {

    private final Connection connection;

    public CustomerAccountRepository(Connection connection) {
        this.connection = connection;
    }

    public String queryAccount(String accountId) {
        String sql = "SELECT account_name FROM accounts WHERE account_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("account_name");
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database error", e);
        }
        return null;
    }
}
