package com.sentinelpr.benchmark.realistic.sec005_04;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class AuditLogRepository {

    private final Connection connection;

    public AuditLogRepository(Connection connection) {
        this.connection = connection;
    }

    public int purgeLogsByStatus(String status) {
        try {
            Statement statement = connection.createStatement();
            String sql = "DELETE FROM audit_logs WHERE status = '" + status + "'";
            return statement.executeUpdate(sql);
        } catch (SQLException e) {
            throw new RuntimeException("Purge failed", e);
        }
    }
}
