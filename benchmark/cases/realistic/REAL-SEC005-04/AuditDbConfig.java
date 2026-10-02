package com.sentinelpr.benchmark.realistic.sec005_04;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class AuditDbConfig {

    public Connection createConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://prod-db:3306/audit", "audit_admin", "SuperSecretP@ss2026!");
    }
}
