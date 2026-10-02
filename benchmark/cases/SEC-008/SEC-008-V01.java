package com.sentinelpr.benchmark.cases.sec008;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Sec008HardcodedSecretVulnerable {

    public Connection acquireConnection() throws SQLException {
        // INTENTIONAL VULNERABILITY: Hardcoded database credentials
        return DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/production_db",
            "root",
            "SuperSecretDbPassword123!"
        );
    }
}
