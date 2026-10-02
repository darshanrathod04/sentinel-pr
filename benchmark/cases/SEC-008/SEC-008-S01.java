package com.sentinelpr.benchmark.cases.sec008;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Sec008HardcodedSecretSafe {

    public Connection acquireConnection() throws SQLException {
        // SAFE: Externalized environment credentials
        return DriverManager.getConnection(
            System.getenv("DB_URL"),
            System.getenv("DB_USER"),
            System.getenv("DB_PASSWORD")
        );
    }
}
