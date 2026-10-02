package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005ExecuteRawSqlVulnerable {

    public boolean purgeAuditRecords(Connection connection, String cutoffDate) throws SQLException {
        Statement stmt = connection.createStatement();
        String ddl = "DELETE FROM audit_events WHERE created_at < '" + cutoffDate + "'";
        return stmt.execute(ddl);
    }
}
