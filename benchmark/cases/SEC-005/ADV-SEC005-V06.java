package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005MultilineSqlVulnerable {

    public ResultSet queryOrderHistory(Connection conn, String customerId, String status) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT order_id, total_amount, created_at "
                + "FROM orders "
                + "WHERE customer_id = '" + customerId + "' "
                + "AND status = '" + status + "' "
                + "ORDER BY created_at DESC";
        return stmt.executeQuery(query);
    }
}
