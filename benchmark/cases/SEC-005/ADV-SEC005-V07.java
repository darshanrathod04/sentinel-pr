package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005InterveningStatementsVulnerable {

    public ResultSet searchProducts(Connection connection, String category) throws SQLException {
        Statement statement = connection.createStatement();
        long startTime = System.currentTimeMillis();
        boolean traceEnabled = (category != null && category.startsWith("EXP-"));
        if (traceEnabled) {
            System.out.println("Processing product search for category trace: " + category);
        }
        String sql = "SELECT id, title, price FROM products WHERE category = '" + category + "'";
        ResultSet rs = statement.executeQuery(sql);
        long elapsed = System.currentTimeMillis() - startTime;
        return rs;
    }
}
