package com.sentinelpr.benchmark.realistic.sec005_01;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class OrderJdbcRepository {

    private final Connection connection;

    public OrderJdbcRepository(Connection connection) {
        this.connection = connection;
    }

    public List<String> searchByCustomer(String customerId) {
        List<String> results = new ArrayList<>();
        try {
            Statement statement = connection.createStatement();
            String sql = "SELECT order_id FROM orders WHERE customer_id = '" + customerId + "'";
            ResultSet rs = statement.executeQuery(sql);
            while (rs.next()) {
                results.add(rs.getString("order_id"));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database error", e);
        }
        return results;
    }
}
