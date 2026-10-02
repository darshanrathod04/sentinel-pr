package com.sentinelpr.benchmark.realistic.sec005_03;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class InventoryRepository {

    private final Connection connection;

    public InventoryRepository(Connection connection) {
        this.connection = connection;
    }

    public int findItemBySku(String sku) {
        try {
            Statement statement = connection.createStatement();
            String sql = "SELECT stock_count FROM inventory_items WHERE sku = '" + sku + "'";
            ResultSet rs = statement.executeQuery(sql);
            if (rs.next()) {
                return rs.getInt("stock_count");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database query error", e);
        }
        return 0;
    }
}
