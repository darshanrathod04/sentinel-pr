package com.sentinelpr.benchmark.cases.xfile.sql01;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class OrderDynamicRepository {

    private final Connection connection;

    public OrderDynamicRepository(Connection connection) {
        this.connection = connection;
    }

    public List<String> executeOrderQuery(String sqlPredicate) throws SQLException {
        List<String> orderIds = new ArrayList<>();
        Statement statement = connection.createStatement();
        String sql = "SELECT order_id FROM customer_orders WHERE " + sqlPredicate;
        ResultSet rs = statement.executeQuery(sql);
        while (rs.next()) {
            orderIds.add(rs.getString("order_id"));
        }
        return orderIds;
    }
}
