package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005StringParamVulnerable {

    public ResultSet searchCustomers(Connection connection, String tenantCode) throws SQLException {
        Statement statement = connection.createStatement();
        String sql = "SELECT id, name, email FROM customers WHERE tenant_code = '" + tenantCode + "'";
        return statement.executeQuery(sql);
    }
}
