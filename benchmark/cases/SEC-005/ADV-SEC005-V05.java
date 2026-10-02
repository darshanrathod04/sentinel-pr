package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005DirectExecuteQueryVulnerable {

    public ResultSet fetchInventory(Connection conn, String warehouseCode) throws SQLException {
        Statement statement = conn.createStatement();
        return statement.executeQuery("SELECT sku, stock FROM inventory WHERE warehouse = '" + warehouseCode + "'");
    }
}
