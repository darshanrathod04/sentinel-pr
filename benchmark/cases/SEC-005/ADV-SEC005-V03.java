package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005NumericParamVulnerable {

    public ResultSet getAccountBalance(Connection conn, long accountId) throws SQLException {
        Statement statement = conn.createStatement();
        String query = "SELECT balance FROM accounts WHERE account_id = " + accountId;
        return statement.executeQuery(query);
    }
}
