package com.sentinelpr.benchmark.cases.sec005;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AdvSec005NestedExpressionVulnerable {

    public ResultSet loadDocuments(Connection conn, String tag, boolean archived) throws SQLException {
        Statement statement = conn.createStatement();
        String sql = "SELECT doc_id, title FROM documents WHERE tag = '" 
                + (tag != null ? tag.trim() : "default") + "' AND is_archived = " + (archived ? 1 : 0);
        return statement.executeQuery(sql);
    }
}
