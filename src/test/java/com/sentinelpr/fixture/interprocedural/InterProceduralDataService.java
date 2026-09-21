package com.sentinelpr.fixture.interprocedural;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Service component demonstrating inter-procedural method return taint and field assignment.
 */
public class InterProceduralDataService {

    private String lastFilter;

    /**
     * Propagates taint from parameter -> local variable -> return statement.
     */
    public String buildQueryFilter(String filterInput) {
        String formattedFilter = "WHERE tenant_id = '" + filterInput + "'";
        return formattedFilter;
    }

    /**
     * Propagates taint from parameter -> field assignment -> SQL execution sink.
     */
    public ResultSet executeDirectQuery(Connection conn, String rawFilter) throws SQLException {
        this.lastFilter = rawFilter;
        String sql = "SELECT * FROM records " + this.lastFilter;
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }

    public String getLastFilter() {
        return lastFilter;
    }
}
