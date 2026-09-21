package com.sentinelpr.fixture.interprocedural;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Controller endpoint passing tainted user input across inter-procedural call boundaries.
 */
public class InterProceduralController {

    private final InterProceduralDataService dataService;

    public InterProceduralController(InterProceduralDataService dataService) {
        this.dataService = dataService;
    }

    /**
     * Source: userInput (Method parameter)
     * -> localFilter (Local variable)
     * -> dataService.buildQueryFilter(localFilter) (Method call argument)
     * -> computedFilter (Return value assigned to local variable)
     * -> dataService.executeDirectQuery(conn, computedFilter) (Method call argument)
     * -> Sink: stmt.executeQuery(sql)
     */
    public ResultSet handleUserSearch(String userInput, Connection conn) throws SQLException {
        String localFilter = userInput;
        String computedFilter = dataService.buildQueryFilter(localFilter);
        return dataService.executeDirectQuery(conn, computedFilter);
    }
}
