package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008EnvironmentVariableSafe {

    // SAFE: Secret loaded from runtime environment variable
    private final String dbPassword = System.getenv("DB_PASSWORD");

    public String getDbPassword() {
        return dbPassword;
    }
}
