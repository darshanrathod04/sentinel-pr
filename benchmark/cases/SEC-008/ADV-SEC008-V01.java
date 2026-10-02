package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008DatabasePasswordVulnerable {

    // INTENTIONAL VULNERABILITY: Hardcoded production database password
    private String db_password = "Pr0d#Database!SuperSecure99";

    public String getDatabasePassword() {
        return db_password;
    }
}
