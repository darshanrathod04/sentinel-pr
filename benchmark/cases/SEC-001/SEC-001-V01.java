package com.sentinelpr.benchmark.cases.sec001;

public class Sec001FailOpenVulnerable {

    public boolean verifyAccess(String authToken) {
        try {
            if (authToken == null || authToken.isBlank()) {
                throw new IllegalArgumentException("Token cannot be blank");
            }
            return authToken.startsWith("AUTH-VALID-");
        } catch (Exception e) {
            // INTENTIONAL VULNERABILITY: Fail-open security block
            return true;
        }
    }
}
