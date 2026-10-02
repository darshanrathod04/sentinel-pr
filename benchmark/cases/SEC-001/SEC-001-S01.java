package com.sentinelpr.benchmark.cases.sec001;

public class Sec001FailOpenSafe {

    public boolean verifyAccess(String authToken) {
        try {
            if (authToken == null || authToken.isBlank()) {
                throw new IllegalArgumentException("Token cannot be blank");
            }
            return authToken.startsWith("AUTH-VALID-");
        } catch (Exception e) {
            // SAFE: Fail-closed security block
            return false;
        }
    }
}
