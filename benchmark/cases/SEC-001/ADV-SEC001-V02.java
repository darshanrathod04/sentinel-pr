package com.sentinelpr.benchmark.cases.sec001;

public class AdvSec001ValidateSessionVulnerable {

    public boolean validateApiSession(String sessionId) {
        try {
            if (sessionId == null || sessionId.length() < 10) {
                throw new IllegalStateException("Invalid session format");
            }
            return sessionId.startsWith("SESS-ACTIVE-");
        } catch (Exception e) {
            // INTENTIONAL VULNERABILITY: Fail-open session validation
            return true;
        }
    }
}
