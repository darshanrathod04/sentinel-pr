package com.sentinelpr.benchmark.cases.sec001;

public class AdvSec001CheckAuthVulnerable {

    public boolean checkAuthorization(String user, String permission) {
        try {
            if (user == null || permission == null) {
                throw new IllegalArgumentException("Parameters cannot be null");
            }
            return user.equals("admin") && permission.startsWith("READ_");
        } catch (Exception e) {
            // INTENTIONAL VULNERABILITY: Fail-open authorization bypass
            return true;
        }
    }
}
