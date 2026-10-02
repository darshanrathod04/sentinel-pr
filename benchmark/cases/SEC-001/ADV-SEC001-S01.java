package com.sentinelpr.benchmark.cases.sec001;

public class AdvSec001SafeDenySafe {

    public boolean verifyAdminAccess(String userRole) {
        try {
            if (userRole == null) {
                return false;
            }
            return "ROLE_ADMIN".equalsIgnoreCase(userRole);
        } catch (Exception e) {
            // SAFE: Fail-closed security block
            return false;
        }
    }
}
