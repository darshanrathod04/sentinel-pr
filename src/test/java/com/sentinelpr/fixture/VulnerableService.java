package com.sentinelpr.fixture;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Test fixture containing intentional security and architectural vulnerabilities:
 * 1. Intentional unclosed FileInputStream resource leak.
 * 2. Intentional fail-open catch block granting access on NullPointerException.
 * 3. Intentional volatile compound operation (non-atomic mutation).
 */
public class VulnerableService {

    private volatile int requestCount;

    /**
     * Vulnerability 1: Intentional unclosed I/O stream.
     */
    public String readConfigurationData(File configFile) throws IOException {
        FileInputStream fis = new FileInputStream(configFile);
        byte[] buffer = new byte[1024];
        int bytesRead = fis.read(buffer);
        return new String(buffer, 0, bytesRead);
    }

    /**
     * Vulnerability 2: Intentional fail-open catch block.
     */
    public boolean checkUserAuthorization(String userId, String requiredRole) {
        try {
            if (userId == null || userId.isBlank()) {
                throw new NullPointerException("User identity is null");
            }
            return userId.equals("admin") && requiredRole.equals("SUPERUSER");
        } catch (NullPointerException e) {
            // VULNERABLE: Fail-open security block returns true on error
            return true;
        }
    }

    /**
     * Vulnerability 3: Non-atomic compound mutation on volatile field.
     */
    public void trackRequest() {
        requestCount++;
    }

    public int getRequestCount() {
        return requestCount;
    }
}
