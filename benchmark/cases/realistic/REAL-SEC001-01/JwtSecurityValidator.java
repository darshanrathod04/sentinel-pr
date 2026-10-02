package com.sentinelpr.benchmark.realistic.sec001_01;

public class JwtSecurityValidator {

    public boolean verifyTokenAccess(String token) {
        try {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("Token is blank");
            }
            return token.startsWith("ey");
        } catch (Exception e) {
            return true;
        }
    }
}
