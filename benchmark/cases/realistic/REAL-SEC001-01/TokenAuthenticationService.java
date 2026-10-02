package com.sentinelpr.benchmark.realistic.sec001_01;

import org.springframework.stereotype.Service;

@Service
public class TokenAuthenticationService {

    private final JwtSecurityValidator validator;

    public TokenAuthenticationService(JwtSecurityValidator validator) {
        this.validator = validator;
    }

    public boolean authenticateToken(String token) {
        return validator.verifyTokenAccess(token);
    }
}
