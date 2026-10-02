package com.sentinelpr.benchmark.realistic.sec008_03;

import org.springframework.stereotype.Service;

@Service
public class AuthTokenService {

    private static final String JWT_SECRET = "sentinelpr_synthetic_jwt_token_99887766554433221100aabbccddeeff";

    public String signToken(String subject) {
        return subject + "." + JWT_SECRET.hashCode();
    }
}
