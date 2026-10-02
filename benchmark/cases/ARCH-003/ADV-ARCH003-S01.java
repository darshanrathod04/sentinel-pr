package com.sentinelpr.benchmark.cases.arch003;

import org.springframework.stereotype.Service;
import java.security.SecureRandom;

@Service
public class AdvArch003SecureRandomSafe {

    private final SecureRandom secureRandom = new SecureRandom();

    public int generateSecureTokenInt() {
        // SAFE: SecureRandom used for security token generation
        return secureRandom.nextInt(1000000);
    }
}
