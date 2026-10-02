package com.sentinelpr.benchmark.cases.arch003;

import org.springframework.stereotype.Service;

@Service
public class Arch003NonDeterministicServiceVulnerable {

    public long generateTransactionTimestamp() {
        // INTENTIONAL VULNERABILITY: Direct System.currentTimeMillis() call in business service
        return System.currentTimeMillis();
    }
}
