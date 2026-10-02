package com.sentinelpr.benchmark.cases.arch003;

import org.springframework.stereotype.Service;
import java.time.Clock;

@Service
public class Arch003NonDeterministicServiceSafe {

    private final Clock clock;

    public Arch003NonDeterministicServiceSafe(Clock clock) {
        this.clock = clock;
    }

    public long generateTransactionTimestamp() {
        // SAFE: Deterministic Clock dependency injection
        return clock.millis();
    }
}
