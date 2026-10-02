package com.sentinelpr.benchmark.cases.sec003;

public class Sec003VolatileCompoundVulnerable {

    private volatile int requestCount = 0;

    public void recordRequest() {
        // INTENTIONAL VULNERABILITY: Compound non-atomic mutation on volatile variable
        requestCount++;
    }

    public int getRequestCount() {
        return requestCount;
    }
}
