package com.sentinelpr.benchmark.cases.sec003;

import java.util.concurrent.atomic.AtomicInteger;

public class Sec003VolatileCompoundSafe {

    private final AtomicInteger requestCount = new AtomicInteger(0);

    public void recordRequest() {
        // SAFE: Thread-safe atomic increment
        requestCount.incrementAndGet();
    }

    public int getRequestCount() {
        return requestCount.get();
    }
}
