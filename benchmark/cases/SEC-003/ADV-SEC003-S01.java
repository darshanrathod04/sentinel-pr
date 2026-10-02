package com.sentinelpr.benchmark.cases.sec003;

import java.util.concurrent.atomic.AtomicLong;

public class AdvSec003AtomicSafe {

    private final AtomicLong transactionCounter = new AtomicLong(0L);

    public void recordTransaction() {
        // SAFE: Atomic operation on thread-safe variable
        transactionCounter.incrementAndGet();
    }

    public long getTransactionCount() {
        return transactionCounter.get();
    }
}
