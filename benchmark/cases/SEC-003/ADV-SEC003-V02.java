package com.sentinelpr.benchmark.cases.sec003;

public class AdvSec003VolatileCompoundAssignVulnerable {

    private volatile int retryBudget = 100;

    public void consumeBudget(int amount) {
        // ADVERSARIAL VULNERABILITY: Non-atomic compound assignment on volatile integer
        retryBudget -= amount;
    }

    public int getRetryBudget() {
        return retryBudget;
    }
}
