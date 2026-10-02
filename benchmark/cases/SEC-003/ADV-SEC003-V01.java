package com.sentinelpr.benchmark.cases.sec003;

public class AdvSec003VolatilePostIncrementVulnerable {

    private volatile int sequenceNumber = 0;

    public void nextSequence() {
        // ADVERSARIAL VULNERABILITY: Postfix increment on volatile integer
        sequenceNumber++;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }
}
