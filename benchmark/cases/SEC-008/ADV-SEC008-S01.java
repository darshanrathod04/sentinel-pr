package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008DummyCredentialSafe {

    // SAFE: Known dummy test credential whitelisted in automated scans
    private String testPassword = "changeme";

    public String getTestPassword() {
        return testPassword;
    }
}
