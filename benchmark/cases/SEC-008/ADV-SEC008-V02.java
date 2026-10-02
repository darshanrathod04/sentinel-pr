package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008ApiTokenVulnerable {

    // INTENTIONAL VULNERABILITY: Embedded API token
    private String api_key = "sentinelpr_synthetic_api_key_9f83acb1049281729482910384729103";

    public String fetchAuthHeader() {
        return "Bearer " + api_key;
    }
}
