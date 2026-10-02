package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008ConfigurationPropertySafe {

    // SAFE: Secret loaded from external system properties or framework config
    private final String apiKey = System.getProperty("app.security.api-key", "default-dev-key");

    public String getApiKey() {
        return apiKey;
    }
}
