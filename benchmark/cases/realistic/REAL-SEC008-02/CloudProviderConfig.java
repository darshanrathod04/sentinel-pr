package com.sentinelpr.benchmark.realistic.sec008_02;

public class CloudProviderConfig {

    public String getApiKey() {
        return System.getenv("CLOUD_API_KEY");
    }

    public String getApiSecret() {
        return System.getenv("CLOUD_API_SECRET");
    }
}
