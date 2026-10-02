package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008NormalConstantSafe {

    // SAFE: Ordinary non-security configuration constant
    public static final String CACHE_CONTROL_HEADER = "public, max-age=86400";
    public static final String API_BASE_URL = "https://api.example.com/v1";

    public String getApiBaseUrl() {
        return API_BASE_URL;
    }
}
