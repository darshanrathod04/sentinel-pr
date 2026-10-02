package com.sentinelpr.benchmark.realistic.sec008_02;

import org.springframework.stereotype.Service;

@Service
public class CloudSecretsService {

    private final CloudProviderConfig config;

    public CloudSecretsService(CloudProviderConfig config) {
        this.config = config;
    }

    public boolean isProviderConfigured() {
        return config.getApiKey() != null && !config.getApiKey().isBlank();
    }
}
