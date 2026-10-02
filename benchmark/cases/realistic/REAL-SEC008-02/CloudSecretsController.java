package com.sentinelpr.benchmark.realistic.sec008_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CloudSecretsController {

    private final CloudSecretsService secretsService;

    public CloudSecretsController(CloudSecretsService secretsService) {
        this.secretsService = secretsService;
    }

    @GetMapping("/api/cloud/status")
    public boolean checkCloudConfig() {
        return secretsService.isProviderConfigured();
    }
}
