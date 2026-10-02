package com.sentinelpr.benchmark.cases.sec010;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdvSec010MethodCorsVulnerable {

    // ADVERSARIAL VULNERABILITY: Permissive wildcard CORS on endpoint
    @CrossOrigin(origins = "*")
    @GetMapping("/api/v2/telemetry")
    public String exportTelemetry() {
        return "telemetry-payload";
    }
}
