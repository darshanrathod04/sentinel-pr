package com.sentinelpr.benchmark.cases.sec010;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "https://admin.enterprise.internal")
public class AdvSec010RestrictedCorsSafe {

    @GetMapping("/api/v2/telemetry")
    public String exportTelemetry() {
        // SAFE: Restricted CORS domain
        return "telemetry-payload";
    }
}
