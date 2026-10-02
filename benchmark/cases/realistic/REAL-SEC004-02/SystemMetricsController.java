package com.sentinelpr.benchmark.realistic.sec004_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class SystemMetricsController {

    private final SystemDiagnosticsService diagnosticsService;

    public SystemMetricsController(SystemDiagnosticsService diagnosticsService) {
        this.diagnosticsService = diagnosticsService;
    }

    @GetMapping("/api/metrics/uptime")
    public String getUptime() throws IOException, InterruptedException {
        return diagnosticsService.readSystemUptime();
    }
}
