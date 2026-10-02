package com.sentinelpr.benchmark.realistic.sec006_02;

import java.io.File;
import java.nio.file.Path;

public class ReportStorageManager {

    private final Path baseDir = Path.of("/var/app/reports").toAbsolutePath().normalize();

    public Path safeResolveReport(String reportName) {
        if (reportName == null || reportName.isBlank()) {
            throw new IllegalArgumentException("Report name required");
        }
        File target = new File(baseDir.toFile(), reportName);
        Path normalized = target.toPath().normalize();
        if (!normalized.startsWith(baseDir)) {
            throw new SecurityException("Access outside reports directory denied");
        }
        return normalized;
    }
}
