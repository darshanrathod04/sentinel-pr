package com.sentinelpr.benchmark.realistic.sec006_02;

import org.springframework.stereotype.Service;
import java.nio.file.Path;

@Service
public class ReportExportService {

    private final ReportStorageManager storageManager;

    public ReportExportService(ReportStorageManager storageManager) {
        this.storageManager = storageManager;
    }

    public Path getExportedReportPath(String reportName) {
        return storageManager.safeResolveReport(reportName);
    }
}
