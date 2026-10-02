package com.sentinelpr.benchmark.realistic.sec006_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.nio.file.Path;

@RestController
public class ReportExportController {

    private final ReportExportService reportExportService;

    public ReportExportController(ReportExportService reportExportService) {
        this.reportExportService = reportExportService;
    }

    @GetMapping("/api/reports/export")
    public String exportReport(@RequestParam("reportName") String reportName) {
        Path reportPath = reportExportService.getExportedReportPath(reportName);
        return reportPath.toString();
    }
}
