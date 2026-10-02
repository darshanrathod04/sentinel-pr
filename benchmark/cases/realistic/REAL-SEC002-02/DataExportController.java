package com.sentinelpr.benchmark.realistic.sec002_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class DataExportController {

    private final DataExportService exportService;

    public DataExportController(DataExportService exportService) {
        this.exportService = exportService;
    }

    @GetMapping("/api/data/export")
    public boolean triggerExport(@RequestParam("target") String targetPath) throws IOException {
        return exportService.exportData(targetPath);
    }
}
