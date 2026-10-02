package com.sentinelpr.benchmark.realistic.sec002_01;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class BatchImportController {

    private final CsvImportService importService;

    public BatchImportController(CsvImportService importService) {
        this.importService = importService;
    }

    @PostMapping("/api/batch/import")
    public int importBatch(@RequestParam("path") String filePath) throws IOException {
        return importService.processImportFile(filePath);
    }
}
