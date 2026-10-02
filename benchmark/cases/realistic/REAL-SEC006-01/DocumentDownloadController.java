package com.sentinelpr.benchmark.realistic.sec006_01;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.File;
import java.io.IOException;

@RestController
public class DocumentDownloadController {

    private final DocumentStorageService storageService;

    public DocumentDownloadController(DocumentStorageService storageService) {
        this.storageService = storageService;
    }

    @GetMapping("/api/documents/download")
    public String downloadDocument(@RequestParam("name") String fileName) throws IOException {
        File file = storageService.retrieveDocument(fileName);
        return file.getAbsolutePath();
    }
}
