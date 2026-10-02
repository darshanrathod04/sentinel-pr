package com.sentinelpr.benchmark.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sentinelpr.benchmark.model.BenchmarkReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class JsonBenchmarkReporter {

    private final ObjectMapper objectMapper;

    public JsonBenchmarkReporter() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public void writeReport(BenchmarkReport report, Path outputPath) throws IOException {
        if (outputPath.getParent() != null && !Files.exists(outputPath.getParent())) {
            Files.createDirectories(outputPath.getParent());
        }
        byte[] bytes = objectMapper.writeValueAsBytes(report);
        Files.write(outputPath, bytes);
    }
}
