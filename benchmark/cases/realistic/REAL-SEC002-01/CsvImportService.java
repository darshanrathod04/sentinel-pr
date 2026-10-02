package com.sentinelpr.benchmark.realistic.sec002_01;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

@Service
public class CsvImportService {

    private final CsvRecordParser parser;

    public CsvImportService(CsvRecordParser parser) {
        this.parser = parser;
    }

    public int processImportFile(String filePath) throws IOException {
        int validCount = 0;
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        String line;
        while ((line = reader.readLine()) != null) {
            validCount += parser.parseRecordTokens(line);
        }
        return validCount;
    }
}
