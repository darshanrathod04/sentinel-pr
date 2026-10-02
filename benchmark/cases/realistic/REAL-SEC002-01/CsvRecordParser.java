package com.sentinelpr.benchmark.realistic.sec002_01;

public class CsvRecordParser {

    public boolean isValidRecord(String line) {
        return line != null && !line.isBlank() && line.contains(",");
    }

    public int parseRecordTokens(String line) {
        return isValidRecord(line) ? 1 : 0;
    }
}
