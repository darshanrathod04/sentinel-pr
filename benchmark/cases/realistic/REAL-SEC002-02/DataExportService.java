package com.sentinelpr.benchmark.realistic.sec002_02;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.util.List;

@Service
public class DataExportService {

    private final ArchiveWriter archiveWriter;

    public DataExportService(ArchiveWriter archiveWriter) {
        this.archiveWriter = archiveWriter;
    }

    public boolean exportData(String targetPath) throws IOException {
        List<String> records = List.of("RECORD-1", "RECORD-2", "RECORD-3");
        return archiveWriter.writeRecords(targetPath, records);
    }
}
