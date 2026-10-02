package com.sentinelpr.benchmark.realistic.sec002_02;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class ArchiveWriter {

    public boolean writeRecords(String targetPath, List<String> records) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(targetPath))) {
            for (String rec : records) {
                writer.write(rec);
                writer.newLine();
            }
            return true;
        }
    }
}
