package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class Sec002UnclosedStreamVulnerable {

    public int countBytes(File file) throws IOException {
        int total = 0;
        // INTENTIONAL VULNERABILITY: FileInputStream not managed by try-with-resources or finally block
        FileInputStream fis = new FileInputStream(file);
        int b;
        while ((b = fis.read()) != -1) {
            total++;
        }
        return total;
    }
}
